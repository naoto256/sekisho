//! Process startup, listener supervision, and shutdown.
//!
//! [`run`] is the daemon's whole life cycle. The ordering in it is not
//! incidental — several steps exist specifically to make a misconfigured
//! daemon fail before it can serve anything.
//!
//! ## Startup order
//!
//! 1. Logging and metrics, so every later failure is observable.
//! 2. TLS builders select the AWS-LC crypto provider explicitly; startup does
//!    not install process-global rustls state.
//! 3. The master key, resolved *before* the store opens: the instance-config
//!    table is encrypted, so the store cannot be read without it.
//! 4. The store, then the management RPK — the management listener's identity
//!    has to exist before that listener can be built.
//! 5. [`crate::startup::run_sync_checks`], the fail-start boundary. The
//!    signed-identity authority is built here, before any router, task or
//!    socket exists, so every request and every protocol callback in the
//!    process observes one canonical origin. A daemon that cannot agree with
//!    itself about its own issuer must not reach the point of serving traffic.
//! 6. Routers, background tasks, then listeners.
//!
//! ## Secrets are owned narrowly
//!
//! The cookie secret is wrapped in [`ProxyCookieSecret`] and scoped to the
//! block that builds the proxy's dependencies, so the plaintext is zeroized as
//! soon as `CookieManager` has copied it — well before any long-lived task
//! starts. A debug assertion pins that: if the owner ever outlives dependency
//! construction, the test build fails rather than the property quietly
//! eroding.
//!
//! The master key never has a command-line form and the legacy
//! `SEKISHO_MASTER_KEY` *value* variable is rejected outright; only a path to
//! an operator-provisioned file is accepted. See [`resolve_master_key`].
//!
//! ## Listeners
//!
//! Each listener runs its own accept loop as a tracked task. Socket-level
//! behaviour travels with the service ([`TlsService`] / [`TcpBehavior`])
//! rather than being a flag on the serving function, because what a socket
//! needs follows from what it will carry — the proxy port tunnels interactive
//! WebSocket traffic and wants `TCP_NODELAY`; the management port does not.
//!
//! Shutdown drains in stages: stop accepting, join the accept loops
//! ([`drain_listener_tasks`]), then let in-flight work finish within its
//! budget before the store closes. Closing the store while a request still
//! held it would turn a clean shutdown into a burst of errors.

use crate::acl::AcceptFrom;
use crate::config::{CliConfig, LogFormat};
use crate::crypto::{IdentityKeyRingSnapshot, MasterKey};
use crate::store::Store;
use crate::store::instance::{InstanceStore, ManagementRpkMaterial};
use crate::tls::{self, acme::AcmeManager, resolver::CertResolver};
use crate::{api, audit, observability, proxy, shutdown, startup};
use axum::response::IntoResponse;
use std::ffi::OsStr;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use zeroize::{Zeroize, Zeroizing};

/// Run the daemon until shutdown. The binary's entire body after flag
/// parsing; see the module docs for why the steps are in this order.
pub async fn run(cli: CliConfig) -> anyhow::Result<()> {
    init_subscriber(&cli);

    observability::init_metrics();
    observability::record_build_info();

    tracing::info!(
        target: "sekishod",
        version = env!("CARGO_PKG_VERSION"),
        "starting sekisho identity-aware proxy"
    );

    // Master key must be resolved before opening the Store: the Store
    // keeps an encrypted instance_config table that needs the key
    // both to decrypt any existing cluster_db_url and to import a
    // fresh one from `SEKISHO_SERVICE_DB` on first boot.
    let master_key = resolve_master_key()?;
    let store = Store::new(&cli.instance_config, Arc::clone(&master_key)).await?;
    let management_rpk = store
        .instance()
        .ensure_management_rpk(ManagementRpkMaterial::generate()?)
        .await?;
    let api_tls_config = tls::api::server_config(&management_rpk)?;
    drop(management_rpk);
    // Signed-identity configuration is a fail-start boundary. Build the
    // immutable authority before routers, tasks, sockets, or TCP listeners so
    // every request and protocol callback observes the same canonical origin.
    let identity_authority = Arc::new(startup::run_sync_checks(&store).await?);
    let challenge_store = Arc::new(api::local_auth::ChallengeStore::new());
    tracing::info!(
        target: "sekishod",
        instance_config = %cli.instance_config,
        "database initialized"
    );

    let identity_key_ring = store.identity_key_ring_snapshot().await?;

    // ACME Manager
    let global_config = store.get_config().await?;
    crate::validation::validate_global_config(&global_config)
        .map_err(|e| anyhow::anyhow!("invalid global config: {e}"))?;
    let http01_provider = Arc::new(tls::acme::challenge::Http01Provider::new(store.clone()));
    let acme_manager = Arc::new(AcmeManager::new(
        store.clone(),
        http01_provider.clone(),
        &global_config.acme_directory,
        global_config.acme_email.clone(),
    ));

    // Certificate resolver — created before API router so cert issuance can reload it.
    let cert_resolver = Arc::new(CertResolver::new(store.clone()));
    if let Err(e) = cert_resolver.reload().await {
        tracing::warn!(
            target: "sekishod",
            error = %e,
            "failed to preload certificates (using self-signed fallback)"
        );
    }

    // Built before the routers, the periodic-tick helpers, the signal
    // watcher, the hard-deadline watchdog, and the per-listener accept
    // loops — each of those subsystems takes an `Arc<ShutdownController>`
    // clone or a late-safe shutdown signal at construction / spawn time.
    // Deferring the build to a subsystem call site would leave earlier
    // spawns unable to honour the signal.
    let shutdown_ctl = Arc::new(shutdown::ShutdownController::new());

    // One background observer owns every proxy route publication. Construct
    // its state before the routers so both receive the same authority, but do
    // not spawn it until cookie bootstrap and proxy construction have
    // succeeded.
    let route_generation = crate::route_generation::RouteGeneration::new(store.clone());

    // Management API
    let api_app = api::router(
        store.clone(),
        Arc::clone(&route_generation),
        acme_manager.clone(),
        cert_resolver.clone(),
        Arc::clone(&master_key),
        Arc::clone(&identity_key_ring),
        Arc::clone(&identity_authority),
        challenge_store.clone(),
        shutdown_ctl.clone(),
        global_config.acme_issuance_concurrency_limit,
    );

    // Cookie bootstrap and proxy construction must both succeed before the
    // route observer or any listener, socket, or other task can start.
    let proxy_app = build_proxy_and_start_route_observer(
        store.clone(),
        Arc::clone(&route_generation),
        acme_manager.clone(),
        Arc::clone(&master_key),
        identity_key_ring,
        Arc::clone(&identity_authority),
        !cli.no_tls,
        global_config.cookie_name.clone(),
        global_config.websocket_concurrency_limit,
        global_config.session_lifetime_hours,
        shutdown_ctl.clone(),
    )
    .await?;

    // Localhost is always listened to so on-host tools (sekisho-cli,
    // sekisho-webui) can reach the management API without knowing the
    // configured bind address. `instance_config.api_listen` adds one
    // additional concrete address when set. Wildcard management binds
    // are rejected before listener creation.
    // Per-listener source-IP ACLs. Loaded once at startup; a config
    // change requires a daemon restart (same posture as the listen
    // address itself). Parse failures abort boot — an unparsable rule
    // list means the operator's intent is unknown, and silently
    // falling back to ANY would be the wrong default.
    let proxy_accept_from = Arc::new(
        AcceptFrom::parse(&store.instance().get_proxy_accept_from().await?)
            .map_err(|e| anyhow::anyhow!("invalid proxy_accept_from in instance_config: {e}"))?,
    );
    let api_listen = store.instance().get_api_listen().await?;
    let api_accept_from_value = store.instance().get_api_accept_from().await?;
    let api_accept_from = Arc::new(
        crate::validation::validate_management_api_binding(&api_listen, &api_accept_from_value)
            .map_err(|error| anyhow::anyhow!("invalid management API binding: {error}"))?,
    );
    let http_accept_from = Arc::new(
        AcceptFrom::parse(&store.instance().get_http_accept_from().await?)
            .map_err(|e| anyhow::anyhow!("invalid http_accept_from in instance_config: {e}"))?,
    );
    tracing::info!(
        target: "sekishod",
        proxy_filtered = !proxy_accept_from.is_any(),
        api_filtered = !api_accept_from.is_any(),
        http_filtered = !http_accept_from.is_any(),
        "accept_from policies loaded",
    );

    let api_addrs = compute_api_addrs(if api_listen.is_empty() {
        None
    } else {
        Some(api_listen.as_str())
    })?;
    let mut api_listeners: Vec<TcpListener> = Vec::with_capacity(api_addrs.len());
    for addr in &api_addrs {
        api_listeners.push(TcpListener::bind(addr).await?);
    }

    let api_tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(api_tls_config));
    tracing::info!(
        target: "sekishod",
        listeners = ?api_addrs,
        "management API server started (TLS 1.3 RPK)"
    );
    let mut listener_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // Unix socket for local auth challenge-response
    if !cli.control_socket.is_empty() {
        let socket_path = cli.control_socket.clone();
        if let Some(parent) = std::path::Path::new(&socket_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(&socket_path);
        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))?;
        }
        tracing::info!(
            target: "sekishod",
            path = %socket_path,
            "control socket started (challenge auth)"
        );
        listener_tasks.push(tokio::spawn(api::local_auth::serve_control_socket(
            listener,
            challenge_store.clone(),
            shutdown_ctl.clone(),
        )));
    }

    // TLS listener setup. proxy_listen lives in the per-instance
    // bootstrap config (plaintext) so each peer can bind independently
    // in HA without the cluster-wide GlobalConfig forcing a single
    // address.
    let proxy_listen = store.instance().get_proxy_listen().await?;
    let proxy_listener = TcpListener::bind(&proxy_listen).await?;

    if cli.no_tls {
        tracing::info!(
            target: "sekishod",
            listen = %proxy_listen,
            "proxy server started (plain HTTP, TLS disabled)"
        );
    } else {
        tracing::info!(
            target: "sekishod",
            listen = %proxy_listen,
            "proxy server started (TLS enabled)"
        );
    }

    // HTTP listener for ACME challenges + HTTPS redirect. http_listen
    // is per-node, also in the plaintext bootstrap config; an empty
    // string disables it (e.g. running behind another TLS terminator).
    let http_listen = store.instance().get_http_listen().await?;
    if !http_listen.is_empty() && !cli.no_tls {
        let http_listener = TcpListener::bind(&http_listen).await?;
        tracing::info!(
            target: "sekishod",
            listen = %http_listen,
            "HTTP listener started (ACME + redirect)"
        );
        let ctl = shutdown_ctl.clone();
        let app = build_http_listener_app(
            acme_manager.clone(),
            Arc::clone(&route_generation),
            Arc::clone(&identity_authority),
            http_accept_from.clone(),
        );
        listener_tasks.push(spawn_http_listener(http_listener, app, ctl));
    }

    // Periodic session cleanup (every 5 minutes). Registered via
    // `shutdown::spawn_periodic` so the shutdown signal short-circuits
    // the inter-tick wait; the tracked-task join below waits within a
    // 5 s budget.
    {
        let cleanup_store = store.clone();
        shutdown::spawn_periodic(
            &shutdown_ctl,
            "session.cleanup",
            std::time::Duration::from_secs(300),
            shutdown::PeriodicOpts::default(),
            move || {
                let store = cleanup_store.clone();
                async move {
                    match store.cleanup_expired_sessions().await {
                        Ok(count) if count > 0 => {
                            tracing::info!(
                                target: audit::TARGET,
                                event = "session.expire_batch",
                                category = "auth",
                                result = "success",
                                actor_type = "system",
                                actor_id = "system",
                                count,
                                "expired sessions reaped"
                            );
                        }
                        Err(e) => tracing::warn!(
                            target: audit::TARGET,
                            event = "session.expire_batch",
                            category = "auth",
                            result = "failure",
                            actor_type = "system",
                            actor_id = "system",
                            error = %e,
                            "session cleanup failed"
                        ),
                        _ => {}
                    }
                }
            },
        );
    }

    // Periodic ACME leader-election tick (every 5 minutes).
    //
    // Runs on every node regardless of the `acme_leader` config
    // setting: in static-override mode the election row is maintained
    // but ignored by `leader_check`, which costs one DB round-trip per
    // node per tick and means a later flip to `acme_leader = None`
    // picks up a live row instead of waiting up to 15 minutes for the
    // first tick to land.
    {
        let election = std::sync::Arc::new(tls::acme::election::AcmeElection::new(store.clone()));
        // First tick fires immediately so a freshly-booted cluster
        // gets a leader within seconds rather than waiting the full
        // interval. `spawn_periodic`'s default opts honour that —
        // tokio::time::interval's first tick resolves at once.
        shutdown::spawn_periodic(
            &shutdown_ctl,
            "acme.election",
            std::time::Duration::from_secs(300),
            shutdown::PeriodicOpts::default(),
            move || {
                let election = election.clone();
                async move {
                    match election.tick().await {
                        Ok(outcome) => {
                            use crate::store::backend::ElectionAction;
                            // Initial / Takeover / Preempt change ownership of
                            // ACME issuance — those land as audit info events
                            // so an HA operator can correlate "renewal failed
                            // on node-A" with "node-B took over at <time>".
                            // Refresh / None happen every tick by definition;
                            // they're just the tick's heartbeat and stay at
                            // debug level to keep the audit stream clean.
                            let event_name = match outcome.action_taken {
                                ElectionAction::Initial => Some("acme.election.initial"),
                                ElectionAction::Takeover => Some("acme.election.takeover"),
                                ElectionAction::Preempt => Some("acme.election.preempt"),
                                ElectionAction::Refresh | ElectionAction::None => None,
                            };
                            if let Some(event) = event_name {
                                tracing::info!(
                                    target: audit::TARGET,
                                    event,
                                    category = "system",
                                    result = "success",
                                    actor_type = "system",
                                    actor_id = "system",
                                    action = ?outcome.action_taken,
                                    current_leader = %outcome.current_leader_node_id,
                                    i_am_leader = outcome.i_am_leader,
                                    "ACME leader-election ownership change"
                                );
                            } else {
                                tracing::debug!(
                                    target: "sekishod",
                                    action = ?outcome.action_taken,
                                    leader = %outcome.current_leader_node_id,
                                    i_am_leader = outcome.i_am_leader,
                                    "ACME election tick (no ownership change)",
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: audit::TARGET,
                                event = "acme.election.tick_failed",
                                category = "system",
                                result = "failure",
                                actor_type = "system",
                                actor_id = "system",
                                error = %e,
                                "ACME election tick failed"
                            );
                        }
                    }
                }
            },
        );
    }

    // Periodic cert-cache staleness check (every 60s).
    //
    // A peer node (typically the ACME leader) that renewed a cert
    // writes through the service DB and bumps `cert_version`. This
    // tick is how every other node learns to drop its local
    // `CertResolver` cache and reload — without it, a non-leader
    // keeps serving the old PEM (or worse, the self-signed fallback
    // once the cached entry expires) until the process restarts.
    // Single-node deployments do the same thing harmlessly: the
    // version check is cheap and the reload is a no-op when nothing
    // changed.
    {
        let stale_resolver = cert_resolver.clone();
        // Skip the immediate first tick — startup already loaded the
        // cache, and re-loading it 0ms later just adds noise.
        shutdown::spawn_periodic(
            &shutdown_ctl,
            "cert-cache.stale",
            std::time::Duration::from_secs(60),
            shutdown::PeriodicOpts {
                skip_first_tick: true,
                ..Default::default()
            },
            move || {
                let resolver = stale_resolver.clone();
                async move {
                    if let Err(e) = resolver.reload_if_stale().await {
                        tracing::warn!(
                            target: "sekishod",
                            error = %e,
                            "cert-cache staleness check failed"
                        );
                    }
                }
            },
        );
    }

    // DEK ring staleness check. Mirrors the cert-cache pattern above —
    // every node polls the shared `key_ring_version` counter; a peer's
    // add / activate / retire bumps it and the next tick rebuilds the
    // in-memory ring on this node. Without this, a non-leader would
    // keep encrypt-routing onto the old active DEK after the leader
    // flipped, producing v3 blobs the leader's ring already considers
    // legacy.
    {
        let ring_store = store.clone();
        let ring_kek = Arc::clone(&master_key);
        // Tick body needs cross-tick state (`last_seen`) so we own a
        // bootstrapped initial value here and stash it in a Mutex; the
        // closure clones the Arc once per tick. This is the one place
        // a spawn_periodic body has stateful tick-to-tick memory.
        let last_seen = std::sync::Arc::new(tokio::sync::Mutex::new(
            ring_store.key_ring_snapshot().await.version(),
        ));
        shutdown::spawn_periodic(
            &shutdown_ctl,
            "key-ring.stale",
            std::time::Duration::from_secs(60),
            shutdown::PeriodicOpts {
                skip_first_tick: true,
                ..Default::default()
            },
            move || {
                let ring_store = ring_store.clone();
                let ring_kek = Arc::clone(&ring_kek);
                let last_seen = last_seen.clone();
                async move {
                    let current = match ring_store.key_ring_version_current().await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                target: "sekishod",
                                error = %e,
                                "key_ring_version read failed; keeping ring"
                            );
                            return;
                        }
                    };
                    {
                        let seen = last_seen.lock().await;
                        if current == *seen {
                            return;
                        }
                    }
                    match crate::store::key_ring_loader::refresh(&ring_store, &ring_kek).await {
                        Ok(ring) => {
                            let new_version = ring.version();
                            ring_store.replace_key_ring(ring).await;
                            *last_seen.lock().await = new_version;
                            tracing::info!(
                                target: audit::TARGET,
                                event = "crypto.dek_ring.refresh",
                                category = "crypto",
                                result = "success",
                                actor_type = "system",
                                actor_id = "system",
                                trigger = "peer_version_bump",
                                new_version,
                                "DEK ring refreshed from peer-side mutation"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "sekishod",
                                error = %e,
                                "key_ring refresh failed; keeping previous snapshot"
                            );
                        }
                    }
                }
            },
        );
    }

    // Identity-signing ring staleness check. The shared snapshot is
    // replaced only after a complete durable load, so request paths always
    // observe either the previous or the next coherent ring.
    {
        let identity_store = store.clone();
        let last_seen = std::sync::Arc::new(tokio::sync::Mutex::new(
            identity_store.identity_key_ring_snapshot().await?.version(),
        ));
        shutdown::spawn_periodic(
            &shutdown_ctl,
            "identity-key-ring.stale",
            std::time::Duration::from_secs(60),
            shutdown::PeriodicOpts {
                skip_first_tick: true,
                ..Default::default()
            },
            move || {
                let identity_store = identity_store.clone();
                let last_seen = last_seen.clone();
                async move {
                    let current = match identity_store.identity_signing_version_current().await {
                        Ok(version) => version,
                        Err(error) => {
                            tracing::warn!(
                                target: "sekishod",
                                error = %error,
                                "identity signing version read failed; keeping ring"
                            );
                            return;
                        }
                    };
                    {
                        let seen = last_seen.lock().await;
                        if current == *seen {
                            return;
                        }
                    }
                    match identity_store.refresh_identity_signing_ring().await {
                        Ok(()) => {
                            *last_seen.lock().await = current;
                            tracing::info!(
                                target: audit::TARGET,
                                event = "identity_signing.refresh",
                                category = "crypto",
                                result = "success",
                                actor_type = "system",
                                actor_id = "system",
                                trigger = "peer_version_bump",
                                new_version = current,
                                "identity-signing ring refreshed from peer-side mutation"
                            );
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: "sekishod",
                                error = %error,
                                "identity signing refresh failed; keeping previous snapshot"
                            );
                        }
                    }
                }
            },
        );
    }

    // ACME issuance-queue processor. Runs on every node: the task
    // only does work when this node owns the configured leader pin or
    // election row, so
    // starting it unconditionally keeps spawn-site and leader-promotion
    // decoupled. A non-leader wakes up, sees it's not leader, goes
    // back to sleep.
    tls::acme::queue::spawn_tick(
        &shutdown_ctl,
        store.clone(),
        acme_manager.clone(),
        cert_resolver.clone(),
        global_config.acme_issuance_concurrency_limit,
    );

    // Periodic ACME renewal admission. The queue worker is the sole
    // production path that starts an order.
    // 60s pre-loop delay so we don't fire a renewal pass at boot time —
    // and 12h period so each subsequent pass is a normal interval tick.
    {
        let renewal_acme = acme_manager.clone();
        let renewal_period = std::time::Duration::from_secs(
            u64::from(global_config.acme_renewal_scan_interval_hours) * 60 * 60,
        );
        shutdown::spawn_periodic(
            &shutdown_ctl,
            "acme.renewal",
            renewal_period,
            shutdown::PeriodicOpts {
                initial_delay: Some(std::time::Duration::from_secs(60)),
                ..Default::default()
            },
            move || {
                let renewal_acme = renewal_acme.clone();
                async move {
                    tracing::info!(target: "sekishod", "checking for certificate renewals");
                    match renewal_acme.renew_expiring().await {
                        Ok(result) if !result.is_empty() => {
                            tracing::info!(
                                target: "sekishod",
                                inserted = result.inserted,
                                existing = result.existing,
                                full = result.full,
                                "certificate renewals admitted"
                            );
                        }
                        Err(e) => tracing::warn!(
                            target: "sekishod",
                            error = %e,
                            "certificate renewal check failed"
                        ),
                        _ => tracing::debug!(target: "sekishod", "no certificates need renewal"),
                    }
                }
            },
        );
    }

    // Graceful shutdown is driven by the `ShutdownController` built
    // inside `run` before its consumers are constructed / spawned (see
    // `shutdown.rs`). A single signal-watcher task flips the controller
    // on SIGTERM / SIGINT; a second signal collapses to a single drain
    // — the controller is idempotent. `/readyz` reads the same
    // controller via the `axum::Extension`-injected
    // `Arc<ShutdownController>` on the mgmt API router.
    {
        let ctl = shutdown_ctl.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm =
                    signal(SignalKind::terminate()).expect("failed to register SIGTERM");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            tracing::info!(
                target: audit::TARGET,
                event = "daemon.shutdown.start",
                category = "system",
                result = "success",
                actor_type = "system",
                actor_id = "system",
                http_drain_timeout_ms = shutdown::HTTP_DRAIN_TIMEOUT.as_millis() as u64,
                ws_drain_timeout_ms = shutdown::WS_DRAIN_TIMEOUT.as_millis() as u64,
                hard_deadline_ms = shutdown::HARD_DEADLINE.as_millis() as u64,
                "shutdown signal received; draining"
            );
            ctl.signal();
        });
    }

    // Hard-deadline watchdog. If the full shutdown sequence exceeds
    // `HARD_DEADLINE` we abort the process ourselves rather than wait for
    // systemd to SIGKILL us — that way the `daemon.shutdown.force_exit`
    // audit event actually lands in the journal before the process
    // goes. The watchdog is armed *after* the signal fires; a
    // still-healthy daemon never enters this timer.
    {
        let ctl = shutdown_ctl.clone();
        tokio::spawn(async move {
            ctl.wait().await;
            tokio::time::sleep(shutdown::HARD_DEADLINE).await;
            tracing::error!(
                target: audit::TARGET,
                event = "daemon.shutdown.force_exit",
                category = "system",
                result = "failure",
                actor_type = "system",
                actor_id = "system",
                deadline_ms = shutdown::HARD_DEADLINE.as_millis() as u64,
                "hard deadline exceeded; forcing exit"
            );
            // `std::process::exit` runs no destructors — intentional:
            // we've already tried the clean path for the full 90s and
            // something is wedged. A dirty exit is better than being
            // stuck past the systemd `TimeoutStopSec` and getting
            // killed with no trace of what happened.
            std::process::exit(1);
        });
    }

    // Startup config validation. Sync portion (config sanity, route
    // URL parse, cert expiry) runs inline — DB-only, fast. The IdP
    // discovery probe is tracked but non-blocking: it touches the
    // network and must not delay the first inbound request if an
    // upstream issuer is wedged. The controller cancels and joins it
    // before Store closure. See `startup` for the deploy-time-vs-runtime
    // policy split.
    startup::spawn_idp_probes(&shutdown_ctl, store.clone());

    for listener in api_listeners {
        let app = api_app.clone();
        let acceptor = api_tls_acceptor.clone();
        let acl = api_accept_from.clone();
        let shutdown = shutdown_ctl.subscribe();
        listener_tasks.push(tokio::spawn(async move {
            let service = TlsService {
                app,
                tcp_behavior: TcpBehavior::default(),
            };
            if let Err(e) = serve_tls(listener, acceptor, service, acl, shutdown).await {
                tracing::error!(target: "sekishod", error = %e, "API server error");
            }
        }));
    }

    if cli.no_tls {
        // Source-IP ACL also applies in the no-TLS dev path, so
        // testing against `--no-tls` mirrors production semantics
        // for the filter behaviour. Wrap axum's stock service in a
        // middleware that closes connections from disallowed peers
        // by returning 403 with no body. We can't drop the TCP
        // stream pre-parse here (axum::serve owns the accept loop),
        // but a 403 is acceptable for the dev-only no-tls path.
        let proxy_shutdown = shutdown_ctl.wait();
        let acl = proxy_accept_from.clone();
        let app = proxy_app.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let acl = acl.clone();
                async move {
                    if let Some(ci) = req
                        .extensions()
                        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                        && !acl.allows(ci.0.ip())
                    {
                        tracing::debug!(
                            target: "sekishod",
                            peer = %ci.0,
                            "accept_from rejected source (no-tls)"
                        );
                        return axum::http::StatusCode::FORBIDDEN.into_response();
                    }
                    next.run(req).await
                }
            },
        ));
        if let Err(e) = axum::serve(
            proxy_listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(proxy_shutdown)
        .await
        {
            tracing::error!(target: "sekishod", error = %e, "proxy server error");
        }
    } else {
        let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        let tls_shutdown = shutdown_ctl.subscribe();
        let proxy_service = TlsService {
            app: proxy_app,
            // Proxy carries interactive WebSocket payloads (keystrokes,
            // mouse events, terminal echo). NODELAY on accepted sockets
            // avoids a Nagle / delayed-ACK deadlock on the inbound side;
            // the upstream WebSocket socket applies the same setting.
            tcp_behavior: TcpBehavior { nodelay: true },
        };
        if let Err(e) = serve_tls(
            proxy_listener,
            tls_acceptor,
            proxy_service,
            proxy_accept_from.clone(),
            tls_shutdown,
        )
        .await
        {
            tracing::error!(target: "sekishod", error = %e, "TLS proxy server error");
        }
    }

    // If the foreground proxy returned without observing the external
    // signal, stop the remaining listeners and background tasks too.
    shutdown_ctl.signal();

    // Listener, WebSocket, and background drains run concurrently so
    // their individual budgets do not add up past HARD_DEADLINE.
    let listener_drain = drain_listener_tasks(
        listener_tasks,
        shutdown_ctl.clone(),
        shutdown::HTTP_DRAIN_TIMEOUT,
    );
    let websocket_drain = shutdown_ctl.drain_websockets(shutdown::WS_DRAIN_TIMEOUT);
    let background_drain = shutdown_ctl.join_tracked_tasks(std::time::Duration::from_secs(5));
    let ((), ws_remaining, ()) = tokio::join!(listener_drain, websocket_drain, background_drain);
    if ws_remaining > 0 {
        tracing::warn!(
            target: "sekishod",
            remaining = ws_remaining,
            timeout_ms = shutdown::WS_DRAIN_TIMEOUT.as_millis() as u64,
            "websocket drain timed out; abandoning tunnels"
        );
    }

    // Close DB pools after the three scoped drains above: listener
    // accept loops, registered WebSocket guards, and tracked background
    // tasks. This ordering prevents those tracked DB users from racing
    // pool closure; it does not claim ownership of accepted-connection
    // or other detached tasks.
    store.close().await;

    // Clean up Unix socket file
    if !cli.control_socket.is_empty() {
        let _ = std::fs::remove_file(&cli.control_socket);
    }

    tracing::info!(
        target: audit::TARGET,
        event = "daemon.shutdown.complete",
        category = "system",
        result = "success",
        actor_type = "system",
        actor_id = "system",
        "shutdown complete"
    );
    Ok(())
}

fn build_http_listener_app(
    acme_manager: Arc<AcmeManager>,
    route_generation: Arc<crate::route_generation::RouteGeneration>,
    identity_authority: Arc<crate::identity::IdentityAuthority>,
    http_accept_from: Arc<AcceptFrom>,
) -> axum::Router {
    let http_acme = acme_manager;
    let redirect_routes = route_generation;
    let redirect_authority = identity_authority;
    let app = axum::Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(
                move |axum::extract::Path(token): axum::extract::Path<String>| {
                    let acme = http_acme.clone();
                    async move {
                        match acme.challenge_provider().get_response(&token).await {
                            Some(key_auth) => {
                                tracing::debug!(
                                    target: "sekishod",
                                    token = %token,
                                    "serving ACME challenge (HTTP)"
                                );
                                axum::response::IntoResponse::into_response(key_auth)
                            }
                            None => axum::response::IntoResponse::into_response(
                                axum::http::StatusCode::NOT_FOUND,
                            ),
                        }
                    }
                },
            ),
        )
        .fallback(move |req: axum::http::Request<axum::body::Body>| {
            let routes = Arc::clone(&redirect_routes);
            let authority = Arc::clone(&redirect_authority);
            async move { http_redirect_response(&req, &routes, &authority) }
        });

    // The ACL wraps both ACME and redirect handling. An empty list preserves
    // the existing public-listener default.
    app.layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let acl = http_accept_from.clone();
            async move {
                if let Some(ci) = req
                    .extensions()
                    .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    && !acl.allows(ci.0.ip())
                {
                    tracing::debug!(
                        target: "sekishod",
                        peer = %ci.0,
                        "accept_from rejected source (http)"
                    );
                    return axum::http::StatusCode::FORBIDDEN.into_response();
                }
                next.run(req).await
            }
        },
    ))
}

/// Build the cleartext listener's redirect response from trusted published
/// authorities only. Client `Host` bytes select an existing authority but are
/// never copied into `Location`.
fn http_redirect_response(
    request: &axum::http::Request<axum::body::Body>,
    routes: &crate::route_generation::RouteGeneration,
    identity_authority: &crate::identity::IdentityAuthority,
) -> axum::http::Response<axum::body::Body> {
    let mut values = request.headers().get_all(axum::http::header::HOST).iter();
    let Some(value) = values.next() else {
        return empty_http_response(axum::http::StatusCode::MISDIRECTED_REQUEST);
    };
    if values.next().is_some() {
        return empty_http_response(axum::http::StatusCode::MISDIRECTED_REQUEST);
    }
    let Ok(request_authority) = value.to_str() else {
        return empty_http_response(axum::http::StatusCode::MISDIRECTED_REQUEST);
    };
    let Some((request_host, request_port)) =
        crate::identity::CanonicalHost::from_authority(request_authority)
    else {
        return empty_http_response(axum::http::StatusCode::MISDIRECTED_REQUEST);
    };

    let auth_origin = identity_authority.auth_origin().ok();
    let redirect_authority = if let Some(origin) = auth_origin
        && origin.matches_host(&request_host, request_port)
    {
        origin.authority().to_owned()
    } else {
        match routes.redirect_host(&request_host) {
            Ok(Some(hostname)) => hostname,
            Ok(None) => {
                return empty_http_response(axum::http::StatusCode::MISDIRECTED_REQUEST);
            }
            Err(_) => return empty_http_response(axum::http::StatusCode::SERVICE_UNAVAILABLE),
        }
    };
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let location = format!("https://{redirect_authority}{path}");
    axum::http::Response::builder()
        .status(axum::http::StatusCode::MOVED_PERMANENTLY)
        .header(axum::http::header::LOCATION, location)
        .header(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains",
        )
        .body(axum::body::Body::empty())
        .expect("static redirect response headers are valid")
}

fn empty_http_response(status: axum::http::StatusCode) -> axum::http::Response<axum::body::Body> {
    axum::http::Response::builder()
        .status(status)
        .body(axum::body::Body::empty())
        .expect("static HTTP response status is valid")
}

/// Which management-RPK maintenance action a one-shot invocation should take.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementRpkCommand {
    /// Show the current pin, creating one if the instance has none yet.
    Print,
    /// Replace the key and show the new pin. Takes effect at the next start.
    Rotate,
}

/// Execute the management-RPK maintenance path without constructing the
/// service store, routers, listeners, or background tasks.
pub async fn management_rpk_one_shot(
    command: ManagementRpkCommand,
    instance_config: &str,
) -> anyhow::Result<()> {
    let master_key = resolve_master_key()?;
    let store = InstanceStore::new(instance_config, master_key).await?;
    let candidate = ManagementRpkMaterial::generate()?;
    let material = match command {
        ManagementRpkCommand::Print => store.ensure_management_rpk(candidate).await?,
        ManagementRpkCommand::Rotate => store.rotate_management_rpk(candidate).await?,
    };
    println!("{}", material.pin());
    store.close().await;
    Ok(())
}

/// Build the proxy router, then start the route observer and the router's
/// background tasks.
///
/// Exists as its own function to give the cookie secret a scope to die in: the
/// plaintext is owned by a block that ends before any task is spawned, so no
/// long-lived task can ever observe it. See [`ProxyCookieSecret`].
#[allow(clippy::too_many_arguments)]
async fn build_proxy_and_start_route_observer(
    store: Store,
    route_generation: Arc<crate::route_generation::RouteGeneration>,
    acme_manager: Arc<AcmeManager>,
    master_key: Arc<MasterKey>,
    identity_key_ring: Arc<IdentityKeyRingSnapshot>,
    identity_authority: Arc<crate::identity::IdentityAuthority>,
    tls_enabled: bool,
    cookie_name: String,
    websocket_concurrency_limit: u32,
    session_lifetime_hours: u32,
    shutdown_ctl: Arc<shutdown::ShutdownController>,
) -> anyhow::Result<axum::Router> {
    #[cfg(test)]
    let cookie_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Keep plaintext ownership inside the dependency-construction boundary.
    // CookieManager has copied the key before this block ends, so unrelated
    // observer and cleanup tasks never start while the bootstrap owner lives.
    let proxy_app = {
        let cookie_secret = ProxyCookieSecret::new(
            ensure_cookie_secret(&store).await?,
            #[cfg(test)]
            Arc::clone(&cookie_dropped),
        );
        proxy::router_deferred(
            store,
            Arc::clone(&route_generation),
            cookie_secret.as_bytes(),
            acme_manager,
            master_key,
            identity_key_ring,
            identity_authority,
            tls_enabled,
            cookie_name,
            websocket_concurrency_limit,
            session_lifetime_hours,
            shutdown_ctl.clone(),
        )
    };

    #[cfg(test)]
    assert!(
        cookie_dropped.load(std::sync::atomic::Ordering::SeqCst),
        "cookie plaintext owner outlived proxy dependency construction"
    );
    route_generation.spawn(&shutdown_ctl);
    Ok(proxy_app.start_background_tasks(&shutdown_ctl))
}

/// Scoped owner of the cookie-signing key's plaintext.
///
/// `Zeroizing` already wipes on drop; this wrapper adds the *timing*
/// guarantee. Under `cfg(test)` it also flips a flag on drop, which the caller
/// asserts on — turning "the plaintext does not outlive dependency
/// construction" from a comment into something that fails the test suite if it
/// stops being true.
struct ProxyCookieSecret {
    bytes: Zeroizing<Vec<u8>>,
    #[cfg(test)]
    dropped: Arc<std::sync::atomic::AtomicBool>,
}

impl ProxyCookieSecret {
    fn new(
        bytes: Zeroizing<Vec<u8>>,
        #[cfg(test)] dropped: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            dropped,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ProxyCookieSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Stop the accept loops and record that the drain has begun.
///
/// Deliberately separate from waiting on in-flight work: accepting must stop
/// first, or new connections keep arriving for as long as the drain takes and
/// it never converges. The emitted event carries the WebSocket in-flight count
/// because long-lived tunnels are the usual reason a drain runs long.
async fn drain_listener_tasks(
    handles: Vec<tokio::task::JoinHandle<()>>,
    shutdown_ctl: Arc<shutdown::ShutdownController>,
    budget: std::time::Duration,
) {
    shutdown::join_tasks(handles, budget, "listener").await;
    tracing::info!(
        target: audit::TARGET,
        event = "daemon.shutdown.drain",
        category = "system",
        result = "success",
        actor_type = "system",
        actor_id = "system",
        ws_inflight = shutdown_ctl.ws_inflight(),
        "listener accept loops stopped; draining in-flight work"
    );
}

/// Spawn the plain-HTTP accept loop.
///
/// The only caller binds the cleartext port, which exists for ACME HTTP-01
/// challenges and the HTTPS redirect — nothing authenticated is served over
/// it. An accept error is logged and ends this listener only; the TLS
/// listeners are separate tasks and keep running.
fn spawn_http_listener(
    listener: TcpListener,
    app: axum::Router,
    shutdown_ctl: Arc<shutdown::ShutdownController>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_ctl.wait())
        .await
        {
            tracing::error!(
                target: "sekishod",
                error = %e,
                "HTTP listener error"
            );
        }
    })
}

/// Configure the global tracing subscriber.
///
/// Defaults to JSON because production runs under systemd → journald,
/// where structured fields are non-negotiable for forensics — the
/// downstream forwarder reads `MESSAGE` per-line as JSON. `text` mode
/// stays available for `cargo run` where the JSON form is unreadable.
///
/// `EnvFilter` falls back to `RUST_LOG` first, then the `--log-level`
/// CLI value, so an operator can crank up a noisy module without
/// rebuilding (`RUST_LOG=sekishod::auth=debug,info`).
fn init_subscriber(cli: &CliConfig) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));
    let builder = tracing_subscriber::fmt().with_env_filter(env_filter);
    match cli.log_format {
        LogFormat::Json => builder
            .json()
            .with_current_span(false)
            .with_span_list(true)
            .init(),
        LogFormat::Text => builder.init(),
    }
}

/// Loopback management-API listener that is always bound so on-host
/// tools can reach the daemon regardless of the operator-configured
/// `api_listen`. Declared at module scope so `compute_api_addrs` and
/// its tests share the literal.
const LOCALHOST_API: &str = "127.0.0.1:9443";

/// Decide which addresses the management API should bind, given the
/// operator-supplied `instance_config.api_listen`.
///
/// Rules:
/// * `None` or empty / equal to loopback → loopback only.
/// * Specific (non-loopback) IP → both loopback and the configured
///   address.
/// * Unspecified IP (`0.0.0.0` / `::`) → rejected. Management exposure
///   must always name a concrete interface and pair it with an ACL.
fn compute_api_addrs(api_listen: Option<&str>) -> anyhow::Result<Vec<String>> {
    let trimmed = api_listen.map(str::trim).unwrap_or("");
    if trimmed.is_empty() || trimmed == LOCALHOST_API {
        return Ok(vec![LOCALHOST_API.to_string()]);
    }
    let parsed: std::net::SocketAddr = trimmed.parse().map_err(|e| {
        anyhow::anyhow!("invalid bootstrap api_listen '{trimmed}': {e}; expected host:port")
    })?;
    if parsed.ip().is_unspecified() {
        anyhow::bail!("management api_listen must not use an unspecified address")
    } else {
        Ok(vec![LOCALHOST_API.to_string(), trimmed.to_string()])
    }
}

/// TCP-level behavior the service wants applied to every accepted
/// connection. Declarative: the service describes *what* it needs
/// (e.g. NODELAY for interactive payloads); `serve_tls` is
/// responsible for the *how* (calling `setsockopt`). Keeps the
/// service out of the transport protocol layer — it never touches
/// `TcpStream` directly — while still letting it shape transport
/// behavior. Extend by adding a field here; `apply` translates it
/// into the appropriate calls.
#[derive(Default, Clone, Copy)]
pub(crate) struct TcpBehavior {
    /// `TCP_NODELAY`. Default `false` matches the kernel default
    /// (Nagle on). Set `true` for interactive WS workloads where
    /// small frames must flow without delayed-ACK stalls.
    pub nodelay: bool,
    // Future: keepalive intervals, SO_SNDBUF / SO_RCVBUF, IP_TOS
    // (DSCP), TCP_USER_TIMEOUT. Add fields here; extend `apply`.
}

impl TcpBehavior {
    /// Apply the declared behavior to a freshly-accepted stream.
    /// Failures (e.g. an OS without `TCP_NODELAY`) are swallowed —
    /// they degrade behavior but don't justify aborting the
    /// connection.
    fn apply(self, stream: &tokio::net::TcpStream) {
        if self.nodelay {
            let _ = stream.set_nodelay(true);
        }
    }
}

/// Bundle of "what to serve on a TLS listener": the request handler
/// (`app`) plus the TCP-level behavior (`tcp_behavior`) the service
/// wants.
///
/// Why per-service rather than a `serve_tls` flag: socket-level
/// requirements come from what the connection will carry. The proxy
/// listener serves WebSocket tunnels whose interactive payloads
/// (keystrokes, mouse events, terminal echo) need `TCP_NODELAY` to
/// avoid Nagle / delayed-ACK stalls on high-RTT client paths; the
/// management API listener serves request/response
/// HTTP and gets nothing useful out of NODELAY. Encoding the choice
/// in a struct that travels with the service keeps the dependency
/// direction right — infra (`serve_tls`) reads what each service
/// declares, instead of growing a flag per protocol concern.
pub(crate) struct TlsService {
    pub app: axum::Router,
    pub tcp_behavior: TcpBehavior,
}

/// Serve axum app over TLS using a custom TLS acceptor.
async fn serve_tls(
    listener: TcpListener,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    service: TlsService,
    accept_from: Arc<AcceptFrom>,
    mut shutdown: shutdown::ShutdownSignal,
) -> anyhow::Result<()> {
    loop {
        let (stream, addr) = tokio::select! {
            biased;
            _ = shutdown.wait() => {
                tracing::info!(target: "sekishod", "TLS proxy server shutting down");
                return Ok(());
            }
            result = listener.accept() => result?,
        };
        // Source-IP ACL check before TLS handshake. Drops the
        // connection by closing the TcpStream — no TLS round-trip,
        // no audit event (the deny is high-volume by design once a
        // scanner finds the address). Debug log only.
        if !accept_from.allows(addr.ip()) {
            tracing::debug!(
                target: "sekishod",
                peer = %addr,
                "accept_from rejected source"
            );
            drop(stream);
            continue;
        }
        // Apply the service's declared TCP behavior (NODELAY for
        // interactive services, etc) before TLS handshake so the
        // settings are in effect from the first record exchange.
        service.tcp_behavior.apply(&stream);
        let acceptor = tls_acceptor.clone();
        let app = service.app.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    // Inject ConnectInfo so transforms can access client IP.
                    // Use a middleware that inserts directly into request extensions
                    // (same location as into_make_service_with_connect_info).
                    let connect_info = axum::extract::ConnectInfo(addr);
                    let app = app.layer(axum::middleware::from_fn(
                        move |mut req: axum::http::Request<axum::body::Body>,
                              next: axum::middleware::Next| {
                            req.extensions_mut().insert(connect_info);
                            async move { next.run(req).await }
                        },
                    ));
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(app);
                    // `_with_upgrades` is required for the WebSocket
                    // path: `hyper::upgrade::OnUpgrade` (which the
                    // `proxy::websocket` handler awaits to grab the
                    // raw upgraded socket) is only populated when the
                    // connection was built with upgrade support.
                    // Without this, every `wss://` request through
                    // the TLS proxy fails with "upgrade expected but
                    // low level API in use".
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection_with_upgrades(io, service)
                    .await
                    {
                        tracing::debug!(
                            target: "sekishod",
                            addr = %addr,
                            error = %e,
                            "connection error"
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        target: "sekishod",
                        addr = %addr,
                        error = %e,
                        "TLS handshake failed"
                    );
                }
            }
        });
    }
}

/// Resolve the master key (KEK) from an operator-provisioned file.
///
/// The KEK is the root of the at-rest encryption hierarchy and is
/// treated as a system secret on the same tier as the host's disk
/// encryption key — it must come from outside the daemon. We refuse
/// to boot without an explicit credential path rather than silently
/// generate a key or place it next to the data it protects.
///
/// To bootstrap a fresh node, generate a key out of band, store it in
/// a provider-managed credential file, and pass only its path:
///
/// ```sh
/// SEKISHO_MASTER_KEY_FILE=/run/secrets/sekisho_master_key
/// ```
fn resolve_master_key() -> anyhow::Result<Arc<MasterKey>> {
    let legacy_value = std::env::var_os("SEKISHO_MASTER_KEY");
    let path = std::env::var_os("SEKISHO_MASTER_KEY_FILE");
    resolve_master_key_from_sources(legacy_value.as_deref(), path.as_deref())
}

#[cfg(test)]
fn resolve_master_key_from_file(path: Option<&OsStr>) -> anyhow::Result<Arc<MasterKey>> {
    resolve_master_key_from_sources(None, path)
}

fn resolve_master_key_from_sources(
    legacy_value: Option<&OsStr>,
    path: Option<&OsStr>,
) -> anyhow::Result<Arc<MasterKey>> {
    let result = if legacy_value.is_some() {
        Err(MasterKeyLoadError::LegacyEnvironmentPresent)
    } else {
        path.filter(|path| !path.is_empty())
            .ok_or(MasterKeyLoadError::MissingFilePath)
            .and_then(|path| {
                read_master_key_file(Path::new(path)).and_then(parse_master_key_file_bytes)
            })
    };

    match result {
        Ok(key) => {
            tracing::info!(
                target: audit::TARGET,
                event = "crypto.master_key.load",
                category = "crypto",
                result = "success",
                actor_type = "system",
                actor_id = "system",
                source = "file",
                "master key loaded"
            );
            Ok(Arc::new(key))
        }
        Err(error) => {
            tracing::error!(
                target: audit::TARGET,
                event = "crypto.master_key.load",
                category = "crypto",
                result = "failure",
                actor_type = "system",
                actor_id = "system",
                source = "file",
                reason = error.reason(),
                error = %error,
                "master key load failed"
            );
            Err(error.into())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MasterKeyLoadError {
    LegacyEnvironmentPresent,
    MissingFilePath,
    ReadFailed,
    InvalidLength,
    InvalidHex,
}

impl MasterKeyLoadError {
    fn reason(self) -> &'static str {
        match self {
            Self::LegacyEnvironmentPresent => "legacy_master_key_environment_present",
            Self::MissingFilePath => "no_master_key_file_provided",
            Self::ReadFailed => "master_key_file_read_failed",
            Self::InvalidLength => "invalid_length",
            Self::InvalidHex => "hex_decode_failed",
        }
    }
}

impl fmt::Display for MasterKeyLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyEnvironmentPresent => write!(
                f,
                "SEKISHO_MASTER_KEY is no longer accepted; remove it and provide only \
                 SEKISHO_MASTER_KEY_FILE"
            ),
            Self::MissingFilePath => write!(
                f,
                "SEKISHO_MASTER_KEY_FILE is required and must name an \
                 operator-provisioned credential file"
            ),
            Self::ReadFailed => write!(f, "failed to read the master-key credential file"),
            Self::InvalidLength => {
                write!(f, "master key must be exactly 32 bytes (64 hex chars)")
            }
            Self::InvalidHex => write!(
                f,
                "master-key credential must contain only hexadecimal text"
            ),
        }
    }
}

impl std::error::Error for MasterKeyLoadError {}

fn read_master_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, MasterKeyLoadError> {
    // The longest accepted representation is 64 hex bytes plus CRLF. Read one
    // extra byte so an oversized credential is rejected without an unbounded
    // startup allocation.
    let file = std::fs::File::open(path).map_err(|_| MasterKeyLoadError::ReadFailed)?;
    let mut value = Zeroizing::new(Vec::with_capacity(67));
    file.take(67)
        .read_to_end(&mut value)
        .map_err(|_| MasterKeyLoadError::ReadFailed)?;
    Ok(value)
}

fn parse_master_key_file_bytes(value: Zeroizing<Vec<u8>>) -> Result<MasterKey, MasterKeyLoadError> {
    let hex_key = if value.ends_with(b"\r\n") {
        &value[..value.len() - 2]
    } else if value.ends_with(b"\n") {
        &value[..value.len() - 1]
    } else {
        value.as_slice()
    };
    if hex_key.len() != 64 {
        return Err(MasterKeyLoadError::InvalidLength);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(hex_key, bytes.as_mut()).map_err(|_| MasterKeyLoadError::InvalidHex)?;
    Ok(MasterKey::new(bytes))
}

/// Ensure a cookie signing secret exists, encrypted at rest through
/// the DEK ring.
async fn ensure_cookie_secret(store: &Store) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if let Some(encrypted_b64) = store.get_secret("cookie_secret").await? {
        let plaintext = store
            .decrypt_any_from_base64_zeroizing(&encrypted_b64)
            .await
            .map_err(|e| anyhow::anyhow!("failed to decrypt cookie secret: {e}"))?;
        return Ok(plaintext);
    }

    // Generate new cookie secret (64 bytes for cookie::Key)
    use rand::RngCore;
    let mut secret = Zeroizing::new(vec![0u8; 64]);
    rand::rng().fill_bytes(secret.as_mut_slice());

    let encoded = store
        .encrypt_active_to_base64(&secret)
        .await
        .map_err(|e| match e {
            crate::error::Error::Crypto(inner) => {
                anyhow::anyhow!("failed to encrypt cookie secret: {inner}")
            }
            other => anyhow::Error::new(other),
        })?;
    store.set_secret("cookie_secret", &encoded).await?;

    tracing::info!(
        target: "sekishod",
        "cookie secret generated and encrypted"
    );
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_capture::AuditCapture;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tower::ServiceExt;
    use tracing_subscriber::prelude::*;

    const LOWER_MASTER_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const UPPER_MASTER_KEY: &str =
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    #[tokio::test]
    async fn pre_signalled_serve_tls_returns_without_accepting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ctl = Arc::new(shutdown::ShutdownController::new());
        ctl.signal();
        let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
        let service = TlsService {
            app: axum::Router::new(),
            tcp_behavior: TcpBehavior::default(),
        };

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            serve_tls(
                listener,
                acceptor,
                service,
                Arc::new(AcceptFrom::any()),
                ctl.subscribe(),
            ),
        )
        .await
        .expect("pre-signalled TLS listener did not stop")
        .expect("TLS listener returned an error");
    }

    #[tokio::test]
    async fn listener_abort_completes_before_drain_audit() {
        struct DropFlag {
            dropped: Arc<AtomicBool>,
            audit_observed_at_drop: Arc<AtomicBool>,
            capture: AuditCapture,
        }

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.audit_observed_at_drop.store(
                    self.capture.find("daemon.shutdown.drain").is_some(),
                    Ordering::SeqCst,
                );
                self.dropped.store(true, Ordering::SeqCst);
            }
        }

        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let dropped = Arc::new(AtomicBool::new(false));
        let audit_observed_at_drop = Arc::new(AtomicBool::new(false));
        let drop_flag = DropFlag {
            dropped: dropped.clone(),
            audit_observed_at_drop: audit_observed_at_drop.clone(),
            capture: capture.clone(),
        };
        let task = tokio::spawn(async move {
            let _drop_flag = drop_flag;
            std::future::pending::<()>().await;
        });

        drain_listener_tasks(
            vec![task],
            Arc::new(shutdown::ShutdownController::new()),
            std::time::Duration::from_millis(20),
        )
        .await;

        assert!(
            dropped.load(Ordering::SeqCst),
            "listener task was not dropped before drain returned"
        );
        assert!(
            !audit_observed_at_drop.load(Ordering::SeqCst),
            "listeners-stopped audit was emitted before listener task drop"
        );
        assert!(
            capture.find("daemon.shutdown.drain").is_some(),
            "listeners-stopped audit was not emitted"
        );
    }

    #[tokio::test]
    async fn http_listener_stops_and_rejects_new_connections_after_signal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ctl = Arc::new(shutdown::ShutdownController::new());
        ctl.signal();
        let task = spawn_http_listener(listener, axum::Router::new(), ctl.clone());

        shutdown::join_tasks(
            vec![task],
            std::time::Duration::from_secs(1),
            "test-http-listener",
        )
        .await;

        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "HTTP listener accepted a new connection after shutdown join"
        );
    }

    fn http_request(uri: &str, host: Option<&[u8]>) -> axum::http::Request<axum::body::Body> {
        let mut request = axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        if let Some(host) = host {
            request.headers_mut().insert(
                axum::http::header::HOST,
                axum::http::HeaderValue::from_bytes(host).unwrap(),
            );
        }
        request
    }

    async fn assert_empty_response(
        response: axum::http::Response<axum::body::Body>,
        status: axum::http::StatusCode,
    ) {
        assert_eq!(response.status(), status);
        assert!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .is_none()
        );
        assert!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn http_redirect_uses_boot_auth_authority_and_published_route_host() {
        let store = Store::new_for_test("sqlite::memory:", [71; 32], None)
            .await
            .unwrap();
        let route: crate::models::route::Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "app",
            "from": "https://app.example",
            "to": ["http://127.0.0.1:9"],
            "access": {"allow_public_unauthenticated_access": true},
            "enabled": true
        }))
        .unwrap();
        store.create_route(&route).await.unwrap();
        let mut ipv6_route = route.clone();
        ipv6_route.id = uuid::Uuid::new_v4();
        ipv6_route.name = "ipv6".into();
        ipv6_route.from = "https://[2001:db8::1]".into();
        store.create_route(&ipv6_route).await.unwrap();
        let routes = crate::route_generation::RouteGeneration::new_for_test(store).await;
        let authority = crate::identity::IdentityAuthority::for_test("auth.example:8443");

        let auth = http_redirect_response(
            &http_request("/login?next=%2F", Some(b"AUTH.EXAMPLE:8443")),
            &routes,
            &authority,
        );
        assert_eq!(auth.status(), axum::http::StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            auth.headers()
                .get(axum::http::header::STRICT_TRANSPORT_SECURITY)
                .unwrap(),
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(
            auth.headers().get(axum::http::header::LOCATION).unwrap(),
            "https://auth.example:8443/login?next=%2F"
        );

        let route = http_redirect_response(
            &http_request("/dashboard?tab=1", Some(b"APP.EXAMPLE:8080")),
            &routes,
            &authority,
        );
        assert_eq!(route.status(), axum::http::StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            route.headers().get(axum::http::header::LOCATION).unwrap(),
            "https://app.example/dashboard?tab=1"
        );

        let ipv6 = http_redirect_response(
            &http_request("/status", Some(b"[2001:0db8::1]:80")),
            &routes,
            &authority,
        );
        assert_eq!(ipv6.status(), axum::http::StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            ipv6.headers().get(axum::http::header::LOCATION).unwrap(),
            "https://[2001:db8::1]/status"
        );

        assert_empty_response(
            http_redirect_response(
                &http_request("/", Some(b"auth.example:80")),
                &routes,
                &authority,
            ),
            axum::http::StatusCode::MISDIRECTED_REQUEST,
        )
        .await;

        routes.request_refresh();
        assert_empty_response(
            http_redirect_response(
                &http_request("/dashboard", Some(b"app.example")),
                &routes,
                &authority,
            ),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;
    }

    #[tokio::test]
    async fn http_redirect_rejects_untrusted_host_forms_without_location() {
        let store = Store::new_for_test("sqlite::memory:", [72; 32], None)
            .await
            .unwrap();
        let routes = crate::route_generation::RouteGeneration::new_ready_empty_for_test(store);
        let authority = crate::identity::IdentityAuthority::for_test("auth.example");

        for host in [
            None,
            Some(&b"unknown.example"[..]),
            Some(&b"auth.example:not-a-port"[..]),
            Some(&b"https://auth.example"[..]),
            Some(&b"\xff"[..]),
        ] {
            assert_empty_response(
                http_redirect_response(&http_request("/", host), &routes, &authority),
                axum::http::StatusCode::MISDIRECTED_REQUEST,
            )
            .await;
        }

        let mut duplicate = http_request("/", Some(b"auth.example"));
        duplicate.headers_mut().append(
            axum::http::header::HOST,
            axum::http::HeaderValue::from_static("app.example"),
        );
        assert_empty_response(
            http_redirect_response(&duplicate, &routes, &authority),
            axum::http::StatusCode::MISDIRECTED_REQUEST,
        )
        .await;
    }

    #[tokio::test]
    async fn http_redirect_fails_closed_until_route_snapshot_is_available() {
        let store = Store::new_for_test("sqlite::memory:", [73; 32], None)
            .await
            .unwrap();
        let routes = crate::route_generation::RouteGeneration::new(store);
        let authority = crate::identity::IdentityAuthority::for_test("auth.example");

        let auth = http_redirect_response(
            &http_request("/login", Some(b"AUTH.EXAMPLE:443")),
            &routes,
            &authority,
        );
        assert_eq!(auth.status(), axum::http::StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            auth.headers().get(axum::http::header::LOCATION).unwrap(),
            "https://auth.example/login"
        );

        assert_empty_response(
            http_redirect_response(
                &http_request("/", Some(b"app.example")),
                &routes,
                &authority,
            ),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;

        let route_only_authority = crate::identity::IdentityAuthority::from_boot(
            &crate::models::config::GlobalConfig::default(),
            &[],
        )
        .unwrap();
        assert_empty_response(
            http_redirect_response(
                &http_request("/", Some(b"app.example:not-a-port")),
                &routes,
                &route_only_authority,
            ),
            axum::http::StatusCode::MISDIRECTED_REQUEST,
        )
        .await;
        assert_empty_response(
            http_redirect_response(
                &http_request("/", Some(b"app.example")),
                &routes,
                &route_only_authority,
            ),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;
    }

    #[tokio::test]
    async fn http_redirect_allows_published_route_without_auth_domain() {
        let store = Store::new_for_test("sqlite::memory:", [76; 32], None)
            .await
            .unwrap();
        let route: crate::models::route::Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "route-only",
            "from": "https://app.example",
            "to": ["http://127.0.0.1:9"],
            "access": {"allow_public_unauthenticated_access": true},
            "enabled": true
        }))
        .unwrap();
        store.create_route(&route).await.unwrap();
        let routes = crate::route_generation::RouteGeneration::new_for_test(store).await;
        let authority = crate::identity::IdentityAuthority::from_boot(
            &crate::models::config::GlobalConfig::default(),
            &[],
        )
        .unwrap();

        let response = http_redirect_response(
            &http_request("/dashboard", Some(b"APP.EXAMPLE:80")),
            &routes,
            &authority,
        );
        assert_eq!(response.status(), axum::http::StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .unwrap(),
            "https://app.example/dashboard"
        );

        assert_empty_response(
            http_redirect_response(
                &http_request("/", Some(b"unknown.example")),
                &routes,
                &authority,
            ),
            axum::http::StatusCode::MISDIRECTED_REQUEST,
        )
        .await;
    }

    #[tokio::test]
    async fn acme_http01_route_takes_priority_over_redirect_fallback() {
        let store = Store::new_for_test("sqlite::memory:", [74; 32], None)
            .await
            .unwrap();
        let provider = Arc::new(crate::tls::acme::challenge::Http01Provider::new(
            store.clone(),
        ));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            provider,
            "https://acme.example/directory",
            None,
        ));
        let routes = crate::route_generation::RouteGeneration::new_ready_empty_for_test(store);
        let authority = Arc::new(crate::identity::IdentityAuthority::for_test("auth.example"));
        let app = build_http_listener_app(acme, routes, authority, Arc::new(AcceptFrom::any()));

        let response = app
            .oneshot(http_request(
                "/.well-known/acme-challenge/unknown-token",
                Some(b"auth.example"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        assert!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .is_none()
        );
    }

    #[tokio::test]
    async fn production_http_listener_negotiates_acme_redirect_and_unknown_host() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn raw_request(addr: std::net::SocketAddr, request: &[u8]) -> String {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(request).await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            String::from_utf8(response).unwrap()
        }

        async fn request(addr: std::net::SocketAddr, target: &str, host: &str) -> String {
            raw_request(
                addr,
                format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
        }

        let store = Store::new_for_test("sqlite::memory:", [75; 32], None)
            .await
            .unwrap();
        let provider = Arc::new(crate::tls::acme::challenge::Http01Provider::new(
            store.clone(),
        ));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            provider,
            "https://acme.example/directory",
            None,
        ));
        let routes = crate::route_generation::RouteGeneration::new_ready_empty_for_test(store);
        let authority = Arc::new(crate::identity::IdentityAuthority::for_test("auth.example"));
        let app = build_http_listener_app(acme, routes, authority, Arc::new(AcceptFrom::any()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ctl = Arc::new(shutdown::ShutdownController::new());
        let task = spawn_http_listener(listener, app, ctl.clone());

        let redirect = request(addr, "/login?next=%2F", "AUTH.EXAMPLE:443").await;
        assert!(redirect.starts_with("HTTP/1.1 301 Moved Permanently\r\n"));
        assert!(redirect.contains("location: https://auth.example/login?next=%2F\r\n"));

        let unknown = request(addr, "/", "unknown.example").await;
        assert!(unknown.starts_with("HTTP/1.1 421 Misdirected Request\r\n"));
        assert!(!unknown.to_ascii_lowercase().contains("\r\nlocation:"));

        let duplicate = raw_request(
            addr,
            b"GET / HTTP/1.1\r\nHost: auth.example\r\nHost: other.example\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(duplicate.starts_with("HTTP/1.1 421 Misdirected Request\r\n"));

        let missing = raw_request(addr, b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n").await;
        assert!(missing.starts_with("HTTP/1.1 421 Misdirected Request\r\n"));

        let challenge = request(
            addr,
            "/.well-known/acme-challenge/unknown-token",
            "auth.example",
        )
        .await;
        assert!(challenge.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(!challenge.to_ascii_lowercase().contains("\r\nlocation:"));

        ctl.signal();
        shutdown::join_tasks(
            vec![task],
            std::time::Duration::from_secs(1),
            "test-http-redirect-listener",
        )
        .await;
    }

    #[test]
    fn master_key_parser_accepts_exact_lower_and_upper_hex() {
        let expected = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        assert!(
            parse_master_key_file_bytes(Zeroizing::new(LOWER_MASTER_KEY.as_bytes().to_vec()))
                .unwrap()
                .matches_test_bytes(&expected)
        );
        assert!(
            parse_master_key_file_bytes(Zeroizing::new(UPPER_MASTER_KEY.as_bytes().to_vec()))
                .unwrap()
                .matches_test_bytes(&expected)
        );
    }

    #[test]
    fn master_key_file_parser_accepts_exact_lf_and_crlf() {
        for bytes in [
            LOWER_MASTER_KEY.as_bytes().to_vec(),
            format!("{LOWER_MASTER_KEY}\n").into_bytes(),
            format!("{LOWER_MASTER_KEY}\r\n").into_bytes(),
        ] {
            assert!(
                parse_master_key_file_bytes(Zeroizing::new(bytes))
                    .unwrap()
                    .matches_test_bytes(&[
                        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                        0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    ])
            );
        }
    }

    #[test]
    fn master_key_file_parser_rejects_other_whitespace() {
        for bytes in [
            format!(" {LOWER_MASTER_KEY}").into_bytes(),
            format!("{LOWER_MASTER_KEY} ").into_bytes(),
            format!("{LOWER_MASTER_KEY}\n\n").into_bytes(),
            vec![b'0'; 67],
        ] {
            assert!(parse_master_key_file_bytes(Zeroizing::new(bytes)).is_err());
        }
    }

    #[test]
    fn master_key_file_ingress_requires_a_path() {
        let error = resolve_master_key_from_file(None).unwrap_err();
        assert!(format!("{error}").contains("SEKISHO_MASTER_KEY_FILE"));
    }

    #[test]
    fn master_key_file_ingress_rejects_legacy_presence_before_file_access() {
        for legacy in [OsStr::new(""), OsStr::new(LOWER_MASTER_KEY)] {
            let error = resolve_master_key_from_sources(
                Some(legacy),
                Some(OsStr::new("/path/that/must/not/be/read")),
            )
            .unwrap_err();
            assert_eq!(
                error.downcast_ref::<MasterKeyLoadError>(),
                Some(&MasterKeyLoadError::LegacyEnvironmentPresent)
            );
            assert!(!format!("{error}").contains("/path/that/must/not/be/read"));
        }
    }

    #[test]
    fn master_key_parser_rejects_missing_bad_hex_length_and_whitespace() {
        assert_eq!(
            resolve_master_key_from_file(None)
                .unwrap_err()
                .downcast_ref::<MasterKeyLoadError>(),
            Some(&MasterKeyLoadError::MissingFilePath)
        );
        assert_eq!(
            parse_master_key_file_bytes(Zeroizing::new(
                b"g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_vec()
            ))
            .unwrap_err(),
            MasterKeyLoadError::InvalidHex
        );
        assert_eq!(
            parse_master_key_file_bytes(Zeroizing::new(b"0123".to_vec())).unwrap_err(),
            MasterKeyLoadError::InvalidLength
        );
        assert_eq!(
            parse_master_key_file_bytes(Zeroizing::new(
                b" 123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_vec()
            ))
            .unwrap_err(),
            MasterKeyLoadError::InvalidHex
        );
        assert_eq!(
            parse_master_key_file_bytes(Zeroizing::new(
                format!("{LOWER_MASTER_KEY}\n\n").into_bytes()
            ))
            .unwrap_err(),
            MasterKeyLoadError::InvalidLength,
        );
    }

    #[test]
    fn master_key_parser_rejects_non_utf8() {
        assert_eq!(
            parse_master_key_file_bytes(Zeroizing::new(vec![0xff; 64])).unwrap_err(),
            MasterKeyLoadError::InvalidHex
        );
    }

    #[test]
    fn master_key_audit_fields_and_errors_do_not_expose_secret() {
        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let error =
            resolve_master_key_from_file(Some(OsStr::new("/missing/master-key"))).unwrap_err();

        let event = capture.find("crypto.master_key.load").unwrap();
        assert_eq!(event.field("source"), Some("file"));
        assert_eq!(event.field("reason"), Some("master_key_file_read_failed"));
        assert!(!format!("{error}").contains("/missing/master-key"));
        assert!(
            !event
                .fields
                .values()
                .any(|value| value.contains("/missing/master-key"))
        );
    }

    #[test]
    fn master_key_success_audit_uses_file_source() {
        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let path =
            std::env::temp_dir().join(format!("sekisho-master-key-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, LOWER_MASTER_KEY).unwrap();

        let result = resolve_master_key_from_file(Some(path.as_os_str()));
        let _ = std::fs::remove_file(path);
        result.unwrap();

        let event = capture.find("crypto.master_key.load").unwrap();
        assert_eq!(event.field("result"), Some("success"));
        assert_eq!(event.field("source"), Some("file"));
    }

    #[test]
    fn master_key_wrong_length_has_auditable_reason_without_secret() {
        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let path =
            std::env::temp_dir().join(format!("sekisho-master-key-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, "0123").unwrap();
        let error = resolve_master_key_from_file(Some(path.as_os_str())).unwrap_err();
        let _ = std::fs::remove_file(path);
        let event = capture.find("crypto.master_key.load").unwrap();

        assert_eq!(event.field("reason"), Some("invalid_length"));
        assert!(!format!("{error}").contains("0123"));
        assert!(!event.fields.values().any(|value| value.contains("0123")));
    }

    #[test]
    fn compute_api_addrs_none_means_loopback_only() {
        assert_eq!(compute_api_addrs(None).unwrap(), vec![LOCALHOST_API]);
    }

    #[test]
    fn compute_api_addrs_empty_means_loopback_only() {
        assert_eq!(compute_api_addrs(Some("")).unwrap(), vec![LOCALHOST_API]);
        assert_eq!(compute_api_addrs(Some("   ")).unwrap(), vec![LOCALHOST_API]);
    }

    #[test]
    fn compute_api_addrs_loopback_match_dedups() {
        // Operator typed the literal default — must not bind it twice.
        assert_eq!(
            compute_api_addrs(Some("127.0.0.1:9443")).unwrap(),
            vec![LOCALHOST_API],
        );
    }

    #[test]
    fn compute_api_addrs_rejects_unspecified_ipv4() {
        assert!(compute_api_addrs(Some("0.0.0.0:9443")).is_err());
    }

    #[test]
    fn compute_api_addrs_rejects_unspecified_ipv6() {
        assert!(compute_api_addrs(Some("[::]:9443")).is_err());
    }

    #[test]
    fn compute_api_addrs_specific_ip_keeps_loopback_shadow() {
        // Specific IP: bind both so on-host tools (sekisho-cli) and
        // remote callers can both reach the API.
        let v = compute_api_addrs(Some("10.0.0.5:9443")).unwrap();
        assert_eq!(v, vec![LOCALHOST_API, "10.0.0.5:9443"]);
    }

    #[test]
    fn compute_api_addrs_rejects_garbage() {
        assert!(compute_api_addrs(Some("not-a-host-port")).is_err());
        assert!(compute_api_addrs(Some("0.0.0.0")).is_err());
    }

    #[tokio::test]
    async fn degraded_secret_initialization_preserves_startup_cause() {
        let store = Store::new_for_test_degraded("service DB offline")
            .await
            .unwrap();

        let err = ensure_cookie_secret(&store)
            .await
            .expect_err("degraded startup must not synthesize a cookie secret");

        assert!(matches!(
            err.downcast_ref::<crate::error::Error>(),
            Some(crate::error::Error::ServiceUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn cookie_failure_starts_no_route_observer_or_proxy_task() {
        let store = Store::new_for_test_degraded("service DB offline")
            .await
            .unwrap();
        let shutdown = Arc::new(shutdown::ShutdownController::new());
        let generation = crate::route_generation::RouteGeneration::new(store.clone());
        let provider = Arc::new(tls::acme::challenge::Http01Provider::new(store.clone()));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            provider,
            "https://acme.invalid/directory",
            None,
        ));

        let result = build_proxy_and_start_route_observer(
            store,
            Arc::clone(&generation),
            acme,
            MasterKey::from_test_bytes([0x51; 32]),
            IdentityKeyRingSnapshot::from_test_bytes([0x52; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            4,
            8,
            Arc::clone(&shutdown),
        )
        .await;

        assert!(
            result.is_err(),
            "degraded cookie bootstrap unexpectedly succeeded"
        );
        assert_eq!(generation.observer_counts_for_test(), (0, 0));
        assert_eq!(
            shutdown.tracked_task_count(),
            0,
            "cookie failure registered an observer or proxy cleanup task"
        );
    }

    #[tokio::test]
    async fn successful_proxy_construction_drops_cookie_before_starting_observer() {
        let store = Store::new_for_test("sqlite::memory:", [0x53; 32], None)
            .await
            .unwrap();
        let shutdown = Arc::new(shutdown::ShutdownController::new());
        let generation = crate::route_generation::RouteGeneration::new(store.clone());
        let provider = Arc::new(tls::acme::challenge::Http01Provider::new(store.clone()));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            provider,
            "https://acme.invalid/directory",
            None,
        ));

        let _proxy = build_proxy_and_start_route_observer(
            store,
            Arc::clone(&generation),
            acme,
            MasterKey::from_test_bytes([0x54; 32]),
            IdentityKeyRingSnapshot::from_test_bytes([0x55; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            4,
            8,
            Arc::clone(&shutdown),
        )
        .await
        .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            generation.wait_for_observer_iteration_for_test(),
        )
        .await
        .expect("route observer did not start");
        assert_eq!(generation.observer_counts_for_test(), (1, 1));

        shutdown.signal();
        shutdown
            .join_tracked_tasks(std::time::Duration::from_secs(1))
            .await;
        assert_eq!(generation.observer_counts_for_test(), (1, 1));
    }

    #[tokio::test]
    async fn cookie_secret_bootstrap_keeps_generated_and_loaded_bytes_zeroizing() {
        let store = Store::new_for_test("sqlite::memory:", [0x21; 32], None)
            .await
            .unwrap();

        let generated: zeroize::Zeroizing<Vec<u8>> = ensure_cookie_secret(&store).await.unwrap();
        let loaded: zeroize::Zeroizing<Vec<u8>> = ensure_cookie_secret(&store).await.unwrap();

        assert_eq!(generated.len(), 64);
        assert_eq!(&*loaded, &*generated);
    }
}
