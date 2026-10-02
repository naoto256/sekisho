//! `sekishoweb` — the admin web UI.
//!
//! Server-rendered with maud and HTMX: no client-side framework, no JSON API
//! of its own, no build step. It is a BFF over the daemon's management API,
//! and holds no database.
//!
//! ## Handwritten per resource, not schema-driven
//!
//! An earlier design rendered generic CRUD from a schema the daemon served.
//! It was removed: UI-only concerns leaked into the server's data model while
//! the client still hard-coded per-resource behaviour anyway, so the split
//! bought neither decoupling nor a good UI. Now each resource owns its own
//! handlers and views, and the startup `/version` handshake is what keeps the
//! compiled-in knowledge honest.
//!
//! ## A version mismatch degrades, it does not refuse
//!
//! Unlike the CLI, which exits, the web UI records the outcome in
//! [`ServerVersion`] and renders a badge. The reasoning is that the operator
//! is often here *because* something is wrong, and a UI that refuses to load
//! removes the tool they would use to fix it. A matching pair renders nothing
//! at all — silence is the right output when there is nothing to say.
//!
//! ## Binds loopback, and does not share the daemon's database
//!
//! Everything goes through the management API over pinned TLS. Pointing this
//! at the daemon's database directly would give it a second writer with none
//! of the admission validation the API applies.

mod assets;
mod auth;
mod client;
mod config;
mod csrf;
mod handlers;
mod registry;
mod security_headers;
mod tls_serve;
mod views;
mod yaml_config;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::sync::{Arc, RwLock};

use crate::auth::Credential;
use crate::auth::guard::{GuardMode, SharedGuard};
use crate::client::SekishoClient;
use crate::config::Args;
use crate::yaml_config::WebuiConfig;

/// Compile-time build tag; checked against the server's `/version`
/// response on startup. Clients refuse to run against a mismatched
/// server because the resource registry is version-locked.
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version-handshake outcome captured at startup. Held in `AppState`
/// so the layout can render a compact mismatch / unreachable badge in
/// the nav without re-fetching `/version` per page render. A matching
/// pair renders no badge at all — silent is the right posture when
/// nothing is wrong.
#[derive(Debug, Clone)]
pub enum ServerVersion {
    /// Server reported a version that matches `CLIENT_VERSION` exactly.
    Match,
    /// Server reported a different version. Stored verbatim so the
    /// badge can show both ends of the drift.
    Mismatch(String),
    /// `/version` was unreachable at startup (server still booting,
    /// network blip). Sekisho refuses to hard-fail on this so the UI
    /// still renders — the badge surfaces the uncertainty.
    Unreachable,
}

/// Shared per-request state. Cloned into every handler, so each field is
/// either cheap to clone or behind an `Arc`.
#[derive(Clone)]
pub struct AppState {
    /// Loaded + validated YAML config. Field name is preserved
    /// from the previous Args-based shape so downstream handlers
    /// (`state.args.sekisho_api_url`) keep compiling without churn.
    pub args: Arc<WebuiConfig>,
    pub cred: crate::auth::SharedCredential,
    pub client: SekishoClient,
    pub guard: SharedGuard,
    /// Outcome of the startup `/version` handshake. A `std::sync`
    /// `RwLock` (rather than `tokio::sync`) lets the synchronous
    /// `render_page` helper read it without an async context — the
    /// critical section is a clone of a tiny enum, so contention with
    /// any future reconcile-tick writer is negligible.
    pub server_version: Arc<RwLock<ServerVersion>>,
    pub management_rpk_pin: Arc<sekisho_api_protocol::management_rpk::ManagementRpkPin>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,sekisho-webui=debug")),
        )
        .init();

    let cli = Args::parse();
    let cfg = WebuiConfig::load_with_management_rpk_pin(&cli.config, cli.management_rpk_pin)
        .with_context(|| format!("loading webui config from {}", cli.config.display()))?;
    let management_rpk_pin: sekisho_api_protocol::management_rpk::ManagementRpkPin = cfg
        .management_rpk_pin
        .as_deref()
        .expect("validated management RPK pin")
        .parse()
        .context("parse management_rpk_pin")?;
    tracing::info!(%cfg.listen, %cfg.sekisho_api_url, config = %cli.config.display(), "sekisho-webui starting");

    // Credential: either local-auth (starts authenticated + self-refreshing),
    // a pre-seeded api_key from YAML, or admin-entered API key (setup flow
    // populates this lazily).
    let cred = auth::new_shared(Credential::None);
    if let Some(local) = &cfg.auth.local_auth {
        let (token, expires_at) =
            auth::local::authenticate(&cfg.sekisho_api_url, &local.socket, &management_rpk_pin)
                .await
                .context("initial local-auth challenge failed")?;
        tracing::info!(%expires_at, "obtained local-auth session token");
        *cred.write().await = Credential::LocalSession { token, expires_at };
        auth::local::spawn_refresh_loop(
            cfg.sekisho_api_url.clone(),
            local.socket.clone(),
            cred.clone(),
            management_rpk_pin.clone(),
        );
    } else if let Some(api_key) = &cfg.auth.api_key {
        tracing::info!("using api_key credential from webui.yaml");
        *cred.write().await = Credential::ApiKey(api_key.clone());
    }

    let client = SekishoClient::new(
        cfg.sekisho_api_url.clone(),
        cred.clone(),
        &management_rpk_pin,
    )?;

    // Version handshake: surface the result through a nav badge rather
    // than refusing to start. Mismatched pairs are still loud — the
    // operator sees the badge on every page and the warning log
    // points them at the matching binary — but a mid-rolling-deploy
    // node should still serve its UI so the operator can see what
    // happened.
    let server_version = match client.get_unauthenticated_version().await {
        Ok(v) if v == CLIENT_VERSION => {
            tracing::info!(version = %v, "sekisho server version matches");
            ServerVersion::Match
        }
        Ok(v) => {
            tracing::warn!(
                client_version = CLIENT_VERSION,
                server_version = %v,
                "version mismatch: the UI ships with a version-locked resource model; rebuild / \
                 reinstall the matching sekisho-webui binary"
            );
            ServerVersion::Mismatch(v)
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not reach /version at startup — proceeding");
            ServerVersion::Unreachable
        }
    };

    // Guard selection. JWT mode requires a complete public JWKS before the
    // listener is bound; refreshes retain the last verified set on failure.
    let guard_mode =
        match (&cfg.guard.trust_sekisho_jwt, &cfg.guard.basic_auth) {
            (Some(_), Some(_)) => {
                return Err(anyhow!(
                    "guard.trust_sekisho_jwt and guard.basic_auth are mutually exclusive"
                ));
            }
            (Some(jwt), None) => {
                // sekisho-webui's guard takes a single URL today (no
                // failover). Honour the first list entry; warn if more
                // were supplied so the operator knows only one is in use.
                let api_url =
                    jwt.sekisho_api_urls.first().cloned().ok_or_else(|| {
                        anyhow!("guard.trust_sekisho_jwt.sekisho_api_urls is empty")
                    })?;
                if jwt.sekisho_api_urls.len() > 1 {
                    tracing::warn!(
                        count = jwt.sekisho_api_urls.len(),
                        used = %api_url,
                        "guard.trust_sekisho_jwt.sekisho_api_urls has more than one entry; \
                         sekisho-webui has no multi-URL failover — only the first entry is used"
                    );
                }
                let constraints = auth::guard::JwtConstraints {
                    expected_aud: jwt.expected_aud.clone().ok_or_else(|| {
                        anyhow!("guard.trust_sekisho_jwt.expected_aud is required")
                    })?,
                    expected_iss: jwt.expected_iss.clone().ok_or_else(|| {
                        anyhow!("guard.trust_sekisho_jwt.expected_iss is required")
                    })?,
                };
                let keys = auth::guard::shared_jwks(
                    auth::guard::fetch_jwks(&api_url, &management_rpk_pin)
                        .await
                        .context("load initial public identity JWKS before listener bind")?,
                );
                auth::guard::spawn_refresh_loop(keys.clone(), api_url, management_rpk_pin.clone());
                tracing::info!("loaded public identity JWKS; trusting EdDSA X-Sekisho-Jwt");
                GuardMode::TrustSekishoJwt { keys, constraints }
            }
            (None, Some(raw)) => auth::guard::parse_basic_auth(raw)?,
            (None, None) => {
                tracing::warn!(
                    "neither guard.trust_sekisho_jwt nor guard.basic_auth is set; \
                 sekisho-webui is unprotected — ensure it is fronted by a reverse proxy \
                 or bound to a trusted network"
                );
                GuardMode::None
            }
        };
    let guard = auth::guard::shared(guard_mode);

    let listen = cfg.listen;
    // Build the rustls config up front (before move into AppState)
    // so a misconfigured cert/key fails the boot rather than the
    // first incoming request.
    let tls_config = if let Some(tls) = &cfg.tls {
        Some(tls_serve::load_server_config(&tls.cert, &tls.key)?)
    } else {
        None
    };
    let state = AppState {
        args: Arc::new(cfg),
        cred,
        client,
        guard,
        server_version: Arc::new(RwLock::new(server_version)),
        management_rpk_pin: Arc::new(management_rpk_pin),
    };

    let app = handlers::router(state)
        .layer(axum::middleware::from_fn(security_headers::middleware))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower_http::compression::CompressionLayer::new());

    let listener = tokio::net::TcpListener::bind(listen).await?;
    if let Some(tls_config) = tls_config {
        tracing::info!(listen = %listen, "sekisho-webui ready (TLS terminated locally)");
        tls_serve::serve(listener, tls_config, app).await?;
    } else {
        tracing::info!(listen = %listen, "sekisho-webui ready (plain HTTP — front with a TLS proxy)");
        axum::serve(listener, app).await?;
    }
    Ok(())
}
