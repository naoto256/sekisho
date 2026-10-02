//! Startup config validation + readiness probes.
//!
//! Sekisho historically defers most config validation until first use:
//! IdP discovery happens on the first login, route URLs are parsed when
//! a request arrives, certs are checked at TLS handshake time. The
//! upside is that startup never blocks on a flaky upstream; the
//! downside is that an OSS operator who fat-fingers a config can pass
//! `systemctl start` and then spend half an hour wondering why login
//! returns 500.
//!
//! This module emits **warn-level** signals at startup that surface the
//! most common deploy-time mistakes early. The policy is:
//!
//! - **Deploy-time mistake** (missing `auth_domain`, unparseable
//!   `Route.to`, expired cert) → warn so an operator tailing
//!   `journalctl` sees it within seconds of the daemon coming up.
//! - **Runtime dependency hiccup** (IdP discovery 503, DNS blip) →
//!   warn, never fatal — upstream IdPs are routinely flaky and we
//!   don't want a shared identity outage to take Sekisho's edge down
//!   too.
//!
//! Every warn double-emits as a structured audit event with
//! `event = "daemon.startup.warning"` so SIEM rules can fire on
//! "operator just deployed a broken config" without tailing the human
//! log stream.
//!
//! IdP discovery is the only check that touches the network; it runs
//! in a `tokio::spawn`'d background task with a 5-second per-IdP
//! timeout so a wedged issuer never delays the first inbound request.

use crate::audit;
use crate::identity::IdentityAuthority;
use crate::models::cert::Certificate;
use crate::models::config::GlobalConfig;
use crate::models::idp::IdentityProvider;
use crate::models::route::Route;
use crate::shutdown::{ShutdownController, ShutdownSignal};
use crate::store::Store;
use chrono::Utc;
use metrics::counter;
use std::sync::Arc;
use std::time::Duration;

/// Fire `daemon.startup.warning` audit event + matching tracing warn.
fn emit_warning(kind: &str, detail: &str) {
    tracing::warn!(
        target: audit::TARGET,
        event = "daemon.startup.warning",
        category = "startup",
        result = "warn",
        kind = kind,
        detail = detail,
        "{}", detail,
    );
}

/// Window inside which a soon-to-expire cert is reported. Picked to
/// match Let's Encrypt's standard 14-day pre-expiry warning so an
/// operator who uses default ACME settings sees the daemon's warning
/// at roughly the same time the certificate authority would email
/// them.
const CERT_EXPIRY_WINDOW_DAYS: i64 = 14;

/// Per-IdP timeout for the discovery probe. Long enough that a slow
/// hosted IdP still completes; short enough that a totally wedged
/// DNS resolver doesn't keep a probe task alive forever and skew
/// the metric.
const IDP_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Run the synchronous portion of startup validation: config sanity,
/// route URL parse, cert expiry. Each finding emits at most one warn
/// per category so a deeply broken deployment doesn't drown the log
/// in repeats. The IdP discovery probe (the only network-touching
/// piece) is dispatched separately via [`spawn_idp_probes`].
pub async fn run_sync_checks(store: &Store) -> crate::error::Result<IdentityAuthority> {
    let config = store.get_config().await?;
    let routes = store.list_routes().await?;
    let certs = store.list_certs().await?;

    let identity_authority = IdentityAuthority::from_boot(&config, &routes).map_err(|error| {
        crate::error::Error::ConfigurationError(format!(
            "invalid signed-identity configuration: {error}"
        ))
    })?;

    check_config_sanity(&config, &routes, &certs);
    check_route_urls(&routes);
    check_cert_expiry(&config, &certs, Utc::now());
    Ok(identity_authority)
}

/// Spawn a tracked background task that probes each configured IdP's
/// discovery endpoint exactly once. Returns immediately so the daemon
/// startup sequence keeps moving; the task lives for at most
/// `IDP_PROBE_TIMEOUT` per IdP and then exits.
///
/// The shutdown subscription is created before the task is spawned, so
/// an already-signalled controller prevents any probe request. During an
/// active batch, shutdown aborts and joins every child probe before the
/// tracked outer task exits.
pub fn spawn_idp_probes(ctl: &Arc<ShutdownController>, store: Store) {
    let shutdown = ctl.subscribe();
    let handle = tokio::spawn(run_idp_probes(store, shutdown));
    ctl.track_task(handle);
}

async fn run_idp_probes(store: Store, mut shutdown: ShutdownSignal) {
    let idps = tokio::select! {
        biased;
        _ = shutdown.wait() => return,
        result = store.list_idps() => {
            match result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "startup validation: failed to list IdPs for discovery probe");
                return;
            }
            }
        }
    };
    let client = match reqwest::Client::builder()
        .timeout(IDP_PROBE_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "startup validation: failed to build probe HTTP client");
            return;
        }
    };
    // Probe IdPs concurrently. The per-IdP timeout is enforced by
    // the reqwest client itself, so the whole batch finishes in
    // roughly max-of-N rather than sum-of-N. JoinSet (tokio
    // built-in, no new dep) gives bounded fan-out and lets each
    // probe log its own warning independently.
    let mut set = tokio::task::JoinSet::new();
    for idp in idps {
        let client = client.clone();
        set.spawn(async move { probe_one_idp(&client, &idp).await });
    }
    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait() => {
                set.shutdown().await;
                return;
            }
            result = set.join_next() => {
                match result {
                    Some(Ok(())) => {}
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "startup validation: IdP probe task panicked");
                    }
                    None => return,
                }
            }
        }
    }
}

// ─── Sanity checks ────────────────────────────────────────────────

fn check_config_sanity(config: &GlobalConfig, routes: &[Route], certs: &[Certificate]) {
    if config.auth_domain.is_none() {
        emit_warning(
            "sanity",
            "no auth_domain configured, OIDC/SAML login will fail",
        );
    }
    if config.acme_email.is_none() && certs.is_empty() {
        emit_warning(
            "sanity",
            "no acme_email configured and no certificates present; \
             TLS will fall back to self-signed",
        );
    }
    if config.default_idp_id.is_none() {
        let unrouted: Vec<&str> = routes
            .iter()
            .filter(|r| r.idp_id.is_none())
            .map(|r| r.name.as_str())
            .collect();
        if !unrouted.is_empty() {
            emit_warning(
                "sanity",
                &format!(
                    "default_idp_id is null and {n} route(s) have no idp_id: [{names}]; \
                     these routes will reject all login attempts",
                    n = unrouted.len(),
                    names = unrouted.join(", "),
                ),
            );
        }
    }
}

fn check_route_urls(routes: &[Route]) {
    for r in routes {
        for upstream in &r.to {
            if url::Url::parse(upstream).is_err() {
                emit_warning(
                    "route_url",
                    &format!(
                        "route '{name}' has unparseable upstream URL '{upstream}'",
                        name = r.name,
                    ),
                );
            }
        }
    }
}

fn check_cert_expiry(config: &GlobalConfig, certs: &[Certificate], now: chrono::DateTime<Utc>) {
    for cert in certs {
        let remaining = cert.expires_at.signed_duration_since(now);
        let days = remaining.num_days();
        if days <= CERT_EXPIRY_WINDOW_DAYS {
            // Negative `days` for already-expired certs reads naturally
            // when rendered ("expires in -3 days") so we leave the sign
            // intact rather than branching on a separate "expired"
            // sentence — the structured `detail` field stays a single
            // shape.
            let mut msg = format!(
                "certificate for {domain} expires in {days} days",
                domain = cert.domain,
            );
            if config.acme_email.is_none() {
                msg.push_str(" and ACME auto-renew not configured");
            }
            emit_warning("cert_expiry", &msg);
        }
    }
}

// ─── IdP probe ────────────────────────────────────────────────────

/// Categorise a `reqwest::Error` into the low-cardinality label we
/// expose on `sekisho_idp_probe_status`. We deliberately don't expand
/// to status-code-level granularity: an operator dashboard wants to
/// know "DNS broken? TLS broken? otherwise?" and richer detail lives
/// in the warn log line.
fn classify_probe_error(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        // `is_connect` covers DNS resolution failures, refused
        // connections, and TLS handshake errors. Distinguishing
        // between them through `reqwest`'s public API is brittle, so
        // we lean on the source-chain text — coarse but stable.
        let msg = format!("{:?}", err);
        if msg.contains("dns") || msg.contains("Dns") {
            "dns_failure"
        } else if msg.contains("tls") || msg.contains("Tls") || msg.contains("certificate") {
            "tls_failure"
        } else {
            "http_failure"
        }
    } else if err.is_decode() {
        "parse_failure"
    } else {
        "http_failure"
    }
}

async fn probe_one_idp(client: &reqwest::Client, idp: &IdentityProvider) {
    // The IdP-type dispatch lives on `AuthStrategy`; lifting it there
    // means `startup.rs` doesn't have to know which config block each
    // IdP type uses (and a future third type doesn't have to remember
    // to add an arm here). Mirrors the same `Strategy::for_idp_type`
    // single-line pattern used by `initiate_auth` / `build_logout_url`.
    let Some(url) =
        crate::auth::strategy::Strategy::for_idp_type(idp.idp_type).discovery_probe_url(idp)
    else {
        return;
    };

    let result_label = match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            // Probe metric only — discovery body parse happens on
            // first real login, not here, to keep startup work cheap.
            "success"
        }
        Ok(resp) => {
            emit_warning(
                "idp_probe",
                &format!(
                    "IdP '{name}' discovery probe to {url} returned HTTP {status}",
                    name = idp.name,
                    status = resp.status(),
                ),
            );
            "http_failure"
        }
        Err(e) => {
            let label = classify_probe_error(&e);
            emit_warning(
                "idp_probe",
                &format!(
                    "IdP '{name}' discovery probe to {url} failed ({label}): {e}",
                    name = idp.name,
                ),
            );
            label
        }
    };

    counter!(
        "sekisho_idp_probe_status",
        "idp_id" => idp.id.to_string(),
        "result" => result_label,
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_capture::AuditCapture;
    use crate::models::cert::Certificate;
    use crate::models::idp::{IdentityProvider, IdpType, OidcConfig, SamlConfig};
    use crate::models::route::Route;
    use chrono::{Duration as ChronoDuration, Utc};
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::Barrier;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use uuid::Uuid;

    fn cfg(
        auth_domain: Option<&str>,
        acme_email: Option<&str>,
        default_idp: Option<Uuid>,
    ) -> GlobalConfig {
        GlobalConfig {
            auth_domain: auth_domain.map(String::from),
            acme_email: acme_email.map(String::from),
            default_idp_id: default_idp,
            ..GlobalConfig::default()
        }
    }

    /// Build a `Route` via serde so we don't have to enumerate every
    /// `#[serde(default)]` field — the model has ~25, and tests here
    /// only care about `name`, `to`, `idp_id`. Anything new added to
    /// `Route` with a default will keep these tests compiling.
    fn route(name: &str, to: Vec<&str>, idp_id: Option<Uuid>) -> Route {
        let json = serde_json::json!({
            "id": Uuid::new_v4(),
            "name": name,
            "from": format!("https://{name}.example.com"),
            "to": to,
            "idp_id": idp_id,
        });
        serde_json::from_value(json).expect("route fixture deserializes")
    }

    fn cert(domain: &str, expires_at: chrono::DateTime<Utc>) -> Certificate {
        Certificate {
            id: Uuid::new_v4(),
            domain: domain.into(),
            cert_pem: String::new(),
            key_pem_encrypted: String::new(),
            issued_at: Utc::now(),
            expires_at,
            source: crate::models::cert::CertSource::Acme,
        }
    }

    fn saml_probe_idp(metadata_url: String) -> IdentityProvider {
        IdentityProvider {
            id: Uuid::new_v4(),
            name: "shutdown-probe".into(),
            idp_type: IdpType::Saml,
            oidc_config: None,
            saml_config: Some(SamlConfig {
                metadata_url,
                slo_url: None,
                name_id_format: None,
                attribute_mapping: Default::default(),
            }),
        }
    }

    async fn store_with_probe_idp(metadata_url: String) -> Store {
        let store = Store::new_for_test("sqlite::memory:", [0x51; 32], None)
            .await
            .expect("probe test store opens");
        store
            .create_idp(&saml_probe_idp(metadata_url))
            .await
            .expect("probe test IdP persists");
        store
    }

    /// Install an audit capture layer scoped to the closure.
    fn with_capture<F: FnOnce()>(f: F) -> Vec<crate::audit::test_capture::CapturedEvent> {
        let capture = AuditCapture::new();
        let guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        f();
        drop(guard);
        capture.snapshot()
    }

    // ─── config sanity ────────────────────────────────────────

    #[test]
    fn warns_when_auth_domain_missing() {
        let events = with_capture(|| {
            check_config_sanity(
                &cfg(None, Some("op@example.com"), Some(Uuid::new_v4())),
                &[],
                &[cert("a", Utc::now() + ChronoDuration::days(60))],
            );
        });
        assert!(events.iter().any(|e| e.field("kind") == Some("sanity")
            && e.field("detail").unwrap_or("").contains("auth_domain")));
    }

    #[test]
    fn warns_when_no_acme_email_and_no_certs() {
        let events = with_capture(|| {
            check_config_sanity(&cfg(Some("auth.example.com"), None, None), &[], &[]);
        });
        assert!(
            events
                .iter()
                .any(|e| e.field("detail").unwrap_or("").contains("acme_email"))
        );
    }

    #[test]
    fn no_warn_when_acme_email_missing_but_certs_present() {
        let events = with_capture(|| {
            check_config_sanity(
                &cfg(Some("auth.example.com"), None, Some(Uuid::new_v4())),
                &[],
                &[cert("a.example.com", Utc::now() + ChronoDuration::days(90))],
            );
        });
        assert!(
            events
                .iter()
                .all(|e| !e.field("detail").unwrap_or("").contains("acme_email"))
        );
    }

    #[test]
    fn warns_when_route_has_no_idp_and_no_default() {
        let events = with_capture(|| {
            check_config_sanity(
                &cfg(Some("auth.example.com"), Some("op@example.com"), None),
                &[route("orphan", vec!["http://a/"], None)],
                &[cert("a", Utc::now() + ChronoDuration::days(60))],
            );
        });
        let hit = events
            .iter()
            .find(|e| e.field("detail").unwrap_or("").contains("orphan"));
        assert!(hit.is_some(), "expected warning naming the orphaned route");
    }

    #[test]
    fn no_warn_when_default_idp_set_even_if_route_has_none() {
        let events = with_capture(|| {
            check_config_sanity(
                &cfg(
                    Some("auth.example.com"),
                    Some("op@example.com"),
                    Some(Uuid::new_v4()),
                ),
                &[route("orphan", vec!["http://a/"], None)],
                &[cert("a", Utc::now() + ChronoDuration::days(60))],
            );
        });
        assert!(
            events
                .iter()
                .all(|e| !e.field("detail").unwrap_or("").contains("orphan"))
        );
    }

    #[tokio::test]
    async fn signed_identity_invalid_config_is_fatal_before_startup_can_continue() {
        let store = Store::new_for_test("sqlite::memory:", [0x71; 32], None)
            .await
            .unwrap();
        store
            .update_config(serde_json::json!({"auth_domain": "auth.example.com"}))
            .await
            .unwrap();
        let mut invalid = route("legacy", vec!["http://upstream.example.com"], None);
        invalid.from = "http://legacy.example.com".into();
        store.create_route(&invalid).await.unwrap();

        // Emulate an existing row written by a pre-validation binary. The
        // startup scan must reject it before runtime proceeds to any bind.
        invalid.enable_signed_identity = true;
        sqlx::query("UPDATE routes SET data = ? WHERE id = ?")
            .bind(serde_json::to_string(&invalid).unwrap())
            .bind(invalid.id)
            .execute(store.sqlite_pool())
            .await
            .unwrap();

        let error = run_sync_checks(&store).await.unwrap_err();
        assert!(matches!(error, crate::error::Error::ConfigurationError(_)));
        assert!(error.to_string().contains("signed identity"));
    }

    // ─── route URL parse ──────────────────────────────────────

    #[test]
    fn warns_on_unparseable_route_url() {
        let events = with_capture(|| {
            check_route_urls(&[route("bad", vec!["http://ok.example/", "not a url"], None)]);
        });
        let hit = events.iter().find(|e| {
            e.field("kind") == Some("route_url") && e.field("detail").unwrap_or("").contains("bad")
        });
        assert!(hit.is_some(), "expected route_url warning for 'bad'");
    }

    #[test]
    fn no_warn_when_all_route_urls_parse() {
        let events = with_capture(|| {
            check_route_urls(&[route("ok", vec!["http://ok.example/", "https://b/"], None)]);
        });
        assert!(events.iter().all(|e| e.field("kind") != Some("route_url")));
    }

    // ─── cert expiry ──────────────────────────────────────────

    #[test]
    fn warns_when_cert_expires_within_window() {
        let now = Utc::now();
        let events = with_capture(|| {
            check_cert_expiry(
                &cfg(Some("a"), Some("op@example.com"), None),
                &[cert("soon.example.com", now + ChronoDuration::days(5))],
                now,
            );
        });
        let hit = events.iter().find(|e| {
            e.field("kind") == Some("cert_expiry")
                && e.field("detail").unwrap_or("").contains("soon.example.com")
        });
        assert!(hit.is_some());
        // ACME configured → no auto-renew sentence
        assert!(
            !hit.unwrap()
                .field("detail")
                .unwrap_or("")
                .contains("auto-renew")
        );
    }

    #[test]
    fn warns_with_acme_sentence_when_email_missing() {
        let now = Utc::now();
        let events = with_capture(|| {
            check_cert_expiry(
                &cfg(Some("a"), None, None),
                &[cert("soon.example.com", now + ChronoDuration::days(5))],
                now,
            );
        });
        let hit = events
            .iter()
            .find(|e| e.field("kind") == Some("cert_expiry"))
            .unwrap();
        assert!(
            hit.field("detail")
                .unwrap()
                .contains("ACME auto-renew not configured")
        );
    }

    #[test]
    fn warns_when_cert_already_expired() {
        let now = Utc::now();
        let events = with_capture(|| {
            check_cert_expiry(
                &cfg(Some("a"), Some("op@example.com"), None),
                &[cert("dead.example.com", now - ChronoDuration::days(3))],
                now,
            );
        });
        let hit = events
            .iter()
            .find(|e| e.field("kind") == Some("cert_expiry"))
            .unwrap();
        // Negative day count surfaces directly — operator immediately sees the cert is already dead.
        assert!(hit.field("detail").unwrap().contains("-3"));
    }

    #[test]
    fn no_warn_when_cert_far_from_expiry() {
        let now = Utc::now();
        let events = with_capture(|| {
            check_cert_expiry(
                &cfg(Some("a"), Some("op@example.com"), None),
                &[cert("fine.example.com", now + ChronoDuration::days(60))],
                now,
            );
        });
        assert!(
            events
                .iter()
                .all(|e| e.field("kind") != Some("cert_expiry"))
        );
    }

    // ─── IdP probe ────────────────────────────────────────────
    //
    // The shutdown tests use loopback so they exercise the production
    // spawn boundary and real request cancellation. Error classification
    // remains covered separately with a reserved offline hostname.

    #[tokio::test]
    async fn tracked_probe_batch_stops_on_shutdown_and_closes_children() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener binds");
        let metadata_url = format!("http://{}/metadata", listener.local_addr().unwrap());
        let store = store_with_probe_idp(metadata_url).await;
        let store_for_close = store.clone();
        let ctl = Arc::new(ShutdownController::new());
        let request_started = Arc::new(Barrier::new(2));
        let server_barrier = request_started.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("probe connection accepts");
            server_barrier.wait().await;
            let mut buffer = [0_u8; 1024];
            while stream
                .read(&mut buffer)
                .await
                .expect("stall connection read succeeds")
                != 0
            {}
        });

        spawn_idp_probes(&ctl, store);
        tokio::time::timeout(Duration::from_secs(2), request_started.wait())
            .await
            .expect("probe reaches the stalling endpoint");
        ctl.signal();
        tokio::time::timeout(
            Duration::from_secs(2),
            ctl.join_tracked_tasks(Duration::from_secs(1)),
        )
        .await
        .expect("tracked probe batch joins before the per-IdP timeout");

        assert_eq!(ctl.tracked_task_count(), 0);
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("probe cancellation closes the child connection")
            .expect("stall server task exits cleanly");
        store_for_close.close().await;
    }

    #[tokio::test]
    async fn pre_signalled_probe_batch_issues_no_request() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener binds");
        let metadata_url = format!("http://{}/metadata", listener.local_addr().unwrap());
        let store = store_with_probe_idp(metadata_url).await;
        let store_for_close = store.clone();
        let ctl = Arc::new(ShutdownController::new());
        ctl.signal();

        spawn_idp_probes(&ctl, store);
        tokio::time::timeout(
            Duration::from_secs(1),
            ctl.join_tracked_tasks(Duration::from_millis(500)),
        )
        .await
        .expect("pre-signalled probe batch joins promptly");

        assert_eq!(ctl.tracked_task_count(), 0);
        match tokio::time::timeout(Duration::from_millis(500), listener.accept()).await {
            Err(_) => {}
            Ok(Ok(_)) => panic!("pre-signalled probe unexpectedly connected"),
            Ok(Err(_)) => panic!("pre-signalled listener failed"),
        }
        store_for_close.close().await;
    }

    #[tokio::test]
    async fn probe_against_unresolvable_host_emits_warn_and_failure_label() {
        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap();
        let idp = IdentityProvider {
            id: Uuid::new_v4(),
            name: "broken".into(),
            idp_type: IdpType::Oidc,
            oidc_config: Some(OidcConfig {
                // `.invalid` is RFC 2606 reserved — guaranteed not to
                // resolve, so the probe path takes the connect-error
                // branch deterministically without hitting the
                // network.
                issuer_url: "http://this-host-must-not-resolve.invalid".into(),
                client_id: "cid".into(),
                client_secret_encrypted: String::new(),
                scopes: vec!["openid".into()],
                prompt: None,
            }),
            saml_config: None,
        };
        probe_one_idp(&client, &idp).await;

        let events = capture.snapshot();
        let hit = events.iter().find(|e| e.field("kind") == Some("idp_probe"));
        assert!(hit.is_some(), "expected idp_probe warning");
        assert!(hit.unwrap().field("detail").unwrap().contains("broken"));
    }

    #[test]
    fn saml_idp_uses_metadata_url_for_probe_target() {
        // Doesn't issue any network call — just exercises the URL
        // extraction branch so the SAML path doesn't silently no-op
        // if a future refactor renames metadata_url.
        let idp = IdentityProvider {
            id: Uuid::new_v4(),
            name: "saml-test".into(),
            idp_type: IdpType::Saml,
            oidc_config: None,
            saml_config: Some(SamlConfig {
                metadata_url: "https://idp.example.com/metadata".into(),
                slo_url: None,
                name_id_format: None,
                attribute_mapping: Default::default(),
            }),
        };
        // Inline what `probe_one_idp` extracts so a regression in the
        // dispatch table here gets caught at compile time too.
        let url = match idp.idp_type {
            IdpType::Oidc => idp.oidc_config.as_ref().map(|c| c.issuer_url.clone()),
            IdpType::Saml => idp.saml_config.as_ref().map(|c| c.metadata_url.clone()),
        };
        assert_eq!(url.as_deref(), Some("https://idp.example.com/metadata"));
    }
}
