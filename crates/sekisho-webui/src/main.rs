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
//! handlers and views, and the startup API-version handshake keeps the
//! compiled-in knowledge honest.
//!
//! ## Product skew warns; API skew refuses
//!
//! A product-version mismatch is recorded in [`ServerVersion`] and rendered as
//! a badge. An API-version mismatch refuses startup because the UI's compiled
//! resource knowledge is unsafe against an incompatible management contract.
//! Failure to obtain or classify `/version` also refuses startup: the UI must
//! establish compatibility before it can issue management operations.
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

/// Compile-time product version used for diagnostics. Management compatibility
/// is gated separately by `sekisho_api_protocol::version::API_VERSION`.
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version-handshake outcome captured at startup. Held in `AppState`
/// so the layout can render a compact product-mismatch badge in the nav
/// without re-fetching `/version` per page render. A matching pair renders the
/// normal compact green version badge.
#[derive(Debug, Clone)]
pub enum ServerVersion {
    /// Server reported a version that matches `CLIENT_VERSION` exactly.
    Match,
    /// Server reported a different product version but a compatible API.
    Mismatch(String),
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
    /// critical section is a clone of a tiny enum.
    pub server_version: Arc<RwLock<ServerVersion>>,
    pub management_rpk_pin: Arc<sekisho_api_protocol::management_rpk::ManagementRpkPin>,
}

/// Turn a compatibility verdict into the startup decision.
///
/// `Ok` carries the badge state for a usable daemon; `Err` refuses startup.
fn server_version_state(
    compatibility: sekisho_api_protocol::version::VersionCompatibility,
) -> Result<ServerVersion> {
    use sekisho_api_protocol::version::{API_VERSION, VersionCompatibility};

    match compatibility {
        VersionCompatibility::Match => Ok(ServerVersion::Match),
        VersionCompatibility::ProductMismatch { server_version } => {
            Ok(ServerVersion::Mismatch(server_version))
        }
        VersionCompatibility::ApiMismatch {
            server_api_version, ..
        } => Err(anyhow!(
            "management API version mismatch: sekisho-webui supports v{API_VERSION}, \
             daemon reports v{server_api_version}"
        )),
        VersionCompatibility::InvalidResponse { reason } => {
            Err(anyhow!("invalid /version response: {reason}"))
        }
    }
}

/// Require the startup probe to establish a compatibility verdict while
/// retaining its transport/response context in the returned error.
fn startup_server_version(
    probe: std::result::Result<
        sekisho_api_protocol::version::VersionCompatibility,
        client::VersionProbeError,
    >,
) -> Result<ServerVersion> {
    probe
        .map_err(anyhow::Error::new)
        .and_then(server_version_state)
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

    let client = SekishoClient::new(
        cfg.sekisho_api_url.clone(),
        cred.clone(),
        &management_rpk_pin,
    )?;

    // Product-version skew remains visible during rolling upgrades. Establish
    // API compatibility before installing the configured credential or
    // starting local auth, before the listener is bound, and before any
    // management operation is issued.
    let server_version =
        startup_server_version(client.get_unauthenticated_version(CLIENT_VERSION).await)?;
    match &server_version {
        ServerVersion::Match => {
            tracing::info!(
                product_version = CLIENT_VERSION,
                api_version = sekisho_api_protocol::version::API_VERSION,
                "sekisho server API is compatible"
            );
        }
        ServerVersion::Mismatch(server_version) => {
            tracing::warn!(
                client_version = CLIENT_VERSION,
                server_version = %server_version,
                api_version = sekisho_api_protocol::version::API_VERSION,
                "product version differs; management API is compatible, continuing"
            );
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use sekisho_api_protocol::version::{API_VERSION, VersionCompatibility};

    #[test]
    fn product_mismatch_keeps_the_ui_available() {
        let state = server_version_state(VersionCompatibility::ProductMismatch {
            server_version: "9.9.9".to_string(),
        })
        .unwrap();
        assert!(matches!(state, ServerVersion::Mismatch(version) if version == "9.9.9"));
    }

    #[test]
    fn api_mismatch_refuses_startup() {
        let error = server_version_state(VersionCompatibility::ApiMismatch {
            server_version: "0.1.1".to_string(),
            server_api_version: API_VERSION + 1,
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("management API version mismatch")
        );
    }

    #[test]
    fn malformed_version_response_refuses_startup() {
        let error = server_version_state(VersionCompatibility::InvalidResponse {
            reason: "bad api_version".to_string(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("invalid /version response"));
    }

    #[test]
    fn unreachable_version_endpoint_refuses_startup_with_context() {
        let error = startup_server_version(Err(client::VersionProbeError::Unreachable(
            "connection refused".to_string(),
        )))
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("GET /version failed"), "{message}");
        assert!(message.contains("connection refused"), "{message}");
    }

    #[test]
    fn invalid_version_response_refuses_startup_with_context() {
        let error = startup_server_version(Err(client::VersionProbeError::InvalidResponse(
            "decode JSON: expected value".to_string(),
        )))
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("invalid /version response"), "{message}");
        assert!(message.contains("decode JSON"), "{message}");
    }

    #[test]
    fn compatibility_probe_precedes_local_auth_and_listener_bind() {
        let source = include_str!("main.rs");
        let probe = source
            .find("startup_server_version(client.get_unauthenticated_version")
            .expect("startup compatibility probe");
        let local_auth = source
            .find("auth::local::authenticate")
            .expect("local-auth exchange");
        let listener = source.find("TcpListener::bind").expect("listener bind");
        assert!(
            probe < local_auth && probe < listener,
            "compatibility must be established before auth exchange and listener bind"
        );
    }
}
