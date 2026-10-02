//! Access control for sekisho-webui itself (distinct from credentials used
//! against the upstream Sekisho API).
//!
//! Modes, configured via CLI:
//!
//! * `guard.trust_sekisho_jwt` — verify the EdDSA `X-Sekisho-Jwt` header
//!   locally against Sekisho's public JWKS. Startup fails before listener
//!   bind if the initial JWKS cannot be loaded.
//! * `--basic-auth user:argon2:<PHC-hash>` — RFC 7617 Basic auth against an
//!   Argon2id hash. `user:plain:<password>` is also accepted for dev use and
//!   is hashed on the fly at startup.
//! * neither — requests pass through. sekisho-webui is expected to be protected
//!   by a front-end (reverse proxy / VPN / firewall). A warning is logged
//!   at startup.
//!
//! Submodules carry the scheme-specific machinery; this module wires them
//! together behind a single axum middleware.

mod basic;
mod jwt;

pub use basic::parse_basic_auth;
pub use jwt::{fetch_jwks, shared as shared_jwks, spawn_refresh_loop};

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::AppState;

/// Exact issuer and audience constraints applied to every verified token.
#[derive(Debug, Clone)]
pub struct JwtConstraints {
    pub expected_aud: String,
    pub expected_iss: String,
}

#[derive(Clone)]
pub enum GuardMode {
    /// No guard — sekisho-webui is wide open.
    None,
    /// Verify `X-Sekisho-Jwt` locally with a refreshable public JWKS.
    TrustSekishoJwt {
        keys: jwt::SharedJwks,
        constraints: JwtConstraints,
    },
    /// HTTP Basic with the user's password stored as a PHC-format Argon2
    /// hash (e.g. `$argon2id$v=19$m=...$...$...`). Verification is done by
    /// the `argon2` crate and uses a constant-time tag compare internally.
    Basic { user: String, password_hash: String },
}

impl std::fmt::Debug for GuardMode {
    // Public JWK bytes are not secrets, but omit them from logs to keep the
    // mode summary stable across rotation. The PHC password hash is redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardMode::None => f.write_str("GuardMode::None"),
            GuardMode::TrustSekishoJwt { constraints, .. } => f
                .debug_struct("GuardMode::TrustSekishoJwt")
                .field("keys", &"<public JWKS>")
                .field("constraints", constraints)
                .finish(),
            GuardMode::Basic { user, .. } => f
                .debug_struct("GuardMode::Basic")
                .field("user", user)
                .field("password_hash", &"<redacted>")
                .finish(),
        }
    }
}

pub type SharedGuard = std::sync::Arc<tokio::sync::RwLock<GuardMode>>;

pub fn shared(mode: GuardMode) -> SharedGuard {
    std::sync::Arc::new(tokio::sync::RwLock::new(mode))
}

/// Identity extracted from a verified guard credential. Handlers that want
/// to show the current user can read it from request extensions.
#[derive(Debug, Clone)]
#[allow(dead_code)] // `email` and `groups` are reserved for future per-user audit logging.
pub struct AuthenticatedUser {
    pub user: String,
    pub email: String,
    pub groups: Vec<String>,
}

/// Decoded JWT claims — shared shape for local and remote verification
/// paths; kept private to the guard module hierarchy.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // `aud`/`iss` surface for future logging or per-claim policy.
pub(crate) struct IdentityClaims {
    pub sub: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
}

pub async fn guard(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    // Snapshot the mode so we release the read lock before awaiting the
    // downstream handler.
    let mode = { state.guard.read().await.clone() };
    match mode {
        GuardMode::None => next.run(request).await,
        GuardMode::TrustSekishoJwt { keys, constraints } => {
            match jwt::verify_local(request.headers(), &*keys.read().await, &constraints) {
                Ok(claims) => {
                    request.extensions_mut().insert(AuthenticatedUser {
                        user: claims.sub,
                        email: claims.email,
                        groups: claims.groups,
                    });
                    next.run(request).await
                }
                Err(e) => {
                    tracing::warn!(error = %e, "JWT guard rejected request");
                    unauthorized_plain("missing or invalid X-Sekisho-Jwt")
                }
            }
        }
        GuardMode::Basic {
            user,
            password_hash,
        } => match basic::verify_basic(request.headers(), &user, &password_hash) {
            Ok(()) => {
                request.extensions_mut().insert(AuthenticatedUser {
                    user: user.clone(),
                    email: String::new(),
                    groups: Vec::new(),
                });
                next.run(request).await
            }
            Err(_) => basic::basic_challenge(),
        },
    }
}

fn unauthorized_plain(msg: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, msg).into_response()
}

#[cfg(test)]
mod redaction_tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn debug_identifies_public_jwks_without_material() {
        let public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let jwks = jwt::Jwks::parse(
            serde_json::json!({"keys":[{
                "kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig",
                "kid":"example-kid","x":public
            }]})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let mode = GuardMode::TrustSekishoJwt {
            keys: jwt::shared(jwks),
            constraints: JwtConstraints {
                expected_aud: "https://admin.example.com".into(),
                expected_iss: "https://auth.example.com".into(),
            },
        };
        let s = format!("{mode:?}");
        assert!(!s.contains("example-kid"), "unexpected key material: {s}");
        assert!(s.contains("public JWKS"), "should identify source: {s}");
    }

    #[test]
    fn debug_does_not_leak_password_hash() {
        let mode = GuardMode::Basic {
            user: "admin".into(),
            password_hash: "$argon2id$v=19$m=65536,t=2,p=1$SECRETSALTVALUE$SECRETHASHVALUE".into(),
        };
        let s = format!("{mode:?}");
        assert!(!s.contains("SECRETHASHVALUE"), "leak: {s}");
        assert!(!s.contains("SECRETSALTVALUE"), "leak: {s}");
        assert!(s.contains("admin"), "user preserved: {s}");
        assert!(s.contains("redacted"), "should mark: {s}");
    }
}
