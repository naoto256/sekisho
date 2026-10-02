//! The daemon's error type and its HTTP projection.
//!
//! ## Two audiences, two messages
//!
//! Every variant is rendered twice: once into the log (via `tracing`, with
//! whatever detail the source produced) and once into the HTTP response body
//! (usually a fixed string). The split is the whole design. Diagnostics for
//! internal failures routinely embed a database DSN, an upstream URL or a
//! provider error, and the management API is reachable by anyone holding a
//! read-scoped key — so `Display` detail goes to the operator's journal, and
//! the caller gets a stable code plus a message that carries no deployment
//! state.
//!
//! The exceptions are deliberate and narrow: [`Error::BadRequest`],
//! [`Error::Conflict`] and [`Error::NotClusterLeader`] do put their payload on
//! the wire, because in those cases the payload *is* the actionable answer
//! (which field was wrong, which node to retry against) and is derived from
//! the caller's own input or from cluster topology rather than from secrets.
//!
//! ## Conversions narrow deliberately
//!
//! The `From` impls for [`acme_core::Error`] and [`auth_idp::Error`] keep the
//! upstream crate's *classification* — transient vs. rejected vs. internal,
//! which is what decides the status code and whether a retry makes sense —
//! while dropping the upstream crate's message. That loses grep-ability in
//! exchange for a guarantee that a dependency cannot start leaking through
//! Sekisho's API surface after a version bump. The tests below pin it with
//! sentinel strings.
//!
//! ## Status codes
//!
//! Anything the operator can fix by changing configuration maps to 503 rather
//! than 500 — a misconfigured daemon is unavailable, not broken — which also
//! keeps it out of the error budget that 500s are meant to track.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Every failure the daemon can return, from either the management API or the
/// proxy data plane. One type for both so that a store or crypto failure can
/// propagate upward without a conversion at each layer boundary.
#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)] // ConfigurationError, ExternalServiceError are intentionally descriptive
pub enum Error {
    /// The addressed resource does not exist. Carries no payload: which id
    /// was missing is already in the request line the caller sent.
    #[error("not found")]
    NotFound,

    /// A uniqueness or state precondition failed (duplicate name, a
    /// transition that is not legal from the current state). The detail is
    /// echoed to the caller because it describes their own request.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Admission validation rejected the body. The detail names the offending
    /// field and is safe to echo — it is derived from caller input, never from
    /// stored state.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// No usable credential was presented. Distinct from
    /// [`Self::AuthenticationFailed`] so that a missing key is not logged at
    /// the same severity as a rejected one.
    #[error("unauthorized")]
    Unauthorized,

    /// A credential was presented and rejected. Logged at `warn` because a
    /// run of these is the signal a brute-force attempt produces.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// The daemon cannot serve this request until an operator changes
    /// configuration. Maps to 503, not 500: nothing is broken, something is
    /// unset, and the caller should retry after the fix.
    #[error("configuration error: {0}")]
    ConfigurationError(String),

    /// Every v3 DEK key-id slot (0..=255) is durably reserved.
    #[error("DEK key ring is full")]
    KeyRingFull,

    /// A dependency the daemon called out to (IdP, ACME directory) failed.
    /// Maps to 502 so the caller can tell "the thing behind sekisho broke"
    /// from "sekisho broke".
    #[error("external service error: {0}")]
    ExternalServiceError(String),

    /// A query failed against a database that *is* reachable — distinct from
    /// [`Self::ServiceUnavailable`], which means it is not. sqlx diagnostics
    /// can quote SQL and parameter values, so only the log sees them.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// The operational service DB was configured but is not reachable.
    /// Raised by the `Backend::Unavailable` arm of the `dispatch!`
    /// macro; maps to HTTP 503. The bootstrap API keeps running so the
    /// operator can correct the DSN.
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    /// A management mutation reached a follower; the leader identifier is
    /// preserved as the caller's retry target in the HTTP 503 response.
    #[error("this node is not the cluster leader; retry against {0}")]
    NotClusterLeader(String),

    /// An invariant the daemon itself owns was violated. The catch-all, and
    /// the only variant that should be read as "this is a bug".
    #[error("internal error: {0}")]
    Internal(String),

    /// Sealing, unsealing or key-ring access failed. Surfaced as a flat 500:
    /// distinguishing "wrong key" from "corrupt ciphertext" on the wire would
    /// hand an attacker a decryption oracle.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    /// An `auth-idp` error kept in its original form because the caller needs
    /// the variant, not a summary — currently only `KidNotFound`, where the
    /// key id genuinely identifies what the relying party must refresh.
    #[error(transparent)]
    IapAuth(auth_idp::Error),
}

impl From<acme_core::Error> for Error {
    fn from(e: acme_core::Error) -> Self {
        // Keep the protocol classification while crossing the HTTP boundary,
        // but never copy provider errors, opaque credentials, or raw upstream
        // responses into Sekisho diagnostics.
        match e {
            acme_core::Error::Transient(_) => {
                Error::ExternalServiceError("ACME operation failed".into())
            }
            acme_core::Error::Rejected(_) => {
                Error::BadRequest("ACME directory rejected the request".into())
            }
            acme_core::Error::Internal(_) => Error::Internal("ACME protocol failure".into()),
            acme_core::Error::Challenge(_) => {
                Error::Internal("ACME challenge provider failed".into())
            }
            acme_core::Error::Unsupported(_) => {
                Error::BadRequest("ACME capability is not supported".into())
            }
            acme_core::Error::InvalidCredentials => {
                Error::ConfigurationError("invalid persisted ACME account credentials".into())
            }
            acme_core::Error::CredentialDirectoryMismatch => Error::ConfigurationError(
                "persisted ACME account credentials do not match the directory".into(),
            ),
            acme_core::Error::InvalidPredecessorCertificate => {
                Error::BadRequest("invalid predecessor certificate".into())
            }
            acme_core::Error::RenewalInformation(_) => {
                Error::ExternalServiceError("ACME renewal information failed".into())
            }
        }
    }
}

impl From<auth_idp::Error> for Error {
    fn from(e: auth_idp::Error) -> Self {
        // auth-idp v0.2.0 dropped the `Crypto` variant entirely when
        // envelope encryption moved to the standalone `envelope-aead`
        // crate. sekisho's own `Crypto` variant now wraps
        // `envelope_aead::Error` directly (see the crypto shim in
        // `crate::crypto`).
        match e {
            auth_idp::Error::AuthenticationFailed(m) => Error::AuthenticationFailed(m),
            auth_idp::Error::ConfigurationError(m) => Error::ConfigurationError(m),
            auth_idp::Error::ExternalServiceError(m) => Error::ExternalServiceError(m),
            auth_idp::Error::Internal(m) => Error::Internal(m),
            other @ auth_idp::Error::KidNotFound(_) => Error::IapAuth(other),
        }
    }
}

impl Error {
    /// Machine-readable error code for API responses.
    ///
    /// Coarser than the variant set on purpose: clients branch on this string,
    /// so several variants intentionally share a code (`Crypto` and `Internal`
    /// both report `INTERNAL_ERROR`) and adding a variant does not have to be
    /// a breaking change for them.
    fn code(&self) -> &'static str {
        match self {
            Error::NotFound => "NOT_FOUND",
            Error::Conflict(_) => "CONFLICT",
            Error::BadRequest(_) => "BAD_REQUEST",
            Error::Unauthorized => "UNAUTHORIZED",
            Error::AuthenticationFailed(_) => "AUTHENTICATION_FAILED",
            Error::ConfigurationError(_) | Error::KeyRingFull => "CONFIGURATION_ERROR",
            Error::ExternalServiceError(_) => "EXTERNAL_SERVICE_ERROR",
            Error::Database(_) => "DATABASE_ERROR",
            Error::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            Error::NotClusterLeader(_) => "SERVICE_UNAVAILABLE",
            Error::Internal(_) => "INTERNAL_ERROR",
            Error::Crypto(_) => "INTERNAL_ERROR",
            Error::IapAuth(_) => "EXTERNAL_SERVICE_ERROR",
        }
    }
}

impl IntoResponse for Error {
    /// Log the full diagnostic, then answer with the sanitized projection.
    ///
    /// This is the only place the two forms are produced, so the guarantee
    /// that a detail never reaches the wire unreviewed holds by construction
    /// rather than by discipline at each call site.
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            Error::NotFound => (StatusCode::NOT_FOUND, self.code(), self.to_string()),
            Error::Conflict(_) => (StatusCode::CONFLICT, self.code(), self.to_string()),
            Error::BadRequest(_) => (StatusCode::BAD_REQUEST, self.code(), self.to_string()),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, self.code(), self.to_string()),
            Error::AuthenticationFailed(_) => {
                tracing::warn!("authentication failed: {self}");
                (StatusCode::UNAUTHORIZED, self.code(), self.to_string())
            }
            Error::ConfigurationError(msg) => {
                tracing::error!("configuration error: {msg}");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    self.code(),
                    "service not configured".to_string(),
                )
            }
            Error::KeyRingFull => {
                tracing::error!("DEK key ring is full");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    self.code(),
                    "service not configured".to_string(),
                )
            }
            Error::ExternalServiceError(msg) => {
                tracing::error!("external service error: {msg}");
                (
                    StatusCode::BAD_GATEWAY,
                    self.code(),
                    "upstream service error".to_string(),
                )
            }
            Error::Database(e) => {
                tracing::error!("database error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    self.code(),
                    "internal server error".to_string(),
                )
            }
            Error::ServiceUnavailable(_) => {
                // `Store::new` already logged the connection failure, whose
                // diagnostic may contain deployment-specific details. Do not
                // copy it across the HTTP boundary or re-log it per request
                // while the daemon sits in degraded mode.
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    self.code(),
                    "service unavailable".to_string(),
                )
            }
            Error::NotClusterLeader(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                self.code(),
                self.to_string(),
            ),
            Error::Internal(msg) => {
                tracing::error!("internal error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    self.code(),
                    "internal server error".to_string(),
                )
            }
            Error::Crypto(e) => {
                tracing::error!("crypto error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    self.code(),
                    "internal server error".to_string(),
                )
            }
            Error::IapAuth(e) => {
                tracing::error!("auth-idp error: {e}");
                (
                    StatusCode::BAD_GATEWAY,
                    self.code(),
                    "upstream service error".to_string(),
                )
            }
        };

        let body = serde_json::json!({
            "error": {
                "code": code,
                "message": message,
            }
        });
        (status, axum::Json(body)).into_response()
    }
}

/// Crate-wide result alias. Everything fallible in the daemon converges on
/// [`Error`] so that any layer can return upward without a per-boundary
/// conversion.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    use super::Error;

    #[derive(Debug, thiserror::Error)]
    #[error("provider-secret-sentinel")]
    struct ProviderFailure;

    #[test]
    fn acme_error_mapping_is_typed_and_secret_safe() {
        let cases = [
            Error::from(acme_core::Error::Transient("raw-upstream-sentinel".into())),
            Error::from(acme_core::Error::Rejected("raw-rejection-sentinel".into())),
            Error::from(acme_core::Error::Internal("raw-internal-sentinel".into())),
            Error::from(acme_core::Error::Challenge(Box::new(ProviderFailure))),
            Error::from(acme_core::Error::Unsupported("raw-capability-sentinel")),
            Error::from(acme_core::Error::InvalidCredentials),
            Error::from(acme_core::Error::CredentialDirectoryMismatch),
            Error::from(acme_core::Error::InvalidPredecessorCertificate),
            Error::from(acme_core::Error::RenewalInformation(
                acme_core::RenewalInformationFailure::LongTerm {
                    retry_after: std::time::Duration::from_secs(1),
                },
            )),
        ];

        for mapped in cases {
            let diagnostic = mapped.to_string();
            assert!(!diagnostic.contains("sentinel"), "{diagnostic}");
        }
    }

    #[tokio::test]
    async fn service_unavailable_response_is_fixed_and_secret_safe() {
        let reason = "sqlx pool error for postgres://operator:credential-sentinel@db.internal.example/sekisho";
        let response = Error::ServiceUnavailable(reason.into()).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read error response body");
        let body: serde_json::Value =
            serde_json::from_slice(&body).expect("decode error response body");

        assert_eq!(
            body,
            serde_json::json!({
                "error": {
                    "code": "SERVICE_UNAVAILABLE",
                    "message": "service unavailable",
                }
            })
        );
        let encoded = serde_json::to_string(&body).expect("encode error response body");
        for sensitive in [
            reason,
            "postgres://",
            "credential-sentinel",
            "db.internal.example",
        ] {
            assert!(!encoded.contains(sensitive), "response leaked {sensitive}");
        }
    }

    #[tokio::test]
    async fn not_cluster_leader_preserves_actionable_response() {
        let response = Error::NotClusterLeader("sekisho-leader-2".into()).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read error response body");
        let body: serde_json::Value =
            serde_json::from_slice(&body).expect("decode error response body");

        assert_eq!(
            body,
            serde_json::json!({
                "error": {
                    "code": "SERVICE_UNAVAILABLE",
                    "message": "this node is not the cluster leader; retry against sekisho-leader-2",
                }
            })
        );
    }
}
