//! Identity-signing key: public JWKS and operator-triggered rotation.
//!
//! The two endpoints sit at opposite ends of the trust scale, which is why
//! they are registered on different subrouters from one file. JWKS is
//! deliberately unauthenticated — an upstream verifying `X-Sekisho-Jwt` needs
//! the public key and by definition has no management credential — while
//! rotation is admin-only.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use super::AppState;
use crate::audit::Actor;
use crate::store::backend::IdentitySigningRotateOutcome;

/// The unauthenticated half, merged into the public subrouter by
/// [`crate::api`]. Kept as a function here rather than a route line there so
/// the JWKS endpoint and the key ring it serves stay in one place.
pub fn public_router() -> Router<AppState> {
    Router::new().route("/auth/jwks", get(jwks))
}

/// Serve the current JWKS.
///
/// Snapshot-based and timestamp-driven: the ring publishes retiring keys
/// alongside the current one for a grace period, so a token minted just before
/// a rotation still verifies against a document fetched just after it.
async fn jwks(State(state): State<AppState>) -> Response {
    Json(
        state
            .identity_key_ring()
            .jwks(chrono::Utc::now().timestamp()),
    )
    .into_response()
}

/// Rotate the identity-signing key.
///
/// Refuses with 409 while a previous key is still inside its retirement grace.
/// Rotating twice in quick succession would evict a key that live tokens are
/// still signed with, turning a routine operation into an outage — the
/// operator is told to wait rather than having the second rotation silently
/// dropped.
pub async fn rotate(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
) -> crate::error::Result<Response> {
    match state.store.rotate_identity_signing_ring().await? {
        IdentitySigningRotateOutcome::RetiringStillEligible => Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "an identity signing key is still retiring"
            })),
        )
            .into_response()),
        IdentitySigningRotateOutcome::Rotated => {
            let snapshot = state.store.identity_key_ring_snapshot().await?;
            crate::audit_crypto!(
                actor = actor,
                event = "crypto.identity_signing.rotate",
                resource = "identity_signing_key",
                target = snapshot.current_kid(),
                action = "rotate",
                "operator rotated identity signing key"
            );
            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "kid": snapshot.current_kid(),
                    "algorithm": "EdDSA"
                })),
            )
                .into_response())
        }
    }
}
