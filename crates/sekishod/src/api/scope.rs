//! Scope enforcement for the management API.
//!
//! One middleware per privilege level, attached to a whole subrouter in
//! [`crate::api`]. Every authenticated request passes through exactly one of
//! them, which is what lets the handlers hold no authorization logic.
//!
//! ## Two kinds of caller
//!
//! **API keys** are looked up by value, and their scope set is checked against
//! what the subrouter requires ([`ApiKeyScope`] is hierarchical, so a write
//! key satisfies a read requirement).
//!
//! **Management session tokens** (the `mgmt_` prefix) come from the
//! Unix-socket challenge flow in [`local_auth`] and are accepted at *every*
//! level, including admin, without a scope check. That is intentional rather
//! than an oversight: the challenge accepts only a peer whose effective UID
//! exactly matches the daemon's effective UID. Redeeming the resulting
//! one-time token therefore establishes the local management identity, which
//! the management API treats as admin authority.
//!
//! ## Every outcome is an audit event
//!
//! Success, missing header, bad key, and insufficient scope each emit a
//! structured record under [`crate::audit::TARGET`] with a stable `event`
//! name, because these lines are what a SIEM correlates on. Failures
//! deliberately log a key *prefix* only — enough to identify which credential
//! was used, never enough to reuse it.
//!
//! Note that the last-used timestamp update is best-effort: a failure is
//! logged but does not reject the request. Bookkeeping must not be able to
//! lock an operator out of the daemon they are trying to repair.

use std::sync::Arc;

use axum::Extension;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::api::local_auth;
use crate::audit::{Actor, ActorKind};
use crate::models::api_key::ApiKeyScope;
use crate::store::Store;

/// Require at least `management:read`.
pub async fn require_read(
    state: State<Store>,
    challenge_store: Extension<Arc<local_auth::ChallengeStore>>,
    request: Request,
    next: Next,
) -> Response {
    authorize(ApiKeyScope::Read, state, challenge_store, request, next).await
}

/// Require at least `management:write`.
pub async fn require_write(
    state: State<Store>,
    challenge_store: Extension<Arc<local_auth::ChallengeStore>>,
    request: Request,
    next: Next,
) -> Response {
    authorize(ApiKeyScope::Write, state, challenge_store, request, next).await
}

/// Require `management:admin`. Guards key management, encryption-key
/// rotation, and global/instance config — everything that can change the
/// daemon's own security posture rather than the traffic it serves.
pub async fn require_admin(
    state: State<Store>,
    challenge_store: Extension<Arc<local_auth::ChallengeStore>>,
    request: Request,
    next: Next,
) -> Response {
    authorize(ApiKeyScope::Admin, state, challenge_store, request, next).await
}

/// Shared body of the three middlewares.
///
/// On success the resolved [`Actor`] is inserted into the request extensions
/// so downstream audit events can name who did the thing without repeating
/// the credential lookup — and so a handler cannot accidentally attribute an
/// action to the wrong caller.
async fn authorize(
    required: ApiKeyScope,
    State(store): State<Store>,
    Extension(challenge_store): Extension<Arc<local_auth::ChallengeStore>>,
    mut request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let key = match request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
    {
        Some(key) if !key.is_empty() => key.to_owned(),
        _ => {
            tracing::warn!(
                target: crate::audit::TARGET,
                event = "auth.api.failure",
                category = "auth",
                result = "failure",
                method = %method,
                required_scope = required.as_str(),
                reason = "missing_or_invalid_authorization_header",
                "API authentication rejected"
            );
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(
                    serde_json::json!({ "error": "missing or invalid Authorization header" }),
                ),
            )
                .into_response();
        }
    };

    if key.starts_with("mgmt_") {
        if challenge_store.validate_token(&key) {
            let token_id = key.get(..12).unwrap_or("mgmt_short").to_owned();
            request.extensions_mut().insert(Actor {
                kind: ActorKind::MgmtSession,
                id: token_id.clone(),
            });
            tracing::info!(
                target: crate::audit::TARGET,
                event = "auth.api.success",
                category = "auth",
                result = "success",
                actor_type = "mgmt_session",
                actor_id = %token_id,
                method = %method,
                required_scope = required.as_str(),
                "management session authenticated and authorized"
            );
            return next.run(request).await;
        }

        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.api.failure",
            category = "auth",
            result = "failure",
            actor_type = "mgmt_session",
            method = %method,
            required_scope = required.as_str(),
            reason = "invalid_or_expired_management_token",
            "API authentication rejected"
        );
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "invalid or expired management token" })),
        )
            .into_response();
    }

    let api_key = match store.lookup_api_key(&key).await {
        Ok(api_key) => api_key,
        Err(_) => {
            tracing::warn!(
                target: crate::audit::TARGET,
                event = "auth.api.failure",
                category = "auth",
                result = "failure",
                actor_type = "api_key",
                key_prefix = key.get(..12).unwrap_or("<short>"),
                method = %method,
                required_scope = required.as_str(),
                reason = "invalid_api_key",
                "API authentication rejected"
            );
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({ "error": "invalid API key" })),
            )
                .into_response();
        }
    };

    if !api_key.scopes.allows(required) {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.api.scope_denied",
            category = "auth",
            result = "failure",
            actor_type = "api_key",
            actor_id = %api_key.prefix,
            method = %method,
            required_scope = required.as_str(),
            reason = "insufficient_scope",
            "API key authorization rejected"
        );
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "error": "insufficient API key scope" })),
        )
            .into_response();
    }

    if store.touch_api_key_usage(api_key.id).await.is_err() {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.api_key.usage_touch_failed",
            category = "auth",
            result = "failure",
            actor_type = "api_key",
            actor_id = %api_key.prefix,
            method = %method,
            required_scope = required.as_str(),
            reason = "usage_touch_failed",
            "authorized API key usage timestamp was not updated"
        );
    }

    request.extensions_mut().insert(Actor {
        kind: ActorKind::ApiKey,
        id: api_key.prefix.clone(),
    });
    tracing::info!(
        target: crate::audit::TARGET,
        event = "auth.api.success",
        category = "auth",
        result = "success",
        actor_type = "api_key",
        actor_id = %api_key.prefix,
        method = %method,
        required_scope = required.as_str(),
        "API key authenticated and authorized"
    );
    next.run(request).await
}
