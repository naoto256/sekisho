//! Session inspection and forced sign-out.
//!
//! Read-only apart from [`delete`], which is the operator's revocation lever:
//! because sessions are server-side state, removing the row ends the session
//! on the next request rather than waiting for a cookie to expire.
//!
//! Every response goes through [`redact_session`]. Sessions hold sealed
//! refresh and ID tokens plus SAML logout identifiers, none of which an
//! operator needs in order to answer "who is logged in, and since when".

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use uuid::Uuid;

use super::pagination::{PageQuery, normalize, wrap};
use crate::audit::Actor;
use crate::error::Result;
use crate::models::session::Session;

/// Query parameters for [`list`]. Carries its own `limit`/`offset` rather
/// than reusing `PageQuery` because it adds the `user` filter; the values are
/// still normalized through the shared pagination helper so the bounds match
/// every other listing endpoint.
#[derive(Deserialize)]
pub struct SessionFilter {
    pub user: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Redact sensitive fields from session before returning in API response.
///
/// Timestamps are explicitly `.timestamp()`-converted because `json!`
/// expands fields through the default `Serialize` impl on
/// `DateTime<Utc>` (RFC 3339 string), bypassing the
/// `#[serde(with = "ts_seconds")]` annotation on `Session`. Without
/// these explicit casts the wire shape would silently disagree with
/// every other resource endpoint, which all return integer epoch.
fn redact_session(session: &Session) -> serde_json::Value {
    serde_json::json!({
        "id": session.id,
        "user_id": session.user_id,
        "idp_id": session.idp_id,
        "claims": session.claims,
        "groups": session.groups,
        "created_at": session.created_at.timestamp(),
        "expires_at": session.expires_at.timestamp(),
        "last_accessed_at": session.last_accessed_at.timestamp(),
    })
}

/// List sessions, optionally filtered to one user.
pub async fn list(
    State(store): State<crate::store::Store>,
    Query(filter): Query<SessionFilter>,
) -> Result<impl IntoResponse> {
    let (limit, offset) = normalize(PageQuery {
        limit: filter.limit,
        offset: filter.offset,
    });
    let mut sessions = store
        .list_sessions(filter.user.as_deref(), limit + 1, offset)
        .await?;
    let has_more = sessions.len() > limit as usize;
    sessions.truncate(limit as usize);
    let items: Vec<serde_json::Value> = sessions.iter().map(redact_session).collect();
    Ok(Json(wrap(&items, limit, offset, has_more)))
}

/// Fetch one session, redacted.
pub async fn get(
    State(store): State<crate::store::Store>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let session = store.get_session(id).await?;
    Ok(Json(redact_session(&session)))
}

/// Terminate a session immediately.
pub async fn delete(
    State(store): State<crate::store::Store>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    // Capture the user_id *before* the delete so the audit event can
    // tell the operator whose session was forcibly revoked. If the
    // session is already gone (race / typo) we still want a log line,
    // so the get failure is non-fatal.
    let revoked_user = store
        .get_session(id)
        .await
        .ok()
        .map(|s| s.user_id)
        .unwrap_or_default();
    store.delete_session(id).await?;
    crate::audit_mgmt!(
        actor = actor,
        event = "session.admin_revoke",
        resource = "session",
        target = id,
        action = "delete",
        revoked_user = %revoked_user,
        "session revoked by admin"
    );
    Ok(StatusCode::NO_CONTENT)
}
