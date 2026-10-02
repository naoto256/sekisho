//! API key management. Admin scope only — a caller who can mint keys can mint
//! one for any scope, so this endpoint is equivalent to full control.
//!
//! The plaintext key exists exactly once, in the 201 response to
//! [`create`]. It is not recoverable afterwards, which is why the audit event
//! records the id and prefix and nothing else: an audit log that contained the
//! secret would be a second, longer-lived copy of it in a place designed to be
//! shipped elsewhere.

use super::SanitizedJson;
use super::pagination::{PageQuery, normalize, remove_probe, wrap};
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::audit::Actor;
use crate::error::{Error, Result};
use crate::models::api_key::CreateApiKey;

/// Shared wording so the two rejection paths cannot describe the same rule
/// differently.
const INVALID_NAME_REASON: &str = "api key name must not be empty or exceed 255 bytes";

/// Local rather than borrowed from [`crate::validation`]: the bound here is
/// 255 *bytes*, not characters, because the name is stored in a fixed-width
/// column and echoed into audit fields.
fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 255 {
        return Err(Error::BadRequest(INVALID_NAME_REASON.into()));
    }
    Ok(())
}

/// Paginated key list. Safe to return whole: [`crate::models::api_key::ApiKey`]
/// skips the hash on serialization and never held the key itself.
pub async fn list(
    State(store): State<crate::store::Store>,
    Query(q): Query<PageQuery>,
) -> Result<impl IntoResponse> {
    let (limit, offset) = normalize(q);
    let mut keys = store.list_api_keys_page(limit + 1, offset).await?;
    let has_more = remove_probe(&mut keys, limit);
    Ok(Json(wrap(&keys, limit, offset, has_more)))
}

/// Fetch one key's metadata.
pub async fn get(
    State(store): State<crate::store::Store>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let key = store.get_api_key(id).await?;
    Ok(Json(key))
}

/// Mint a key and return it once.
pub async fn create(
    State(store): State<crate::store::Store>,
    Extension(actor): Extension<Actor>,
    SanitizedJson(body): SanitizedJson<CreateApiKey>,
) -> Result<impl IntoResponse> {
    validate_name(&body.name)?;
    let key_with_secret = store.create_api_key(&body.name, &body.scopes).await?;
    // Log only the prefix and the new key's id — never the secret
    // returned to the caller in the body.
    crate::audit_mgmt!(
        actor = actor,
        event = "api_key.create",
        resource = "api_key",
        target = key_with_secret.api_key.id,
        action = "create",
        name = %key_with_secret.api_key.name,
        new_prefix = %key_with_secret.api_key.prefix,
        "api key created"
    );
    Ok((StatusCode::CREATED, Json(key_with_secret)))
}

/// Revoke a key. Immediate: authorization looks the key up per request, so
/// there is no cached grant to outlive the deletion.
pub async fn delete(
    State(store): State<crate::store::Store>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    store.delete_api_key(id).await?;
    crate::audit_mgmt!(
        actor = actor,
        event = "api_key.delete",
        resource = "api_key",
        target = id,
        action = "delete",
        "api key revoked"
    );
    Ok(StatusCode::NO_CONTENT)
}
