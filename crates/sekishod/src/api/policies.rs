//! `Policy` CRUD. Path segment can be a UUID or a policy name. PATCH performs
//! JSON Merge Patch. The `expr` field is validated by parsing it before storing
//! — invalid expressions are rejected at write time, not at request time.

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

use super::SanitizedJson;
use super::pagination::{PageQuery, normalize, remove_probe, wrap};
use crate::audit::{self, Actor};
use crate::error::{Error, Result};
use crate::models::policy::{CreatePolicy, Policy, UpdatePolicy};
use crate::store::Store;

async fn resolve(store: &Store, key: &str) -> Result<Policy> {
    if let Ok(id) = Uuid::parse_str(key) {
        store.get_policy(id).await
    } else {
        store.get_policy_by_name(key).await
    }
}

fn validate_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(Error::BadRequest("policy name must not be empty".into()));
    }
    if trimmed.contains(char::is_whitespace) {
        return Err(Error::BadRequest(
            "policy name must not contain whitespace".into(),
        ));
    }
    Ok(())
}

fn validate_expr(expr: &str) -> Result<()> {
    crate::policy::parse(expr)
        .map_err(|e| Error::BadRequest(format!("invalid expression: {e}")))?;
    Ok(())
}

pub async fn list(
    State(store): State<Store>,
    Query(q): Query<PageQuery>,
) -> Result<impl IntoResponse> {
    let (limit, offset) = normalize(q);
    let mut items = store.list_policies_page(limit + 1, offset).await?;
    let has_more = remove_probe(&mut items, limit);
    Ok(Json(wrap(&items, limit, offset, has_more)))
}

pub async fn get(State(store): State<Store>, Path(key): Path<String>) -> Result<impl IntoResponse> {
    Ok(Json(resolve(&store, &key).await?))
}

pub async fn create(
    State(store): State<Store>,
    Extension(actor): Extension<Actor>,
    SanitizedJson(body): SanitizedJson<CreatePolicy>,
) -> Result<impl IntoResponse> {
    validate_name(&body.name)?;
    validate_expr(&body.expr)?;
    let p = body.into_policy();
    store.create_policy(&p).await?;
    crate::audit_mgmt!(
        actor = actor,
        event = "policy.create",
        resource = "policy",
        target = p.id,
        action = "create",
        name = %p.name,
        "policy created"
    );
    Ok((StatusCode::CREATED, Json(p)))
}

pub async fn update(
    State(store): State<Store>,
    Extension(actor): Extension<Actor>,
    Path(key): Path<String>,
    SanitizedJson(body): SanitizedJson<UpdatePolicy>,
) -> Result<impl IntoResponse> {
    if let Some(name) = &body.name {
        validate_name(name)?;
    }
    if let Some(expr) = &body.expr {
        validate_expr(expr)?;
    }
    let existing = resolve(&store, &key).await?;
    let patch = serde_json::to_value(&body)
        .map_err(|e| Error::Internal(format!("serialize error: {e}")))?;
    let fields = audit::changed_fields(&patch);
    let updated = store.update_policy(existing.id, patch).await?;
    crate::audit_mgmt!(
        actor = actor,
        event = "policy.update",
        resource = "policy",
        target = existing.id,
        action = "update",
        changed_fields = ?fields,
        "policy updated"
    );
    Ok(Json(updated))
}

pub async fn delete(
    State(store): State<Store>,
    Extension(actor): Extension<Actor>,
    Path(key): Path<String>,
) -> Result<impl IntoResponse> {
    let existing = resolve(&store, &key).await?;
    store.delete_policy(existing.id).await?;
    crate::audit_mgmt!(
        actor = actor,
        event = "policy.delete",
        resource = "policy",
        target = existing.id,
        action = "delete",
        name = %existing.name,
        "policy deleted"
    );
    Ok(StatusCode::NO_CONTENT)
}
