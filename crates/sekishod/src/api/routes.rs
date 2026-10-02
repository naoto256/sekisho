//! Route CRUD.
//!
//! ## The server does not orchestrate
//!
//! `enabled` is treated as an ordinary boolean field. Flipping it does not
//! trigger certificate acquisition, dependency checks or any other
//! lifecycle — the client runs that preflight (see
//! `sekisho_api_protocol::ensure_cert_before_enable`) and then PATCHes. The
//! server owning data and integrity while clients own workflow is the
//! project's central split; a server-side enable lifecycle would drag
//! client-shaped concerns back into the daemon.
//!
//! ## Writes republish, they do not wait
//!
//! Every mutation calls `route_generation.request_refresh()` rather than
//! rebuilding the cache inline. The proxy serves from an atomically published
//! generation, so a write returns as soon as it is durable and the data plane
//! picks up the new generation on its own. A write that blocked on cache
//! rebuild would couple management latency to data-plane work for no gain in
//! correctness.
//!
//! ## Two flags are audited as discrete fields
//!
//! `allow_credential_overrides` and `session_cookie_samesite` each widen a
//! blast radius (upstream credential injection, CSRF exposure). They are
//! emitted as their own audit fields, not folded into `changed_fields`, so a
//! SIEM rule can alert on "any route that granted itself this" without parsing
//! a list.

use super::SanitizedJson;
use super::pagination::{PageQuery, normalize, remove_probe, wrap};
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::error::{Error, Result};
use crate::models::route::{CreateRoute, UpdateRoute};
use crate::store::Store;
use crate::validation;

/// Paginated route list. Routes hold no secrets, so this is the stored form
/// verbatim.
pub async fn list(
    State(store): State<Store>,
    Query(q): Query<PageQuery>,
) -> Result<impl IntoResponse> {
    let (limit, offset) = normalize(q);
    let mut routes = store.list_routes_page(limit + 1, offset).await?;
    let has_more = remove_probe(&mut routes, limit);
    Ok(Json(wrap(&routes, limit, offset, has_more)))
}

/// Fetch one route.
pub async fn get(State(store): State<Store>, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    let route = store.get_route(id).await?;
    Ok(Json(route))
}

/// Create a route.
///
/// Validation runs twice on purpose: [`validation::validate_route_create`]
/// over the request body, then
/// [`crate::identity::validate_route`] over the materialized route. The second
/// pass sees the values `into_route` filled in from defaults, which the first
/// pass could not.
pub async fn create(
    State(store): State<Store>,
    Extension(route_generation): Extension<
        std::sync::Arc<crate::route_generation::RouteGeneration>,
    >,
    Extension(actor): Extension<Actor>,
    SanitizedJson(body): SanitizedJson<CreateRoute>,
) -> Result<impl IntoResponse> {
    validation::validate_route_create(&body)?;
    let route = body.into_route();
    crate::identity::validate_route(route.signed_identity_input())
        .map_err(|_| Error::BadRequest(crate::identity::INVALID_SIGNED_ROUTE.into()))?;
    store.create_route(&route).await?;
    route_generation.request_refresh();
    crate::audit_mgmt!(
        actor = actor,
        event = "route.create",
        resource = "route",
        target = route.id,
        action = "create",
        name = %route.name,
        // High-blast-radius opt-in: this route can override the user's
        // Authorization / Cookie before forwarding upstream. Surface
        // it as a discrete audit field so a Splunk / Sentinel rule
        // can alert on every route that grants itself this power.
        allow_credential_overrides = route.headers.allow_credential_overrides,
        // Same idea for the SameSite override — `none` widens the
        // CSRF blast radius, so every route that opts in should
        // be discoverable in the audit stream.
        session_cookie_samesite = ?route.session_cookie_samesite,
        "route created"
    );
    Ok((StatusCode::CREATED, Json(route)))
}

/// Plain merge-patch. No side effects, no cert acquisition, no
/// enable-lifecycle reasoning — the server treats `enabled` as just
/// another boolean field and the client is responsible for
/// orchestrating whatever pre-flight it needs (cert existence, policy
/// bindings, DNS readiness) before flipping it.
pub async fn update(
    State(store): State<Store>,
    Extension(route_generation): Extension<
        std::sync::Arc<crate::route_generation::RouteGeneration>,
    >,
    Extension(actor): Extension<Actor>,
    Path(id): Path<Uuid>,
    SanitizedJson(body): SanitizedJson<UpdateRoute>,
) -> Result<impl IntoResponse> {
    validation::validate_route_update(&body)?;
    let patch = serde_json::to_value(&body)
        .map_err(|e| Error::Internal(format!("serialize error: {e}")))?;
    let fields = audit::changed_fields(&patch);
    // Capture the credential-override flag before the patch is sent.
    // The flag matters for the audit trail even when other fields
    // change (e.g. someone flipped the route's `to` and the existing
    // route already had the override on).
    let credential_override_in_patch = body
        .headers
        .as_ref()
        .map(|h| h.allow_credential_overrides)
        .unwrap_or(false);
    let route = store.update_route(id, patch).await?;
    route_generation.request_refresh();
    crate::audit_mgmt!(
        actor = actor,
        event = "route.update",
        resource = "route",
        target = id,
        action = "update",
        changed_fields = ?fields,
        allow_credential_overrides_in_patch = credential_override_in_patch,
        allow_credential_overrides_post = route.headers.allow_credential_overrides,
        session_cookie_samesite_post = ?route.session_cookie_samesite,
        "route updated"
    );
    Ok(Json(route))
}

/// Delete a route. Certificates issued for its hostname are left in place —
/// they are a separate resource with their own lifecycle, and dropping one
/// here would make a re-created route pay for a fresh ACME issuance it does
/// not need.
pub async fn delete(
    State(store): State<Store>,
    Extension(route_generation): Extension<
        std::sync::Arc<crate::route_generation::RouteGeneration>,
    >,
    Extension(actor): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    store.delete_route(id).await?;
    route_generation.request_refresh();
    crate::audit_mgmt!(
        actor = actor,
        event = "route.delete",
        resource = "route",
        target = id,
        action = "delete",
        "route deleted"
    );
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn successful_local_create_withdraws_generation_before_handler_returns() {
        let store = Store::new_for_test("sqlite::memory:", [91; 32], None)
            .await
            .unwrap();
        let generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;
        let body: CreateRoute = serde_json::from_value(serde_json::json!({
            "name": "new-route",
            "from": "https://new.example",
            "to": ["http://127.0.0.1:9"],
            "access": {"allow_public_unauthenticated_access": true},
            "enabled": true
        }))
        .unwrap();

        create(
            State(store),
            Extension(Arc::clone(&generation)),
            Extension(Actor::system()),
            SanitizedJson(body),
        )
        .await
        .unwrap();

        assert!(matches!(
            generation.find("new.example", "/"),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        ));
    }
}
