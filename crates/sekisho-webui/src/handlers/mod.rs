//! Request handlers and the router that wires them.
//!
//! One module per resource, each owning its own route table. There is no
//! generic `{resource}/{id}` dispatcher — see [`crate`] for why the
//! schema-driven version was removed.
//!
//! ## Middleware order is the access-control story
//!
//! [`require_credential`] runs *before* the authentication guard. A fresh
//! install has no credential at all, and an operator who lands on a blank 401
//! has no way to discover that they need to visit `/setup`; redirecting first
//! means the unconfigured case has an obvious next step while the
//! misconfigured case still gets a proper refusal. Only `/setup`, the static
//! assets and `/healthz` are exempt, because each of those has to work before
//! a credential exists.

pub mod api_keys;
pub mod certificates;
pub mod common;
pub mod encryption_keys;
pub mod general;
pub mod home;
pub mod idps;
pub mod instance;
pub mod policies;
pub mod routes;
pub mod sessions;
pub mod setup;

use crate::AppState;
use crate::auth::guard::AuthenticatedUser;

use axum::response::{IntoResponse, Redirect, Response};
use axum::{
    Extension, Router,
    extract::State,
    middleware,
    routing::{delete, get, post},
};

/// Maximum request body size for any sekisho-webui endpoint. Certificate
/// uploads are the largest legitimate payload; 5 MiB is comfortable for
/// realistic certificates while bounding OOM risk from hostile uploads.
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Decide whether the user needs the setup screen. When no credential is
/// installed, every interactive path is redirected to `/setup`.
pub async fn require_credential(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path().to_string();
    let exempt = path == "/setup" || path.starts_with("/_assets") || path == "/healthz";
    if !exempt && !state.cred.read().await.is_set() {
        return Redirect::to("/setup").into_response();
    }
    next.run(request).await
}

/// Construct the full router. `guard` is applied after `require_credential`
/// so unauthenticated users see Setup rather than a blank 401.
///
/// Every resource now owns its own route table — the generic
/// `{resource}/{id}` dispatcher is gone along with schema-driven UI.
/// Build the complete router: resource routes, middleware stack, and the
/// body-size limit.
pub fn router(state: AppState) -> Router {
    let mut routes_ = Router::new()
        .route("/", get(home::index))
        .route("/setup", get(setup::show).post(setup::submit))
        .route("/healthz", get(|| async { "ok" }))
        // Routes
        .route("/routes", get(routes::list).post(routes::create))
        .route("/routes/new", get(routes::new_form))
        .route(
            "/routes/{id}",
            get(routes::edit)
                .post(routes::update)
                .delete(routes::delete),
        )
        .route("/routes/{id}/enable", post(routes::enable))
        .route("/routes/{id}/disable", post(routes::disable))
        // IdPs
        .route("/idps", get(idps::list).post(idps::create))
        .route("/idps/new", get(idps::new_form))
        .route(
            "/idps/{id}",
            get(idps::edit).post(idps::update).delete(idps::delete),
        )
        // Policies
        .route("/policies", get(policies::list).post(policies::create))
        .route("/policies/new", get(policies::new_form))
        .route(
            "/policies/{id}",
            get(policies::edit)
                .post(policies::update)
                .delete(policies::delete),
        )
        // Read-mostly resources with bespoke UX.
        .route("/api_keys", get(api_keys::list).post(api_keys::create))
        .route("/api_keys/{id}", delete(api_keys::delete))
        .route("/sessions", get(sessions::list))
        .route("/sessions/{id}", delete(sessions::delete))
        // Cert acquisition is route-driven (`enable route` triggers
        // ACME via api-protocol::ensure_cert_before_enable). No
        // standalone "request a cert by domain" UI: that would mint
        // an unparented cert and contradict the route-as-source-of-
        // truth model the CLI already follows.
        .route("/certificates", get(certificates::list))
        .route("/certificates/upload", post(certificates::upload))
        .route("/certificates/{id}", delete(certificates::delete))
        // Consolidated General page hosts everyday config plus the
        // Danger Zone (Instance config + DEK ring rotation).
        // Sub-handlers POST to nested paths so each form owns its
        // own request shape.
        .route("/general", get(general::show).post(general::update))
        .route("/general/instance", post(instance::update))
        // DEK ring management. The four POST verbs all re-render the
        // consolidated General page so success / error banners stay
        // anchored at the operator's submission point. `rotate` lives
        // before the `{key_id}` route so axum's matcher doesn't try to
        // parse "rotate" as an i16.
        .route("/general/encryption_keys", post(encryption_keys::add))
        .route(
            "/general/encryption_keys/rotate",
            post(encryption_keys::rotate),
        )
        .route(
            "/general/encryption_keys/{key_id}/activate",
            post(encryption_keys::activate),
        )
        .route(
            "/general/encryption_keys/{key_id}/retire",
            post(encryption_keys::retire),
        )
        // Unknown path → framed 404 page. Inherits the same middleware
        // stack as regular routes, so an unauthenticated request
        // still redirects to /setup rather than leaking the existence
        // of arbitrary URLs.
        .fallback(not_found);

    routes_ = routes_
        // CSRF must run inside the body-size limit (so huge bodies don't
        // reach it) but before user-supplied Form extractors, which consume
        // the body. axum applies layers outer-to-inner based on the call
        // order, so this ordering is:
        //   body-size → guard → require_credential → csrf → handler
        // which means csrf sees the original body but only after auth.
        .layer(middleware::from_fn(crate::csrf::middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_credential,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::guard::guard,
        ))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_BODY_BYTES,
        ))
        // Admin pages are dynamic and reflect server-side state that
        // changes on every PATCH (route fields, IdP secrets-redaction,
        // ACME election state). A stale cached page is dangerous: the
        // operator looks at it, sees an unticked checkbox, hits Save,
        // and silently clears a flag the previous tab had already set.
        // Force a fresh fetch on every navigation. Applied only to
        // the dynamic-route layer; the asset router merged below
        // keeps its own caching posture.
        .layer(middleware::from_fn(no_store_cache));

    // Static bundled assets are merged at the top level so they are not
    // subject to CSRF / credential-required / body-limit layers — they're
    // cacheable public files, not authenticated operations.
    routes_.merge(crate::assets::router()).with_state(state)
}

/// Tag every admin-page response as `Cache-Control: no-store` so a
/// browser back-button or refresh re-fetches the current server state
/// instead of replaying a snapshot from a previous deploy. Static
/// assets are not affected — they're served by the unmounted asset
/// router and explicitly want long-lived caching.
async fn no_store_cache(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    resp
}

/// Router fallback: any path the table above doesn't claim lands
/// here. `common::not_found` sets status 404 and renders the page
/// with the nav bar so the user can navigate away.
async fn not_found(
    State(state): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    common::not_found(&state, user.as_deref())
}
