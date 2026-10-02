//! Authorized request forwarding.
//!
//! This module owns the boundary after routing and authorization: preparing
//! the trusted identity, applying transforms, selecting the HTTP/WebSocket
//! transport, enforcing upload limits, and translating upstream failures.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, uri::Uri};
use metrics::counter;
use std::sync::Arc;

use crate::models::route::Route;
use crate::models::session::Session;
use crate::state::AppState;

use super::response_lease::RouteResponseLease;
use super::{RouteClientCache, WebSocketBudget, websocket};

/// Borrowed per-request forwarding context that is not part of the request.
#[derive(Clone, Copy)]
pub(super) struct ForwardingRuntime<'a> {
    pub(super) shutdown_ctl: &'a Arc<crate::shutdown::ShutdownController>,
    pub(super) websocket_budget: &'a WebSocketBudget,
    pub(super) selection: &'a crate::route_generation::RouteSelection,
}

/// Rewrite an authorized request and send it upstream.
///
/// Order matters: signed-identity claims are prepared before selecting an
/// upstream or rewriting a header, so a rejected assertion has no upstream
/// side effect.
pub(super) async fn forward_request(
    state: AppState,
    mut req: Request<Body>,
    route: &Route,
    session: Option<&Session>,
    client_host: &str,
    runtime: ForwardingRuntime<'_>,
    lease: &mut RouteResponseLease,
) -> Result<Response<Body>, StatusCode> {
    let prepared_identity_claims = if route.enable_signed_identity {
        match session {
            Some(session) => {
                let identity = session
                    .upstream_identity
                    .as_ref()
                    .ok_or(StatusCode::FORBIDDEN)?;
                Some(
                    state
                        .identity_authority
                        .prepare_claims(
                            route.signed_identity_input(),
                            identity,
                            &session.groups,
                            chrono::Utc::now(),
                        )
                        .map_err(|error| match error {
                            crate::identity::IdentityError::MissingExplicitEmail => {
                                StatusCode::FORBIDDEN
                            }
                            _ => {
                                tracing::error!(%error, route = %route.name, "signed identity preparation failed");
                                StatusCode::SERVICE_UNAVAILABLE
                            }
                        })?,
                )
            }
            None => None,
        }
    } else {
        None
    };

    let idx =
        runtime
            .selection
            .load_balancer
            .select(route.id, route.to.len(), &route.load_balancing);
    let upstream_base = route.to[idx].clone();

    let client_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());
    let ctx = super::transform::TransformContext {
        tls_enabled: state.tls_enabled,
        client_host,
        client_ip: client_ip.as_deref(),
        session,
        prepared_identity_claims: prepared_identity_claims.as_ref(),
        identity_key_ring: state.identity_key_ring(),
        session_cookie_name: &state.session_cookie_name,
    };

    let canonical_path = req
        .extensions()
        .get::<crate::request_target::CanonicalRequestTarget>()
        .ok_or(StatusCode::BAD_REQUEST)?
        .path()
        .to_owned();
    super::transform::apply_path_rewrite_compiled(
        &mut req,
        route,
        &canonical_path,
        runtime.selection.rewrite.as_ref(),
    )?;

    let websocket_handshake = if route.enable_websocket {
        super::header_boundary::classify_websocket_request(&req)?
    } else {
        None
    };
    if let Some(websocket_handshake) = websocket_handshake {
        req.extensions_mut().insert(websocket_handshake);
        let websocket_permit = match runtime.websocket_budget.try_acquire() {
            Ok(permit) => permit,
            Err(status) => {
                tracing::warn!(
                    route = %route.name,
                    "websocket concurrency limit reached, returning 503"
                );
                counter!(
                    "sekisho_proxy_websocket_capacity_rejected_total",
                    "route" => route.name.clone()
                )
                .increment(1);
                return Err(status);
            }
        };
        let response = websocket::handle_websocket(
            req,
            &upstream_base,
            route,
            &ctx,
            runtime.shutdown_ctl,
            &mut lease.permit,
            websocket_permit,
        )
        .await;
        if response
            .as_ref()
            .is_ok_and(|response| response.status() != StatusCode::SWITCHING_PROTOCOLS)
        {
            lease.idle_timeout = Some(std::time::Duration::from_millis(
                route.response_idle_timeout_ms,
            ));
        }
        return response;
    }

    lease.idle_timeout = Some(std::time::Duration::from_millis(
        route.response_idle_timeout_ms,
    ));

    let upstream_uri = build_upstream_uri(&upstream_base, req.uri())?;
    let (mut parts, body) = req.into_parts();
    parts.uri = upstream_uri;
    state.pipeline.apply_all(&mut parts, route, &ctx);

    let timeout = std::time::Duration::from_millis(route.timeout_ms);
    match tokio::time::timeout(
        timeout,
        send_upstream(
            state,
            parts,
            body,
            route,
            &upstream_base,
            client_host,
            &runtime.selection.clients,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(route = %route.name, timeout_ms = route.timeout_ms, "upstream request timed out");
            record_upstream_error(&route.name, "timeout");
            Err(StatusCode::GATEWAY_TIMEOUT)
        }
    }
}

fn record_upstream_error(route: &str, kind: &'static str) {
    counter!(
        "sekisho_proxy_upstream_errors_total",
        "route" => route.to_string(),
        "kind" => kind
    )
    .increment(1);
}

fn request_body_limit_exceeded(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = source {
        if error
            .downcast_ref::<http_body_util::LengthLimitError>()
            .is_some()
        {
            return true;
        }
        source = error.source();
    }
    false
}

fn record_request_body_limit(route: &Route) {
    tracing::warn!(
        route = %route.name,
        "request body exceeded proxy limit while streaming to upstream"
    );
    counter!(
        "sekisho_proxy_request_body_too_large_total",
        "route" => route.name.clone()
    )
    .increment(1);
}

/// Send the prepared request to the upstream, choosing the route-specific
/// reqwest client when authority rewriting or TLS relaxation requires it.
async fn send_upstream(
    state: AppState,
    parts: axum::http::request::Parts,
    body: Body,
    route: &Route,
    upstream_base: &str,
    public_host: &str,
    route_clients: &RouteClientCache,
) -> Result<Response<Body>, StatusCode> {
    let needs_route_client = route.tls_skip_verify || route.host_rewrite.is_some();
    if needs_route_client {
        let method_str = parts.method.to_string();
        let route_client = route_clients
            .get_or_build(route, upstream_base)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, route = %route.name, "failed to build route client");
                record_upstream_error(&route.name, "route_client_build");
                StatusCode::BAD_GATEWAY
            })?;
        let url = super::route_client::build_rewritten_url(&route_client, &parts.uri);
        let mut req_builder = route_client.client.request(
            reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET),
            url,
        );
        let skip_host_header = route_client.authority_rewritten;
        for (key, value) in &parts.headers {
            if skip_host_header && key == axum::http::header::HOST {
                continue;
            }
            if let Ok(value) = value.to_str() {
                req_builder = req_builder.header(key.as_str(), value);
            }
        }
        if !hyper::body::Body::is_end_stream(&body) {
            req_builder = req_builder.body(reqwest::Body::wrap_stream(body.into_data_stream()));
        }
        let resp = match req_builder.send().await {
            Ok(response) => response,
            Err(error) if request_body_limit_exceeded(&error) => {
                record_request_body_limit(route);
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Err(error) => {
                let mut chain = Vec::new();
                let mut source: Option<&dyn std::error::Error> = Some(&error);
                while let Some(error) = source {
                    chain.push(error.to_string());
                    source = error.source();
                }
                tracing::error!(
                    error = %error,
                    error_chain = ?chain,
                    route = %route.name,
                    "upstream request failed (insecure)"
                );
                record_upstream_error(&route.name, "upstream_send");
                return Err(StatusCode::BAD_GATEWAY);
            }
        };
        let status = resp.status();
        tracing::debug!(
            route = %route.name,
            upstream_status = %status.as_u16(),
            upstream_http_version = ?resp.version(),
            "route_client received upstream response"
        );
        let received_version = resp.version();
        let mut resp_headers = resp.headers().clone();
        super::header_boundary::sanitize_hop_by_hop(&mut resp_headers);
        super::transform::append_via_to_response(&mut resp_headers, received_version);
        super::transform::rewrite_response_location(&mut resp_headers, route, public_host);
        let body = Body::from_stream(resp.bytes_stream());
        let mut builder = Response::builder().status(status.as_u16());
        for (key, value) in &resp_headers {
            builder = builder.header(key, value);
        }
        builder
            .body(body)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        let upstream_req = Request::from_parts(parts, body);
        let resp = match state.client.request(upstream_req).await {
            Ok(response) => response,
            Err(error) if request_body_limit_exceeded(&error) => {
                record_request_body_limit(route);
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Err(error) => {
                tracing::error!(error = %error, route = %route.name, "upstream request failed");
                record_upstream_error(&route.name, "upstream_send");
                return Err(StatusCode::BAD_GATEWAY);
            }
        };
        let (mut parts, incoming) = resp.into_parts();
        super::header_boundary::sanitize_hop_by_hop(&mut parts.headers);
        super::transform::append_via_to_response(&mut parts.headers, parts.version);
        super::transform::rewrite_response_location(&mut parts.headers, route, public_host);
        let mut builder = Response::builder().status(parts.status);
        for (key, value) in &parts.headers {
            builder = builder.header(key, value);
        }
        builder
            .body(Body::new(incoming))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// Join an upstream base URL with the incoming path and query.
///
/// Shared with the WebSocket path, hence `pub` through the handler re-export.
pub fn build_upstream_uri(base: &str, original: &Uri) -> Result<Uri, StatusCode> {
    let base = base.trim_end_matches('/');
    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    format!("{base}{path_and_query}")
        .parse::<Uri>()
        .map_err(|error| {
            tracing::error!(%error, "failed to build upstream URI");
            StatusCode::BAD_GATEWAY
        })
}
