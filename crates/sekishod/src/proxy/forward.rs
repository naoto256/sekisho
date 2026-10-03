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

/// Borrowed per-request context that [`forward_request`] needs but that is
/// not part of the request itself. Grouped into one struct purely to keep the
/// argument list of an already long signature readable.
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
    // Prepare the complete assertion before selecting an upstream, rewriting
    // the request, or adding headers. A legacy session (or an upstream
    // identity without an explicit email) is therefore a fixed-safe 403 with
    // no data-plane side effect on both protected and public routes.
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

    // The selected generation owns the round-robin cursor, so a route mutation
    // cannot mix counters with a different upstream set. Random selection is
    // memoryless and does not touch that cursor. Both strategies are
    // deliberately node-local.
    let idx =
        runtime
            .selection
            .load_balancer
            .select(route.id, route.to.len(), &route.load_balancing);
    let upstream_base = route.to[idx].clone();

    // Build the same TransformContext both branches need. WebSocket
    // upgrades used to short-circuit the pipeline entirely, which
    // meant client-supplied `X-Sekisho-Jwt` / `X-Forwarded-*`
    // headers reached the upstream unchanged — and the trusted
    // identity headers were never injected. Now both paths receive
    // the same context, so `handle_websocket` can apply the safe
    // corresponding WS pipeline with its own connection-boundary sanitation.
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

    // A route-enabled WebSocket attempt must satisfy the complete downstream
    // handshake contract. Malformed attempts fail before any upstream work.
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

    // 1. Build upstream URI
    let upstream_uri = build_upstream_uri(&upstream_base, req.uri())?;
    let (mut parts, body) = req.into_parts();
    parts.uri = upstream_uri;
    // 2. Apply the remaining transform pipeline after path rewrite
    // (strip headers, rewrite host, add proxy/identity headers, route headers).
    state.pipeline.apply_all(&mut parts, route, &ctx);

    // 3. Send to upstream with route-level timeout
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

/// Single emission point for `sekisho_proxy_upstream_errors_total` so
/// every error site uses the same metric name and label set. `kind` is
/// a stable, low-cardinality enum (timeout / route_client_build /
/// upstream_send); never include error message text — it explodes cardinality.
fn record_upstream_error(route: &str, kind: &'static str) {
    counter!(
        "sekisho_proxy_upstream_errors_total",
        "route" => route.to_string(),
        "kind" => kind
    )
    .increment(1);
}

/// Walk either HTTP client's error chain looking for the typed local body
/// limit marker. Both clients must classify this before their generic
/// upstream-send branch so a client upload rejection is never counted as an
/// upstream failure.
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

/// Log and count an upload cut off at the proxy's body limit.
///
/// Kept separate from the generic upstream-failure path so the metric means
/// one thing: the client sent too much, not that the upstream broke. Both HTTP
/// clients call this from their own limit branch, and only one of them runs
/// for any given request, so a rejection is counted exactly once.
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
    // Use the per-route reqwest client whenever the route needs
    // cert-verification relaxation OR host authority rewriting.
    // host_rewrite has to go through this path even without
    // tls_skip_verify, because the rewrite must reshape the URL
    // authority (so that H2's `:authority` pseudo-header agrees
    // with the rewritten Host) and pin the TCP target via
    // `resolve()` — neither of which the raw hyper legacy client
    // supports.
    //
    // route_client also handles the `preserve_host_header: true`
    // implicit-rewrite case (sync URL authority to `route.from`'s
    // hostname so `:authority` and `Host` agree under H2 — RFC 9113
    // §8.3.1). The strict-H2 regression that motivated this hits
    // routes that already entered route_client via `tls_skip_verify`
    // (HTTPS to an internal IP appliance), so the gating below is
    // unchanged from the original `host_rewrite` fix. Routes with neither
    // `tls_skip_verify` nor `host_rewrite` that hit a strict H2
    // upstream would also benefit from route_client; we leave that
    // out of scope here to keep this fix narrow, since the legacy
    // hyper path has independent considerations (TCP-target pinning,
    // pool sharing) and no operator-reported regression yet.
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
        // Skip Host whenever the URL authority has been rewritten —
        // that's the case where the URL-derived `:authority` (under
        // H2) or the URL's host (under H1) is already carrying the
        // value we want the upstream to see, and forwarding a separate
        // Host header would either duplicate it (H2: trips RFC 9113
        // §8.3.1 on strict upstreams like nginx → 400 with empty
        // request line in access.log) or risk diverging from it.
        //
        // Two paths set `authority_rewritten`:
        //   1. Explicit `host_rewrite` (the original fix).
        //   2. `preserve_host_header: true` with no `host_rewrite` —
        //      route_client rewrites the URL authority to
        //      `route.from`'s hostname so `:authority` matches the
        //      inbound Host on the wire.
        //
        // When the authority is *not* rewritten (e.g. a tls_skip_verify
        // route with `preserve_host_header: false` against an internal
        // IP appliance), the URL authority is the backend's own IP.
        // Stripping Host there would surface `Host: 192.0.2.16` to
        // the appliance and break Host-derived redirect URLs (many
        // network appliances emit `Location: https://<own-IP>/...`).
        // Preserving the original Host on that branch keeps the
        // appliance's notion of itself aligned with the public
        // hostname.
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
            // The router's observed body-limit adapter remains the byte-budget
            // authority. Passing its body through as a stream preserves
            // backpressure and avoids retaining and copying the full upload.
            // Streaming bodies are intentionally not replayable by reqwest.
            // A declared `Content-Length` above the cap fails before the
            // upstream connection is opened; unknown-size and chunked
            // uploads may forward up to the cap and surface the same 413
            // mid-stream.
            req_builder = req_builder.body(reqwest::Body::wrap_stream(body.into_data_stream()));
        }
        let resp = match req_builder.send().await {
            Ok(response) => response,
            Err(error) if request_body_limit_exceeded(&error) => {
                record_request_body_limit(route);
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            Err(error) => {
                // reqwest's Display is shallow — chain through .source() so we
                // see which layer actually broke (TLS? connect? H2 frame?).
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
        // Drop RFC 7230 §6.1 hop-by-hop headers BEFORE we add our
        // own Via, so the proxy's contribution survives even if
        // upstream tried to pass through a hop-by-hop Via somehow.
        // reqwest/hyper has already decoded the upstream transfer
        // framing. Transfer-Encoding is hop-by-hop, so it is not
        // copied across the proxy boundary; downstream framing is
        // chosen by Hyper.
        super::header_boundary::sanitize_hop_by_hop(&mut resp_headers);
        super::transform::append_via_to_response(&mut resp_headers, received_version);
        super::transform::rewrite_response_location(&mut resp_headers, route, public_host);
        // Current reqwest build enables none of
        // gzip/brotli/deflate/zstd, so `bytes_stream` is not
        // auto-decompressed; `Content-Length` is copied if present.
        // Re-audit header/body forwarding if reqwest features or
        // client configuration change.
        let body = Body::from_stream(resp.bytes_stream());
        let mut builder = Response::builder().status(status.as_u16());
        for (key, value) in &resp_headers {
            builder = builder.header(key, value);
        }
        builder
            .body(body)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        // Standard hyper client
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
/// The base's trailing slash is trimmed because `route.to` is written both
/// ways by operators and the path always starts with one; without the trim
/// every such route would produce a `//` prefix that some upstreams treat as
/// a distinct path. The path component has already been canonicalized and
/// re-encoded upstream of here, so this is a concatenation, not a place to
/// re-sanitize.
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
