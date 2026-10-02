//! The proxy request path: match, authenticate, authorize, forward.
//!
//! [`proxy_handler`] is the fallback for everything not claimed by the
//! internal `/.sekisho` surface. In order it resolves a route from the
//! `Host` and canonical path, answers redirect-only routes, decides whether
//! the caller may proceed, applies the outbound transform pipeline, and
//! forwards to an upstream.
//!
//! ## Why the handler is split in two
//!
//! [`proxy_handler_inner`] returns `Result<_, StatusCode>` so the whole path
//! can use `?`; [`proxy_handler`] is the thin wrapper that turns that back
//! into a response. The wrapper exists because two things must happen on the
//! error path as well as the success path, and `?` would skip them:
//!
//! - The matched route id has to reach the response extensions so the edge
//!   metric can label a 403 or a 502 with the route that produced it. It
//!   travels out through an `&mut Option<String>` parameter rather than the
//!   return value, because by definition the error path has no return value
//!   to carry it.
//! - Permits and timers acquired mid-request have to outlive the handler —
//!   see below.
//!
//! ## Resource leases outlive the handler
//!
//! A route's concurrency permit must be held until the response body is fully
//! delivered, not until the handler returns, or a slow transfer would sit
//! outside the limit that is supposed to bound it. [`RouteResponseLease`]
//! collects whatever the request acquired and the response-body lease drops
//! the permit on the last frame.
//!
//! The same wrapper enforces `response_idle_timeout_ms`. It is a *timer reset
//! by each non-empty DATA frame*, not a total deadline — a large download and
//! a stalled upstream look identical if you only measure total elapsed time,
//! and only the second one should be killed. `timeout_ms` is the separate,
//! earlier deadline that ends when response headers arrive.
//!
//! ## Fail closed, and fail before side effects
//!
//! [`forward_request`] builds the signed-identity claim set *before* selecting
//! an upstream or touching headers, so a session that cannot produce a
//! trustworthy assertion turns into a 403 with nothing having happened
//! upstream. Errors are answered through [`proxy_error`] with a fixed,
//! route-independent message: the caller is an untrusted browser, and which
//! rule refused it is information it does not get.

use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{Request, Response, StatusCode, header, uri::Uri};
use metrics::counter;

use crate::auth::strategy::initiate_auth;
use crate::models::route::Route;
use crate::observability::MatchedRouteId;
use std::sync::Arc;

use super::WebSocketBudget;
use super::error_response::proxy_error;
pub(crate) use super::error_response::{
    ProxyErrorKind, ProxyErrorRepresentation, legacy_proxy_error_response,
    proxy_error_representation, proxy_error_response,
};
pub use super::forward::build_upstream_uri;
use super::forward::{ForwardingRuntime, forward_request};
use super::response_lease::RouteResponseLease;
use crate::state::AppState;

/// Entry point for all proxied traffic.
///
/// Thin by design: it exists to attach the matched-route label and the
/// resource lease to whatever [`proxy_handler_inner`] produced. See the module
/// docs for why those two cannot live inside the `?`-using inner function.
pub async fn proxy_handler(
    state: State<AppState>,
    Extension(shutdown_ctl): Extension<Arc<crate::shutdown::ShutdownController>>,
    Extension(websocket_budget): Extension<WebSocketBudget>,
    req: Request<Body>,
) -> Response<Body> {
    let representation = proxy_error_representation(req.headers());
    // Out-parameter so the matched route id survives the Result boundary
    // and ends up on the response extensions for both success and error
    // paths. Edge metric reads it via MatchedRouteId.
    let mut matched: Option<String> = None;
    let mut lease = RouteResponseLease::new();
    let mut resp = match proxy_handler_inner(
        state,
        req,
        &shutdown_ctl,
        &websocket_budget,
        &mut matched,
        &mut lease,
    )
    .await
    {
        Ok(resp) => resp,
        Err(status) => proxy_error(status, representation),
    };
    if let Some(route_id) = matched {
        resp.extensions_mut().insert(MatchedRouteId(route_id));
    }
    lease.wrap(resp)
}

/// The actual request path, written against `Result` so every rejection is a
/// `?` rather than an early return that could forget the response bookkeeping.
async fn proxy_handler_inner(
    State(state): State<AppState>,
    req: Request<Body>,
    shutdown_ctl: &Arc<crate::shutdown::ShutdownController>,
    websocket_budget: &WebSocketBudget,
    matched_route: &mut Option<String>,
    lease: &mut RouteResponseLease,
) -> Result<Response<Body>, StatusCode> {
    // Reject TRACE (and the Microsoft TRACK extension) before any
    // policy / routing kicks in. TRACE echoes the request back as
    // the response body, including Cookie / Authorization, which
    // turns the proxy into the perfect Cross-Site Tracing (XST)
    // delivery vehicle. Even if the upstream disables it, a proxy
    // worth its name doesn't depend on the upstream's posture for a
    // method this dangerous.
    if matches!(req.method().as_str(), "TRACE" | "TRACK") {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }

    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let hostname = host.split(':').next().unwrap_or(&host);

    let raw_request_path = req.uri().path().to_owned();
    let request_path = req
        .extensions()
        .get::<crate::request_target::CanonicalRequestTarget>()
        .ok_or(StatusCode::BAD_REQUEST)?
        .path()
        .to_owned();

    // Internal `/.sekisho/*` endpoints are served by the axum router before
    // this fallback is reached. If one ever falls through — e.g. a trailing
    // slash or an unknown subpath that doesn't match a nested route — we
    // must NOT run it through route-policy evaluation: signout in
    // particular has to remain callable even when the user's session is
    // being denied by the route they came from. Short-circuit to 404 here
    // (the request was for an internal path that doesn't exist) rather
    // than pretending a proxied route might match.
    if is_internal_path(&request_path) {
        tracing::debug!(
            "internal path fell through proxy; returning 404 without policy evaluation"
        );
        return Err(StatusCode::NOT_FOUND);
    }

    // Match route (hostname + longest path prefix)
    let mut selection = match find_route(&state, hostname, &request_path).await? {
        Some(selection) => selection,
        None => {
            tracing::debug!(host = %host, "no route matched");
            return Err(StatusCode::NOT_FOUND);
        }
    };
    let route = Arc::clone(&selection.route);

    // Stamp route id so the edge metric attributes the response (and any
    // downstream error response) to this route. Done eagerly: even if a
    // policy deny or upstream failure follows, the metric should bucket
    // by the route the request was *for*.
    *matched_route = Some(route.name.clone());
    lease.route = Some(route.name.clone());

    // Per-route concurrency cap. Held for the life of the request so a
    // slow upstream on one route can't starve the global pool. Routes
    // with no `concurrency_limit` skip this per-route budget while the
    // proxy-wide HTTP budget remains in force. `try_acquire_owned` is
    // non-blocking — over-cap requests get 503 immediately rather than
    // queueing behind the slow upstream that filled the bucket.
    lease.permit = if let Some(limit) = route.concurrency_limit {
        match selection.take_permit() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(
                    route = %route.name,
                    limit,
                    "per-route concurrency limit reached, returning 503"
                );
                counter!(
                    "sekisho_proxy_route_concurrency_rejected_total",
                    "route" => route.name.clone()
                )
                .increment(1);
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        }
    } else {
        None
    };

    // Handle redirect routes (no upstream needed)
    if let Some(ref redirect) = route.redirect {
        return handle_redirect(&route.from, &raw_request_path, redirect);
    }

    if route.to.is_empty() {
        tracing::error!(route = %route.name, "route has no upstreams and no redirect");
        return Err(StatusCode::BAD_GATEWAY);
    }

    // Check if public access is allowed
    if !route.access.allow_public_unauthenticated_access {
        // Check session
        let cookie_header = req
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok());

        // Session lookup outcomes:
        //   Ok(s)         — treat as authenticated with `s`.
        //   Err(NotFound) — cookie referenced a session that is
        //                   expired or deleted; fall through to
        //                   `initiate_auth` below as unauthenticated.
        //   Err(other)    — any non-NotFound validation or storage
        //                   failure returns 500 rather than falling
        //                   back to unauthenticated, so an outage
        //                   does not surface as an unrelated login
        //                   prompt.
        let session = match state.cookie_manager.get_session_id(cookie_header) {
            Some(session_id) => match state.session_manager.validate(session_id).await {
                Ok(s) => Some(s),
                Err(crate::error::Error::NotFound) => None,
                Err(e) => {
                    tracing::error!(error = %e, "session validation failed (database error)");
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            },
            None => None,
        };

        match session {
            Some(session) => {
                let client_ip = extract_client_ip(&req);
                let client_port = req
                    .extensions()
                    .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    .map(|ci| ci.0.port());
                let request_method = req.method().as_str().to_string();
                let request_host = hostname.to_string();
                let request_headers: std::collections::HashMap<String, String> = req
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|vs| (k.as_str().to_ascii_lowercase(), vs.to_string()))
                    })
                    .collect();

                let ctx = crate::policy::EvalContext {
                    session: Some(&session),
                    client_ip,
                    client_port,
                    request_method: Some(&request_method),
                    request_path: Some(&request_path),
                    request_host: Some(&request_host),
                    request_headers: Some(&request_headers),
                };

                if !evaluate_route_access(&route, &ctx, &state.store).await {
                    tracing::warn!(
                        user = %session.user_id,
                        route = %route.name,
                        "access denied by policy"
                    );
                    counter!(
                        "sekisho_proxy_policy_denied_total",
                        "route" => route.name.clone(),
                        "reason" => "policy_deny"
                    )
                    .increment(1);
                    return Err(StatusCode::FORBIDDEN);
                }
                tracing::debug!(
                    user = %session.user_id,
                    route = %route.name,
                    "access granted"
                );
                return forward_request(
                    state,
                    req,
                    &route,
                    Some(&session),
                    &host,
                    ForwardingRuntime {
                        shutdown_ctl,
                        websocket_budget,
                        selection: &selection,
                    },
                    lease,
                )
                .await;
            }
            None => {
                tracing::debug!(route = %route.name, "unauthenticated request, redirecting to IdP");
                let original_url = format!("https://{host}{}", req.uri());

                // Resolve IdP: route-specific > config default
                let idp_id = match route.idp_id {
                    Some(id) => id,
                    None => {
                        let config = state.store.get_config().await.map_err(|e| {
                            tracing::error!(error = %e, "failed to get config");
                            StatusCode::INTERNAL_SERVER_ERROR
                        })?;
                        config.default_idp_id.ok_or_else(|| {
                            tracing::error!(
                                "no IdP configured for route and no default_idp_id in config"
                            );
                            StatusCode::SERVICE_UNAVAILABLE
                        })?
                    }
                };

                return initiate_auth(&state, idp_id, &original_url).await;
            }
        }
    }

    // Public route — still try to read session for optional identity headers
    let cookie_header = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());

    let session = match state.cookie_manager.get_session_id(cookie_header) {
        Some(session_id) => match state.session_manager.validate(session_id).await {
            Ok(s) => Some(s),
            Err(crate::error::Error::NotFound) => None,
            Err(e) => {
                // Public route: log the error but proceed without session
                tracing::warn!(error = %e, "session validation failed on public route");
                None
            }
        },
        None => None,
    };

    forward_request(
        state,
        req,
        &route,
        session.as_ref(),
        &host,
        ForwardingRuntime {
            shutdown_ctl,
            websocket_budget,
            selection: &selection,
        },
        lease,
    )
    .await
}

/// Evaluate the route's `access.policy` expression. The AST is parsed once
/// per unique expression string and then reused via `parse_cached`; the
/// fallback for a missing policy or a parse error remains fail-closed
/// (deny). Use `policy.<name>` inside the expression to reference a
/// reusable named Policy resource.
pub async fn evaluate_route_access(
    route: &Route,
    ctx: &crate::policy::EvalContext<'_>,
    store: &crate::store::Store,
) -> bool {
    let Some(expr_str) = route.access.policy.as_deref() else {
        return false;
    };
    match crate::policy::parse_cached(expr_str) {
        Ok(expr) => crate::policy::evaluate(&expr, ctx, store).await,
        Err(e) => {
            tracing::warn!(route = %route.name, error = %e, "route policy failed to parse");
            false
        }
    }
}

/// Extract the client IP used for policy evaluation (`client.ip`).
///
/// Returns the TCP peer IP only. `X-Forwarded-For` is deliberately ignored
/// here: it is client-controlled and `client.ip` feeds IP allow-lists in the
/// policy DSL, so honoring the header would let an attacker bypass
/// `client.ip in [...]` rules by setting the header themselves. The header
/// is also stripped on the inbound side by
/// `transform::strip_user_supplied_proxy_headers` (run from
/// `transform::StripInternalHeaders`), and route config cannot re-add it
/// because `header_boundary::is_reserved_route_header` covers the whole
/// `x-forwarded-` prefix — the `AddProxyHeaders` transform re-adds a trusted
/// value derived from this peer IP before forwarding.
///
/// Trusted-proxy handling (honouring XFF from a configured front LB)
/// is not implemented; until then, deployments must terminate TLS
/// directly at `sekisho` — a front proxy or load balancer appears
/// here only as the TCP peer address.
fn extract_client_ip(req: &Request<Body>) -> Option<std::net::IpAddr> {
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Is this path reserved for sekisho's own internal endpoints
/// (mounted under `/.sekisho/*` by `proxy::router`)?
///
/// The proxy fallback uses this to opt such paths out of the route-match
/// / policy-evaluation flow. The axum router normally serves them
/// directly, but if a request ever falls through (unknown subpath,
/// trailing slash, etc.) we return 404 rather than letting a deny policy
/// on the matched route swallow signout / signin / userinfo.
pub(super) fn is_internal_path(path: &str) -> bool {
    path.starts_with("/.sekisho/") || path == "/.sekisho"
}

/// Build the response for a redirect-only route.
///
/// Always `https://`: a redirect emitted by an IAP that downgrades the scheme
/// would strip the protection the route exists to provide. An unset
/// `host_redirect` means "same host", taken from the route's own `from`
/// rather than from the request's `Host` header — the header is
/// client-controlled, and reflecting it would make this an open redirect.
/// An unset `path_redirect` preserves the original path.
fn handle_redirect(
    configured_from: &str,
    original_path: &str,
    redirect: &crate::models::route::RedirectRule,
) -> Result<Response<Body>, StatusCode> {
    let host = match redirect.host_redirect.as_deref() {
        Some(host) => host.to_string(),
        None => configured_from
            .parse::<Uri>()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .authority()
            .map(|authority| authority.as_str().to_string())
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?,
    };
    let path = redirect.path_redirect.as_deref().unwrap_or(original_path);
    let location = format!("https://{host}{path}");
    let code = redirect.code;

    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND);

    Response::builder()
        .status(status)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Resolve a request to a route against the currently published generation.
///
/// A one-line delegation, kept as a named function so the call site reads as
/// a routing step and so the lookup has one place to grow into if matching
/// ever needs more than the hostname and path.
async fn find_route(
    state: &AppState,
    hostname: &str,
    request_path: &str,
) -> Result<Option<crate::route_generation::RouteSelection>, StatusCode> {
    state.route_generation.find(hostname, request_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ConnectInfo;
    use axum::http::HeaderMap;
    use http_body_util::{BodyExt, Full};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct OneFrameBody(Option<Result<hyper::body::Frame<axum::body::Bytes>, std::io::Error>>);

    impl hyper::body::Body for OneFrameBody {
        type Data = axum::body::Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Ready(self.0.take())
        }
    }

    fn request_with_headers(peer: Option<SocketAddr>, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().uri("/");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        if let Some(addr) = peer {
            req.extensions_mut().insert(ConnectInfo(addr));
        }
        req
    }

    async fn headers_then_stall_case(use_route_client: bool) {
        use crate::store::Store;
        use crate::tls::acme::AcmeManager;
        use crate::tls::acme::challenge::Http01Provider;
        use tower::ServiceExt;

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _recorder_guard = metrics::set_default_local_recorder(&recorder);
        crate::observability::seed_control_budget_metrics_for_test();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let release_stalled = Arc::new(tokio::sync::Notify::new());
        let release_server = release_stalled.clone();
        let server = tokio::spawn(async move {
            for request_index in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept upstream");
                let mut received = Vec::new();
                loop {
                    let mut chunk = [0u8; 256];
                    let n = stream.read(&mut chunk).await.expect("read request");
                    assert!(n > 0, "request closed before headers");
                    received.extend_from_slice(&chunk[..n]);
                    if received.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
                    .await
                    .expect("write headers");
                if request_index == 0 {
                    release_server.notified().await;
                } else {
                    stream.write_all(b"done").await.expect("write body");
                }
            }
        });

        let store = Store::new_for_test("sqlite::memory:", [5u8; 32], None)
            .await
            .expect("store");
        let route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "streaming",
            "from": "https://stream.example.com",
            "to": [upstream],
            "access": {"allow_public_unauthenticated_access": true},
            "tls_skip_verify": use_route_client,
            "response_idle_timeout_ms": 50,
            "concurrency_limit": 1,
            "enabled": true
        }))
        .expect("route");
        store.create_route(&route).await.expect("persist route");
        let provider = Arc::new(Http01Provider::new(store.clone()));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            provider,
            "https://acme.invalid/directory",
            None,
        ));
        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;
        let app = crate::proxy::router(
            store,
            route_generation,
            &[1u8; 64],
            acme,
            crate::crypto::MasterKey::from_test_bytes([2u8; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([3u8; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            100,
            Arc::new(crate::shutdown::ShutdownController::new()),
        );
        let request = || {
            Request::builder()
                .uri("/")
                .header(header::HOST, "stream.example.com")
                .body(Body::empty())
                .unwrap()
        };

        let first = app
            .clone()
            .oneshot(request())
            .await
            .expect("first response");
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.headers()[header::CONTENT_LENGTH], "4");
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_http"
            ),
            Some(1.0),
            "global HTTP observation must follow the pending response body"
        );

        let rejected = app.clone().oneshot(request()).await.expect("rejection");
        assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(rejected);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_http"
            ),
            Some(1.0),
            "completed sibling response must release only its own observation"
        );

        let mut first_body = first.into_body();
        let timeout_frame = first_body.frame().await.expect("timeout frame");
        assert!(timeout_frame.is_err(), "stalled body must error");
        drop(first_body);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_http"
            ),
            Some(0.0)
        );
        release_stalled.notify_one();

        let recovered = app.oneshot(request()).await.expect("recovered response");
        assert_eq!(recovered.status(), StatusCode::OK);
        assert_eq!(recovered.headers()[header::CONTENT_LENGTH], "4");
        let bytes = recovered
            .into_body()
            .collect()
            .await
            .expect("recovered body")
            .to_bytes();
        assert_eq!(&bytes[..], b"done");
        server.await.expect("upstream task");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn legacy_hyper_body_stall_keeps_route_permit_until_idle_error() {
        headers_then_stall_case(false).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reqwest_body_stall_keeps_route_permit_until_idle_error() {
        headers_then_stall_case(true).await;
    }

    async fn build_test_proxy(
        routes: Vec<Route>,
        http_limit: usize,
        websocket_limit: u32,
        shutdown: Arc<crate::shutdown::ShutdownController>,
    ) -> axum::Router {
        use crate::store::Store;
        use crate::tls::acme::AcmeManager;
        use crate::tls::acme::challenge::Http01Provider;

        let store = Store::new_for_test("sqlite::memory:", [15u8; 32], None)
            .await
            .expect("store");
        for route in routes {
            store.create_route(&route).await.expect("persist route");
        }
        let provider = Arc::new(Http01Provider::new(store.clone()));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            provider,
            "https://acme.invalid/directory",
            None,
        ));
        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;
        crate::proxy::router_with_limits(
            store,
            route_generation,
            &[11u8; 64],
            acme,
            crate::crypto::MasterKey::from_test_bytes([12u8; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([13u8; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            crate::proxy::ProxyConcurrencyLimits {
                http: http_limit,
                websocket: websocket_limit,
            },
            8,
            shutdown.clone(),
        )
        .start_background_tasks(&shutdown)
    }

    /// A browser-shaped `Accept` gets the HTML page, and the page is the fixed
    /// one — no request value reaches it.
    #[tokio::test]
    async fn browser_accept_receives_fixed_html_proxy_error() {
        use tower::ServiceExt;

        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let app = build_test_proxy(Vec::new(), 2, 2, shutdown.clone()).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "missing.example.com")
                    .header(header::ACCEPT, "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert_eq!(response.headers().get(header::VARY).unwrap(), "Accept");
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(
            response
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("<main>"));
        assert!(!body.contains("missing.example.com"));
        shutdown.signal();
    }

    /// Negotiation is scoped to refusals Sekisho owns. An error the upstream
    /// produced passes through as the upstream wrote it, even when the client
    /// asked for HTML.
    #[tokio::test]
    async fn browser_accept_does_not_rewrite_upstream_error_response() {
        use tower::ServiceExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream = listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept upstream");
            let _ = read_http_headers(&mut stream).await;
            use tokio::io::AsyncWriteExt;
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nX-Upstream: kept\r\n\r\norigin down",
                )
                .await
                .expect("write upstream response");
        });
        let route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "upstream-pass-through",
            "from": "https://upstream-pass.example.com",
            "to": [format!("http://{upstream}")],
            "access": {"allow_public_unauthenticated_access": true},
            "enabled": true
        }))
        .unwrap();
        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let app = build_test_proxy(vec![route], 2, 2, shutdown.clone()).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "upstream-pass.example.com")
                    .header(header::ACCEPT, "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
        assert_eq!(response.headers()["x-upstream"], "kept");
        assert!(!response.headers().contains_key(header::VARY));
        assert!(
            !response
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"origin down");
        upstream_task.await.unwrap();
        shutdown.signal();
    }

    async fn spawn_test_proxy(app: axum::Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy");
        let addr = listener.local_addr().expect("proxy address");
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve proxy");
        });
        (addr, task)
    }

    async fn spawn_h2_tls_upstream() -> (String, tokio::task::JoinHandle<()>) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind HTTP/2 upstream");
        let addr = listener.local_addr().expect("HTTP/2 upstream address");

        let params = rcgen::CertificateParams::new(vec!["localhost".into()])
            .expect("certificate parameters");
        let key_pair = rcgen::KeyPair::generate().expect("certificate key");
        let cert = params
            .self_signed(&key_pair)
            .expect("self-signed certificate");
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("TLS server configuration");
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept HTTP/2 upstream");
            let tls = acceptor.accept(tcp).await.expect("accept HTTP/2 TLS");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let service = hyper::service::service_fn(|request| async move {
                assert_eq!(request.version(), axum::http::Version::HTTP_2);
                let mut response = Response::new(Full::new(axum::body::Bytes::from_static(b"ok")));
                response.headers_mut().append(
                    header::VIA,
                    axum::http::HeaderValue::from_static("1.0 upstream"),
                );
                Ok::<_, std::convert::Infallible>(response)
            });
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                .await
                .expect("serve HTTP/2 upstream");
        });
        (format!("https://{addr}"), task)
    }

    #[tokio::test]
    async fn route_client_response_via_uses_received_http2_version() {
        use tower::ServiceExt;

        let (upstream, upstream_task) = spawn_h2_tls_upstream().await;
        let mut route = websocket_route(
            "route-client-h2".into(),
            "route-client-h2.example",
            &upstream,
        );
        route.enable_websocket = false;
        route.tls_skip_verify = true;
        let app = build_test_proxy(
            vec![route],
            4,
            4,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "route-client-h2.example")
                    .body(Body::empty())
                    .expect("HTTP/2 route request"),
            )
            .await
            .expect("HTTP/2 route response");
        assert_eq!(response.status(), StatusCode::OK);
        let via = response
            .headers()
            .get_all(header::VIA)
            .iter()
            .map(|value| value.to_str().expect("Via text"))
            .collect::<Vec<_>>();
        assert_eq!(via, vec!["1.0 upstream", "2 sekisho"]);
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("HTTP/2 response body")
                .to_bytes(),
            "ok"
        );
        upstream_task.await.expect("HTTP/2 upstream task");
    }

    async fn read_http_headers(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut headers = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.expect("read response");
                headers.push(byte[0]);
                if headers.ends_with(b"\r\n\r\n") {
                    return headers;
                }
            }
        })
        .await
        .expect("response headers timeout")
    }

    fn response_content_length(headers: &[u8]) -> usize {
        std::str::from_utf8(headers)
            .expect("response headers utf8")
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
            })
            .unwrap_or(0)
    }

    fn assert_websocket_upgrade_headers(headers: &[u8]) {
        assert!(headers.starts_with(b"HTTP/1.1 101"));
        let headers = String::from_utf8_lossy(headers).to_ascii_lowercase();
        assert!(headers.contains("\r\nconnection: upgrade\r\n"));
        assert!(headers.contains("\r\nupgrade: websocket\r\n"));
        assert!(headers.contains("\r\nsec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=\r\n"));
    }

    async fn raw_proxy_request(
        proxy: SocketAddr,
        host: &str,
        websocket: bool,
    ) -> (tokio::net::TcpStream, Vec<u8>) {
        raw_proxy_request_target(proxy, host, "/", websocket).await
    }

    async fn raw_proxy_request_target(
        proxy: SocketAddr,
        host: &str,
        target: &str,
        websocket: bool,
    ) -> (tokio::net::TcpStream, Vec<u8>) {
        let mut stream = tokio::net::TcpStream::connect(proxy)
            .await
            .expect("connect proxy");
        let request = if websocket {
            format!(
                "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
        } else {
            format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
        };
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write proxy request");
        let headers = read_http_headers(&mut stream).await;
        (stream, headers)
    }

    async fn raw_proxy_custom_request(
        proxy: SocketAddr,
        request: &[u8],
    ) -> (tokio::net::TcpStream, Vec<u8>) {
        let mut stream = tokio::net::TcpStream::connect(proxy)
            .await
            .expect("connect proxy");
        stream
            .write_all(request)
            .await
            .expect("write proxy request");
        let headers = read_http_headers(&mut stream).await;
        (stream, headers)
    }

    async fn read_upstream_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 256];
            let n = stream
                .read(&mut chunk)
                .await
                .expect("read upstream request");
            assert!(n > 0, "request closed before headers");
            request.extend_from_slice(&chunk[..n]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return request;
            }
        }
    }

    #[derive(Debug)]
    enum UploadEvent {
        Started(Option<usize>),
        FirstData(usize),
        Finished { bytes: usize, error: bool },
    }

    async fn spawn_upload_observer() -> (
        SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<UploadEvent>,
        tokio::task::JoinHandle<()>,
    ) {
        async fn observe(
            State(events): State<tokio::sync::mpsc::UnboundedSender<UploadEvent>>,
            req: Request<Body>,
        ) -> StatusCode {
            let content_length = req
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok());
            events
                .send(UploadEvent::Started(content_length))
                .expect("upload event receiver");

            let mut body = req.into_body();
            let mut bytes = 0usize;
            let mut first = true;
            while let Some(frame) = body.frame().await {
                match frame {
                    Ok(frame) => {
                        if let Some(data) = frame.data_ref() {
                            bytes += data.len();
                            if first && !data.is_empty() {
                                first = false;
                                events
                                    .send(UploadEvent::FirstData(bytes))
                                    .expect("upload event receiver");
                            }
                        }
                    }
                    Err(_) => {
                        events
                            .send(UploadEvent::Finished { bytes, error: true })
                            .expect("upload event receiver");
                        return StatusCode::BAD_REQUEST;
                    }
                }
            }
            events
                .send(UploadEvent::Finished {
                    bytes,
                    error: false,
                })
                .expect("upload event receiver");
            StatusCode::OK
        }

        let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
        let app = axum::Router::new()
            .fallback(axum::routing::any(observe))
            .with_state(events_tx);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upload observer");
        let addr = listener.local_addr().expect("upload observer address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve upload observer");
        });
        (addr, events_rx, task)
    }

    fn upload_route_with_transport(host: &str, upstream: SocketAddr, route_client: bool) -> Route {
        serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": format!("upload-{host}"),
            "from": format!("https://{host}"),
            "to": [format!("http://{upstream}")],
            "access": {"allow_public_unauthenticated_access": true},
            "tls_skip_verify": route_client,
            "concurrency_limit": 1,
            "enabled": true
        }))
        .expect("upload route")
    }

    fn upload_route(host: &str, upstream: SocketAddr) -> Route {
        upload_route_with_transport(host, upstream, true)
    }

    async fn next_upload_event(
        events: &mut tokio::sync::mpsc::UnboundedReceiver<UploadEvent>,
    ) -> UploadEvent {
        tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
            .await
            .expect("upload event timeout")
            .expect("upload observer stopped")
    }

    async fn open_upload(proxy: SocketAddr, host: &str, framing: &str) -> tokio::net::TcpStream {
        let mut stream = tokio::net::TcpStream::connect(proxy)
            .await
            .expect("connect proxy");
        let headers =
            format!("POST /upload HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{framing}\r\n");
        stream
            .write_all(headers.as_bytes())
            .await
            .expect("write upload headers");
        stream
    }

    async fn write_chunked(stream: &mut tokio::net::TcpStream, data: &[u8]) {
        for chunk in data.chunks(64 * 1024) {
            stream
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .expect("write chunk size");
            stream.write_all(chunk).await.expect("write chunk data");
            stream.write_all(b"\r\n").await.expect("write chunk end");
        }
        stream
            .write_all(b"0\r\n\r\n")
            .await
            .expect("finish chunked body");
    }

    async fn assert_ok_response(stream: &mut tokio::net::TcpStream) {
        let headers = read_http_headers(stream).await;
        assert!(
            headers.starts_with(b"HTTP/1.1 200"),
            "expected safe success"
        );
    }

    async fn rendered_metrics() -> String {
        let body = crate::observability::metrics_handler()
            .await
            .expect("metrics response")
            .into_body()
            .collect()
            .await
            .expect("metrics body")
            .to_bytes();
        std::str::from_utf8(&body)
            .expect("metrics utf8")
            .to_string()
    }

    fn metric_sample(rendered: &str, name: &str, budget: &str) -> Option<f64> {
        rendered.lines().find_map(|line| {
            let prefix = format!("{name}{{budget=\"{budget}\"}} ");
            line.strip_prefix(&prefix)?.parse().ok()
        })
    }

    #[tokio::test]
    async fn route_client_streams_upload_before_client_completion_and_preserves_bodyless() {
        let (upstream_addr, mut events, upstream_task) = spawn_upload_observer().await;
        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let app = build_test_proxy(
            vec![upload_route("upload-stream.example", upstream_addr)],
            1,
            1,
            shutdown,
        )
        .await;
        let (proxy_addr, proxy_task) = spawn_test_proxy(app).await;

        let mut upload = open_upload(
            proxy_addr,
            "upload-stream.example",
            "Content-Length: 10\r\n",
        )
        .await;
        upload.write_all(b"first").await.expect("write first half");
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Started(Some(10))
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::FirstData(5)
        ));
        upload
            .write_all(b"second")
            .await
            .expect("write second half");
        assert_ok_response(&mut upload).await;
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Finished {
                bytes: 10,
                error: false
            }
        ));

        let mut bodyless =
            open_upload(proxy_addr, "upload-stream.example", "Content-Length: 0\r\n").await;
        assert_ok_response(&mut bodyless).await;
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Started(Some(0))
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Finished {
                bytes: 0,
                error: false
            }
        ));

        proxy_task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn route_client_enforces_known_and_chunked_upload_budget() {
        crate::observability::init_metrics();
        let limit = super::super::PROXY_BODY_LIMIT;
        let payload = vec![b'x'; limit];
        let (upstream_addr, mut events, upstream_task) = spawn_upload_observer().await;
        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let app = build_test_proxy(
            vec![upload_route("upload-limit.example", upstream_addr)],
            1,
            1,
            shutdown,
        )
        .await;
        let (proxy_addr, proxy_task) = spawn_test_proxy(app).await;

        let mut known = open_upload(
            proxy_addr,
            "upload-limit.example",
            &format!("Content-Length: {limit}\r\n"),
        )
        .await;
        known.write_all(&payload).await.expect("write known body");
        assert_ok_response(&mut known).await;
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Started(Some(value)) if value == limit
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::FirstData(value) if value <= limit
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Finished { bytes, error: false } if bytes == limit
        ));

        let mut oversized = open_upload(
            proxy_addr,
            "upload-limit.example",
            &format!("Content-Length: {}\r\n", limit + 1),
        )
        .await;
        let oversized_headers = read_http_headers(&mut oversized).await;
        assert!(oversized_headers.starts_with(b"HTTP/1.1 413"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), events.recv())
                .await
                .is_err(),
            "known oversized upload must not connect upstream"
        );

        let mut chunked = open_upload(
            proxy_addr,
            "upload-limit.example",
            "Transfer-Encoding: chunked\r\n",
        )
        .await;
        write_chunked(&mut chunked, &payload).await;
        assert_ok_response(&mut chunked).await;
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Started(None)
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::FirstData(value) if value <= limit
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Finished { bytes, error: false } if bytes == limit
        ));

        let sentinel = b"fixed-upload-secret-sentinel";
        let mut over_payload = payload;
        over_payload[..sentinel.len()].copy_from_slice(sentinel);
        over_payload.push(b'!');
        let mut chunked_over = open_upload(
            proxy_addr,
            "upload-limit.example",
            "Transfer-Encoding: chunked\r\nAccept: text/html\r\n",
        )
        .await;
        write_chunked(&mut chunked_over, &over_payload).await;
        let rejection_headers = read_http_headers(&mut chunked_over).await;
        assert!(rejection_headers.starts_with(b"HTTP/1.1 413"));
        assert!(
            rejection_headers
                .windows(b"content-type: text/html; charset=utf-8".len())
                .any(|value| value.eq_ignore_ascii_case(b"content-type: text/html; charset=utf-8"))
        );
        assert!(
            rejection_headers
                .windows(b"vary: Accept".len())
                .any(|value| value.eq_ignore_ascii_case(b"vary: Accept"))
        );
        let mut rejection_body = Vec::new();
        chunked_over
            .read_to_end(&mut rejection_body)
            .await
            .expect("read fixed rejection");
        assert!(
            !rejection_body
                .windows(sentinel.len())
                .any(|v| v == sentinel)
        );
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Started(None)
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::FirstData(value) if value <= limit
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Finished { bytes, error: true } if bytes <= limit
        ));
        let metrics = rendered_metrics().await;
        assert_eq!(
            metrics
                .lines()
                .filter(|line| {
                    line.starts_with("sekisho_proxy_request_body_too_large_total")
                        && line.contains("route=\"upload-upload-limit.example\"")
                        && line.ends_with(" 1")
                })
                .count(),
            1,
            "streamed size rejection counter must be exact-once"
        );
        assert_eq!(
            metrics
                .lines()
                .filter(|line| {
                    line.starts_with("sekisho_proxy_upstream_errors_total")
                        && line.contains("route=\"upload-upload-limit.example\"")
                })
                .count(),
            0,
            "local body limit must not be classified as an upstream failure"
        );

        proxy_task.abort();
        upstream_task.abort();
    }

    /// A client upload cut off at the cap is attributed to the client, not to the
    /// upstream: the limit metric moves and the upstream-failure path stays
    /// untouched.
    #[tokio::test]
    async fn hyper_client_classifies_body_limit_without_upstream_error_side_effects() {
        crate::observability::init_metrics();
        let limit = super::super::PROXY_BODY_LIMIT;
        let (upstream_addr, mut events, upstream_task) = spawn_upload_observer().await;
        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let stream_host = "hyper-upload-stream.example";
        let limit_host = "hyper-upload-limit.example";
        let app = build_test_proxy(
            vec![
                upload_route_with_transport(stream_host, upstream_addr, false),
                upload_route_with_transport(limit_host, upstream_addr, false),
            ],
            1,
            1,
            shutdown,
        )
        .await;
        let (proxy_addr, proxy_task) = spawn_test_proxy(app).await;

        let mut partial = open_upload(proxy_addr, stream_host, "Content-Length: 10\r\n").await;
        partial.write_all(b"first").await.expect("write first half");
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Started(Some(10))
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::FirstData(5)
        ));
        partial
            .write_all(b"again")
            .await
            .expect("write second half");
        assert_ok_response(&mut partial).await;
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Finished {
                bytes: 10,
                error: false
            }
        ));

        let mut dropped = open_upload(proxy_addr, stream_host, "Content-Length: 64\r\n").await;
        dropped
            .write_all(b"partial")
            .await
            .expect("write partial upload");
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Started(Some(64))
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::FirstData(7)
        ));
        drop(dropped);
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Finished {
                bytes: 7,
                error: true
            }
        ));

        let mut known = open_upload(
            proxy_addr,
            limit_host,
            &format!("Content-Length: {}\r\nAccept: text/html\r\n", limit + 1),
        )
        .await;
        let known_headers = read_http_headers(&mut known).await;
        assert!(known_headers.starts_with(b"HTTP/1.1 413"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), events.recv())
                .await
                .is_err(),
            "declared overflow must not connect upstream"
        );

        let mut payload = vec![b'x'; limit + 1];
        let sentinel = b"hyper-limit-secret-sentinel";
        payload[..sentinel.len()].copy_from_slice(sentinel);
        let mut chunked = open_upload(
            proxy_addr,
            limit_host,
            "Transfer-Encoding: chunked\r\nAccept: text/html\r\n",
        )
        .await;
        write_chunked(&mut chunked, &payload).await;
        let rejection_headers = read_http_headers(&mut chunked).await;
        assert!(rejection_headers.starts_with(b"HTTP/1.1 413"));
        assert!(
            rejection_headers
                .windows(b"content-type: text/html; charset=utf-8".len())
                .any(|value| value.eq_ignore_ascii_case(b"content-type: text/html; charset=utf-8"))
        );
        let mut rejection_body = Vec::new();
        chunked
            .read_to_end(&mut rejection_body)
            .await
            .expect("read fixed rejection");
        assert!(
            !rejection_body
                .windows(sentinel.len())
                .any(|value| value == sentinel)
        );
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Started(None)
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::FirstData(value) if value <= limit
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Finished { bytes, error: true } if bytes <= limit
        ));

        let route_name = format!("route=\"upload-{limit_host}\"");
        let metrics = rendered_metrics().await;
        assert_eq!(
            metrics
                .lines()
                .filter(|line| {
                    line.starts_with("sekisho_proxy_request_body_too_large_total")
                        && line.contains(&route_name)
                        && line.ends_with(" 1")
                })
                .count(),
            1,
            "hyper limit rejection counter must be exact-once"
        );
        assert_eq!(
            metrics
                .lines()
                .filter(|line| {
                    line.starts_with("sekisho_proxy_upstream_errors_total")
                        && line.contains(&route_name)
                })
                .count(),
            0,
            "local hyper body limit must not be classified as an upstream failure"
        );

        proxy_task.abort();
        upstream_task.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn route_client_disconnect_aborts_upload_and_releases_request_budgets() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _recorder_guard = metrics::set_default_local_recorder(&recorder);
        crate::observability::seed_control_budget_metrics_for_test();

        let (upstream_addr, mut events, upstream_task) = spawn_upload_observer().await;
        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let app = build_test_proxy(
            vec![upload_route("upload-drop.example", upstream_addr)],
            1,
            1,
            shutdown,
        )
        .await;
        let (proxy_addr, proxy_task) = spawn_test_proxy(app).await;

        let mut dropped =
            open_upload(proxy_addr, "upload-drop.example", "Content-Length: 64\r\n").await;
        dropped
            .write_all(b"partial-fixed-sentinel")
            .await
            .expect("write partial body");
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Started(Some(64))
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::FirstData(value) if value > 0
        ));
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_http"
            ),
            Some(1.0)
        );
        drop(dropped);
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Finished { error: true, .. }
        ));
        tokio::task::yield_now().await;
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_http"
            ),
            Some(0.0)
        );

        let mut recovered =
            open_upload(proxy_addr, "upload-drop.example", "Content-Length: 2\r\n").await;
        recovered
            .write_all(b"ok")
            .await
            .expect("write recovery body");
        assert_ok_response(&mut recovered).await;
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Started(Some(2))
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::FirstData(2)
        ));
        assert!(matches!(
            next_upload_event(&mut events).await,
            UploadEvent::Finished {
                bytes: 2,
                error: false
            }
        ));

        proxy_task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn route_client_non_limit_body_error_remains_bad_gateway() {
        use tower::ServiceExt;

        crate::observability::init_metrics();
        let (upstream_addr, _events, upstream_task) = spawn_upload_observer().await;
        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let app = build_test_proxy(
            vec![upload_route("upload-error.example", upstream_addr)],
            1,
            1,
            shutdown,
        )
        .await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/upload")
                    .header(header::HOST, "upload-error.example")
                    .body(Body::new(OneFrameBody(Some(Err(std::io::Error::other(
                        "fixed fixture transport error",
                    ))))))
                    .expect("body error request"),
            )
            .await
            .expect("proxy response");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let response_body = response
            .into_body()
            .collect()
            .await
            .expect("fixed error body")
            .to_bytes();
        assert!(
            !response_body
                .windows(b"fixed fixture transport error".len())
                .any(|value| value == b"fixed fixture transport error")
        );

        let metrics = rendered_metrics().await;
        assert_eq!(
            metrics
                .lines()
                .filter(|line| {
                    line.starts_with("sekisho_proxy_upstream_errors_total")
                        && line.contains("kind=\"upstream_send\"")
                        && line.contains("route=\"upload-upload-error.example\"")
                        && line.ends_with(" 1")
                })
                .count(),
            1,
            "non-limit body error must remain an upstream send failure"
        );
        assert_eq!(
            metrics
                .lines()
                .filter(|line| {
                    line.starts_with("sekisho_proxy_request_body_too_large_total")
                        && line.contains("route=\"upload-upload-error.example\"")
                })
                .count(),
            0,
            "transport body error must not be classified as a size violation"
        );
        upstream_task.abort();
    }

    fn websocket_route(name: String, host: &str, upstream: &str) -> Route {
        serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": name,
            "from": format!("https://{host}"),
            "to": [upstream],
            "access": {"allow_public_unauthenticated_access": true},
            "enable_websocket": true,
            "response_idle_timeout_ms": 50,
            "concurrency_limit": 1,
            "enabled": true
        }))
        .expect("route")
    }

    #[tokio::test]
    async fn websocket_non_101_body_uses_idle_timeout_and_releases_leases() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let upstream_for_response = upstream.clone();
        let release_stalled = Arc::new(tokio::sync::Notify::new());
        let release_server = release_stalled.clone();
        let upstream_task = tokio::spawn(async move {
            for request_index in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept upstream");
                let request = read_upstream_request(&mut stream).await;
                assert!(
                    String::from_utf8_lossy(&request)
                        .to_ascii_lowercase()
                        .contains("upgrade: websocket"),
                    "test request must use the websocket path"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: X-Hop\r\nX-Hop: remove\r\nKeep-Alive: timeout=5\r\nX-Ordinary: keep\r\nSet-Cookie: session=abc; Path=/\r\nSet-Cookie: csrf=xyz; Secure\r\nLocation: {upstream_for_response}/login\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write non-101 headers");
                if request_index == 0 {
                    release_server.notified().await;
                } else {
                    stream.write_all(b"done").await.expect("write body");
                }
            }
        });

        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let route = websocket_route("ws-non-101".into(), "ws-non-101.example", &upstream);
        let app = build_test_proxy(vec![route], 1, 1, shutdown).await;
        let (proxy_addr, proxy_task) = spawn_test_proxy(app).await;

        let (mut first, first_headers) =
            raw_proxy_request(proxy_addr, "ws-non-101.example", true).await;
        assert!(first_headers.starts_with(b"HTTP/1.1 200"));
        let mut byte = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), first.read(&mut byte))
            .await
            .expect("idle timeout must terminate the response")
            .expect("read truncated body");
        assert_eq!(n, 0, "idle expiry must truncate the advertised body");
        release_stalled.notify_one();

        let (mut recovered, recovered_headers) =
            raw_proxy_request(proxy_addr, "ws-non-101.example", true).await;
        assert!(recovered_headers.starts_with(b"HTTP/1.1 200"));
        assert_eq!(response_content_length(&recovered_headers), 4);
        let recovered_header_text =
            String::from_utf8_lossy(&recovered_headers).to_ascii_lowercase();
        assert!(!recovered_header_text.contains("\r\nconnection:"));
        assert!(!recovered_header_text.contains("\r\nkeep-alive:"));
        assert!(!recovered_header_text.contains("\r\nx-hop:"));
        assert!(recovered_header_text.contains("\r\nx-ordinary: keep\r\n"));
        assert_eq!(recovered_header_text.matches("\r\nset-cookie:").count(), 2);
        assert!(recovered_header_text.contains("\r\nvia: 1.1 sekisho\r\n"));
        assert!(
            recovered_header_text.contains("\r\nlocation: https://ws-non-101.example/login\r\n")
        );
        let mut body = [0u8; 4];
        recovered
            .read_exact(&mut body)
            .await
            .expect("read recovered body");
        assert_eq!(&body, b"done");

        upstream_task.await.expect("upstream task");
        proxy_task.abort();
    }

    #[tokio::test]
    async fn malformed_websocket_attempts_return_canonical_400_before_upstream() {
        use tower::ServiceExt;

        let sentinel = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = format!("http://{}", sentinel.local_addr().unwrap());
        let route = websocket_route("strict-ws".into(), "strict-ws.example", &upstream);
        let app = build_test_proxy(
            vec![route],
            4,
            4,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
        .await;
        let request_id = "strict-ws-request";

        let requests = [
            Request::builder()
                .method("POST")
                .version(axum::http::Version::HTTP_11)
                .uri("/")
                .header(header::HOST, "strict-ws.example")
                .header(header::CONNECTION, "Upgrade")
                .header(header::UPGRADE, "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header(crate::audit::REQUEST_ID_HEADER, request_id)
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .method("GET")
                .version(axum::http::Version::HTTP_11)
                .uri("/")
                .header(header::HOST, "strict-ws.example")
                .header(header::CONNECTION, "Upgrade")
                .header(header::UPGRADE, "websocket, h2c")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header(crate::audit::REQUEST_ID_HEADER, request_id)
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .method("GET")
                .version(axum::http::Version::HTTP_11)
                .uri("/")
                .header(header::HOST, "strict-ws.example")
                .header(header::CONNECTION, "Upgrade")
                .header(header::UPGRADE, "websocket")
                .header("sec-websocket-version", "12")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header(crate::audit::REQUEST_ID_HEADER, request_id)
                .body(Body::empty())
                .unwrap(),
            Request::builder()
                .method("GET")
                .version(axum::http::Version::HTTP_11)
                .uri("/")
                .header(header::HOST, "strict-ws.example")
                .header(header::CONNECTION, "Upgrade")
                .header(header::UPGRADE, "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==bad")
                .header(crate::audit::REQUEST_ID_HEADER, request_id)
                .body(Body::empty())
                .unwrap(),
        ];
        for request in requests {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(
                !response
                    .headers()
                    .get(crate::audit::REQUEST_ID_HEADER)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.as_ref(), br#"{"error":"bad request"}"#);
        }

        sentinel.set_nonblocking(true).unwrap();
        assert_eq!(
            sentinel.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "malformed WebSocket attempt reached upstream"
        );
    }

    #[tokio::test]
    async fn websocket_boundary_pins_request_and_validates_and_sanitizes_101() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let capture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_upstream_request(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade, x-hop\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: chat\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Hop: drop\r\nContent-Length: 7\r\n\r\n",
                )
                .await
                .unwrap();
            let mut sink = Vec::new();
            stream.read_to_end(&mut sink).await.unwrap();
            request
        });
        let route = websocket_route("boundary-ws".into(), "boundary-ws.example", &upstream);
        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let app = build_test_proxy(vec![route], 4, 4, shutdown.clone()).await;
        let (proxy, proxy_task) = spawn_test_proxy(app).await;
        let request = b"GET /socket?opaque=%252f HTTP/1.1\r\nHost: boundary-ws.example\r\nConnection: keep-alive, X-Hop\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat\r\nX-Hop: remove\r\nVia: 1.0 prior-a\r\nVia: 1.1 prior-b\r\n\r\n";
        let (client, headers) = raw_proxy_custom_request(proxy, request).await;
        assert!(headers.starts_with(b"HTTP/1.1 101"));
        let response = String::from_utf8_lossy(&headers).to_ascii_lowercase();
        assert_eq!(response.matches("\r\nconnection: upgrade\r\n").count(), 1);
        assert_eq!(response.matches("\r\nupgrade: websocket\r\n").count(), 1);
        assert!(!response.contains("\r\nx-hop:"));
        assert!(!response.contains("\r\ncontent-length:"));
        assert_eq!(response.matches("\r\nset-cookie:").count(), 2);
        assert!(response.contains("\r\nsec-websocket-protocol: chat\r\n"));
        assert!(response.contains("\r\nvia: 1.1 sekisho\r\n"));

        drop(client);
        let upstream_request = capture.await.unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_request).to_ascii_lowercase();
        assert!(upstream_request.starts_with("get /socket?opaque=%252f http/1.1\r\n"));
        assert_eq!(
            upstream_request
                .matches("\r\nconnection: upgrade\r\n")
                .count(),
            1
        );
        assert_eq!(
            upstream_request
                .matches("\r\nupgrade: websocket\r\n")
                .count(),
            1
        );
        assert!(!upstream_request.contains("\r\nx-hop:"));
        assert!(upstream_request.contains("\r\nsec-websocket-protocol: chat\r\n"));
        assert_eq!(upstream_request.matches("\r\nvia:").count(), 3);
        assert!(upstream_request.contains("\r\nvia: 1.0 prior-a\r\n"));
        assert!(upstream_request.contains("\r\nvia: 1.1 prior-b\r\n"));
        assert_eq!(
            upstream_request.matches("\r\nvia: 1.1 sekisho\r\n").count(),
            1
        );
        shutdown.signal();
        proxy_task.abort();
    }

    #[tokio::test]
    async fn invalid_upstream_101_returns_bad_gateway_without_tunnel() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let upstream_task = tokio::spawn(async move {
            let mut closed = Vec::new();
            for accept in ["wrong", "S3pPLMBiTxaQ9kYGzzhZRbK+xOo="] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _request = read_upstream_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                let mut byte = [0u8; 1];
                closed.push(
                    tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut byte))
                        .await
                        .expect("proxy did not close invalid upstream handshake")
                        .unwrap(),
                );
            }
            closed
        });
        let route = websocket_route("invalid-101".into(), "invalid-101.example", &upstream);
        let app = build_test_proxy(
            vec![route],
            4,
            4,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
        .await;
        let (proxy, proxy_task) = spawn_test_proxy(app).await;
        for _ in 0..2 {
            let (_client, headers) = raw_proxy_request(proxy, "invalid-101.example", true).await;
            assert!(headers.starts_with(b"HTTP/1.1 502"));
        }
        assert_eq!(
            upstream_task.await.unwrap(),
            vec![0, 0],
            "invalid 101 opened a tunnel"
        );
        proxy_task.abort();
    }

    #[tokio::test]
    async fn http_boundary_sanitizes_all_connection_fields_on_both_hops() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let upstream = format!("http://{upstream_addr}");
        let capture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_upstream_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: X-First\r\nConnection: X-Second\r\nX-First: drop\r\nX-Second: drop\r\nVia: 1.0 upstream-a\r\nVia: 1.1 upstream-b\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nLocation: http://{upstream_addr}/next\r\n\r\nok"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            request
        });
        let mut route = websocket_route("http-boundary".into(), "http-boundary.example", &upstream);
        route.enable_websocket = false;
        let app = build_test_proxy(
            vec![route],
            4,
            4,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
        .await;
        let (proxy, proxy_task) = spawn_test_proxy(app).await;
        let request = b"GET /raw%25path?opaque=%252f HTTP/1.1\r\nHost: http-boundary.example\r\nConnection: keep-alive, X-First\r\nConnection: X-Second\r\nX-First: drop\r\nX-Second: drop\r\nVia: 1.0 client-a\r\nVia: 1.1 client-b\r\nCookie: a=1; b=2\r\n\r\n";
        let (mut client, headers) = raw_proxy_custom_request(proxy, request).await;
        assert!(headers.starts_with(b"HTTP/1.1 200"));
        let response = String::from_utf8_lossy(&headers).to_ascii_lowercase();
        assert!(!response.contains("\r\nconnection:"));
        assert!(!response.contains("\r\nx-first:"));
        assert!(!response.contains("\r\nx-second:"));
        assert_eq!(response.matches("\r\nvia:").count(), 3);
        assert_eq!(response.matches("\r\nset-cookie:").count(), 2);
        assert!(response.contains("\r\nlocation: https://http-boundary.example/next\r\n"));
        let mut body = [0u8; 2];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"ok");

        let upstream_request = capture.await.unwrap();
        let upstream_request = String::from_utf8_lossy(&upstream_request).to_ascii_lowercase();
        assert!(upstream_request.starts_with("get /raw%25path?opaque=%252f http/1.1\r\n"));
        assert!(!upstream_request.contains("\r\nconnection:"));
        assert!(!upstream_request.contains("\r\nx-first:"));
        assert!(!upstream_request.contains("\r\nx-second:"));
        assert_eq!(upstream_request.matches("\r\nvia:").count(), 3);
        assert_eq!(upstream_request.matches("\r\ncookie:").count(), 1);
        assert!(upstream_request.contains("a=1"));
        assert!(upstream_request.contains("b=2"));
        proxy_task.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn production_router_hands_websocket_leases_off_and_rejects_at_capacity() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _recorder_guard = metrics::set_default_local_recorder(&recorder);
        crate::observability::seed_control_budget_metrics_for_test();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepts_server = accepts.clone();
        let upstream_task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.expect("accept upstream");
                accepts_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                connections.spawn(async move {
                    let request = read_upstream_request(&mut stream).await;
                    if String::from_utf8_lossy(&request)
                        .to_ascii_lowercase()
                        .contains("upgrade: websocket")
                    {
                        stream
                            .write_all(
                                b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                            )
                            .await
                            .expect("write 101");
                        let mut sink = Vec::new();
                        stream.read_to_end(&mut sink).await.expect("tunnel close");
                    } else {
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                            )
                            .await
                            .expect("write ordinary response");
                    }
                });
            }
            while connections.join_next().await.is_some() {}
        });

        let suffix = uuid::Uuid::new_v4();
        let route_a_name = format!("ws-a-{suffix}");
        let route_b_name = format!("ws-b-{suffix}");
        let route_a = websocket_route(route_a_name.clone(), "ws-a.example", &upstream);
        let route_b = websocket_route(route_b_name.clone(), "ws-b.example", &upstream);
        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let app = build_test_proxy(vec![route_a, route_b], 1, 1, shutdown.clone()).await;
        let initial = handle.render();
        assert_eq!(
            metric_sample(&initial, "sekisho_control_budget_limit", "proxy_http"),
            Some(1.0)
        );
        assert_eq!(
            metric_sample(&initial, "sekisho_control_budget_limit", "proxy_websocket"),
            Some(1.0)
        );
        let (proxy_addr, proxy_task) = spawn_test_proxy(app).await;

        let (first_ws, first_headers) = raw_proxy_request(proxy_addr, "ws-a.example", true).await;
        assert_websocket_upgrade_headers(&first_headers);
        assert_eq!(shutdown.ws_inflight(), 1);
        assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_websocket"
            ),
            Some(1.0)
        );

        let (mut route_rejected, route_rejected_headers) =
            raw_proxy_request(proxy_addr, "ws-a.example", false).await;
        assert!(route_rejected_headers.starts_with(b"HTTP/1.1 503"));
        let mut route_error = vec![0u8; response_content_length(&route_rejected_headers)];
        route_rejected
            .read_exact(&mut route_error)
            .await
            .expect("route rejection body");

        let (mut capacity_rejected, capacity_headers) =
            raw_proxy_request(proxy_addr, "ws-b.example", true).await;
        assert!(capacity_headers.starts_with(b"HTTP/1.1 503"));
        let mut capacity_error = vec![0u8; response_content_length(&capacity_headers)];
        capacity_rejected
            .read_exact(&mut capacity_error)
            .await
            .expect("capacity rejection body");
        assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_rejected_total",
                "proxy_websocket"
            ),
            Some(1.0)
        );

        let (mut ordinary, ordinary_headers) =
            raw_proxy_request(proxy_addr, "ws-b.example", false).await;
        assert!(ordinary_headers.starts_with(b"HTTP/1.1 200"));
        let mut ordinary_body = [0u8; 2];
        ordinary
            .read_exact(&mut ordinary_body)
            .await
            .expect("ordinary body");
        assert_eq!(&ordinary_body, b"ok");
        assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 2);

        drop(first_ws);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while shutdown.ws_inflight() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first websocket lease release");

        let (reopened_ws, reopened_headers) =
            raw_proxy_request(proxy_addr, "ws-b.example", true).await;
        assert_websocket_upgrade_headers(&reopened_headers);
        assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 3);
        shutdown.signal();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while shutdown.ws_inflight() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown websocket lease release");
        drop(reopened_ws);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_websocket"
            ),
            Some(0.0)
        );

        let rendered = handle.render();
        let rejection = format!(
            "sekisho_proxy_websocket_capacity_rejected_total{{route=\"{route_b_name}\"}} 1"
        );
        assert_eq!(
            rendered.lines().filter(|line| *line == rejection).count(),
            1,
            "capacity rejection counter must be exact-once"
        );
        for route in [&route_a_name, &route_b_name] {
            assert_eq!(
                rendered
                    .lines()
                    .filter(|line| {
                        line.starts_with(
                            "sekisho_proxy_websocket_connection_duration_seconds_count",
                        ) && line.contains(&format!("route=\"{route}\""))
                            && line.ends_with(" 1")
                    })
                    .count(),
                1,
                "each websocket tunnel must record one duration"
            );
        }

        upstream_task.await.expect("upstream task");
        proxy_task.abort();
    }

    async fn redirect_router(from: &str, host_redirect: Option<&str>) -> axum::Router {
        use crate::store::Store;
        use crate::tls::acme::AcmeManager;
        use crate::tls::acme::challenge::Http01Provider;

        let store = Store::new_for_test("sqlite::memory:", [5u8; 32], None)
            .await
            .unwrap();
        let route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "redirect",
            "from": from,
            "to": [],
            "redirect": {
                "host_redirect": host_redirect,
                "path_redirect": null,
                "code": 302
            },
            "enabled": true
        }))
        .unwrap();
        store.create_route(&route).await.unwrap();

        let http01 = Arc::new(Http01Provider::new(store.clone()));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            http01,
            "https://acme.invalid/directory",
            None,
        ));

        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;

        crate::proxy::router(
            store,
            route_generation,
            &[0u8; 64],
            acme,
            crate::crypto::MasterKey::from_test_bytes([4u8; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([2u8; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            100,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
    }

    #[tokio::test]
    async fn redirect_fallback_uses_configured_authority_not_inbound_host() {
        use tower::ServiceExt;

        let response = redirect_router("https://app.example.com", None)
            .await
            .oneshot(
                Request::builder()
                    .uri("/continue")
                    .header(header::HOST, "app.example.com:1@evil.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://app.example.com/continue"
        );
    }

    #[tokio::test]
    async fn redirect_fallback_preserves_configured_explicit_port() {
        use tower::ServiceExt;

        let response = redirect_router("https://app.example.com:8443", None)
            .await
            .oneshot(
                Request::builder()
                    .uri("/continue")
                    .header(header::HOST, "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://app.example.com:8443/continue"
        );
    }

    #[tokio::test]
    async fn encoded_internal_path_cannot_alias_or_reach_catch_all() {
        use tower::ServiceExt;

        let response = redirect_router("https://app.example.com", None)
            .await
            .oneshot(
                Request::builder()
                    .uri("/%2Esekisho/signin")
                    .header(header::HOST, "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn canonical_path_selects_route_while_redirect_preserves_raw_path() {
        use tower::ServiceExt;

        let route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "admin",
            "from": "https://app.example.com",
            "path": "/admin",
            "to": [],
            "redirect": {"host_redirect": null, "path_redirect": null, "code": 302},
            "enabled": true
        }))
        .unwrap();
        let app = build_test_proxy(
            vec![route],
            2,
            2,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
        .await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/%61dmin/?raw=1")
                    .header(header::HOST, "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://app.example.com/%61dmin/"
        );
    }

    #[tokio::test]
    async fn canonical_match_forwards_raw_path_when_rewrite_does_not_fire() {
        use tower::ServiceExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let capture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_upstream_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            request
        });
        let route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "admin",
            "from": "https://app.example.com",
            "path": "/admin",
            "to": [format!("http://{upstream}")],
            "access": {"allow_public_unauthenticated_access": true},
            "regex_rewrite_pattern": "^/other$",
            "regex_rewrite_substitution": "/changed",
            "enabled": true
        }))
        .unwrap();
        let app = build_test_proxy(
            vec![route],
            2,
            2,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
        .await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/%61dmin?raw=1")
                    .header(header::HOST, "app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        drop(response);
        let request = capture.await.unwrap();
        assert!(request.starts_with(b"GET /%61dmin?raw=1 HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn canonical_rewrite_encodes_literal_percent_over_http() {
        use tower::ServiceExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let capture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_upstream_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            request
        });
        let route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "rewrite-http",
            "from": "https://rewrite-http.example.com",
            "path": "/",
            "to": [format!("http://{upstream}")],
            "access": {"allow_public_unauthenticated_access": true},
            "regex_rewrite_pattern": "^/(.*)$",
            "regex_rewrite_substitution": "/$1",
            "enabled": true
        }))
        .unwrap();
        let app = build_test_proxy(
            vec![route],
            2,
            2,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
        .await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/100%25?opaque=%252f")
                    .header(header::HOST, "rewrite-http.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let request = capture.await.unwrap();
        assert!(request.starts_with(b"GET /100%25?opaque=%252f HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn canonical_rewrite_encodes_non_ascii_path_over_websocket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let capture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept upstream");
            let request = read_upstream_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("write response");
            request
        });
        let mut route = websocket_route(
            "rewrite-websocket".into(),
            "rewrite-websocket.example.com",
            &upstream,
        );
        route.path = Some("/".into());
        route.regex_rewrite_pattern = Some("^/(.*)$".into());
        route.regex_rewrite_substitution = Some("/$1".into());
        let app = build_test_proxy(
            vec![route],
            2,
            2,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
        .await;
        let (proxy, proxy_task) = spawn_test_proxy(app).await;
        let (_stream, headers) = raw_proxy_request_target(
            proxy,
            "rewrite-websocket.example.com",
            "/%E2%98%83?opaque=%252f",
            true,
        )
        .await;
        assert!(headers.starts_with(b"HTTP/1.1 400"));
        let request = capture.await.unwrap();
        assert!(request.starts_with(b"GET /%E2%98%83?opaque=%252f HTTP/1.1\r\n"));
        assert!(
            String::from_utf8_lossy(&request)
                .to_ascii_lowercase()
                .contains("\r\nupgrade: websocket\r\n")
        );
        proxy_task.abort();
    }

    #[tokio::test]
    async fn rewrite_delimiters_fail_closed_before_downstream() {
        use tower::ServiceExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind downstream sentinel");
        let upstream = listener.local_addr().unwrap();
        for replacement in [
            "/unsafe?part",
            "/unsafe#part",
            "/unsafe%3fpart",
            "/unsafe%23part",
        ] {
            let route: Route = serde_json::from_value(serde_json::json!({
                "id": uuid::Uuid::new_v4(),
                "name": "invalid-rewrite",
                "from": "https://invalid-rewrite.example.com",
                "path": "/source",
                "to": [format!("http://{upstream}")],
                "access": {"allow_public_unauthenticated_access": true},
                "regex_rewrite_pattern": "^/source$",
                "regex_rewrite_substitution": replacement,
                "enabled": true
            }))
            .unwrap();
            let app = build_test_proxy(
                vec![route],
                2,
                2,
                Arc::new(crate::shutdown::ShutdownController::new()),
            )
            .await;
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/source?opaque=%252f")
                        .header(header::HOST, "invalid-rewrite.example.com")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "accepted rewrite delimiter {replacement}"
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], br#"{"error":"service not configured"}"#);
        }
        let listener = listener.into_std().expect("convert downstream sentinel");
        listener
            .set_nonblocking(true)
            .expect("set downstream sentinel nonblocking");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "invalid rewrite reached downstream"
        );
    }

    #[tokio::test]
    async fn request_target_and_legacy_method_guards_preserve_fixed_safe_wire() {
        use tower::ServiceExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind downstream sentinel");
        let upstream = listener.local_addr().unwrap();
        let route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "guard-sentinel",
            "from": "https://guard.example.com",
            "to": [format!("http://{upstream}")],
            "access": {"allow_public_unauthenticated_access": true},
            "enabled": true
        }))
        .unwrap();
        let app = build_test_proxy(
            vec![route],
            2,
            2,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
        .await;
        let request_id = "018f2f16-2a38-7ec2-989d-7fd985550000";
        for (method, target, status, body) in [
            (
                axum::http::Method::GET,
                "https://guard.example.com/path",
                StatusCode::BAD_REQUEST,
                br#"{"error":"bad request"}"#.as_slice(),
            ),
            (
                axum::http::Method::GET,
                "*",
                StatusCode::BAD_REQUEST,
                br#"{"error":"bad request"}"#.as_slice(),
            ),
            (
                axum::http::Method::GET,
                "/%3f",
                StatusCode::BAD_REQUEST,
                br#"{"error":"bad request"}"#.as_slice(),
            ),
            (
                axum::http::Method::GET,
                "/%23",
                StatusCode::BAD_REQUEST,
                br#"{"error":"bad request"}"#.as_slice(),
            ),
            (
                axum::http::Method::CONNECT,
                "guard.example.com:443",
                StatusCode::METHOD_NOT_ALLOWED,
                br#"{"error":"method not allowed"}"#.as_slice(),
            ),
            (
                axum::http::Method::TRACE,
                "/",
                StatusCode::METHOD_NOT_ALLOWED,
                br#"{"error":"internal server error"}"#.as_slice(),
            ),
            (
                axum::http::Method::from_bytes(b"TRACK").unwrap(),
                "/",
                StatusCode::METHOD_NOT_ALLOWED,
                br#"{"error":"internal server error"}"#.as_slice(),
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(target)
                        .header(header::HOST, "guard.example.com")
                        .header(crate::audit::REQUEST_ID_HEADER, request_id)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status, "accepted {target}");
            assert_eq!(
                response
                    .headers()
                    .get(crate::audit::REQUEST_ID_HEADER)
                    .unwrap(),
                request_id
            );
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            let actual = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(actual.as_ref(), body);
        }
        let listener = listener.into_std().expect("convert downstream sentinel");
        listener
            .set_nonblocking(true)
            .expect("set downstream sentinel nonblocking");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "rejected request reached downstream"
        );
    }

    #[tokio::test]
    async fn invalid_enabled_snapshot_returns_service_unavailable() {
        use tower::ServiceExt;

        let mut invalid: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "invalid",
            "from": "https://invalid.example.com",
            "path": "/a//b",
            "to": [],
            "redirect": {"host_redirect": null, "path_redirect": null, "code": 302},
            "enabled": true
        }))
        .unwrap();
        invalid.access.allow_public_unauthenticated_access = true;
        let app = build_test_proxy(
            vec![invalid],
            2,
            2,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
        .await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "invalid.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn redirect_explicit_host_override_still_takes_priority() {
        use tower::ServiceExt;

        let response = redirect_router(
            "https://app.example.com:8443",
            Some("redirect.example.net:9443"),
        )
        .await
        .oneshot(
            Request::builder()
                .uri("/continue")
                .header(header::HOST, "app.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://redirect.example.net:9443/continue"
        );
    }

    #[test]
    fn extract_client_ip_returns_peer_when_present() {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 12345);
        let req = request_with_headers(Some(peer), &[]);
        assert_eq!(
            extract_client_ip(&req),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
        );
    }

    #[test]
    fn extract_client_ip_returns_none_without_peer() {
        // No ConnectInfo extension — happens in tests that build requests
        // by hand; production axum always inserts it, but this keeps the
        // fallback behaviour contractual.
        let req = request_with_headers(None, &[]);
        assert_eq!(extract_client_ip(&req), None);
    }

    #[test]
    fn x_forwarded_for_header_ignored_for_client_ip() {
        // client.ip feeds policy allow-lists; trusting XFF would let any
        // external caller impersonate any IP. The peer address wins even
        // when XFF is present and parseable.
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 44321);
        let req =
            request_with_headers(Some(peer), &[("x-forwarded-for", "10.0.0.1, 198.51.100.2")]);
        assert_eq!(
            extract_client_ip(&req),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
        );
    }

    #[test]
    fn x_forwarded_for_header_without_peer_yields_none() {
        // Belt-and-braces: even in the no-peer edge case, we must not fall
        // back to XFF — returning None (fail-closed for `client.ip` rules)
        // is safer than honouring a header an attacker controls.
        let req = request_with_headers(None, &[("x-forwarded-for", "10.0.0.1")]);
        assert_eq!(extract_client_ip(&req), None);
    }

    #[test]
    fn internal_paths_bypass_policy() {
        // `/.sekisho/*` endpoints must never be routed through the
        // route-policy evaluation block. The bug this guards against:
        // a user whose session is denied by their route's policy still
        // needs to be able to hit `/.sekisho/sign-out` — otherwise the
        // only recovery is for the operator to clear the cookie by
        // hand. Signin / callback / userinfo etc. are in the same boat.
        assert!(is_internal_path("/.sekisho/sign-out"));
        assert!(is_internal_path("/.sekisho/sign-out/"));
        assert!(is_internal_path("/.sekisho/signed-out"));
        assert!(is_internal_path("/.sekisho/callback"));
        assert!(is_internal_path("/.sekisho/userinfo"));
        assert!(is_internal_path("/.sekisho/saml/acs"));
        assert!(is_internal_path("/.sekisho/session-handoff"));
        assert!(is_internal_path("/.sekisho/unknown-subpath"));
        assert!(is_internal_path("/.sekisho"));
    }

    #[test]
    fn hop_by_hop_classification_matches_rfc7230() {
        // This locks the RFC hop-by-hop set and ensures
        // Transfer-Encoding does not cross the proxy boundary.
        for h in [
            "Connection",
            "connection",
            "Keep-Alive",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
        ] {
            assert!(
                crate::proxy::header_boundary::is_static_hop_header(h),
                "expected {h:?} to be hop-by-hop"
            );
        }
        for h in [
            "Authorization",
            "Cookie",
            "Set-Cookie",
            "Content-Length",
            "Content-Type",
            "X-Custom",
            "Vary",
        ] {
            assert!(
                !crate::proxy::header_boundary::is_static_hop_header(h),
                "{h:?} must pass through"
            );
        }
    }

    #[test]
    fn strip_hop_by_hop_helper_removes_connection_tokens_and_preserves_end_to_end_headers() {
        // RFC 6265 §4.1: Set-Cookie is the canonical multi-valued
        // header — an upstream that issues two cookies sends two
        // separate `Set-Cookie:` lines. axum's HeaderMap supports
        // that natively (multiple values per name), and the
        // response-builder loop iterates each value in order. The
        // hop-by-hop strip must preserve all of them: dropping one
        // would silently log out a downstream session or strip a
        // CSRF token cookie.
        let mut headers = HeaderMap::new();
        headers.append("set-cookie", "session=abc; Path=/".parse().unwrap());
        headers.append("set-cookie", "csrf=xyz; Secure".parse().unwrap());
        headers.append(
            "connection",
            "x-remove, bad token@, , x-also-remove".parse().unwrap(),
        );
        headers.append("connection", "X-Third \t, @invalid".parse().unwrap());
        headers.insert("x-remove", "first".parse().unwrap());
        headers.insert("x-also-remove", "second".parse().unwrap());
        headers.insert("x-third", "third".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("upgrade", "other".parse().unwrap());
        headers.insert("x-ordinary", "keep".parse().unwrap());
        crate::proxy::header_boundary::sanitize_hop_by_hop(&mut headers);
        for name in [
            "connection",
            "keep-alive",
            "upgrade",
            "x-remove",
            "x-also-remove",
            "x-third",
        ] {
            assert!(headers.get(name).is_none(), "{name} must be removed");
        }
        assert_eq!(headers.get("x-ordinary").unwrap(), "keep");
        let cookies: Vec<&str> = headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookies.len(), 2, "both Set-Cookie values must survive");
        assert!(cookies.iter().any(|c| c.starts_with("session=")));
        assert!(cookies.iter().any(|c| c.starts_with("csrf=")));
    }

    #[test]
    fn strip_hop_by_hop_helper_drops_te_pair_pre_via() {
        // `strip_hop_by_hop_headers` removes TE / Connection while
        // leaving end-to-end `Content-Length` untouched; this test
        // proves only that CL and TE are not forwarded together.
        // Callers remain responsible for header/body consistency.
        let mut headers = HeaderMap::new();
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("content-type", "text/html".parse().unwrap());
        headers.insert("content-length", "1234".parse().unwrap());
        crate::proxy::header_boundary::sanitize_hop_by_hop(&mut headers);
        assert!(headers.get("transfer-encoding").is_none());
        assert!(headers.get("connection").is_none());
        // Content-* are end-to-end and survive.
        assert_eq!(headers.get("content-type").unwrap(), "text/html");
    }

    #[test]
    fn non_internal_paths_still_evaluated() {
        // Regular proxied requests must keep going through route match
        // and policy evaluation — the bypass is scoped to `/.sekisho/`
        // and must not swallow ordinary traffic.
        assert!(!is_internal_path("/"));
        assert!(!is_internal_path("/api/foo"));
        assert!(!is_internal_path("/.sekisho-foo"));
        // Subtle: `/.sekishod/...` shares a prefix but is not an internal
        // path. The exact marker is `/.sekisho/` or bare `/.sekisho`.
        assert!(!is_internal_path("/.sekishod/foo"));
    }

    #[tokio::test]
    async fn signed_routes_reject_missing_explicit_email_before_upstream_side_effects() {
        use crate::models::session::{Session, UpstreamIdentity, UpstreamIdentityProvenance};
        use crate::session::cookie_manager::CookieManager;
        use crate::store::Store;
        use crate::tls::acme::AcmeManager;
        use crate::tls::acme::challenge::Http01Provider;
        use cookie::SameSite;
        use tower::ServiceExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sentinel upstream");
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let store = Store::new_for_test("sqlite::memory:", [0x61; 32], None)
            .await
            .expect("store");

        let public_route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "signed-public",
            "from": "https://public.example.com",
            "to": [upstream.clone()],
            "access": {"allow_public_unauthenticated_access": true},
            "enable_signed_identity": true,
            "enabled": true
        }))
        .unwrap();
        let protected_route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "signed-protected",
            "from": "https://protected.example.com",
            "to": [upstream],
            "access": {"policy": "claim.username == \"legacy@example.com\""},
            "enable_signed_identity": true,
            "enabled": true
        }))
        .unwrap();
        store.create_route(&public_route).await.unwrap();
        store.create_route(&protected_route).await.unwrap();

        let now = chrono::Utc::now();
        let mut claims = std::collections::HashMap::new();
        claims.insert(
            "username".into(),
            serde_json::Value::String("legacy@example.com".into()),
        );
        let public_session = Session {
            id: uuid::Uuid::new_v4(),
            user_id: "subject-without-email".into(),
            idp_id: uuid::Uuid::new_v4(),
            claims: Default::default(),
            groups: vec![],
            upstream_identity: Some(UpstreamIdentity {
                subject: "subject-without-email".into(),
                explicit_email: None,
                provenance: UpstreamIdentityProvenance::Oidc,
            }),
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            refresh_token_encrypted: None,
            id_token_encrypted: None,
            saml_name_id: None,
            saml_session_index: None,
            last_accessed_at: now,
        };
        let protected_legacy_session = Session {
            id: uuid::Uuid::new_v4(),
            user_id: "legacy@example.com".into(),
            idp_id: uuid::Uuid::new_v4(),
            claims,
            groups: vec![],
            upstream_identity: None,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            refresh_token_encrypted: None,
            id_token_encrypted: None,
            saml_name_id: None,
            saml_session_index: None,
            last_accessed_at: now,
        };
        store.create_session(&public_session).await.unwrap();
        store
            .create_session(&protected_legacy_session)
            .await
            .unwrap();

        let provider = Arc::new(Http01Provider::new(store.clone()));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            provider,
            "https://acme.invalid/directory",
            None,
        ));
        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;
        let cookie_secret = [0x62; 64];
        let app = crate::proxy::router(
            store,
            route_generation,
            &cookie_secret,
            acme,
            crate::crypto::MasterKey::from_test_bytes([0x63; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([0x64; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            100,
            Arc::new(crate::shutdown::ShutdownController::new()),
        );
        let cookies = CookieManager::new(&cookie_secret).with_name("sekisho_session".into());

        for (host, session_id) in [
            ("public.example.com", public_session.id),
            ("protected.example.com", protected_legacy_session.id),
        ] {
            let cookie = cookies.create_cookie(session_id, SameSite::Lax);
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header(header::HOST, host)
                        .header(header::COOKIE, cookie.split(';').next().unwrap())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], br#"{"error":"access denied"}"#);
        }

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "missing explicit email reached the upstream"
        );
    }

    #[tokio::test]
    async fn expired_sessions_are_revalidated_on_http_and_websocket_handshakes() {
        use crate::models::session::Session;
        use crate::session::cookie_manager::CookieManager;
        use crate::store::Store;
        use crate::tls::acme::AcmeManager;
        use crate::tls::acme::challenge::Http01Provider;
        use cookie::SameSite;
        use tower::ServiceExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sentinel upstream");
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let store = Store::new_for_test("sqlite::memory:", [0x65; 32], None)
            .await
            .expect("store");
        let route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "name": "session-handshake",
            "from": "https://handshake.example.com",
            "to": [upstream],
            "access": {},
            "enable_websocket": true,
            "enabled": true
        }))
        .unwrap();
        store.create_route(&route).await.unwrap();
        let now = chrono::Utc::now();
        let session = Session {
            id: uuid::Uuid::new_v4(),
            user_id: "handshake@example.com".into(),
            idp_id: uuid::Uuid::new_v4(),
            claims: Default::default(),
            groups: vec![],
            upstream_identity: None,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            refresh_token_encrypted: None,
            id_token_encrypted: None,
            saml_name_id: None,
            saml_session_index: None,
            last_accessed_at: now,
        };
        store.create_session(&session).await.unwrap();
        sqlx::query("UPDATE sessions SET expires_at = unixepoch() WHERE id = ?")
            .bind(session.id)
            .execute(store.sqlite_pool())
            .await
            .unwrap();

        let provider = Arc::new(Http01Provider::new(store.clone()));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            provider,
            "https://acme.invalid/directory",
            None,
        ));
        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;
        let cookie_secret = [0x66; 64];
        let app = crate::proxy::router(
            store,
            route_generation,
            &cookie_secret,
            acme,
            crate::crypto::MasterKey::from_test_bytes([0x67; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([0x68; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            100,
            Arc::new(crate::shutdown::ShutdownController::new()),
        );
        let cookies = CookieManager::new(&cookie_secret).with_name("sekisho_session".into());
        let cookie = cookies.create_cookie(session.id, SameSite::Lax);
        let cookie = cookie.split(';').next().unwrap();

        let http = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "handshake.example.com")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(http.status(), StatusCode::SERVICE_UNAVAILABLE);

        let websocket = app
            .oneshot(
                Request::builder()
                    .uri("/socket")
                    .header(header::HOST, "handshake.example.com")
                    .header(header::COOKIE, cookie)
                    .header(header::CONNECTION, "Upgrade")
                    .header(header::UPGRADE, "websocket")
                    .header("sec-websocket-version", "13")
                    .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(websocket.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "expired HTTP/WS handshake reached the upstream"
        );
    }
}
