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
//! collects whatever the request acquired and [`RouteLeaseBody`] wraps the
//! response body so the permit drops on the last frame.
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
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header, uri::Uri};
use metrics::counter;

use crate::auth::strategy::initiate_auth;
use crate::models::route::Route;
use crate::models::session::Session;
use crate::observability::MatchedRouteId;
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;

use super::{RouteClientCache, WebSocketBudget};
use crate::state::AppState;

/// Resources acquired during a request that must survive past the handler.
///
/// Filled in as the request progresses (the route permit is only known once a
/// route matches) and applied by [`Self::wrap`] on the way out, on both the
/// success and error paths. Holding nothing is the common case for a 404, so
/// `wrap` returns the response untouched rather than paying for a body
/// wrapper that would do nothing.
struct RouteResponseLease {
    permit: Option<OwnedSemaphorePermit>,
    idle_timeout: Option<std::time::Duration>,
    route: Option<String>,
}

impl RouteResponseLease {
    fn new() -> Self {
        Self {
            permit: None,
            idle_timeout: None,
            route: None,
        }
    }

    /// Attach the lease to the response body, or return the response as-is
    /// when there is nothing to hold.
    fn wrap(&mut self, response: Response<Body>) -> Response<Body> {
        if self.permit.is_none() && self.idle_timeout.is_none() {
            return response;
        }
        let (parts, body) = response.into_parts();
        Response::from_parts(
            parts,
            Body::new(RouteLeaseBody::new(
                body,
                self.permit.take(),
                self.idle_timeout,
                self.route.clone().unwrap_or_else(|| "_unrouted".into()),
            )),
        )
    }
}

/// Response body that owns a concurrency permit and enforces the per-route
/// idle timeout.
///
/// The timer is reset on every non-empty DATA frame, so a slow-but-progressing
/// transfer is never cut off while a genuinely stalled upstream is. Empty
/// frames deliberately do not count as progress — trailers and zero-length
/// chunks would otherwise let an upstream keep the connection alive forever
/// without sending anything.
///
/// `done` latches so that a terminated stream cannot be polled back into
/// life: after the permit has been released, returning further frames would
/// mean serving a body outside the budget that authorized it.
struct RouteLeaseBody {
    inner: Body,
    permit: Option<OwnedSemaphorePermit>,
    idle: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    idle_timeout: Option<std::time::Duration>,
    route: String,
    done: bool,
}

impl RouteLeaseBody {
    fn new(
        inner: Body,
        permit: Option<OwnedSemaphorePermit>,
        idle_timeout: Option<std::time::Duration>,
        route: String,
    ) -> Self {
        Self {
            inner,
            permit,
            idle: idle_timeout.map(|timeout| Box::pin(tokio::time::sleep(timeout))),
            idle_timeout,
            route,
            done: false,
        }
    }

    /// Release the permit and drop the timer. Called on end-of-stream, on
    /// body error, and on idle expiry — every path out of the stream, so the
    /// permit cannot be stranded.
    fn finish(&mut self) {
        self.done = true;
        self.permit.take();
        self.idle.take();
    }
}

impl hyper::body::Body for RouteLeaseBody {
    type Data = axum::body::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.done {
            return std::task::Poll::Ready(None);
        }

        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if frame.data_ref().is_some_and(|data| !data.is_empty())
                    && let (Some(idle), Some(timeout)) = (this.idle.as_mut(), this.idle_timeout)
                {
                    idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                }
                return std::task::Poll::Ready(Some(Ok(frame)));
            }
            std::task::Poll::Ready(Some(Err(_))) => {
                this.finish();
                return std::task::Poll::Ready(Some(Err(std::io::Error::other(
                    "upstream response body error",
                ))));
            }
            std::task::Poll::Ready(None) => {
                this.finish();
                return std::task::Poll::Ready(None);
            }
            std::task::Poll::Pending => {}
        }

        if let Some(idle) = this.idle.as_mut()
            && idle.as_mut().poll(cx).is_ready()
        {
            tracing::warn!(
                route = %this.route,
                timeout_ms = this.idle_timeout.map(|v| v.as_millis() as u64).unwrap_or_default(),
                "upstream response body idle timeout"
            );
            counter!(
                "sekisho_proxy_response_body_idle_timeouts_total",
                "route" => this.route.clone()
            )
            .increment(1);
            this.finish();
            return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream response body idle timeout",
            ))));
        }

        std::task::Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Representation selected for a Sekisho-owned public proxy rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProxyErrorRepresentation {
    Json,
    Html,
}

/// The owned rejection source. Each variant keeps the exact wire form it had
/// before negotiation existed — JSON for the handler and request-target
/// rejections, plain text for the body limit, and an empty body with no
/// content type for the concurrency rejection — while sharing HTML
/// negotiation and security headers.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ProxyErrorKind {
    Handler(StatusCode),
    GlobalConcurrency,
    RequestBodyLimit,
    RequestTargetBadRequest,
    RequestTargetMethodNotAllowed,
}

impl ProxyErrorKind {
    /// The status each owned rejection answers with. Fixed per variant so a
    /// caller cannot pass a status that contradicts the body it is about to
    /// get; `Handler` is the one variant that carries its own, because the
    /// request pipeline chooses it.
    fn status(self) -> StatusCode {
        match self {
            Self::Handler(status) => status,
            Self::GlobalConcurrency => StatusCode::SERVICE_UNAVAILABLE,
            Self::RequestBodyLimit => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RequestTargetBadRequest => StatusCode::BAD_REQUEST,
            Self::RequestTargetMethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
        }
    }

    /// The exact body and content type this rejection had before negotiation
    /// existed, returned so the JSON branch can reproduce it byte for byte.
    ///
    /// The content type is optional because not every variant had one: the
    /// concurrency rejection was an empty body with no type at all, and the
    /// body limit was plain text. Preserving those exactly is what lets HTML
    /// be added without any existing client seeing a changed response.
    fn legacy_representation(self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::Handler(status) => {
                let body = match status {
                    StatusCode::NOT_FOUND => r#"{"error":"no matching route"}"#,
                    StatusCode::FORBIDDEN => r#"{"error":"access denied"}"#,
                    StatusCode::BAD_GATEWAY => r#"{"error":"upstream error"}"#,
                    StatusCode::SERVICE_UNAVAILABLE => r#"{"error":"service not configured"}"#,
                    StatusCode::BAD_REQUEST => r#"{"error":"bad request"}"#,
                    StatusCode::PAYLOAD_TOO_LARGE => r#"{"error":"request body too large"}"#,
                    _ => r#"{"error":"internal server error"}"#,
                };
                (body, Some("application/json"))
            }
            Self::GlobalConcurrency => ("", None),
            Self::RequestBodyLimit => ("length limit exceeded", Some("text/plain; charset=utf-8")),
            Self::RequestTargetBadRequest => {
                (r#"{"error":"bad request"}"#, Some("application/json"))
            }
            Self::RequestTargetMethodNotAllowed => (
                r#"{"error":"method not allowed"}"#,
                Some("application/json"),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// How strongly a request asked for one media type.
///
/// Field order is the comparison order — `derive(Ord)` compares `quality`
/// first and only falls through to `specificity` on a tie, which is the
/// precedence RFC 7231 describes: a higher q wins outright, and among equal q
/// the more specific range wins.
struct MediaPreference {
    quality: u16,
    specificity: u8,
}

/// Fold one `Accept` member into the best preference seen so far for a type.
///
/// A more specific range replaces a less specific one outright rather than
/// competing on quality, because RFC 7231 says the most specific match
/// determines the value: `text/html;q=0.1` alongside `text/*;q=0.9` means the
/// client wants HTML at 0.1, not 0.9. Among equally specific ranges the
/// highest quality wins.
fn update_preference(current: &mut Option<MediaPreference>, quality: u16, specificity: u8) {
    let candidate = MediaPreference {
        quality,
        specificity,
    };
    match current {
        Some(existing) if existing.specificity > specificity => {}
        Some(existing) if existing.specificity == specificity => {
            existing.quality = existing.quality.max(quality);
        }
        _ => *current = Some(candidate),
    }
}

/// Parse a `q=` value into thousandths, or `None` if it is not well formed.
///
/// Integer thousandths rather than a float: quality values compare for
/// ordering and equality, and exact integer comparison avoids a tie being
/// decided by representation error. `None` is a real answer here — the caller
/// discards the whole member rather than guessing a default, so a malformed
/// parameter cannot silently become `q=1`.
fn parse_quality(value: &str) -> Option<u16> {
    let value = value.trim();
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => {
            let mut quality = 0u16;
            for byte in fraction.bytes() {
                quality = quality * 10 + u16::from(byte - b'0');
            }
            Some(quality * 10u16.pow(3 - fraction.len() as u32))
        }
        "1" if fraction.bytes().all(|byte| byte == b'0') => Some(1000),
        _ => None,
    }
}

/// Select HTML only when its (quality, specificity) pair strictly outranks
/// JSON's; ties fall back to JSON. A malformed media range or parameter
/// discards that member alone, so the remaining well-formed members still
/// decide the outcome.
pub(crate) fn proxy_error_representation(headers: &HeaderMap) -> ProxyErrorRepresentation {
    let mut html = None;
    let mut json = None;

    for value in headers.get_all(header::ACCEPT) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for member in value.split(',') {
            let mut parts = member.split(';');
            let media_range = parts.next().unwrap_or_default().trim();
            if media_range.is_empty() {
                continue;
            }

            let mut quality = None;
            let mut valid = true;
            for parameter in parts {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    valid = false;
                    break;
                };
                if name.trim().eq_ignore_ascii_case("q") {
                    if quality.is_some() {
                        valid = false;
                        break;
                    }
                    quality = parse_quality(value);
                    if quality.is_none() {
                        valid = false;
                        break;
                    }
                }
            }
            if !valid {
                continue;
            }
            let quality = quality.unwrap_or(1000);

            if media_range.eq_ignore_ascii_case("text/html") {
                update_preference(&mut html, quality, 2);
            } else if media_range.eq_ignore_ascii_case("text/*") {
                update_preference(&mut html, quality, 1);
            } else if media_range.eq_ignore_ascii_case("application/json") {
                update_preference(&mut json, quality, 2);
            } else if media_range.eq_ignore_ascii_case("application/*") {
                update_preference(&mut json, quality, 1);
            } else if media_range == "*/*" {
                update_preference(&mut html, quality, 0);
                update_preference(&mut json, quality, 0);
            }
        }
    }

    let html_wins = match (html, json) {
        (Some(html), Some(json)) => html.quality > 0 && html > json,
        (Some(html), None) => html.quality > 0,
        _ => false,
    };
    if html_wins {
        ProxyErrorRepresentation::Html
    } else {
        ProxyErrorRepresentation::Json
    }
}

/// The HTML page for an owned rejection.
///
/// Every value interpolated here is a literal chosen by status code. No
/// request-derived value is reflected into the document — not the path, the
/// host, the user, the upstream, nor an internal error string — so a page that
/// lands in the wrong browser, a shared screen or a bug report carries none of
/// them. The status itself, and the fact that Sekisho refused, remain visible.
/// It also references no external asset, which keeps a refusal from turning
/// into a request to a third party.
fn html_error_body(status: StatusCode) -> String {
    let (title, message) = match status {
        StatusCode::BAD_REQUEST => ("Bad request", "The request could not be understood."),
        StatusCode::FORBIDDEN => ("Access denied", "You do not have access to this resource."),
        StatusCode::NOT_FOUND => ("Page not found", "The requested resource was not found."),
        StatusCode::METHOD_NOT_ALLOWED => {
            ("Method not allowed", "This request method is not allowed.")
        }
        StatusCode::PAYLOAD_TOO_LARGE => (
            "Request body too large",
            "The request body exceeds the allowed size.",
        ),
        StatusCode::BAD_GATEWAY => (
            "Upstream unavailable",
            "The upstream service could not respond.",
        ),
        StatusCode::SERVICE_UNAVAILABLE => (
            "Service unavailable",
            "The service is temporarily unavailable.",
        ),
        StatusCode::GATEWAY_TIMEOUT => (
            "Upstream timed out",
            "The upstream service did not respond in time.",
        ),
        _ => ("Request failed", "The request could not be completed."),
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title></head><body><main><h1>{title}</h1><p>{message}</p></main></body></html>"
    )
}

/// Reproduce an owned source's pre-negotiation response exactly. Internal
/// routes use this when they share a transport limit with the public proxy but
/// remain outside the public representation contract.
pub(crate) fn legacy_proxy_error_response(kind: ProxyErrorKind) -> Response<Body> {
    let (body, content_type) = kind.legacy_representation();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = kind.status();
    if let Some(content_type) = content_type {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    }
    response
}

/// Build a negotiated fixed error response for a Sekisho-owned public proxy
/// rejection. No request-derived value is included in either representation.
pub(crate) fn proxy_error_response(
    kind: ProxyErrorKind,
    representation: ProxyErrorRepresentation,
) -> Response<Body> {
    let status = kind.status();
    let mut response = match representation {
        ProxyErrorRepresentation::Json => legacy_proxy_error_response(kind),
        ProxyErrorRepresentation::Html => {
            let mut response = Response::new(Body::from(html_error_body(status)));
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(
                    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
                ),
            );
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            );
            response
        }
    };
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Shorthand for the rejections the request pipeline raises by status.
fn proxy_error(status: StatusCode, representation: ProxyErrorRepresentation) -> Response<Body> {
    proxy_error_response(ProxyErrorKind::Handler(status), representation)
}

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

/// Rewrite an authorized request and send it upstream.
///
/// Order matters here: the signed-identity claim set is prepared first, so
/// that a session which cannot produce one fails with 403 before an upstream
/// has been chosen or a single header rewritten. Doing it later would mean a
/// rejected request had already been partially committed.
async fn forward_request(
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

/// Borrowed per-request context that [`forward_request`] needs but that is
/// not part of the request itself. Grouped into one struct purely to keep the
/// argument list of an already long signature readable.
#[derive(Clone, Copy)]
struct ForwardingRuntime<'a> {
    shutdown_ctl: &'a Arc<crate::shutdown::ShutdownController>,
    websocket_budget: &'a WebSocketBudget,
    selection: &'a crate::route_generation::RouteSelection,
}

/// Single emission point for `sekisho_proxy_upstream_errors_total` so
/// every error site uses the same metric name and label set. `kind` is
/// a stable, low-cardinality enum (timeout / connect / tls / response
/// / etc.); never include error message text — it explodes cardinality.
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

/// Send the prepared request to the upstream, choosing the right client.
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
    // unchanged from the c31e725 era. Routes with neither
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
        //   1. Explicit `host_rewrite` (the original c31e725 fix).
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
            if let Ok(v) = value.to_str() {
                req_builder = req_builder.header(key.as_str(), v);
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
            Err(e) => {
                // reqwest's Display is shallow — chain through .source() so we
                // see which layer actually broke (TLS? connect? H2 frame?).
                let mut chain = Vec::new();
                let mut src: Option<&dyn std::error::Error> = Some(&e);
                while let Some(s) = src {
                    chain.push(s.to_string());
                    src = s.source();
                }
                tracing::error!(
                    error = %e,
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
        for (k, v) in resp_headers.iter() {
            builder = builder.header(k, v);
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
        for (k, v) in parts.headers.iter() {
            builder = builder.header(k, v);
        }
        builder
            .body(Body::new(incoming))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
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

/// Join an upstream base URL with the incoming path and query.
///
/// The base's trailing slash is trimmed because `route.to` is written both
/// ways by operators and the path always starts with one; without the trim
/// every such route would produce a `//` prefix that some upstreams treat as
/// a distinct path. The path component has already been canonicalized and
/// re-encoded upstream of here, so this is a concatenation, not a place to
/// re-sanitize.
///
/// Shared with the WebSocket path, hence `pub`.
pub fn build_upstream_uri(base: &str, original: &Uri) -> Result<Uri, StatusCode> {
    let base = base.trim_end_matches('/');
    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    format!("{base}{path_and_query}")
        .parse::<Uri>()
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build upstream URI");
            StatusCode::BAD_GATEWAY
        })
}

use super::websocket;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ConnectInfo;
    use http_body_util::{BodyExt, Full};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct PendingBody;

    impl hyper::body::Body for PendingBody {
        type Data = axum::body::Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Pending
        }
    }

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

    fn leased_body(
        body: Body,
        semaphore: &Arc<tokio::sync::Semaphore>,
        idle: Option<std::time::Duration>,
    ) -> RouteLeaseBody {
        RouteLeaseBody::new(
            body,
            Some(semaphore.clone().try_acquire_owned().unwrap()),
            idle,
            "test-route".into(),
        )
    }

    #[tokio::test]
    async fn route_lease_releases_on_eof_error_drop_and_idle_expiry() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));

        let mut eof = leased_body(Body::empty(), &semaphore, None);
        assert!(eof.frame().await.is_none());
        assert_eq!(semaphore.available_permits(), 1);

        let mut error = leased_body(
            Body::new(OneFrameBody(Some(Err(std::io::Error::other(
                "fixture failure",
            ))))),
            &semaphore,
            None,
        );
        assert!(error.frame().await.expect("error frame").is_err());
        assert_eq!(semaphore.available_permits(), 1);

        let dropped = leased_body(Body::new(PendingBody), &semaphore, None);
        assert_eq!(semaphore.available_permits(), 0);
        drop(dropped);
        assert_eq!(semaphore.available_permits(), 1);

        let mut idle = leased_body(
            Body::new(PendingBody),
            &semaphore,
            Some(std::time::Duration::from_secs(60)),
        );
        idle.idle
            .as_mut()
            .expect("idle timer")
            .as_mut()
            .reset(tokio::time::Instant::now());
        let frame = idle.frame().await.expect("timeout frame");
        assert!(frame.is_err());
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn non_empty_data_resets_body_idle_deadline() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let mut body = leased_body(
            Body::new(OneFrameBody(Some(Ok(hyper::body::Frame::data(
                axum::body::Bytes::from_static(b"data"),
            ))))),
            &semaphore,
            Some(std::time::Duration::from_secs(60)),
        );
        body.idle
            .as_mut()
            .expect("idle timer")
            .as_mut()
            .reset(tokio::time::Instant::now());

        let frame = body
            .frame()
            .await
            .expect("data frame")
            .expect("successful data");
        assert_eq!(frame.data_ref().expect("DATA"), b"data".as_slice());
        assert!(body.idle.as_ref().expect("idle timer").deadline() > tokio::time::Instant::now());
        assert_eq!(semaphore.available_permits(), 0);
        assert!(body.frame().await.is_none());
        assert_eq!(semaphore.available_permits(), 1);
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

    fn representation_for(values: &[&str]) -> ProxyErrorRepresentation {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                header::ACCEPT,
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
        }
        proxy_error_representation(&headers)
    }

    /// The default-to-JSON contract, case by case: absent, empty, wildcard-only,
    /// tie, and `q=0` all stay on the legacy wire. Only an explicit preference
    /// that outranks JSON switches.
    #[test]
    fn proxy_error_accept_contract_is_json_safe_by_default() {
        for (values, expected) in [
            (vec![], ProxyErrorRepresentation::Json),
            (vec![""], ProxyErrorRepresentation::Json),
            (vec!["*/*"], ProxyErrorRepresentation::Json),
            (vec!["image/png"], ProxyErrorRepresentation::Json),
            (vec!["text/html"], ProxyErrorRepresentation::Html),
            (vec!["TEXT/HTML; Q=1"], ProxyErrorRepresentation::Html),
            (vec!["text/html;q=0"], ProxyErrorRepresentation::Json),
            (
                vec!["text/html;q=0, */*;q=1"],
                ProxyErrorRepresentation::Json,
            ),
            (
                vec!["text/html;q=0.8, application/json;q=0.8"],
                ProxyErrorRepresentation::Json,
            ),
            (
                vec!["text/html;q=0.8, application/*;q=0.8"],
                ProxyErrorRepresentation::Html,
            ),
            (
                vec!["text/*;q=0.8, application/json;q=0.8"],
                ProxyErrorRepresentation::Json,
            ),
            (
                vec!["text/html;q=0.8, */*;q=0.9"],
                ProxyErrorRepresentation::Json,
            ),
            (vec!["text/html;q=bogus"], ProxyErrorRepresentation::Json),
            (vec!["text/html;q=1.001"], ProxyErrorRepresentation::Json),
            (
                vec!["text/html;q=0.9;q=0.8"],
                ProxyErrorRepresentation::Json,
            ),
            (
                vec!["application/json;q=0.8", "text/html;level=1;q=0.9"],
                ProxyErrorRepresentation::Html,
            ),
            (
                vec!["text/html;q=0.5, text/html;q=0.9, application/json;q=0.8"],
                ProxyErrorRepresentation::Html,
            ),
            (
                vec!["text/html;q=0.9, application/json;q=malformed"],
                ProxyErrorRepresentation::Html,
            ),
        ] {
            assert_eq!(representation_for(&values), expected, "{values:?}");
        }
    }

    /// Existing clients see byte-identical bodies and content types. The only
    /// additions are `Vary` and `Cache-Control`, which a JSON client ignores but
    /// a cache needs.
    #[tokio::test]
    async fn proxy_json_wire_is_exact_except_for_negotiation_headers() {
        for (status, expected) in [
            (StatusCode::NOT_FOUND, r#"{"error":"no matching route"}"#),
            (StatusCode::FORBIDDEN, r#"{"error":"access denied"}"#),
            (StatusCode::BAD_GATEWAY, r#"{"error":"upstream error"}"#),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"service not configured"}"#,
            ),
            (StatusCode::BAD_REQUEST, r#"{"error":"bad request"}"#),
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"request body too large"}"#,
            ),
            (
                StatusCode::METHOD_NOT_ALLOWED,
                r#"{"error":"internal server error"}"#,
            ),
            (
                StatusCode::GATEWAY_TIMEOUT,
                r#"{"error":"internal server error"}"#,
            ),
        ] {
            let response = proxy_error(status, ProxyErrorRepresentation::Json);
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(response.headers()[header::VARY], "Accept");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(
                !response
                    .headers()
                    .contains_key(header::CONTENT_SECURITY_POLICY)
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], expected.as_bytes());
        }
    }

    /// For each owned status listed here, the page is well-formed, carries the
    /// security headers, and reflects no request-derived value. The list is
    /// written out rather than derived, so it covers exactly these statuses.
    #[tokio::test]
    async fn proxy_html_is_fixed_accessible_and_hardened_for_every_owned_status() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let response = proxy_error(status, ProxyErrorRepresentation::Html);
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "text/html; charset=utf-8"
            );
            assert_eq!(response.headers()[header::VARY], "Accept");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
            assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
            assert!(
                response.headers()[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap()
                    .contains("default-src 'none'")
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(body.starts_with("<!doctype html><html lang=\"en\">"));
            assert!(body.contains("<main><h1>"));
            assert!(!body.contains("<script"));
            assert!(!body.contains("<link"));
            assert!(!body.contains("missing.example.com"));
        }
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
