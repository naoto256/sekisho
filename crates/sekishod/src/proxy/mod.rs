//! The data plane: the router every proxied request travels through.
//!
//! ## Layer order is the security model
//!
//! Axum applies `.layer()` in reverse registration order, so the outermost
//! middleware is the last one listed in [`router_with_limits`]. Reading it
//! outside-in, a request meets: request-id assignment, request-target
//! canonicalization, the shutdown handle, the concurrency budgets, the body
//! limit, metrics, and only then the route match in
//! [`handler::proxy_handler`].
//!
//! That order is not cosmetic. Target canonicalization has to run before
//! anything inspects the path, or route matching and policy evaluation would
//! be deciding on a string the upstream may read differently — see
//! [`crate::request_target`]. The request id has to be assigned outside
//! everything else, or a request rejected by an early layer produces log lines
//! with no correlation id, which is exactly the case an operator is trying to
//! trace.
//!
//! ## Two budgets, two shapes
//!
//! Both limits exist for the same reason — one degraded upstream must not be
//! able to consume the whole runtime — but they are enforced differently.
//!
//! [`HttpConcurrencyBudget`] *waits*: an HTTP request queues for a permit, and
//! the permit is held until the response body finishes streaming, not until
//! the handler returns. That is what [`GlobalPermitBody`] is for; releasing at
//! handler exit would let an unbounded number of slow body transfers pile up
//! behind a budget that believes it is idle.
//!
//! [`WebSocketBudget`] *rejects*: a tunnel is long-lived, so queueing for one
//! means holding a connection open with no idea how long the wait is. An
//! immediate 503 is the honest answer, and the caller can retry.
//!
//! ## Internal endpoints are nested, not routed
//!
//! Everything under `/.sekisho` is Sekisho's own surface (auth callbacks, ACME
//! challenge, sign-out) and is nested ahead of the proxy fallback, with CORS
//! set to an empty origin list — these endpoints are only ever reached by
//! top-level navigation, so any cross-origin read is by definition not a
//! legitimate caller.

pub mod handler;
pub(super) mod header_boundary;
pub mod route_client;
pub mod transform;
pub mod upstream;
pub mod websocket;

pub use route_client::RouteClientCache;

use crate::auth;
use crate::auth::handoff::HandoffCipher;
use crate::auth::middleware::AuthStateStore;
use crate::crypto::{IdentityKeyRingSnapshot, MasterKey};
use crate::session::cookie_manager::CookieManager;
use crate::session::manager::SessionManager;
use crate::state::AppState;
use crate::store::Store;
use crate::tls::acme::AcmeManager;
use crate::tls::acme::challenge::Http01Provider;
use axum::Router;
use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, Response, StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::get;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};

/// Cap on a single request body. Transforms that need to inspect or rewrite a
/// body collect it into memory first, so an unbounded body is a direct path to
/// swap. 10 MiB covers ordinary web traffic including small uploads.
const PROXY_BODY_LIMIT: usize = 10 * 1024 * 1024;

/// Default ceiling on in-flight HTTP requests across all routes. Per-route
/// caps ([`crate::models::route::Route::concurrency_limit`]) subdivide this;
/// the global figure exists so that a route without one still cannot exhaust
/// the runtime.
const PROXY_CONCURRENCY_LIMIT: usize = 500;

/// Permit pool bounding concurrent WebSocket tunnels.
///
/// Sized from `global_config.websocket_concurrency_limit`, which is why the
/// limit is also published to metrics at construction: the gauge is meaningless
/// without the denominator, and the denominator is only known here.
#[derive(Clone)]
pub(crate) struct WebSocketBudget(Arc<Semaphore>);

impl WebSocketBudget {
    fn new(limit: u32) -> Self {
        crate::observability::record_control_budget_limit(
            crate::observability::ControlBudget::ProxyWebsocket,
            limit as usize,
        );
        Self(Arc::new(Semaphore::new(limit as usize)))
    }

    /// Take a permit or fail immediately with 503.
    ///
    /// Non-blocking on purpose — see the module docs. The rejection is counted
    /// before the error is returned so that "we are shedding tunnels" is
    /// visible in metrics even though the caller only sees a status code.
    pub(crate) fn try_acquire(&self) -> Result<ObservedWebSocketPermit, StatusCode> {
        let permit = self.0.clone().try_acquire_owned().map_err(|_| {
            crate::observability::record_control_budget_rejection(
                crate::observability::RejectedControlBudget::ProxyWebsocket,
            );
            StatusCode::SERVICE_UNAVAILABLE
        })?;
        Ok(ObservedWebSocketPermit {
            _permit: permit,
            _observation: crate::observability::observe_control_budget(
                crate::observability::ControlBudget::ProxyWebsocket,
            ),
        })
    }
}

/// A held WebSocket permit bundled with its metrics observation.
///
/// Both fields are drop guards and neither is read, hence the underscores.
/// Pairing them in one value is what keeps the gauge honest: there is no way
/// to release the permit without also ending the observation.
pub(crate) struct ObservedWebSocketPermit {
    _permit: OwnedSemaphorePermit,
    _observation: crate::observability::ControlBudgetObservation,
}

/// Permit pool bounding in-flight HTTP requests.
#[derive(Clone)]
struct HttpConcurrencyBudget(Arc<Semaphore>);

impl HttpConcurrencyBudget {
    fn new(limit: usize) -> Self {
        crate::observability::record_control_budget_limit(
            crate::observability::ControlBudget::ProxyHttp,
            limit,
        );
        Self(Arc::new(Semaphore::new(limit)))
    }
}

/// Response body wrapper that holds the concurrency permit until the last
/// frame is delivered.
///
/// Without this the permit would drop when the handler returns, and a hundred
/// slow clients each streaming a large response would sit outside the budget
/// entirely. Both the permit and the observation are released on end-of-stream
/// *and* on error, since a failed transfer frees the same resources a
/// successful one does.
struct GlobalPermitBody {
    inner: Body,
    permit: Option<OwnedSemaphorePermit>,
    observation: Option<crate::observability::ControlBudgetObservation>,
}

impl hyper::body::Body for GlobalPermitBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(result, std::task::Poll::Ready(None | Some(Err(_)))) {
            this.permit.take();
            this.observation.take();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Acquire an HTTP permit, run the request, and hand the permit to the
/// response body so it outlives this function.
async fn global_concurrency_middleware(
    Extension(budget): Extension<HttpConcurrencyBudget>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let public_representation = public_proxy_error_representation(&req);
    let permit = match budget.0.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            return public_representation.map_or_else(
                || StatusCode::SERVICE_UNAVAILABLE.into_response(),
                |representation| {
                    handler::proxy_error_response(
                        handler::ProxyErrorKind::GlobalConcurrency,
                        representation,
                    )
                },
            );
        }
    };
    let observation = crate::observability::observe_control_budget(
        crate::observability::ControlBudget::ProxyHttp,
    );
    let response = next.run(req).await;
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(GlobalPermitBody {
            inner: body,
            permit: Some(permit),
            observation: Some(observation),
        }),
    )
}

/// The representation to use for a rejection, or `None` when this request is
/// not one the public contract covers.
///
/// Negotiation is offered only to traffic that reached the proxy as a public
/// request and is not bound for Sekisho's own endpoints. Returning `None` for
/// everything else is what keeps the internal surface on its legacy wire form:
/// a probe, a callback or a management call has a machine on the other end,
/// and handing it HTML because some client sent a browser-shaped `Accept`
/// would be a regression no one asked for.
fn public_proxy_error_representation(
    request: &Request<Body>,
) -> Option<handler::ProxyErrorRepresentation> {
    request
        .extensions()
        .get::<crate::request_target::CanonicalRequestTarget>()
        .filter(|target| !handler::is_internal_path(target.path()))
        .map(|_| handler::proxy_error_representation(request.headers()))
}

/// A capped body that remembers whether the cap was actually hit.
///
/// The cap itself comes from `Limited`; what this adds is the flag. Once the
/// body is handed downstream the middleware no longer sees the error — the
/// handler does, and it turns into some response of its own. The shared flag is
/// how the middleware learns, after the fact, that the response it is holding
/// exists because the upload was too large, and should be replaced with the
/// limit rejection rather than passed through.
struct ObservedBodyLimit {
    inner: http_body_util::Limited<Body>,
    overflowed: Arc<std::sync::atomic::AtomicBool>,
}

impl hyper::body::Body for ObservedBodyLimit {
    type Data = axum::body::Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(
            &result,
            std::task::Poll::Ready(Some(Err(error)))
                if error.downcast_ref::<http_body_util::LengthLimitError>().is_some()
        ) {
            this.overflowed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Build the 413, negotiated for public traffic and left in its legacy form
/// for everything else. `None` is not a fallback for "could not decide" — it
/// is the positive answer that this request is outside the public contract.
fn request_body_limit_response(
    representation: Option<handler::ProxyErrorRepresentation>,
) -> Response<Body> {
    match representation {
        Some(representation) => {
            handler::proxy_error_response(handler::ProxyErrorKind::RequestBodyLimit, representation)
        }
        None => handler::legacy_proxy_error_response(handler::ProxyErrorKind::RequestBodyLimit),
    }
}

/// Reject on a declared Content-Length above the cap before any body is read,
/// and otherwise cap the stream so an unknown-length body is cut at the same
/// budget. The representation is captured up front and used by both paths.
/// The streaming rejection is signalled by the body adapter itself rather than
/// inferred by post-processing a response.
async fn request_body_limit_middleware(request: Request<Body>, next: Next) -> Response<Body> {
    let representation = public_proxy_error_representation(&request);
    let content_length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    let body_limit = match content_length {
        Some(length) if length > PROXY_BODY_LIMIT => {
            return request_body_limit_response(representation);
        }
        Some(length) => PROXY_BODY_LIMIT.min(length),
        None => PROXY_BODY_LIMIT,
    };

    let overflowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let body_overflowed = Arc::clone(&overflowed);
    let request = request.map(|body| {
        Body::new(ObservedBodyLimit {
            inner: http_body_util::Limited::new(body, body_limit),
            overflowed: body_overflowed,
        })
    });
    let response = next.run(request).await;
    if overflowed.load(std::sync::atomic::Ordering::Acquire) {
        request_body_limit_response(representation)
    } else {
        response
    }
}

/// Start the periodic sweep for expired pending-auth states and handoff
/// nonces.
///
/// Split out of router construction so the router can be built without
/// spawning anything — see [`DeferredProxyRouter`].
fn spawn_auth_state_cleanup(
    shutdown_ctl: &Arc<crate::shutdown::ShutdownController>,
    cleanup_auth_state: Arc<AuthStateStore>,
    cleanup_store: Store,
) {
    crate::shutdown::spawn_periodic(
        shutdown_ctl,
        "auth-state.cleanup",
        std::time::Duration::from_secs(300),
        crate::shutdown::PeriodicOpts::default(),
        move || {
            let cleanup_auth_state = cleanup_auth_state.clone();
            let cleanup_store = cleanup_store.clone();
            async move {
                match cleanup_auth_state.cleanup_expired().await {
                    Ok(removed) if removed > 0 => {
                        tracing::debug!(removed, "cleaned up expired auth states");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        // A degraded service DB will surface here; we log
                        // and move on — losing this tick doesn't break any
                        // live flow, just delays TTL enforcement.
                        tracing::warn!(error = %e, "pending-auth cleanup sweep failed");
                    }
                }
                match cleanup_store.handoff_nonce_cleanup_expired().await {
                    Ok(removed) if removed > 0 => {
                        tracing::debug!(removed, "cleaned up expired handoff nonces");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "handoff nonce cleanup sweep failed");
                    }
                }
            }
        },
    );
}

/// Build a fully started proxy router.
///
/// Convenience wrapper over [`router_deferred`] +
/// [`DeferredProxyRouter::start_background_tasks`] that also fixes the session
/// lifetime. Only in-crate tests use it — production goes through
/// [`router_deferred`] so that listener binding and background-task startup
/// can be sequenced explicitly — hence the `dead_code` allowance.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn router(
    store: Store,
    route_generation: Arc<crate::route_generation::RouteGeneration>,
    cookie_secret: &[u8],
    acme_manager: Arc<AcmeManager<Http01Provider>>,
    master_key: Arc<MasterKey>,
    identity_key_ring: Arc<IdentityKeyRingSnapshot>,
    identity_authority: Arc<crate::identity::IdentityAuthority>,
    tls_enabled: bool,
    cookie_name: String,
    websocket_concurrency_limit: u32,
    shutdown_ctl: Arc<crate::shutdown::ShutdownController>,
) -> Router {
    router_deferred(
        store,
        route_generation,
        cookie_secret,
        acme_manager,
        master_key,
        identity_key_ring,
        identity_authority,
        tls_enabled,
        cookie_name,
        websocket_concurrency_limit,
        8,
        shutdown_ctl.clone(),
    )
    .start_background_tasks(&shutdown_ctl)
}

/// A built router whose background tasks have not started yet.
///
/// Startup wants to construct the router, verify it can bind, and only then
/// spawn periodic work — a task spawned before a failed bind would have to be
/// torn down again, and the shutdown controller would be tracking a task that
/// never had a listener. Making the unstarted state a distinct type means the
/// caller cannot forget the second step: the `Router` is unreachable until
/// [`Self::start_background_tasks`] is called.
pub(crate) struct DeferredProxyRouter {
    router: Router,
    cleanup_auth_state: Arc<AuthStateStore>,
    cleanup_store: Store,
}

impl DeferredProxyRouter {
    pub(crate) fn start_background_tasks(
        self,
        shutdown_ctl: &Arc<crate::shutdown::ShutdownController>,
    ) -> Router {
        spawn_auth_state_cleanup(shutdown_ctl, self.cleanup_auth_state, self.cleanup_store);
        self.router
    }
}

/// Build the proxy router with the default global HTTP concurrency limit.
///
/// The production entry point. Takes the WebSocket limit from config but not
/// the HTTP one, which stays a compile-time constant — see
/// [`PROXY_CONCURRENCY_LIMIT`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn router_deferred(
    store: Store,
    route_generation: Arc<crate::route_generation::RouteGeneration>,
    cookie_secret: &[u8],
    acme_manager: Arc<AcmeManager<Http01Provider>>,
    master_key: Arc<MasterKey>,
    identity_key_ring: Arc<IdentityKeyRingSnapshot>,
    identity_authority: Arc<crate::identity::IdentityAuthority>,
    tls_enabled: bool,
    cookie_name: String,
    websocket_concurrency_limit: u32,
    session_lifetime_hours: u32,
    shutdown_ctl: Arc<crate::shutdown::ShutdownController>,
) -> DeferredProxyRouter {
    router_with_limits(
        store,
        route_generation,
        cookie_secret,
        acme_manager,
        master_key,
        identity_key_ring,
        identity_authority,
        tls_enabled,
        cookie_name,
        ProxyConcurrencyLimits {
            http: PROXY_CONCURRENCY_LIMIT,
            websocket: websocket_concurrency_limit,
        },
        session_lifetime_hours,
        shutdown_ctl,
    )
}

/// Both concurrency ceilings, grouped so tests can override them together.
#[derive(Clone, Copy)]
struct ProxyConcurrencyLimits {
    http: usize,
    websocket: u32,
}

/// The real router construction. Assembles shared state, mounts the internal
/// `/.sekisho` surface ahead of the proxy fallback, and stacks the middleware
/// described in the module docs.
#[allow(clippy::too_many_arguments)]
fn router_with_limits(
    store: Store,
    route_generation: Arc<crate::route_generation::RouteGeneration>,
    cookie_secret: &[u8],
    acme_manager: Arc<AcmeManager<Http01Provider>>,
    master_key: Arc<MasterKey>,
    identity_key_ring: Arc<IdentityKeyRingSnapshot>,
    identity_authority: Arc<crate::identity::IdentityAuthority>,
    tls_enabled: bool,
    cookie_name: String,
    limits: ProxyConcurrencyLimits,
    session_lifetime_hours: u32,
    shutdown_ctl: Arc<crate::shutdown::ShutdownController>,
) -> DeferredProxyRouter {
    let client = Client::builder(TokioExecutor::new()).build_http();

    let cookie_manager = CookieManager::new(cookie_secret).with_name(cookie_name.clone());
    let session_manager = SessionManager::new(store.clone(), session_lifetime_hours);
    let handoff_cipher = HandoffCipher::new(master_key);
    // DB-backed so an HA load balancer that sends `/saml/login` and
    // the ACS POST to different nodes still finds the flow. The
    // underlying `Store` dispatches to whichever backend is configured
    // (SQLite single-node or Postgres HA), so no branching is needed.
    let auth_state_store = Arc::new(AuthStateStore::new(store.clone()));

    let state = AppState {
        store,
        client,
        route_generation,
        auth_state_store,
        session_manager: Arc::new(session_manager),
        cookie_manager: Arc::new(cookie_manager),
        acme_manager,
        handoff_cipher,
        #[cfg(not(test))]
        identity_key_ring: Arc::clone(&identity_key_ring),
        #[cfg(test)]
        jwt_signing_key: identity_key_ring,
        identity_authority,
        tls_enabled,
        session_cookie_name: cookie_name,
        pipeline: Arc::new(transform::default_pipeline()),
        oidc_clients: Arc::new(RwLock::new(std::collections::HashMap::new())),
        saml_clients: Arc::new(RwLock::new(std::collections::HashMap::new())),
        idp_version_seen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    };

    // Internal /.sekisho/* endpoints with explicit CORS deny
    let internal_routes = Router::new()
        .route("/auth-start", get(auth::strategy::auth_start))
        .route("/callback", get(auth::oidc::callback::oidc_callback))
        .route("/session-handoff", get(auth::handoff::session_handoff))
        .route(
            "/.well-known/acme-challenge/{token}",
            get(acme_challenge_handler),
        )
        .route("/sign-out", get(auth::sign_out))
        .route("/signed-out", get(auth::signed_out))
        .route("/userinfo", get(auth::userinfo))
        .route(
            "/saml/acs",
            axum::routing::post(auth::saml::callback::saml_acs),
        )
        .route("/saml/metadata", get(auth::saml::callback::saml_metadata))
        // SAML Single Logout callback. The spec allows either binding,
        // and IdPs do choose (Entra defaults to Redirect, some ADFS
        // deployments to POST) — register both so the same URL works.
        .route(
            "/saml/slo",
            get(auth::saml::callback::saml_slo_redirect).post(auth::saml::callback::saml_slo_post),
        )
        .layer(tower_http::cors::CorsLayer::new().allow_origin(
            tower_http::cors::AllowOrigin::list(std::iter::empty::<axum::http::HeaderValue>()),
        ));

    // Nominally wakes every 300 s; each tick first runs the pending-
    // auth store cleanup, then the handoff-nonce retention cleanup.
    // Scheduling and DB delay mean 300 s is not an upper bound on
    // stale-entry retention. The tracked periodic task stops
    // on shutdown and is joined before Store close.
    let cleanup_auth_state = state.auth_state_store.clone();
    let cleanup_store = state.store.clone();
    // Coarse DoS guards for the proxy layer.
    //
    // - Body limit: collecting upstream response bodies for transforms
    //   like OIDC-cookie rewriting already allocates into memory. An
    //   untrusted upstream (or a misbehaving client POST) could push us
    //   into swap if we accept unbounded bodies. 10 MiB covers normal
    //   web traffic including small file uploads; operators running a
    //   genuinely large-upload workload will need to raise this.
    // - Concurrency limit: a slow upstream can pin in-flight tasks;
    //   without a cap, a single degraded backend eats the whole tokio
    //   runtime and takes every other route down with it. 500 is a
    //   safe default for a jump-host style proxy.
    //
    // Per-route / per-client limits are a follow-up concern — the
    // goal here is to keep any single route from OOMing the process.
    let http_budget = HttpConcurrencyBudget::new(limits.http);
    let websocket_budget = WebSocketBudget::new(limits.websocket);

    let router = Router::new()
        .nest("/.sekisho", internal_routes)
        // All other requests go through the proxy
        .fallback(handler::proxy_handler)
        .layer(axum::middleware::from_fn(
            crate::observability::metrics_middleware,
        ))
        .layer(axum::middleware::from_fn(request_body_limit_middleware))
        .layer(axum::middleware::from_fn(global_concurrency_middleware))
        .layer(Extension(http_budget))
        .layer(Extension(websocket_budget))
        .layer(axum::Extension(shutdown_ctl))
        .layer(axum::middleware::from_fn(crate::request_target::middleware))
        // Per-request correlation id. Same posture as the management
        // API: outermost middleware so every audit-relevant log line
        // (denial, upstream failure, signed-identity emission) ties
        // back to a single id, and the response carries it for caller
        // correlation. Honours `X-Request-ID` only when it parses as a
        // UUID — see `audit::request_id_middleware`.
        .layer(axum::middleware::from_fn(
            crate::audit::request_id_middleware,
        ))
        .with_state(state);

    DeferredProxyRouter {
        router,
        cleanup_auth_state,
        cleanup_store,
    }
}

/// Serve an HTTP-01 challenge response.
///
/// Lives on the proxy listener rather than the management API because the
/// ACME server fetches it over plain HTTP from the internet, unauthenticated
/// — the one endpoint here that is meant to be reachable by anyone. Unknown
/// tokens return 404 rather than an error body: the provider holds the only
/// valid tokens, so anything else is a scan.
async fn acme_challenge_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> std::result::Result<String, axum::http::StatusCode> {
    match state
        .acme_manager
        .challenge_provider()
        .get_response(&token)
        .await
    {
        Some(key_auth) => {
            tracing::debug!(token = %token, "serving ACME challenge response");
            Ok(key_auth)
        }
        None => {
            tracing::debug!(token = %token, "ACME challenge token not found");
            Err(axum::http::StatusCode::NOT_FOUND)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

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

    struct ErrorBody;

    impl hyper::body::Body for ErrorBody {
        type Data = axum::body::Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Ready(Some(Err(std::io::Error::other("body failed"))))
        }
    }

    fn metric_sample(rendered: &str, name: &str, budget: &str) -> Option<f64> {
        rendered.lines().find_map(|line| {
            let prefix = format!("{name}{{budget=\"{budget}\"}} ");
            line.strip_prefix(&prefix)?.parse().ok()
        })
    }

    #[tokio::test(flavor = "current_thread")]
    async fn global_http_permit_lives_until_body_completion_or_drop() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _recorder_guard = metrics::set_default_local_recorder(&recorder);
        crate::observability::seed_control_budget_metrics_for_test();

        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let mut body = GlobalPermitBody {
            inner: Body::empty(),
            permit: Some(permit),
            observation: Some(crate::observability::observe_control_budget(
                crate::observability::ControlBudget::ProxyHttp,
            )),
        };
        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_http"
            ),
            Some(1.0)
        );
        assert!(body.frame().await.is_none());
        assert_eq!(semaphore.available_permits(), 1);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_http"
            ),
            Some(0.0),
            "EOF must release the observation while the wrapper remains alive"
        );
        drop(body);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_http"
            ),
            Some(0.0),
            "dropping after EOF must not double-decrement"
        );

        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let mut body = GlobalPermitBody {
            inner: Body::new(ErrorBody),
            permit: Some(permit),
            observation: Some(crate::observability::observe_control_budget(
                crate::observability::ControlBudget::ProxyHttp,
            )),
        };
        assert_eq!(semaphore.available_permits(), 0);
        assert!(body.frame().await.expect("error frame").is_err());
        assert_eq!(semaphore.available_permits(), 1);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_http"
            ),
            Some(0.0),
            "body error must release the observation while the wrapper remains alive"
        );
        drop(body);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "proxy_http"
            ),
            Some(0.0),
            "dropping after error must not double-decrement"
        );

        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let body = GlobalPermitBody {
            inner: Body::new(PendingBody),
            permit: Some(permit),
            observation: Some(crate::observability::observe_control_budget(
                crate::observability::ControlBudget::ProxyHttp,
            )),
        };
        assert_eq!(semaphore.available_permits(), 0);
        drop(body);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn outer_owned_rejections_negotiate_without_changing_json_wire() {
        use tower::ServiceExt;

        async fn consume_body(request: Request<Body>) -> Response<Body> {
            match request.into_body().collect().await {
                Ok(_) => StatusCode::NO_CONTENT.into_response(),
                Err(_) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
            }
        }

        let closed = Arc::new(Semaphore::new(0));
        closed.close();
        let concurrency_app = Router::new()
            .fallback(|| async { StatusCode::NO_CONTENT })
            .layer(axum::middleware::from_fn(global_concurrency_middleware))
            .layer(Extension(HttpConcurrencyBudget(closed)))
            .layer(axum::middleware::from_fn(crate::request_target::middleware));

        let html = concurrency_app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT, "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(html.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            html.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert!(html.headers().contains_key(header::CONTENT_SECURITY_POLICY));

        let json = concurrency_app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(json.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!json.headers().contains_key(header::CONTENT_TYPE));
        assert_eq!(json.headers()[header::VARY], "Accept");
        assert_eq!(json.headers()[header::CACHE_CONTROL], "no-store");
        assert!(
            json.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );

        let body_limit_app = Router::new()
            .fallback(consume_body)
            .layer(axum::middleware::from_fn(request_body_limit_middleware))
            .layer(axum::middleware::from_fn(crate::request_target::middleware));
        let html = body_limit_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::ACCEPT, "text/html")
                    .header(header::CONTENT_LENGTH, PROXY_BODY_LIMIT + 1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(html.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            html.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );

        let json = body_limit_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_LENGTH, PROXY_BODY_LIMIT + 1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(json.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            json.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(json.headers()[header::VARY], "Accept");
        assert_eq!(
            &json.into_body().collect().await.unwrap().to_bytes()[..],
            b"length limit exceeded"
        );

        let internal = body_limit_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.sekisho/internal")
                    .header(header::ACCEPT, "text/html")
                    .header(header::CONTENT_LENGTH, PROXY_BODY_LIMIT + 1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(internal.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!internal.headers().contains_key(header::VARY));
        assert!(
            !internal
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );

        let unknown_html = body_limit_app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::ACCEPT, "text/html")
                    .body(Body::from(vec![b'x'; PROXY_BODY_LIMIT + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown_html.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            unknown_html.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(unknown_html.headers()[header::VARY], "Accept");
        assert!(
            unknown_html
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );

        let unknown_json = body_limit_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .body(Body::from(vec![b'x'; PROXY_BODY_LIMIT + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown_json.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            unknown_json.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(unknown_json.headers()[header::VARY], "Accept");
        assert_eq!(unknown_json.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            &unknown_json.into_body().collect().await.unwrap().to_bytes()[..],
            b"length limit exceeded"
        );
    }

    #[test]
    fn websocket_budget_is_non_queueing_and_reopens_on_drop() {
        let budget = WebSocketBudget::new(1);
        let first = budget.try_acquire().expect("first permit");
        assert!(budget.try_acquire().is_err(), "full budget must reject");
        drop(first);
        assert!(
            budget.try_acquire().is_ok(),
            "dropped permit must reopen cap"
        );
    }

    #[tokio::test]
    async fn switching_protocols_body_releases_http_budget_without_ws_release() {
        let http = Arc::new(Semaphore::new(1));
        let websocket = WebSocketBudget::new(1);
        let ws_permit = websocket.try_acquire().expect("websocket permit");
        let mut response_body = GlobalPermitBody {
            inner: Body::empty(),
            permit: Some(http.clone().try_acquire_owned().unwrap()),
            observation: Some(crate::observability::observe_control_budget(
                crate::observability::ControlBudget::ProxyHttp,
            )),
        };
        assert_eq!(http.available_permits(), 0);
        assert!(websocket.try_acquire().is_err());

        assert!(response_body.frame().await.is_none());
        assert_eq!(http.available_permits(), 1);
        assert!(websocket.try_acquire().is_err());

        drop(ws_permit);
        assert!(websocket.try_acquire().is_ok());
    }

    #[tokio::test]
    async fn auth_state_cleanup_is_tracked_and_joins_promptly() {
        let master_key = MasterKey::from_test_bytes([0u8; 32]);
        let store = Store::new_for_test("sqlite::memory:", [0u8; 32], None)
            .await
            .expect("store");
        store
            .pending_auth_insert(
                "expired-cleanup-proof",
                &crate::auth::middleware::PendingAuth {
                    idp_id: uuid::Uuid::new_v4(),
                    nonce: String::new(),
                    code_verifier: String::new(),
                    redirect_url: "/".into(),
                    created_at: chrono::Utc::now() - chrono::Duration::hours(1),
                    saml_authn_request_id: None,
                    kind: crate::auth::middleware::PendingAuthKind::Login,
                    browser_nonce_hash: None,
                },
            )
            .await
            .expect("insert expired pending auth");
        let ctl = Arc::new(crate::shutdown::ShutdownController::new());
        ctl.signal();

        let acme_provider = Arc::new(Http01Provider::new(store.clone()));
        let acme_manager = Arc::new(AcmeManager::new(
            store.clone(),
            acme_provider,
            "https://acme.invalid/directory",
            None,
        ));
        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;
        let _router = router(
            store.clone(),
            route_generation,
            &[1u8; 64],
            acme_manager,
            master_key,
            IdentityKeyRingSnapshot::from_test_bytes([2u8; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            100,
            ctl.clone(),
        );
        assert_eq!(
            ctl.tracked_task_count(),
            1,
            "router did not register its cleanup task"
        );

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            ctl.join_tracked_tasks(std::time::Duration::from_secs(1)),
        )
        .await
        .expect("tracked cleanup did not join promptly");
        assert_eq!(ctl.tracked_task_count(), 0);
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pending_auth WHERE csrf = ?")
            .bind("expired-cleanup-proof")
            .fetch_one(store.sqlite_pool())
            .await
            .expect("count pending auth");
        assert_eq!(remaining, 1, "pre-signalled cleanup ran a periodic tick");
    }

    #[tokio::test]
    async fn request_target_guard_preserves_http01_internal_dispatch() {
        use acme_core::ChallengeProvider;
        use tower::ServiceExt;

        let store = Store::new_for_test("sqlite::memory:", [21u8; 32], None)
            .await
            .unwrap();
        let provider = Arc::new(Http01Provider::new(store.clone()));
        provider
            .set("example.com", "safe-token", "safe-key-authorization")
            .await
            .unwrap();
        let manager = Arc::new(AcmeManager::new(
            store.clone(),
            provider,
            "https://acme.invalid/directory",
            None,
        ));
        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;
        let app = router(
            store,
            route_generation,
            &[22u8; 64],
            manager,
            MasterKey::from_test_bytes([23u8; 32]),
            IdentityKeyRingSnapshot::from_test_bytes([24u8; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            2,
            shutdown.clone(),
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.sekisho/.well-known/acme-challenge/safe-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"safe-key-authorization");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.sekisho/.well-known/acme-challenge/missing-token")
                    .header(header::ACCEPT, "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            !response
                .headers()
                .get_all(header::VARY)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .any(|value| value.trim().eq_ignore_ascii_case("accept"))
        );
        assert!(
            !response
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );
        shutdown.signal();
    }
}
