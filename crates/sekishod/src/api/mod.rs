//! The management REST API, nested under `/.sekisho/api/v1`.
//!
//! Served on its own RPK-pinned TLS listener, separate from the proxy port.
//! Nothing here is reachable from proxied traffic.
//!
//! ## Authorization is a property of the subrouter, not the handler
//!
//! Routes are assembled into three groups — `read`, `write`, `admin` — and the
//! corresponding [`scope`] middleware is attached with `route_layer` to the
//! group, not to each handler. Handlers therefore contain no authorization
//! code at all, and adding one to the wrong group is the only way to get its
//! scope wrong. That is deliberate: a missing `require_*` call inside a
//! handler is invisible, whereas a handler in the wrong `Router::new()` block
//! is visible in the shape of this file.
//!
//! A few endpoints are intentionally unauthenticated: `/version` (clients must
//! negotiate compatibility *before* they have credentials), `/metrics`, the
//! JWKS endpoint, the public JWT verifier, the liveness/readiness probes, and
//! `/auth/challenge`. None of them is exposed on the proxy port — "public"
//! here means unauthenticated *within the management plane*, which is itself
//! bound to loopback unless an operator says otherwise (see
//! [`crate::validation::validate_management_api_binding`]).
//!
//! ## Three separate admission budgets
//!
//! The management plane, the probes and the local-auth challenge each get
//! their own semaphore rather than sharing one. The reason is isolation of
//! failure modes: a burst of management writes must not make the readiness
//! probe time out and get the node killed by its orchestrator, and an
//! unauthenticated `/auth/challenge` flood must not consume the capacity an
//! operator needs to fix things. The probe budget is deliberately tiny —
//! probes are cheap and any real backlog of them means something is already
//! wrong.
//!
//! The management budget *queues* (Tower's `GlobalConcurrencyLimitLayer`,
//! since a slow admin request is better than a failed one), while the probe
//! and challenge budgets *reject* through [`AdmissionBudget`], because a
//! queued probe is a probe that has already failed its purpose.

pub mod acme;
pub mod api_keys;
pub mod certs;
pub mod config;
pub mod encryption_keys;
pub mod identity_signing;
pub mod idps;
pub mod instance;
pub mod local_auth;
pub mod pagination;
pub mod policies;
pub mod routes;
pub mod scope;
pub mod sessions;

use crate::crypto::{IdentityKeyRingSnapshot, MasterKey};
use crate::store::Store;
use crate::tls::acme::AcmeManager;
use crate::tls::acme::challenge::Http01Provider;
use crate::tls::resolver::CertResolver;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, FromRef, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// In-flight ceiling for authenticated management requests. Small because the
/// management plane is an operator surface, not a data plane — the figure only
/// has to cover a handful of humans plus a web UI's parallel fetches.
const MANAGEMENT_CONCURRENCY_LIMIT: usize = 50;

/// In-flight ceiling for liveness/readiness probes. Tiny on purpose: probes
/// are cheap and an orchestrator sends them on a fixed schedule, so a backlog
/// means something is already stuck rather than that the limit is too low.
const PROBE_CONCURRENCY_LIMIT: usize = 4;

/// In-flight ceiling for the unauthenticated local-auth challenge endpoint.
/// Sized to absorb a burst from a provisioning script while still capping what
/// an unauthenticated caller can make the daemon do.
const CHALLENGE_CONCURRENCY_LIMIT: usize = 20;

/// A reject-on-exhaustion concurrency budget.
///
/// Distinct from the queueing limiter used for the management plane: here an
/// exhausted budget produces 503 immediately. The metric handles are carried
/// alongside the semaphore so that every rejection is counted at the point it
/// happens — a caller that only sees a status code would otherwise leave no
/// trace of *which* budget shed the request.
#[derive(Clone)]
struct AdmissionBudget {
    permits: Arc<Semaphore>,
    exhausted_reason: &'static str,
    in_flight: crate::observability::ControlBudget,
    rejected: crate::observability::RejectedControlBudget,
}

impl AdmissionBudget {
    /// Wrap a semaphore, publishing its capacity as the gauge denominator.
    ///
    /// Capacity is read from the semaphore rather than passed separately so
    /// the reported limit cannot disagree with the enforced one.
    fn rejecting(
        permits: Arc<Semaphore>,
        exhausted_reason: &'static str,
        in_flight: crate::observability::ControlBudget,
        rejected: crate::observability::RejectedControlBudget,
    ) -> Self {
        crate::observability::record_control_budget_limit(in_flight, permits.available_permits());
        Self {
            permits,
            exhausted_reason,
            in_flight,
            rejected,
        }
    }

    /// Take a permit or fail with 503. Never waits — see the module docs for
    /// why queueing would defeat the purpose on these routes.
    async fn acquire(&self) -> crate::error::Result<ObservedAdmissionPermit> {
        let permit = self.permits.clone().try_acquire_owned().map_err(|_| {
            crate::observability::record_control_budget_rejection(self.rejected);
            crate::error::Error::ServiceUnavailable(self.exhausted_reason.to_owned())
        })?;
        Ok(ObservedAdmissionPermit {
            _permit: permit,
            _observation: crate::observability::observe_control_budget(self.in_flight),
        })
    }
}

/// Held permit plus its in-flight observation. Both are drop guards, so
/// releasing the permit and ending the observation cannot get out of step.
struct ObservedAdmissionPermit {
    _permit: OwnedSemaphorePermit,
    _observation: crate::observability::ControlBudgetObservation,
}

#[cfg(test)]
#[derive(Clone)]
struct AdmissionTestGate {
    entered: Arc<Semaphore>,
    release: tokio::sync::watch::Sender<bool>,
}

#[cfg(test)]
impl AdmissionTestGate {
    fn new() -> Self {
        let (release, _) = tokio::sync::watch::channel(false);
        Self {
            entered: Arc::new(Semaphore::new(0)),
            release,
        }
    }

    async fn wait_in_handler(&self) {
        let mut release = self.release.subscribe();
        self.entered.add_permits(1);
        if !*release.borrow() {
            release
                .changed()
                .await
                .expect("test retains the release sender");
        }
    }

    async fn wait_for_entries(&self, count: u32) {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.entered.clone().acquire_many_owned(count),
        )
        .await
        .expect("timed out waiting for handler entries")
        .expect("handler entry semaphore remains open")
        .forget();
    }

    fn release(&self) {
        self.release.send(true).expect("handler retains a receiver");
    }
}

/// Shared state for management API handlers.
///
/// Most handlers only need the `Store` and use `State<Store>` (extracted via `FromRef`).
/// Handlers that drive certificate issuance (e.g. `certs::issue`) take `State<AppState>`
/// to reach the ACME manager and the live cert resolver.
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub acme: Arc<AcmeManager<Http01Provider>>,
    pub cert_resolver: Arc<CertResolver>,
    /// Key-encryption key. Decrypts every at-rest secret (cookie secret,
    /// OIDC client secrets, TLS private keys, refresh tokens, the JWT
    /// signing key below). Never exposed over the API — a leak here is
    /// total compromise of the daemon's secrets.
    pub master_key: Arc<MasterKey>,
    /// Boot-fixed canonical identity authority shared with the proxy.
    /// Public assertion verification must never derive issuer authority
    /// from request data or a mutable route/config read.
    pub(crate) identity_authority: Arc<crate::identity::IdentityAuthority>,
    /// Ed25519 identity-signing snapshot. Only public keys are exposed via
    /// JWKS; private material never crosses the daemon boundary.
    #[cfg(not(test))]
    pub identity_key_ring: Arc<IdentityKeyRingSnapshot>,
    #[cfg(test)]
    pub jwt_signing_key: Arc<IdentityKeyRingSnapshot>,
}

impl AppState {
    pub(crate) fn identity_key_ring(&self) -> &IdentityKeyRingSnapshot {
        #[cfg(not(test))]
        {
            self.identity_key_ring.as_ref()
        }
        #[cfg(test)]
        {
            self.jwt_signing_key.as_ref()
        }
    }
}

impl FromRef<AppState> for Store {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn router(
    store: Store,
    route_generation: Arc<crate::route_generation::RouteGeneration>,
    acme: Arc<AcmeManager<Http01Provider>>,
    cert_resolver: Arc<CertResolver>,
    master_key: Arc<MasterKey>,
    identity_key_ring: Arc<IdentityKeyRingSnapshot>,
    identity_authority: Arc<crate::identity::IdentityAuthority>,
    challenge_store: Arc<local_auth::ChallengeStore>,
    shutdown_ctl: Arc<crate::shutdown::ShutdownController>,
    acme_issuance_concurrency_limit: u32,
) -> Router {
    router_with_admission_budgets(
        store,
        route_generation,
        acme,
        cert_resolver,
        master_key,
        identity_key_ring,
        identity_authority,
        challenge_store,
        shutdown_ctl,
        acme_issuance_concurrency_limit,
        Arc::new(Semaphore::new(MANAGEMENT_CONCURRENCY_LIMIT)),
        Arc::new(Semaphore::new(PROBE_CONCURRENCY_LIMIT)),
        Arc::new(Semaphore::new(CHALLENGE_CONCURRENCY_LIMIT)),
    )
}

#[allow(clippy::too_many_arguments)]
fn router_with_admission_budgets(
    store: Store,
    route_generation: Arc<crate::route_generation::RouteGeneration>,
    acme: Arc<AcmeManager<Http01Provider>>,
    cert_resolver: Arc<CertResolver>,
    master_key: Arc<MasterKey>,
    identity_key_ring: Arc<IdentityKeyRingSnapshot>,
    identity_authority: Arc<crate::identity::IdentityAuthority>,
    challenge_store: Arc<local_auth::ChallengeStore>,
    shutdown_ctl: Arc<crate::shutdown::ShutdownController>,
    acme_issuance_concurrency_limit: u32,
    management_budget: Arc<Semaphore>,
    probe_budget: Arc<Semaphore>,
    challenge_budget: Arc<Semaphore>,
) -> Router {
    let state = AppState {
        store: store.clone(),
        acme,
        cert_resolver,
        master_key,
        identity_authority,
        #[cfg(not(test))]
        identity_key_ring: Arc::clone(&identity_key_ring),
        #[cfg(test)]
        jwt_signing_key: identity_key_ring,
    };
    // Scope assignment is deliberately centralized here. Handlers never
    // re-implement authorization and module-local routers cannot drift from
    // this table.
    let read = Router::new()
        .route(sekisho_api_protocol::api_paths::ROUTES, get(routes::list))
        .route("/routes/{id}", get(routes::get))
        .route(sekisho_api_protocol::api_paths::IDPS, get(idps::list))
        .route("/idps/{id}", get(idps::get))
        .route(
            sekisho_api_protocol::api_paths::SESSIONS,
            get(sessions::list),
        )
        .route("/sessions/{id}", get(sessions::get))
        .route(sekisho_api_protocol::api_paths::CERTS, get(certs::list))
        .route("/certs/{id}", get(certs::get))
        .route(
            &format!("{}/{{id}}", sekisho_api_protocol::api_paths::CERTS_QUEUE),
            get(certs::queue_status),
        )
        .route(
            sekisho_api_protocol::api_paths::POLICIES,
            get(policies::list),
        )
        .route("/policies/{key}", get(policies::get))
        .route("/acme/leader_election", get(acme::leader_election))
        .route("/_internal/host", get(host_info));
    #[cfg(test)]
    let read = read.route("/_test/admission", get(admission_test_handler));
    let read = read.route_layer(middleware::from_fn_with_state(
        store.clone(),
        scope::require_read,
    ));

    let write = Router::new()
        .route(
            sekisho_api_protocol::api_paths::ROUTES,
            post(routes::create),
        )
        .route("/routes/{id}", patch(routes::update).delete(routes::delete))
        .route(sekisho_api_protocol::api_paths::IDPS, post(idps::create))
        .route("/idps/{id}", patch(idps::update).delete(idps::delete))
        .route("/sessions/{id}", delete(sessions::delete))
        .route(sekisho_api_protocol::api_paths::CERTS, post(certs::issue))
        .route(
            sekisho_api_protocol::api_paths::CERTS_UPLOAD,
            post(certs::upload),
        )
        .route("/certs/{id}", delete(certs::delete))
        .route(
            sekisho_api_protocol::api_paths::POLICIES,
            post(policies::create),
        )
        .route(
            "/policies/{key}",
            patch(policies::update).delete(policies::delete),
        )
        .route_layer(middleware::from_fn_with_state(
            store.clone(),
            scope::require_write,
        ));

    let admin = Router::new()
        .route(
            sekisho_api_protocol::api_paths::API_KEYS,
            get(api_keys::list).post(api_keys::create),
        )
        .route(
            "/api_keys/{id}",
            get(api_keys::get).delete(api_keys::delete),
        )
        .route(
            sekisho_api_protocol::api_paths::ENCRYPTION_KEYS,
            get(encryption_keys::list).post(encryption_keys::add),
        )
        .route(
            "/encryption_keys/{key_id}/activate",
            post(encryption_keys::activate),
        )
        .route(
            "/encryption_keys/{key_id}/retire",
            post(encryption_keys::retire),
        )
        .route("/encryption_keys/rotate", post(encryption_keys::rotate))
        .route(
            "/identity-signing-keys/rotate",
            post(identity_signing::rotate),
        )
        .route(
            sekisho_api_protocol::api_paths::CONFIG,
            get(config::get).patch(config::update),
        )
        .route(
            sekisho_api_protocol::api_paths::INSTANCE,
            get(instance::get).patch(instance::update),
        )
        .route_layer(middleware::from_fn_with_state(
            store.clone(),
            scope::require_admin,
        ));
    let protected = read.merge(write).merge(admin);

    // Ordinary public endpoints (no auth required). `/version` is deliberately
    // unauthenticated so `sekisho-cli` / `sekisho-webui` can negotiate
    // compatibility before they have credentials in hand.
    let metrics_store = store.clone();
    let ordinary_public = Router::new()
        // Prometheus exposition. Unauthenticated within the management
        // plane and never exposed on the proxy port.
        .route(
            sekisho_api_protocol::api_paths::METRICS,
            get(move || {
                let store = metrics_store.clone();
                async move {
                    crate::observability::durable_acme_metrics_handler(
                        store,
                        acme_issuance_concurrency_limit,
                    )
                    .await
                }
            }),
        )
        .route(sekisho_api_protocol::api_paths::VERSION, get(version))
        .route("/auth/verify_jwt", axum::routing::post(verify_jwt))
        .merge(identity_signing::public_router());

    let probes = Router::new()
        .route(sekisho_api_protocol::api_paths::HEALTH, get(health))
        .route(sekisho_api_protocol::api_paths::READY, get(ready))
        // k8s / Docker HEALTHCHECK aliases. Mgmt-port only — see
        // handler doc. Registered on the public (no-auth) subrouter
        // because probes don't authenticate, but the whole mgmt API
        // Router itself is only bound to 127.0.0.1:9443 (+ the
        // configured mgmt bind), so "public" here means
        // "unauthenticated within the mgmt plane", not "exposed on
        // the proxy port".
        .route(sekisho_api_protocol::api_paths::HEALTHZ, get(healthz))
        .route(sekisho_api_protocol::api_paths::READYZ, get(readyz));
    let probes = probes
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .route_layer(middleware::from_fn_with_state(
            AdmissionBudget::rejecting(
                probe_budget,
                "probe budget exhausted",
                crate::observability::ControlBudget::Probe,
                crate::observability::RejectedControlBudget::Probe,
            ),
            admission_middleware,
        ));

    let challenge = Router::new().route("/auth/challenge", axum::routing::post(challenge));
    let challenge = challenge
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .route_layer(middleware::from_fn_with_state(
            AdmissionBudget::rejecting(
                challenge_budget,
                "challenge budget exhausted",
                crate::observability::ControlBudget::Challenge,
                crate::observability::RejectedControlBudget::Challenge,
            ),
            admission_middleware,
        ));

    crate::observability::record_control_budget_limit(
        crate::observability::ControlBudget::Management,
        management_budget.available_permits(),
    );
    let ordinary = protected
        .merge(ordinary_public)
        // Preserve the management plane's existing body limit and Tower
        // concurrency authority for every route not isolated above.
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .route_layer(
            tower::ServiceBuilder::new()
                .layer(tower::limit::GlobalConcurrencyLimitLayer::with_semaphore(
                    management_budget,
                ))
                .layer(middleware::from_fn(observe_management_admission)),
        );

    Router::new()
        .nest("/.sekisho/api/v1", ordinary.merge(probes).merge(challenge))
        .layer(Extension(route_generation))
        .layer(Extension(challenge_store))
        .layer(Extension(shutdown_ctl))
        // Per-request correlation id. Outermost layer so the id is
        // injected before any other middleware (auth, body-limit) can
        // log against it. Echoes back as `X-Request-ID`.
        .layer(middleware::from_fn(crate::audit::request_id_middleware))
        .with_state(state)
}

async fn admission_middleware(
    State(budget): State<AdmissionBudget>,
    request: Request,
    next: Next,
) -> Response {
    let _permit = match budget.acquire().await {
        Ok(permit) => permit,
        Err(error) => return error.into_response(),
    };
    next.run(request).await
}

async fn observe_management_admission(request: Request, next: Next) -> Response {
    let _observation = crate::observability::observe_control_budget(
        crate::observability::ControlBudget::Management,
    );
    next.run(request).await
}

async fn health(#[cfg(test)] gate: Option<Extension<AdmissionTestGate>>) -> impl IntoResponse {
    #[cfg(test)]
    if let Some(Extension(gate)) = gate {
        gate.wait_in_handler().await;
    }
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn challenge(
    Extension(challenge_store): Extension<Arc<local_auth::ChallengeStore>>,
    request: Request,
) -> Response {
    #[cfg(test)]
    if let Some(gate) = request.extensions().get::<AdmissionTestGate>().cloned() {
        gate.wait_in_handler().await;
    }
    local_auth::challenge(Extension(challenge_store), request)
        .await
        .into_response()
}

/// Readiness probe: distinguishes "daemon listening" from "daemon
/// fully operational". Returns 503 when the service DB was configured
/// but unreachable at startup (degraded mode). Used by load balancers
/// to drain HA nodes that can't reach Postgres while still letting
/// operators hit `/instance` on the same process to correct the DSN.
async fn ready(State(state): State<AppState>) -> Response {
    if state.store.is_service_backend_available() {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "status": "ready" })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "degraded",
                "reason": "service database unreachable",
            })),
        )
            .into_response()
    }
}

/// Kubernetes / Docker HEALTHCHECK-style liveness probe.
///
/// Semantics match `/health`: the answer is always 200, no DB
/// dependency, no shutdown-flag check. Liveness is "the process is
/// running and the event loop is not wedged" — a probe that fails
/// here tells the orchestrator to kill the container, which is a
/// bigger hammer than what `/readyz` controls. Deliberately terse
/// body (`{status:"ok"}`) and no audit log: k8s hits this every few
/// seconds and logging each one would drown the audit stream.
async fn healthz() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

/// Kubernetes / Docker HEALTHCHECK-style readiness probe.
///
/// Returns 200 + `{status:"ready"}` only when all four conditions hold:
///
///   1. service DB was reachable at boot *and* answers a live
///      `SELECT 1` round-trip right now,
///   2. route generation has published a usable route snapshot,
///   3. `CertResolver` has atomically published an empty snapshot or has
///      at least one currently usable proxy certificate,
///   4. the daemon has not started graceful shutdown.
///
/// On any failure returns 503 + `{status:"not_ready"}`. The body
/// deliberately does not name the failing subsystem: high-frequency
/// probe polling is a fingerprinting vector, and a load balancer only
/// needs the binary 200 / 503. Operators diagnosing a stuck 503 should
/// consult logs / metrics / `/ready`, not this probe.
///
/// Shutdown handling flips the flag before the listeners actually
/// close so external load balancers can drain this node before
/// in-flight requests start getting ECONNRESET.
async fn readyz(
    State(state): State<AppState>,
    Extension(shutdown_ctl): Extension<Arc<crate::shutdown::ShutdownController>>,
    Extension(route_generation): Extension<Arc<crate::route_generation::RouteGeneration>>,
) -> Response {
    // Ordering: cheapest check first. A shutdown-flipped node stays
    // 503 regardless of DB / cert state, and we avoid a pointless
    // round-trip for every probe during drain.
    if shutdown_ctl.is_shutting_down() {
        return not_ready();
    }
    if !state.store.is_service_backend_available() {
        return not_ready();
    }
    if state.store.ping().await.is_err() {
        return not_ready();
    }
    if !route_generation.is_ready() {
        return not_ready();
    }
    if !state.cert_resolver.is_ready() {
        return not_ready();
    }

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "status": "ready" })),
    )
        .into_response()
}

fn not_ready() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({ "status": "not_ready" })),
    )
        .into_response()
}

/// Verify a signed identity assertion (`X-Sekisho-Jwt`).
///
/// Intentionally *public*: the JWT itself is the authentication artifact.
/// A caller without a valid JWT learns nothing but `{valid: false}`. Admin
/// Diagnostic clients can use this without receiving private signing material.
///
/// Request body: `{ "jwt": "...", "expected_aud": "https://app.example.com" }`
/// Response (valid): verified claims plus the verified signing `kid`.
/// Response (invalid): `{ "valid": false, "error": "..." }`
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyJwtRequest {
    jwt: String,
    expected_aud: String,
}

fn invalid_jwt_response() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "valid": false,
        "error": "invalid token",
    }))
}

async fn verify_jwt(
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> impl IntoResponse {
    use jsonwebtoken::{Algorithm, Validation};
    let request: VerifyJwtRequest = match serde_json::from_value(body) {
        Ok(request) => request,
        Err(_) => return invalid_jwt_response(),
    };
    let audience =
        match crate::identity::validate_route(crate::models::route::SignedIdentityRouteInput {
            enabled: true,
            from: &request.expected_aud,
            redirect: false,
        }) {
            Ok(Some(audience)) => audience,
            _ => return invalid_jwt_response(),
        };
    let issuer = match state.identity_authority.auth_origin() {
        Ok(issuer) => issuer,
        Err(_) => return invalid_jwt_response(),
    };
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[audience.as_str()]);
    validation.set_issuer(&[issuer.as_str()]);
    validation.validate_aud = true;
    validation.validate_nbf = true;
    validation.required_spec_claims = ["sub", "email", "iss", "aud", "iat", "nbf", "exp"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    match state
        .identity_key_ring()
        .verify::<crate::identity::SignedIdentityClaims>(
            &request.jwt,
            &validation,
            chrono::Utc::now().timestamp(),
        ) {
        Ok(data) => {
            let Some(kid) = data.header.kid else {
                return invalid_jwt_response();
            };
            axum::Json(serde_json::json!({
                "valid": true,
                "iss": data.claims.iss,
                "aud": data.claims.aud,
                "sub": data.claims.sub,
                "email": data.claims.email,
                "groups": data.claims.groups,
                "iat": data.claims.iat,
                "nbf": data.claims.nbf,
                "exp": data.claims.exp,
                "kid": kid,
            }))
        }
        Err(_) => invalid_jwt_response(),
    }
}

/// Return the server's OS hostname. Used by `sekisho-cli` so its prompt
/// (`sekisho@<host>>`) identifies which Sekisho daemon it's pointed at —
/// especially useful for operators who run `sekisho-cli` from their
/// workstation against multiple jump hosts. Protected by the standard
/// auth middleware: anyone reachable here is already an admin, and
/// hostnames aren't a secret anyway.
async fn host_info() -> impl IntoResponse {
    let hostname = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".into());
    axum::Json(serde_json::json!({ "hostname": hostname }))
}

/// Return the server's crate version. Clients call this at startup
/// to refuse connecting to a mismatched server — in the version-locked
/// model, the server owns data and integrity while the client owns
/// the domain semantics, so the pair must ship together. Unauthenticated
/// on purpose: the version is not a secret and clients need it before
/// they have credentials.
async fn version() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": env!("CARGO_PKG_NAME"),
    }))
}

#[cfg(test)]
async fn admission_test_handler(
    Extension(gate): Extension<AdmissionTestGate>,
) -> impl IntoResponse {
    gate.wait_in_handler().await;
    axum::Json(serde_json::json!({ "algorithm": "EdDSA" }))
}

/// Custom JSON extractor that returns a sanitized error message
/// instead of leaking serde deserialization details.
pub struct SanitizedJson<T>(pub T);

impl<S, T> axum::extract::FromRequest<S> for SanitizedJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    fn from_request(
        req: Request,
        state: &S,
    ) -> impl std::future::Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        let fut = axum::Json::<T>::from_request(req, state);
        async {
            match fut.await {
                Ok(axum::Json(value)) => Ok(SanitizedJson(value)),
                Err(rejection) => {
                    let status = match &rejection {
                        JsonRejection::JsonDataError(_) => StatusCode::UNPROCESSABLE_ENTITY,
                        JsonRejection::JsonSyntaxError(_) => StatusCode::BAD_REQUEST,
                        JsonRejection::MissingJsonContentType(_) => {
                            StatusCode::UNSUPPORTED_MEDIA_TYPE
                        }
                        JsonRejection::BytesRejection(_) => StatusCode::PAYLOAD_TOO_LARGE,
                        _ => StatusCode::BAD_REQUEST,
                    };

                    tracing::debug!(error = %rejection, "JSON parse error");

                    let message = match &rejection {
                        JsonRejection::JsonSyntaxError(_) => "invalid JSON syntax",
                        JsonRejection::MissingJsonContentType(_) => {
                            "Content-Type must be application/json"
                        }
                        JsonRejection::BytesRejection(_) => "request body too large",
                        _ => "invalid request body",
                    };

                    Err(
                        (status, axum::Json(serde_json::json!({ "error": message })))
                            .into_response(),
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod endpoint_tests {
    //! End-to-end tests for the management API router.
    //!
    //! We drive the built `Router` through `tower::ServiceExt::oneshot`
    //! rather than calling the handlers directly: that exercises the
    //! same route-matching, state-binding, middleware ordering, and
    //! public/protected split a real client sees.
    //!
    //! Coverage:
    //! - Liveness / readiness / metrics: `healthz`, `readyz`, `metrics`
    //!   (live-bound assertions including 503 on degraded service DB and
    //!   the invariant that probe paths never leak onto the proxy router).
    //! - Auth middleware: 401 on missing / invalid Authorization header.
    //! - Body / validation rejections: 400 / 422 on malformed JSON and
    //!   schema-valid-but-domain-invalid payloads.
    //! - Resource CRUD round-trip: create → list → get → patch → delete
    //!   exercised over HTTP with an authenticated API-key bearer, so a
    //!   regression that loses the middleware on a protected route shows
    //!   up here.
    use super::*;
    use crate::models::api_key::ApiKeyScopeSet;
    use crate::models::idp::{IdentityProvider, IdpType, OidcConfig, SamlConfig};
    use crate::store::Store;
    use crate::tls::acme::AcmeManager;
    use crate::tls::acme::challenge::Http01Provider;
    use crate::tls::resolver::CertResolver;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn mk_cert_and_key_pem(domain: &str) -> (String, String) {
        let params = rcgen::CertificateParams::new(vec![domain.into()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    async fn build_state(store: Store) -> (AppState, Arc<CertResolver>) {
        let master_key = MasterKey::from_test_bytes([7u8; 32]);
        let identity_key_ring = IdentityKeyRingSnapshot::from_test_bytes([9u8; 32]);

        let http01 = Arc::new(Http01Provider::new(store.clone()));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            http01,
            "https://acme.invalid/directory",
            None,
        ));

        let cert_resolver = Arc::new(CertResolver::new(store.clone()));

        let state = AppState {
            store,
            acme,
            cert_resolver: cert_resolver.clone(),
            master_key,
            identity_authority: Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            jwt_signing_key: identity_key_ring,
        };
        (state, cert_resolver)
    }

    async fn verify_identity_json(state: AppState, body: serde_json::Value) -> serde_json::Value {
        let response = verify_jwt(State(state), axum::Json(body))
            .await
            .into_response();
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn identity_handlers_share_owner_and_verify_eddsa() {
        let store = Store::new_for_test("sqlite::memory:", [0x18; 32], None)
            .await
            .unwrap();
        let (state, _) = build_state(store).await;
        let cloned = state.clone();
        assert!(Arc::ptr_eq(&state.jwt_signing_key, &cloned.jwt_signing_key));

        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": "alice@example.com",
            "email": "alice@example.com",
            "groups": ["admins"],
            "iss": "https://auth.example.com",
            "aud": "https://app.example.com",
            "iat": now,
            "nbf": now,
            "exp": now + 60,
        });
        let kid = state.jwt_signing_key.current_kid();
        let token = state
            .jwt_signing_key
            .sign(&claims)
            .expect("sign fixture JWT");
        let verify_json = verify_identity_json(
            state,
            serde_json::json!({
                "jwt": token,
                "expected_aud": "https://app.example.com",
            }),
        )
        .await;
        assert_eq!(verify_json["valid"], true);
        assert_eq!(verify_json["iss"], "https://auth.example.com");
        assert_eq!(verify_json["aud"], "https://app.example.com");
        assert_eq!(verify_json["sub"], "alice@example.com");
        assert_eq!(verify_json["email"], "alice@example.com");
        assert_eq!(verify_json["groups"], serde_json::json!(["admins"]));
        assert_eq!(verify_json["iat"], now);
        assert_eq!(verify_json["nbf"], now);
        assert_eq!(verify_json["exp"], now + 60);
        assert_eq!(verify_json["kid"], kid);
    }

    #[tokio::test]
    async fn public_identity_verifier_binds_boot_issuer_and_canonical_expected_audience() {
        let store = Store::new_for_test("sqlite::memory:", [0x19; 32], None)
            .await
            .unwrap();
        let (state, _) = build_state(store).await;
        let now = chrono::Utc::now().timestamp();
        let sign = |aud: &str, iss: &str| {
            state
                .jwt_signing_key
                .sign(&serde_json::json!({
                    "sub": "alice@example.com",
                    "email": "alice@example.com",
                    "groups": ["admins"],
                    "iss": iss,
                    "aud": aud,
                    "iat": now,
                    "nbf": now,
                    "exp": now + 60,
                }))
                .unwrap()
        };
        let valid_token = sign("https://app.example.com", "https://auth.example.com");
        let wrong_issuer = sign("https://app.example.com", "https://other-auth.example.com");
        let wrong_token_audience =
            sign("https://other-app.example.com", "https://auth.example.com");
        let invalid = serde_json::json!({
            "valid": false,
            "error": "invalid token",
        });
        let bodies = [
            serde_json::json!({ "jwt": valid_token }),
            serde_json::json!({
                "jwt": valid_token,
                "expected_aud": "https://app.example.com/",
            }),
            serde_json::json!({
                "jwt": valid_token,
                "expected_aud": "https://wrong.example.com",
            }),
            serde_json::json!({
                "jwt": wrong_issuer,
                "expected_aud": "https://app.example.com",
            }),
            serde_json::json!({
                "jwt": wrong_token_audience,
                "expected_aud": "https://app.example.com",
            }),
            serde_json::json!({
                "expected_aud": "https://app.example.com",
            }),
        ];
        for body in bodies {
            assert_eq!(verify_identity_json(state.clone(), body).await, invalid);
        }
    }

    fn mk_router(state: AppState) -> Router {
        mk_router_with_shutdown(state, Arc::new(crate::shutdown::ShutdownController::new()))
    }

    fn mk_router_with_shutdown(
        state: AppState,
        shutdown_ctl: Arc<crate::shutdown::ShutdownController>,
    ) -> Router {
        mk_router_with_challenge(
            state,
            shutdown_ctl,
            Arc::new(local_auth::ChallengeStore::new()),
        )
    }

    fn mk_router_with_challenge(
        state: AppState,
        shutdown_ctl: Arc<crate::shutdown::ShutdownController>,
        challenge_store: Arc<local_auth::ChallengeStore>,
    ) -> Router {
        let route_generation =
            crate::route_generation::RouteGeneration::new_ready_empty_for_test(state.store.clone());
        mk_router_with_generation(state, shutdown_ctl, challenge_store, route_generation)
    }

    fn mk_router_with_generation(
        state: AppState,
        shutdown_ctl: Arc<crate::shutdown::ShutdownController>,
        challenge_store: Arc<local_auth::ChallengeStore>,
        route_generation: Arc<crate::route_generation::RouteGeneration>,
    ) -> Router {
        router(
            state.store.clone(),
            route_generation,
            state.acme.clone(),
            state.cert_resolver.clone(),
            state.master_key,
            state.jwt_signing_key,
            state.identity_authority,
            challenge_store,
            shutdown_ctl,
            crate::models::config::default_acme_issuance_concurrency_limit(),
        )
    }

    fn mk_router_with_admission_budgets(
        state: AppState,
        management_budget: Arc<tokio::sync::Semaphore>,
        probe_budget: Arc<tokio::sync::Semaphore>,
        challenge_budget: Arc<tokio::sync::Semaphore>,
        challenge_store: Arc<local_auth::ChallengeStore>,
    ) -> Router {
        router_with_admission_budgets(
            state.store.clone(),
            crate::route_generation::RouteGeneration::new_ready_empty_for_test(state.store.clone()),
            state.acme.clone(),
            state.cert_resolver.clone(),
            state.master_key,
            state.jwt_signing_key,
            state.identity_authority,
            challenge_store,
            Arc::new(crate::shutdown::ShutdownController::new()),
            crate::models::config::default_acme_issuance_concurrency_limit(),
            management_budget,
            probe_budget,
            challenge_budget,
        )
    }

    async fn request(router: Router, method: axum::http::Method, path: &str) -> Response {
        router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
    }

    fn gated_request(
        method: axum::http::Method,
        path: &str,
        gate: AdmissionTestGate,
        bearer: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request.extensions_mut().insert(gate);
        request
    }

    async fn assert_admission_lifetime(
        router: Router,
        budget: Arc<Semaphore>,
        method: axum::http::Method,
        path: &str,
    ) {
        let completion_gate = AdmissionTestGate::new();
        let completion_task = tokio::spawn(router.clone().oneshot(gated_request(
            method.clone(),
            path,
            completion_gate.clone(),
            None,
        )));
        completion_gate.wait_for_entries(1).await;
        assert_eq!(budget.available_permits(), 0);
        completion_gate.release();
        assert_eq!(
            completion_task.await.unwrap().unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(budget.available_permits(), 1);

        let cancellation_gate = AdmissionTestGate::new();
        let cancellation_task = tokio::spawn(router.oneshot(gated_request(
            method,
            path,
            cancellation_gate.clone(),
            None,
        )));
        cancellation_gate.wait_for_entries(1).await;
        assert_eq!(budget.available_permits(), 0);
        cancellation_task.abort();
        assert!(cancellation_task.await.unwrap_err().is_cancelled());
        assert_eq!(budget.available_permits(), 1);
    }

    fn metric_sample(rendered: &str, name: &str, budget: &str) -> Option<f64> {
        rendered.lines().find_map(|line| {
            let prefix = format!("{name}{{budget=\"{budget}\"}} ");
            line.strip_prefix(&prefix)?.parse().ok()
        })
    }

    #[test]
    fn management_admission_limits_are_fixed() {
        assert_eq!(MANAGEMENT_CONCURRENCY_LIMIT, 50);
        assert_eq!(PROBE_CONCURRENCY_LIMIT, 4);
        assert_eq!(CHALLENGE_CONCURRENCY_LIMIT, 20);
    }

    #[tokio::test]
    async fn shared_admission_holds_probe_and_challenge_until_response_or_cancel() {
        let store = Store::new_for_test_degraded("admission-isolation")
            .await
            .unwrap();
        let (state, _) = build_state(store).await;
        let management_budget = Arc::new(Semaphore::new(MANAGEMENT_CONCURRENCY_LIMIT));
        let probe_budget = Arc::new(Semaphore::new(1));
        let challenge_budget = Arc::new(Semaphore::new(1));
        assert!(!Arc::ptr_eq(&probe_budget, &challenge_budget));
        let router = mk_router_with_admission_budgets(
            state,
            management_budget,
            probe_budget.clone(),
            challenge_budget.clone(),
            Arc::new(local_auth::ChallengeStore::new()),
        );

        assert_admission_lifetime(
            router.clone(),
            probe_budget,
            axum::http::Method::GET,
            "/.sekisho/api/v1/health",
        )
        .await;
        assert_admission_lifetime(
            router,
            challenge_budget,
            axum::http::Method::POST,
            "/.sekisho/api/v1/auth/challenge",
        )
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admission_metrics_follow_actual_probe_and_challenge_lifetimes() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _recorder_guard = metrics::set_default_local_recorder(&recorder);
        crate::observability::seed_control_budget_metrics_for_test();

        let store = Store::new_for_test_degraded("admission-metrics")
            .await
            .unwrap();
        let (state, _) = build_state(store).await;
        let management_budget = Arc::new(Semaphore::new(MANAGEMENT_CONCURRENCY_LIMIT));
        let probe_budget = Arc::new(Semaphore::new(1));
        let challenge_budget = Arc::new(Semaphore::new(1));
        let router = mk_router_with_admission_budgets(
            state,
            management_budget,
            probe_budget,
            challenge_budget.clone(),
            Arc::new(local_auth::ChallengeStore::new()),
        );

        let initial = handle.render();
        assert_eq!(
            metric_sample(&initial, "sekisho_control_budget_limit", "management"),
            Some(MANAGEMENT_CONCURRENCY_LIMIT as f64)
        );
        assert_eq!(
            metric_sample(&initial, "sekisho_control_budget_limit", "probe"),
            Some(1.0)
        );
        assert_eq!(
            metric_sample(&initial, "sekisho_control_budget_limit", "challenge"),
            Some(1.0)
        );

        let gate = AdmissionTestGate::new();
        let probe = tokio::spawn(router.clone().oneshot(gated_request(
            axum::http::Method::GET,
            "/.sekisho/api/v1/health",
            gate.clone(),
            None,
        )));
        gate.wait_for_entries(1).await;
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "probe"
            ),
            Some(1.0)
        );
        gate.release();
        assert_eq!(probe.await.unwrap().unwrap().status(), StatusCode::OK);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "probe"
            ),
            Some(0.0)
        );

        let cancellation_gate = AdmissionTestGate::new();
        let cancelled = tokio::spawn(router.clone().oneshot(gated_request(
            axum::http::Method::GET,
            "/.sekisho/api/v1/health",
            cancellation_gate.clone(),
            None,
        )));
        cancellation_gate.wait_for_entries(1).await;
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "probe"
            ),
            Some(1.0)
        );
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "probe"
            ),
            Some(0.0)
        );

        let held = challenge_budget.try_acquire_owned().unwrap();
        let response = request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/auth/challenge",
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_rejected_total",
                "challenge"
            ),
            Some(1.0)
        );
        drop(held);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_budget_admits_fifty_protected_json_handlers_and_queues_next() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _recorder_guard = metrics::set_default_local_recorder(&recorder);
        crate::observability::seed_control_budget_metrics_for_test();

        let store = Store::new_for_test("sqlite::memory:", [0x24; 32], None)
            .await
            .unwrap();
        let api_key = store
            .create_api_key("admission-limit", &ApiKeyScopeSet::admin())
            .await
            .unwrap();
        let (state, _) = build_state(store).await;
        let management_budget = Arc::new(Semaphore::new(MANAGEMENT_CONCURRENCY_LIMIT));
        let router = mk_router_with_admission_budgets(
            state,
            management_budget.clone(),
            Arc::new(Semaphore::new(PROBE_CONCURRENCY_LIMIT)),
            Arc::new(Semaphore::new(CHALLENGE_CONCURRENCY_LIMIT)),
            Arc::new(local_auth::ChallengeStore::new()),
        );

        let admitted_gate = AdmissionTestGate::new();
        let mut admitted = Vec::with_capacity(MANAGEMENT_CONCURRENCY_LIMIT);
        for _ in 0..MANAGEMENT_CONCURRENCY_LIMIT {
            admitted.push(tokio::spawn(router.clone().oneshot(gated_request(
                axum::http::Method::GET,
                "/.sekisho/api/v1/_test/admission",
                admitted_gate.clone(),
                Some(&api_key.key),
            ))));
        }
        admitted_gate
            .wait_for_entries(MANAGEMENT_CONCURRENCY_LIMIT as u32)
            .await;
        assert_eq!(management_budget.available_permits(), 0);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "management"
            ),
            Some(MANAGEMENT_CONCURRENCY_LIMIT as f64)
        );

        let queued_gate = AdmissionTestGate::new();
        let queued = tokio::spawn(router.clone().oneshot(gated_request(
            axum::http::Method::GET,
            "/.sekisho/api/v1/_test/admission",
            queued_gate.clone(),
            Some(&api_key.key),
        )));
        tokio::task::yield_now().await;
        assert_eq!(queued_gate.entered.available_permits(), 0);
        assert_eq!(management_budget.available_permits(), 0);
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "management"
            ),
            Some(MANAGEMENT_CONCURRENCY_LIMIT as f64),
            "Tower-queued request must not be observed as admitted"
        );
        assert_eq!(
            request(router, axum::http::Method::GET, "/.sekisho/api/v1/health",)
                .await
                .status(),
            StatusCode::OK,
            "ordinary saturation leaked into the probe budget"
        );

        admitted_gate.release();
        queued_gate.wait_for_entries(1).await;
        queued_gate.release();
        for task in admitted {
            let response = task.await.unwrap().unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response_json(response).await["algorithm"], "EdDSA");
        }
        let response = queued.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["algorithm"], "EdDSA");
        assert_eq!(
            management_budget.available_permits(),
            MANAGEMENT_CONCURRENCY_LIMIT
        );
        assert_eq!(
            metric_sample(
                &handle.render(),
                "sekisho_control_budget_in_flight",
                "management"
            ),
            Some(0.0)
        );
    }

    #[tokio::test]
    async fn rejected_challenge_never_reaches_rate_or_nonce_handler() {
        let store = Store::new_for_test_degraded("challenge-admission")
            .await
            .unwrap();
        let (state, _) = build_state(store).await;
        let challenge_store = Arc::new(local_auth::ChallengeStore::new());
        let challenge_budget = Arc::new(Semaphore::new(1));
        let router = mk_router_with_admission_budgets(
            state,
            Arc::new(Semaphore::new(MANAGEMENT_CONCURRENCY_LIMIT)),
            Arc::new(Semaphore::new(PROBE_CONCURRENCY_LIMIT)),
            challenge_budget.clone(),
            challenge_store,
        );

        let held = challenge_budget.clone().try_acquire_owned().unwrap();
        let rejected_gate = AdmissionTestGate::new();
        let rejected = tokio::spawn(router.clone().oneshot(gated_request(
            axum::http::Method::POST,
            "/.sekisho/api/v1/auth/challenge",
            rejected_gate.clone(),
            None,
        )));
        let response = rejected.await.unwrap().unwrap();
        assert_eq!(rejected_gate.entered.available_permits(), 0);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .is_none()
        );
        let body = response_json(response).await;
        assert!(body.get("nonce").is_none());
        assert_eq!(
            body,
            serde_json::json!({
                "error": {
                    "code": "SERVICE_UNAVAILABLE",
                    "message": "service unavailable"
                }
            })
        );

        drop(held);
        let accepted_gate = AdmissionTestGate::new();
        let accepted = tokio::spawn(router.oneshot(gated_request(
            axum::http::Method::POST,
            "/.sekisho/api/v1/auth/challenge",
            accepted_gate.clone(),
            None,
        )));
        accepted_gate.wait_for_entries(1).await;
        accepted_gate.release();
        let accepted = accepted.await.unwrap().unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        assert!(response_json(accepted).await["nonce"].is_string());
    }

    async fn get(router: Router, path: &str) -> (StatusCode, serde_json::Value) {
        let resp = router
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    #[tokio::test]
    async fn healthz_returns_200_without_auth_or_db() {
        // Degraded store: service backend unreachable. `/healthz`
        // must still flip to 200 — that's the whole liveness contract.
        let store = Store::new_for_test_degraded("test").await.unwrap();
        let (state, _) = build_state(store).await;
        let router = mk_router(state);

        let (status, body) = get(router, "/.sekisho/api/v1/healthz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn readyz_503_when_service_db_unreachable() {
        let store = Store::new_for_test_degraded("boot-time-unreachable")
            .await
            .unwrap();
        let (state, _) = build_state(store).await;
        let router = mk_router(state);

        let (status, body) = get(router, "/.sekisho/api/v1/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "not_ready");
    }

    #[tokio::test]
    async fn readyz_503_after_route_observation_error_while_store_remains_reachable() {
        let store = Store::new_for_test("sqlite::memory:", [57u8; 32], None)
            .await
            .unwrap();
        let (state, cert_resolver) = build_state(store.clone()).await;
        cert_resolver.reload().await.unwrap();
        let route_generation = crate::route_generation::RouteGeneration::new_for_test(store).await;
        route_generation.database_error_for_test();
        let router = mk_router_with_generation(
            state,
            Arc::new(crate::shutdown::ShutdownController::new()),
            Arc::new(local_auth::ChallengeStore::new()),
            route_generation,
        );

        let (status, body) = get(router, "/.sekisho/api/v1/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "not_ready");
    }

    #[tokio::test]
    async fn readyz_503_until_cert_resolver_initial_load() {
        // Service DB healthy, but cert resolver has never reloaded:
        // the fallback-only state is "not ready" from an operator POV.
        let store = Store::new_for_test("sqlite::memory:", [5u8; 32], None)
            .await
            .unwrap();
        let (state, cert_resolver) = build_state(store).await;
        let router = mk_router(state);

        // Before reload: cert resolver not ready → 503.
        let (status, _) = get(router.clone(), "/.sekisho/api/v1/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        // After reload (empty certs table is fine — the flag flips
        // after the first successful list, regardless of count).
        cert_resolver.reload().await.unwrap();
        assert!(cert_resolver.is_ready());
        let (status, body) = get(router, "/.sekisho/api/v1/readyz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
    }

    #[tokio::test]
    async fn readyz_503_after_nonempty_reload_with_no_usable_certificate() {
        let store = Store::new_for_test("sqlite::memory:", [0x5a; 32], None)
            .await
            .unwrap();
        let (cert_pem, plaintext_key) = mk_cert_and_key_pem("invalid-only.example.com");
        store
            .upsert_cert(&crate::models::cert::Certificate {
                id: uuid::Uuid::new_v4(),
                domain: "invalid-only.example.com".into(),
                cert_pem,
                key_pem_encrypted: plaintext_key,
                issued_at: chrono::Utc::now() - chrono::Duration::days(1),
                expires_at: chrono::Utc::now() + chrono::Duration::days(1),
                source: crate::models::cert::CertSource::Upload,
            })
            .await
            .unwrap();
        let (state, cert_resolver) = build_state(store).await;
        cert_resolver.reload().await.unwrap();
        let router = mk_router(state);

        let (status, body) = get(router, "/.sekisho/api/v1/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "not_ready");
    }

    #[tokio::test]
    async fn readyz_503_when_shutting_down() {
        let store = Store::new_for_test("sqlite::memory:", [6u8; 32], None)
            .await
            .unwrap();
        let (state, cert_resolver) = build_state(store).await;
        cert_resolver.reload().await.unwrap();
        let shutdown_ctl = Arc::new(crate::shutdown::ShutdownController::new());
        let router = mk_router_with_shutdown(state, shutdown_ctl.clone());
        shutdown_ctl.signal();

        let (status, body) = get(router, "/.sekisho/api/v1/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "not_ready");
    }

    #[tokio::test]
    async fn readyz_does_not_require_auth() {
        // No Authorization header: must still get a 2xx / 5xx probe
        // answer rather than a 401. `get()` above sends no auth header,
        // so just asserting `!= UNAUTHORIZED` exercises the invariant.
        let store = Store::new_for_test("sqlite::memory:", [8u8; 32], None)
            .await
            .unwrap();
        let (state, cert_resolver) = build_state(store).await;
        cert_resolver.reload().await.unwrap();
        let router = mk_router(state);

        let (status, _) = get(router, "/.sekisho/api/v1/readyz").await;
        assert_ne!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn public_proxy_router_does_not_expose_healthz_or_readyz() {
        // Core security invariant: probes live on the mgmt port, never
        // the public proxy port. If a future refactor accidentally
        // merges them the public proxy router must still 404 on these.
        use crate::proxy;

        let store = Store::new_for_test("sqlite::memory:", [3u8; 32], None)
            .await
            .unwrap();
        let cookie_secret = [0u8; 64];
        let master_key = MasterKey::from_test_bytes([4u8; 32]);
        let identity_key_ring = IdentityKeyRingSnapshot::from_test_bytes([2u8; 32]);

        let http01 = Arc::new(Http01Provider::new(store.clone()));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            http01,
            "https://acme.invalid/directory",
            None,
        ));

        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;

        let proxy_app = proxy::router(
            store,
            route_generation,
            &cookie_secret,
            acme,
            master_key,
            identity_key_ring,
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            100,
            Arc::new(crate::shutdown::ShutdownController::new()),
        );

        for path in [
            "/healthz",
            "/readyz",
            "/metrics",
            "/.sekisho/api/v1/healthz",
            "/.sekisho/api/v1/readyz",
            "/.sekisho/api/v1/metrics",
        ] {
            let (status, _) = get(proxy_app.clone(), path).await;
            // Anything except 200 is acceptable — what we must NOT
            // have is a 2xx that leaks readiness state. In practice
            // the proxy answers these with 502 (no matching route)
            // or a redirect; assert non-200 to stay robust against
            // small proxy-side behaviour changes.
            assert_ne!(
                status,
                StatusCode::OK,
                "probe path leaked onto proxy router: {path}"
            );
        }
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_prometheus_exposition() {
        // The recorder is a process-global, so this test calls
        // init_metrics() unconditionally — the OnceLock inside makes
        // a second install a no-op, and other tests in this binary
        // are allowed to do the same.
        crate::observability::init_metrics();
        // Touch a counter so the exposition body is non-empty even on
        // a fresh process where nothing else has emitted yet.
        metrics::counter!("sekisho_test_metric_seed").increment(1);

        let store = Store::new_for_test("sqlite::memory:", [11u8; 32], None)
            .await
            .unwrap();
        let (state, _) = build_state(store.clone()).await;
        let router = mk_router(state);
        store
            .update_config(serde_json::json!({
                "acme_queue_capacity": 17,
                "acme_issuance_concurrency_limit": 2
            }))
            .await
            .unwrap();

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/.sekisho/api/v1/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.starts_with("text/plain"),
            "expected text/plain exposition, got {content_type}"
        );
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(
            body_str.contains("sekisho_test_metric_seed"),
            "exposition body should contain emitted metrics; got: {body_str}"
        );
        for expected in [
            "sekisho_acme_queue_active 0",
            "sekisho_acme_queue_capacity 17",
            "sekisho_acme_issuance_in_progress 0",
            "sekisho_acme_issuance_limit 5",
        ] {
            assert!(
                body_str.lines().any(|line| line == expected),
                "missing durable metric sample {expected}: {body_str}"
            );
        }
        assert!(
            !body_str
                .lines()
                .any(|line| line == "sekisho_acme_issuance_limit 2"),
            "the target-local startup limit must not follow live config: {body_str}"
        );
        for name in [
            "sekisho_acme_queue_active",
            "sekisho_acme_queue_capacity",
            "sekisho_acme_issuance_in_progress",
            "sekisho_acme_issuance_limit",
        ] {
            assert_eq!(
                body_str
                    .lines()
                    .filter(|line| line.starts_with(&format!("# HELP {name} ")))
                    .count(),
                1
            );
            assert_eq!(
                body_str
                    .lines()
                    .filter(|line| *line == format!("# TYPE {name} gauge"))
                    .count(),
                1
            );
        }
    }

    #[tokio::test]
    async fn metrics_endpoint_does_not_require_auth() {
        // Same posture as healthz/readyz: the mgmt port is loopback-bound,
        // and a local Prometheus agent should be able to scrape without
        // negotiating an API key.
        crate::observability::init_metrics();
        let store = Store::new_for_test("sqlite::memory:", [12u8; 32], None)
            .await
            .unwrap();
        let (state, _) = build_state(store).await;
        let router = mk_router(state);

        let (status, _) = get(router, "/.sekisho/api/v1/metrics").await;
        assert_ne!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(status, StatusCode::FORBIDDEN);
    }

    // ─── Auth / body / validation rejections + CRUD round-trip ────────
    //
    // These exercise the protected sub-router end-to-end so a regression
    // that drops `auth_middleware` from a route, mangles the
    // `SanitizedJson` extractor, or misclassifies validation errors
    // shows up at the HTTP layer instead of only at the handler unit-test
    // level. The CRUD round-trip below specifically guards against a
    // future refactor that loses the bearer-token requirement on
    // `routes::create` / `routes::list` without anyone noticing.

    /// Send a request through the router, returning status, headers, and
    /// parsed-or-empty JSON body. Used by the rejection tests below; the
    /// existing `get()` helper above is GET-only.
    async fn send_request(
        router: Router,
        method: axum::http::Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let req = builder
            .body(
                body.map(|s| Body::from(s.to_owned()))
                    .unwrap_or(Body::empty()),
            )
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    async fn test_router_with_api_key() -> (Router, String) {
        let (router, key, _) = test_router_store_api_key().await;
        (router, key)
    }

    async fn test_router_store_api_key_with_scopes(
        scopes: &str,
    ) -> (Router, String, uuid::Uuid, Store) {
        let store = Store::new_for_test("sqlite::memory:", [42u8; 32], None)
            .await
            .unwrap();
        let api_key = store
            .create_api_key(
                "test",
                &ApiKeyScopeSet::from_storage(scopes).expect("valid test scopes"),
            )
            .await
            .unwrap();
        let api_key_id = api_key.api_key.id;
        let (state, _) = build_state(store.clone()).await;
        let router = mk_router(state);
        (router, api_key.key, api_key_id, store)
    }

    async fn test_router_store_api_key() -> (Router, String, Store) {
        let (router, key, _, store) =
            test_router_store_api_key_with_scopes(r#"["management:admin"]"#).await;
        (router, key, store)
    }

    #[tokio::test]
    async fn api_key_scope_matrix_is_central_and_hierarchical() {
        for (scope, read_status, write_status, admin_status) in [
            (
                "management:read",
                StatusCode::OK,
                StatusCode::FORBIDDEN,
                StatusCode::FORBIDDEN,
            ),
            (
                "management:write",
                StatusCode::OK,
                StatusCode::NOT_FOUND,
                StatusCode::FORBIDDEN,
            ),
            (
                "management:admin",
                StatusCode::OK,
                StatusCode::NOT_FOUND,
                StatusCode::OK,
            ),
        ] {
            let scopes = format!(r#"["{scope}"]"#);
            let (router, key, _, _) = test_router_store_api_key_with_scopes(&scopes).await;

            let (status, _) = send_request(
                router.clone(),
                axum::http::Method::GET,
                "/.sekisho/api/v1/_internal/host",
                Some(&key),
                None,
            )
            .await;
            assert_eq!(status, read_status, "read mapping for {scope}");

            let (status, _) = send_request(
                router.clone(),
                axum::http::Method::DELETE,
                &format!("/.sekisho/api/v1/routes/{}", uuid::Uuid::new_v4()),
                Some(&key),
                None,
            )
            .await;
            assert_eq!(status, write_status, "write mapping for {scope}");

            let (status, _) = send_request(
                router,
                axum::http::Method::GET,
                "/.sekisho/api/v1/api_keys",
                Some(&key),
                None,
            )
            .await;
            assert_eq!(status, admin_status, "admin mapping for {scope}");
        }
    }

    #[tokio::test]
    async fn insufficient_scope_is_fixed_403_with_no_touch_handler_or_resource_mutation() {
        use crate::audit::test_capture::AuditCapture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let (router, key, key_id, store) =
            test_router_store_api_key_with_scopes(r#"["management:read"]"#).await;
        let version_before = store.route_version_current().await.unwrap();

        let (status, body) = send_request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/routes",
            Some(&key),
            Some(r#"{"name":"must-not-run"}"#),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            serde_json::json!({ "error": "insufficient API key scope" })
        );
        assert_eq!(store.route_version_current().await.unwrap(), version_before);
        assert!(store.list_routes().await.unwrap().is_empty());
        assert_eq!(store.get_api_key(key_id).await.unwrap().last_used_at, None);
        let event = capture
            .find("auth.api.scope_denied")
            .expect("bounded scope denial audit event");
        assert_eq!(event.field("required_scope"), Some("management:write"));
        assert_eq!(event.field("reason"), Some("insufficient_scope"));
    }

    #[tokio::test]
    async fn authorized_request_survives_usage_touch_failure() {
        use crate::audit::test_capture::AuditCapture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let (router, key, key_id, store) =
            test_router_store_api_key_with_scopes(r#"["management:read"]"#).await;
        sqlx::query(
            "CREATE TRIGGER reject_api_key_touch BEFORE UPDATE OF last_used_at ON api_keys \
             BEGIN SELECT RAISE(ABORT, 'sensitive injected detail'); END",
        )
        .execute(store.sqlite_pool())
        .await
        .unwrap();

        let (status, _) = send_request(
            router,
            axum::http::Method::GET,
            "/.sekisho/api/v1/routes",
            Some(&key),
            None,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(store.get_api_key(key_id).await.unwrap().last_used_at, None);
        let event = capture
            .find("auth.api_key.usage_touch_failed")
            .expect("bounded touch failure audit event");
        assert_eq!(event.field("reason"), Some("usage_touch_failed"));
        assert!(
            event
                .fields
                .values()
                .all(|value| !value.contains("sensitive injected detail"))
        );
    }

    #[tokio::test]
    async fn api_key_create_rejects_invalid_names_with_fixed_error_and_no_side_effects() {
        use crate::audit::test_capture::AuditCapture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let (router, key, store) = test_router_store_api_key().await;
        let count_before = store.api_key_count().await.unwrap();
        let expected = serde_json::json!({
            "error": {
                "code": "BAD_REQUEST",
                "message": "bad request: api key name must not be empty or exceed 255 bytes",
            }
        });
        let invalid_names = [
            String::new(),
            " \t\n ".to_owned(),
            "a".repeat(256),
            "界".repeat(86),
        ];

        for name in invalid_names {
            let body = serde_json::json!({
                "name": name,
                "scopes": ["management:admin"],
            })
            .to_string();
            let (status, response) = send_request(
                router.clone(),
                axum::http::Method::POST,
                "/.sekisho/api/v1/api_keys",
                Some(&key),
                Some(&body),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(response, expected);
            assert_eq!(store.api_key_count().await.unwrap(), count_before);
        }

        assert!(capture.find("api_key.create").is_none());
    }

    #[tokio::test]
    async fn api_key_create_rejects_missing_empty_duplicate_or_noncanonical_scopes() {
        use crate::audit::test_capture::AuditCapture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let (router, key, store) = test_router_store_api_key().await;
        let count_before = store.api_key_count().await.unwrap();

        for body in [
            serde_json::json!({ "name": "missing" }),
            serde_json::json!({ "name": "empty", "scopes": [] }),
            serde_json::json!({
                "name": "duplicate",
                "scopes": ["management:read", "management:read"],
            }),
            serde_json::json!({ "name": "unknown", "scopes": ["management:owner"] }),
            serde_json::json!({ "name": "noncanonical", "scopes": ["Management:read"] }),
        ] {
            let (status, _) = send_request(
                router.clone(),
                axum::http::Method::POST,
                "/.sekisho/api/v1/api_keys",
                Some(&key),
                Some(&body.to_string()),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body={body}");
            assert_eq!(store.api_key_count().await.unwrap(), count_before);
        }

        assert!(capture.find("api_key.create").is_none());
    }

    #[tokio::test]
    async fn api_key_name_validation_precedes_store_and_secret_generation() {
        let store = Store::new_for_test_degraded("must-not-be-read")
            .await
            .unwrap();
        let error = match api_keys::create(
            State(store),
            Extension(crate::audit::Actor::system()),
            SanitizedJson(crate::models::api_key::CreateApiKey {
                name: " \t ".to_owned(),
                scopes: ApiKeyScopeSet::admin(),
            }),
        )
        .await
        {
            Ok(_) => panic!("invalid API-key name was accepted"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            crate::error::Error::BadRequest(ref message)
                if message == "api key name must not be empty or exceed 255 bytes"
        ));
    }

    #[tokio::test]
    async fn api_key_create_preserves_valid_name_bytes_and_never_audits_secret() {
        use crate::audit::test_capture::AuditCapture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let (router, key, store) = test_router_store_api_key().await;
        let names = ["a".repeat(255), "界".repeat(85), "  ops key\t".to_owned()];
        let mut created = Vec::new();

        for name in &names {
            let body = serde_json::json!({
                "name": name,
                "scopes": ["management:write"],
            })
            .to_string();
            let (status, response) = send_request(
                router.clone(),
                axum::http::Method::POST,
                "/.sekisho/api/v1/api_keys",
                Some(&key),
                Some(&body),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(response["name"], name.as_str());
            assert_eq!(response["scopes"], serde_json::json!(["management:write"]));
            let id = uuid::Uuid::parse_str(response["id"].as_str().unwrap()).unwrap();
            let secret = response["key"].as_str().unwrap().to_owned();
            assert_eq!(store.get_api_key(id).await.unwrap().name, *name);
            created.push((id, secret));
        }

        let stored_names = store
            .list_api_keys()
            .await
            .unwrap()
            .into_iter()
            .map(|api_key| api_key.name)
            .collect::<Vec<_>>();
        for name in &names {
            assert!(stored_names.contains(name));
        }

        let events = capture
            .snapshot()
            .into_iter()
            .filter(|event| event.field("event") == Some("api_key.create"))
            .collect::<Vec<_>>();
        assert_eq!(events.len(), names.len());
        for ((_, secret), event) in created.iter().zip(&events) {
            assert!(
                event.fields.values().all(|value| !value.contains(secret)),
                "audit event leaked full API-key secret"
            );
            assert_eq!(event.field("new_prefix"), Some(&secret[..8]));
        }

        let (delete_id, _) = created.last().unwrap();
        let (status, body) = send_request(
            router,
            axum::http::Method::DELETE,
            &format!("/.sekisho/api/v1/api_keys/{delete_id}"),
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(body, serde_json::Value::Null);
        assert!(matches!(
            store.get_api_key(*delete_id).await,
            Err(crate::error::Error::NotFound)
        ));
    }

    #[tokio::test]
    async fn api_key_name_validation_does_not_hide_existing_rows() {
        let (router, key, store) = test_router_store_api_key().await;
        let legacy_name = " \t ";
        let legacy = store
            .create_api_key(legacy_name, &ApiKeyScopeSet::admin())
            .await
            .unwrap()
            .api_key;

        let (status, body) = send_request(
            router.clone(),
            axum::http::Method::GET,
            &format!("/.sekisho/api/v1/api_keys/{}", legacy.id),
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["name"], legacy_name);

        let (status, body) = send_request(
            router.clone(),
            axum::http::Method::GET,
            "/.sekisho/api/v1/api_keys",
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| { item["id"] == legacy.id.to_string() && item["name"] == legacy_name })
        );

        let (status, body) = send_request(
            router,
            axum::http::Method::DELETE,
            &format!("/.sekisho/api/v1/api_keys/{}", legacy.id),
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(body, serde_json::Value::Null);
        assert!(matches!(
            store.get_api_key(legacy.id).await,
            Err(crate::error::Error::NotFound)
        ));
    }

    #[tokio::test]
    async fn concurrent_sqlite_encryption_key_posts_allocate_distinct_ids() {
        let (router, key, store) = test_router_store_api_key().await;
        let version_before = store.key_ring_version_current().await.unwrap();
        let path = "/.sekisho/api/v1/encryption_keys";

        let (first, second) = tokio::join!(
            send_request(
                router.clone(),
                axum::http::Method::POST,
                path,
                Some(&key),
                None,
            ),
            send_request(router, axum::http::Method::POST, path, Some(&key), None,),
        );

        assert_eq!(
            first.0,
            StatusCode::CREATED,
            "first response: {:?}",
            first.1
        );
        assert_eq!(
            second.0,
            StatusCode::CREATED,
            "second response: {:?}",
            second.1
        );
        let mut ids = [
            first.1["key_id"].as_i64().unwrap(),
            second.1["key_id"].as_i64().unwrap(),
        ];
        ids.sort_unstable();
        assert_eq!(ids, [1, 2]);
        assert_eq!(
            store.key_ring_version_current().await.unwrap(),
            version_before + 2
        );
        let rows = store.master_keys_load_active_set().await.unwrap();
        assert_eq!(rows.iter().filter(|row| !row.active).count(), 2);
    }

    #[tokio::test]
    async fn encryption_key_post_reserves_retired_ids_and_reports_full_ring_safely() {
        let (router, key, store) = test_router_store_api_key().await;
        sqlx::query(
            "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
             VALUES (1, 'retired-reservation', 0, 1)",
        )
        .execute(store.sqlite_pool())
        .await
        .unwrap();

        let (status, body) = send_request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/encryption_keys",
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "response: {body:?}");
        assert_eq!(body["key_id"], 2);

        let (router, key, store) = test_router_store_api_key().await;
        for key_id in 1i64..=255 {
            sqlx::query(
                "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
                 VALUES (?, 'reserved', 0, 1)",
            )
            .bind(key_id)
            .execute(store.sqlite_pool())
            .await
            .unwrap();
        }
        let version_before = store.key_ring_version_current().await.unwrap();
        let (status, body) = send_request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/encryption_keys",
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            serde_json::json!({
                "error": {
                    "code": "CONFIGURATION_ERROR",
                    "message": "service not configured"
                }
            })
        );
        assert_eq!(
            store.key_ring_version_current().await.unwrap(),
            version_before
        );
        let reserved = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM master_keys")
            .fetch_one(store.sqlite_pool())
            .await
            .unwrap();
        assert_eq!(reserved, 256);
    }

    #[tokio::test]
    async fn postgres_concurrent_encryption_key_posts_allocate_distinct_ids() {
        let Ok(base_url) = std::env::var("TEST_POSTGRES_URL") else {
            return;
        };
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let schema = format!(
            "sekisho_p2_8_api_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let root = sqlx::PgPool::connect(&base_url).await.unwrap();
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&root)
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let scoped = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let store_a = Store::new_for_test(
            "sqlite::memory:",
            [42u8; 32],
            Some(&format!("{scoped}&application_name=sekisho_p2_8_a")),
        )
        .await
        .unwrap();
        let store_b = Store::new_for_test(
            "sqlite::memory:",
            [42u8; 32],
            Some(&format!("{scoped}&application_name=sekisho_p2_8_b")),
        )
        .await
        .unwrap();
        let api_key = store_a
            .create_api_key("p2-8-live", &ApiKeyScopeSet::admin())
            .await
            .unwrap()
            .key;
        let (state_a, _) = build_state(store_a.clone()).await;
        let (state_b, _) = build_state(store_b.clone()).await;
        let version_before = store_a.key_ring_version_current().await.unwrap();
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:p2_8_key_alloc");

        let path = "/.sekisho/api/v1/encryption_keys";
        let (first, second) = tokio::join!(
            send_request(
                mk_router(state_a),
                axum::http::Method::POST,
                path,
                Some(&api_key),
                None,
            ),
            send_request(
                mk_router(state_b),
                axum::http::Method::POST,
                path,
                Some(&api_key),
                None,
            ),
        );
        assert_eq!(first.0, StatusCode::CREATED, "node A: {:?}", first.1);
        assert_eq!(second.0, StatusCode::CREATED, "node B: {:?}", second.1);
        let mut ids = [
            first.1["key_id"].as_i64().unwrap(),
            second.1["key_id"].as_i64().unwrap(),
        ];
        ids.sort_unstable();
        assert_eq!(ids, [1, 2]);
        assert_eq!(
            store_a.key_ring_version_current().await.unwrap(),
            version_before + 2
        );

        store_a.close().await;
        store_b.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&root)
            .await
            .unwrap();
        root.close().await;
    }

    enum PageDbControl {
        Sqlite(sqlx::SqlitePool),
        Postgres(sqlx::PgPool),
    }

    async fn management_page_test_routers()
    -> Vec<(&'static str, Router, String, Store, PageDbControl)> {
        let sqlite = Store::new_for_test("sqlite::memory:", [42u8; 32], None)
            .await
            .unwrap();
        let sqlite_key = sqlite
            .create_api_key("page-auth", &ApiKeyScopeSet::admin())
            .await
            .unwrap();
        let sqlite_control = PageDbControl::Sqlite(sqlite.sqlite_pool().clone());
        let (sqlite_state, _) = build_state(sqlite.clone()).await;
        let mut out = vec![(
            "sqlite",
            mk_router(sqlite_state),
            sqlite_key.key,
            sqlite,
            sqlite_control,
        )];

        if let Ok(url) = std::env::var("TEST_POSTGRES_URL") {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let schema = format!(
                "sekisho_api_page_{}_{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let root_pool = sqlx::PgPool::connect(&url).await.unwrap();
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&root_pool)
                .await
                .unwrap();
            drop(root_pool);
            let separator = if url.contains('?') { '&' } else { '?' };
            let scoped_url = format!("{url}{separator}options=-csearch_path%3D{schema}");
            let postgres = Store::new_for_test("sqlite::memory:", [42u8; 32], Some(&scoped_url))
                .await
                .unwrap();
            let postgres_key = postgres
                .create_api_key("page-auth", &ApiKeyScopeSet::admin())
                .await
                .unwrap();
            let postgres_control =
                PageDbControl::Postgres(sqlx::PgPool::connect(&scoped_url).await.unwrap());
            let (postgres_state, _) = build_state(postgres.clone()).await;
            out.push((
                "postgres",
                mk_router(postgres_state),
                postgres_key.key,
                postgres,
                postgres_control,
            ));
        }

        out
    }

    fn management_page_route(id: uuid::Uuid, name: &str) -> crate::models::route::Route {
        let mut route = crate::models::route::CreateRoute {
            name: name.into(),
            from: format!("https://{name}.example"),
            to: vec!["http://upstream.example".into()],
            access: crate::models::route::RouteAccess::default(),
            load_balancing: None,
            preserve_host_header: None,
            timeout_ms: None,
            response_idle_timeout_ms: None,
            enable_websocket: None,
            enable_grpc: None,
            enable_signed_identity: None,
            tls_downstream: None,
            path: None,
            redirect: None,
            idp_id: None,
            host_rewrite: None,
            regex_rewrite_pattern: None,
            regex_rewrite_substitution: None,
            tls_skip_verify: None,
            headers: crate::models::route::HeaderModifications::default(),
            session_cookie_samesite: None,
            response_location_rewrite: None,
            enabled: None,
            concurrency_limit: None,
        }
        .into_route();
        route.id = id;
        route
    }

    async fn seed_management_pages(store: &Store, control: &PageDbControl) {
        for (index, name) in ["alpha", "beta"].iter().enumerate() {
            store
                .create_route(&management_page_route(
                    uuid::Uuid::from_u128(0x100 + index as u128),
                    name,
                ))
                .await
                .unwrap();
            store
                .create_idp(&IdentityProvider {
                    id: uuid::Uuid::from_u128(0x200 + index as u128),
                    name: (*name).into(),
                    idp_type: IdpType::Oidc,
                    oidc_config: Some(OidcConfig {
                        issuer_url: format!("https://{name}.example"),
                        client_id: format!("client-{name}"),
                        client_secret_encrypted: "encrypted".into(),
                        scopes: vec!["openid".into()],
                        prompt: None,
                    }),
                    saml_config: None,
                })
                .await
                .unwrap();
            store
                .create_policy(&crate::models::policy::Policy {
                    id: uuid::Uuid::from_u128(0x300 + index as u128),
                    name: (*name).into(),
                    expr: r#"claim.username == "page@example.com""#.into(),
                })
                .await
                .unwrap();
            store
                .upsert_cert(&crate::models::cert::Certificate {
                    id: uuid::Uuid::from_u128(0x400 + index as u128),
                    domain: format!("{name}.example"),
                    cert_pem: "certificate".into(),
                    key_pem_encrypted: "encrypted-key".into(),
                    issued_at: chrono::Utc::now(),
                    expires_at: chrono::Utc::now() + chrono::Duration::days(30),
                    source: crate::models::cert::CertSource::Upload,
                })
                .await
                .unwrap();
        }

        let poison_id = uuid::Uuid::from_u128(0xffff);
        match control {
            PageDbControl::Sqlite(pool) => {
                for (table, extra_columns, extra_values) in [
                    ("routes", "", ""),
                    ("policies", "", ""),
                    ("identity_providers", ", idp_type", ", 'oidc'"),
                ] {
                    sqlx::query(&format!(
                        "INSERT INTO {table} (id, name{extra_columns}, data) \
                         VALUES (?, 'z-poison'{extra_values}, '{{')"
                    ))
                    .bind(poison_id)
                    .execute(pool)
                    .await
                    .unwrap();
                }
                sqlx::query(
                    "INSERT INTO certificates (id, domain, data, expires_at) \
                     VALUES (?, 'z-poison.example', '{', 2000000000)",
                )
                .bind(poison_id)
                .execute(pool)
                .await
                .unwrap();
                sqlx::query("UPDATE api_keys SET created_at = 1")
                    .execute(pool)
                    .await
                    .unwrap();
                sqlx::query(
                    r#"INSERT INTO api_keys
                       (id, name, prefix, key_hash, scopes, created_at, last_used_at) VALUES
                       (?, 'page-valid', 'page0001', 'page-valid-hash', '["management:admin"]', 2, NULL),
                       (?, 'page-poison', 'page0002', 'page-poison-hash', '["management:admin"]', ?, NULL)"#,
                )
                .bind(uuid::Uuid::from_u128(0xfffd))
                .bind(uuid::Uuid::from_u128(0xfffe))
                .bind(i64::MAX)
                .execute(pool)
                .await
                .unwrap();
            }
            PageDbControl::Postgres(pool) => {
                for (table, extra_columns, extra_values) in [
                    ("routes", "", ""),
                    ("policies", "", ""),
                    ("identity_providers", ", idp_type", ", 'oidc'"),
                ] {
                    sqlx::query(&format!(
                        "INSERT INTO {table} (id, name{extra_columns}, data) \
                         VALUES ($1, 'z-poison'{extra_values}, '{{')"
                    ))
                    .bind(poison_id)
                    .execute(pool)
                    .await
                    .unwrap();
                }
                sqlx::query(
                    "INSERT INTO certificates (id, domain, data, expires_at) \
                     VALUES ($1, 'z-poison.example', '{', 2000000000)",
                )
                .bind(poison_id)
                .execute(pool)
                .await
                .unwrap();
                sqlx::query("UPDATE api_keys SET created_at = 1")
                    .execute(pool)
                    .await
                    .unwrap();
                sqlx::query(
                    r#"INSERT INTO api_keys
                       (id, name, prefix, key_hash, scopes, created_at, last_used_at) VALUES
                       ($1, 'page-valid', 'page0001', 'page-valid-hash', '["management:admin"]', 2, NULL),
                       ($2, 'page-poison', 'page0002', 'page-poison-hash', '["management:admin"]', $3, NULL)"#,
                )
                .bind(uuid::Uuid::from_u128(0xfffd))
                .bind(uuid::Uuid::from_u128(0xfffe))
                .bind(i64::MAX)
                .execute(pool)
                .await
                .unwrap();
            }
        }
    }

    async fn remove_management_page_poison(control: &PageDbControl) {
        let poison_id = uuid::Uuid::from_u128(0xffff);
        let api_key_poison_id = uuid::Uuid::from_u128(0xfffe);
        match control {
            PageDbControl::Sqlite(pool) => {
                for table in ["routes", "policies", "identity_providers", "certificates"] {
                    sqlx::query(&format!("DELETE FROM {table} WHERE id = ?"))
                        .bind(poison_id)
                        .execute(pool)
                        .await
                        .unwrap();
                }
                sqlx::query("DELETE FROM api_keys WHERE id = ?")
                    .bind(api_key_poison_id)
                    .execute(pool)
                    .await
                    .unwrap();
            }
            PageDbControl::Postgres(pool) => {
                for table in ["routes", "policies", "identity_providers", "certificates"] {
                    sqlx::query(&format!("DELETE FROM {table} WHERE id = $1"))
                        .bind(poison_id)
                        .execute(pool)
                        .await
                        .unwrap();
                }
                sqlx::query("DELETE FROM api_keys WHERE id = $1")
                    .bind(api_key_poison_id)
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn management_lists_use_bounded_sql_pages_on_every_backend() {
        let routers = management_page_test_routers().await;
        let expected_backends = if std::env::var_os("TEST_POSTGRES_URL").is_some() {
            2
        } else {
            1
        };
        assert_eq!(
            routers.len(),
            expected_backends,
            "TEST_POSTGRES_URL must execute the Postgres router case"
        );

        for (label, router, key, store, control) in routers {
            seed_management_pages(&store, &control).await;
            for path in ["routes", "idps", "policies", "api_keys", "certs"] {
                let (status, page) = send_request(
                    router.clone(),
                    axum::http::Method::GET,
                    &format!("/.sekisho/api/v1/{path}?limit=1&offset=0"),
                    Some(&key),
                    None,
                )
                .await;
                assert_eq!(status, StatusCode::OK, "[{label}] {path}: {page:?}");
                assert_eq!(
                    page["items"].as_array().unwrap().len(),
                    1,
                    "[{label}] {path}"
                );
                assert_eq!(page["limit"], 1, "[{label}] {path}");
                assert_eq!(page["offset"], 0, "[{label}] {path}");
                assert_eq!(page["has_more"], true, "[{label}] {path}");
            }

            for path in ["routes", "idps", "policies", "certs"] {
                let (status, _) = send_request(
                    router.clone(),
                    axum::http::Method::GET,
                    &format!("/.sekisho/api/v1/{path}?limit=1&offset=1"),
                    Some(&key),
                    None,
                )
                .await;
                assert_eq!(
                    status,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "[{label}] poison inside {path} lookahead must fail"
                );
            }

            remove_management_page_poison(&control).await;
            for path in ["routes", "idps", "policies", "api_keys", "certs"] {
                let (status, terminal) = send_request(
                    router.clone(),
                    axum::http::Method::GET,
                    &format!("/.sekisho/api/v1/{path}?limit=2&offset=0"),
                    Some(&key),
                    None,
                )
                .await;
                assert_eq!(status, StatusCode::OK, "[{label}] {path}: {terminal:?}");
                assert_eq!(
                    terminal["items"].as_array().unwrap().len(),
                    2,
                    "[{label}] exact-terminal {path}"
                );
                assert_eq!(
                    terminal["has_more"], false,
                    "[{label}] exact-terminal {path}"
                );

                let (status, empty) = send_request(
                    router.clone(),
                    axum::http::Method::GET,
                    &format!("/.sekisho/api/v1/{path}?limit=2&offset=100"),
                    Some(&key),
                    None,
                )
                .await;
                assert_eq!(status, StatusCode::OK, "[{label}] {path}: {empty:?}");
                assert_eq!(
                    empty["items"].as_array().unwrap().len(),
                    0,
                    "[{label}] high-offset {path}"
                );
                assert_eq!(empty["has_more"], false, "[{label}] high-offset {path}");
            }
        }
    }

    #[tokio::test]
    async fn encryption_key_mutations_reject_out_of_range_ids_before_store_access() {
        let (router, key, store) = test_router_store_api_key().await;
        let wrapped_key_zero_blob = store
            .encrypt_active_to_base64(b"wraparound-scan-guard")
            .await
            .unwrap();
        store
            .set_secret("cookie_secret", &wrapped_key_zero_blob)
            .await
            .unwrap();
        let out_of_range_key_blob = store
            .master_keys_load_active_set()
            .await
            .unwrap()
            .remove(0)
            .key_encrypted;
        store
            .master_keys_insert(-1, &out_of_range_key_blob)
            .await
            .unwrap();
        store
            .master_keys_insert(256, &out_of_range_key_blob)
            .await
            .unwrap();

        let rows_before = store
            .master_keys_load_active_set()
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.key_id, row.key_encrypted, row.active, row.retired))
            .collect::<Vec<_>>();
        let version_before = store.key_ring_version_current().await.unwrap();
        let expected = serde_json::json!({
            "error": {
                "code": "BAD_REQUEST",
                "message": "bad request: key_id must be between 0 and 255"
            }
        });

        for verb in ["activate", "retire"] {
            for key_id in [
                "-1",
                "256",
                "32768",
                "999999999999999999999999",
                "not-a-number",
            ] {
                let (status, body) = send_request(
                    router.clone(),
                    axum::http::Method::POST,
                    &format!("/.sekisho/api/v1/encryption_keys/{key_id}/{verb}"),
                    Some(&key),
                    None,
                )
                .await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{verb} {key_id}");
                assert_eq!(body, expected, "{verb} {key_id}");
                let rows_after = store
                    .master_keys_load_active_set()
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|row| (row.key_id, row.key_encrypted, row.active, row.retired))
                    .collect::<Vec<_>>();
                assert_eq!(rows_after, rows_before, "{verb} {key_id} changed rows");
                assert_eq!(
                    store.key_ring_version_current().await.unwrap(),
                    version_before,
                    "{verb} {key_id} changed the key-ring version"
                );
            }
        }
    }

    #[tokio::test]
    async fn encryption_key_id_validation_precedes_unavailable_store_access() {
        let store = Store::new_for_test_degraded("must-not-be-read")
            .await
            .unwrap();
        let (state, _) = build_state(store).await;

        let activate_error = match encryption_keys::activate(
            State(state.clone()),
            Extension(crate::audit::Actor::system()),
            axum::extract::Path("-1".to_owned()),
        )
        .await
        {
            Ok(_) => panic!("invalid activate key ID was accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            activate_error,
            crate::error::Error::BadRequest(ref message)
                if message == "key_id must be between 0 and 255"
        ));

        let retire_error = match encryption_keys::retire(
            State(state),
            Extension(crate::audit::Actor::system()),
            axum::extract::Path("256".to_owned()),
        )
        .await
        {
            Ok(_) => panic!("invalid retire key ID was accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            retire_error,
            crate::error::Error::BadRequest(ref message)
                if message == "key_id must be between 0 and 255"
        ));
    }

    #[tokio::test]
    async fn encryption_key_mutations_accept_boundary_ids() {
        let (router, key, store) = test_router_store_api_key().await;
        let upper_key_blob = store
            .master_keys_load_active_set()
            .await
            .unwrap()
            .remove(0)
            .key_encrypted;
        store
            .master_keys_insert(255, &upper_key_blob)
            .await
            .unwrap();

        for key_id in [255, 0] {
            let (status, body) = send_request(
                router.clone(),
                axum::http::Method::POST,
                &format!("/.sekisho/api/v1/encryption_keys/{key_id}/activate"),
                Some(&key),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "activate {key_id}");
            assert_eq!(body["key_id"], key_id);
            assert_eq!(body["status"], "active");
        }

        let (status, body) = send_request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/encryption_keys/255/retire",
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["key_id"], 255);
        assert_eq!(body["status"], "retired");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn challenge_roundtrip_uses_shared_router_and_control_socket_store() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let store = Store::new_for_test("sqlite::memory:", [42u8; 32], None)
            .await
            .unwrap();
        let (state, _) = build_state(store).await;
        let challenge_store = Arc::new(local_auth::ChallengeStore::new());
        let shutdown_ctl = Arc::new(crate::shutdown::ShutdownController::new());
        let router = mk_router_with_challenge(state, shutdown_ctl.clone(), challenge_store.clone());

        let (status, body) = send_request(
            router.clone(),
            axum::http::Method::POST,
            "/.sekisho/api/v1/auth/challenge",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let nonce = body["nonce"].as_str().unwrap();

        let socket_path = std::path::Path::new("/tmp").join(format!(
            "sekishod-challenge-{}-{}.sock",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let control_task = tokio::spawn(local_auth::serve_control_socket(
            listener,
            challenge_store,
            shutdown_ctl.clone(),
        ));
        let mut stream = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        stream
            .write_all(format!("{nonce}\n").as_bytes())
            .await
            .unwrap();
        let mut token = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            BufReader::new(stream).read_line(&mut token),
        )
        .await
        .unwrap()
        .unwrap();
        let token = token.trim();
        assert!(token.starts_with("mgmt_"));

        let (status, _) = send_request(
            router,
            axum::http::Method::GET,
            "/.sekisho/api/v1/_internal/host",
            Some(token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        shutdown_ctl.signal();
        tokio::time::timeout(std::time::Duration::from_secs(1), control_task)
            .await
            .expect("control listener did not stop after shutdown")
            .expect("control listener panicked");
        std::fs::remove_file(socket_path).unwrap();
    }

    #[tokio::test]
    async fn protected_endpoint_returns_401_without_authorization_header() {
        let (router, _key) = test_router_with_api_key().await;
        let (status, body) = send_request(
            router,
            axum::http::Method::GET,
            "/.sekisho/api/v1/routes",
            /* bearer */ None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            body.get("error").is_some(),
            "401 body must carry an error message; got {body:?}"
        );
    }

    #[tokio::test]
    async fn protected_endpoint_returns_401_with_invalid_bearer() {
        let (router, _key) = test_router_with_api_key().await;
        let (status, _) = send_request(
            router,
            axum::http::Method::GET,
            "/.sekisho/api/v1/routes",
            Some("sk_does_not_exist_in_store"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn protected_endpoint_returns_400_on_malformed_json() {
        let (router, key) = test_router_with_api_key().await;
        let (status, body) = send_request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/routes",
            Some(&key),
            Some("{not valid json"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Body must carry a sanitized message, not raw serde output —
        // the SanitizedJson extractor is the load-bearing piece here.
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(msg, "invalid JSON syntax");
    }

    #[tokio::test]
    async fn protected_endpoint_returns_422_on_schema_mismatch() {
        // `from` is a required `String`; sending an integer makes serde
        // fail with JsonDataError, which the extractor maps to 422.
        let (router, key) = test_router_with_api_key().await;
        let (status, _) = send_request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/routes",
            Some(&key),
            Some(r#"{"name":"r","from":42,"to":["http://upstream.example/"]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn protected_endpoint_returns_400_on_validation_failure() {
        // Schema-valid but domain-invalid: empty name fails
        // `validate_route_create` which returns `Error::BadRequest`.
        let (router, key) = test_router_with_api_key().await;
        let (status, body) = send_request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/routes",
            Some(&key),
            Some(r#"{"name":"","from":"http://x.example/","to":["http://up.example/"]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.get("error").is_some());
    }

    async fn seed_oidc_idp(store: &Store) -> (uuid::Uuid, String) {
        let encrypted = store
            .encrypt_active_to_base64(b"test-preserved-secret")
            .await
            .unwrap();
        let idp = IdentityProvider {
            id: uuid::Uuid::new_v4(),
            name: "oidc-test".into(),
            idp_type: IdpType::Oidc,
            oidc_config: Some(OidcConfig {
                issuer_url: "https://issuer.example".into(),
                client_id: "client-id".into(),
                client_secret_encrypted: encrypted.clone(),
                scopes: vec!["openid".into()],
                prompt: Some("login".into()),
            }),
            saml_config: None,
        };
        store.create_idp(&idp).await.unwrap();
        (idp.id, encrypted)
    }

    async fn seed_saml_idp(store: &Store) -> uuid::Uuid {
        let mut attribute_mapping = std::collections::HashMap::new();
        attribute_mapping.insert("email".into(), "mail".into());
        attribute_mapping.insert("groups".into(), "memberOf".into());
        let idp = IdentityProvider {
            id: uuid::Uuid::new_v4(),
            name: "saml-test".into(),
            idp_type: IdpType::Saml,
            oidc_config: None,
            saml_config: Some(SamlConfig {
                metadata_url: "https://idp.example/metadata".into(),
                slo_url: Some("https://idp.example/logout".into()),
                name_id_format: Some("persistent".into()),
                attribute_mapping,
            }),
        };
        store.create_idp(&idp).await.unwrap();
        idp.id
    }

    #[tokio::test]
    async fn idp_update_rejects_invalid_active_config_before_mutation() {
        use crate::audit::test_capture::AuditCapture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let (router, key, store) = test_router_store_api_key().await;
        let (oidc_id, _) = seed_oidc_idp(&store).await;
        let saml_id = seed_saml_idp(&store).await;

        let oidc_before = serde_json::to_value(store.get_idp(oidc_id).await.unwrap()).unwrap();
        let saml_before = serde_json::to_value(store.get_idp(saml_id).await.unwrap()).unwrap();
        let version_before = store.idp_version_current().await.unwrap();

        for body in [
            serde_json::json!({
                "oidc_config": {
                    "issuer_url": "not-a-url",
                    "client_id": "client-id",
                    "scopes": ["openid"]
                }
            }),
            serde_json::json!({
                "oidc_config": {
                    "issuer_url": "file:///tmp/issuer",
                    "client_id": "client-id",
                    "scopes": ["openid"]
                }
            }),
            serde_json::json!({
                "oidc_config": {
                    "issuer_url": "https://issuer.example",
                    "client_id": "",
                    "scopes": ["openid"]
                }
            }),
            serde_json::json!({
                "oidc_config": {
                    "issuer_url": "https://issuer.example",
                    "client_id": " \t ",
                    "scopes": ["openid"]
                }
            }),
        ] {
            let (status, _) = send_request(
                router.clone(),
                axum::http::Method::PATCH,
                &format!("/.sekisho/api/v1/idps/{oidc_id}"),
                Some(&key),
                Some(&body.to_string()),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        for metadata_url in ["not-a-url", "file:///tmp/metadata"] {
            let body = serde_json::json!({
                "saml_config": {
                    "metadata_url": metadata_url,
                    "slo_url": null,
                    "name_id_format": null,
                    "attribute_mapping": {}
                }
            });
            let (status, _) = send_request(
                router.clone(),
                axum::http::Method::PATCH,
                &format!("/.sekisho/api/v1/idps/{saml_id}"),
                Some(&key),
                Some(&body.to_string()),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        let invalid_mapping = serde_json::json!({
            "saml_config": {
                "attribute_mapping": {
                    "email": 42
                }
            }
        });
        let (status, _) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{saml_id}"),
            Some(&key),
            Some(&invalid_mapping.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let oidc_after = serde_json::to_value(store.get_idp(oidc_id).await.unwrap()).unwrap();
        let saml_after = serde_json::to_value(store.get_idp(saml_id).await.unwrap()).unwrap();
        assert!(
            oidc_after == oidc_before,
            "invalid PATCH mutated the OIDC row"
        );
        assert!(
            saml_after == saml_before,
            "invalid PATCH mutated the SAML row"
        );
        assert_eq!(store.idp_version_current().await.unwrap(), version_before);
        assert!(
            capture.find("idp.update").is_none(),
            "invalid PATCH emitted an update success audit"
        );
    }

    #[tokio::test]
    async fn idp_update_preserves_or_rotates_secret_and_redacts_response() {
        let (router, key, store) = test_router_store_api_key().await;
        let (id, original_encrypted) = seed_oidc_idp(&store).await;

        for secret_field in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::Value::String(String::new())),
            Some(serde_json::Value::String(idps::REDACTED.into())),
        ] {
            let mut config = serde_json::json!({
                "issuer_url": "https://issuer.example",
                "client_id": "client-id",
                "scopes": ["openid"]
            });
            if let Some(value) = secret_field {
                config["client_secret"] = value;
            }
            let body = serde_json::json!({"oidc_config": config});
            let (status, response) = send_request(
                router.clone(),
                axum::http::Method::PATCH,
                &format!("/.sekisho/api/v1/idps/{id}"),
                Some(&key),
                Some(&body.to_string()),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(response["oidc_config"]["client_secret"], idps::REDACTED);
            assert!(
                response["oidc_config"]
                    .get("client_secret_encrypted")
                    .is_none()
            );
            let stored = store.get_idp(id).await.unwrap();
            let ciphertext = &stored.oidc_config.as_ref().unwrap().client_secret_encrypted;
            assert!(
                ciphertext == &original_encrypted,
                "secret-preserving PATCH changed stored ciphertext"
            );
        }

        let body = serde_json::json!({
            "oidc_config": {
                "issuer_url": "https://issuer.example",
                "client_id": "client-id",
                "client_secret": "test-rotated-secret",
                "scopes": ["openid"]
            }
        });
        let (status, response) = send_request(
            router,
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{id}"),
            Some(&key),
            Some(&body.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["oidc_config"]["client_secret"], idps::REDACTED);
        let stored = store.get_idp(id).await.unwrap();
        let ciphertext = &stored.oidc_config.as_ref().unwrap().client_secret_encrypted;
        assert!(
            ciphertext != &original_encrypted,
            "secret rotation preserved old ciphertext"
        );
        let plaintext = store.decrypt_any_from_base64(ciphertext).await.unwrap();
        assert!(
            plaintext == b"test-rotated-secret",
            "rotated secret plaintext differs"
        );
    }

    #[tokio::test]
    async fn idp_update_preserves_schema_type_and_valid_paths() {
        let (router, key, store) = test_router_store_api_key().await;
        let (oidc_id, _) = seed_oidc_idp(&store).await;
        let saml_id = seed_saml_idp(&store).await;
        let oidc_before = serde_json::to_value(store.get_idp(oidc_id).await.unwrap()).unwrap();
        let saml_before = serde_json::to_value(store.get_idp(saml_id).await.unwrap()).unwrap();
        let version_before = store.idp_version_current().await.unwrap();

        let (status, _) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{oidc_id}"),
            Some(&key),
            Some(r#"{"oidc_config":{"client_id":"client-id"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            serde_json::to_value(store.get_idp(oidc_id).await.unwrap()).unwrap() == oidc_before,
            "effective no-op OIDC update changed the stored row"
        );
        assert_eq!(store.idp_version_current().await.unwrap(), version_before);

        let (status, _) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{oidc_id}"),
            Some(&key),
            Some(r#"{"oidc_config":{"issuer_url":"https://issuer.example.com"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let updated_oidc = store.get_idp(oidc_id).await.unwrap();
        let updated_oidc_config = updated_oidc.oidc_config.as_ref().unwrap();
        assert_eq!(updated_oidc_config.issuer_url, "https://issuer.example.com");
        assert_eq!(updated_oidc_config.client_id, "client-id");

        let (status, _) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{oidc_id}"),
            Some(&key),
            Some(r#"{"oidc_config":{"prompt":null}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            store
                .get_idp(oidc_id)
                .await
                .unwrap()
                .oidc_config
                .unwrap()
                .prompt
                .is_none()
        );

        let (status, _) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{saml_id}"),
            Some(&key),
            Some(r#"{"saml_config":{}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            serde_json::to_value(store.get_idp(saml_id).await.unwrap()).unwrap() == saml_before,
            "effective no-op SAML update changed the stored row"
        );

        let missing_id = uuid::Uuid::new_v4();
        let (status, _) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{missing_id}"),
            Some(&key),
            Some(r#"{"name":""}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{missing_id}"),
            Some(&key),
            Some(r#"{"name":"valid"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{oidc_id}"),
            Some(&key),
            Some(r#"{"type":"saml","name":"oidc-renamed"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let stored = store.get_idp(oidc_id).await.unwrap();
        assert_eq!(stored.idp_type, IdpType::Oidc);
        assert_eq!(stored.name, "oidc-renamed");

        let saml_body = serde_json::json!({
            "saml_config": {
                "metadata_url": "https://new-idp.example/metadata",
                "slo_url": null,
                "name_id_format": null,
                "attribute_mapping": {}
            }
        });
        let (status, _) = send_request(
            router,
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{saml_id}"),
            Some(&key),
            Some(&saml_body.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            store
                .get_idp(saml_id)
                .await
                .unwrap()
                .saml_config
                .as_ref()
                .unwrap()
                .metadata_url,
            "https://new-idp.example/metadata"
        );
        let stored_saml = store.get_idp(saml_id).await.unwrap();
        let stored_saml_config = stored_saml.saml_config.unwrap();
        assert!(stored_saml_config.slo_url.is_none());
        assert!(stored_saml_config.name_id_format.is_none());
    }

    #[tokio::test]
    async fn idp_nested_patch_preserves_saml_siblings_and_deletes_one_mapping() {
        let (router, key, store) = test_router_store_api_key().await;
        let saml_id = seed_saml_idp(&store).await;

        let body = serde_json::json!({
            "saml_config": {
                "attribute_mapping": {
                    "email": "emailAddress"
                }
            }
        });
        let (status, _) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{saml_id}"),
            Some(&key),
            Some(&body.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let stored = store.get_idp(saml_id).await.unwrap();
        let config = stored.saml_config.unwrap();
        assert_eq!(config.metadata_url, "https://idp.example/metadata");
        assert_eq!(
            config.slo_url.as_deref(),
            Some("https://idp.example/logout")
        );
        assert_eq!(config.name_id_format.as_deref(), Some("persistent"));
        assert_eq!(
            config.attribute_mapping.get("email").map(String::as_str),
            Some("emailAddress")
        );
        assert_eq!(
            config.attribute_mapping.get("groups").map(String::as_str),
            Some("memberOf")
        );

        let delete_email = serde_json::json!({
            "saml_config": {
                "attribute_mapping": {
                    "email": null
                }
            }
        });
        let (status, _) = send_request(
            router,
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/idps/{saml_id}"),
            Some(&key),
            Some(&delete_email.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let config = store.get_idp(saml_id).await.unwrap().saml_config.unwrap();
        assert!(!config.attribute_mapping.contains_key("email"));
        assert_eq!(
            config.attribute_mapping.get("groups").map(String::as_str),
            Some("memberOf")
        );
    }

    #[tokio::test]
    async fn idp_required_nested_null_is_fixed_bad_request_without_mutation() {
        let (router, key, store) = test_router_store_api_key().await;
        let (oidc_id, _) = seed_oidc_idp(&store).await;
        let saml_id = seed_saml_idp(&store).await;
        let before = serde_json::to_vec(&store.get_idp(oidc_id).await.unwrap()).unwrap();
        let saml_before = serde_json::to_value(store.get_idp(saml_id).await.unwrap()).unwrap();
        let version_before = store.idp_version_current().await.unwrap();

        for (id, body, field) in [
            (
                oidc_id,
                r#"{"oidc_config":{"issuer_url":null}}"#,
                "oidc_config.issuer_url",
            ),
            (
                oidc_id,
                r#"{"oidc_config":{"client_id":null}}"#,
                "oidc_config.client_id",
            ),
            (
                oidc_id,
                r#"{"oidc_config":{"scopes":null}}"#,
                "oidc_config.scopes",
            ),
            (
                saml_id,
                r#"{"saml_config":{"metadata_url":null}}"#,
                "saml_config.metadata_url",
            ),
            (
                saml_id,
                r#"{"saml_config":{"attribute_mapping":null}}"#,
                "saml_config.attribute_mapping",
            ),
        ] {
            let (status, response) = send_request(
                router.clone(),
                axum::http::Method::PATCH,
                &format!("/.sekisho/api/v1/idps/{id}"),
                Some(&key),
                Some(body),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "field={field}");
            assert_eq!(response["error"]["code"], "BAD_REQUEST");
            assert_eq!(
                response["error"]["message"],
                format!("bad request: {field} must not be null")
            );
        }
        assert_eq!(
            serde_json::to_vec(&store.get_idp(oidc_id).await.unwrap()).unwrap(),
            before
        );
        assert_eq!(
            serde_json::to_value(store.get_idp(saml_id).await.unwrap()).unwrap(),
            saml_before
        );
        assert_eq!(store.idp_version_current().await.unwrap(), version_before);
    }

    #[tokio::test]
    async fn idp_effective_no_ops_do_not_write_version_or_success_audit() {
        use crate::audit::test_capture::AuditCapture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let (router, key, store) = test_router_store_api_key().await;
        let (oidc_id, _) = seed_oidc_idp(&store).await;
        let before = serde_json::to_vec(&store.get_idp(oidc_id).await.unwrap()).unwrap();
        let version_before = store.idp_version_current().await.unwrap();

        for body in [
            r#"{"unknown":"ignored"}"#,
            r#"{"name":null}"#,
            r#"{"oidc_config":{}}"#,
            r#"{"oidc_config":{"unknown":"ignored"}}"#,
            r#"{"oidc_config":{"client_secret":null}}"#,
            r#"{"oidc_config":{"client_secret":""}}"#,
            r#"{"oidc_config":{"client_secret":"**REDACTED**"}}"#,
            r#"{"oidc_config":null}"#,
        ] {
            let (status, _) = send_request(
                router.clone(),
                axum::http::Method::PATCH,
                &format!("/.sekisho/api/v1/idps/{oidc_id}"),
                Some(&key),
                Some(body),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body={body}");
        }

        assert_eq!(
            serde_json::to_vec(&store.get_idp(oidc_id).await.unwrap()).unwrap(),
            before
        );
        assert_eq!(store.idp_version_current().await.unwrap(), version_before);
        assert!(capture.find("idp.update").is_none());
    }

    #[tokio::test]
    async fn proxy_cert_upload_rejects_mismatched_pair_before_persist_and_reload() {
        let store = Store::new_for_test("sqlite::memory:", [42u8; 32], None)
            .await
            .unwrap();
        let api_key = store
            .create_api_key("test", &ApiKeyScopeSet::admin())
            .await
            .unwrap();
        let (state, cert_resolver) = build_state(store.clone()).await;
        let router = mk_router(state);
        let (cert_pem, _) = mk_cert_and_key_pem("mismatch.example.com");
        let (_, different_key_pem) = mk_cert_and_key_pem("different.example.com");
        let body = serde_json::json!({
            "domain": "mismatch.example.com",
            "cert_pem": cert_pem,
            "key_pem": different_key_pem,
        })
        .to_string();

        let (status, _) = send_request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/certs/upload",
            Some(&api_key.key),
            Some(&body),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(store.list_certs().await.unwrap().is_empty());
        assert!(!cert_resolver.is_ready());
    }

    #[tokio::test]
    async fn proxy_cert_upload_rejects_san_mismatch_before_persist_and_reload() {
        use crate::audit::test_capture::AuditCapture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let store = Store::new_for_test("sqlite::memory:", [42u8; 32], None)
            .await
            .unwrap();
        let api_key = store
            .create_api_key("test", &ApiKeyScopeSet::admin())
            .await
            .unwrap();
        let (state, cert_resolver) = build_state(store.clone()).await;
        let router = mk_router(state);
        let (cert_pem, key_pem) = mk_cert_and_key_pem("other.example.com");
        let body = serde_json::json!({
            "domain": "requested.example.com",
            "cert_pem": cert_pem,
            "key_pem": key_pem,
        })
        .to_string();

        let (status, _) = send_request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/certs/upload",
            Some(&api_key.key),
            Some(&body),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(store.list_certs().await.unwrap().is_empty());
        assert!(!cert_resolver.is_ready());
        assert!(capture.find("cert.upload").is_none());
    }

    #[tokio::test]
    async fn proxy_cert_upload_persists_matching_pair_and_reloads_resolver() {
        let store = Store::new_for_test("sqlite::memory:", [42u8; 32], None)
            .await
            .unwrap();
        let api_key = store
            .create_api_key("test", &ApiKeyScopeSet::admin())
            .await
            .unwrap();
        let (state, cert_resolver) = build_state(store.clone()).await;
        let router = mk_router(state);
        let domain = "matched.example.com";
        let (cert_pem, key_pem) = mk_cert_and_key_pem(domain);
        let body = serde_json::json!({
            "domain": domain,
            "cert_pem": cert_pem,
            "key_pem": key_pem,
        })
        .to_string();

        let (status, _) = send_request(
            router,
            axum::http::Method::POST,
            "/.sekisho/api/v1/certs/upload",
            Some(&api_key.key),
            Some(&body),
        )
        .await;

        assert_eq!(status, StatusCode::CREATED);
        let rows = store.list_certs().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].domain, domain);
        assert_eq!(rows[0].cert_pem, cert_pem);
        let stored_key = store
            .decrypt_any_from_base64(&rows[0].key_pem_encrypted)
            .await
            .unwrap();
        assert!(
            stored_key == key_pem.as_bytes(),
            "stored private key material differs"
        );
        assert!(cert_resolver.is_ready());
    }

    #[tokio::test]
    async fn routes_crud_roundtrip_via_http() {
        // Full CRUD through the HTTP layer: this is the regression
        // canary for "auth middleware silently fell off a protected
        // route in a future refactor". If create / list / get / patch /
        // delete all return 2xx with a valid bearer and 401 without
        // one, the middleware ordering, state binding, and JSON shape
        // are all wired up.
        let (router, key) = test_router_with_api_key().await;

        // CREATE
        let create_body = serde_json::json!({
            "name": "test-route",
            "from": "https://app.example/",
            "to": ["http://upstream.example/"]
        });
        let (status, created) = send_request(
            router.clone(),
            axum::http::Method::POST,
            "/.sekisho/api/v1/routes",
            Some(&key),
            Some(&create_body.to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().expect("created route has id");

        // LIST — paginated envelope shape.
        let (status, list) = send_request(
            router.clone(),
            axum::http::Method::GET,
            "/.sekisho/api/v1/routes",
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for field in ["items", "limit", "offset", "has_more"] {
            assert!(
                list.get(field).is_some(),
                "pagination envelope missing `{field}`: {list:?}"
            );
        }
        assert!(
            list["items"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
            "list should contain the just-created route"
        );

        // GET
        let (status, got) = send_request(
            router.clone(),
            axum::http::Method::GET,
            &format!("/.sekisho/api/v1/routes/{id}"),
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["id"].as_str(), Some(id));
        assert_eq!(got["name"].as_str(), Some("test-route"));

        // PATCH — partial update of `enabled`.
        let (status, patched) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/routes/{id}"),
            Some(&key),
            Some(r#"{"enabled":true}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(patched["enabled"].as_bool(), Some(true));

        // DELETE
        let (status, _) = send_request(
            router.clone(),
            axum::http::Method::DELETE,
            &format!("/.sekisho/api/v1/routes/{id}"),
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // GET after DELETE → 404.
        let (status, _) = send_request(
            router,
            axum::http::Method::GET,
            &format!("/.sekisho/api/v1/routes/{id}"),
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn proxy_owned_policy_headers_are_fixed_400_before_store_version_or_audit() {
        use crate::audit::test_capture::AuditCapture;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        const UNSAFE: &str = r#"request.header.x_sekisho_user == "admin""#;
        const SAFE: &str = r#"request.header.x_request_source == "scheduler""#;

        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let (router, key, store) = test_router_store_api_key().await;

        let (status, body) = send_request(
            router.clone(),
            axum::http::Method::POST,
            "/.sekisho/api/v1/policies",
            Some(&key),
            Some(&serde_json::json!({"name": "unsafe-policy", "expr": UNSAFE}).to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "BAD_REQUEST");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("proxy-owned header"))
        );
        assert!(store.list_policies().await.unwrap().is_empty());
        assert!(capture.find("policy.create").is_none());

        let version0 = store.route_version_current().await.unwrap();
        let (status, body) = send_request(
            router.clone(),
            axum::http::Method::POST,
            "/.sekisho/api/v1/routes",
            Some(&key),
            Some(
                &serde_json::json!({
                    "name": "unsafe-route",
                    "from": "https://unsafe-route.example.com",
                    "to": ["http://upstream.example.com"],
                    "access": {"policy": UNSAFE}
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "BAD_REQUEST");
        assert!(store.list_routes().await.unwrap().is_empty());
        assert_eq!(store.route_version_current().await.unwrap(), version0);
        assert!(capture.find("route.create").is_none());

        let policy = crate::models::policy::Policy {
            id: uuid::Uuid::new_v4(),
            name: "safe-policy".into(),
            expr: SAFE.into(),
        };
        store.create_policy(&policy).await.unwrap();
        let (status, body) = send_request(
            router.clone(),
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/policies/{}", policy.id),
            Some(&key),
            Some(&serde_json::json!({"expr": UNSAFE}).to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "BAD_REQUEST");
        assert_eq!(store.get_policy(policy.id).await.unwrap().expr, SAFE);
        assert!(capture.find("policy.update").is_none());

        let mut route = management_page_route(uuid::Uuid::new_v4(), "safe-route");
        route.access.policy = Some(SAFE.into());
        store.create_route(&route).await.unwrap();
        let version1 = store.route_version_current().await.unwrap();
        let (status, body) = send_request(
            router,
            axum::http::Method::PATCH,
            &format!("/.sekisho/api/v1/routes/{}", route.id),
            Some(&key),
            Some(
                &serde_json::json!({
                    "access": {
                        "policy": UNSAFE,
                        "allow_public_unauthenticated_access": false
                    },
                    "enabled": true
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "BAD_REQUEST");
        let unchanged = store.get_route(route.id).await.unwrap();
        assert_eq!(unchanged.access.policy.as_deref(), Some(SAFE));
        assert!(!unchanged.enabled);
        assert_eq!(store.route_version_current().await.unwrap(), version1);
        assert!(capture.find("route.update").is_none());
    }

    #[tokio::test]
    async fn sessions_router_reports_exact_pages_with_stable_ties() {
        let (router, key, store) = test_router_store_api_key().await;
        let created_at = chrono::Utc::now();
        for suffix in [3_u128, 1, 2] {
            let session = crate::models::session::Session {
                id: uuid::Uuid::from_u128(suffix),
                user_id: "pagination@example.com".into(),
                idp_id: uuid::Uuid::from_u128(99),
                upstream_identity: None,
                claims: std::collections::HashMap::new(),
                groups: Vec::new(),
                created_at,
                expires_at: created_at + chrono::Duration::hours(1),
                refresh_token_encrypted: None,
                id_token_encrypted: None,
                saml_name_id: None,
                saml_session_index: None,
                last_accessed_at: created_at,
            };
            store.create_session(&session).await.unwrap();
        }

        let (status, first) = send_request(
            router.clone(),
            axum::http::Method::GET,
            "/.sekisho/api/v1/sessions?limit=2&offset=0",
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{first:?}");
        assert_eq!(first["limit"], 2);
        assert_eq!(first["offset"], 0);
        assert_eq!(first["has_more"], true);
        let first_ids = first["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            first_ids,
            [
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            ]
        );

        let (status, second) = send_request(
            router.clone(),
            axum::http::Method::GET,
            "/.sekisho/api/v1/sessions?limit=2&offset=2",
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["has_more"], false);
        assert_eq!(second["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            second["items"][0]["id"],
            "00000000-0000-0000-0000-000000000003"
        );

        let (status, exact_terminal) = send_request(
            router,
            axum::http::Method::GET,
            "/.sekisho/api/v1/sessions?limit=2&offset=1",
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(exact_terminal["items"].as_array().unwrap().len(), 2);
        assert_eq!(exact_terminal["has_more"], false);
    }
}
