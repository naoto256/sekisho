//! Metrics: the Prometheus registry, the request middleware, and the
//! control-budget instrumentation.
//!
//! ## Budgets are described up front, not on first use
//!
//! [`seed_control_budget_metrics`] emits a `describe_*` and a zero sample for
//! every budget at startup. Without it a series only appears once it has been
//! touched, so "no rejections have happened" and "this build does not have
//! that budget" look identical to a dashboard, and an alert on a
//! never-yet-incremented counter never fires. Seeding makes absence meaningful.
//!
//! ## Two enums, asymmetric on purpose
//!
//! [`ControlBudget`] lists everything with a utilization gauge;
//! [`RejectedControlBudget`] lists only what can reject *immediately*. The
//! queueing budgets appear in the first and not the second, because a queued
//! request is not a rejection and a synthetic rejection series that is
//! permanently zero would be read as a guarantee rather than as an absence of
//! measurement. Keeping them as separate types makes that asymmetry something
//! the compiler enforces instead of something a reviewer has to notice.
//!
//! ## Gauges are released by drop, never by hand
//!
//! [`observe_control_budget`] hands back a [`ControlBudgetObservation`] whose
//! `Drop` decrements. An explicit decrement call would leak on every `?` and
//! every error path, and an in-flight gauge that only ever climbs is worse
//! than no gauge at all.
//!
//! Label cardinality is bounded deliberately: budget labels come from a closed
//! enum, and error labels from a fixed `kind` set. Route names appear as
//! labels because the route table is operator-sized, but error text never
//! does.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use axum::middleware::Next;
use metrics::{counter, describe_counter, describe_gauge, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::fmt::Write as _;
use std::sync::OnceLock;
use std::time::Instant;

/// The exporter handle, installed once. `OnceLock` rather than a parameter
/// threaded through the app because `metrics!` macros reach a global recorder
/// anyway — pretending otherwise would add plumbing without adding control.
static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Guards the one-time seeding of the budget series. Tests build several
/// routers in one process, and re-describing a metric is not free of warnings.
static CONTROL_BUDGET_METRICS_INITIALIZED: OnceLock<()> = OnceLock::new();

// Metric names are consts so the emission site and the `describe_*` /
// seeding site cannot drift — a typo in either place would otherwise create a
// second, undescribed series that looks plausible on a dashboard.
const CONTROL_BUDGET_IN_FLIGHT: &str = "sekisho_control_budget_in_flight";
const CONTROL_BUDGET_LIMIT: &str = "sekisho_control_budget_limit";
const CONTROL_BUDGET_REJECTED: &str = "sekisho_control_budget_rejected_total";
const ACME_QUEUE_ACTIVE: &str = "sekisho_acme_queue_active";
const ACME_QUEUE_CAPACITY: &str = "sekisho_acme_queue_capacity";
const ACME_ISSUANCE_IN_PROGRESS: &str = "sekisho_acme_issuance_in_progress";
const ACME_ISSUANCE_LIMIT: &str = "sekisho_acme_issuance_limit";

/// Process-local permit/reservation owners that expose utilization gauges.
///
/// Keeping this set separate from [`RejectedControlBudget`] makes the
/// intentionally asymmetric Prometheus label sets a compile-time property:
/// queued budgets do not acquire a synthetic rejection series.
#[derive(Clone, Copy)]
pub(crate) enum ControlBudget {
    /// Global in-flight HTTP requests on the proxy listener. Queues.
    ProxyHttp,
    ProxyWebsocket,
    Management,
    Probe,
    Challenge,
}

impl ControlBudget {
    const ALL: [Self; 5] = [
        Self::ProxyHttp,
        Self::ProxyWebsocket,
        Self::Management,
        Self::Probe,
        Self::Challenge,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::ProxyHttp => "proxy_http",
            Self::ProxyWebsocket => "proxy_websocket",
            Self::Management => "management",
            Self::Probe => "probe",
            Self::Challenge => "challenge",
        }
    }
}

/// Admission outcomes that are genuine immediate rejections.
#[derive(Clone, Copy)]
pub(crate) enum RejectedControlBudget {
    /// Tunnel refused because the WebSocket budget was full.
    ProxyWebsocket,
    Probe,
    Challenge,
    AcmeQueue,
}

impl RejectedControlBudget {
    const ALL: [Self; 4] = [
        Self::ProxyWebsocket,
        Self::Probe,
        Self::Challenge,
        Self::AcmeQueue,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::ProxyWebsocket => "proxy_websocket",
            Self::Probe => "probe",
            Self::Challenge => "challenge",
            Self::AcmeQueue => "acme_queue",
        }
    }
}

/// A metric-only lifetime token. The corresponding semaphore permit remains
/// owned by the subsystem that enforces the budget.
pub(crate) struct ControlBudgetObservation(metrics::Gauge);

impl Drop for ControlBudgetObservation {
    fn drop(&mut self) {
        self.0.decrement(1.0);
    }
}

/// Increment a budget's in-flight gauge and hand back the guard that
/// decrements it. Hold the guard for exactly as long as the resource is held.
pub(crate) fn observe_control_budget(budget: ControlBudget) -> ControlBudgetObservation {
    let value = gauge!(CONTROL_BUDGET_IN_FLIGHT, "budget" => budget.label());
    value.increment(1.0);
    ControlBudgetObservation(value)
}

/// Publish a budget's capacity. Called at construction, from the same place
/// that sizes the semaphore, so the gauge's denominator cannot disagree with
/// what is actually enforced.
pub(crate) fn record_control_budget_limit(budget: ControlBudget, limit: usize) {
    gauge!(CONTROL_BUDGET_LIMIT, "budget" => budget.label()).set(limit as f64);
}

/// Count an immediate rejection. Emitted at the rejection site rather than
/// inferred from status codes, which cannot distinguish "budget full" from any
/// other 503.
pub(crate) fn record_control_budget_rejection(budget: RejectedControlBudget) {
    counter!(CONTROL_BUDGET_REJECTED, "budget" => budget.label()).increment(1);
}

/// Describe and zero every budget series so a dashboard can tell "nothing has
/// happened" from "this series does not exist". See the module docs.
fn seed_control_budget_metrics() {
    describe_gauge!(
        CONTROL_BUDGET_IN_FLIGHT,
        "Current process-local control-budget permits or reservations in use."
    );
    describe_gauge!(
        CONTROL_BUDGET_LIMIT,
        "Configured process-local control-budget permit or reservation limit."
    );
    describe_counter!(
        CONTROL_BUDGET_REJECTED,
        "Immediate control-budget admission rejections observed by this process."
    );

    for budget in ControlBudget::ALL {
        gauge!(CONTROL_BUDGET_IN_FLIGHT, "budget" => budget.label()).set(0.0);
        gauge!(CONTROL_BUDGET_LIMIT, "budget" => budget.label()).set(0.0);
    }
    for budget in RejectedControlBudget::ALL {
        counter!(CONTROL_BUDGET_REJECTED, "budget" => budget.label()).absolute(0);
    }
}

#[cfg(test)]
pub(crate) fn seed_control_budget_metrics_for_test() {
    seed_control_budget_metrics();
}

/// Stamp on a response when the proxy resolves a request to a configured
/// route. Read by [`metrics_middleware`] so the edge counter can attribute
/// per-route traffic without the middleware having to re-resolve the
/// route itself. Requests that never matched a route (404s, internal
/// `/.sekisho/*` paths, malformed traffic) are accounted to the
/// sentinel `"_unrouted"` label below.
#[derive(Clone, Debug)]
pub struct MatchedRouteId(pub String);

const UNROUTED: &str = "_unrouted";

/// Wraps every request hitting the proxy listener and splits header latency
/// from the lifetime of the streamed response body.
///
/// * `sekisho_proxy_requests_total{route, status}` — request count
/// * `sekisho_proxy_response_headers_duration_seconds{route, status}` —
///   request start through response headers
/// * `sekisho_proxy_response_body_duration_seconds{route, status, outcome}` —
///   response headers through EOF, body error, or downstream drop
///
/// The shared `route` and `status` labels are low cardinality: `route`
/// is a configured route name (or `_unrouted`) and `status` is an HTTP
/// status code. The body-duration metric's additional `outcome` label
/// is a fixed enum (`eof` / `error` / `dropped`). The handler is
/// expected to stamp [`MatchedRouteId`] onto the response extensions
/// when a route matched; everything else is bucketed under `_unrouted`
/// so unmatched traffic still shows up in dashboards.
pub async fn metrics_middleware(req: Request<Body>, next: Next) -> Response<Body> {
    let start = Instant::now();
    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();
    let route = response
        .extensions()
        .get::<MatchedRouteId>()
        .map(|r| r.0.clone())
        .unwrap_or_else(|| UNROUTED.to_string());

    counter!(
        "sekisho_proxy_requests_total",
        "route" => route.clone(),
        "status" => status.clone()
    )
    .increment(1);
    histogram!(
        "sekisho_proxy_response_headers_duration_seconds",
        "route" => route.clone(),
        "status" => status.clone()
    )
    .record(duration);

    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        return response;
    }

    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(ObservedResponseBody::new(body, route, status)),
    )
}

struct ObservedResponseBody {
    inner: Body,
    route: String,
    status: String,
    started: Instant,
    recorded: bool,
}

impl ObservedResponseBody {
    fn new(inner: Body, route: String, status: String) -> Self {
        let already_complete = hyper::body::Body::is_end_stream(&inner);
        let mut observed = Self {
            inner,
            route,
            status,
            started: Instant::now(),
            recorded: false,
        };
        if already_complete {
            observed.record("eof");
        }
        observed
    }

    fn record(&mut self, outcome: &'static str) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        histogram!(
            "sekisho_proxy_response_body_duration_seconds",
            "route" => self.route.clone(),
            "status" => self.status.clone(),
            "outcome" => outcome
        )
        .record(self.started.elapsed().as_secs_f64());
    }
}

impl hyper::body::Body for ObservedResponseBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        match &result {
            std::task::Poll::Ready(None) => this.record("eof"),
            std::task::Poll::Ready(Some(Err(_))) => this.record("error"),
            _ => {}
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

impl Drop for ObservedResponseBody {
    fn drop(&mut self) {
        self.record("dropped");
    }
}

fn append_durable_acme_metrics(
    rendered: &mut String,
    snapshot: crate::store::backend::AcmeBudgetSnapshot,
    issuance_limit: u32,
) {
    if !rendered.is_empty() && !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    writeln!(
        rendered,
        "# HELP {ACME_QUEUE_ACTIVE} Current cluster-wide active ACME queue rows."
    )
    .expect("writing metrics to a String cannot fail");
    writeln!(rendered, "# TYPE {ACME_QUEUE_ACTIVE} gauge")
        .expect("writing metrics to a String cannot fail");
    writeln!(rendered, "{ACME_QUEUE_ACTIVE} {}", snapshot.queue_active)
        .expect("writing metrics to a String cannot fail");
    writeln!(
        rendered,
        "# HELP {ACME_QUEUE_CAPACITY} Current live cluster-wide ACME queue capacity."
    )
    .expect("writing metrics to a String cannot fail");
    writeln!(rendered, "# TYPE {ACME_QUEUE_CAPACITY} gauge")
        .expect("writing metrics to a String cannot fail");
    writeln!(
        rendered,
        "{ACME_QUEUE_CAPACITY} {}",
        snapshot.queue_capacity
    )
    .expect("writing metrics to a String cannot fail");
    writeln!(
        rendered,
        "# HELP {ACME_ISSUANCE_IN_PROGRESS} Current cluster-wide non-stale durable ACME issuances in progress."
    )
    .expect("writing metrics to a String cannot fail");
    writeln!(rendered, "# TYPE {ACME_ISSUANCE_IN_PROGRESS} gauge")
        .expect("writing metrics to a String cannot fail");
    writeln!(
        rendered,
        "{ACME_ISSUANCE_IN_PROGRESS} {}",
        snapshot.issuance_in_progress
    )
    .expect("writing metrics to a String cannot fail");
    writeln!(
        rendered,
        "# HELP {ACME_ISSUANCE_LIMIT} Startup ACME issuance limit for this scraped target."
    )
    .expect("writing metrics to a String cannot fail");
    writeln!(rendered, "# TYPE {ACME_ISSUANCE_LIMIT} gauge")
        .expect("writing metrics to a String cannot fail");
    writeln!(rendered, "{ACME_ISSUANCE_LIMIT} {issuance_limit}")
        .expect("writing metrics to a String cannot fail");
}

fn metrics_response(rendered: String) -> Result<Response<Body>, StatusCode> {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(Body::from(rendered))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Prometheus exposition handler for the management API.
///
/// Durable ACME samples are appended only when their one-statement database
/// snapshot succeeds. A snapshot failure leaves the existing process metrics
/// intact and omits the complete durable block from this response.
pub(crate) async fn durable_acme_metrics_handler(
    store: crate::store::Store,
    issuance_limit: u32,
) -> Result<Response<Body>, StatusCode> {
    let handle = PROMETHEUS_HANDLE
        .get()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut rendered = handle.render();
    let stale_before = chrono::Utc::now()
        - chrono::Duration::minutes(crate::tls::acme::queue::QUEUE_STALE_AFTER_MINUTES);
    if let Ok(snapshot) = store.acme_budget_snapshot(stale_before).await {
        append_durable_acme_metrics(&mut rendered, snapshot, issuance_limit);
    }
    metrics_response(rendered)
}

/// Process-only exposition seam retained for tests that exercise metrics not
/// backed by the service database.
#[cfg(test)]
pub async fn metrics_handler() -> Result<Response<Body>, StatusCode> {
    let handle = PROMETHEUS_HANDLE
        .get()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    metrics_response(handle.render())
}

/// Install the global Prometheus recorder. Idempotent: a second call
/// (e.g. from tests) is silently ignored.
pub fn init_metrics() {
    let builder = PrometheusBuilder::new();
    match builder.install_recorder() {
        Ok(handle) => {
            let _ = PROMETHEUS_HANDLE.set(handle);
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to install prometheus recorder");
        }
    }
    CONTROL_BUDGET_METRICS_INITIALIZED.get_or_init(seed_control_budget_metrics);
}

/// Emits `sekisho_build_info{version, git_commit} 1`, a constant gauge
/// that lets dashboards filter by build. Called once at daemon start.
pub fn record_build_info() {
    let version = env!("CARGO_PKG_VERSION");
    let git_commit = option_env!("SEKISHO_GIT_SHA").unwrap_or("unknown");
    gauge!(
        "sekisho_build_info",
        "version" => version.to_string(),
        "git_commit" => git_commit.to_string()
    )
    .set(1.0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn metric_labels(rendered: &str, name: &str) -> std::collections::BTreeSet<String> {
        rendered
            .lines()
            .filter_map(|line| {
                let rest = line.strip_prefix(&format!("{name}{{budget=\""))?;
                let (budget, _) = rest.split_once("\"}")?;
                Some(budget.to_owned())
            })
            .collect()
    }

    fn metric_occurrences(rendered: &str, name: &str) -> usize {
        rendered
            .lines()
            .filter(|line| {
                *line == format!("# TYPE {name} gauge")
                    || line.starts_with(&format!("# HELP {name} "))
                    || line.starts_with(&format!("{name} "))
            })
            .count()
    }

    async fn response_text(response: Response<Body>) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("metrics body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("metrics utf8")
    }

    #[test]
    fn control_budget_seed_has_closed_asymmetric_label_sets() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _recorder_guard = metrics::set_default_local_recorder(&recorder);
        seed_control_budget_metrics_for_test();

        let rendered = handle.render();
        assert!(rendered.contains("# TYPE sekisho_control_budget_in_flight gauge"));
        assert!(rendered.contains("# HELP sekisho_control_budget_in_flight "));
        assert!(rendered.contains("# TYPE sekisho_control_budget_limit gauge"));
        assert!(rendered.contains("# HELP sekisho_control_budget_limit "));
        assert!(rendered.contains("# TYPE sekisho_control_budget_rejected_total counter"));
        assert!(rendered.contains("# HELP sekisho_control_budget_rejected_total "));
        assert_eq!(
            metric_labels(&rendered, CONTROL_BUDGET_IN_FLIGHT),
            [
                "challenge",
                "management",
                "probe",
                "proxy_http",
                "proxy_websocket",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert_eq!(
            metric_labels(&rendered, CONTROL_BUDGET_LIMIT),
            [
                "challenge",
                "management",
                "probe",
                "proxy_http",
                "proxy_websocket",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert_eq!(
            metric_labels(&rendered, CONTROL_BUDGET_REJECTED),
            ["acme_queue", "challenge", "probe", "proxy_websocket"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
    }

    #[test]
    fn durable_block_has_stable_newlines_and_one_complete_family_each() {
        let snapshot = crate::store::backend::AcmeBudgetSnapshot {
            queue_active: 2,
            queue_capacity: 7,
            issuance_in_progress: 1,
        };
        for prefix in [
            "process_metric 1".to_owned(),
            "process_metric 1\n".to_owned(),
        ] {
            let mut rendered = prefix;
            append_durable_acme_metrics(&mut rendered, snapshot, 3);
            assert!(rendered.starts_with("process_metric 1\n# HELP"));
            assert!(!rendered.starts_with("process_metric 1\n\n"));
            assert!(rendered.ends_with('\n'));
            for name in [
                ACME_QUEUE_ACTIVE,
                ACME_QUEUE_CAPACITY,
                ACME_ISSUANCE_IN_PROGRESS,
                ACME_ISSUANCE_LIMIT,
            ] {
                assert_eq!(metric_occurrences(&rendered, name), 3);
            }
            assert!(rendered.contains("sekisho_acme_queue_active 2\n"));
            assert!(rendered.contains("sekisho_acme_queue_capacity 7\n"));
            assert!(rendered.contains("sekisho_acme_issuance_in_progress 1\n"));
            assert!(rendered.contains("sekisho_acme_issuance_limit 3\n"));
        }
    }

    #[tokio::test]
    async fn durable_snapshot_success_and_failure_are_response_local_and_atomic() {
        init_metrics();
        let healthy = crate::store::Store::new_for_test("sqlite::memory:", [0x61; 32], None)
            .await
            .unwrap();
        let degraded = crate::store::Store::new_for_test_degraded("metrics-test")
            .await
            .unwrap();
        let (healthy_response, degraded_response) = tokio::join!(
            durable_acme_metrics_handler(healthy, 4),
            durable_acme_metrics_handler(degraded, 4),
        );
        let healthy_response = healthy_response.unwrap();
        let degraded_response = degraded_response.unwrap();
        assert_eq!(healthy_response.status(), StatusCode::OK);
        assert_eq!(degraded_response.status(), StatusCode::OK);
        let healthy = response_text(healthy_response).await;
        let degraded = response_text(degraded_response).await;
        for name in [
            ACME_QUEUE_ACTIVE,
            ACME_QUEUE_CAPACITY,
            ACME_ISSUANCE_IN_PROGRESS,
            ACME_ISSUANCE_LIMIT,
        ] {
            assert_eq!(metric_occurrences(&healthy, name), 3);
            assert_eq!(metric_occurrences(&degraded, name), 0);
        }
        assert!(healthy.contains("sekisho_acme_queue_capacity 1000\n"));
        assert!(healthy.contains("sekisho_acme_issuance_limit 4\n"));
        assert!(degraded.contains(CONTROL_BUDGET_IN_FLIGHT));
    }

    #[tokio::test]
    async fn response_body_observer_records_eof_and_drop_once() {
        init_metrics();
        let route = format!("already-eof-{}", uuid::Uuid::new_v4());
        let mut eof = ObservedResponseBody::new(Body::empty(), route.clone(), "299".into());
        assert!(
            eof.recorded,
            "an already-complete body records at construction"
        );
        assert!(eof.frame().await.is_none());
        assert!(eof.recorded);
        drop(eof);

        let rendered = metrics_handler()
            .await
            .expect("metrics")
            .into_body()
            .collect()
            .await
            .expect("metrics body")
            .to_bytes();
        let rendered = std::str::from_utf8(&rendered).expect("utf8 metrics");
        assert_eq!(
            rendered
                .lines()
                .filter(|line| {
                    line.starts_with("sekisho_proxy_response_body_duration_seconds_count")
                        && line.contains("outcome=\"eof\"")
                        && line.contains(&format!("route=\"{route}\""))
                        && line.contains("status=\"299\"")
                        && line.ends_with(" 1")
                })
                .count(),
            1,
            "already-complete body must record eof exactly once"
        );
        assert!(
            rendered.lines().all(|line| {
                !line.contains("outcome=\"dropped\"")
                    || !line.contains(&format!("route=\"{route}\""))
                    || !line.contains("status=\"299\"")
            }),
            "dropping an already-complete body must not record dropped"
        );
    }

    #[tokio::test]
    async fn middleware_exports_split_header_and_body_metrics() {
        init_metrics();
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(metrics_middleware));
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .expect("response");
        response.into_body().collect().await.expect("body");

        let rendered = PROMETHEUS_HANDLE.get().expect("metrics handle").render();
        assert!(rendered.contains("sekisho_proxy_requests_total"));
        assert!(rendered.contains("sekisho_proxy_response_headers_duration_seconds"));
        assert!(rendered.contains("sekisho_proxy_response_body_duration_seconds"));
        assert!(rendered.contains("outcome=\"eof\""));
        assert!(!rendered.contains("sekisho_proxy_request_duration_seconds"));
    }
}
