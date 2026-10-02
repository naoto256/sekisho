//! Graceful shutdown coordination for the sekishod daemon.
//!
//! A single [`ShutdownController`] is built inside `runtime::run`,
//! before its consumers are constructed or spawned, and shared with
//! subsystems that need to stop cleanly by cloning the `Arc`:
//!
//! * No-TLS proxy server (dev mode) — takes a
//!   [`ShutdownController::wait`] future and hands it to
//!   `axum::serve(...).with_graceful_shutdown(...)`.
//! * TLS accept loops (mgmt API and TLS proxy) — take a late-safe
//!   [`ShutdownSignal`] and multiplex accept + shutdown in one
//!   `tokio::select!` inside `serve_tls`.
//! * Background periodic tasks (session cleanup, ACME election, cert
//!   renewal, staleness checks) via [`spawn_periodic`] — take a
//!   [`ShutdownSignal`] used to race the `initial_delay` sleep and each
//!   inter-tick wait; register their
//!   [`JoinHandle`] via
//!   [`ShutdownController::track_task`] so the drain path can join on
//!   them within a supplied budget.
//! * WebSocket tunnels — increment / decrement
//!   [`ShutdownController::ws_guard`] at spawn / end so the drain path
//!   can poll the counter within a supplied budget.
//!
//! The controller carries an "are we shutting down?" flag readable via
//! [`ShutdownController::is_shutting_down`]. The management-API `/readyz`
//! handler receives the same `Arc<ShutdownController>` through an
//! `axum::Extension` and reads the flag to flip readiness to `false` as
//! soon as the drain begins, so the external load balancer can stop
//! sending new connections while in-flight requests finish.
//!
//! Lifetime: one controller per daemon run. There is no process-global
//! fallback and no free-function accessor — any subsystem that needs to
//! observe or signal shutdown must receive an `Arc` clone (or a
//! [`ShutdownSignal`]) at construction / spawn time. Detached tasks
//! that never take a clone are outside this coordination surface.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Total time from SIGTERM to forced exit. Must stay in sync with
/// `TimeoutStopSec` in `debian/sekishod.service`; if that timer fires
/// first, systemd escalates to SIGKILL and we lose the clean-exit
/// audit event.
pub const HARD_DEADLINE: Duration = Duration::from_secs(90);

/// Maximum time spent joining fixed listener tasks before unfinished
/// listeners are aborted.
pub const HTTP_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time spent polling registered WebSocket guards during the
/// drain phase. If guards remain, shutdown continues; this timeout
/// does not abort their tasks.
pub const WS_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-run shutdown state. See module docs.
pub struct ShutdownController {
    /// Set to `true` as soon as a shutdown signal arrives. Any holder of
    /// an `Arc<ShutdownController>` reads it via
    /// [`ShutdownController::is_shutting_down`] — the management API
    /// wires its `axum::Extension` clone into `/readyz`.
    shutting_down: AtomicBool,
    /// Watch channel that carries the "please stop" signal.
    tx: watch::Sender<bool>,
    /// Count of live WebSocket tunnels. Incremented when
    /// `handle_websocket` spawns its bidirectional copy, decremented
    /// when that copy returns. Used by [`ShutdownController::drain_websockets`]
    /// to poll-wait rather than tracking every `JoinHandle`.
    ws_inflight: AtomicUsize,
    /// Background tasks (cleanup / election / renewal / etc.) that we
    /// want to join on shutdown so their final audit-event log line lands
    /// before the process exits. `Some` is the open registry; the drain
    /// atomically takes it to `None`, after which late registrations are
    /// aborted instead of becoming detached.
    tracked_tasks: std::sync::Mutex<Option<Vec<JoinHandle<()>>>>,
}

impl ShutdownController {
    pub(crate) fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self {
            shutting_down: AtomicBool::new(false),
            tx,
            ws_inflight: AtomicUsize::new(0),
            tracked_tasks: std::sync::Mutex::new(Some(Vec::new())),
        }
    }

    /// Fast "is the daemon draining?" check. Cheap (a relaxed atomic
    /// load) so it's safe to call on the request hot path.
    ///
    /// Primary consumer is the management API `/readyz` handler, which
    /// reads it via the `Arc<ShutdownController>` injected as an
    /// `axum::Extension` and flips to 503 as soon as this reads `true`,
    /// letting the LB drain connections.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Relaxed)
    }

    /// Flip the shutdown flag and update the watch channel. Idempotent
    /// — a double signal (SIGTERM then SIGINT) collapses to a single
    /// drain sequence instead of racing two shutdowns.
    pub fn signal(&self) {
        if !self.shutting_down.swap(true, Ordering::SeqCst) {
            // `send_replace` stores the value even when no receivers
            // exist. `send` would return `Err` in that case and leave
            // the stored value stale — a later `wait()` (which reads
            // its current value before waiting) would then miss a flip
            // that landed before subscription.
            self.tx.send_replace(true);
        }
    }

    /// Wait for shutdown. If `signal()` already fired, the future
    /// resolves immediately.
    pub fn wait(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut signal = self.subscribe();
        async move { signal.wait().await }
    }

    /// Create a late-safe signal handle for a caller that needs to
    /// select shutdown against other work.
    pub(crate) fn subscribe(&self) -> ShutdownSignal {
        ShutdownSignal {
            rx: self.tx.subscribe(),
        }
    }

    /// Register a WebSocket tunnel so the drain path can wait for it.
    /// Returns a guard whose `Drop` decrements the counter — callers
    /// just bind it for the lifetime of the tunnel, no manual
    /// bookkeeping. The guard is fire-and-forget: if the tunnel task
    /// is dropped (panic, cancellation) the counter still unwinds.
    pub fn ws_guard(self: &Arc<Self>) -> WsGuard {
        self.ws_inflight.fetch_add(1, Ordering::SeqCst);
        WsGuard { ctl: self.clone() }
    }

    /// Current count of live WebSocket tunnels. Exposed for tests and
    /// observability; the drain loop uses it internally to decide
    /// when to give up waiting.
    pub fn ws_inflight(&self) -> usize {
        self.ws_inflight.load(Ordering::SeqCst)
    }

    /// Track a long-lived background task so the drain path can join
    /// on it. Only call with tasks that honour the shutdown signal.
    /// Registration after the one-shot drain has started, or against
    /// a poisoned registry, aborts the task immediately.
    pub fn track_task(&self, handle: JoinHandle<()>) {
        match self.tracked_tasks.lock() {
            Ok(mut guard) => match guard.as_mut() {
                Some(handles) => handles.push(handle),
                None => handle.abort(),
            },
            Err(_) => handle.abort(),
        }
    }

    #[cfg(test)]
    pub(crate) fn tracked_task_count(&self) -> usize {
        self.tracked_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map_or(0, Vec::len)
    }

    /// Take and join every tracked background task, bounded by `budget`.
    /// Unfinished tasks are explicitly aborted and awaited before this
    /// method returns.
    pub async fn join_tracked_tasks(&self, budget: Duration) {
        let handles: Vec<JoinHandle<()>> = {
            let mut guard = match self.tracked_tasks.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.take().unwrap_or_default()
        };
        join_tasks(handles, budget, "background").await;
    }

    /// Wait for all in-flight WebSocket tunnels to close, bounded by
    /// `budget`. Returns the number of tunnels still live when the
    /// wait ended — `0` means a clean drain.
    pub async fn drain_websockets(&self, budget: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + budget;
        while self.ws_inflight() > 0 {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            // 100ms poll interval: short enough that a cluster of tunnels
            // closing together doesn't add more than ~100ms latency, long
            // enough to not spin a core on the atomic load.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.ws_inflight()
    }
}

/// A shutdown subscription that always checks the channel's current
/// value before waiting for a change. This prevents a signal sent before
/// subscription from being lost.
pub(crate) struct ShutdownSignal {
    rx: watch::Receiver<bool>,
}

impl ShutdownSignal {
    pub(crate) async fn wait(&mut self) {
        if *self.rx.borrow() {
            return;
        }
        let _ = self.rx.changed().await;
    }
}

/// Join a fixed group of tasks within `budget`. Once the deadline
/// expires, abort and await every remaining task so none is detached.
pub(crate) async fn join_tasks(
    mut handles: Vec<JoinHandle<()>>,
    budget: Duration,
    group: &'static str,
) {
    let deadline = tokio::time::Instant::now() + budget;
    let mut completed = 0;

    while completed < handles.len() {
        match tokio::time::timeout_at(deadline, &mut handles[completed]).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if error.is_cancelled() => {}
            Ok(Err(error)) => {
                tracing::warn!(task_group = group, error = %error, "task failed during shutdown");
            }
            Err(_) => break,
        }
        completed += 1;
    }

    if completed == handles.len() {
        return;
    }

    tracing::warn!(
        task_group = group,
        budget_ms = budget.as_millis() as u64,
        remaining = handles.len() - completed,
        "tasks did not finish within budget; aborting"
    );
    for handle in &handles[completed..] {
        handle.abort();
    }
    for handle in handles.into_iter().skip(completed) {
        let _ = handle.await;
    }
}

/// RAII guard for a WebSocket tunnel. Decrements the in-flight counter
/// when dropped — see [`ShutdownController::ws_guard`].
pub struct WsGuard {
    ctl: Arc<ShutdownController>,
}

impl Drop for WsGuard {
    fn drop(&mut self) {
        self.ctl.ws_inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Knobs for [`spawn_periodic`]. Defaults match the most common shape
/// (immediate first tick, no pre-loop delay); the cert-cache and DEK
/// ring tasks set `skip_first_tick = true` because startup already
/// loaded those caches and the ACME renewal task uses
/// `initial_delay = Some(60s)` to avoid hammering Let's Encrypt the
/// instant the daemon comes up.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeriodicOpts {
    /// Sleep this long *before* the interval starts. Bypassed cleanly
    /// if a shutdown signal lands during the wait — the helper races
    /// the sleep against a late-safe [`ShutdownSignal`]. Used by
    /// the ACME renewal task so it doesn't fire a renewal pass at
    /// boot time.
    pub initial_delay: Option<Duration>,
    /// `tokio::time::interval` resolves the first `tick().await`
    /// immediately. For most tasks that's desirable (run once at
    /// startup, then on the cadence). For cache-staleness checks the
    /// startup already populated the cache — the immediate tick would
    /// just produce a noisy reload-of-nothing. Setting this to `true`
    /// consumes that auto-immediate first tick before entering the
    /// loop.
    pub skip_first_tick: bool,
}

/// Spawn a long-lived background tick that:
/// 1. Optionally sleeps `initial_delay` first, racing the sleep against
///    the shutdown signal.
/// 2. Drives a `tokio::time::interval(period)` loop, racing each
///    inter-tick wait against the shutdown signal.
/// 3. Once a tick fires, the `tick` body is not directly raced against
///    shutdown and normally runs to completion. If the tracked-task
///    join budget expires, the controller aborts the task.
/// 4. Registers its `JoinHandle` with the controller so
///    [`ShutdownController::join_tracked_tasks`] can wait for it.
///
/// `name` is emitted as `task = <name>` on the `"periodic tick fired"`
/// trace event; no other consumer today.
///
/// The sites collapse to one line per tick:
///
/// ```ignore
/// spawn_periodic(&shutdown_ctl, "cert-cache.stale", Duration::from_secs(60),
///     PeriodicOpts { skip_first_tick: true, ..Default::default() },
///     move || {
///         let resolver = stale_resolver.clone();
///         async move {
///             if let Err(e) = resolver.reload_if_stale().await {
///                 tracing::warn!(error = %e, "cert-cache staleness check failed");
///             }
///         }
///     });
/// ```
pub fn spawn_periodic<F, Fut>(
    ctl: &Arc<ShutdownController>,
    name: &'static str,
    period: Duration,
    opts: PeriodicOpts,
    mut tick: F,
) where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut shutdown = ctl.subscribe();
    let handle = tokio::spawn(async move {
        if let Some(delay) = opts.initial_delay {
            // Race the pre-loop delay against shutdown — otherwise a
            // SIGTERM landing during a long initial_delay (e.g. the
            // 60s warmup on the renewal task) would block the drain
            // for the remainder of the sleep.
            tokio::select! {
                biased;
                _ = shutdown.wait() => return,
                _ = tokio::time::sleep(delay) => {}
            }
        }
        let mut interval = tokio::time::interval(period);
        if opts.skip_first_tick {
            // tokio::time::interval's first tick resolves immediately.
            // For cache-staleness checks startup already populated the
            // cache, so we consume that first tick instead of doing a
            // pointless reload-of-nothing.
            interval.tick().await;
        }
        loop {
            tokio::select! {
                biased;
                _ = shutdown.wait() => return,
                _ = interval.tick() => {}
            }
            tracing::trace!(task = name, "periodic tick fired");
            tick().await;
        }
    });
    ctl.track_task(handle);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn new_controller() -> Arc<ShutdownController> {
        Arc::new(ShutdownController::new())
    }

    #[tokio::test]
    async fn signal_flips_flag_and_wakes_subscribers() {
        let ctl = new_controller();
        assert!(!ctl.is_shutting_down());

        let wait = ctl.wait();
        let handle = tokio::spawn(wait);

        ctl.signal();
        assert!(ctl.is_shutting_down());
        // Subscriber should resolve promptly.
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("wait() did not resolve after signal")
            .expect("join");
    }

    #[tokio::test]
    async fn signal_is_idempotent() {
        let ctl = new_controller();
        ctl.signal();
        ctl.signal(); // Must not panic / deadlock on a second flip.
        assert!(ctl.is_shutting_down());
    }

    #[tokio::test]
    async fn late_subscriber_sees_already_shutdown_state() {
        let ctl = new_controller();
        ctl.signal();
        // Subscribing *after* signal() must still resolve — otherwise a
        // task spawned during the drain window would hang forever.
        tokio::time::timeout(Duration::from_millis(100), ctl.wait())
            .await
            .expect("late subscriber should observe shutdown");
    }

    #[tokio::test]
    async fn late_shutdown_signal_sees_already_shutdown_state() {
        let ctl = new_controller();
        ctl.signal();
        let mut signal = ctl.subscribe();

        tokio::time::timeout(Duration::from_millis(100), signal.wait())
            .await
            .expect("late ShutdownSignal should observe shutdown");
    }

    #[tokio::test]
    async fn ws_guard_tracks_inflight_count() {
        let ctl = new_controller();
        assert_eq!(ctl.ws_inflight(), 0);
        {
            let _g1 = ctl.ws_guard();
            let _g2 = ctl.ws_guard();
            assert_eq!(ctl.ws_inflight(), 2);
        }
        assert_eq!(ctl.ws_inflight(), 0);
    }

    #[tokio::test]
    async fn drain_websockets_returns_zero_on_clean_drain() {
        let ctl = new_controller();
        let guard = ctl.ws_guard();
        let ctl2 = ctl.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(guard);
            // Silence unused warning on ctl2 in some builds.
            let _ = ctl2.ws_inflight();
        });
        let remaining = ctl.drain_websockets(Duration::from_secs(1)).await;
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn drain_websockets_times_out_with_stuck_tunnel() {
        let ctl = new_controller();
        let _stuck = ctl.ws_guard();
        let remaining = ctl.drain_websockets(Duration::from_millis(150)).await;
        assert_eq!(remaining, 1, "stuck tunnel should still be reported");
    }

    #[tokio::test]
    async fn join_tracked_tasks_waits_for_clean_exit() {
        let ctl = new_controller();
        let counter = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let c = counter.clone();
            ctl.track_task(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                c.fetch_add(1, Ordering::SeqCst);
            }));
        }
        ctl.join_tracked_tasks(Duration::from_secs(2)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn join_tracked_tasks_uses_one_budget_and_aborts_every_remaining_task() {
        struct DropFlag(Arc<AtomicUsize>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let ctl = new_controller();
        let dropped = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let task_dropped = dropped.clone();
            let task_completed = completed.clone();
            ctl.track_task(tokio::spawn(async move {
                let _drop_flag = DropFlag(task_dropped);
                tokio::time::sleep(Duration::from_secs(5)).await;
                task_completed.fetch_add(1, Ordering::SeqCst);
            }));
        }

        let budget = Duration::from_millis(150);
        let started = tokio::time::Instant::now();
        ctl.join_tracked_tasks(budget).await;
        assert!(
            started.elapsed() < budget + Duration::from_millis(150),
            "task budgets were applied serially instead of once to the group"
        );
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            3,
            "every timed-out task must be dropped before join returns"
        );
        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "an aborted task ran its post-wait side effect"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "an aborted task remained detached after join returned"
        );
    }

    #[tokio::test]
    async fn tracked_task_registered_after_drain_is_cancelled() {
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let ctl = new_controller();
        ctl.join_tracked_tasks(Duration::from_millis(10)).await;

        let dropped = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicUsize::new(0));
        let drop_flag = DropFlag(dropped.clone());
        let task_completed = completed.clone();
        ctl.track_task(tokio::spawn(async move {
            let _drop_flag = drop_flag;
            tokio::time::sleep(Duration::from_secs(5)).await;
            task_completed.fetch_add(1, Ordering::SeqCst);
        }));

        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late task was not cancelled");
        assert_eq!(completed.load(Ordering::SeqCst), 0);
    }

    /// End-to-end check that `ShutdownController::wait` plugs into
    /// `axum::serve`'s `with_graceful_shutdown` and lets an in-flight
    /// handler finish instead of tearing the connection down. Covers
    /// the "regression that would re-introduce the 502 window on
    /// `systemctl restart`" case.
    #[tokio::test]
    async fn axum_server_drains_in_flight_request_on_signal() {
        use axum::Router;
        use axum::routing::get;
        use std::sync::atomic::AtomicBool;

        let ctl = new_controller();
        let handler_reached = Arc::new(AtomicBool::new(false));
        let handler_completed = Arc::new(AtomicBool::new(false));

        let hr = handler_reached.clone();
        let hc = handler_completed.clone();
        let app = Router::new().route(
            "/slow",
            get(move || {
                let hr = hr.clone();
                let hc = hc.clone();
                async move {
                    hr.store(true, Ordering::SeqCst);
                    // Slower than the time the client takes to send the
                    // request but faster than the test's outer timeout
                    // — exercises the drain path without flake risk.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    hc.store(true, Ordering::SeqCst);
                    "ok"
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = ctl.wait();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await;
        });

        // Client fires a request in parallel; once the server confirms
        // it landed in the handler, we trigger shutdown. A correctly
        // wired `with_graceful_shutdown` must let the handler run to
        // completion and return the response body — an early tear-down
        // would drop the connection and the client would see an error.
        let client = tokio::spawn(async move {
            let body = reqwest::get(format!("http://{addr}/slow"))
                .await
                .expect("connect")
                .text()
                .await
                .expect("body");
            assert_eq!(body, "ok");
        });

        // Wait for the handler to actually start before signalling. Poll
        // rather than sleep so this test is fast on a healthy build.
        let handler_start_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !handler_reached.load(Ordering::SeqCst) {
            if tokio::time::Instant::now() >= handler_start_deadline {
                panic!("handler never reached");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        ctl.signal();

        // Both must finish cleanly: the handler body completes, the
        // client reads the response, and the server task exits.
        tokio::time::timeout(Duration::from_secs(5), client)
            .await
            .expect("client timed out — connection likely torn down by shutdown")
            .expect("client panicked");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server did not exit after shutdown signal")
            .expect("server panicked");
        assert!(
            handler_completed.load(Ordering::SeqCst),
            "handler was cut off mid-flight"
        );
    }

    #[tokio::test]
    async fn spawn_periodic_runs_tick_and_exits_on_signal() {
        // Default opts (no skip-first, no initial_delay) → first tick
        // fires immediately and at least one body invocation lands
        // before we signal. Tests the happy path: helper registers the
        // task, ticks fire, shutdown unwinds cleanly.
        let ctl = new_controller();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        spawn_periodic(
            &ctl,
            "test.tick",
            Duration::from_millis(20),
            PeriodicOpts::default(),
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        // Let a couple of ticks land.
        tokio::time::sleep(Duration::from_millis(100)).await;
        ctl.signal();
        ctl.join_tracked_tasks(Duration::from_secs(1)).await;
        let runs = counter.load(Ordering::SeqCst);
        assert!(runs >= 2, "expected >=2 ticks, got {runs}");
    }

    #[tokio::test]
    async fn spawn_periodic_skip_first_tick_does_not_fire_immediately() {
        // skip_first_tick → the auto-immediate tick is consumed before
        // the loop, so a body shouldn't run for at least `period`. We
        // signal shutdown well within that period and verify the body
        // never ran.
        let ctl = new_controller();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        spawn_periodic(
            &ctl,
            "test.skip-first",
            Duration::from_secs(30),
            PeriodicOpts {
                skip_first_tick: true,
                ..Default::default()
            },
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        // Let the spawn settle; with skip_first_tick the body must
        // not have executed yet.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "skip_first_tick should suppress the immediate first tick"
        );
        ctl.signal();
        ctl.join_tracked_tasks(Duration::from_secs(1)).await;
        // Still zero — we never waited the full 30s period.
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn spawn_periodic_after_signal_runs_no_tick() {
        let ctl = new_controller();
        ctl.signal();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();

        spawn_periodic(
            &ctl,
            "test.pre-signalled",
            Duration::from_millis(1),
            PeriodicOpts::default(),
            move || {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        ctl.join_tracked_tasks(Duration::from_secs(1)).await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "pre-signalled periodic task must not run its immediate tick"
        );
    }

    #[tokio::test]
    async fn spawn_periodic_initial_delay_aborts_on_shutdown() {
        // initial_delay much longer than the test budget: the helper
        // must race the sleep against shutdown so signalling within the
        // delay returns the task immediately, instead of blocking the
        // drain for the remainder of the sleep.
        let ctl = new_controller();
        let ran = Arc::new(AtomicUsize::new(0));
        let r = ran.clone();
        spawn_periodic(
            &ctl,
            "test.initial-delay",
            Duration::from_secs(60),
            PeriodicOpts {
                initial_delay: Some(Duration::from_secs(60)),
                ..Default::default()
            },
            move || {
                let r = r.clone();
                async move {
                    r.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        ctl.signal();
        // Must drain quickly, well under the 60s initial_delay.
        let start = tokio::time::Instant::now();
        ctl.join_tracked_tasks(Duration::from_secs(1)).await;
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "body must not run if shutdown lands in initial_delay"
        );
    }
}
