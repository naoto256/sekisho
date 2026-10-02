//! Leader-side queue processor for ACME issuance.
//!
//! Every node parks `POST /certs` requests in `acme_queue` and hands
//! 202 back to the caller. This module is the other half: the leader's
//! background tick pulls the oldest pending rows, runs the ACME orders,
//! and writes the results back for requesters to poll.
//!
//! Each polling tick reserves at most the configured number of durable
//! `in_progress` rows and runs those orders concurrently. The database
//! queue remains the admission and ordering authority; the limit does
//! not claim external ACME calls are exactly-once before fencing exists.

use crate::error::Result;
use crate::shutdown::{self, PeriodicOpts, ShutdownController};
use crate::store::Store;
use crate::tls::acme::AcmeManager;
use crate::tls::resolver::CertResolver;
use acme_core::ChallengeProvider;
use std::sync::Arc;

/// Nominal interval between polls in the spawned loop. Scheduling,
/// an in-flight order, and DB or network work can delay later polls.
pub const QUEUE_TICK_INTERVAL_SECS: u64 = 5;

/// Age after which an `in_progress` row becomes eligible for recycling
/// by a later pick. This cutoff is not a bound on retry latency.
pub const QUEUE_STALE_AFTER_MINUTES: i64 = 10;

/// Spawn the leader queue processor.
///
/// The polling task is registered with the runtime shutdown
/// controller. Each tick calls `process_batch`, which honors either
/// the configured leader pin or the automatic election row.
pub fn spawn_tick<C>(
    shutdown_ctl: &Arc<ShutdownController>,
    store: Store,
    acme: Arc<AcmeManager<C>>,
    resolver: Arc<CertResolver>,
    concurrency_limit: u32,
) where
    C: ChallengeProvider + Send + Sync + 'static,
{
    spawn_queue_loop(
        shutdown_ctl,
        std::time::Duration::from_secs(QUEUE_TICK_INTERVAL_SECS),
        move || {
            let store = store.clone();
            let acme = acme.clone();
            let resolver = resolver.clone();
            async move {
                if let Err(e) = process_batch(&store, &acme, &resolver, concurrency_limit).await {
                    tracing::warn!(error = %e, "ACME queue tick failed");
                }
            }
        },
    );
}

fn spawn_queue_loop<F, Fut>(
    shutdown_ctl: &Arc<ShutdownController>,
    period: std::time::Duration,
    tick: F,
) where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    shutdown::spawn_periodic(
        shutdown_ctl,
        "acme.queue",
        period,
        PeriodicOpts {
            // Drop the immediate first tick — the API listeners may
            // not have finished binding yet when this task starts, and
            // the election row might not exist. The first scheduled
            // poll is nominally one interval later.
            skip_first_tick: true,
            ..Default::default()
        },
        tick,
    );
}

/// Run one tick. Extracted so tests can drive the processor
/// deterministically without spinning up the timer loop.
///
/// Handles at most one row under a one-slot durable bound. DB errors from the leader read, row pick,
/// or completed/failed status write propagate. An issuance error is
/// recorded on the row and logged; a resolver reload error is logged
/// and the successfully issued row is still marked completed.
#[cfg(test)]
pub async fn process_once<C>(
    store: &Store,
    acme: &Arc<AcmeManager<C>>,
    resolver: &Arc<CertResolver>,
) -> Result<()>
where
    C: ChallengeProvider + Send + Sync + 'static,
{
    process_batch(store, acme, resolver, 1).await
}

async fn process_batch<C>(
    store: &Store,
    acme: &Arc<AcmeManager<C>>,
    resolver: &Arc<CertResolver>,
    concurrency_limit: u32,
) -> Result<()>
where
    C: ChallengeProvider + Send + Sync + 'static,
{
    // Manual and renewal callers only enqueue. The worker is therefore the
    // sole production order starter and must honor both leader modes.
    if acme.leader_check().await?.is_err() {
        return Ok(());
    }

    let stale_after = chrono::Duration::minutes(QUEUE_STALE_AFTER_MINUTES);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..concurrency_limit {
        let Some(row) = store
            .acme_queue_pick_next(stale_after, concurrency_limit)
            .await?
        else {
            break;
        };
        let store = store.clone();
        let acme = Arc::clone(acme);
        let resolver = Arc::clone(resolver);
        tasks.spawn(async move { process_row(&store, &acme, &resolver, row).await });
    }

    #[cfg(test)]
    let result = drain_task_results(&mut tasks, acme.test_drain_error_hook()).await;
    #[cfg(not(test))]
    let result = drain_task_results(&mut tasks).await;
    result
}

async fn drain_task_results(
    tasks: &mut tokio::task::JoinSet<Result<()>>,
    #[cfg(test)] first_error_hook: Option<crate::tls::acme::TestDrainErrorHook>,
) -> Result<()> {
    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        let result = match result {
            Ok(result) => result,
            Err(error) => Err(crate::error::Error::Internal(error.to_string())),
        };
        if let Err(error) = result
            && first_error.is_none()
        {
            first_error = Some(error);
            #[cfg(test)]
            if let Some(hook) = &first_error_hook {
                hook();
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn process_row<C>(
    store: &Store,
    acme: &Arc<AcmeManager<C>>,
    resolver: &Arc<CertResolver>,
    row: crate::models::acme_queue::AcmeQueueRow,
) -> Result<()>
where
    C: ChallengeProvider + Send + Sync + 'static,
{
    tracing::info!(
        target: crate::audit::TARGET,
        event = "cert.issue.queue.picked",
        category = "system",
        result = "in_progress",
        actor_type = "system",
        actor_id = "system",
        target_resource = "cert_queue",
        target_id = %row.id,
        domain = %row.domain,
        requester_node = %row.requester_node,
        action = "pick",
        "leader picked ACME queue row"
    );

    match acme.issue_certificate_unchecked(&row.domain).await {
        Ok(cert) => {
            // Attempt a local reload. A top-level reload error is logged
            // and processing continues to mark the row completed. The
            // new cert is used locally only if its row is loaded; peers
            // make their own later version-triggered reload attempts.
            if let Err(e) = resolver.reload().await {
                tracing::error!(
                    domain = %row.domain,
                    error = %e,
                    "failed to reload cert resolver after queued issuance"
                );
            }
            if let Err(e) = store.acme_queue_mark_completed(row.id, cert.id).await {
                tracing::error!(
                    queue_id = %row.id,
                    cert_id = %cert.id,
                    error = %e,
                    "failed to mark ACME queue row completed; cert was issued"
                );
                return Err(e);
            }
            tracing::info!(
                target: crate::audit::TARGET,
                event = "cert.issue.queue.completed",
                category = "system",
                result = "success",
                actor_type = "system",
                actor_id = "system",
                target_resource = "cert_queue",
                target_id = %row.id,
                cert_id = %cert.id,
                domain = %row.domain,
                action = "complete",
                "ACME queue row completed"
            );
        }
        Err(e) => {
            let msg = e.to_string();
            if let Err(mark_err) = store.acme_queue_mark_failed(row.id, &msg).await {
                tracing::error!(
                    queue_id = %row.id,
                    original_error = %msg,
                    mark_error = %mark_err,
                    "failed to mark ACME queue row failed"
                );
                return Err(mark_err);
            }
            tracing::warn!(
                target: crate::audit::TARGET,
                event = "cert.issue.queue.failed",
                category = "system",
                result = "failure",
                actor_type = "system",
                actor_id = "system",
                target_resource = "cert_queue",
                target_id = %row.id,
                domain = %row.domain,
                action = "fail",
                error = %msg,
                "ACME queue row failed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::acme_queue::AcmeQueueAdmission;
    use crate::models::acme_queue::AcmeQueueStatus;
    use crate::tls::acme::{ENV_NODE_ID, env_guard};

    const TEST_MASTER_KEY: [u8; 32] = [0u8; 32];

    async fn store() -> Store {
        Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .expect("store")
    }

    fn temp_store_path(tag: &str) -> String {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sekisho-acme-queue-{tag}-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        format!("sqlite:{}", path.display())
    }

    fn admitted(admission: AcmeQueueAdmission) -> crate::models::acme_queue::AcmeQueueRow {
        match admission {
            AcmeQueueAdmission::Inserted(row) | AcmeQueueAdmission::Existing(row) => row,
            AcmeQueueAdmission::Full => panic!("queue unexpectedly full"),
        }
    }

    /// A fresh enqueue for a new domain inserts a pending row.
    /// Re-enqueueing the same domain returns the existing id (dedupe).
    #[tokio::test]
    async fn enqueue_is_idempotent_per_domain() {
        let s = store().await;
        let a = admitted(
            s.acme_queue_enqueue("app.example", "node-a")
                .await
                .expect("first"),
        );
        assert_eq!(a.status, AcmeQueueStatus::Pending);

        let b = admitted(
            s.acme_queue_enqueue("app.example", "node-b")
                .await
                .expect("second"),
        );
        assert_eq!(a.id, b.id, "same domain should dedupe to one queue row");
        assert_eq!(
            b.requester_node, "node-a",
            "dedupe preserves the original requester"
        );

        // Different domain => different row.
        let c = admitted(
            s.acme_queue_enqueue("other.example", "node-a")
                .await
                .expect("third"),
        );
        assert_ne!(c.id, a.id);
    }

    /// Pick picks oldest-first and transitions to in_progress.
    #[tokio::test]
    async fn pick_moves_oldest_pending_to_in_progress() {
        let s = store().await;
        let first = admitted(s.acme_queue_enqueue("one.example", "node-a").await.unwrap());
        // Small sleep so the enqueued_at ordering is deterministic even
        // on a coarse clock.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let second = admitted(s.acme_queue_enqueue("two.example", "node-a").await.unwrap());

        let picked = s
            .acme_queue_pick_next(chrono::Duration::minutes(10), 2)
            .await
            .expect("pick")
            .expect("a row to pick");
        assert_eq!(picked.id, first.id);
        assert_eq!(picked.status, AcmeQueueStatus::InProgress);
        assert!(picked.picked_at.is_some());

        let picked2 = s
            .acme_queue_pick_next(chrono::Duration::minutes(10), 2)
            .await
            .expect("pick")
            .expect("second row");
        assert_eq!(picked2.id, second.id);

        // Queue drained — next pick returns None.
        let none = s
            .acme_queue_pick_next(chrono::Duration::minutes(10), 2)
            .await
            .expect("pick");
        assert!(none.is_none());
    }

    /// Stale in_progress rows re-enqueue on the next pick.
    #[tokio::test]
    async fn stale_in_progress_is_recovered() {
        let s = store().await;
        let row = admitted(
            s.acme_queue_enqueue("stale.example", "node-a")
                .await
                .unwrap(),
        );
        s.acme_queue_pick_next(chrono::Duration::minutes(10), 1)
            .await
            .unwrap();

        // Age the picked_at backwards past the stale window.
        let aged = (chrono::Utc::now() - chrono::Duration::minutes(30)).timestamp();
        sqlx::query("UPDATE acme_queue SET picked_at = ? WHERE id = ?")
            .bind(aged)
            .bind(row.id)
            .execute(s.sqlite_pool())
            .await
            .unwrap();

        // Next pick with a 10-minute stale window should find no
        // pending row first, flip the aged in_progress back to
        // pending, and then pick it — all in the same call.
        let repicked = s
            .acme_queue_pick_next(chrono::Duration::minutes(10), 1)
            .await
            .unwrap()
            .expect("stale row should re-enqueue");
        assert_eq!(repicked.id, row.id);
        assert_eq!(repicked.status, AcmeQueueStatus::InProgress);
    }

    #[tokio::test]
    async fn restart_residual_in_progress_consumes_the_durable_slot() {
        let path = temp_store_path("restart-slot");
        let first_id;
        {
            let store = Store::new_for_test(&path, TEST_MASTER_KEY, None)
                .await
                .unwrap();
            first_id = admitted(
                store
                    .acme_queue_enqueue("first.example", "node-a")
                    .await
                    .unwrap(),
            )
            .id;
            store
                .acme_queue_enqueue("second.example", "node-a")
                .await
                .unwrap();
            let picked = store
                .acme_queue_pick_next(chrono::Duration::minutes(10), 1)
                .await
                .unwrap()
                .expect("first durable slot");
            assert_eq!(picked.id, first_id);
            store.close().await;
        }

        let restarted = Store::new_for_test(&path, TEST_MASTER_KEY, None)
            .await
            .unwrap();
        let blocked = restarted
            .acme_queue_pick_next(chrono::Duration::minutes(10), 1)
            .await
            .unwrap();
        assert!(
            blocked.is_none(),
            "a non-stale row from the previous process must consume the slot"
        );
        restarted
            .acme_queue_mark_completed(first_id, uuid::Uuid::new_v4())
            .await
            .unwrap();
        assert!(
            restarted
                .acme_queue_pick_next(chrono::Duration::minutes(10), 1)
                .await
                .unwrap()
                .is_some(),
            "a completed row must release the durable slot"
        );
    }

    #[tokio::test]
    async fn process_batch_drains_siblings_after_one_status_write_fails() {
        let _g = env_guard().await;
        unsafe {
            std::env::set_var(ENV_NODE_ID, "node-batch");
        }
        let store = store().await;
        store
            .update_config(serde_json::json!({"acme_leader": "node-batch"}))
            .await
            .unwrap();
        let failed = admitted(
            store
                .acme_queue_enqueue("fail.example", "node-a")
                .await
                .unwrap(),
        );
        let completed = admitted(
            store
                .acme_queue_enqueue("complete.example", "node-a")
                .await
                .unwrap(),
        );
        sqlx::query(
            "CREATE TRIGGER reject_one_completion \
             BEFORE UPDATE OF status ON acme_queue \
             WHEN OLD.domain = 'fail.example' AND NEW.status = 'completed' \
             BEGIN SELECT RAISE(ABORT, 'forced completion failure'); END",
        )
        .execute(store.sqlite_pool())
        .await
        .unwrap();

        use crate::models::cert::{CertSource, Certificate};
        use crate::tls::acme::AcmeManager;
        use acme_core::{ChallengeProvider, ChallengeType, ProviderError};

        struct ControlledProvider;
        impl ChallengeProvider for ControlledProvider {
            fn challenge_type(&self) -> ChallengeType {
                ChallengeType::Http01
            }

            async fn set(
                &self,
                _domain: &str,
                _token: &str,
                _key_authorization: &str,
            ) -> std::result::Result<(), ProviderError> {
                panic!("test issuance hook must bypass ACME challenge setup");
            }

            async fn cleanup(&self, _domain: &str) -> std::result::Result<(), ProviderError> {
                panic!("test issuance hook must bypass ACME challenge cleanup");
            }
        }

        let drain_observed_error = Arc::new(tokio::sync::Notify::new());
        let sibling_gate = Arc::clone(&drain_observed_error);
        let acme = AcmeManager::new(
            store.clone(),
            Arc::new(ControlledProvider),
            "https://acme.example.invalid/directory",
            None,
        )
        .with_test_issue_hook(move |domain| {
            let sibling_gate = Arc::clone(&sibling_gate);
            async move {
                if domain == "complete.example" {
                    sibling_gate.notified().await;
                }
                let now = chrono::Utc::now();
                Ok(Certificate {
                    id: uuid::Uuid::new_v4(),
                    domain,
                    cert_pem: "test-cert".into(),
                    key_pem_encrypted: "test-key".into(),
                    issued_at: now,
                    expires_at: now + chrono::Duration::days(90),
                    source: CertSource::Acme,
                })
            }
        })
        .with_test_drain_error_hook({
            let drain_observed_error = Arc::clone(&drain_observed_error);
            move || drain_observed_error.notify_one()
        });
        let acme = Arc::new(acme);
        let resolver = Arc::new(CertResolver::new(store.clone()));

        let error = process_batch(&store, &acme, &resolver, 2)
            .await
            .expect_err("the status failure must propagate after the sibling completes");
        assert!(matches!(error, crate::error::Error::Database(_)));
        assert_eq!(
            store
                .acme_queue_get(completed.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            AcmeQueueStatus::Completed
        );
        assert_eq!(
            store
                .acme_queue_get(failed.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            AcmeQueueStatus::InProgress
        );
        unsafe {
            std::env::remove_var(ENV_NODE_ID);
        }
    }

    /// Completed rows record the cert id and stop appearing in picks.
    #[tokio::test]
    async fn mark_completed_closes_the_row() {
        let s = store().await;
        let row = admitted(
            s.acme_queue_enqueue("done.example", "node-a")
                .await
                .unwrap(),
        );
        s.acme_queue_pick_next(chrono::Duration::minutes(10), 1)
            .await
            .unwrap();

        let cert_id = uuid::Uuid::new_v4();
        s.acme_queue_mark_completed(row.id, cert_id).await.unwrap();

        let fetched = s.acme_queue_get(row.id).await.unwrap().expect("row");
        assert_eq!(fetched.status, AcmeQueueStatus::Completed);
        assert_eq!(fetched.result_cert_id, Some(cert_id));
        assert!(fetched.completed_at.is_some());

        // New enqueue for the same domain now goes through — the old
        // row is terminal, not "active".
        let fresh = admitted(
            s.acme_queue_enqueue("done.example", "node-a")
                .await
                .unwrap(),
        );
        assert_ne!(fresh.id, row.id);
    }

    /// `process_once` honors the configured leader pin: a different node
    /// does not pick or start an order.
    #[tokio::test]
    async fn process_once_respects_configured_leader_pin() {
        let _g = env_guard().await;
        unsafe {
            std::env::set_var(ENV_NODE_ID, "node-nonleader");
        }
        let s = store().await;
        s.update_config(serde_json::json!({"acme_leader": "node-other"}))
            .await
            .unwrap();

        // Enqueue something — it should stay pending because the pin names
        // a different node.
        s.acme_queue_enqueue("gate.example", "node-x")
            .await
            .unwrap();

        // Build an AcmeManager purely for `process_once` — the
        // provider is a panic so any accidental ACME path trips the
        // test rather than talking to Let's Encrypt.
        use crate::tls::acme::AcmeManager;
        use acme_core::{ChallengeProvider, ChallengeType, ProviderError};

        struct PanicProvider;
        impl ChallengeProvider for PanicProvider {
            fn challenge_type(&self) -> ChallengeType {
                ChallengeType::Http01
            }
            async fn set(
                &self,
                _d: &str,
                _t: &str,
                _k: &str,
            ) -> std::result::Result<(), ProviderError> {
                panic!("ChallengeProvider.set called on non-leader");
            }
            async fn cleanup(&self, _d: &str) -> std::result::Result<(), ProviderError> {
                panic!("ChallengeProvider.cleanup called on non-leader");
            }
        }

        let acme = Arc::new(AcmeManager::new(
            s.clone(),
            Arc::new(PanicProvider),
            "https://acme.example.invalid/directory",
            None,
        ));
        let resolver = Arc::new(CertResolver::new(s.clone()));

        process_once(&s, &acme, &resolver)
            .await
            .expect("non-leader tick should be ok");

        // Row stays pending — confirms we didn't accidentally pick.
        let rows = sqlx::query_scalar::<_, String>("SELECT status FROM acme_queue")
            .fetch_all(s.sqlite_pool())
            .await
            .unwrap();
        assert_eq!(rows, vec!["pending".to_string()]);

        unsafe {
            std::env::remove_var(ENV_NODE_ID);
        }
    }

    #[tokio::test]
    async fn queue_loop_preserves_delayed_first_poll_and_stops_on_shutdown() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let ctl = Arc::new(ShutdownController::new());
        let ticks = Arc::new(AtomicUsize::new(0));
        let observed = ticks.clone();
        spawn_queue_loop(&ctl, std::time::Duration::from_millis(50), move || {
            let observed = observed.clone();
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(ticks.load(Ordering::SeqCst), 0, "first poll was immediate");

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while ticks.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("first scheduled poll did not run");

        ctl.signal();
        ctl.join_tracked_tasks(std::time::Duration::from_secs(1))
            .await;
        let after_shutdown = ticks.load(Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            after_shutdown,
            "queue polled after shutdown"
        );
    }
    #[tokio::test]
    async fn queue_capacity_counts_active_rows_after_deduplication() {
        let store = store().await;
        store
            .update_config(serde_json::json!({"acme_queue_capacity": 1}))
            .await
            .unwrap();

        let first = store
            .acme_queue_enqueue("one.example", "node-a")
            .await
            .unwrap();
        assert!(matches!(first, AcmeQueueAdmission::Inserted(_)));
        let duplicate = store
            .acme_queue_enqueue("one.example", "node-b")
            .await
            .unwrap();
        assert!(matches!(duplicate, AcmeQueueAdmission::Existing(_)));
        let full = store
            .acme_queue_enqueue("two.example", "node-a")
            .await
            .unwrap();
        assert!(matches!(full, AcmeQueueAdmission::Full));
    }
}
