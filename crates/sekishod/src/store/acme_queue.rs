//! ACME issuance queue facade.
//!
//! The queue carries `POST /certs` requests from whatever node
//! received them to the node that currently owns ACME issuance
//! (the leader). The rest of the crate talks to it through `Store`,
//! not the backend traits directly — same pattern as `acme_challenge`.

use crate::error::Result;
use crate::models::acme_queue::{AcmeQueueAdmission, AcmeQueueRow};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::Store;
use super::backend::AcmeBudgetSnapshot;
use super::dispatch;

impl Store {
    /// Insert (or return an existing) queue row for `domain`. The
    /// `requester_node` is purely informational — consumers identify
    /// the leader by the row state, not this field.
    pub async fn acme_queue_enqueue(
        &self,
        domain: &str,
        requester_node: &str,
    ) -> Result<AcmeQueueAdmission> {
        let admission = dispatch!(self, acme_queue_enqueue, domain, requester_node)?;
        if matches!(admission, AcmeQueueAdmission::Full) {
            crate::observability::record_control_budget_rejection(
                crate::observability::RejectedControlBudget::AcmeQueue,
            );
        }
        Ok(admission)
    }

    /// Read the durable queue and issuance budget occupancy without changing
    /// queue state. `stale_before` is computed by the caller from the same
    /// process clock authority used by the queue worker.
    pub(crate) async fn acme_budget_snapshot(
        &self,
        stale_before: DateTime<Utc>,
    ) -> Result<AcmeBudgetSnapshot> {
        dispatch!(self, acme_budget_snapshot, stale_before)
    }

    /// Fetch a queue row by id. `None` when absent; the polling
    /// endpoint surfaces that as a 404.
    pub async fn acme_queue_get(&self, id: Uuid) -> Result<Option<AcmeQueueRow>> {
        dispatch!(self, acme_queue_get, id)
    }

    /// Pick the oldest pending row for processing, atomically flipping
    /// its status to `in_progress`. Stale `in_progress` rows (picked
    /// more than `stale_after` ago) are re-enqueued inside the same
    /// transaction. The transaction only claims a new row while the
    /// durable `in_progress` count is below `concurrency_limit`.
    pub async fn acme_queue_pick_next(
        &self,
        stale_after: chrono::Duration,
        concurrency_limit: u32,
    ) -> Result<Option<AcmeQueueRow>> {
        dispatch!(self, acme_queue_pick_next, stale_after, concurrency_limit)
    }

    /// Mark a row `completed` with the minted cert's id.
    pub async fn acme_queue_mark_completed(&self, id: Uuid, result_cert_id: Uuid) -> Result<()> {
        dispatch!(self, acme_queue_mark_completed, id, result_cert_id)
    }

    /// Mark a row `failed` with an operator-facing message.
    pub async fn acme_queue_mark_failed(&self, id: Uuid, error_msg: &str) -> Result<()> {
        dispatch!(self, acme_queue_mark_failed, id, error_msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn admitted_row(admission: AcmeQueueAdmission) -> AcmeQueueRow {
        match admission {
            AcmeQueueAdmission::Inserted(row) => row,
            other => panic!("expected inserted queue row, got {other:?}"),
        }
    }

    fn rejected_total(rendered: &str) -> f64 {
        rendered
            .lines()
            .find_map(|line| {
                line.strip_prefix("sekisho_control_budget_rejected_total{budget=\"acme_queue\"} ")?
                    .parse()
                    .ok()
            })
            .expect("acme_queue rejection sample")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queue_full_is_the_only_counted_admission_outcome() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _recorder_guard = metrics::set_default_local_recorder(&recorder);
        crate::observability::seed_control_budget_metrics_for_test();

        let store = Store::new_for_test("sqlite::memory:", [0x71; 32], None)
            .await
            .unwrap();
        store
            .update_config(serde_json::json!({"acme_queue_capacity": 1}))
            .await
            .unwrap();

        assert!(matches!(
            store
                .acme_queue_enqueue("one.example", "node-a")
                .await
                .unwrap(),
            AcmeQueueAdmission::Inserted(_)
        ));
        assert!(matches!(
            store
                .acme_queue_enqueue("one.example", "node-b")
                .await
                .unwrap(),
            AcmeQueueAdmission::Existing(_)
        ));
        assert_eq!(rejected_total(&handle.render()), 0.0);

        assert!(matches!(
            store
                .acme_queue_enqueue("two.example", "node-a")
                .await
                .unwrap(),
            AcmeQueueAdmission::Full
        ));
        assert_eq!(rejected_total(&handle.render()), 1.0);

        let degraded = Store::new_for_test_degraded("queue-metrics-error")
            .await
            .unwrap();
        assert!(
            degraded
                .acme_queue_enqueue("error.example", "node-a")
                .await
                .is_err()
        );
        assert_eq!(rejected_total(&handle.render()), 1.0);
    }

    #[tokio::test]
    async fn durable_budget_snapshot_is_single_view_read_only_and_stale_aware() {
        let store = Store::new_for_test("sqlite::memory:", [0x72; 32], None)
            .await
            .unwrap();
        let pool = match &store.backend {
            crate::store::backend::Backend::Sqlite(backend) => backend.pool(),
            _ => panic!("test store must use SQLite"),
        };

        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM global_config")
                .fetch_one(pool)
                .await
                .unwrap(),
            0
        );
        let initial = store
            .acme_budget_snapshot(chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(initial.queue_active, 0);
        assert_eq!(initial.queue_capacity, 1_000);
        assert_eq!(initial.issuance_in_progress, 0);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM global_config")
                .fetch_one(pool)
                .await
                .unwrap(),
            0,
            "a metrics read must not seed the default config row"
        );

        store
            .update_config(serde_json::json!({"acme_queue_capacity": 7}))
            .await
            .unwrap();
        let fresh = admitted_row(
            store
                .acme_queue_enqueue("fresh.example", "node-a")
                .await
                .unwrap(),
        );
        let stale = admitted_row(
            store
                .acme_queue_enqueue("stale.example", "node-a")
                .await
                .unwrap(),
        );
        let at_cutoff = admitted_row(
            store
                .acme_queue_enqueue("at-cutoff.example", "node-a")
                .await
                .unwrap(),
        );
        let missing_pick_time = admitted_row(
            store
                .acme_queue_enqueue("missing-time.example", "node-a")
                .await
                .unwrap(),
        );
        store
            .acme_queue_enqueue("pending.example", "node-a")
            .await
            .unwrap();

        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(10);
        sqlx::query("UPDATE acme_queue SET status = 'in_progress', picked_at = ? WHERE id = ?")
            .bind((cutoff + chrono::Duration::seconds(1)).timestamp())
            .bind(fresh.id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE acme_queue SET status = 'in_progress', picked_at = ? WHERE id = ?")
            .bind((cutoff - chrono::Duration::seconds(1)).timestamp())
            .bind(stale.id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE acme_queue SET status = 'in_progress', picked_at = ? WHERE id = ?")
            .bind(cutoff.timestamp())
            .bind(at_cutoff.id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE acme_queue SET status = 'in_progress', picked_at = NULL WHERE id = ?")
            .bind(missing_pick_time.id)
            .execute(pool)
            .await
            .unwrap();

        let snapshot = store.acme_budget_snapshot(cutoff).await.unwrap();
        assert_eq!(snapshot.queue_active, 5);
        assert_eq!(snapshot.queue_capacity, 7);
        assert_eq!(snapshot.issuance_in_progress, 3);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM acme_queue WHERE status = 'in_progress'",
            )
            .fetch_one(pool)
            .await
            .unwrap(),
            4,
            "the snapshot must not recycle stale rows"
        );
    }

    #[tokio::test]
    async fn corrupt_config_omits_the_entire_durable_metrics_block() {
        crate::observability::init_metrics();
        let store = Store::new_for_test("sqlite::memory:", [0x73; 32], None)
            .await
            .unwrap();
        let pool = match &store.backend {
            crate::store::backend::Backend::Sqlite(backend) => backend.pool(),
            _ => panic!("test store must use SQLite"),
        };
        sqlx::query("INSERT INTO global_config (id, data) VALUES (1, '{')")
            .execute(pool)
            .await
            .unwrap();

        assert!(
            store
                .acme_budget_snapshot(chrono::Utc::now())
                .await
                .is_err()
        );
        let response = crate::observability::durable_acme_metrics_handler(store, 5)
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let rendered = std::str::from_utf8(&body).unwrap();
        assert!(rendered.contains("sekisho_control_budget_in_flight"));
        assert!(!rendered.contains("sekisho_acme_queue_active"));
        assert!(!rendered.contains("sekisho_acme_queue_capacity"));
        assert!(!rendered.contains("sekisho_acme_issuance_in_progress"));
        assert!(!rendered.contains("sekisho_acme_issuance_limit"));
    }

    #[tokio::test]
    async fn cancelled_snapshot_wait_does_not_poison_the_next_scrape() {
        crate::observability::init_metrics();
        let store = Store::new_for_test("sqlite::memory:", [0x74; 32], None)
            .await
            .unwrap();
        let pool = match &store.backend {
            crate::store::backend::Backend::Sqlite(backend) => backend.pool().clone(),
            _ => panic!("test store must use SQLite"),
        };
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(pool.acquire().await.unwrap());
        }

        let blocked_store = store.clone();
        let blocked = tokio::spawn(async move {
            crate::observability::durable_acme_metrics_handler(blocked_store, 5).await
        });
        tokio::task::yield_now().await;
        assert!(
            !blocked.is_finished(),
            "snapshot must wait for a DB connection"
        );
        blocked.abort();
        assert!(blocked.await.unwrap_err().is_cancelled());
        drop(held);

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::observability::durable_acme_metrics_handler(store, 5),
        )
        .await
        .expect("next scrape must not inherit cancelled state")
        .unwrap();
        let rendered = response.into_body().collect().await.unwrap().to_bytes();
        let rendered = std::str::from_utf8(&rendered).unwrap();
        assert!(rendered.contains("sekisho_acme_queue_active 0\n"));
        assert!(rendered.contains("sekisho_acme_issuance_limit 5\n"));
    }
}
