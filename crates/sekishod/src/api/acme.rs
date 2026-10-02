//! Read-only views into the ACME background machinery.
//!
//! `GET /acme/leader_election` exposes who currently owns ACME issuance
//! across an HA cluster — the elected leader's node id, when it last
//! refreshed its heartbeat, and how that compares to the operator's
//! `config.acme_leader` pin (if any). The election logic itself lives
//! in `tls::acme::election`; this handler is a JSON projection of that
//! state so sekisho-cli / sekisho-webui can show "node-A is leader, you're
//! looking at node-B" without operators having to grep journalctl.
//!
//! HTTP-01 challenges (the other half of the ACME machinery) are
//! intentionally not exposed: they are ephemeral (~minutes during a
//! single issuance) and inspecting them mid-flight via a polling UI
//! would give a misleading "active issuance / no active issuance"
//! signal that lags the real state. If we ever need it, add it here.

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::json;

use super::AppState;
use crate::error::Result;
use crate::tls::acme;

pub async fn leader_election(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let my_node_id = acme::node_id();
    let row = state.store.acme_election_read().await?;
    let pinned = state.store.get_config().await?.acme_leader;
    let body = match row {
        Some(r) => {
            let i_am_leader = r.node_id == my_node_id;
            json!({
                "my_node_id": my_node_id,
                "current_leader_node_id": r.node_id,
                // `.timestamp()` so the wire shape matches the rest of
                // the API (integer epoch seconds). `json!` would
                // otherwise round-trip `r.updated_at` through the
                // default `DateTime<Utc>` Serialize impl, which emits
                // RFC 3339.
                "current_leader_updated_at": r.updated_at.timestamp(),
                "i_am_leader": i_am_leader,
                "pinned_acme_leader": pinned,
            })
        }
        None => json!({
            "my_node_id": my_node_id,
            "current_leader_node_id": serde_json::Value::Null,
            "current_leader_updated_at": serde_json::Value::Null,
            "i_am_leader": false,
            "pinned_acme_leader": pinned,
        }),
    };
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use crate::store::Store;

    async fn empty_store() -> Store {
        Store::new_for_test("sqlite::memory:", [0x01u8; 32], None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn leader_election_returns_null_before_first_tick() {
        // Freshly-migrated DB: no row in acme_leader_election yet. The
        // shape stays consistent so callers don't have to special-case
        // the "no leader yet" state — fields are just null / false.
        let store = empty_store().await;
        let row = store.acme_election_read().await.unwrap();
        assert!(row.is_none(), "precondition: no election yet");

        let pinned = store.get_config().await.unwrap().acme_leader;
        assert!(pinned.is_none());
    }

    #[tokio::test]
    async fn leader_election_after_promotion_marks_self_leader() {
        // After a single tick from "node-test", the read must report
        // node-test as the current leader. Mirrors what an HA-mode
        // operator would see immediately after first-boot.
        let store = empty_store().await;
        let outcome = store
            .acme_election_try_promote_or_refresh(
                "node-test",
                "0000000000000000",
                chrono::Duration::seconds(60),
            )
            .await
            .unwrap();
        assert_eq!(outcome.current_leader_node_id, "node-test");
        let row = store.acme_election_read().await.unwrap().unwrap();
        assert_eq!(row.node_id, "node-test");
    }
}
