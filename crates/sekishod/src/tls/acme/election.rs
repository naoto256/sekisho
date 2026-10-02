//! ACME leader election — auto mode.
//!
//! Pre-HA `AcmeManager` gated issuance on a hand-edited
//! `GlobalConfig.acme_leader` string: the operator picked one node as
//! the leader, every other node refused to run orders, and failover
//! meant editing config and restarting. That works for two nodes and
//! a careful operator, but it does not survive the leader going
//! offline at 3 AM.
//!
//! This module provides an `acme_leader = None` path: nodes compete
//! for a singleton row in the service DB and the winner runs
//! issuance. The competition is deterministic (smaller node_hash
//! wins) and the row carries a heartbeat, so a dead leader's claim
//! ages out and a peer takes over automatically without an operator
//! in the loop.
//!
//! The three-rule transition (initial / takeover / preempt / refresh
//! / none) lives in `store::backend::evaluate_election_rules` so the
//! atomic evaluation happens inside the DB transaction where the
//! read-and-write has to be atomic. This file is purely the "how do
//! we drive it from the daemon" layer: compute the node hash, call
//! the store, turn the outcome into a log line.

use crate::error::Result;
use crate::store::Store;
use crate::store::backend::AcmeElectionOutcome;

/// Staleness threshold supplied to an election tick. A heartbeat older
/// than 15 minutes is eligible for takeover when a rival tick runs;
/// this is not a bound on tick scheduling or recovery latency.
const STALE_AFTER_MINUTES: i64 = 15;

/// Owns the node-identity used in election rounds. Cheap to clone
/// (inside it's just a `Store` handle and two `String`s) — the
/// background task and `AcmeManager::leader_check` each get their
/// own without contention.
#[derive(Clone)]
pub struct AcmeElection {
    store: Store,
    node_id: String,
    node_hash: String,
}

impl AcmeElection {
    /// Compute this node's hash once at construction so every tick
    /// reuses the same value. Resolution of the node_id itself
    /// reaches into the env/hostname — see `super::node_id`.
    pub fn new(store: Store) -> Self {
        let node_id = super::node_id();
        let node_hash = Self::compute_hash(&node_id);
        Self {
            store,
            node_id,
            node_hash,
        }
    }

    /// SHA-256 of the node id, truncated to 8 bytes and hex-encoded.
    /// 16 hex chars is equivalent to a u64 for comparison purposes;
    /// string comparison in the DB is deterministic and works
    /// identically on SQLite and Postgres without any integer-encoding
    /// gymnastics.
    fn compute_hash(node_id: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(node_id.as_bytes());
        hex::encode(&digest[..8])
    }

    /// Run one election tick. Called from the background task every
    /// few minutes; returns the `AcmeElectionOutcome` so the caller can
    /// log what happened. Any DB error propagates — the caller treats
    /// that as a transient failure and retries on the next tick.
    pub async fn tick(&self) -> Result<AcmeElectionOutcome> {
        let stale = chrono::Duration::minutes(STALE_AFTER_MINUTES);
        self.store
            .acme_election_try_promote_or_refresh(&self.node_id, &self.node_hash, stale)
            .await
    }

    /// Fast-path leader check used by the ACME issuance path.
    /// Read-only — the background `tick()` maintains the heartbeat;
    /// this function issues no DB write.
    ///
    /// A missing row resolves to `false`; promotion happens only via
    /// `tick()`. This function does not observe or affect in-flight
    /// issuances that have already passed a previous check on this
    /// node.
    pub async fn is_leader(&self) -> Result<bool> {
        Ok(self
            .store
            .acme_election_read()
            .await?
            .is_some_and(|row| row.node_id == self.node_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::env_guard;

    const TEST_MASTER_KEY: [u8; 32] = [0u8; 32];

    async fn store() -> Store {
        Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .expect("store")
    }

    fn hash_of(node_id: &str) -> String {
        AcmeElection::compute_hash(node_id)
    }

    /// Empty DB + first tick: the row gets inserted and the caller
    /// becomes leader. This is the bootstrap case — nothing else
    /// works until this runs somewhere.
    #[tokio::test]
    async fn election_initial_write_on_empty_table() {
        let _g = env_guard().await;
        unsafe {
            std::env::set_var(super::super::ENV_NODE_ID, "node-initial");
        }
        let s = store().await;
        let election = AcmeElection::new(s.clone());
        let outcome = election.tick().await.expect("tick");
        assert!(outcome.i_am_leader);
        assert_eq!(outcome.current_leader_node_id, "node-initial");
        assert_eq!(
            outcome.action_taken,
            crate::store::backend::ElectionAction::Initial
        );
        assert!(election.is_leader().await.expect("is_leader"));
        unsafe {
            std::env::remove_var(super::super::ENV_NODE_ID);
        }
    }

    /// Two nodes pointing at the same store race (serially, here) for
    /// the row. The one with the smaller hash wins regardless of who
    /// inserted first — Preempt is the whole reason the deterministic
    /// tiebreak exists.
    #[tokio::test]
    async fn election_smaller_hash_preempts_larger() {
        let _g = env_guard().await;
        let s = store().await;

        // Pick two IDs whose hashes sort opposite to their names so the
        // test can't accidentally pass because of alphabetical
        // coincidence.
        let mut a = "node-zz-0".to_string();
        let mut b = "node-aa-0".to_string();
        for i in 0..10000u32 {
            let ca = format!("node-zz-{i}");
            let cb = format!("node-aa-{i}");
            if hash_of(&ca) < hash_of(&cb) {
                a = ca;
                b = cb;
                break;
            }
        }
        assert!(hash_of(&a) < hash_of(&b), "need a smaller-hash A");

        // B ticks first — becomes leader by Initial rule.
        unsafe {
            std::env::set_var(super::super::ENV_NODE_ID, &b);
        }
        let eb = AcmeElection::new(s.clone());
        let out = eb.tick().await.expect("b tick");
        assert!(out.i_am_leader);

        // A ticks — has the smaller hash so it preempts.
        unsafe {
            std::env::set_var(super::super::ENV_NODE_ID, &a);
        }
        let ea = AcmeElection::new(s.clone());
        let out = ea.tick().await.expect("a tick");
        assert!(out.i_am_leader, "A should preempt B");
        assert_eq!(out.current_leader_node_id, a);
        assert_eq!(
            out.action_taken,
            crate::store::backend::ElectionAction::Preempt
        );

        // Larger-hash B ticks again — sees smaller-hash A, no write.
        unsafe {
            std::env::set_var(super::super::ENV_NODE_ID, &b);
        }
        let out = eb.tick().await.expect("b tick 2");
        assert!(!out.i_am_leader);
        assert_eq!(out.current_leader_node_id, a);
        assert_eq!(
            out.action_taken,
            crate::store::backend::ElectionAction::None
        );

        unsafe {
            std::env::remove_var(super::super::ENV_NODE_ID);
        }
    }

    /// The happy-path heartbeat: leader ticks, nothing changes, the
    /// row's `updated_at` moves forward. Important because it's what
    /// keeps a healthy leader's claim alive against the stale
    /// takeover rule.
    #[tokio::test]
    async fn election_heartbeat_refreshes_timestamp() {
        let _g = env_guard().await;
        unsafe {
            std::env::set_var(super::super::ENV_NODE_ID, "node-hb");
        }
        let s = store().await;
        let election = AcmeElection::new(s.clone());
        let first = election.tick().await.expect("first tick");
        assert_eq!(
            first.action_taken,
            crate::store::backend::ElectionAction::Initial
        );

        let ts_before = s
            .acme_election_read()
            .await
            .expect("read")
            .expect("row present")
            .updated_at;

        // Sleep past 1s so the unixepoch-second timestamp has room to
        // move. Anything sub-second collapses to the same integer
        // value and would defeat the assertion.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let second = election.tick().await.expect("second tick");
        assert_eq!(
            second.action_taken,
            crate::store::backend::ElectionAction::Refresh
        );
        let ts_after = s
            .acme_election_read()
            .await
            .expect("read")
            .expect("row present")
            .updated_at;
        assert!(ts_after > ts_before, "heartbeat should bump updated_at");

        unsafe {
            std::env::remove_var(super::super::ENV_NODE_ID);
        }
    }

    /// Stale takeover: the leader's heartbeat has lapsed (simulated by
    /// backdating the row) and a rival takes the claim on its next
    /// tick. This is the whole point of auto-election — a dead leader
    /// can't stay leader forever.
    #[tokio::test]
    async fn election_stale_takeover() {
        let _g = env_guard().await;
        let s = store().await;

        // A claims leadership.
        unsafe {
            std::env::set_var(super::super::ENV_NODE_ID, "node-a-stale");
        }
        let ea = AcmeElection::new(s.clone());
        ea.tick().await.expect("a tick");

        // Age A's heartbeat well past the 15-minute threshold by
        // poking the DB directly. Going through the backend would
        // refresh the timestamp — exactly what we're trying to avoid.
        let pool = s.sqlite_pool();
        let aged = (chrono::Utc::now() - chrono::Duration::minutes(30)).timestamp();
        sqlx::query("UPDATE acme_leader_election SET updated_at = ? WHERE id = 1")
            .bind(aged)
            .execute(pool)
            .await
            .expect("age row");

        // B ticks — sees a stale leader, takes over.
        unsafe {
            std::env::set_var(super::super::ENV_NODE_ID, "node-b-takeover");
        }
        let eb = AcmeElection::new(s.clone());
        let out = eb.tick().await.expect("b tick");
        assert!(out.i_am_leader);
        assert_eq!(out.current_leader_node_id, "node-b-takeover");
        assert_eq!(
            out.action_taken,
            crate::store::backend::ElectionAction::Takeover
        );

        unsafe {
            std::env::remove_var(super::super::ENV_NODE_ID);
        }
    }

    /// Two ticks concurrently against the same store must converge to
    /// one leader. SQLite's `BEGIN IMMEDIATE` serialises the txs;
    /// Postgres's `FOR UPDATE` does the same upstream. This test is a
    /// smoke check that the SQLite framing doesn't break it — the
    /// Postgres side is covered by the ha_test suite.
    #[tokio::test]
    async fn election_concurrent_ticks_serialize() {
        let _g = env_guard().await;
        let s = store().await;

        // Prime the row so we're testing the concurrent-preempt path
        // rather than two concurrent Initials (which would both be
        // correct but less interesting).
        unsafe {
            std::env::set_var(super::super::ENV_NODE_ID, "node-seed");
        }
        AcmeElection::new(s.clone()).tick().await.expect("seed");

        let a = AcmeElection {
            store: s.clone(),
            node_id: "node-c-race".to_string(),
            node_hash: AcmeElection::compute_hash("node-c-race"),
        };
        let b = AcmeElection {
            store: s.clone(),
            node_id: "node-d-race".to_string(),
            node_hash: AcmeElection::compute_hash("node-d-race"),
        };

        let (ra, rb) = tokio::join!(a.tick(), b.tick());
        ra.expect("a");
        rb.expect("b");

        // After both ticks settle, whoever has the smaller hash should
        // own the row. Regardless of who ran second, the row is
        // consistent: the serialised transactions leave it in a
        // single definite state.
        let winner = if a.node_hash < b.node_hash {
            &a.node_id
        } else {
            &b.node_id
        };
        let seed_hash = AcmeElection::compute_hash("node-seed");
        let winner_hash = if a.node_hash < b.node_hash {
            &a.node_hash
        } else {
            &b.node_hash
        };
        // Either seed still wins (if its hash is smaller than both
        // competitors) or the competitor with the smaller hash took
        // over. Only constraint: the row converges to a single node.
        let row = s.acme_election_read().await.expect("read").expect("row");
        let expected = if seed_hash.as_str() < winner_hash.as_str() {
            "node-seed".to_string()
        } else {
            winner.clone()
        };
        assert_eq!(row.node_id, expected);

        unsafe {
            std::env::remove_var(super::super::ENV_NODE_ID);
        }
    }
}
