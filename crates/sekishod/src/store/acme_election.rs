//! ACME leader-election facade.
//!
//! Two thin pass-throughs to the `StorageBackend` trait: the read-only
//! `acme_election_read` that the fast-path `is_leader` check hits on
//! every issuance attempt, and the transactional
//! `acme_election_try_promote_or_refresh` driven from the background
//! tick. The actual rule evaluation lives in the backend layer so the
//! atomic "read, decide, maybe write" runs inside a single DB
//! transaction; doing it up here would have re-introduced the race the
//! transaction is there to close.

use crate::error::Result;

use super::Store;
use super::backend::{AcmeElectionOutcome, AcmeElectionRow};
use super::dispatch;

impl Store {
    /// Peek at the current election row without mutating it. Returns
    /// `None` on a freshly-migrated DB where no one has ticked yet —
    /// the caller (typically `AcmeElection::is_leader`) treats that as
    /// "not leader" so a still-booting cluster doesn't accidentally
    /// double-issue before the first tick lands.
    pub async fn acme_election_read(&self) -> Result<Option<AcmeElectionRow>> {
        dispatch!(self, acme_election_read)
    }

    /// Run one atomic election cycle for `my_node_id`. See the trait
    /// method for the rule ordering. `stale_after` is how old a peer
    /// leader's heartbeat can get before this node takes over — pick a
    /// value comfortably larger than the tick interval so a slow tick
    /// doesn't trigger a false takeover.
    pub async fn acme_election_try_promote_or_refresh(
        &self,
        my_node_id: &str,
        my_node_hash: &str,
        stale_after: chrono::Duration,
    ) -> Result<AcmeElectionOutcome> {
        dispatch!(
            self,
            acme_election_try_promote_or_refresh,
            my_node_id,
            my_node_hash,
            stale_after,
        )
    }
}
