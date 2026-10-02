//! ACME issuance queue row.
//!
//! Any node that receives `POST /certs` inserts or reuses a queue row
//! and returns `202 Accepted` with the queue id. The effective leader's
//! background tick pulls `pending` rows, runs ACME issuance, and writes
//! the result back. The requester polls `GET /certs/queue/{id}` until
//! `status` transitions to `completed` or `failed`.
//!
//! Why a table instead of a node-to-node HTTP forward: nodes share the
//! service DB already, so the queue is zero new attack surface — no
//! extra mutual-TLS, no extra API-key scope, no new listener to bind.
//! The DB is the only integration point between nodes today
//! (`acme_challenges`, `acme_leader_election`, `pending_auth`), so
//! issuance joins the same shape.

use chrono::serde::{ts_seconds, ts_seconds_option};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Lifecycle of a queued issuance request.
///
/// Written as a lower-case string to the DB (one column for every
/// backend, no enum types) and parsed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeQueueStatus {
    /// Inserted by any node's admission path; no tick has picked it yet.
    Pending,
    /// Leader has claimed the row (`picked_at` set) and is running the
    /// ACME order. A crash mid-order leaves the row in this state —
    /// the leader's startup sweep re-enqueues anything older than the
    /// stale window.
    InProgress,
    /// ACME issuance succeeded. `result_cert_id` points at the minted
    /// certificate row.
    Completed,
    /// ACME issuance failed. `error_msg` carries the operator-facing
    /// reason. The row is kept so the poller sees why.
    Failed,
}

impl AcmeQueueStatus {
    /// Textual form written into / read from the DB column. Kept
    /// centralised so `from_db_str` and the backend SQL use the same
    /// vocabulary.
    #[allow(dead_code)]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// Parse a row's textual status. Unknown values map to `Failed`
    /// with the assumption that a future schema extension would ship
    /// as a migration plus a matching variant here — a row that
    /// predates this binary being rolled back should be visible as a
    /// terminal state rather than silently treated as pending.
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "in_progress" => Self::InProgress,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            _ => Self::Failed,
        }
    }
}

/// One row of `acme_queue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeQueueRow {
    pub id: Uuid,
    pub domain: String,
    /// `node_id` of the node that inserted the row. Informational; the
    /// leader doesn't route anything back, it just updates the row and
    /// lets the requester poll.
    pub requester_node: String,
    pub status: AcmeQueueStatus,
    /// Populated when status is `Completed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_cert_id: Option<Uuid>,
    /// Populated when status is `Failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_msg: Option<String>,
    #[serde(with = "ts_seconds")]
    pub enqueued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "ts_seconds_option"
    )]
    pub picked_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "ts_seconds_option"
    )]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Result of one cluster-wide admission decision.
///
/// Capacity is deliberately not represented as an error: a full queue is a
/// successful, retryable admission decision, while database/config failures
/// remain errors and must not be surfaced as capacity pressure.
#[derive(Debug, Clone)]
pub enum AcmeQueueAdmission {
    Inserted(AcmeQueueRow),
    Existing(AcmeQueueRow),
    Full,
}
