//! Storage backend abstraction.
//!
//! `Store` is a facade over the closed `Backend` enum. Its concrete
//! storage backends are SQLite and Postgres; `Unavailable` is the
//! degraded stub. `StorageBackend` defines the shared persistence
//! surface, and `Store` dispatches through exhaustive matches.
//!
//! Design choices:
//!
//! * No `async_trait` crate. We use native `async fn` in traits (AFIT,
//!   stable since Rust 1.75) with explicit `Send` bounds on the returned
//!   futures. That keeps us free of proc-macro overhead and lets the
//!   compiler see through the dispatch.
//! * `Backend` is an `enum`, not a `Box<dyn StorageBackend>`. Dispatch
//!   is static, and changing the closed variant set requires updating
//!   its exhaustive matches.

use crate::error::Result;
use crate::models::acme_queue::{AcmeQueueAdmission, AcmeQueueRow};
use crate::models::api_key::{ApiKey, ApiKeyScopeSet, ApiKeyWithSecret};
use crate::models::cert::Certificate;
use crate::models::config::GlobalConfig;
use crate::models::idp::IdentityProvider;
use crate::models::policy::Policy;
use crate::models::route::Route;
use crate::models::session::Session;
use crate::store::route::RouteObservation;
use chrono::{DateTime, Utc};
use std::future::Future;
use uuid::Uuid;

/// Stable service-schema migrations applied after the idempotent bootstrap
/// DDL. Dialect-specific SQL stays in each concrete backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ServiceMigration {
    pub(super) version: i64,
    pub(super) name: &'static str,
}

pub(super) const SERVICE_MIGRATIONS: &[ServiceMigration] = &[
    ServiceMigration {
        version: 1,
        name: "pending_auth_kind",
    },
    ServiceMigration {
        version: 2,
        name: "remove_dead_saml_sp_fields",
    },
    ServiceMigration {
        version: 3,
        name: "pending_auth_browser_nonce_hash",
    },
    ServiceMigration {
        version: 4,
        name: "session_relational_expiry_authority",
    },
    ServiceMigration {
        version: 5,
        name: "identity_signing_key_ring",
    },
    ServiceMigration {
        version: 6,
        name: "remove_management_api_certificate",
    },
    ServiceMigration {
        version: 7,
        name: "api_key_management_scopes",
    },
    ServiceMigration {
        version: 8,
        name: "handoff_nonce_replay_guard",
    },
];

/// How long a consumed handoff nonce is remembered.
///
/// Twice the token's own 60-second lifetime. A nonce only has to outlive every
/// token that could still present it: past expiry the token is rejected on its
/// `exp` before the nonce is ever looked up, so a longer window would grow the
/// table without closing any replay. The doubling is headroom for clock skew
/// between nodes, which matters because in HA the minting node and the
/// redeeming node are different machines reading the same table.
pub(super) const HANDOFF_NONCE_RETENTION_SECONDS: i64 = 120;

#[derive(Debug, Clone)]
pub(crate) struct IdentitySigningKeyRow {
    pub(crate) kid: String,
    pub(crate) state: String,
    pub(crate) private_key_encrypted: Option<String>,
    pub(crate) public_jwk: String,
    pub(crate) retire_until: Option<i64>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdentitySigningReencryptOutcome {
    pub(crate) examined: u64,
    pub(crate) reencrypted: u64,
    pub(crate) skipped: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentitySigningBootstrapOutcome {
    Inserted,
    Existing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentitySigningRotateOutcome {
    Rotated,
    RetiringStillEligible,
}

/// Database-time validation snapshot. `touch_due` is computed in the same
/// statement that reads the relational expiry columns.
#[derive(Debug)]
pub(crate) struct SessionValidation {
    pub(crate) session: Session,
    pub(crate) touch_due: bool,
}

/// Result of the conditional session access-time compare-and-set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionTouchOutcome {
    Touched(DateTime<Utc>),
    Current(DateTime<Utc>),
    GoneOrExpired,
}

pub(super) fn legacy_session_last_accessed_at(data: &str) -> std::result::Result<i64, sqlx::Error> {
    let value: serde_json::Value = serde_json::from_str(data)
        .map_err(|_| sqlx::Error::Protocol("invalid legacy session JSON".to_owned()))?;
    let timestamp = value
        .get("last_accessed_at")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| {
            sqlx::Error::Protocol(
                "legacy session last_accessed_at is missing or malformed".to_owned(),
            )
        })?;
    DateTime::<Utc>::from_timestamp(timestamp, 0).ok_or_else(|| {
        sqlx::Error::Protocol("legacy session last_accessed_at is out of range".to_owned())
    })?;
    Ok(timestamp)
}

#[cfg(test)]
mod session_migration_value_tests {
    use super::legacy_session_last_accessed_at;

    #[test]
    fn legacy_session_timestamp_requires_present_integral_representable_seconds() {
        assert_eq!(
            legacy_session_last_accessed_at(r#"{"last_accessed_at":1700000000}"#).unwrap(),
            1_700_000_000
        );
        for invalid in [
            r#"{}"#,
            r#"{"last_accessed_at":"1700000000"}"#,
            r#"{"last_accessed_at":1.5}"#,
            r#"{"last_accessed_at":9223372036854775807}"#,
        ] {
            assert!(
                legacy_session_last_accessed_at(invalid).is_err(),
                "invalid timestamp was accepted: {invalid}"
            );
        }
    }
}

/// One row from the `master_keys` table. Carries the KEK-encrypted DEK
/// blob (base64) and the active/retired flags so the loader can build
/// the in-memory ring. The backend row and trait use `i16`; `build_ring`
/// converts it to `u16`, then ring construction applies the v3 wire
/// format's one-byte key-id range (`0..=255`). This struct does not
/// validate values read from a corrupt database.
#[derive(Debug, Clone)]
pub struct MasterKeyRow {
    pub key_id: i16,
    pub key_encrypted: String,
    pub active: bool,
    pub retired: bool,
}

pub(super) fn build_master_key_ring(
    master_key: &crate::crypto::MasterKey,
    rows: Vec<MasterKeyRow>,
    version: u64,
) -> Result<crate::crypto::MasterKeyRing> {
    use base64::Engine;
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let key_id: u16 = row.key_id.try_into().map_err(|_| {
            crate::error::Error::ConfigurationError(format!("key_id {} out of range", row.key_id))
        })?;
        let encrypted_blob = base64::engine::general_purpose::STANDARD
            .decode(&row.key_encrypted)
            .map_err(|e| {
                crate::error::Error::ConfigurationError(format!(
                    "master_keys.key_id={} base64-decode failed: {e}",
                    row.key_id
                ))
            })?;
        records.push(crate::crypto::EncryptedDekRecord {
            key_id,
            encrypted_blob,
            active: row.active,
            retired: row.retired,
        });
    }
    crate::crypto::MasterKeyRing::from_encrypted_records(
        &master_key.kek_capability(),
        records,
        version,
    )
    .map_err(|e| crate::error::Error::ConfigurationError(format!("ring construction failed: {e}")))
}

/// Result of atomically installing a write-once secret.
///
/// The returned value is always the durable database winner: it is the
/// caller's candidate when `inserted` is true and the pre-existing value
/// otherwise. This lets HA callers converge without a check-then-insert race.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SecretInsertOutcome {
    pub(crate) inserted: bool,
    pub(crate) value: String,
}

/// Result of the first-DEK bootstrap insert.
///
/// `AlreadyInitialized` means the atomic attempt inserted no bootstrap
/// row: either the table was already nonempty, or a concurrent conflicting
/// writer won after the empty check and the insert produced no row through
/// `ON CONFLICT`. Non-conflict database, transaction, and commit failures
/// remain errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirstDekInsertOutcome {
    Inserted,
    AlreadyInitialized,
}

/// Snapshot of the `acme_leader_election` singleton row.
///
/// Exposed up through `StorageBackend` so the election module can
/// compare against the currently-stored leader without reimplementing
/// the "SELECT one singleton row" dance per backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeElectionRow {
    pub node_id: String,
    pub node_hash: String,
    pub updated_at: DateTime<Utc>,
}

/// What `acme_election_try_promote_or_refresh` actually did to the row.
/// Surfaced for structured logging and tests — callers shouldn't branch
/// on it for business logic (use `i_am_leader` on the outcome for that).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElectionAction {
    /// Table had no row — we inserted ourselves as the initial leader.
    Initial,
    /// Existing leader's heartbeat was older than `stale_after` — we
    /// took over.
    Takeover,
    /// Existing leader's hash sorted higher than ours — we preempted
    /// deterministically (smaller hash wins).
    Preempt,
    /// We were already leader — just refreshed `updated_at`.
    Refresh,
    /// Someone else is leader, still fresh, with a smaller-or-equal
    /// hash — we did nothing.
    None,
}

/// One statement-level view of the durable ACME queue budgets.
///
/// Queue occupancy includes all active rows, while issuance occupancy excludes
/// rows that the next picker would recycle as stale. The process-local startup
/// issuance limit is deliberately not stored here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AcmeBudgetSnapshot {
    pub(crate) queue_active: u64,
    pub(crate) queue_capacity: u32,
    pub(crate) issuance_in_progress: u64,
}

/// Result of a single election tick. `current_leader_node_id` reflects
/// the post-operation state of the row so a caller can log who owns
/// issuance without a second read.
#[derive(Debug, Clone)]
pub struct AcmeElectionOutcome {
    pub current_leader_node_id: String,
    pub i_am_leader: bool,
    pub action_taken: ElectionAction,
}

/// Decide what an election tick should do given the existing row.
///
/// Pure function — no DB, no clock — so the three-rule logic is
/// unit-testable without a live backend and stays identical between
/// SQLite and Postgres. Rule ordering matches the trait docs:
/// Initial → Takeover → Refresh → Preempt → None.
///
/// `now` is passed in rather than read here so the caller uses the
/// same timestamp it will write, and so tests can freeze time.
pub(super) fn evaluate_election_rules(
    existing: Option<AcmeElectionRow>,
    my_node_id: &str,
    my_node_hash: &str,
    stale_after: chrono::Duration,
    now: DateTime<Utc>,
) -> AcmeElectionOutcome {
    match existing {
        None => AcmeElectionOutcome {
            current_leader_node_id: my_node_id.to_string(),
            i_am_leader: true,
            action_taken: ElectionAction::Initial,
        },
        Some(row) => {
            let stale = now - row.updated_at > stale_after;
            if stale {
                AcmeElectionOutcome {
                    current_leader_node_id: my_node_id.to_string(),
                    i_am_leader: true,
                    action_taken: ElectionAction::Takeover,
                }
            } else if row.node_id == my_node_id {
                AcmeElectionOutcome {
                    current_leader_node_id: my_node_id.to_string(),
                    i_am_leader: true,
                    action_taken: ElectionAction::Refresh,
                }
            } else if row.node_hash.as_str() > my_node_hash {
                // Smaller hash wins. Deterministic across peers without
                // needing a shared clock or priority config.
                AcmeElectionOutcome {
                    current_leader_node_id: my_node_id.to_string(),
                    i_am_leader: true,
                    action_taken: ElectionAction::Preempt,
                }
            } else {
                AcmeElectionOutcome {
                    current_leader_node_id: row.node_id,
                    i_am_leader: false,
                    action_taken: ElectionAction::None,
                }
            }
        }
    }
}

pub mod api_key_hash;
mod crud_helpers;
mod epoch;
pub mod postgres;
pub mod sqlite;

/// Resources whose storage row carries a `name` column that the store
/// layer binds into INSERT / UPDATE statements and surfaces in
/// uniqueness-violation messages. Route / IdP / Policy all qualify;
/// config is a singleton and does not.
///
/// Lives in the shared `backend` module rather than each backend's
/// `crud.rs` because the trait is pure Rust — no SQL, no executor type
/// — and the impls for Route / IdP / Policy were verbatim duplicated
/// between `sqlite/crud.rs` and `postgres/crud.rs`. Centralising it
/// removes that copy and means a future fourth named resource only has
/// to add one impl line, not two.
pub(in crate::store::backend) trait NamedResource:
    serde::Serialize + serde::de::DeserializeOwned
{
    fn name(&self) -> &str;
}

/// Tables that the JSON-blob CRUD helpers (`backend::{sqlite,postgres}::crud`)
/// operate over. Modeled as a closed enum rather than `&str` so the SQL-
/// building helpers can only ever interpolate a fixed, vetted set of
/// identifiers: a future caller cannot accidentally route user input into
/// the table-name slot of a `format!("SELECT ... FROM {table} ...")` and
/// open a SQL injection. Adding a new table is a one-line variant + a one-
/// line match arm — same shape as `NamedResource` above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::store::backend) enum Table {
    Routes,
    IdentityProviders,
    Policies,
}

impl Table {
    /// Bare SQL identifier (`"routes"`, `"identity_providers"`, `"policies"`).
    pub(in crate::store::backend) fn sql(self) -> &'static str {
        match self {
            Table::Routes => "routes",
            Table::IdentityProviders => "identity_providers",
            Table::Policies => "policies",
        }
    }

    /// Human-readable resource name woven into error messages
    /// ("corrupt {kind} data: ...", "conflict on {kind} '...'"). Kept
    /// separate from `sql()` so the wire identifier and the user-facing
    /// label can diverge — `identity_providers` is the canonical column
    /// name, "identity provider" is what an operator wants to read in a
    /// 409 response.
    pub(in crate::store::backend) fn kind(self) -> &'static str {
        match self {
            Table::Routes => "route",
            Table::IdentityProviders => "identity provider",
            Table::Policies => "policy",
        }
    }
}

impl NamedResource for crate::models::route::Route {
    fn name(&self) -> &str {
        &self.name
    }
}
impl NamedResource for crate::models::idp::IdentityProvider {
    fn name(&self) -> &str {
        &self.name
    }
}
impl NamedResource for crate::models::policy::Policy {
    fn name(&self) -> &str {
        &self.name
    }
}

pub use postgres::PostgresBackend;
pub use sqlite::SqliteBackend;

/// The set of persistence operations the rest of the crate depends on.
///
/// Shape mirrors the pre-refactor `impl Store` surface so `Store` can
/// stay a thin dispatch facade. Every method is `&self`; concurrency is
/// the backend's problem.
pub(crate) trait StorageBackend {
    // ───── Routes ─────
    fn observe_routes(&self) -> impl Future<Output = Result<RouteObservation>> + Send;
    fn list_routes(&self) -> impl Future<Output = Result<Vec<Route>>> + Send;
    fn list_routes_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<Route>>> + Send;
    fn get_route(&self, id: Uuid) -> impl Future<Output = Result<Route>> + Send;
    fn create_route(&self, route: &Route) -> impl Future<Output = Result<()>> + Send;
    fn update_route(
        &self,
        id: Uuid,
        update: serde_json::Value,
    ) -> impl Future<Output = Result<Route>> + Send;
    fn delete_route(&self, id: Uuid) -> impl Future<Output = Result<()>> + Send;

    // ───── IdPs ─────
    fn list_idps(&self) -> impl Future<Output = Result<Vec<IdentityProvider>>> + Send;
    fn list_idps_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<IdentityProvider>>> + Send;
    fn get_idp(&self, id: Uuid) -> impl Future<Output = Result<IdentityProvider>> + Send;
    fn create_idp(&self, idp: &IdentityProvider) -> impl Future<Output = Result<()>> + Send;
    fn update_idp(
        &self,
        id: Uuid,
        update: serde_json::Value,
    ) -> impl Future<Output = Result<IdentityProvider>> + Send;
    fn delete_idp(&self, id: Uuid) -> impl Future<Output = Result<()>> + Send;

    // ───── Policies ─────
    #[allow(dead_code)] // Retained as the unbounded internal operation.
    fn list_policies(&self) -> impl Future<Output = Result<Vec<Policy>>> + Send;
    fn list_policies_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<Policy>>> + Send;
    fn get_policy(&self, id: Uuid) -> impl Future<Output = Result<Policy>> + Send;
    fn get_policy_by_name(&self, name: &str) -> impl Future<Output = Result<Policy>> + Send;
    fn create_policy(&self, p: &Policy) -> impl Future<Output = Result<()>> + Send;
    fn update_policy(
        &self,
        id: Uuid,
        update: serde_json::Value,
    ) -> impl Future<Output = Result<Policy>> + Send;
    fn delete_policy(&self, id: Uuid) -> impl Future<Output = Result<()>> + Send;

    // ───── Config ─────
    /// Reads the raw row from storage. Cache management lives in `Store`.
    fn load_config(&self) -> impl Future<Output = Result<GlobalConfig>> + Send;
    fn update_config(
        &self,
        update: serde_json::Value,
    ) -> impl Future<Output = Result<GlobalConfig>> + Send;

    // ───── Sessions ─────
    fn create_session(&self, session: &Session) -> impl Future<Output = Result<()>> + Send;
    fn get_session(&self, id: Uuid) -> impl Future<Output = Result<Session>> + Send;
    fn get_session_for_validation(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<SessionValidation>> + Send;
    fn touch_session_if_due(
        &self,
        id: Uuid,
        expected_last_accessed_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<SessionTouchOutcome>> + Send;
    fn list_sessions(
        &self,
        user_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<Session>>> + Send;
    fn delete_session(&self, id: Uuid) -> impl Future<Output = Result<()>> + Send;
    fn cleanup_expired_sessions(&self) -> impl Future<Output = Result<u64>> + Send;

    // ───── Certificates ─────
    fn list_certs(&self) -> impl Future<Output = Result<Vec<Certificate>>> + Send;
    fn list_certs_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<Certificate>>> + Send;
    fn get_cert(&self, id: Uuid) -> impl Future<Output = Result<Certificate>> + Send;
    fn upsert_cert(&self, cert: &Certificate) -> impl Future<Output = Result<()>> + Send;
    fn delete_cert(&self, id: Uuid) -> impl Future<Output = Result<()>> + Send;
    fn get_expiring_certs(
        &self,
        days_before: i64,
    ) -> impl Future<Output = Result<Vec<Certificate>>> + Send;

    // ───── API keys ─────
    fn create_api_key(
        &self,
        name: &str,
        scopes: &ApiKeyScopeSet,
    ) -> impl Future<Output = Result<ApiKeyWithSecret>> + Send;
    fn get_api_key(&self, id: Uuid) -> impl Future<Output = Result<ApiKey>> + Send;
    fn lookup_api_key(&self, raw_key: &str) -> impl Future<Output = Result<ApiKey>> + Send;
    fn touch_api_key_usage(&self, id: Uuid) -> impl Future<Output = Result<()>> + Send;
    #[allow(dead_code)] // Retained as the unbounded internal operation.
    fn list_api_keys(&self) -> impl Future<Output = Result<Vec<ApiKey>>> + Send;
    fn list_api_keys_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> impl Future<Output = Result<Vec<ApiKey>>> + Send;
    fn delete_api_key(&self, id: Uuid) -> impl Future<Output = Result<()>> + Send;
    #[allow(dead_code)] // exercised by store_test; kept for future ops/admin use
    fn api_key_count(&self) -> impl Future<Output = Result<i64>> + Send;

    // ───── Secrets ─────
    fn get_secret(&self, key: &str) -> impl Future<Output = Result<Option<String>>> + Send;
    fn set_secret(&self, key: &str, value: &str) -> impl Future<Output = Result<()>> + Send;
    /// Insert `value` only when `key` is absent and return the durable winner.
    fn insert_secret_if_absent(
        &self,
        key: &str,
        value: &str,
    ) -> impl Future<Output = Result<SecretInsertOutcome>> + Send;

    // ───── ACME challenges (HTTP-01) ─────
    /// Persist a `token → key_authorization` binding so any node sharing
    /// the service DB can answer `/.well-known/acme-challenge/{token}`
    /// during validation. `domain` is recorded alongside the token so the
    /// cleanup path can scope the delete to a single issuance run rather
    /// than flushing every in-flight challenge.
    fn set_acme_challenge(
        &self,
        token: &str,
        key_auth: &str,
        domain: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Look up the `key_authorization` for a given challenge token.
    /// Returns `None` when the token is unknown — the HTTP-01 handler
    /// maps that to 404.
    fn get_acme_challenge(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<Option<String>>> + Send;
    /// Drop every challenge row recorded for `domain`. Called at the end
    /// of an issuance (successful or otherwise) so the table doesn't
    /// accumulate stale entries.
    fn delete_acme_challenges_for_domain(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<u64>> + Send;

    // ───── ACME leader election ─────
    /// Read the current election row without modifying it. Used by the
    /// fast-path `is_leader` check on the hot ACME issuance path —
    /// there's no reason to bump `updated_at` on every request when the
    /// background tick already keeps it fresh.
    fn acme_election_read(&self) -> impl Future<Output = Result<Option<AcmeElectionRow>>> + Send;

    /// Atomic "read the singleton row, apply the three election rules,
    /// maybe write back" in a single transaction. The rules, evaluated
    /// in order:
    ///
    ///   1. row absent → INSERT self (`Initial`).
    ///   2. `updated_at < now - stale_after` → UPDATE to self (`Takeover`).
    ///   3. `node_id == me` → UPDATE `updated_at` only (`Refresh`).
    ///   4. `node_hash > my_node_hash` → UPDATE to self (`Preempt`).
    ///      Smaller hash wins: arbitrary but deterministic across peers.
    ///   5. otherwise → no write (`None`).
    ///
    /// Returns who the effective leader is after the transaction
    /// commits, so callers can log and non-leaders can log who owns
    /// issuance.
    fn acme_election_try_promote_or_refresh(
        &self,
        my_node_id: &str,
        my_node_hash: &str,
        stale_after: chrono::Duration,
    ) -> impl Future<Output = Result<AcmeElectionOutcome>> + Send;

    // ───── ACME issuance queue (HA-transparent /certs) ─────
    /// Insert a new `pending` queue row, or — if a pending /
    /// in-progress row already exists for the same domain — return the
    /// existing row. Idempotent so a client retrying after a transient
    /// network error doesn't accidentally race the leader on two
    /// parallel ACME orders for the same FQDN.
    fn acme_queue_enqueue(
        &self,
        domain: &str,
        requester_node: &str,
    ) -> impl Future<Output = Result<AcmeQueueAdmission>> + Send;

    /// Read queue occupancy, live capacity, and non-stale issuance occupancy
    /// from one database statement without recycling or otherwise mutating
    /// queue rows.
    fn acme_budget_snapshot(
        &self,
        stale_before: DateTime<Utc>,
    ) -> impl Future<Output = Result<AcmeBudgetSnapshot>> + Send;

    /// Fetch one queue row by id. Used by the polling endpoint; 404
    /// when absent.
    fn acme_queue_get(&self, id: Uuid)
    -> impl Future<Output = Result<Option<AcmeQueueRow>>> + Send;

    /// Atomically pick the oldest `pending` row (`ORDER BY enqueued_at
    /// ASC`), mark it `in_progress`, and return it. Returns `None`
    /// when no pending row exists or the durable `in_progress` count is
    /// already at `concurrency_limit`.
    ///
    /// Also re-enqueues any `in_progress` row whose `picked_at` has
    /// gone stale (older than `stale_after`): a leader that crashed
    /// mid-order leaves one of those behind, and the next pick attempt
    /// flips it back to `pending` before looking for work. The
    /// stale reset, durable-slot count, and new pick run in one
    /// cluster-serialized transaction so peers cannot oversubscribe the
    /// startup limit or lose the row in a gap.
    fn acme_queue_pick_next(
        &self,
        stale_after: chrono::Duration,
        concurrency_limit: u32,
    ) -> impl Future<Output = Result<Option<AcmeQueueRow>>> + Send;

    /// Mark `id` as `completed` with the cert row reference.
    fn acme_queue_mark_completed(
        &self,
        id: Uuid,
        result_cert_id: Uuid,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Mark `id` as `failed` with an operator-facing message.
    fn acme_queue_mark_failed(
        &self,
        id: Uuid,
        error_msg: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    // ───── Version counters (HA cache-invalidation) ─────
    /// Test-only scalar view of the routes version. Production reads the
    /// version and ordered route rows together through `observe_routes`.
    #[cfg(test)]
    fn route_version_current(&self) -> impl Future<Output = Result<u64>> + Send;
    fn idp_version_current(&self) -> impl Future<Output = Result<u64>> + Send;
    fn config_version_current(&self) -> impl Future<Output = Result<u64>> + Send;
    /// Current monotonic version for the certificates resource. Bumped on
    /// `upsert_cert` / `delete_cert` so peer nodes can pull-invalidate
    /// their in-process `CertResolver` cache without node-to-node signalling.
    fn cert_version_current(&self) -> impl Future<Output = Result<u64>> + Send;

    // ───── Pending auth (OIDC/SAML in-flight CSRF state) ─────
    /// Insert a pending-auth row keyed by `csrf_token`. Overwrites an
    /// existing row with the same token — callsites use 256-bit random
    /// tokens, so collision is a cryptographic non-event, but the upsert
    /// keeps behaviour sane if two tabs somehow race the same token.
    fn pending_auth_insert(
        &self,
        csrf_token: &str,
        state: &crate::auth::middleware::PendingAuth,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Expiry-aware lookup that leaves the row available for a later
    /// validation attempt. A successful caller must use
    /// [`Self::pending_auth_take`] before producing side effects.
    fn pending_auth_get(
        &self,
        csrf_token: &str,
    ) -> impl Future<Output = Result<Option<crate::auth::middleware::PendingAuth>>> + Send;
    /// Atomic read-and-delete. At-most-once consumption is load-bearing
    /// for CSRF binding: if two callbacks could both succeed with the
    /// same token, an attacker who stole one could replay it.
    fn pending_auth_take(
        &self,
        csrf_token: &str,
    ) -> impl Future<Output = Result<Option<crate::auth::middleware::PendingAuth>>> + Send;
    /// Atomically consume one unexpired `AuthStart` row and create the
    /// corresponding `Login` row. A `false` result means the source row was
    /// absent, expired, already consumed, or did not match the prepared flow.
    /// The Login insert is strict: a token collision is an error and must roll
    /// the source deletion back.
    fn pending_auth_transition(
        &self,
        auth_start_token: &str,
        login_token: &str,
        login_state: &crate::auth::middleware::PendingAuth,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Drop every pending-auth row past its TTL. Returns the number of
    /// rows removed, for metrics / audit logging only.
    fn pending_auth_cleanup_expired(&self) -> impl Future<Output = Result<u64>> + Send;

    // ───── Session handoff replay guard ─────
    /// Atomically record a nonce. `true` is the unique-insert winner;
    /// `false` means the nonce was already consumed.
    fn handoff_nonce_consume(&self, nonce: Uuid) -> impl Future<Output = Result<bool>> + Send;
    /// Delete consumed nonces older than the fixed retention window.
    fn handoff_nonce_cleanup_expired(&self) -> impl Future<Output = Result<u64>> + Send;

    // ───── DEK ring (master_keys table) ─────
    /// Read every non-retired DEK row. Each row's `key_encrypted` is a
    /// base64 v2 blob over the KEK; the caller decrypts and assembles
    /// the in-memory `MasterKeyRing`.
    fn master_keys_load_active_set(&self)
    -> impl Future<Output = Result<Vec<MasterKeyRow>>> + Send;
    /// Atomically install key ID 0 as the first active DEK only when the
    /// complete `master_keys` table is empty. Bumps the ring version only
    /// for the winning insert.
    #[cfg(test)]
    fn master_keys_insert_first_active_if_empty(
        &self,
        key_encrypted: &str,
    ) -> impl Future<Output = Result<FirstDekInsertOutcome>> + Send;
    /// Production bootstrap path. Candidate entropy may be generated before
    /// locking, but KEK encryption happens only after the global I→D locks.
    fn master_keys_insert_first_active_plaintext(
        &self,
        key_plaintext: &[u8],
        master_key: &crate::crypto::MasterKey,
    ) -> impl Future<Output = Result<FirstDekInsertOutcome>> + Send;
    /// Test-only explicit-ID insert used to construct rotation fixtures.
    #[cfg(test)]
    fn master_keys_insert(
        &self,
        key_id: i16,
        key_encrypted: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Allocate the smallest unreserved v3 key ID and insert an inactive
    /// encrypted DEK in the same transaction as the key-ring version bump.
    #[cfg(test)]
    fn master_keys_allocate_inactive(
        &self,
        key_encrypted: &str,
    ) -> impl Future<Output = Result<i16>> + Send;
    /// Production allocation path with lock-before-encrypt semantics.
    fn master_keys_allocate_inactive_plaintext(
        &self,
        key_plaintext: &[u8],
        master_key: &crate::crypto::MasterKey,
    ) -> impl Future<Output = Result<i16>> + Send;
    /// Flip `key_id` to `active = true`, demote any previously-active
    /// row to `active = false`, all in one transaction. Bumps the ring
    /// version. Returns `Err` if the row is missing or retired.
    fn master_keys_activate(&self, key_id: i16) -> impl Future<Output = Result<()>> + Send;
    /// Flip `key_id` to `retired = true`. Caller is responsible for
    /// having confirmed no row in any encrypted column still references
    /// the key (the CLI `retire` verb runs that check before calling
    /// here). Refuses to retire the active row.
    fn master_keys_retire(&self, key_id: i16) -> impl Future<Output = Result<()>> + Send;
    /// Current monotonic `key_ring_version` from `schema_versions`.
    /// Polled by every node; a mismatch triggers a ring rebuild.
    fn key_ring_version_current(&self) -> impl Future<Output = Result<u64>> + Send;

    fn identity_signing_load(
        &self,
    ) -> impl Future<
        Output = Result<(
            u64,
            Vec<IdentitySigningKeyRow>,
            crate::crypto::MasterKeyRing,
        )>,
    > + Send;
    fn identity_signing_bootstrap(
        &self,
        kid: &str,
        private_pkcs8: &[u8],
        public_jwk: &str,
    ) -> impl Future<Output = Result<IdentitySigningBootstrapOutcome>> + Send;
    fn identity_signing_rotate(
        &self,
        kid: &str,
        private_pkcs8: &[u8],
        public_jwk: &str,
        grace_secs: i64,
    ) -> impl Future<Output = Result<IdentitySigningRotateOutcome>> + Send;
    fn identity_signing_version_current(&self) -> impl Future<Output = Result<u64>> + Send;
    fn identity_signing_reencrypt_current(
        &self,
    ) -> impl Future<Output = Result<IdentitySigningReencryptOutcome>> + Send;
    fn identity_signing_scan_key_id(&self, key_id: u8) -> impl Future<Output = Result<u64>> + Send;

    // ───── Liveness / readiness ─────
    /// Issue a trivial `SELECT 1` (or equivalent) to prove the backend's
    /// connection pool still has a live round-trip to the service DB.
    /// Used by `/readyz` so a load balancer / orchestrator drains a node
    /// whose pool has silently stalled (network partition, DB bounced,
    /// etc.) — the boot-time `is_service_backend_available` flag stays
    /// stuck at "true" in that case.
    fn ping(&self) -> impl Future<Output = Result<()>> + Send;
}

/// Closed set of concrete backends. Matches on this enum inside `Store`
/// stay exhaustive, which is deliberately what catches a new backend
/// forgetting to wire one operation through.
#[derive(Clone)]
pub enum Backend {
    Sqlite(SqliteBackend),
    Postgres(PostgresBackend),
    /// A service DB was configured but we couldn't connect on startup.
    /// Operational queries fail with `Error::ServiceUnavailable`; the
    /// bootstrap API (and therefore the `/instance` resource in the
    /// management API) remains functional so the operator can correct
    /// the DSN and restart. No auto-reconnect: a restart is the
    /// intended recovery path.
    Unavailable {
        reason: String,
    },
}

/// Dispatch the auth-start transition without adding another method to the
/// broad `Store` facade. Keeping this beside `StorageBackend` makes the
/// transaction boundary explicit while `AuthStateStore` remains the only
/// auth-layer caller.
pub(crate) async fn pending_auth_transition(
    store: &crate::store::Store,
    auth_start_token: &str,
    login_token: &str,
    login_state: &crate::auth::middleware::PendingAuth,
) -> Result<bool> {
    match &store.backend {
        Backend::Sqlite(backend) => {
            StorageBackend::pending_auth_transition(
                backend,
                auth_start_token,
                login_token,
                login_state,
            )
            .await
        }
        Backend::Postgres(backend) => {
            StorageBackend::pending_auth_transition(
                backend,
                auth_start_token,
                login_token,
                login_state,
            )
            .await
        }
        Backend::Unavailable { reason } => {
            Err(crate::error::Error::ServiceUnavailable(reason.clone()))
        }
    }
}
