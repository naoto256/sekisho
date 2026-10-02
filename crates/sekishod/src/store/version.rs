//! DB-sourced monotonic version counters, one per resource kind.
//!
//! Today the proxy runs on a single node with SQLite, so local in-memory
//! caches (`RouteCache`, `config_cache`, IdP client cache) can be invalidated
//! by direct method calls on the write path. That approach does not extend to
//! the HA configuration we're moving toward: a second node mutating the same
//! DB has no way to poke this node's cache.
//!
//! The fix is to keep an integer column per resource in the DB itself and
//! bump it inside the same transaction that mutates the resource. Readers
//! then compare the DB version against the last value they observed; a
//! mismatch is the signal to drop and reload the local cache. This works
//! unchanged when the backend swaps to Postgres, because the version source
//! of truth is the shared DB — not any process-local state.
//!
//! # Resource identifiers
//!
//! The `schema_versions.resource` column is a short stable string. The three
//! consts below are the only values ever written, and using `&'static str`
//! lets callsites bind without allocating.

use crate::error::{Error, Result};
use sqlx::{Executor, Sqlite, SqlitePool};

/// Resource key for the routes cache.
pub(super) const RESOURCE_ROUTES: &str = "routes";
/// Resource key for the IdP client cache.
pub(super) const RESOURCE_IDPS: &str = "idps";
/// Resource key for the global-config cache.
pub(super) const RESOURCE_CONFIG: &str = "config";
/// Resource key for the TLS certificate cache.
///
/// Bumped on every `upsert_cert` / `delete_cert` (ACME renewals and
/// mgmt-API cert CUD). The proxy hot path compares the last-seen value
/// against the DB-sourced current one and calls `CertResolver::reload()`
/// on a mismatch — which is how a non-leader node learns that the ACME
/// leader just renewed a cert it was still serving from stale cache.
pub(super) const RESOURCE_CERTS: &str = "certs";
/// Resource key for the DEK ring (master_keys table).
///
/// Bumped inside the same transaction as any `master_keys` mutation
/// (`add` / `activate` / `retire`). Each daemon's polling loop watches
/// this counter and rebuilds the in-memory `MasterKeyRing` on a
/// mismatch, so a rotation issued on one node propagates to peers
/// without out-of-band signalling.
pub(super) const RESOURCE_KEY_RING: &str = "key_ring";
/// Resource key for the Ed25519 identity-signing key ring.
pub(super) const RESOURCE_IDENTITY_SIGNING_KEY_RING: &str = "identity_signing_key_ring";

/// All resources seeded on startup. Kept together so a new resource is a
/// single-line change and the `INSERT OR IGNORE` seed cannot drift out of
/// sync with the const list.
///
/// The management RPK is intentionally absent: it is per-instance bootstrap
/// state, not a service-DB resource replicated through the HA version poll.
pub(super) const ALL_RESOURCES: &[&str] = &[
    RESOURCE_ROUTES,
    RESOURCE_IDPS,
    RESOURCE_CONFIG,
    RESOURCE_CERTS,
    RESOURCE_KEY_RING,
    RESOURCE_IDENTITY_SIGNING_KEY_RING,
];

/// Read + bump of a single resource's version row.
///
/// Cloning is cheap — the pool is `Arc` under the hood and the resource name
/// is a `&'static str`. Cloneability matters because `Store` exposes these as
/// plain fields and the struct itself is `Clone`.
#[derive(Clone)]
pub struct DbVersion {
    pool: SqlitePool,
    resource: &'static str,
}

impl DbVersion {
    pub(super) fn new(pool: SqlitePool, resource: &'static str) -> Self {
        Self { pool, resource }
    }

    /// Current version from the DB. Called on every read that wants to
    /// check staleness, so it stays as a single indexed lookup.
    pub async fn current(&self) -> Result<u64> {
        let v: i64 = sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = ?")
            .bind(self.resource)
            .fetch_one(&self.pool)
            .await
            .map_err(Error::Database)?;
        Ok(v as u64)
    }

    /// Increment this resource's version using the caller's executor.
    ///
    /// This is the key shape: the writer is already inside `BEGIN IMMEDIATE`
    /// for the mutation, and passing the same connection keeps the bump in
    /// that same transaction. Commit and rollback both do the right thing
    /// automatically — no version moves without the mutation also landing.
    pub(super) async fn bump<'e, E>(&self, exec: E) -> Result<()>
    where
        E: Executor<'e, Database = Sqlite>,
    {
        sqlx::query(
            "UPDATE schema_versions SET version = version + 1, updated_at = unixepoch() \
             WHERE resource = ?",
        )
        .bind(self.resource)
        .execute(exec)
        .await
        .map_err(Error::Database)?;
        Ok(())
    }

    /// Non-transactional bump against the pool.
    ///
    /// No production writer uses this: all mutations bump their version
    /// inside the same tx as the mutation so a writer crash between
    /// mutation-commit and bump is impossible. The helper survives only
    /// for tests that want to simulate a peer node poking the version
    /// counter out-of-band.
    #[cfg(test)]
    pub(super) async fn bump_pool(&self) -> Result<()> {
        self.bump(&self.pool).await
    }
}
