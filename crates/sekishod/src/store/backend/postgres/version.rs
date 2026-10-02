//! Postgres counterpart of `store::version::DbVersion`. Same semantics
//! (read current / bump inside a tx or on the pool) against the same
//! `schema_versions` table, different database type so it cannot share
//! the SQLite type's generic bounds.

use crate::error::{Error, Result};
use sqlx::{Executor, PgPool, Postgres};

#[derive(Clone)]
pub struct PgDbVersion {
    pool: PgPool,
    resource: &'static str,
}

impl PgDbVersion {
    pub(super) fn new(pool: PgPool, resource: &'static str) -> Self {
        Self { pool, resource }
    }

    pub async fn current(&self) -> Result<u64> {
        // Postgres stores as BIGINT; cast back to u64. Versions monotonic
        // increment so negative values only happen on a corrupted row.
        let v: i64 = sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = $1")
            .bind(self.resource)
            .fetch_one(&self.pool)
            .await
            .map_err(Error::Database)?;
        Ok(v as u64)
    }

    pub(super) async fn bump<'e, E>(&self, exec: E) -> Result<()>
    where
        E: Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            "UPDATE schema_versions SET version = version + 1, \
             updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT \
             WHERE resource = $1",
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
    #[allow(dead_code)]
    pub(super) async fn bump_pool(&self) -> Result<()> {
        self.bump(&self.pool).await
    }
}
