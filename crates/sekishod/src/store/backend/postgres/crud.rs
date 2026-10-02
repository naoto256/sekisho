//! Postgres counterpart of `sqlite/crud.rs`. Same JSON-blob CRUD
//! shape (id / name / data), different placeholder syntax (`$1`
//! rather than `?`) and different executor type (`PgPool`). The
//! helpers stay small and duplicated rather than trying to
//! abstract across backends — the per-backend SQL is the only
//! thing that actually differs, and hiding it behind yet another
//! trait would obscure the few behaviour differences that matter
//! (ON CONFLICT, isolation level, error classification).

use crate::error::{Error, Result};
pub(super) use crate::store::backend::crud_helpers::{
    apply_merge, map_unique_violation, parse_json, to_json_string,
};
use crate::store::backend::{NamedResource, Table};
use serde::de::DeserializeOwned;
use sqlx::PgPool;
use uuid::Uuid;

use super::version::PgDbVersion;

pub(super) async fn list_json<T: DeserializeOwned>(pool: &PgPool, table: Table) -> Result<Vec<T>> {
    let query = format!("SELECT data FROM {} ORDER BY name", table.sql());
    let rows = sqlx::query_scalar::<_, String>(&query)
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|s| parse_json(&s, table.kind()))
        .collect()
}

/// Fetch one API page plus its lookahead row from a closed JSON table.
pub(super) async fn list_json_page<T: DeserializeOwned>(
    pool: &PgPool,
    table: Table,
    limit: i64,
    offset: i64,
) -> Result<Vec<T>> {
    let query = format!(
        "SELECT data FROM {} ORDER BY name LIMIT $1 OFFSET $2",
        table.sql()
    );
    let rows = sqlx::query_scalar::<_, String>(&query)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|s| parse_json(&s, table.kind()))
        .collect()
}

pub(super) async fn get_json_by_id<T: DeserializeOwned>(
    pool: &PgPool,
    table: Table,
    id: Uuid,
) -> Result<T> {
    let query = format!("SELECT data FROM {} WHERE id = $1", table.sql());
    let s = sqlx::query_scalar::<_, String>(&query)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(Error::NotFound)?;
    parse_json(&s, table.kind())
}

/// `INSERT INTO {table} (id, name[, <extras>], data) VALUES ($1, $2, ...)`
/// against an arbitrary executor (pool or transaction connection).
/// Postgres uses numbered placeholders, so `extras` are assembled into the
/// SQL by index.
///
/// Writers that also need to bump a cache-invalidation version pass
/// the same transaction handle to `PgDbVersion::bump` so the INSERT
/// and the version move commit together — no peer ever sees the new
/// row at the old version, and no writer crash leaves an unbumped
/// row behind.
pub(super) async fn insert_named_exec<'e, E, T: NamedResource>(
    exec: E,
    table: Table,
    id: Uuid,
    value: &T,
    extras: &[(&str, &str)],
) -> Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let serialized = to_json_string(value)?;
    let mut columns: Vec<&str> = vec!["id", "name"];
    for (col, _) in extras {
        columns.push(col);
    }
    columns.push("data");
    let placeholders = (1..=columns.len())
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({placeholders})",
        table.sql(),
        columns.join(", ")
    );
    let mut q = sqlx::query(&sql).bind(id).bind(value.name().to_string());
    for (_, v) in extras {
        q = q.bind((*v).to_string());
    }
    q.bind(serialized)
        .execute(exec)
        .await
        .map_err(|e| map_unique_violation(e, table.kind(), value.name()))?;
    Ok(())
}

/// Pool-based insert for callers with no version to bump (policies).
pub(super) async fn insert_named<T: NamedResource>(
    pool: &PgPool,
    table: Table,
    id: Uuid,
    value: &T,
    extras: &[(&str, &str)],
) -> Result<()> {
    insert_named_exec(pool, table, id, value, extras).await
}

/// Apply a merge-patch update inside a single transaction, with
/// optional version-bump. Postgres's default READ COMMITTED isolation
/// combined with `FOR UPDATE` on the initial SELECT is enough to
/// serialise concurrent updates to the same row; with SERIALIZABLE
/// we'd get the same guarantee without the row lock, at the cost of
/// retry-on-serialization-failure, which callers aren't written to
/// handle. Row lock is the pragmatic choice.
pub(super) async fn update_named_by_id<T: NamedResource>(
    pool: &PgPool,
    table: Table,
    id: Uuid,
    update: &serde_json::Value,
    bump_version: Option<&PgDbVersion>,
) -> Result<T> {
    let mut tx = pool.begin().await.map_err(Error::Database)?;

    let result: Result<T> = async {
        // SELECT ... FOR UPDATE so a concurrent writer on another
        // connection blocks here instead of our UPDATE overwriting
        // their unseen change.
        let select_sql = format!("SELECT data FROM {} WHERE id = $1 FOR UPDATE", table.sql());
        let current = sqlx::query_scalar::<_, String>(&select_sql)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::NotFound)?;
        let merged: T = apply_merge(&current, update, table.kind())?;
        let serialized = to_json_string(&merged)?;
        let sql = format!(
            "UPDATE {} SET name = $1, data = $2, \
             updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = $3",
            table.sql()
        );
        sqlx::query(&sql)
            .bind(merged.name().to_string())
            .bind(serialized)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_unique_violation(e, table.kind(), merged.name()))?;
        if let Some(version) = bump_version {
            version.bump(&mut *tx).await?;
        }
        Ok(merged)
    }
    .await;

    match &result {
        Ok(_) => {
            tx.commit().await.map_err(Error::Database)?;
        }
        Err(_) => {
            let _ = tx.rollback().await;
        }
    }
    result
}

/// `DELETE FROM {table} WHERE id = $1`; return `NotFound` if no row matched.
/// Takes an executor so callers can run the delete inside a transaction
/// together with a version bump.
pub(super) async fn delete_by_id_exec<'e, E>(exec: E, table: Table, id: Uuid) -> Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let query = format!("DELETE FROM {} WHERE id = $1", table.sql());
    let r = sqlx::query(&query).bind(id).execute(exec).await?;
    if r.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Pool-based delete for callers with no version to bump (policies).
pub(super) async fn delete_by_id(pool: &PgPool, table: Table, id: Uuid) -> Result<()> {
    delete_by_id_exec(pool, table, id).await
}

pub(super) async fn fetch_json_scalar(pool: &PgPool, sql: &str) -> Result<Option<String>> {
    let row = sqlx::query_scalar::<_, String>(sql)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}
