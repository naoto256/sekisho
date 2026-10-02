//! Shared helpers for the JSON-blob CRUD pattern used by routes, identity
//! providers, and policies. Each of those tables stores the canonical record
//! as a JSON string in `data`, with `id` / `name` as separate columns for
//! indexing and uniqueness. The helpers below factor out the common shape
//! (fetch-parse-error) so the resource modules focus on their resource-
//! specific bindings and side effects (cache invalidation, generation
//! counters, etc.).

use crate::error::{Error, Result};
pub(super) use crate::store::backend::crud_helpers::{
    apply_merge, map_unique_violation, parse_json, to_json_string,
};
use crate::store::backend::{NamedResource, Table};
use crate::store::version::DbVersion;
use serde::de::DeserializeOwned;
use sqlx::{Executor, Sqlite, SqlitePool};
use uuid::Uuid;

/// Fetch all JSON rows from `table` ordered by `name` and deserialize them.
/// `Table::kind()` only appears in error messages ("corrupt {kind} data: ...").
pub(super) async fn list_json<T: DeserializeOwned>(
    pool: &SqlitePool,
    table: Table,
) -> Result<Vec<T>> {
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
    pool: &SqlitePool,
    table: Table,
    limit: i64,
    offset: i64,
) -> Result<Vec<T>> {
    let query = format!(
        "SELECT data FROM {} ORDER BY name LIMIT ? OFFSET ?",
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

/// Fetch one JSON row by `id`, deserialize it, or return `NotFound`.
pub(super) async fn get_json_by_id<T: DeserializeOwned>(
    pool: &SqlitePool,
    table: Table,
    id: Uuid,
) -> Result<T> {
    let query = format!("SELECT data FROM {} WHERE id = ?", table.sql());
    let s = sqlx::query_scalar::<_, String>(&query)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(Error::NotFound)?;
    parse_json(&s, table.kind())
}

/// Fetch the raw JSON string by id from a transaction (for UPDATE flows).
pub(super) async fn fetch_json_tx<'e, E>(exec: E, table: Table, id: Uuid) -> Result<String>
where
    E: Executor<'e, Database = Sqlite>,
{
    let query = format!("SELECT data FROM {} WHERE id = ?", table.sql());
    sqlx::query_scalar::<_, String>(&query)
        .bind(id)
        .fetch_optional(exec)
        .await?
        .ok_or(Error::NotFound)
}

/// `INSERT INTO {table} (id, name, data[, <extras>]) VALUES (...)` against
/// an arbitrary executor (pool or transaction connection).
///
/// `extras` covers resources whose schema has one extra indexable
/// column beside id/name/data (currently only `identity_providers`
/// with its `idp_type` discriminator). Unique-violation errors are
/// mapped to `Conflict` using the resource's own name, so the
/// message reads the same no matter which resource collided.
///
/// Writers that also need to bump a cache-invalidation version pass
/// the same transaction handle to `DbVersion::bump` so the INSERT and
/// the version move commit as a unit — no peer ever sees the new row
/// at the old version, and no writer crash leaves an unbumped row
/// behind.
pub(super) async fn insert_named_exec<'e, E, T: NamedResource>(
    exec: E,
    table: Table,
    id: Uuid,
    value: &T,
    extras: &[(&str, &str)],
) -> Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    let serialized = to_json_string(value)?;
    let mut columns: Vec<&str> = vec!["id", "name"];
    for (col, _) in extras {
        columns.push(col);
    }
    columns.push("data");
    let placeholders = vec!["?"; columns.len()].join(", ");
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

/// Run a merge-patch update under `BEGIN IMMEDIATE` for any resource
/// that stores `{id, name, data, updated_at}`. Takes the writer lock
/// up front (see `super::begin_immediate` for rationale) so concurrent
/// writers queue cleanly instead of racing a DEFERRED-to-RESERVED
/// upgrade into `SQLITE_BUSY`. Returns the merged row.
///
/// `bump_version` is the DB-sourced cache-invalidation counter for this
/// resource, bumped in-tx so readers on any node see the new row and the
/// new version atomically. Pass `None` for resources that don't track a
/// version (currently: policies — no in-memory cache).
pub(super) async fn update_named_by_id<T: NamedResource>(
    pool: &SqlitePool,
    table: Table,
    id: Uuid,
    update: &serde_json::Value,
    bump_version: Option<&DbVersion>,
) -> Result<T> {
    let mut tx = super::begin_immediate(pool).await?;

    let result: Result<T> = async {
        let current = fetch_json_tx(&mut *tx, table, id).await?;
        let merged: T = apply_merge(&current, update, table.kind())?;
        let serialized = to_json_string(&merged)?;
        let sql = format!(
            "UPDATE {} SET name = ?, data = ?, updated_at = unixepoch() WHERE id = ?",
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

    super::finish_immediate(tx, result).await
}

/// `DELETE FROM {table} WHERE id = ?`; return `NotFound` if no row matched.
/// Takes an executor so callers can run the delete inside a transaction
/// together with a version bump.
pub(super) async fn delete_by_id_exec<'e, E>(exec: E, table: Table, id: Uuid) -> Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    let query = format!("DELETE FROM {} WHERE id = ?", table.sql());
    let r = sqlx::query(&query).bind(id).execute(exec).await?;
    if r.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Pool-based delete for callers that don't need transactional framing
/// (resources with no version-bump companion — currently policies only).
pub(super) async fn delete_by_id(pool: &SqlitePool, table: Table, id: Uuid) -> Result<()> {
    delete_by_id_exec(pool, table, id).await
}

/// Pool-based insert for callers with no version to bump (policies).
/// Keeps the Pool-taking shape at the one callsite that still needs it
/// so adding a new resource of that shape doesn't require plumbing a
/// fresh helper.
pub(super) async fn insert_named<T: NamedResource>(
    pool: &SqlitePool,
    table: Table,
    id: Uuid,
    value: &T,
    extras: &[(&str, &str)],
) -> Result<()> {
    insert_named_exec(pool, table, id, value, extras).await
}
