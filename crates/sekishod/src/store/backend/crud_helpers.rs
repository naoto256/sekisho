//! Backend-agnostic helpers shared between the SQLite and Postgres
//! CRUD modules. These are pure functions — no SQL, no executor — so
//! they live above the per-backend submodules. Anything that touches
//! placeholder syntax (`?` vs `$1`) or an executor type stays in the
//! backend-specific `crud.rs`.

use crate::error::{Error, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Parse a JSON row into `T` with a consistent corruption error message.
pub(super) fn parse_json<T: DeserializeOwned>(s: &str, kind: &str) -> Result<T> {
    serde_json::from_str(s).map_err(|e| Error::Internal(format!("corrupt {kind} data: {e}")))
}

/// Serialize any value with a consistent error message.
pub(super) fn to_json_string<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| Error::Internal(format!("serialize error: {e}")))
}

/// Apply RFC 7396 JSON Merge Patch to `current_json` and deserialize the
/// result into `T`. Mismatches after merge are surfaced as `Internal` so the
/// caller can attribute them to a bad patch rather than a bad stored record.
pub(super) fn apply_merge<T: DeserializeOwned>(
    current_json: &str,
    update: &serde_json::Value,
    kind: &str,
) -> Result<T> {
    let mut base: serde_json::Value = serde_json::from_str(current_json)
        .map_err(|e| Error::Internal(format!("corrupt {kind} data: {e}")))?;
    crate::store::merge::json_merge(&mut base, update);
    serde_json::from_value(base)
        .map_err(|e| Error::Internal(format!("invalid {kind} after merge: {e}")))
}

/// Map a sqlx unique-violation into `Conflict("{kind} '{name}' already
/// exists")`; other errors stay as `Database`.
pub(super) fn map_unique_violation(e: sqlx::Error, kind: &str, name: &str) -> Error {
    match e {
        sqlx::Error::Database(ref db) if db.is_unique_violation() => {
            Error::Conflict(format!("{kind} '{name}' already exists"))
        }
        other => Error::Database(other),
    }
}
