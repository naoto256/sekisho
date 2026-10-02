//! Small serde helpers shared across resource models and PATCH handlers.

use serde::{Deserialize, Deserializer};

/// Deserialize an `Option<Option<T>>` field so that the *outer* Option
/// distinguishes "field absent in the JSON object" from "field present"
/// (including JSON `null`). Serde's default `Option` deserializer
/// collapses both to `None`, which makes `Option<Option<T>>` unable to
/// represent an explicit "set this nullable field to null" patch — the
/// CLI's `unset` verb (and any RFC 7396 PATCH that names a field with
/// `null`) silently no-ops without this.
///
/// With this deserializer:
/// * field absent       → outer `None`
/// * field = `null`     → outer `Some`, inner `None`
/// * field = `value`    → outer `Some`, inner `Some(value)`
///
/// Pair with `#[serde(default, deserialize_with = "deserialize_some",
/// skip_serializing_if = "Option::is_none")]` on every `Option<Option<T>>`
/// field that should support explicit-null clears.
pub fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}
