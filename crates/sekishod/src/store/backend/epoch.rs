//! Conversion helpers between `chrono::DateTime<Utc>` and Unix epoch
//! seconds (`i64`).
//!
//! Every timestamp column in both backends is stored as a 64-bit integer
//! count of seconds since the Unix epoch — `INTEGER` on SQLite,
//! `BIGINT` on Postgres. Doing the conversion at the bind / FromRow
//! boundary keeps the rest of the crate working in `DateTime<Utc>` so
//! arithmetic, comparisons, and the `chrono::Duration` API stay
//! ergonomic. The wire format on the API side is also seconds, surfaced
//! through `chrono::serde::ts_seconds` on the model structs.

use chrono::{DateTime, Utc};

#[inline]
pub(super) fn to_epoch(dt: DateTime<Utc>) -> i64 {
    dt.timestamp()
}

/// Convert epoch seconds back into `DateTime<Utc>`. Stored values are
/// only ever produced by `to_epoch` (or by the DB's own `unixepoch()` /
/// `EXTRACT(EPOCH FROM NOW())::BIGINT` defaults) so the value is
/// guaranteed to be in chrono's representable range; the unwrap is the
/// honest signal that a corrupt row is a bug.
#[inline]
pub(super) fn from_epoch(s: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(s, 0)
        .unwrap_or_else(|| panic!("epoch seconds out of chrono range: {s}"))
}

#[inline]
pub(super) fn from_epoch_opt(s: Option<i64>) -> Option<DateTime<Utc>> {
    s.map(from_epoch)
}
