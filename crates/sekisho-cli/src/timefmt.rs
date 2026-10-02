//! Unix-epoch timestamp helpers for `show` listings.
//!
//! The server returns timestamps as Unix epoch seconds (i64). For
//! interactive listings the operator wants two flavours:
//!
//! - **Absolute, local TZ** for "when does this expire": a deadline is
//!   only useful in the operator's wall-clock frame. Renders as
//!   `YYYY-MM-DD HH:MM:SS` in the local zone (no timezone suffix —
//!   the column header carries that).
//! - **Relative, coarse** for "when did this happen": creation times
//!   read as `3 hours ago` / `just now` rather than a precise blob the
//!   eye has to parse.
//!
//! Both helpers degrade to `"-"` on out-of-range input rather than
//! panicking — a malformed timestamp from the server shouldn't break
//! the table render.

use chrono::{DateTime, Local, Utc};

/// Render `epoch_secs` as `YYYY-MM-DD HH:MM:SS ±HHMM` in the local
/// timezone. Returns `"-"` on out-of-range input.
///
/// The trailing UTC offset (`%z` → e.g. `+0900`) is unambiguous and
/// portable across platforms, where `%Z` (timezone name like `JST`)
/// degrades to an empty string on some libc / chrono builds.
pub fn format_local(epoch_secs: i64) -> String {
    match DateTime::<Utc>::from_timestamp(epoch_secs, 0) {
        Some(dt) => dt
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S %z")
            .to_string(),
        None => "-".to_string(),
    }
}

/// Render `epoch_secs` as a coarse "ago" string relative to `now`.
/// Future timestamps render as `in N ...` so the helper stays useful
/// for both `created_at` (past) and `expires_at` debugging (future).
/// Returns `"-"` on out-of-range input.
pub fn format_relative(epoch_secs: i64, now: DateTime<Utc>) -> String {
    let Some(then) = DateTime::<Utc>::from_timestamp(epoch_secs, 0) else {
        return "-".to_string();
    };
    let delta = now.signed_duration_since(then);
    let secs = delta.num_seconds();
    let (magnitude, suffix) = if secs >= 0 {
        (secs, "ago")
    } else {
        (-secs, "from now")
    };
    coarse(magnitude, suffix)
}

fn coarse(secs: i64, suffix: &str) -> String {
    if secs < 60 {
        // The "from now" branch for sub-minute future deltas would
        // read awkwardly; keep "just now" reserved for the past and
        // fall back to "in N seconds" for the future.
        return if suffix == "ago" {
            "just now".to_string()
        } else {
            format!("in {secs} seconds")
        };
    }
    let mins = secs / 60;
    if mins < 60 {
        return plural(mins, "minute", suffix);
    }
    let hours = mins / 60;
    if hours < 24 {
        return plural(hours, "hour", suffix);
    }
    let days = hours / 24;
    if days < 30 {
        return plural(days, "day", suffix);
    }
    let months = days / 30;
    if months < 12 {
        return plural(months, "month", suffix);
    }
    let years = days / 365;
    plural(years, "year", suffix)
}

fn plural(n: i64, unit: &str, suffix: &str) -> String {
    let s = if n == 1 { "" } else { "s" };
    if suffix == "from now" {
        format!("in {n} {unit}{s}")
    } else {
        format!("{n} {unit}{s} {suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn format_local_renders_yyyy_mm_dd_hh_mm_ss() {
        // We can't assert the exact string (depends on the test
        // machine's TZ) but we can assert the shape:
        // `YYYY-MM-DD HH:MM:SS ±HHMM` — 25 chars on every TZ that
        // emits a 4-digit numeric offset (everywhere chrono runs).
        let ts = Utc
            .with_ymd_and_hms(2026, 4, 25, 12, 34, 56)
            .unwrap()
            .timestamp();
        let out = format_local(ts);
        assert_eq!(out.len(), 25);
        assert_eq!(&out[4..5], "-");
        assert_eq!(&out[10..11], " ");
        assert_eq!(&out[13..14], ":");
        assert_eq!(&out[19..20], " ");
        // Sign byte at position 20 must be '+' or '-'.
        let sign = &out[20..21];
        assert!(sign == "+" || sign == "-", "unexpected sign byte: {sign}");
    }

    #[test]
    fn relative_just_now_under_a_minute() {
        let now = Utc.with_ymd_and_hms(2026, 4, 25, 12, 0, 0).unwrap();
        // 30s ago.
        let then = (now - chrono::Duration::seconds(30)).timestamp();
        assert_eq!(format_relative(then, now), "just now");
    }

    #[test]
    fn relative_minutes_pluralize_correctly() {
        let now = Utc.with_ymd_and_hms(2026, 4, 25, 12, 0, 0).unwrap();
        let one = (now - chrono::Duration::minutes(1)).timestamp();
        assert_eq!(format_relative(one, now), "1 minute ago");
        let many = (now - chrono::Duration::minutes(47)).timestamp();
        assert_eq!(format_relative(many, now), "47 minutes ago");
    }

    #[test]
    fn relative_hours_and_days() {
        let now = Utc.with_ymd_and_hms(2026, 4, 25, 12, 0, 0).unwrap();
        let one_h = (now - chrono::Duration::hours(1)).timestamp();
        assert_eq!(format_relative(one_h, now), "1 hour ago");
        let three_h = (now - chrono::Duration::hours(3)).timestamp();
        assert_eq!(format_relative(three_h, now), "3 hours ago");
        let two_d = (now - chrono::Duration::days(2)).timestamp();
        assert_eq!(format_relative(two_d, now), "2 days ago");
    }

    #[test]
    fn relative_future_uses_in_prefix() {
        let now = Utc.with_ymd_and_hms(2026, 4, 25, 12, 0, 0).unwrap();
        let in_two_h = (now + chrono::Duration::hours(2)).timestamp();
        assert_eq!(format_relative(in_two_h, now), "in 2 hours");
        let in_30s = (now + chrono::Duration::seconds(30)).timestamp();
        assert_eq!(format_relative(in_30s, now), "in 30 seconds");
    }
}
