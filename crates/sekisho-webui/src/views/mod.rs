//! HTML views — Maud templates shared by handlers.

pub mod general;
pub mod home;
pub mod idps;
pub mod layout;
pub mod policies;
pub mod routes;
pub mod setup;

pub use layout::Page;

use maud::{Markup, html};
use serde_json::Value;

// ───────────────────────── Shared cell renderers ─────────────────────────

/// Pull a string-ish field out of a JSON object and render it in HTML.
/// Handles the common types without the caller having to destructure
/// the `serde_json::Value`: strings pass through, numbers/bools render
/// as their display form, arrays become comma-joined, null/missing
/// becomes an em-dash.
pub fn render_cell(item: &Value, key: &str) -> Markup {
    match item.get(key) {
        None | Some(Value::Null) => html! { span class="muted" { "—" } },
        Some(Value::String(s)) if s.is_empty() => html! { span class="muted" { "—" } },
        Some(Value::String(s)) => html! { (s) },
        // Columns whose name ends in `_at` are Unix epoch seconds on
        // the wire (chrono::serde::ts_seconds on the daemon side).
        // Render them as `YYYY-MM-DD HH:MM` UTC so the table reads
        // like a date, not a 10-digit blob.
        Some(Value::Number(n)) if key.ends_with("_at") => render_epoch_ts(n),
        Some(Value::Number(n)) => html! { (n.to_string()) },
        Some(Value::Bool(b)) => html! { (b.to_string()) },
        Some(Value::Array(arr)) => {
            let joined: Vec<String> = arr
                .iter()
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            html! { (joined.join(", ")) }
        }
        Some(other) => html! { code { (other.to_string()) } },
    }
}

/// Render a JSON number as a UTC date-time, falling back to the raw
/// digits if it doesn't parse as epoch seconds (defensive: a future
/// non-`_at` numeric column accidentally caught by the suffix rule
/// shouldn't render as `1970-01-...`).
fn render_epoch_ts(n: &serde_json::Number) -> Markup {
    let Some(secs) = n.as_i64() else {
        return html! { (n.to_string()) };
    };
    // Append the literal " UTC" so an operator reading the table
    // can't mistake it for local time. The admin console deliberately
    // stays UTC across all surfaces (log lines, audit events, every
    // _at column) so two operators in different timezones see the
    // same value.
    match chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0) {
        Some(dt) => html! { (dt.format("%Y-%m-%d %H:%M UTC").to_string()) },
        None => html! { (n.to_string()) },
    }
}

/// Pull the `id` out of a resource JSON object, as `Option<String>`.
/// Convenient for htmx attributes that reference the item.
pub fn extract_id(item: &Value) -> Option<String> {
    item.get("id").and_then(|v| v.as_str()).map(String::from)
}
