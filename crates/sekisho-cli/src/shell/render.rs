//! Output rendering for shell commands.
//!
//! `route_status` and `render_sessions_table` are pure presenters
//! taking already-fetched values; `idp_name_map` is the one network
//! call here, kept colocated so the session table's `IDP` column can
//! resolve `idp_id → name` without scattering the lookup across
//! commands.

use sekisho_api_protocol::api_paths;
use serde_json::Value;

use crate::api::ApiClient;

/// One-line status for a route used by `show route` listings.
/// Derived from the single `enabled` flag now that the server no
/// longer carries transient ACME state — the shell's job is just to
/// render what the server has.
pub(super) fn route_status(route: &Value) -> &'static str {
    let enabled = route
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if enabled { "enabled" } else { "disabled" }
}

/// Fetch the IdP list and project it to a `id -> name` map. One round
/// trip; failures degrade to an empty map so a missing `/idps` doesn't
/// break the sessions table — the IDP column will fall back to
/// `<deleted>` for every row.
pub(super) async fn idp_name_map(client: &ApiClient) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Ok(items) = client.get_list(api_paths::IDPS).await else {
        return out;
    };
    for item in &items {
        let id = item.get("id").and_then(|v| v.as_str());
        let name = item.get("name").and_then(|v| v.as_str());
        if let (Some(id), Some(name)) = (id, name) {
            out.insert(id.to_string(), name.to_string());
        }
    }
    out
}

/// Build the 5-column session table body (header + rows). Pure: takes
/// items + IdP-name lookup + "now" so the test suite can pin the
/// relative-time column.
pub(super) fn render_sessions_table(
    items: &[Value],
    idp_names: &std::collections::HashMap<String, String>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|s| {
            let id_full = s.get("id").and_then(|v| v.as_str()).unwrap_or("-");
            // 8-char prefix + ellipsis matches webui's truncation; full
            // UUID is one `show sessions <id>` away if needed.
            let id_short = if id_full.len() > 8 {
                format!("{}...", &id_full[..8])
            } else {
                id_full.to_string()
            };
            let user = s
                .get("user_id")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string();
            let idp_id = s.get("idp_id").and_then(|v| v.as_str()).unwrap_or("");
            let idp = if idp_id.is_empty() {
                "-".to_string()
            } else {
                idp_names
                    .get(idp_id)
                    .cloned()
                    .unwrap_or_else(|| "<deleted>".to_string())
            };
            let expires = s
                .get("expires_at")
                .and_then(|v| v.as_i64())
                .map(crate::timefmt::format_local)
                .unwrap_or_else(|| "-".to_string());
            let created = s
                .get("created_at")
                .and_then(|v| v.as_i64())
                .map(|n| crate::timefmt::format_relative(n, now))
                .unwrap_or_else(|| "-".to_string());
            vec![id_short, user, idp, expires, created]
        })
        .collect();
    crate::table::render(&["ID", "USER", "IDP", "EXPIRES", "CREATED"], &rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        use chrono::TimeZone;
        chrono::Utc.with_ymd_and_hms(2026, 4, 25, 12, 0, 0).unwrap()
    }

    #[test]
    fn render_sessions_table_emits_header_and_one_row() {
        let mut idps = std::collections::HashMap::new();
        idps.insert(
            "11111111-1111-1111-1111-111111111111".into(),
            "entra-saml".into(),
        );
        let items = vec![json!({
            "id": "3a4b1c2d-aaaa-bbbb-cccc-deadbeef0001",
            "user_id": "alice@example.com",
            "idp_id": "11111111-1111-1111-1111-111111111111",
            // 2026-04-25 09:00:00 UTC → fixed_now is 12:00 UTC, so 3 hours ago.
            "created_at": 1777107600i64,
            "expires_at": 1777194000i64,
        })];
        let out = render_sessions_table(&items, &idps, fixed_now());
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "header + 1 row");
        assert!(lines[0].starts_with("ID"));
        assert!(lines[0].contains("USER"));
        assert!(lines[0].contains("IDP"));
        assert!(lines[0].contains("EXPIRES"));
        assert!(lines[0].contains("CREATED"));
        assert!(lines[1].starts_with("3a4b1c2d..."));
        assert!(lines[1].contains("alice@example.com"));
        assert!(lines[1].contains("entra-saml"));
        // 12:00 UTC -> 3 hours after 09:00 UTC creation.
        assert!(lines[1].ends_with("3 hours ago"));
    }

    #[test]
    fn render_sessions_table_emits_n_rows_for_n_items() {
        let mut idps = std::collections::HashMap::new();
        idps.insert(
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
            "google-oidc".into(),
        );
        let items = vec![
            json!({
                "id": "11111111-aaaa-bbbb-cccc-000000000001",
                "user_id": "a@example.com",
                "idp_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "created_at": 1777114800i64,  // 2026-04-25 11:00:00 UTC
                "expires_at": 1777201200i64,  // 2026-04-26 11:00:00 UTC
            }),
            json!({
                "id": "22222222-aaaa-bbbb-cccc-000000000002",
                "user_id": "b@example.com",
                "idp_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "created_at": 1777116600i64,  // 2026-04-25 11:30:00 UTC
                "expires_at": 1777203000i64,  // 2026-04-26 11:30:00 UTC
            }),
        ];
        let out = render_sessions_table(&items, &idps, fixed_now());
        assert_eq!(out.lines().count(), 3, "header + 2 rows");
    }

    #[test]
    fn render_sessions_table_marks_orphan_idp_as_deleted() {
        // Empty idp_names -> session points at a UUID we can't resolve.
        let idps = std::collections::HashMap::new();
        let items = vec![json!({
            "id": "deadbeef-aaaa-bbbb-cccc-000000000099",
            "user_id": "ghost@example.com",
            "idp_id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "created_at": 1777118370i64,  // 2026-04-25 11:59:30 UTC (30s before fixed_now)
            "expires_at": 1777204770i64,  // 2026-04-26 11:59:30 UTC
        })];
        let out = render_sessions_table(&items, &idps, fixed_now());
        assert!(
            out.contains("<deleted>"),
            "orphan IdP must surface as <deleted>: {out}"
        );
        assert!(
            out.contains("just now"),
            "30s-old session reads as 'just now': {out}"
        );
    }

    #[test]
    fn route_status_derivation() {
        assert_eq!(route_status(&json!({ "enabled": true })), "enabled");
        assert_eq!(route_status(&json!({ "enabled": false })), "disabled");
        assert_eq!(route_status(&json!({})), "disabled");
    }
}
