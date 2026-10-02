//! `idp_ref` field handling: turn an operator-typed name or UUID into
//! the JSON value the server expects, and the reverse — annotate a
//! shown resource with the IdP names its UUIDs point at.

use sekisho_api_protocol::api_paths;
use serde_json::Value;

use crate::api::ApiClient;
use crate::resources::descriptor;

use super::json::is_uuid;

/// Convert an operator-typed IdP reference into the JSON value the
/// server expects (`null` to clear, a UUID string otherwise). Raw
/// UUIDs are passed through unchanged — existing scripts that paste a
/// UUID keep working. Anything else is treated as an IdP name and
/// resolved via `GET /idps`; the `name` column is `UNIQUE` server-
/// side so the match is unambiguous. On failure we list the known
/// IdP names so the operator can fix a typo without leaving the shell.
pub(super) async fn resolve_idp_ref(client: &ApiClient, raw: &str) -> Result<Value, String> {
    let v = raw.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("null") || is_uuid(v) {
        return resolve_idp_ref_from_items(v, &[]);
    }
    let items = client
        .get_list(api_paths::IDPS)
        .await
        .map_err(|e| format!("failed to fetch IdP list: {e}"))?;
    resolve_idp_ref_from_items(v, &items)
}

/// Pure resolver kept separate from `resolve_idp_ref` so the
/// name-lookup / error-message logic is unit-testable without
/// standing up an API client.
///
/// - Empty / `null` → JSON null (clears the pointer).
/// - UUID → passed through verbatim; `items` is ignored.
/// - Name → matched against `items[*].name`; UUID pulled from `.id`.
/// - Miss → descriptive error listing known names.
pub(super) fn resolve_idp_ref_from_items(raw: &str, items: &[Value]) -> Result<Value, String> {
    let v = raw.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("null") {
        return Ok(Value::Null);
    }
    if is_uuid(v) {
        return Ok(Value::String(v.to_string()));
    }
    let hit = items.iter().find(|i| {
        i.get("name")
            .and_then(|n| n.as_str())
            .is_some_and(|n| n == v)
    });
    if let Some(idp) = hit
        && let Some(id) = idp.get("id").and_then(|x| x.as_str())
    {
        return Ok(Value::String(id.to_string()));
    }
    let names: Vec<&str> = items
        .iter()
        .filter_map(|i| i.get("name").and_then(|n| n.as_str()))
        .collect();
    let hint = if names.is_empty() {
        "no IdPs are configured; run `create idp <name>` first".to_string()
    } else {
        format!("known IdPs: {}", names.join(", "))
    };
    Err(format!("no IdP named \"{v}\" — {hint}"))
}

/// Print a one-line hint mapping every `idp_ref` field in `value` to
/// the IdP's human-readable name. `resolve_idp_ref` handles the input
/// direction; this is its read-side mirror so `show config` doesn't
/// leave the operator squinting at a bare UUID. Silent on any error
/// (list fetch failing, field missing, unknown IdP) — this is
/// decoration, not data.
pub(super) async fn annotate_idp_refs(client: &ApiClient, resource: &str, value: &Value) {
    let Some(def) = descriptor(resource) else {
        return;
    };
    let refs: Vec<(String, String)> = def
        .fields
        .iter()
        .filter(|f| f.ty == "idp_ref")
        .filter_map(|f| {
            value
                .get(f.name)
                .and_then(|v| v.as_str())
                .map(|id| (f.name.to_string(), id.to_string()))
        })
        .collect();
    if refs.is_empty() {
        return;
    }
    let Ok(items) = client.get_list(api_paths::IDPS).await else {
        return;
    };
    for (field, id) in refs {
        let name = items
            .iter()
            .find(|i| i.get("id").and_then(|x| x.as_str()) == Some(id.as_str()))
            .and_then(|i| i.get("name").and_then(|n| n.as_str()))
            .unwrap_or("<unknown>");
        eprintln!("  {field} -> {name}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_idp_ref_empty_and_null_become_json_null() {
        assert_eq!(resolve_idp_ref_from_items("", &[]).unwrap(), Value::Null);
        assert_eq!(
            resolve_idp_ref_from_items("null", &[]).unwrap(),
            Value::Null
        );
        assert_eq!(
            resolve_idp_ref_from_items("  NULL  ", &[]).unwrap(),
            Value::Null
        );
    }

    #[test]
    fn resolve_idp_ref_passes_uuid_through_without_lookup() {
        // Even with an empty item list, a UUID string is accepted — so
        // operators who already have the UUID keep working even if the
        // list fetch would have been empty or stale.
        let out = resolve_idp_ref_from_items("11111111-2222-3333-4444-555555555555", &[]).unwrap();
        assert_eq!(out, json!("11111111-2222-3333-4444-555555555555"));
    }

    #[test]
    fn resolve_idp_ref_looks_up_name_in_items() {
        let items = vec![
            json!({"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "name": "corp-okta"}),
            json!({"id": "11111111-2222-3333-4444-555555555555", "name": "dev-keycloak"}),
        ];
        let out = resolve_idp_ref_from_items("dev-keycloak", &items).unwrap();
        assert_eq!(out, json!("11111111-2222-3333-4444-555555555555"));
    }

    #[test]
    fn resolve_idp_ref_unknown_name_lists_candidates() {
        let items = vec![
            json!({"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "name": "corp-okta"}),
            json!({"id": "11111111-2222-3333-4444-555555555555", "name": "dev-keycloak"}),
        ];
        let err = resolve_idp_ref_from_items("ghost", &items).unwrap_err();
        assert!(
            err.contains("\"ghost\""),
            "err should quote the name: {err}"
        );
        assert!(err.contains("corp-okta"));
        assert!(err.contains("dev-keycloak"));
    }

    #[test]
    fn resolve_idp_ref_empty_catalog_suggests_create() {
        let err = resolve_idp_ref_from_items("anything", &[]).unwrap_err();
        assert!(
            err.contains("create idp"),
            "err should hint at create: {err}"
        );
    }
}
