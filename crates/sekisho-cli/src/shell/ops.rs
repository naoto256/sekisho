//! Operational + config-mode commands that don't enter edit context:
//! show / show-all / delete / api-key creation / proxy certificate uploads /
//! route enable-disable / DEK ring lifecycle / export / import.

use sekisho_api_protocol::api_paths;
use serde_json::{Map, Value};

use rustyline::Editor;
use rustyline::history::DefaultHistory;

use crate::api::ApiClient;
use crate::resources::{is_singleton, resource_api_path};

use super::completion::ShellHelper;
use super::idp_ref::annotate_idp_refs;
use super::json::{print_json, strip_server_fields};
use super::names::{instance_label, refresh_names, store_resource_names};
use super::render::{idp_name_map, render_sessions_table, route_status};

// ═══════════════════════ Operational immediate-execution ═══════════════════════

/// `create api-key <name> <scope> [scope...]` — immediate execution, no
/// edit/commit needed. The server owns canonical scope validation.
pub(super) async fn cmd_create_api_key(client: &ApiClient, name: &str, scopes: &[&str]) {
    let body = serde_json::json!({ "name": name, "scopes": scopes });
    match client.post(api_paths::API_KEYS, &body).await {
        Ok(v) => {
            if let Some(key) = v.get("key").and_then(|k| k.as_str()) {
                eprintln!("API key created (save this!):");
                eprintln!("  {key}");
                eprintln!();
                if let Some(prefix) = v.get("prefix").and_then(|p| p.as_str()) {
                    eprintln!("  prefix: {prefix}");
                }
                if let Some(id) = v.get("id").and_then(|i| i.as_str()) {
                    eprintln!("  id:     {id}");
                }
            } else {
                print_json(&v);
            }
            refresh_names(client, "api-key").await;
        }
        Err(e) => eprintln!("error: {e}"),
    }
}

/// `enable route <name>` / `disable route <name>`.
///
/// The server treats `enabled` as a plain flag and has no ACME
/// lifecycle of its own — that orchestration lives here because only
/// the shell (with its version-locked knowledge of the data model)
/// can tell what "ready to enable" means for a given route.
///
/// Enable flow:
///   1. Fetch the route.
///   2. If `tls_downstream` implies the proxy terminates TLS
///      (`acme` / `custom`) and no certificate exists for the
///      hostname, issue one first. For ACME this enqueues through
///      `POST /certs` and polls the durable queue; for custom it is a hard
///      error (operator must upload manually).
///   3. PATCH `{enabled: true}`.
///
/// Disable is a direct PATCH — no pre-flight.
pub(super) async fn cmd_set_route_enabled(client: &ApiClient, name_or_id: &str, enabled: bool) {
    let id = match resolve_id(client, api_paths::ROUTES, name_or_id).await {
        Some(id) => id,
        None => {
            eprintln!("route not found: {name_or_id}");
            return;
        }
    };

    if enabled && let Err(e) = sekisho_api_protocol::ensure_cert_before_enable(client, &id).await {
        eprintln!("cannot enable route {name_or_id}: {e}");
        return;
    }

    let body = serde_json::json!({ "enabled": enabled });
    match client.patch(&format!("/routes/{id}"), &body).await {
        Ok(v) => {
            let verb = if enabled { "enabled" } else { "disabled" };
            eprintln!("route {name_or_id} {verb}");
            print_json(&v);
        }
        Err(e) => eprintln!("error: {e}"),
    }
}

/// `upload certificate <domain> <cert_file> <key_file>` — install a
/// hand-minted certificate so a route with `tls_downstream=custom`
/// can be enabled. Both files are read from the local filesystem and
/// sent to the server in a single `POST /certs/upload`; the server
/// parses validity from the cert, encrypts the private key with the
/// master key, and reloads the resolver.
pub(super) async fn cmd_upload_certificate(
    client: &ApiClient,
    domain: &str,
    cert_path: &str,
    key_path: &str,
) {
    let cert_pem = match std::fs::read_to_string(cert_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {cert_path}: {e}");
            return;
        }
    };
    let key_pem = match std::fs::read_to_string(key_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {key_path}: {e}");
            return;
        }
    };
    let body = serde_json::json!({
        "domain": domain,
        "cert_pem": cert_pem,
        "key_pem": key_pem,
    });
    match client.post("/certs/upload", &body).await {
        Ok(v) => {
            eprintln!("certificate for {domain} uploaded");
            print_json(&v);
        }
        Err(e) => eprintln!("error: {e}"),
    }
}

// ═══════════════════════ DEK ring commands ═══════════════════════

pub(super) async fn cmd_add_encryption_key(client: &ApiClient) {
    match client.post(api_paths::ENCRYPTION_KEYS, &Value::Null).await {
        Ok(v) => {
            let id = v.get("key_id").and_then(|x| x.as_i64()).unwrap_or(-1);
            let hex = v.get("key_hex").and_then(|x| x.as_str()).unwrap_or("");
            eprintln!("Generated encryption key {id} (inactive). Hex: {hex}");
            eprintln!("Save offline as recovery.");
            eprintln!("{}", add_encryption_key_guidance(id));
        }
        Err(e) => eprintln!("error: {e}"),
    }
}

/// What to do next after minting a key.
///
/// A new DEK is created inactive and every peer has to be able to see it
/// before it starts encrypting writes; activating while a peer is still
/// unaware produces rows that peer cannot read. The message names both steps in
/// order because this is the point where an operator is most likely to stop.
fn add_encryption_key_guidance(id: i64) -> String {
    format!("Verify with 'show encryption-key' on each peer, then 'activate encryption-key {id}'.")
}

pub(super) async fn cmd_activate_encryption_key(client: &ApiClient, id: &str) {
    let path = format!("/encryption_keys/{id}/activate");
    match client.post(&path, &Value::Null).await {
        Ok(_) => {
            eprintln!(
                "Encryption key {id} active. Run 'rotate encryption-key' to re-encrypt existing data."
            );
        }
        Err(e) => eprintln!("error: {e}"),
    }
}

pub(super) async fn cmd_retire_encryption_key(client: &ApiClient, id: &str) {
    let path = format!("/encryption_keys/{id}/retire");
    match client.post(&path, &Value::Null).await {
        Ok(_) => eprintln!("Encryption key {id} retired."),
        Err(e) => eprintln!("error: {e}"),
    }
}

pub(super) async fn cmd_rotate_encryption_key(client: &ApiClient) {
    eprintln!("Re-encrypting at-rest data ...");
    match client.post("/encryption_keys/rotate", &Value::Null).await {
        Ok(v) => {
            let examined = v.get("examined").and_then(|x| x.as_u64()).unwrap_or(0);
            let reencrypted = v.get("reencrypted").and_then(|x| x.as_u64()).unwrap_or(0);
            let skipped = v.get("skipped").and_then(|x| x.as_u64()).unwrap_or(0);
            eprintln!("done. examined={examined} reencrypted={reencrypted} skipped={skipped}");
        }
        Err(e) => eprintln!("error: {e}"),
    }
}

// ═══════════════════════ Shared show / delete ═══════════════════════

pub(super) async fn cmd_show(client: &ApiClient, parts: &[&str]) {
    if parts.len() < 2 {
        eprintln!("usage: show <resource> [name-or-id]");
        return;
    }
    let resource = parts[1];

    // `config` is a synthetic resource — no API path of its own. Handle it
    // before the path lookup so it isn't rejected as "unknown".
    if resource == "config" {
        cmd_show_all(client).await;
        return;
    }

    // `version` is a pseudo-resource: dump CLI vs. daemon build tags
    // without going through the resource registry. Shares its
    // match / mismatch / unreachable logic with the startup handshake
    // in main.rs so the operator sees the same words in both places.
    if resource == "version" {
        let verdict = crate::version::probe(client).await;
        // Colorize only when stdout is a TTY — piping `show version`
        // into a file or grep should produce clean text.
        let colorize = std::io::IsTerminal::is_terminal(&std::io::stdout());
        print!(
            "{}",
            crate::version::render(client.server_url(), &verdict, colorize)
        );
        return;
    }

    let path = resource_api_path(resource);
    if path.is_empty() {
        eprintln!("unknown resource: {resource}");
        return;
    }

    if is_singleton(resource) {
        // Singleton resources (GlobalConfig, instance) — no /{id}
        // segment; GET returns the full object, already redacted
        // server-side for sensitive fields (e.g. instance's
        // cluster_db_url).
        match client.get(path).await {
            Ok(v) => {
                print_json(&v);
                annotate_idp_refs(client, resource, &v).await;
            }
            Err(e) => eprintln!("error: {e}"),
        }
        return;
    }

    if parts.len() >= 3 {
        let identifier = parts[2];
        let item_path = format!("{path}/{identifier}");
        match client.get(&item_path).await {
            Ok(v) => print_json(&v),
            Err(_) => match client.get_list(path).await {
                Ok(items) => {
                    // Match the identifier against whichever label this
                    // resource happens to use — `name` for routes/idps,
                    // `domain` for certificates, `id` for sessions.
                    let found: Vec<_> = items
                        .iter()
                        .filter(|i| instance_label(i).as_deref() == Some(identifier))
                        .collect();
                    if found.is_empty() {
                        eprintln!("not found: {identifier}");
                    } else {
                        for item in found {
                            print_json(item);
                        }
                    }
                    // Refresh completion cache while we have the list.
                    let labels: Vec<String> = items.iter().filter_map(instance_label).collect();
                    store_resource_names(resource, labels);
                }
                Err(e) => eprintln!("error: {e}"),
            },
        }
    } else {
        match client.get_list(path).await {
            Ok(items) => {
                // Sessions render as a 5-column table (ID / USER / IDP /
                // EXPIRES / CREATED) — UUID-only listings tell the
                // operator nothing useful. Detected by name rather than
                // a generic "rich list" flag because there's only one
                // such case today.
                if resource == "session" {
                    if items.is_empty() {
                        eprintln!("(no active sessions)");
                        store_resource_names(resource, Vec::new());
                        return;
                    }
                    let idp_names = idp_name_map(client).await;
                    let table = render_sessions_table(&items, &idp_names, chrono::Utc::now());
                    eprint!("{table}");
                    eprintln!(
                        "({} active session{})",
                        items.len(),
                        if items.len() == 1 { "" } else { "s" }
                    );
                    let labels: Vec<String> = items.iter().filter_map(instance_label).collect();
                    store_resource_names(resource, labels);
                    return;
                }
                if items.is_empty() {
                    eprintln!("(empty)");
                    store_resource_names(resource, Vec::new());
                    return;
                }
                for item in &items {
                    let label = instance_label(item).unwrap_or_else(|| "-".to_string());
                    let id = item.get("id").and_then(|n| n.as_str()).unwrap_or("-");
                    // Route is the only resource with an enable
                    // lifecycle, so append a status column only here
                    // rather than generalizing across resources.
                    let status_suffix = if resource == "route" {
                        format!("  {}", route_status(item))
                    } else {
                        String::new()
                    };
                    if label == id {
                        eprintln!("  {id}{status_suffix}");
                    } else {
                        eprintln!("  {label:30} {id}{status_suffix}");
                    }
                }
                // Refresh completion cache from the same list response.
                let labels: Vec<String> = items.iter().filter_map(instance_label).collect();
                store_resource_names(resource, labels);
            }
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// Dump the entire configuration tree (GlobalConfig + idps + policies +
/// routes) as a single JSON document. Triggered by `show config` (any mode)
/// and by bare `show` in configure mode — JunOS-style "show configuration".
/// Operational-only resources (certs, api-keys, sessions) are excluded; use
/// `show certificate` etc. to inspect those.
pub(super) async fn cmd_show_all(client: &ApiClient) {
    let mut out = Map::new();

    if let Ok(v) = client.get(api_paths::CONFIG).await {
        out.insert("sekisho".into(), v);
    }
    for (label, path) in [
        ("idps", api_paths::IDPS),
        ("policies", api_paths::POLICIES),
        ("routes", api_paths::ROUTES),
    ] {
        match client.get_list(path).await {
            Ok(items) => {
                out.insert(label.into(), Value::Array(items));
            }
            Err(e) => eprintln!("warn: failed to fetch {label}: {e}"),
        }
    }
    print_json(&Value::Object(out));
}

pub(super) async fn cmd_delete(client: &ApiClient, parts: &[&str]) {
    if parts.len() < 3 {
        eprintln!("usage: delete <resource> <name-or-id>");
        return;
    }
    let resource = parts[1];
    let identifier = parts[2];
    let path = resource_api_path(resource);
    if path.is_empty() {
        eprintln!("unknown resource: {resource}");
        return;
    }

    let id = resolve_id(client, path, identifier).await;
    let id = match id {
        Some(id) => id,
        None => {
            eprintln!("not found: {identifier}");
            return;
        }
    };

    eprintln!("delete {resource} '{identifier}'?");
    let mut confirm = String::new();
    eprint!("[y/N] ");
    if std::io::stdin().read_line(&mut confirm).is_err() {
        return;
    }
    if !matches!(confirm.trim().to_lowercase().as_str(), "y" | "yes") {
        eprintln!("aborted");
        return;
    }

    match client.delete(&format!("{path}/{id}")).await {
        Ok(_) => {
            eprintln!("deleted {resource} {identifier}");
            refresh_names(client, resource).await;
        }
        Err(e) => eprintln!("error: {e}"),
    }
}

// ═══════════════════════ Export / Import ═══════════════════════

pub(super) async fn cmd_export(client: &ApiClient, parts: &[&str]) {
    if parts.len() < 2 {
        eprintln!("usage: export <file.conf>");
        return;
    }
    let path = parts[1];

    eprint!("exporting routes, idps, config ... ");

    let routes = match client.get_list(api_paths::ROUTES).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to get routes: {e}");
            return;
        }
    };
    let idps = match client.get_list(api_paths::IDPS).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to get idps: {e}");
            return;
        }
    };
    let config = match client.get(api_paths::CONFIG).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to get config: {e}");
            return;
        }
    };

    let export = serde_json::json!({
        "version": 1,
        "routes": routes,
        "idps": idps,
        "config": config,
    });

    let content = match serde_json::to_string_pretty(&export) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("serialization error: {e}");
            return;
        }
    };

    match std::fs::write(path, &content) {
        Ok(_) => {
            let route_count = routes.len();
            let idp_count = idps.len();
            eprintln!("ok ({route_count} routes, {idp_count} idps) -> {path}");
            if idp_count > 0 {
                eprintln!("  note: IdP client secrets are REDACTED in export.");
                eprintln!("  after import, you must re-set secrets via 'edit idp <name>'.");
            }
        }
        Err(e) => eprintln!("failed to write file: {e}"),
    }
}

pub(super) async fn cmd_import(
    client: &ApiClient,
    parts: &[&str],
    rl: &mut Editor<ShellHelper, DefaultHistory>,
) {
    if parts.len() < 2 {
        eprintln!("usage: import <file.conf>");
        return;
    }
    let path = parts[1];

    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to read file: {e}");
            return;
        }
    };

    let import: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid JSON: {e}");
            return;
        }
    };

    let version = import.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != 1 {
        eprintln!("unsupported file version: {version} (expected 1)");
        return;
    }

    let new_routes = import.get("routes").and_then(|v| v.as_array());
    let new_idps = import.get("idps").and_then(|v| v.as_array());
    let new_config = import.get("config");

    let route_count = new_routes.map(|a| a.len()).unwrap_or(0);
    let idp_count = new_idps.map(|a| a.len()).unwrap_or(0);
    let has_config = new_config.is_some();

    eprintln!("file contains: {route_count} routes, {idp_count} idps, config: {has_config}");
    eprintln!("this will DELETE all existing routes and idps, then recreate from file.");

    let confirm = match rl.readline("proceed? [y/N] ") {
        Ok(line) => line.trim().to_lowercase(),
        Err(_) => return,
    };
    if !matches!(confirm.as_str(), "y" | "yes") {
        eprintln!("aborted");
        return;
    }

    eprint!("deleting existing routes ... ");
    if let Ok(existing) = client.get_list(api_paths::ROUTES).await {
        for route in &existing {
            if let Some(id) = route.get("id").and_then(|v| v.as_str())
                && let Err(e) = client.delete(&format!("/routes/{id}")).await
            {
                eprintln!("\n  warning: failed to delete route {id}: {e}");
            }
        }
        eprintln!("{} deleted", existing.len());
    }

    eprint!("deleting existing idps ... ");
    if let Ok(existing) = client.get_list(api_paths::IDPS).await {
        for idp in &existing {
            if let Some(id) = idp.get("id").and_then(|v| v.as_str())
                && let Err(e) = client.delete(&format!("/idps/{id}")).await
            {
                eprintln!("\n  warning: failed to delete idp {id}: {e}");
            }
        }
        eprintln!("{} deleted", existing.len());
    }

    if let Some(idps) = new_idps {
        eprint!("importing {idp_count} idps ... ");
        let mut ok = 0;
        for idp in idps {
            let clean = strip_server_fields(idp);
            match client.post(api_paths::IDPS, &clean).await {
                Ok(_) => ok += 1,
                Err(e) => eprintln!("\n  error: {e}"),
            }
        }
        eprintln!("{ok} created");
        if idp_count > 0 {
            eprintln!("  warning: IdP client secrets are REDACTED. Re-set via 'edit idp <name>'.");
        }
    }

    if let Some(routes) = new_routes {
        eprint!("importing {route_count} routes ... ");
        let mut ok = 0;
        for route in routes {
            let clean = strip_server_fields(route);
            match client.post(api_paths::ROUTES, &clean).await {
                Ok(_) => ok += 1,
                Err(e) => eprintln!("\n  error: {e}"),
            }
        }
        eprintln!("{ok} created");
    }

    if let Some(config) = new_config {
        eprint!("importing config ... ");
        match client.patch(api_paths::CONFIG, config).await {
            Ok(_) => eprintln!("ok"),
            Err(e) => eprintln!("error: {e}"),
        }
    }

    eprintln!("import complete");
}

// ═══════════════════════ Helpers ═══════════════════════

pub(super) async fn resolve_id(client: &ApiClient, path: &str, identifier: &str) -> Option<String> {
    if client.get(&format!("{path}/{identifier}")).await.is_ok() {
        return Some(identifier.to_string());
    }
    if let Ok(items) = client.get_list(path).await {
        for item in items {
            if item.get("name").and_then(|n| n.as_str()) == Some(identifier) {
                return item.get("id").and_then(|n| n.as_str()).map(String::from);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_key_guidance_uses_singular_resource_name() {
        let guidance = add_encryption_key_guidance(7);
        assert!(guidance.contains("show encryption-key"));
        assert!(!guidance.contains(&format!("show encryption-key{}", "s")));
        assert!(guidance.contains("activate encryption-key 7"));
    }
}
