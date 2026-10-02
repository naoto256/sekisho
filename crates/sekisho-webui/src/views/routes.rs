//! Route-specific views. The single place in the UI where `enabled`
//! flows through — list view shows a status pill, and each row has
//! Enable/Disable action buttons that drive the client-side
//! orchestration over in `handlers::routes`.

use maud::{Markup, html};
use serde_json::Value;

use super::{extract_id, render_cell};

/// Status label derived from the plain `enabled` flag. Server no
/// longer tracks transient ACME state — there is no "enabling" or
/// "failed" server-side status field. During an in-flight enable the
/// user sees "disabled" until the orchestration completes and the
/// follow-up PATCH lands.
pub fn status_pill(enabled: bool) -> Markup {
    let class = if enabled {
        "pill enabled"
    } else {
        "pill disabled"
    };
    let label = if enabled { "enabled" } else { "disabled" };
    html! { span class=(class) { (label) } }
}

pub fn list(items: &[Value]) -> Markup {
    html! {
        hgroup {
            h2 { "Routes" }
            p class="muted" { "Publicly-reachable hostnames proxied to internal services." }
        }
        p class="toolbar" {
            a href="/routes/new" role="button" class="primary" { "Create new route" }
        }
        table class="resource-list striped" {
            thead {
                tr {
                    th { "Name" }
                    th { "From" }
                    th { "Status" }
                    th class="actions" { "Actions" }
                }
            }
            tbody {
                @for item in items {
                    (row(item))
                }
                @if items.is_empty() {
                    tr { td colspan="4" class="muted center" { "No routes yet. " a href="/routes/new" { "Create one" } "." } }
                }
            }
        }
    }
}

/// Error fragment in the shape of a single row. Returned by the
/// enable/disable handlers when the upstream call fails — htmx is
/// configured to swap the whole `<tr>`, so returning a full error
/// page would splice the page chrome inside the table. A row-sized
/// banner with a reload link keeps the layout sane and makes the
/// failure visible; the reload re-renders the actual state.
pub fn row_error(id: &str, reason: &str) -> Markup {
    html! {
        tr id=(format!("route-{id}")) class="row-error" {
            td colspan="4" {
                div class="flash error" {
                    strong { "Action failed: " }
                    (reason)
                    " "
                    a href="/routes" { "Reload" }
                }
            }
        }
    }
}

/// One route row. Extracted so that POST /routes/{id}/enable can
/// return just this fragment and `hx-swap="outerHTML"` splice it in.
pub fn row(item: &Value) -> Markup {
    let id = extract_id(item).unwrap_or_default();
    let enabled = item
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    html! {
        tr id=(format!("route-{id}")) {
            td { a href=(format!("/routes/{id}")) { (render_cell(item, "name")) } }
            td { code { (render_cell(item, "from")) } }
            td { (status_pill(enabled)) }
            td class="actions" {
                (enable_button(&id, enabled))
                button
                    class="destructive"
                    hx-delete=(format!("/routes/{id}"))
                    hx-confirm="Delete this route?"
                    hx-target="closest tr"
                    hx-swap="outerHTML"
                    { "Delete" }
            }
        }
    }
}

fn enable_button(id: &str, enabled: bool) -> Markup {
    if enabled {
        html! {
            button
                class="secondary"
                hx-post=(format!("/routes/{id}/disable"))
                hx-target=(format!("#route-{id}"))
                hx-swap="outerHTML"
                { "Disable" }
        }
    } else {
        html! {
            button
                class="primary"
                hx-post=(format!("/routes/{id}/enable"))
                hx-target=(format!("#route-{id}"))
                hx-swap="outerHTML"
                hx-indicator=(format!("#route-{id}"))
                { "Enable" }
        }
    }
}

pub fn new_form(idps: &[Value]) -> Markup {
    form_body(None, idps)
}

pub fn edit_form(item: &Value, idps: &[Value]) -> Markup {
    form_body(Some(item), idps)
}

fn form_body(item: Option<&Value>, idps: &[Value]) -> Markup {
    let creating = item.is_none();
    let id = item.and_then(extract_id).unwrap_or_default();
    let get_s = |k: &str| -> String {
        item.and_then(|v| v.get(k))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let get_bool = |k: &str| -> bool {
        item.and_then(|v| v.get(k))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    let to_joined = item
        .and_then(|v| v.get("to"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let tls = item
        .and_then(|v| v.get("tls_downstream"))
        .and_then(|v| v.as_str())
        .unwrap_or("acme")
        .to_string();
    let lb = item
        .and_then(|v| v.get("load_balancing"))
        .and_then(|v| v.as_str())
        .unwrap_or("round_robin")
        .to_string();
    let access = item
        .and_then(|v| v.get("access"))
        .cloned()
        .unwrap_or(Value::Null);
    let policy = access
        .get("policy")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let allow_public = access
        .get("allow_public_unauthenticated_access")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let timeout_ms = item
        .and_then(|v| v.get("timeout_ms"))
        .map(|v| v.to_string())
        .unwrap_or_else(|| "30000".into());
    let response_idle_timeout_ms = item
        .and_then(|v| v.get("response_idle_timeout_ms"))
        .and_then(|v| v.as_u64())
        .unwrap_or(180_000)
        .to_string();
    let response_location_rewrite = item
        .and_then(|v| v.get("response_location_rewrite"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let concurrency_limit = item
        .and_then(|v| v.get("concurrency_limit"))
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_default();
    let headers = item
        .and_then(|v| v.get("headers"))
        .cloned()
        .unwrap_or(Value::Null);
    let headers_add_lines = headers
        .get("add")
        .and_then(|v| v.as_object())
        .map(|m| {
            let mut lines: Vec<String> = m
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| format!("{k}={s}")))
                .collect();
            lines.sort();
            lines.join("\n")
        })
        .unwrap_or_default();
    let headers_remove_lines = headers
        .get("remove")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let allow_credential_overrides = headers
        .get("allow_credential_overrides")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // Empty / null on the wire means "no per-route override stored",
    // which is functionally identical to picking "lax" in the dropdown
    // (lax is the default). Coalesce so the UI presents one canonical
    // selection per behaviour rather than two options that do the same
    // thing.
    let session_cookie_samesite = item
        .and_then(|v| v.get("session_cookie_samesite"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("lax")
        .to_string();
    let enabled = get_bool("enabled");

    let action = if creating {
        "/routes".to_string()
    } else {
        format!("/routes/{id}")
    };

    html! {
        hgroup {
            @if creating {
                h2 { "Create route" }
            } @else {
                h2 { "Edit route " code { (get_s("name")) } }
                p { (status_pill(enabled)) " " code class="mono muted" { (id) } }
            }
        }
        form method="post" action=(action) class="stack" {
            fieldset {
                legend { "Identity" }
                (field_text("name", "Name", &get_s("name"), Some("lowercase, dashes ok — used in `edit route <name>`")))
                (field_text("from", "From (public URL)", &get_s("from"), Some("e.g. https://app.example.com")))
                (field_text("path", "Path prefix (optional)", &get_s("path"), Some("Match only when request path starts with this prefix. Leave blank for any path.")))
                (field_text("to", "To (comma-separated upstream URLs)", &to_joined, Some("e.g. http://127.0.0.1:8080")))
            }

            fieldset {
                legend { "Access" }
                @let current_idp = get_s("idp_id");
                label {
                    "IdP (optional)"
                    select name="idp_id" {
                        option value="" selected[current_idp.is_empty()] { "(use default)" }
                        @for idp in idps {
                            @let id = idp.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            @let name = idp.get("name").and_then(|v| v.as_str()).unwrap_or("(unnamed)");
                            @if !id.is_empty() {
                                option value=(id) selected[id == current_idp] { (name) }
                            }
                        }
                    }
                    small class="muted" { "Leave unset to fall back to the global default. Stored internally as the IdP's UUID." }
                }
                (field_text("access_policy", "Access policy expression", &policy, Some("e.g. claim.groups in [\"admins\"]. Empty = deny unless \"Allow public\" is set.")))
                (checkbox("allow_public_unauthenticated_access", "Allow public, unauthenticated access", allow_public,
                    Some("Bypass IdP + policy entirely. Only set for static landing pages or oauth/acme callback shims.")))
                (checkbox("enable_signed_identity", "Inject X-Sekisho-Jwt identity header to upstream", get_bool("enable_signed_identity"),
                    Some("Signs an EdDSA JWT with a kid. Upstream must verify against the public /auth/jwks key set.")))
            }

            fieldset {
                legend { "TLS" }
                (tls_select(&tls))
                (checkbox("tls_skip_verify", "Skip upstream TLS verification", get_bool("tls_skip_verify"),
                    Some("Only for self-signed upstreams behind a trusted network.")))
            }

            fieldset {
                legend { "Proxy behaviour" }
                (checkbox("preserve_host_header", "Preserve Host header when proxying", get_bool("preserve_host_header"), None))
                (field_text("host_rewrite", "Host rewrite (optional)", &get_s("host_rewrite"),
                    Some("If set, overrides Host header with this value. Leave blank to use upstream URL host.")))
                (field_text("timeout_ms", "Timeout (ms)", &timeout_ms, Some("Upstream request timeout.")))
                (field_text("response_idle_timeout_ms", "Response idle timeout (ms)", &response_idle_timeout_ms,
                    Some("Maximum idle interval between upstream response body frames.")))
                (field_text("concurrency_limit", "Concurrency limit (optional)", &concurrency_limit,
                    Some("Leave blank to inherit the global limit. Zero rejects every request to this route.")))
                (checkbox("response_location_rewrite", "Rewrite upstream Location headers", response_location_rewrite,
                    Some("Rewrite matching upstream absolute redirects back to this route's public URL.")))
                (checkbox("enable_websocket", "Allow WebSocket upgrades", get_bool("enable_websocket"), None))
                (checkbox("enable_grpc", "Allow gRPC (HTTP/2 cleartext upgrades)", get_bool("enable_grpc"), None))
                (load_balancing_select(&lb))
            }

            fieldset {
                legend { "Path rewrite (regex)" }
                (field_text("regex_rewrite_pattern", "Pattern", &get_s("regex_rewrite_pattern"),
                    Some("RE2 pattern applied to the request path before forwarding. Leave both fields blank to disable.")))
                (field_text("regex_rewrite_substitution", "Substitution", &get_s("regex_rewrite_substitution"),
                    Some(r#"Replacement, with $1 / $2 etc. for capture groups."#)))
            }

            fieldset {
                legend { "Header modifications" }
                label {
                    "Add headers"
                    textarea name="headers_add" rows="3" class="mono" placeholder="X-Real-IP=$remote_addr\nX-Request-Id=$request_id" { (headers_add_lines) }
                    small class="muted" { "One " code { "key=value" } " per line. Blank lines ignored." }
                }
                label {
                    "Remove headers"
                    textarea name="headers_remove" rows="3" class="mono" placeholder="X-Forwarded-Host\nAuthorization" { (headers_remove_lines) }
                    small class="muted" { "One header name per line." }
                }
                (checkbox(
                    "allow_credential_overrides",
                    "Allow Authorization / Cookie overrides",
                    allow_credential_overrides,
                    Some("Tick only when intentionally injecting upstream basic-auth credentials (the OIDC-front, basic-back IAP pattern). Without this, attempts to add Authorization or Cookie are rejected at validation. The audit event surfaces this flag — every route that opts in is filterable downstream."),
                ))
            }

            fieldset {
                legend { "Session cookie SameSite (per-route override)" }
                label {
                    "SameSite"
                    select name="session_cookie_samesite" {
                        option value="lax" selected[session_cookie_samesite == "lax"] { "lax (default)" }
                        option value="none" selected[session_cookie_samesite == "none"] { "none — required for upstreams that run their own SAML SP" }
                        option value="strict" selected[session_cookie_samesite == "strict"] { "strict (rare; will break some flows)" }
                    }
                    small class="muted" {
                        "Default is Lax. Switch to "
                        code { "none" }
                        " when the upstream's own SAML POST from "
                        code { "login.microsoftonline.com" }
                        " back to this host needs to carry the IAP session cookie. The audit event for the route surfaces this override so an operator can find every route that's been relaxed."
                    }
                }
            }

            div class="toolbar" {
                button type="submit" class="primary" {
                    @if creating { "Create" } @else { "Save" }
                }
                a href="/routes" role="button" class="secondary outline" { "Cancel" }
            }
        }
    }
}

fn field_text(name: &str, label: &str, value: &str, hint: Option<&str>) -> Markup {
    html! {
        label {
            (label)
            input type="text" name=(name) value=(value);
            @if let Some(h) = hint {
                small class="muted" { (h) }
            }
        }
    }
}

fn checkbox(name: &str, label: &str, checked: bool, hint: Option<&str>) -> Markup {
    html! {
        label class="checkbox-row" {
            input type="checkbox" name=(name) value="true" checked[checked];
            span { (label) }
            @if let Some(h) = hint {
                small class="muted" { (h) }
            }
        }
    }
}

fn tls_select(current: &str) -> Markup {
    let options = [
        ("acme", "acme — obtain cert automatically"),
        ("custom", "custom — use an uploaded cert"),
        ("passthrough", "passthrough — terminate TLS at upstream"),
        ("none", "none — plain HTTP"),
    ];
    html! {
        label {
            "TLS"
            select name="tls_downstream" {
                @for (value, descr) in options {
                    option value=(value) selected[value == current] { (descr) }
                }
            }
        }
    }
}

fn load_balancing_select(current: &str) -> Markup {
    let options = [
        (
            "round_robin",
            "round_robin — rotate through upstreams in order",
        ),
        ("random", "random — pick an upstream uniformly at random"),
    ];
    html! {
        label {
            "Load balancing"
            select name="load_balancing" {
                @for (value, descr) in options {
                    option value=(value) selected[value == current] { (descr) }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checkbox_renders_checked_when_true() {
        let out = checkbox("x", "X", true, None).into_string();
        assert!(
            out.contains("checked"),
            "expected 'checked' attr, got: {out}"
        );
    }

    #[test]
    fn checkbox_omits_checked_when_false() {
        let out = checkbox("x", "X", false, None).into_string();
        assert!(
            !out.contains("checked"),
            "expected no 'checked', got: {out}"
        );
    }

    #[test]
    fn edit_form_shows_allow_credential_overrides_when_stored_true() {
        // Regression: routes for upstreams that need a static Basic
        // credential are PATCH'd with an Authorization header plus
        // the opt-in override flag. If the form view drops the value
        // when reading it back, an operator who revisits the edit
        // page sees an unchecked box and any save would silently
        // clear the override. Lock it in.
        let route = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "device-a",
            "from": "https://device-a.example.com",
            "to": ["http://192.0.2.1"],
            "access": { "policy": null, "allow_public_unauthenticated_access": false },
            "tls_downstream": "acme",
            "headers": {
                "add": { "Authorization": "Basic xxx" },
                "remove": [],
                "allow_credential_overrides": true
            }
        });
        let out = edit_form(&route, &[]).into_string();
        assert!(
            out.contains("name=\"allow_credential_overrides\""),
            "checkbox input must be present"
        );
        assert!(
            out.contains("checked"),
            "stored true must render as checked"
        );
    }

    /// Every route field a client is expected to reach is present in the form with
    /// its server default, so the web UI and the shell cover the same surface.
    #[test]
    fn route_form_renders_client_coverage_fields_and_defaults() {
        let new_form = new_form(&[]).into_string();
        assert!(new_form.contains("name=\"response_idle_timeout_ms\""));
        assert!(new_form.contains("value=\"180000\""));
        assert!(new_form.contains("name=\"concurrency_limit\""));
        assert!(new_form.contains("name=\"response_location_rewrite\""));
        let new_location_input = input_tag(&new_form, "response_location_rewrite");
        assert!(
            new_location_input.contains("checked"),
            "new routes must default Location rewriting on"
        );

        let route = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "app",
            "from": "https://app.example.com",
            "to": ["http://192.0.2.1"],
            "response_idle_timeout_ms": 42000,
            "response_location_rewrite": false,
            "concurrency_limit": 0,
        });
        let edit = edit_form(&route, &[]).into_string();
        assert!(edit.contains("name=\"response_idle_timeout_ms\" value=\"42000\""));
        assert!(edit.contains("name=\"concurrency_limit\" value=\"0\""));
        assert!(edit.contains("name=\"response_location_rewrite\""));
        let edit_location_input = input_tag(&edit, "response_location_rewrite");
        assert!(
            !edit_location_input.contains("checked"),
            "stored false must render unchecked"
        );
    }

    fn input_tag<'a>(html: &'a str, name: &str) -> &'a str {
        let marker = format!("name=\"{name}\"");
        let marker_start = html.find(&marker).expect("named input");
        let tag_start = html[..marker_start].rfind("<input").expect("input start");
        let tag_end = html[marker_start..].find('>').expect("input end") + marker_start + 1;
        &html[tag_start..tag_end]
    }
}
