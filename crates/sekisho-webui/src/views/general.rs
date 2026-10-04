//! Consolidated General page. Layout, top to bottom:
//!
//! 1. **General** — daemon-wide knobs (auth domain, sessions, ACME,
//!    logging). The everyday surface, safe to touch.
//! 2. **Instance Config** — per-node listen addresses and their
//!    paired `accept_from` source-IP ACLs. Restart-required, but
//!    the blast radius is local to this node only — picking the
//!    wrong NIC inconveniences this peer's clients, it doesn't
//!    corrupt cluster state.
//! 3. **Danger Zone** — Cluster DB pointer (mis-set ⇒ data
//!    inaccessible) and DEK ring rotation.
//!
//! Putting Instance Config above the Danger Zone is intentional:
//! restart-required is annoying, but it's not the same risk class
//! as repointing the cluster's data store. The operator scrolls
//! past the safe surface before touching anything that can corrupt
//! state — same visual posture as GitHub's repo settings.

use maud::{Markup, html};
use serde_json::Value;

/// State surfaced by the DEK rotation section. All fields default to
/// "no banner" so callers that just want to render the page can pass
/// [`DekState::default`].
///
/// The view is read-mostly: the only reason this struct exists is to
/// let the POST sub-handlers (add / activate / retire / rotate) re-render
/// the consolidated General page with a flash banner anchored at their
/// own section, in the same idiom as Instance configuration.
#[derive(Default)]
pub struct DekState<'a> {
    /// Encryption-key ring rows from `GET /encryption_keys`. Each item
    /// is the raw daemon JSON (`{key_id, status, active, retired, ...}`).
    pub items: &'a [Value],
    /// Filled after a successful `POST /encryption_keys` so the page
    /// can show the freshly-generated `key_hex` exactly once.
    pub add_result: Option<&'a Value>,
    /// Filled after `POST /encryption_keys/rotate` with the
    /// `{examined, reencrypted, skipped}` counts.
    pub rotate_result: Option<&'a Value>,
    /// Generic error banner (any of add/activate/retire/rotate).
    /// Includes the leader-fence hint when the daemon returned 503.
    pub error: Option<&'a str>,
}

/// Render the full page body. `instance_error` and `instance_restart`
/// surface state from a recent POST to `/general/instance` without
/// embedding form-handling logic in the view; `dek` does the same for
/// the DEK rotation sub-handlers.
///
/// The `instance_cfg` payload feeds two sections now: the
/// per-node listen + accept_from form (above the Danger Zone) and
/// the cluster DB pointer (inside the Danger Zone). They share a
/// single POST endpoint (`/general/instance`) so a save of either
/// re-renders the whole page with the same banner state.
pub fn page(
    config: &Value,
    idps: &[Value],
    instance_cfg: &Value,
    instance_error: Option<&str>,
    instance_restart: bool,
    dek: &DekState<'_>,
) -> Markup {
    html! {
        (general_section(config, idps))
        (instance_config_section(instance_cfg, instance_error, instance_restart))
        (danger_zone(instance_cfg, instance_error, instance_restart, dek))
    }
}

fn general_section(data: &Value, idps: &[Value]) -> Markup {
    let s = |k: &str| -> String {
        match data.get(k) {
            Some(Value::String(v)) => v.clone(),
            Some(Value::Number(v)) => v.to_string(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        }
    };
    let current_idp = s("default_idp_id");
    html! {
        hgroup {
            h2 { "General" }
            p class="muted" { "Daemon-wide configuration shared by every route." }
        }
        form method="post" action="/general" class="stack" {
            fieldset {
                legend { "Proxy" }
                // Listen addresses (proxy / management-API / HTTP-redirect)
                // moved to the Instance section below — they're per-node,
                // not cluster-wide, so they live in the per-instance SQLite
                // alongside the service DB URL.
                label { "Auth domain" input type="text" name="auth_domain" value=(s("auth_domain")) placeholder="auth.example.com"; }
            }
            // `id="sessions"` is a link target: the IdP list points at
            // `/general#sessions` for changing the default IdP. Renaming it
            // breaks those links.
            fieldset id="sessions" {
                legend { "Sessions" }
                label { "Cookie name" input type="text" name="cookie_name" value=(s("cookie_name")) placeholder="_sekisho_session"; }
                label { "Session lifetime (hours)" input type="number" name="session_lifetime_hours" value=(s("session_lifetime_hours")); }
                label {
                    "Default IdP"
                    select name="default_idp_id" {
                        option value="" selected[current_idp.is_empty()] { "(none)" }
                        @for idp in idps {
                            @let id = idp.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            @let name = idp.get("name").and_then(|v| v.as_str()).unwrap_or("(unnamed)");
                            @if !id.is_empty() {
                                option value=(id) selected[id == current_idp] { (name) }
                            }
                        }
                    }
                    small class="muted" { "Routes without their own idp_id fall back to this IdP. Stored internally as the IdP's UUID." }
                }
            }
            fieldset {
                legend { "ACME" }
                label { "ACME directory" input type="text" name="acme_directory" value=(s("acme_directory")) placeholder="https://acme-v02.api.letsencrypt.org/directory"; }
                label { "ACME contact email" input type="email" name="acme_email" value=(s("acme_email")); }
                label {
                    "ACME leader (HA only)"
                    input type="text" name="acme_leader" value=(s("acme_leader")) placeholder="(automatic election)";
                    small class="muted" { "Pin renewal to a specific instance hostname. Leave blank for automatic election — that's the default and right for almost every deployment." }
                }
                label {
                    "Active queue capacity"
                    input type="number" min="1" max="100000" name="acme_queue_capacity" value=(s("acme_queue_capacity")) placeholder="1000";
                    small class="muted" { "Cluster-wide pending plus in-progress admissions. Changes take effect immediately." }
                }
                label {
                    "Concurrent issuances"
                    input type="number" min="1" max="5" name="acme_issuance_concurrency_limit" value=(s("acme_issuance_concurrency_limit")) placeholder="5";
                    small class="muted" { "Queue-worker orders per instance. A restart is required after changing this value." }
                }
                label {
                    "Renewal scan interval (hours)"
                    input type="number" min="1" max="168" name="acme_renewal_scan_interval_hours" value=(s("acme_renewal_scan_interval_hours")) placeholder="12";
                    small class="muted" { "How often due certificates are admitted to the queue. A restart is required after changing this value." }
                }
            }
            fieldset {
                legend { "Logging" }
                label { "Log level" input type="text" name="log_level" value=(s("log_level")) placeholder="info"; }
            }
            fieldset {
                legend { "WebSocket capacity" }
                label {
                    "Concurrent tunnels per instance"
                    input type="number" min="1" name="websocket_concurrency_limit" value=(s("websocket_concurrency_limit")) placeholder="100";
                    small class="muted" { "Applies per daemon instance. A restart is required after changing this value." }
                }
            }
            div class="toolbar" {
                button type="submit" class="primary" { "Save" }
                a href="/general" role="button" class="secondary outline" { "Reload" }
            }
        }
    }
}

fn danger_zone(
    instance_cfg: &Value,
    instance_error: Option<&str>,
    instance_restart: bool,
    dek: &DekState<'_>,
) -> Markup {
    html! {
        section class="danger-zone" role="alert" aria-label="Danger Zone" {
            hgroup {
                h2 { "Danger Zone" }
                p class="muted" {
                    "Rare operations with large blast radius. Read each \
                     section before touching it — these change cluster-shared \
                     state or cryptographic key ownership."
                }
            }
            (cluster_db_section(instance_cfg, instance_error, instance_restart))
            (encryption_keys_section(dek))
        }
    }
}

/// Per-node listen configuration. Lives **outside** the Danger Zone:
/// changing a listen address or `accept_from` rule list is
/// restart-required and affects this node's network exposure, but
/// the change is reversible from the same page and doesn't touch
/// cluster-shared state. Putting it next to the safe knobs keeps the
/// "I just want to bind to a different NIC" workflow out of the
/// scary-confirmation flow.
fn instance_config_section(data: &Value, error: Option<&str>, restart_notice: bool) -> Markup {
    let value_str = |key: &str| -> String {
        data.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    html! {
        section id="instance" {
            hgroup {
                h2 { "Instance Config" }
                p class="muted" {
                    "Per-node network configuration. Each peer in an HA \
                     cluster binds its own NIC and can carry its own source-IP \
                     allow-list — these settings never affect other nodes. \
                     Restart required to apply."
                }
            }
            @if let Some(msg) = error {
                article class="flash error" { strong { "Error: " } (msg) }
            }
            @if restart_notice {
                article class="flash" {
                    strong { "Saved." } " "
                    "A daemon restart is required before the new listen / \
                     accept_from settings take effect."
                }
            }
            form method="post" action="/general/instance" class="stack" {
                fieldset {
                    legend { "Proxy" }
                    label {
                        "Listen"
                        input type="text" name="proxy_listen" value=(value_str("proxy_listen")) placeholder="0.0.0.0:443";
                    }
                    label {
                        "Accept from"
                        input type="text" name="proxy_accept_from" value=(value_str("proxy_accept_from")) placeholder="(empty — any source)";
                        small class="muted" {
                            "Comma-separated CIDRs or IPs allowed to connect. \
                             Empty = any source. Connections from a \
                             non-matching peer are dropped at the TCP layer \
                             before TLS handshake."
                        }
                    }
                }
                fieldset {
                    legend { "Management API" }
                    label {
                        "Listen (extra)"
                        input type="text" name="api_listen" value=(value_str("api_listen")) placeholder="(empty — localhost only)";
                        small class="muted" {
                            "127.0.0.1:9443 is always bound regardless. Leave \
                             blank unless you need to accept admin calls from \
                             another interface."
                        }
                    }
                    label {
                        "Accept from"
                        input type="text" name="api_accept_from" value=(value_str("api_accept_from")) placeholder="(empty — any source)";
                        small class="muted" {
                            "Source-IP ACL for the extra API listener. The \
                             loopback bind is unfiltered."
                        }
                    }
                }
                fieldset {
                    legend { "HTTP (ACME http-01 + redirect)" }
                    label {
                        "Listen"
                        input type="text" name="http_listen" value=(value_str("http_listen")) placeholder="0.0.0.0:80";
                        small class="muted" {
                            "Set blank to disable (e.g. when running behind \
                             another TLS terminator that handles ACME)."
                        }
                    }
                    label {
                        "Accept from"
                        input type="text" name="http_accept_from" value=(value_str("http_accept_from")) placeholder="(empty — any source)";
                    }
                }
                div class="toolbar" {
                    button type="submit" class="primary" { "Save" }
                }
            }
        }
    }
}

/// Cluster DB pointer. Stays in the Danger Zone because mis-setting
/// it points the daemon at a different (or empty) backend on the
/// next restart, which can make existing routes / IdPs / sessions
/// unreachable until the URL is corrected.
fn cluster_db_section(data: &Value, error: Option<&str>, restart_notice: bool) -> Markup {
    // Server-side marker for "configured but redacted". Anchored as a
    // constant so the comparison is one place and any server-side
    // rename (extremely unlikely) breaks compilation rather than UX.
    const REDACTED: &str = "**REDACTED**";
    let configured = data
        .get("cluster_db_url")
        .and_then(|v| v.as_str())
        .map(|s| s == REDACTED)
        .unwrap_or(false);

    html! {
        article id="cluster-db" class="danger-section" {
            h3 { "Cluster DB" }
            p class="muted" {
                "Connection string for the cluster-shared operational \
                 database (routes, IdPs, policies, sessions). Stored \
                 encrypted at rest and never returned by the server. \
                 An incorrect value renders existing configuration \
                 unreachable on the next restart."
            }
            @if let Some(msg) = error {
                article class="flash error" { strong { "Error: " } (msg) }
            }
            @if restart_notice {
                article class="flash error" {
                    strong { "Saved." } " "
                    "A daemon restart is required before the cluster DB \
                     change takes effect."
                }
            }
            form method="post" action="/general/instance" class="stack" {
                fieldset {
                    legend { "Cluster database" }
                    label {
                        "Cluster DB URL"
                        input
                            type="password"
                            name="cluster_db_url"
                            autocomplete="off"
                            placeholder=(if configured { "(configured — leave blank to keep)" } else { "postgres://user:pass@host/db or sqlite:/path.db" });
                    }
                    small class="muted" {
                        "Accepts " code { "postgres://" } ", " code { "postgresql://" }
                        ", or " code { "sqlite:" } " URLs. Empty means \
                         single-node mode (the per-instance SQLite is reused)."
                    }
                    @if configured {
                        p { small { "Currently configured (redacted)." } }
                    }
                }
                div class="toolbar" {
                    button type="submit" class="warning" { "Save" }
                    @if configured {
                        // Resource-name confirmation: the operator must
                        // type the literal string "cluster-db" to arm
                        // the Clear button. Browser-level prompt is the
                        // simplest form of the GitHub-style modal —
                        // sufficient on a same-origin admin page where
                        // the operator is already authenticated.
                        button
                            type="submit"
                            name="__clear"
                            value="1"
                            class="warning"
                            data-confirm-name="cluster-db"
                            data-confirm-prompt="Type \"cluster-db\" to confirm reverting to single-node mode" {
                            "Clear (revert to single-node)"
                        }
                    }
                }
            }
        }
    }
}

/// Render the DEK ring management UI: a status table plus add /
/// activate / retire / rotate actions. Each mutating action posts to
/// its own sub-handler; the daemon already enforces the leader fence
/// and the "retire on used key" safety check, so the view simply
/// surfaces whatever banner the handler hands back via [`DekState`].
fn encryption_keys_section(dek: &DekState<'_>) -> Markup {
    html! {
        article id="encryption-keys" class="danger-section" {
            h3 { "Encryption key rotation" }
            p class="muted" {
                "Data Encryption Keys (DEKs) protect every secret stored at \
                 rest. Add a new key, distribute it to peers, then activate \
                 and bulk re-encrypt. "
                "Activate / rotate / retire are leader-only — non-leader \
                 nodes return 503 with the leader hint."
            }

            @if let Some(msg) = dek.error {
                article class="flash error" { strong { "Error: " } (msg) }
            }
            @if let Some(v) = dek.add_result {
                (add_result_banner(v))
            }
            @if let Some(v) = dek.rotate_result {
                (rotate_result_banner(v))
            }

            (encryption_keys_table(dek.items))

            form method="post" action="/general/encryption_keys" class="stack" {
                p class="muted" {
                    "Generates a new 32-byte DEK on this node, KEK-encrypts \
                     it, and inserts it as " code { "inactive" } ". The \
                     plaintext hex is shown " strong { "exactly once" }
                    " — save it offline as a recovery option. Then verify \
                     peers have loaded it via "
                    code { "show encryption-keys" } " on each node before \
                     activating."
                }
                div class="toolbar" {
                    button type="submit" class="warning" { "Add encryption key" }
                }
            }

            form method="post" action="/general/encryption_keys/rotate" class="stack" {
                p class="muted" {
                    "Re-encrypts every at-rest secret with the active DEK. \
                     Idempotent — rerunning shows " code { "reencrypted=0" } "."
                }
                div class="toolbar" {
                    button
                        type="submit"
                        class="warning"
                        data-confirm-name="rotate"
                        data-confirm-prompt="Type \"rotate\" to confirm bulk re-encrypting every at-rest secret" {
                        "Rotate encryption keys (bulk re-encrypt)"
                    }
                }
            }

            article class="flash" {
                p class="muted" {
                    strong { "KEK note. " }
                    "The Key Encryption Key (the "
                    code { "SEKISHO_MASTER_KEY_FILE" } " credential file) is "
                    strong { "intentionally not online-rotatable" }
                    " — KEK exposure is a host compromise event, not a \
                     routine hygiene action. See "
                    a href="https://github.com/naoto256/sekisho/blob/main/docs/src/security.md" {
                        code { "docs/src/security.md" }
                    }
                    " for the offline incident-response procedure."
                }
            }
        }
    }
}

/// Render the DEK ring table. Empty state prints a one-line note —
/// happens on a brand-new daemon before the first key is generated.
fn encryption_keys_table(items: &[Value]) -> Markup {
    if items.is_empty() {
        return html! {
            p class="muted" { "No encryption keys loaded yet." }
        };
    }
    html! {
        table {
            thead {
                tr {
                    th { "KEY ID" }
                    th { "STATUS" }
                    th { "CREATED" }
                    th { "RETIRED" }
                    th { "Actions" }
                }
            }
            tbody {
                @for item in items {
                    (encryption_key_row(item))
                }
            }
        }
    }
}

fn encryption_key_row(item: &Value) -> Markup {
    let key_id = item
        .get("key_id")
        .and_then(|v| v.as_i64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "?".into());
    let status = item
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("inactive");
    let created = format_ts(item.get("created_at"));
    let retired = format_ts(item.get("retired_at"));
    let is_active = status == "active";
    let is_retired = status == "retired";
    let badge_class = match status {
        "active" => "badge badge-active",
        "retired" => "badge badge-retired",
        _ => "badge badge-inactive",
    };
    let row_class = if is_retired { "row-retired" } else { "" };
    html! {
        tr class=(row_class) {
            td { code { (key_id) } }
            td { span class=(badge_class) { (status) } }
            td { (created) }
            td { (retired) }
            td {
                @if !is_active && !is_retired {
                    div class="toolbar" {
                        form method="post" action={ "/general/encryption_keys/" (key_id) "/activate" } style="display:inline" {
                            button
                                type="submit"
                                class="warning"
                                data-confirm-name="activate"
                                data-confirm-prompt={ "Type \"activate\" to confirm activating key " (key_id) ". Confirm peers have loaded the key first." } {
                                "Activate"
                            }
                        }
                        form method="post" action={ "/general/encryption_keys/" (key_id) "/retire" } style="display:inline" {
                            button
                                type="submit"
                                class="secondary outline"
                                data-confirm-name=(format!("retire {key_id}"))
                                data-confirm-prompt={ "Type \"retire " (key_id) "\" to confirm retiring key " (key_id) } {
                                "Retire"
                            }
                        }
                    }
                } @else {
                    span class="muted" { "—" }
                }
            }
        }
    }
}

/// Server timestamps come back as Unix epoch seconds (or are simply
/// absent on the current wire shape). Render `YYYY-MM-DD HH:MM` in
/// UTC; the admin console deliberately stays UTC to match log lines
/// and so that two operators in different timezones see the same
/// value.
fn format_ts(v: Option<&Value>) -> Markup {
    let secs = match v.and_then(|x| x.as_i64()) {
        Some(s) => s,
        None => return html! { span class="muted" { "—" } },
    };
    // Append " UTC" so the value is unambiguous (matches
    // `views::mod::render_cell` for the rest of the admin console).
    match chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0) {
        Some(dt) => html! { (dt.format("%Y-%m-%d %H:%M UTC").to_string()) },
        None => html! { span class="muted" { "—" } },
    }
}

fn add_result_banner(v: &Value) -> Markup {
    let key_id = v
        .get("key_id")
        .and_then(|x| x.as_i64())
        .map(|n| n.to_string())
        .unwrap_or_default();
    let key_hex = v.get("key_hex").and_then(|x| x.as_str()).unwrap_or("");
    html! {
        article class="flash error" {
            strong { "New encryption key " code { (key_id) } " created." }
            p {
                "Save this hex offline as a recovery option. Then verify \
                 peers have loaded it via "
                code { "show encryption-keys" }
                " on each node before activating. "
                strong { "This value is not retrievable again." }
            }
            pre class="mono" { (key_hex) }
        }
    }
}

fn rotate_result_banner(v: &Value) -> Markup {
    let examined = v
        .get("examined")
        .and_then(|x| x.as_i64())
        .unwrap_or_default();
    let reencrypted = v
        .get("reencrypted")
        .and_then(|x| x.as_i64())
        .unwrap_or_default();
    let skipped = v
        .get("skipped")
        .and_then(|x| x.as_i64())
        .unwrap_or_default();
    html! {
        article class="flash error" {
            strong { "Bulk re-encryption complete." }
            p {
                "examined=" code { (examined.to_string()) }
                " reencrypted=" code { (reencrypted.to_string()) }
                " skipped=" code { (skipped.to_string()) } "."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn render(instance_cfg: Value, err: Option<&str>, restart: bool) -> String {
        page(
            &json!({}),
            &[],
            &instance_cfg,
            err,
            restart,
            &DekState::default(),
        )
        .into_string()
    }

    fn render_with_dek(items: &[Value], dek: &DekState<'_>) -> String {
        let _ = items; // items live inside dek; param kept to make tests readable
        page(&json!({}), &[], &json!({}), None, false, dek).into_string()
    }

    #[test]
    fn page_renders_all_sections() {
        let html = render(json!({}), None, false);
        // Instance Config (per-node listen + accept_from) lives outside
        // the Danger Zone now; Cluster DB is inside it.
        assert!(html.contains("id=\"instance\""), "missing instance section");
        assert!(
            html.contains("id=\"cluster-db\""),
            "missing cluster-db section"
        );
        assert!(
            html.contains("id=\"encryption-keys\""),
            "missing encryption-keys section"
        );
        assert!(
            !html.contains("/general/backup") && !html.to_ascii_lowercase().contains("backup"),
            "removed backup controls must not render: {html}"
        );
    }

    #[test]
    fn instance_config_section_is_outside_danger_zone() {
        // Layout invariant: the per-node listen / accept_from block
        // must come BEFORE the Danger Zone wrapper opens, and the
        // cluster_db block must come AFTER. Catches a refactor that
        // accidentally folds Instance Config back into the Danger
        // Zone.
        let html = render(json!({}), None, false);
        let instance_pos = html.find("id=\"instance\"").expect("instance id");
        let danger_pos = html.find("class=\"danger-zone\"").expect("danger-zone");
        let cluster_db_pos = html.find("id=\"cluster-db\"").expect("cluster-db id");
        assert!(
            instance_pos < danger_pos,
            "Instance Config must render above the Danger Zone",
        );
        assert!(
            cluster_db_pos > danger_pos,
            "Cluster DB must render inside the Danger Zone",
        );
    }

    #[test]
    fn instance_config_section_renders_accept_from_inputs() {
        let html = render(json!({}), None, false);
        assert!(html.contains("name=\"proxy_accept_from\""));
        assert!(html.contains("name=\"api_accept_from\""));
        assert!(html.contains("name=\"http_accept_from\""));
    }

    #[test]
    fn instance_config_section_prefills_accept_from_values() {
        let html = render(
            json!({
                "proxy_accept_from": "127.0.0.1/32,10.0.0.0/8",
                "api_accept_from": "",
                "http_accept_from": "fe80::/10",
            }),
            None,
            false,
        );
        assert!(html.contains("127.0.0.1/32,10.0.0.0/8"));
        assert!(html.contains("fe80::/10"));
    }

    #[test]
    fn danger_zone_carries_class() {
        let html = render(json!({}), None, false);
        assert!(
            html.contains("class=\"danger-zone\""),
            "expected .danger-zone wrapper: {html}"
        );
        assert!(
            html.contains("role=\"alert\""),
            "expected role=alert on danger zone"
        );
    }

    #[test]
    fn destructive_buttons_use_warning_class() {
        let html = render(json!({}), None, false);
        let warning_count = html.matches("class=\"warning\"").count();
        assert!(
            warning_count >= 2,
            "expected multiple .warning buttons in danger zone: {html}"
        );
    }

    #[test]
    fn cluster_db_section_shows_configured_state_when_redacted() {
        let html = render(json!({"cluster_db_url": "**REDACTED**"}), None, false);
        assert!(html.contains("Currently configured"));
        assert!(html.contains("Clear (revert to single-node)"));
        // The Clear button arms with the new resource name.
        assert!(html.contains("data-confirm-name=\"cluster-db\""));
    }

    #[test]
    fn instance_section_renders_error_banner() {
        // Both Instance Config and Cluster DB read from the same
        // (error, restart) pair — the daemon's PATCH /instance
        // response is one document, so a single-form error message
        // surfaces in both sections. That keeps the operator from
        // missing a banner depending on which form they submitted.
        let html = render(json!({}), Some("bad url"), false);
        assert!(html.contains("bad url"), "error message should render");
    }

    #[test]
    fn general_form_renders_acme_leader_field() {
        let html = render(json!({}), None, false);
        assert!(html.contains("name=\"acme_leader\""));
    }

    #[test]
    fn general_form_posts_to_general_route() {
        let html = render(json!({}), None, false);
        assert!(html.contains("action=\"/general\""));
    }

    #[test]
    fn sessions_section_has_a_stable_anchor() {
        let html = render(json!({}), None, false);
        assert!(html.contains("<fieldset id=\"sessions\">"));
    }

    // ───────── DEK rotation section ─────────

    #[test]
    fn dek_section_empty_state_is_explicit() {
        let html = render_with_dek(&[], &DekState::default());
        assert!(html.contains("No encryption keys loaded"));
    }

    #[test]
    fn dek_section_renders_single_active_row() {
        let items =
            vec![json!({"key_id": 0, "status": "active", "active": true, "retired": false})];
        let dek = DekState {
            items: &items,
            ..Default::default()
        };
        let html = render_with_dek(&items, &dek);
        assert!(html.contains("badge-active"), "active badge missing");
        // Active rows must NOT show Activate / Retire buttons.
        assert!(
            !html.contains(">Activate<"),
            "active row should not offer Activate"
        );
        assert!(
            !html.contains(">Retire<"),
            "active row should not offer Retire"
        );
    }

    #[test]
    fn dek_section_renders_multi_key_with_inactive_actions() {
        let items = vec![
            json!({"key_id": 0, "status": "inactive", "active": false, "retired": false}),
            json!({"key_id": 1, "status": "active", "active": true, "retired": false}),
        ];
        let dek = DekState {
            items: &items,
            ..Default::default()
        };
        let html = render_with_dek(&items, &dek);
        assert!(html.contains("/general/encryption_keys/0/activate"));
        assert!(html.contains("/general/encryption_keys/0/retire"));
        // The active row (id=1) must not get its own activate/retire form.
        assert!(!html.contains("/general/encryption_keys/1/activate"));
        assert!(!html.contains("/general/encryption_keys/1/retire"));
    }

    #[test]
    fn dek_section_renders_retired_row_greyed() {
        let items =
            vec![json!({"key_id": 2, "status": "retired", "active": false, "retired": true})];
        let dek = DekState {
            items: &items,
            ..Default::default()
        };
        let html = render_with_dek(&items, &dek);
        assert!(html.contains("badge-retired"));
        assert!(html.contains("row-retired"));
        assert!(!html.contains("/general/encryption_keys/2/activate"));
        assert!(!html.contains("/general/encryption_keys/2/retire"));
    }

    #[test]
    fn dek_add_result_shows_hex_once_with_warning() {
        let result = json!({"key_id": 3, "status": "inactive", "key_hex": "deadbeefcafef00d"});
        let dek = DekState {
            add_result: Some(&result),
            ..Default::default()
        };
        let html = render_with_dek(&[], &dek);
        assert!(html.contains("deadbeefcafef00d"), "hex should be displayed");
        assert!(
            html.contains("not retrievable again"),
            "one-shot warning missing"
        );
    }

    #[test]
    fn dek_rotate_result_renders_counts() {
        let result = json!({"examined": 12, "reencrypted": 5, "skipped": 7});
        let dek = DekState {
            rotate_result: Some(&result),
            ..Default::default()
        };
        let html = render_with_dek(&[], &dek);
        assert!(html.contains("examined=") && html.contains(">12<"));
        assert!(html.contains("reencrypted=") && html.contains(">5<"));
        assert!(html.contains("skipped=") && html.contains(">7<"));
    }

    #[test]
    fn dek_error_banner_carries_leader_hint() {
        let dek = DekState {
            error: Some("not the cluster leader; retry against node-2"),
            ..Default::default()
        };
        let html = render_with_dek(&[], &dek);
        assert!(html.contains("class=\"flash error\""));
        assert!(html.contains("node-2"));
    }

    #[test]
    fn dek_activate_button_carries_confirm_attribute() {
        let items =
            vec![json!({"key_id": 4, "status": "inactive", "active": false, "retired": false})];
        let dek = DekState {
            items: &items,
            ..Default::default()
        };
        let html = render_with_dek(&items, &dek);
        assert!(html.contains("data-confirm-name=\"activate\""));
    }

    #[test]
    fn dek_retire_button_uses_keyed_confirm_token() {
        let items =
            vec![json!({"key_id": 7, "status": "inactive", "active": false, "retired": false})];
        let dek = DekState {
            items: &items,
            ..Default::default()
        };
        let html = render_with_dek(&items, &dek);
        // Retire confirmation includes the key_id so a hasty operator
        // can't blindly type "retire" and zap an arbitrary row.
        assert!(html.contains("data-confirm-name=\"retire 7\""));
    }

    #[test]
    fn dek_rotate_button_carries_confirm_attribute() {
        let html = render(json!({}), None, false);
        assert!(html.contains("data-confirm-name=\"rotate\""));
    }

    #[test]
    fn dek_section_keeps_kek_note() {
        let html = render(json!({}), None, false);
        assert!(html.contains("intentionally not online-rotatable"));
        assert!(html.contains(
            "href=\"https://github.com/naoto256/sekisho/blob/main/docs/src/security.md\""
        ));
        assert!(html.contains("<code>docs/src/security.md</code>"));
    }
}
