//! Route list / create / edit / update / delete, plus the `enable`
//! and `disable` verbs that drive client-side ACME orchestration.
//!
//! The server side no longer understands an "enable lifecycle" — it
//! only flips `enabled` on command. sekisho-webui is the one that knows
//! it must mint a certificate first when `tls_downstream=acme` and
//! none exists for the hostname. That knowledge lives here rather
//! than in the generic client because different UIs (sekisho-cli,
//! sekisho-webui, future Terraform provider) may want to sequence the
//! pre-flight differently.

use anyhow::anyhow;
use axum::{
    Extension, Form,
    extract::{Path, State},
    response::{IntoResponse, Redirect, Response},
};
use sekisho_api_protocol::api_paths;
use serde::Deserialize;
use serde_json::{Value, json};

use super::common::{err_page, render_html, render_page};

/// Wrap an error from an htmx-driven enable/disable flow in a row-
/// shaped error banner so the swap stays inside the table rather
/// than dropping a full error page into a single `<tr>`.
fn row_error_response(route_id: &str, label: &str, e: &anyhow::Error) -> Response {
    tracing::warn!(route_id = %route_id, error = %e, "{label}");
    render_html(view::row_error(route_id, &format!("{label}: {e}")))
}
use crate::AppState;
use crate::auth::guard::AuthenticatedUser;
use crate::views::routes as view;

pub async fn list(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let u = user.as_deref();
    let items = match s.client.get_list(api_paths::ROUTES).await {
        Ok(v) => v,
        Err(e) => return err_page(&s, u, "Route list failed", &e),
    };
    render_page(&s, u, "Routes", view::list(&items))
}

pub async fn new_form(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    // Fetch the IdP list so the route's `idp_id` field can render as
    // a name-labelled dropdown (same rationale as the Config page).
    // Absent list falls through to an empty dropdown; the operator can
    // still leave idp_id blank to inherit the default.
    let idps = s.client.get_list(api_paths::IDPS).await.unwrap_or_default();
    render_page(&s, user.as_deref(), "Create route", view::new_form(&idps))
}

pub async fn edit(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    let u = user.as_deref();
    let item: Value = match s.client.get_json(&format!("/routes/{id}")).await {
        Ok(v) => v,
        Err(e) => return err_page(&s, u, "Route fetch failed", &e),
    };
    let idps = s.client.get_list(api_paths::IDPS).await.unwrap_or_default();
    render_page(&s, u, "Edit route", view::edit_form(&item, &idps))
}

/// Flat HTML form body. Checkbox fields come through as `Option<String>`:
/// `Some("true")` when checked, `None` when unchecked — no hidden
/// "this field was touched" companion is needed because the form
/// always submits the full state of the route.
#[derive(Debug, Deserialize)]
pub struct RouteFormBody {
    pub name: String,
    pub from: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub tls_downstream: String,
    #[serde(default)]
    pub idp_id: String,
    #[serde(default)]
    pub access_policy: String,
    #[serde(default)]
    pub allow_public_unauthenticated_access: Option<String>,
    #[serde(default)]
    pub preserve_host_header: Option<String>,
    #[serde(default)]
    pub host_rewrite: String,
    #[serde(default)]
    pub timeout_ms: String,
    #[serde(default)]
    pub response_idle_timeout_ms: String,
    #[serde(default)]
    pub enable_websocket: Option<String>,
    #[serde(default)]
    pub enable_grpc: Option<String>,
    #[serde(default)]
    pub enable_signed_identity: Option<String>,
    #[serde(default)]
    pub tls_skip_verify: Option<String>,
    #[serde(default)]
    pub load_balancing: String,
    #[serde(default)]
    pub regex_rewrite_pattern: String,
    #[serde(default)]
    pub regex_rewrite_substitution: String,
    /// `key=value` per line; blank lines and lines without `=` are ignored.
    #[serde(default)]
    pub headers_add: String,
    /// One header name per line; blank lines ignored.
    #[serde(default)]
    pub headers_remove: String,
    /// Opt-in checkbox: lets `headers_add` / `headers_remove` carry
    /// `Authorization` / `Cookie`. Same `Option<String>` shape as the
    /// other checkboxes — present (`Some("true")`) when ticked.
    #[serde(default)]
    pub allow_credential_overrides: Option<String>,
    /// `lax` (default), `none`, `strict`, or empty string for "no
    /// override". The select element below maps to one of these.
    #[serde(default)]
    pub session_cookie_samesite: String,
    #[serde(default)]
    pub response_location_rewrite: Option<String>,
    #[serde(default)]
    pub concurrency_limit: String,
}

pub async fn create(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Form(form): Form<RouteFormBody>,
) -> Response {
    let body = match form_to_json(&form) {
        Ok(body) => body,
        Err(error) => return err_page(&s, user.as_deref(), "Create failed", &error),
    };
    match s.client.post_json::<Value>(api_paths::ROUTES, &body).await {
        Ok(_) => Redirect::to("/routes").into_response(),
        Err(e) => err_page(&s, user.as_deref(), "Create failed", &e),
    }
}

pub async fn update(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
    Form(form): Form<RouteFormBody>,
) -> Response {
    let mut body = match form_to_json(&form) {
        Ok(body) => body,
        Err(error) => return err_page(&s, user.as_deref(), "Update failed", &error),
    };
    // RFC 7396 merges sub-objects recursively, so a `headers.add` map
    // that the operator emptied in the form arrives as `{}` and the
    // server's merge step is a no-op: every key the operator removed
    // silently survives. Fix it client-side by fetching the current
    // route and explicitly nulling out every `headers.add` key that
    // the form no longer contains. Arrays (headers.remove) replace
    // wholesale per RFC 7396 so they don't need the same dance.
    if let Ok(current) = s.client.get_json(&format!("/routes/{id}")).await {
        null_out_removed_header_keys(&mut body, &current);
    }
    match s
        .client
        .patch_json::<Value>(&format!("/routes/{id}"), &body)
        .await
    {
        Ok(_) => Redirect::to("/routes").into_response(),
        Err(e) => err_page(&s, user.as_deref(), "Update failed", &e),
    }
}

/// For every key in `current.headers.add` that is missing from
/// `patch.headers.add`, insert it into `patch.headers.add` with a
/// `null` value. After the server's RFC 7396 merge step that null
/// removes the key from the stored route.
fn null_out_removed_header_keys(patch: &mut Value, current: &Value) {
    let Some(current_add) = current
        .get("headers")
        .and_then(|h| h.get("add"))
        .and_then(|a| a.as_object())
    else {
        return;
    };
    let removed: Vec<String> = {
        let patch_add = patch
            .get("headers")
            .and_then(|h| h.get("add"))
            .and_then(|a| a.as_object());
        current_add
            .keys()
            .filter(|k| patch_add.is_none_or(|m| !m.contains_key(*k)))
            .cloned()
            .collect()
    };
    if removed.is_empty() {
        return;
    }
    let Some(patch_add_mut) = patch
        .get_mut("headers")
        .and_then(|h| h.get_mut("add"))
        .and_then(|a| a.as_object_mut())
    else {
        return;
    };
    for k in removed {
        patch_add_mut.insert(k, Value::Null);
    }
}

pub async fn delete(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    match s.client.delete(&format!("/routes/{id}")).await {
        Ok(()) => Response::new(axum::body::Body::empty()),
        Err(e) => err_page(&s, user.as_deref(), "Delete failed", &e),
    }
}

/// `POST /routes/{id}/enable` — orchestrates cert pre-flight, then
/// flips `enabled=true`. Returns the updated row fragment so HTMX
/// can swap it in place; full-page errors still surface through
/// `err_page` if anything unrecoverable goes wrong.
pub async fn enable(
    State(s): State<AppState>,
    _user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    if let Err(msg) = sekisho_api_protocol::ensure_cert_before_enable(&s.client, &id).await {
        return row_error_response(&id, "cannot enable", &anyhow!(msg));
    }
    match s
        .client
        .patch_json::<Value>(&format!("/routes/{id}"), &json!({ "enabled": true }))
        .await
    {
        Ok(v) => render_html(view::row(&v)),
        Err(e) => row_error_response(&id, "enable failed", &e),
    }
}

/// `POST /routes/{id}/disable` — direct flip, no pre-flight.
pub async fn disable(
    State(s): State<AppState>,
    _user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    match s
        .client
        .patch_json::<Value>(&format!("/routes/{id}"), &json!({ "enabled": false }))
        .await
    {
        Ok(v) => render_html(view::row(&v)),
        Err(e) => row_error_response(&id, "disable failed", &e),
    }
}

/// Convert the flat form into the nested `Route` shape.
///
/// The form always submits its whole state, so on PATCH this is effectively a
/// full replace: explicit `false` and `null` are sent rather than omitted, so
/// that unchecking a box or clearing a text input actually propagates. Omitting
/// them instead would make the merge patch treat every cleared field as "leave
/// alone", and the UI would silently refuse to turn anything off.
fn form_to_json(form: &RouteFormBody) -> anyhow::Result<Value> {
    let name = trimmed_opt(&form.name);
    let from = trimmed_opt(&form.from);
    let to: Vec<String> = form
        .to
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let idp = trimmed_opt(&form.idp_id)
        .map(Value::String)
        .unwrap_or(Value::Null);
    let policy = trimmed_opt(&form.access_policy);
    let allow_public = checkbox_bool(&form.allow_public_unauthenticated_access);

    let mut out = serde_json::Map::new();
    if let Some(n) = name {
        out.insert("name".into(), Value::String(n));
    }
    if let Some(f) = from {
        out.insert("from".into(), Value::String(f));
    }
    // `path` is nullable on the server (`Option<Option<String>>` on
    // PATCH). Empty input = null = "any path".
    out.insert(
        "path".into(),
        trimmed_opt(&form.path)
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    if !to.is_empty() {
        out.insert(
            "to".into(),
            Value::Array(to.into_iter().map(Value::String).collect()),
        );
    }
    if !form.tls_downstream.is_empty() {
        out.insert(
            "tls_downstream".into(),
            Value::String(form.tls_downstream.clone()),
        );
    }
    out.insert("idp_id".into(), idp);
    out.insert(
        "access".into(),
        json!({
            "policy": policy,
            "allow_public_unauthenticated_access": allow_public,
        }),
    );

    out.insert(
        "preserve_host_header".into(),
        Value::Bool(checkbox_bool(&form.preserve_host_header)),
    );
    out.insert(
        "host_rewrite".into(),
        trimmed_opt(&form.host_rewrite)
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    if let Ok(ms) = form.timeout_ms.trim().parse::<u64>() {
        out.insert("timeout_ms".into(), json!(ms));
    }
    if let Some(raw) = trimmed_opt(&form.response_idle_timeout_ms) {
        let value = raw
            .parse::<u64>()
            .map_err(|_| anyhow!("response_idle_timeout_ms must be an unsigned integer"))?;
        out.insert("response_idle_timeout_ms".into(), json!(value));
    }
    out.insert(
        "enable_websocket".into(),
        Value::Bool(checkbox_bool(&form.enable_websocket)),
    );
    out.insert(
        "enable_grpc".into(),
        Value::Bool(checkbox_bool(&form.enable_grpc)),
    );
    out.insert(
        "enable_signed_identity".into(),
        Value::Bool(checkbox_bool(&form.enable_signed_identity)),
    );
    out.insert(
        "tls_skip_verify".into(),
        Value::Bool(checkbox_bool(&form.tls_skip_verify)),
    );
    if !form.load_balancing.is_empty() {
        out.insert(
            "load_balancing".into(),
            Value::String(form.load_balancing.clone()),
        );
    }
    out.insert(
        "regex_rewrite_pattern".into(),
        trimmed_opt(&form.regex_rewrite_pattern)
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    out.insert(
        "regex_rewrite_substitution".into(),
        trimmed_opt(&form.regex_rewrite_substitution)
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    out.insert(
        "headers".into(),
        json!({
            "add": parse_headers_add(&form.headers_add),
            "remove": parse_headers_remove(&form.headers_remove),
            "allow_credential_overrides": checkbox_bool(&form.allow_credential_overrides),
        }),
    );
    // Per-route SameSite override. Empty string = "inherit default"
    // (= clear the per-route override on PATCH via JSON null).
    let ss = form.session_cookie_samesite.trim();
    match ss {
        "lax" | "none" | "strict" => {
            out.insert("session_cookie_samesite".into(), json!(ss));
        }
        _ => {
            out.insert("session_cookie_samesite".into(), Value::Null);
        }
    }
    out.insert(
        "response_location_rewrite".into(),
        Value::Bool(checkbox_bool(&form.response_location_rewrite)),
    );
    let concurrency_limit = match trimmed_opt(&form.concurrency_limit) {
        Some(raw) => Value::from(
            raw.parse::<u32>()
                .map_err(|_| anyhow!("concurrency_limit must be an unsigned integer"))?,
        ),
        None => Value::Null,
    };
    out.insert("concurrency_limit".into(), concurrency_limit);
    Ok(Value::Object(out))
}

fn trimmed_opt(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// HTML unchecked checkboxes send no value; browsers submit `"on"` (or
/// whatever `value=` is set to) when checked. Treat any non-empty value
/// as truthy so the server receives an explicit bool either way.
fn checkbox_bool(v: &Option<String>) -> bool {
    matches!(v.as_deref(), Some(s) if !s.is_empty() && !s.eq_ignore_ascii_case("false"))
}

fn parse_headers_add(raw: &str) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        if k.is_empty() {
            continue;
        }
        out.insert(k.to_string(), Value::String(v.trim().to_string()));
    }
    out
}

fn parse_headers_remove(raw: &str) -> Vec<Value> {
    raw.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| Value::String(s.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_route_form() -> RouteFormBody {
        RouteFormBody {
            name: "app".into(),
            from: "https://app.example.com".into(),
            path: "/api".into(),
            to: "http://127.0.0.1:8080".into(),
            tls_downstream: "acme".into(),
            idp_id: String::new(),
            access_policy: "claim.email == \"a@example.com\"".into(),
            allow_public_unauthenticated_access: None,
            preserve_host_header: Some("on".into()),
            host_rewrite: String::new(),
            timeout_ms: "45000".into(),
            response_idle_timeout_ms: "180000".into(),
            enable_websocket: Some("on".into()),
            enable_grpc: None,
            enable_signed_identity: Some("on".into()),
            tls_skip_verify: None,
            load_balancing: "round_robin".into(),
            regex_rewrite_pattern: String::new(),
            regex_rewrite_substitution: String::new(),
            headers_add: "X-Real-IP=$remote\n".into(),
            headers_remove: "X-Forwarded-Host\n".into(),
            allow_credential_overrides: None,
            session_cookie_samesite: String::new(),
            response_location_rewrite: Some("on".into()),
            concurrency_limit: "12".into(),
        }
    }

    #[test]
    fn checkbox_bool_handles_common_browser_values() {
        assert!(!checkbox_bool(&None));
        assert!(!checkbox_bool(&Some(String::new())));
        assert!(!checkbox_bool(&Some("false".into())));
        assert!(checkbox_bool(&Some("on".into())));
        assert!(checkbox_bool(&Some("true".into())));
    }

    #[test]
    fn parse_headers_add_tolerates_blanks_and_bad_lines() {
        let raw = "X-Foo = bar\n  \nX-Baz =\nnocolon\n=noname\nX-Ok=ok";
        let m = parse_headers_add(raw);
        assert_eq!(m.get("X-Foo"), Some(&Value::String("bar".into())));
        assert_eq!(m.get("X-Baz"), Some(&Value::String(String::new())));
        assert_eq!(m.get("X-Ok"), Some(&Value::String("ok".into())));
        assert_eq!(m.len(), 3, "skipped lines shouldn't make it in");
    }

    #[test]
    fn null_out_removed_header_keys_emits_null_for_each_dropped_key() {
        // Operator removed `X-Real-IP` and `X-Request-Id` from the
        // form, kept `Authorization`, and added `X-Trace`. The patch
        // sent by `form_to_json` only carries the surviving + new
        // entries; `null_out_removed_header_keys` must rewrite it so
        // the server's RFC 7396 merge actually drops the removed keys.
        let current = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000000",
            "headers": {
                "add": {
                    "X-Real-IP": "$remote",
                    "X-Request-Id": "$request_id",
                    "Authorization": "Basic abc",
                },
                "remove": [],
                "allow_credential_overrides": false,
            },
        });
        let mut patch = serde_json::json!({
            "headers": {
                "add": {
                    "Authorization": "Basic abc",
                    "X-Trace": "1",
                },
                "remove": [],
                "allow_credential_overrides": false,
            },
        });
        null_out_removed_header_keys(&mut patch, &current);
        let add = patch["headers"]["add"].as_object().unwrap();
        assert!(add.get("X-Real-IP").is_some_and(|v| v.is_null()));
        assert!(add.get("X-Request-Id").is_some_and(|v| v.is_null()));
        assert_eq!(
            add.get("Authorization"),
            Some(&Value::String("Basic abc".into()))
        );
        assert_eq!(add.get("X-Trace"), Some(&Value::String("1".into())));
    }

    #[test]
    fn null_out_removed_header_keys_handles_empty_form_clearing_all() {
        // Operator emptied the textarea entirely. Patch arrives with
        // `headers.add: {}` — without the helper that would be a no-op
        // merge and every existing key would survive.
        let current = serde_json::json!({
            "headers": {
                "add": { "X-A": "1", "X-B": "2" },
            }
        });
        let mut patch = serde_json::json!({
            "headers": { "add": {}, "remove": [] },
        });
        null_out_removed_header_keys(&mut patch, &current);
        let add = patch["headers"]["add"].as_object().unwrap();
        assert_eq!(add.len(), 2);
        assert!(add["X-A"].is_null());
        assert!(add["X-B"].is_null());
    }

    #[test]
    fn parse_headers_remove_ignores_blanks() {
        let v = parse_headers_remove("X-Forwarded-For\n\n  X-Real-IP  \n");
        assert_eq!(
            v,
            vec![
                Value::String("X-Forwarded-For".into()),
                Value::String("X-Real-IP".into()),
            ]
        );
    }

    #[test]
    fn form_to_json_emits_full_route_shape() {
        let form = valid_route_form();
        let j = form_to_json(&form).expect("valid route form");
        assert_eq!(j["name"], "app");
        assert_eq!(j["path"], "/api");
        assert_eq!(
            j["access"]["allow_public_unauthenticated_access"],
            Value::Bool(false)
        );
        assert_eq!(j["preserve_host_header"], Value::Bool(true));
        assert_eq!(j["enable_websocket"], Value::Bool(true));
        assert_eq!(j["enable_grpc"], Value::Bool(false));
        assert_eq!(j["timeout_ms"], 45000);
        assert_eq!(j["response_idle_timeout_ms"], 180000);
        assert_eq!(j["response_location_rewrite"], Value::Bool(true));
        assert_eq!(j["concurrency_limit"], 12);
        assert_eq!(j["idp_id"], Value::Null);
        assert_eq!(j["host_rewrite"], Value::Null);
        assert_eq!(j["headers"]["add"]["X-Real-IP"], "$remote");
        assert_eq!(j["headers"]["remove"], json!(["X-Forwarded-Host"]));
        assert_eq!(
            j["headers"]["allow_credential_overrides"],
            Value::Bool(false),
            "default form submission must not silently grant the override"
        );
    }

    #[test]
    fn form_to_json_preserves_false_zero_and_clear_semantics() {
        let mut form = valid_route_form();
        form.response_location_rewrite = None;
        form.concurrency_limit.clear();

        let j = form_to_json(&form).expect("valid route form");
        assert_eq!(j["response_location_rewrite"], Value::Bool(false));
        assert_eq!(j["concurrency_limit"], Value::Null);

        let mut zero = form;
        zero.concurrency_limit = "0".into();
        assert_eq!(
            form_to_json(&zero).expect("zero is a valid explicit cap")["concurrency_limit"],
            0
        );
    }

    #[test]
    fn form_to_json_rejects_nonempty_invalid_or_overflowing_limits() {
        for invalid in ["nope", "18446744073709551616"] {
            let mut form = valid_route_form();
            form.response_idle_timeout_ms = invalid.into();
            assert!(
                form_to_json(&form).is_err(),
                "invalid response idle timeout must not yield a mutation payload"
            );
        }
        for invalid in ["nope", "4294967296"] {
            let mut form = valid_route_form();
            form.concurrency_limit = invalid.into();
            assert!(
                form_to_json(&form).is_err(),
                "invalid concurrency limit must not yield a mutation payload"
            );
        }
    }
}
