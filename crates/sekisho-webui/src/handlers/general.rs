//! Consolidated "General" page — daemon-wide configuration plus the
//! Danger Zone (cluster DB and DEK ring management). The operator scrolls
//! past everyday settings before reaching destructive controls; that
//! ordering is the point of the Danger Zone pattern.

use axum::{
    Extension, Form,
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use sekisho_api_protocol::api_paths;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::guard::AuthenticatedUser;

use super::common::{err_page, render_page};

pub async fn show(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    render_with_dek_state(&s, user.as_deref(), DekFlash::None).await
}

#[derive(Debug, Deserialize)]
pub struct ConfigFormBody {
    // proxy_listen / api_listen / http_listen used to live here.
    // They moved to the instance form because bind addresses are
    // per-node (so they can't sit in the cluster-wide service DB).
    #[serde(default)]
    pub auth_domain: String,
    #[serde(default)]
    pub cookie_name: String,
    #[serde(default)]
    pub session_lifetime_hours: String,
    #[serde(default)]
    pub default_idp_id: String,
    #[serde(default)]
    pub acme_email: String,
    #[serde(default)]
    pub acme_directory: String,
    /// HA: pin the ACME-renewal leader to a named instance. Server
    /// expects `Option<Option<String>>` — empty input clears the pin
    /// and re-enables automatic election.
    #[serde(default)]
    pub acme_leader: String,
    #[serde(default)]
    pub websocket_concurrency_limit: String,
    #[serde(default)]
    pub acme_queue_capacity: String,
    #[serde(default)]
    pub acme_issuance_concurrency_limit: String,
    #[serde(default)]
    pub acme_renewal_scan_interval_hours: String,
    #[serde(default)]
    pub log_level: String,
}

pub async fn update(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Form(form): Form<ConfigFormBody>,
) -> Response {
    let body = form_to_json(&form);
    match s.client.patch_json::<Value>(api_paths::CONFIG, &body).await {
        Ok(_) => Redirect::to("/general").into_response(),
        Err(e) => err_page(&s, user.as_deref(), "Update failed", &e),
    }
}

pub(crate) fn form_to_json(form: &ConfigFormBody) -> Value {
    let mut out = serde_json::Map::new();
    put(&mut out, "auth_domain", &form.auth_domain);
    put(&mut out, "cookie_name", &form.cookie_name);
    if let Ok(n) = form.session_lifetime_hours.trim().parse::<u32>() {
        out.insert("session_lifetime_hours".into(), json!(n));
    }
    if !form.default_idp_id.trim().is_empty() {
        out.insert(
            "default_idp_id".into(),
            Value::String(form.default_idp_id.trim().to_string()),
        );
    } else {
        out.insert("default_idp_id".into(), Value::Null);
    }
    put(&mut out, "acme_email", &form.acme_email);
    put(&mut out, "acme_directory", &form.acme_directory);
    if form.acme_leader.trim().is_empty() {
        out.insert("acme_leader".into(), Value::Null);
    } else {
        out.insert(
            "acme_leader".into(),
            Value::String(form.acme_leader.trim().to_string()),
        );
    }
    if let Ok(n) = form.websocket_concurrency_limit.trim().parse::<u32>() {
        out.insert("websocket_concurrency_limit".into(), json!(n));
    }
    if let Ok(n) = form.acme_queue_capacity.trim().parse::<u32>() {
        out.insert("acme_queue_capacity".into(), json!(n));
    }
    if let Ok(n) = form.acme_issuance_concurrency_limit.trim().parse::<u32>() {
        out.insert("acme_issuance_concurrency_limit".into(), json!(n));
    }
    if let Ok(n) = form.acme_renewal_scan_interval_hours.trim().parse::<u32>() {
        out.insert("acme_renewal_scan_interval_hours".into(), json!(n));
    }
    put(&mut out, "log_level", &form.log_level);
    Value::Object(out)
}

fn put(map: &mut serde_json::Map<String, Value>, key: &str, v: &str) {
    let t = v.trim();
    if !t.is_empty() {
        map.insert(key.into(), Value::String(t.to_string()));
    }
}

/// Banner state for the DEK rotation section. The four sub-handlers
/// (add / activate / retire / rotate) hand one of these in after the
/// daemon call returns so the consolidated page can re-render with the
/// right success / error chrome anchored at `#encryption-keys`.
pub enum DekFlash {
    None,
    /// `POST /encryption_keys` succeeded — body includes the one-shot
    /// `key_hex` and the new `key_id`. Surfaced verbatim.
    Added(Value),
    /// `POST /encryption_keys/rotate` succeeded — body has the
    /// `examined / reencrypted / skipped` counters.
    Rotated(Value),
    /// Any handler failed. The string is a humanised message (leader
    /// hint already appended for 503s); see
    /// `super::encryption_keys::humanise`.
    Error(String),
}

/// Re-render the consolidated page with an optional instance-section
/// banner. Used by [`super::instance::update`] when it wants to surface
/// a validation error or a "saved (restart required)" notice without
/// losing the surrounding General content.
pub(crate) async fn render_with_instance_state(
    s: &AppState,
    user: Option<&AuthenticatedUser>,
    instance_error: Option<&str>,
    instance_restart: bool,
) -> Response {
    render_full(s, user, instance_error, instance_restart, DekFlash::None).await
}

/// Re-render the consolidated page with the DEK section flashed.
/// Instance state defaults to "no banner" — DEK actions never touch
/// the instance form.
pub(crate) async fn render_with_dek_state(
    s: &AppState,
    user: Option<&AuthenticatedUser>,
    dek: DekFlash,
) -> Response {
    render_full(s, user, None, false, dek).await
}

/// Internal: fetch every input the consolidated page needs and render.
/// One DRY funnel for all three call paths (initial GET, instance
/// re-render, DEK re-render) so a future field added to `views::general::page` only
/// needs to be wired once.
async fn render_full(
    s: &AppState,
    user: Option<&AuthenticatedUser>,
    instance_error: Option<&str>,
    instance_restart: bool,
    dek: DekFlash,
) -> Response {
    let config: Value = match s.client.get_json(api_paths::CONFIG).await {
        Ok(v) => v,
        Err(e) => return err_page(s, user, "Config fetch failed", &e),
    };
    let idps = s.client.get_list(api_paths::IDPS).await.unwrap_or_default();
    let instance_cfg: Value = s
        .client
        .get_json(api_paths::INSTANCE)
        .await
        .unwrap_or(Value::Null);
    // Encryption-key list: degrade to empty rather than failing the
    // whole page — the operator might still need to read other Danger
    // Zone sections even if the daemon momentarily refused this call.
    let dek_items = s
        .client
        .get_list(api_paths::ENCRYPTION_KEYS)
        .await
        .unwrap_or_default();

    // Pre-extract owned bindings so the resulting `&str` / `&Value`
    // references all live for the whole `dek_state` lifetime.
    let (add_ref, rotate_ref, err_ref): (Option<&Value>, Option<&Value>, Option<&str>) = match &dek
    {
        DekFlash::None => (None, None, None),
        DekFlash::Added(v) => (Some(v), None, None),
        DekFlash::Rotated(v) => (None, Some(v), None),
        DekFlash::Error(e) => (None, None, Some(e.as_str())),
    };
    let dek_state = crate::views::general::DekState {
        items: &dek_items,
        add_result: add_ref,
        rotate_result: rotate_ref,
        error: err_ref,
    };

    render_page(
        s,
        user,
        "General",
        crate::views::general::page(
            &config,
            &idps,
            &instance_cfg,
            instance_error,
            instance_restart,
            &dek_state,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_form() -> ConfigFormBody {
        ConfigFormBody {
            auth_domain: String::new(),
            cookie_name: String::new(),
            session_lifetime_hours: String::new(),
            default_idp_id: String::new(),
            acme_email: String::new(),
            acme_directory: String::new(),
            acme_leader: String::new(),
            websocket_concurrency_limit: String::new(),
            acme_queue_capacity: String::new(),
            acme_issuance_concurrency_limit: String::new(),
            acme_renewal_scan_interval_hours: String::new(),
            log_level: String::new(),
        }
    }

    #[test]
    fn empty_default_idp_id_submits_as_null() {
        let f = blank_form();
        let j = form_to_json(&f);
        assert_eq!(j["default_idp_id"], Value::Null);
    }

    #[test]
    fn default_idp_id_uuid_is_passed_through_as_string() {
        let mut f = blank_form();
        f.default_idp_id = "11111111-2222-3333-4444-555555555555".into();
        let j = form_to_json(&f);
        assert_eq!(j["default_idp_id"], "11111111-2222-3333-4444-555555555555");
    }

    #[test]
    fn websocket_limit_is_submitted_as_number() {
        let mut f = blank_form();
        f.websocket_concurrency_limit = "100".into();
        let j = form_to_json(&f);
        assert_eq!(j["websocket_concurrency_limit"], json!(100));
    }
}
