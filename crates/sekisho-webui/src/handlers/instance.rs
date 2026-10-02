//! Instance config form sub-handler. The full UI surface lives inside the
//! consolidated `/general` page (Danger Zone section); this module
//! only owns the POST endpoint that mutates the daemon's encrypted,
//! instance-local `instance_config` table.
//!
//! On success the page is re-rendered through
//! [`super::general::render_with_instance_state`] so the operator
//! lands back on the General view with a "saved (restart required)"
//! banner anchored at the Instance section. Validation errors take
//! the same path with an error banner.

use axum::{
    Extension, Form,
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use sekisho_api_protocol::api_paths;
use serde::Deserialize;
use serde_json::Value;

use crate::AppState;
use crate::auth::guard::AuthenticatedUser;

use super::common::err_page;

#[derive(Debug, Deserialize)]
pub struct InstanceFormBody {
    /// `cluster_db_url` input. Empty means "no change"; a non-empty
    /// value sets it; the `clear` action (rendered as a separate
    /// button) sends `__clear=1` which we convert to `null` for
    /// cluster_db_url specifically.
    #[serde(default)]
    pub cluster_db_url: String,
    /// Listen address fields. Unlike `cluster_db_url`, these are
    /// rendered with their current value pre-filled, so an unchanged
    /// submission echoes the same string back. Semantics:
    ///
    /// * value matches what's already stored → no PATCH for that field.
    /// * value differs (including empty for `api_listen`/`http_listen`,
    ///   which legitimately accept `""`) → PATCH that field.
    ///
    /// We don't try to distinguish empty-typed-by-user from
    /// empty-default — empty just maps to "set to empty string", which
    /// the server treats sensibly (api_listen "" = localhost only;
    /// http_listen "" = disabled; proxy_listen "" is rejected by
    /// validate_listen_addr, surfacing a 400 the operator can correct).
    #[serde(default)]
    pub proxy_listen: String,
    #[serde(default)]
    pub api_listen: String,
    #[serde(default)]
    pub http_listen: String,
    /// Per-listener source-IP ACL ("accept_from"). Comma-separated
    /// CIDRs / IPs. Round-trips through the form just like the listen
    /// addresses; empty value = "any source".
    #[serde(default)]
    pub proxy_accept_from: String,
    #[serde(default)]
    pub api_accept_from: String,
    #[serde(default)]
    pub http_accept_from: String,
    #[serde(default, rename = "__clear")]
    pub clear: String,
}

pub async fn update(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Form(form): Form<InstanceFormBody>,
) -> Response {
    let u = user.as_deref();
    let body = match form_to_json(&form) {
        Ok(Some(b)) => b,
        // No change — bounce back to /general so the user sees the
        // unchanged page rather than a stale form re-render.
        Ok(None) => return Redirect::to("/general#instance").into_response(),
        Err(msg) => {
            return super::general::render_with_instance_state(&s, u, Some(&msg), false).await;
        }
    };

    match s
        .client
        .patch_json::<Value>(api_paths::INSTANCE, &body)
        .await
    {
        Ok(response) => {
            let restart = response
                .get("_restart_required")
                .map(|v| !v.is_null() && v.as_bool() != Some(false))
                .unwrap_or(false);
            super::general::render_with_instance_state(&s, u, None, restart).await
        }
        Err(e) => err_page(&s, u, "Instance update failed", &e),
    }
}

/// Turn the form submission into the PATCH body.
///
/// Returns `Ok(None)` only when there is genuinely nothing to send —
/// `cluster_db_url` blank (= keep current), no clear, and no listen
/// fields touched. The listen fields are always sent when present in
/// the form because the form always echoes the current value back; the
/// daemon side de-duplicates so a no-op submission doesn't appear in
/// the audit log.
fn form_to_json(form: &InstanceFormBody) -> std::result::Result<Option<Value>, String> {
    let mut body = serde_json::Map::new();

    if !form.clear.is_empty() {
        body.insert("cluster_db_url".into(), Value::Null);
    } else {
        let trimmed = form.cluster_db_url.trim();
        if !trimmed.is_empty() {
            let lower = trimmed.to_ascii_lowercase();
            if !(lower.starts_with("postgres://")
                || lower.starts_with("postgresql://")
                || lower.starts_with("sqlite:"))
            {
                return Err(
                    "cluster_db_url must start with postgres://, postgresql://, or sqlite:".into(),
                );
            }
            body.insert("cluster_db_url".into(), Value::String(trimmed.to_string()));
        }
    }

    // Listen fields. Always send them (de-dup happens server-side) so
    // the operator can clear `api_listen` / `http_listen` by submitting
    // the form with the field blank. `proxy_listen` blank would 400 on
    // the server (validate_listen_addr rejects empty), which is the
    // right surface — a blank proxy_listen means "stop listening on
    // the proxy" and that's not a thing.
    body.insert(
        "proxy_listen".into(),
        Value::String(form.proxy_listen.trim().to_string()),
    );
    body.insert(
        "api_listen".into(),
        Value::String(form.api_listen.trim().to_string()),
    );
    body.insert(
        "http_listen".into(),
        Value::String(form.http_listen.trim().to_string()),
    );
    // accept_from fields. Always sent (de-dup happens server-side)
    // so an operator can clear an existing rule list by submitting
    // the field blank. Server-side `acl::AcceptFrom::parse` rejects
    // malformed CIDRs with a 400 — we don't validate here so the
    // error surface stays in one place.
    body.insert(
        "proxy_accept_from".into(),
        Value::String(form.proxy_accept_from.trim().to_string()),
    );
    body.insert(
        "api_accept_from".into(),
        Value::String(form.api_accept_from.trim().to_string()),
    );
    body.insert(
        "http_accept_from".into(),
        Value::String(form.http_accept_from.trim().to_string()),
    );

    if body.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Value::Object(body)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank() -> InstanceFormBody {
        InstanceFormBody {
            cluster_db_url: String::new(),
            proxy_listen: String::new(),
            api_listen: String::new(),
            http_listen: String::new(),
            proxy_accept_from: String::new(),
            api_accept_from: String::new(),
            http_accept_from: String::new(),
            clear: String::new(),
        }
    }

    #[test]
    fn body_omits_cluster_db_url_when_blank_and_not_clearing() {
        // Blank cluster_db_url with no clear is "keep current". Listen
        // fields are always sent (the form always echoes them back),
        // so the body is never genuinely empty after the listen-config
        // move — it just doesn't carry a cluster_db_url key.
        let body = form_to_json(&blank()).unwrap().unwrap();
        assert!(body.get("cluster_db_url").is_none());
        assert_eq!(body["proxy_listen"], Value::String("".into()));
    }

    #[test]
    fn clear_sends_null_for_cluster_db_url() {
        let mut f = blank();
        f.clear = "1".into();
        let body = form_to_json(&f).unwrap().unwrap();
        assert_eq!(body["cluster_db_url"], Value::Null);
    }

    #[test]
    fn sets_trimmed_value() {
        let mut f = blank();
        f.cluster_db_url = "  postgres://u@h/db  ".into();
        let body = form_to_json(&f).unwrap().unwrap();
        assert_eq!(
            body["cluster_db_url"],
            Value::String("postgres://u@h/db".into())
        );
    }

    #[test]
    fn rejects_unknown_scheme() {
        let mut f = blank();
        f.cluster_db_url = "mysql://u@h/db".into();
        assert!(form_to_json(&f).is_err());
    }

    #[test]
    fn clear_beats_value() {
        let mut f = blank();
        f.cluster_db_url = "postgres://u@h/db".into();
        f.clear = "1".into();
        let body = form_to_json(&f).unwrap().unwrap();
        assert_eq!(body["cluster_db_url"], Value::Null);
    }

    #[test]
    fn accept_from_fields_round_trip_through_form() {
        let mut f = blank();
        f.proxy_accept_from = " 127.0.0.1/32, 10.0.0.0/8 ".into();
        f.api_accept_from = "".into();
        f.http_accept_from = "::1/128".into();
        let body = form_to_json(&f).unwrap().unwrap();
        // Trimmed at the outer level; inner whitespace is left for
        // the server's parser to normalise (we don't want to second-
        // guess `acl::AcceptFrom::parse` from the WebUI side).
        assert_eq!(
            body["proxy_accept_from"],
            Value::String("127.0.0.1/32, 10.0.0.0/8".into())
        );
        assert_eq!(body["api_accept_from"], Value::String("".into()));
        assert_eq!(body["http_accept_from"], Value::String("::1/128".into()));
    }

    #[test]
    fn listen_fields_round_trip_verbatim() {
        // Listen addresses go through the form unchanged (modulo
        // trimming). De-duplication against the current value happens
        // server-side, so the handler always sends the user-typed
        // value as-is.
        let mut f = blank();
        f.proxy_listen = "  10.0.0.1:443 ".into();
        f.api_listen = "10.0.0.1:9443".into();
        f.http_listen = "".into();
        let body = form_to_json(&f).unwrap().unwrap();
        assert_eq!(body["proxy_listen"], Value::String("10.0.0.1:443".into()));
        assert_eq!(body["api_listen"], Value::String("10.0.0.1:9443".into()));
        assert_eq!(body["http_listen"], Value::String("".into()));
    }
}
