//! Identity-provider list / create / edit / delete. OIDC and SAML
//! live on the same resource (`/idps`), distinguished by the `type`
//! discriminator and a matching `oidc_config` or `saml_config` sub-
//! object.

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::{IntoResponse, Redirect, Response},
};
use sekisho_api_protocol::api_paths;
use serde::Deserialize;
use serde_json::Value;

use super::common::{err_page, render_page};
use crate::AppState;
use crate::auth::guard::AuthenticatedUser;
use crate::views::idps as view;

pub async fn list(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let u = user.as_deref();
    let items = match s.client.get_list(api_paths::IDPS).await {
        Ok(v) => v,
        Err(e) => return err_page(&s, u, "IdP list failed", &e),
    };
    // The default IdP is daemon-wide enrichment rather than part of each IdP.
    // If that auxiliary fetch fails, keep the primary list available and omit
    // only the badge while leaving a diagnostic for operators.
    let config: anyhow::Result<Value> = s.client.get_json(api_paths::CONFIG).await;
    render_page(
        &s,
        u,
        "Identity Providers",
        list_with_config(&items, config),
    )
}

/// Render the IdP list from an already-attempted configuration fetch.
///
/// Keeping this step separate from [`list`] lets the degraded path be tested
/// without constructing a management client. The generic `E: Display` also
/// lets that test supply a small representative error instead of constructing
/// the client's concrete error type.
fn list_with_config<E>(items: &[Value], config: Result<Value, E>) -> maud::Markup
where
    E: std::fmt::Display,
{
    match config {
        Ok(config) => view::list(items, config.get("default_idp_id").and_then(Value::as_str)),
        Err(error) => {
            tracing::warn!(%error, "Config fetch failed; rendering IdP list without default badge");
            view::list(items, None)
        }
    }
}

pub async fn new_form(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    render_page(&s, user.as_deref(), "Add IdP", view::new_form())
}

pub async fn edit(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    let u = user.as_deref();
    let item: Value = match s.client.get_json(&format!("/idps/{id}")).await {
        Ok(v) => v,
        Err(e) => return err_page(&s, u, "IdP fetch failed", &e),
    };
    render_page(&s, u, "Edit IdP", view::edit_form(&item))
}

#[derive(Debug, Deserialize)]
pub struct IdpFormBody {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub oidc_issuer_url: String,
    #[serde(default)]
    pub oidc_client_id: String,
    #[serde(default)]
    pub oidc_client_secret: String,
    #[serde(default)]
    pub oidc_scopes: String,
    #[serde(default)]
    pub oidc_prompt: String,
    #[serde(default)]
    pub saml_metadata_url: String,
    #[serde(default)]
    pub saml_slo_url: String,
    #[serde(default)]
    pub saml_name_id_format: String,
    #[serde(default)]
    pub saml_email_attribute: String,
    #[serde(default)]
    pub saml_groups_attribute: String,
}

pub async fn create(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Form(form): Form<IdpFormBody>,
) -> Response {
    let body = form_to_json(&form, true);
    match s.client.post_json::<Value>(api_paths::IDPS, &body).await {
        Ok(_) => Redirect::to("/idps").into_response(),
        Err(e) => err_page(&s, user.as_deref(), "Create failed", &e),
    }
}

pub async fn update(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
    Form(form): Form<IdpFormBody>,
) -> Response {
    let body = form_to_json(&form, false);
    match s
        .client
        .patch_json::<Value>(&format!("/idps/{id}"), &body)
        .await
    {
        Ok(_) => Redirect::to("/idps").into_response(),
        Err(e) => err_page(&s, user.as_deref(), "Update failed", &e),
    }
}

pub async fn delete(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    match s.client.delete(&format!("/idps/{id}")).await {
        Ok(()) => Response::new(axum::body::Body::empty()),
        Err(e) => err_page(&s, user.as_deref(), "Delete failed", &e),
    }
}

fn form_to_json(form: &IdpFormBody, creating: bool) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("name".into(), Value::String(form.name.trim().to_string()));
    out.insert("type".into(), Value::String(form.ty.clone()));

    match form.ty.as_str() {
        "oidc" => {
            let mut oidc = serde_json::Map::new();
            put_str(&mut oidc, "issuer_url", &form.oidc_issuer_url);
            put_str(&mut oidc, "client_id", &form.oidc_client_id);
            // `client_secret` is plaintext on the wire — the server
            // encrypts before storing. Empty on edit means "keep the
            // stored secret"; empty on create would make the server
            // reject the request, so send it explicitly so validation
            // messaging lands on the operator rather than serde.
            if !form.oidc_client_secret.is_empty() {
                oidc.insert(
                    "client_secret".into(),
                    Value::String(form.oidc_client_secret.clone()),
                );
            } else if creating {
                oidc.insert("client_secret".into(), Value::String(String::new()));
            }
            let scopes: Vec<Value> = form
                .oidc_scopes
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| Value::String(s.to_string()))
                .collect();
            if !scopes.is_empty() {
                oidc.insert("scopes".into(), Value::Array(scopes));
            }
            // `prompt: Option<String>` on the server. Empty form
            // clears the field — send `null` so RFC 7396 merge
            // deletes the existing value; omitting the key would
            // leave the previous value in place.
            put_str_or_null(&mut oidc, "prompt", &form.oidc_prompt);
            out.insert("oidc_config".into(), Value::Object(oidc));
            out.insert("saml_config".into(), Value::Null);
        }
        "saml" => {
            let mut saml = serde_json::Map::new();
            put_str(&mut saml, "metadata_url", &form.saml_metadata_url);
            // `slo_url` / `name_id_format` are `Option<String>` on the
            // server. Send `null` on empty (not omit) so RFC 7396
            // merge actually clears the stored value.
            put_str_or_null(&mut saml, "slo_url", &form.saml_slo_url);
            put_str_or_null(&mut saml, "name_id_format", &form.saml_name_id_format);
            // `attribute_mapping` is a flat map. We always emit both
            // keys (`email` and `groups`) — empty fields land as
            // `null` so the server's RFC 7396 merge step deletes the
            // entry. Without the explicit null, an emptied form
            // arrived as `{"email": ..., "groups": ...}` minus the
            // cleared key, which merges as a no-op and the entry
            // silently survives.
            let mut mapping = serde_json::Map::new();
            put_str_or_null(&mut mapping, "email", &form.saml_email_attribute);
            put_str_or_null(&mut mapping, "groups", &form.saml_groups_attribute);
            saml.insert("attribute_mapping".into(), Value::Object(mapping));
            out.insert("saml_config".into(), Value::Object(saml));
            out.insert("oidc_config".into(), Value::Null);
        }
        _ => {}
    }
    Value::Object(out)
}

/// Insert a string field, skipping when empty. Reserved for fields
/// the server requires (e.g. `metadata_url`, `issuer_url`,
/// `client_id`) — sending `null` on those would fail validation.
fn put_str(map: &mut serde_json::Map<String, Value>, key: &str, v: &str) {
    if !v.is_empty() {
        map.insert(key.into(), Value::String(v.to_string()));
    }
}

/// Insert a string field, sending JSON `null` when empty so RFC 7396
/// merge clears the existing value on the server. Use this for
/// fields typed `Option<String>` on the server (clearing is a valid
/// state) and for entries inside a map whose values can be cleared
/// individually.
fn put_str_or_null(map: &mut serde_json::Map<String, Value>, key: &str, v: &str) {
    if v.is_empty() {
        map.insert(key.into(), Value::Null);
    } else {
        map.insert(key.into(), Value::String(v.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tracing_subscriber::prelude::*;

    use super::*;

    #[derive(Clone)]
    struct WarningCounter(Arc<AtomicUsize>);

    impl<S> tracing_subscriber::Layer<S> for WarningCounter
    where
        S: tracing::Subscriber,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn base_form(ty: &str) -> IdpFormBody {
        IdpFormBody {
            name: "example".into(),
            ty: ty.into(),
            oidc_issuer_url: "https://issuer.example".into(),
            oidc_client_id: "client".into(),
            oidc_client_secret: String::new(),
            oidc_scopes: "openid,email".into(),
            oidc_prompt: String::new(),
            saml_metadata_url: "https://idp.example/metadata".into(),
            saml_slo_url: String::new(),
            saml_name_id_format: String::new(),
            saml_email_attribute: "mail".into(),
            saml_groups_attribute: String::new(),
        }
    }

    #[test]
    fn saml_update_keeps_full_required_shape_and_explicit_clears() {
        let body = form_to_json(&base_form("saml"), false);
        assert_eq!(
            body["saml_config"]["metadata_url"],
            "https://idp.example/metadata"
        );
        assert!(body["saml_config"]["slo_url"].is_null());
        assert!(body["saml_config"]["name_id_format"].is_null());
        assert_eq!(body["saml_config"]["attribute_mapping"]["email"], "mail");
        assert!(body["saml_config"]["attribute_mapping"]["groups"].is_null());
        assert!(body["oidc_config"].is_null());
    }

    #[test]
    fn oidc_update_omits_empty_secret_but_keeps_full_required_shape() {
        let body = form_to_json(&base_form("oidc"), false);
        let oidc = body["oidc_config"].as_object().unwrap();
        assert_eq!(oidc["issuer_url"], "https://issuer.example");
        assert_eq!(oidc["client_id"], "client");
        assert!(oidc.get("client_secret").is_none());
        assert_eq!(oidc["scopes"], serde_json::json!(["openid", "email"]));
        assert!(oidc["prompt"].is_null());
        assert!(body["saml_config"].is_null());
    }

    #[test]
    fn config_fetch_failure_keeps_idp_list_without_default_badge_and_warns() {
        let warnings = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(WarningCounter(warnings.clone()));
        let items = vec![serde_json::json!({
            "id": "idp-1",
            "name": "Primary",
            "type": "oidc"
        })];

        let rendered = tracing::subscriber::with_default(subscriber, || {
            list_with_config(&items, Err::<Value, _>("config unavailable")).into_string()
        });

        assert!(rendered.contains(">Primary</a>"));
        assert!(!rendered.contains("default-idp-badge"));
        assert_eq!(warnings.load(Ordering::Relaxed), 1);
    }
}
