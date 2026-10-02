//! API keys need a dedicated create flow because the secret is only
//! returned once at creation time — we have to show it prominently.

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use maud::html;
use serde::Deserialize;

use crate::AppState;
use crate::auth::guard::AuthenticatedUser;
use crate::views::{extract_id, render_cell};
use sekisho_api_protocol::api_paths;

use super::common::{err_page, render_page};

pub async fn list(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let u = user.as_deref();
    let items = match s.client.get_list(api_paths::API_KEYS).await {
        Ok(v) => v,
        Err(e) => return err_page(&s, u, "List failed", &e),
    };
    let body = html! {
        hgroup {
            h2 { "API keys" }
            p class="muted" { "Tokens for the Sekisho management API." }
        }
        article class="issue-form" {
            h4 { "Create" }
            form method="post" action="/api_keys" class="inline" {
                input type="text" name="name" required placeholder="e.g. terraform";
                label class="checkbox-row" {
                    input type="checkbox" name="scope_read" value="true";
                    span { "Read" }
                }
                label class="checkbox-row" {
                    input type="checkbox" name="scope_write" value="true";
                    span { "Write" }
                }
                label class="checkbox-row" {
                    input type="checkbox" name="scope_admin" value="true";
                    span { "Admin" }
                }
                button type="submit" class="primary" { "Create" }
            }
        }
        table class="resource-list striped" {
            thead { tr { th { "Name" } th { "Scopes" } th { "Prefix" } th { "Created" } th { "Last used" } th class="actions" { "Actions" } } }
            tbody {
                @for item in &items {
                    tr {
                        td { (render_cell(item, "name")) }
                        td { (render_cell(item, "scopes")) }
                        td { code class="mono" { (render_cell(item, "prefix")) } }
                        td { (render_cell(item, "created_at")) }
                        td { (render_cell(item, "last_used_at")) }
                        td class="actions" {
                            @if let Some(id) = extract_id(item) {
                                button
                                    class="destructive"
                                    hx-delete=(format!("/api_keys/{id}"))
                                    hx-confirm="Revoke this API key?"
                                    hx-target="closest tr"
                                    hx-swap="outerHTML"
                                    { "Revoke" }
                            }
                        }
                    }
                }
                @if items.is_empty() {
                    tr { td colspan="6" class="muted center" { "No API keys yet." } }
                }
            }
        }
    };
    render_page(&s, u, "API keys", body)
}

#[derive(Deserialize)]
pub struct CreateForm {
    name: String,
    #[serde(default)]
    scope_read: bool,
    #[serde(default)]
    scope_write: bool,
    #[serde(default)]
    scope_admin: bool,
}

pub async fn create(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Form(form): Form<CreateForm>,
) -> Response {
    let mut scopes = Vec::with_capacity(3);
    if form.scope_read {
        scopes.push("management:read");
    }
    if form.scope_write {
        scopes.push("management:write");
    }
    if form.scope_admin {
        scopes.push("management:admin");
    }
    if scopes.is_empty() {
        let error = anyhow::anyhow!("at least one API key scope is required");
        return err_page(&s, user.as_deref(), "Create failed", &error);
    }
    let body = serde_json::json!({ "name": form.name, "scopes": scopes });
    let result: serde_json::Value = match s.client.post_json(api_paths::API_KEYS, &body).await {
        Ok(v) => v,
        Err(e) => return err_page(&s, user.as_deref(), "Create failed", &e),
    };
    let secret = result
        .get("key")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>")
        .to_string();
    let key_id = result
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let u = user.as_deref();
    let body = html! {
        article {
            h3 { "API key created" }
            p { "This secret is shown only once. Copy it now." }
            pre class="mono" { (secret) }
            p { code class="mono" { (key_id) } }
            a href="/api_keys" role="button" { "Back" }
        }
    };
    render_page(&s, u, "API key", body)
}

pub async fn delete(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    match s.client.delete(&format!("/api_keys/{id}")).await {
        Ok(()) => Response::new(axum::body::Body::empty()),
        Err(e) => err_page(&s, user.as_deref(), "Delete failed", &e),
    }
}

#[cfg(test)]
mod tests {
    /// The three scope boxes stay a row of checkboxes and keep posting the field
    /// names the API expects — the markup and the wire format are one contract.
    #[test]
    fn scope_controls_keep_checkbox_row_and_form_wire_contract() {
        let source = include_str!("api_keys.rs");
        let form = source
            .split_once("form method=\"post\" action=\"/api_keys\" class=\"inline\"")
            .expect("API-key create form")
            .1
            .split_once("button type=\"submit\" class=\"primary\"")
            .expect("API-key create button")
            .0;
        let checkbox_row = ["class=", "\"checkbox-row\""].concat();

        assert_eq!(form.matches(&checkbox_row).count(), 3);
        for (name, label) in [
            ("scope_read", "Read"),
            ("scope_write", "Write"),
            ("scope_admin", "Admin"),
        ] {
            assert!(form.contains(&format!(
                "input type=\"checkbox\" name=\"{name}\" value=\"true\""
            )));
            assert!(form.contains(&format!("span {{ \"{label}\" }}")));
        }
    }
}
