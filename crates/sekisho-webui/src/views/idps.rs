//! Identity provider views. OIDC and SAML share a list/delete flow
//! but their create/edit forms look different enough that we render
//! them as two distinct sections on the same form page.

use maud::{Markup, html};
use serde_json::Value;

use super::{extract_id, render_cell};

/// Look up a key from a SAML config's `attribute_mapping` object,
/// falling back to empty string when the whole section or the key is
/// absent. Used to prefill the dedicated email / groups inputs.
fn saml_mapping(saml: &Value, key: &str) -> String {
    saml.get("attribute_mapping")
        .and_then(|m| m.get(key))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn list(items: &[Value]) -> Markup {
    html! {
        hgroup {
            h2 { "Identity Providers" }
            p class="muted" { "The OIDC or SAML IdPs Sekisho trusts for user authentication." }
        }
        p class="toolbar" {
            a href="/idps/new" role="button" class="primary" { "Add identity provider" }
        }
        table class="resource-list striped" {
            thead { tr { th { "Name" } th { "Type" } th class="actions" { "Actions" } } }
            tbody {
                @for item in items {
                    tr {
                        td {
                            @if let Some(id) = extract_id(item) {
                                a href=(format!("/idps/{id}")) { (render_cell(item, "name")) }
                            } @else {
                                (render_cell(item, "name"))
                            }
                        }
                        td { (render_cell(item, "type")) }
                        td class="actions" {
                            @if let Some(id) = extract_id(item) {
                                button
                                    class="destructive"
                                    hx-delete=(format!("/idps/{id}"))
                                    hx-confirm="Delete this identity provider?"
                                    hx-target="closest tr"
                                    hx-swap="outerHTML"
                                    { "Delete" }
                            }
                        }
                    }
                }
                @if items.is_empty() {
                    tr { td colspan="3" class="muted center" { "No identity providers yet." } }
                }
            }
        }
    }
}

pub fn new_form() -> Markup {
    form_body(None)
}

pub fn edit_form(item: &Value) -> Markup {
    form_body(Some(item))
}

fn form_body(item: Option<&Value>) -> Markup {
    let creating = item.is_none();
    let ty = item
        .and_then(|v| v.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("oidc");
    let name = item
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let oidc = item
        .and_then(|v| v.get("oidc_config"))
        .cloned()
        .unwrap_or(Value::Null);
    let saml = item
        .and_then(|v| v.get("saml_config"))
        .cloned()
        .unwrap_or(Value::Null);
    let action = match item.and_then(extract_id) {
        Some(id) => format!("/idps/{id}"),
        None => "/idps".into(),
    };
    let o = |k: &str| -> String {
        oidc.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let oidc_scopes = oidc
        .get("scopes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| "openid, profile, email".to_string());
    let s_ = |k: &str| -> String {
        saml.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    // `attribute_mapping` is a string→string map on the server. The
    // form surfaces the two keys actually consulted in `auth::saml`
    // (email, groups). Other keys round-trip untouched through the
    // handler's `form_to_json` since we never read them here.

    html! {
        hgroup {
            h2 { @if creating { "Add identity provider" } @else { "Edit identity provider " code { (name) } } }
            p class="muted" { "Pick OIDC or SAML; only the selected variant's fields are sent." }
        }
        form method="post" action=(action) class="stack" id="idp-form" {
            label {
                "Name"
                input type="text" name="name" value=(name) required;
            }
            label {
                "Type"
                select name="type" onchange="this.form.dataset.idptype=this.value" {
                    option value="oidc" selected[ty == "oidc"] { "OIDC" }
                    option value="saml" selected[ty == "saml"] { "SAML" }
                }
            }

            fieldset {
                legend { "OIDC configuration" }
                label { "Issuer URL" input type="text" name="oidc_issuer_url" value=(o("issuer_url")) placeholder="https://accounts.example.com"; }
                label { "Client ID" input type="text" name="oidc_client_id" value=(o("client_id")); }
                label {
                    "Client secret"
                    input type="password" name="oidc_client_secret" placeholder="(unchanged)" autocomplete="new-password";
                    small class="muted" { "Leave blank to keep the existing secret. The server encrypts what you type before storing." }
                }
                label { "Scopes (comma-separated)" input type="text" name="oidc_scopes" value=(oidc_scopes); }
                label {
                    "Prompt (optional)"
                    input type="text" name="oidc_prompt" value=(o("prompt")) placeholder="e.g. login, consent";
                    small class="muted" { "Passed through to the IdP's /authorize prompt parameter. Usually left blank." }
                }
            }

            fieldset {
                legend { "SAML configuration" }
                label {
                    "IdP metadata URL"
                    input type="text" name="saml_metadata_url" value=(s_("metadata_url")) placeholder="https://idp.example.com/metadata";
                    small class="muted" { "Sekisho fetches entity ID, SSO URL, and signing cert from this endpoint. SP entity ID and ACS URL are derived from auth_domain." }
                }
                label {
                    "SP single-logout URL (optional)"
                    input type="text" name="saml_slo_url" value=(s_("slo_url"));
                }
                label {
                    "NameID format (optional)"
                    input type="text" name="saml_name_id_format" value=(s_("name_id_format")) placeholder="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
                }
                label { "Email attribute name" input type="text" name="saml_email_attribute" value=(saml_mapping(&saml, "email")); }
                label { "Groups attribute name" input type="text" name="saml_groups_attribute" value=(saml_mapping(&saml, "groups")); }
            }

            div class="toolbar" {
                button type="submit" class="primary" { @if creating { "Create" } @else { "Save" } }
                a href="/idps" role="button" class="secondary outline" { "Cancel" }
            }
        }
    }
}
