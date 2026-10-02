//! Certificate list and ACME issuance form. Server exposes:
//!   - `GET /certs` — list
//!   - `POST /certs {domain}` — durable ACME queue admission
//!   - `DELETE /certs/{id}`
//!
//! sekisho-webui uses all three; issuance is polled through the durable queue.

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::{IntoResponse, Redirect, Response},
};
use maud::html;
use sekisho_api_protocol::api_paths;
use serde::Deserialize;
use serde_json::{Value, json};

use super::common::{err_page, render_page};
use crate::AppState;
use crate::auth::guard::AuthenticatedUser;
use crate::views::{extract_id, render_cell};

pub async fn list(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let u = user.as_deref();
    let items = match s.client.get_list(api_paths::CERTS).await {
        Ok(v) => v,
        Err(e) => return err_page(&s, u, "Cert list failed", &e),
    };
    let acme_state = s
        .client
        .get_json::<Value>(api_paths::ACME_LEADER_ELECTION)
        .await
        .ok();
    let body = html! {
        hgroup {
            h2 { "Certificates" }
            p class="muted" { "TLS certificates minted by ACME or uploaded out-of-band." }
        }
        (acme_state_section(acme_state.as_ref()))
        article class="issue-form" {
            h4 { "Upload a custom certificate" }
            p class="muted" {
                "Paste a PEM-encoded certificate and its matching private "
                "key. For routes whose " code { "tls_downstream" } " is "
                code { "custom" } " — Sekisho will not renew these; you own "
                "the lifecycle."
            }
            form method="post" action="/certificates/upload" class="stack" {
                label {
                    "Domain"
                    input type="text" name="domain" required placeholder="app.example.com";
                }
                label {
                    "Certificate (PEM)"
                    textarea name="cert_pem" rows="5" required placeholder="-----BEGIN CERTIFICATE-----..." {}
                }
                label {
                    "Private key (PEM)"
                    textarea name="key_pem" rows="5" required placeholder="-----BEGIN PRIVATE KEY-----..." {}
                }
                div class="toolbar" {
                    button type="submit" class="primary" { "Upload" }
                }
            }
        }
        table class="resource-list striped" {
            thead {
                tr {
                    th { "Domain" }
                    th { "Source" }
                    th { "Issued" }
                    th { "Expires" }
                    th class="actions" { "Actions" }
                }
            }
            tbody {
                @for item in &items {
                    tr {
                        td { code { (render_cell(item, "domain")) } }
                        td { (render_cell(item, "source")) }
                        td { (render_cell(item, "issued_at")) }
                        td { (render_cell(item, "expires_at")) }
                        td class="actions" {
                            @if let Some(id) = extract_id(item) {
                                button
                                    class="destructive"
                                    hx-delete=(format!("/certificates/{id}"))
                                    hx-confirm="Delete this certificate?"
                                    hx-target="closest tr"
                                    hx-swap="outerHTML"
                                    { "Delete" }
                            }
                        }
                    }
                }
                @if items.is_empty() {
                    tr { td colspan="5" class="muted center" { "No certificates yet." } }
                }
            }
        }
    };
    render_page(&s, u, "Certificates", body)
}

#[derive(Deserialize)]
pub struct UploadBody {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
}

impl std::fmt::Debug for UploadBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadBody")
            .field("domain", &self.domain)
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

pub async fn upload(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Form(form): Form<UploadBody>,
) -> Response {
    let body = json!({
        "domain": form.domain.trim(),
        "cert_pem": form.cert_pem,
        "key_pem": form.key_pem,
    });
    match s
        .client
        .post_json::<Value>(api_paths::CERTS_UPLOAD, &body)
        .await
    {
        Ok(_) => Redirect::to("/certificates").into_response(),
        Err(e) => err_page(&s, user.as_deref(), "Certificate upload failed", &e),
    }
}

pub async fn delete(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    match s.client.delete(&format!("/certs/{id}")).await {
        Ok(()) => Response::new(axum::body::Body::empty()),
        Err(e) => err_page(&s, user.as_deref(), "Delete failed", &e),
    }
}

/// Render the "ACME leader election" status panel. Surfaces who
/// currently owns issuance across the cluster, when their heartbeat
/// last refreshed, whether *this* node thinks it's leader, and how
/// the elected state compares to any operator-pinned `acme_leader`.
/// Empty fields render as `—` so a freshly-migrated single-node DB
/// (no election row yet) is still legible rather than cryptic.
fn acme_state_section(state: Option<&Value>) -> maud::Markup {
    let Some(s) = state else {
        return html! {
            article class="issue-form" {
                h4 { "ACME leader election" }
                p class="muted" { "Election state unavailable (server unreachable or endpoint missing)." }
            }
        };
    };
    let str_or_dash = |k: &str| -> String {
        s.get(k)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("—")
            .to_string()
    };
    let i_am_leader = s
        .get("i_am_leader")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let pinned = s
        .get("pinned_acme_leader")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let my = str_or_dash("my_node_id");
    let leader = str_or_dash("current_leader_node_id");
    let updated = str_or_dash("current_leader_updated_at");
    let pin_disagrees = !pinned.is_empty() && pinned != leader;
    html! {
        article class="issue-form" {
            h4 { "ACME leader election" }
            p class="muted" {
                "Which Sekisho instance currently owns ACME renewals. In single-node mode this is just "
                code { "this node" } "; in HA the leader rotates on heartbeat staleness or operator pin."
            }
            dl class="meta" {
                dt { "This node" } dd { code { (my) } }
                dt { "Current leader" } dd {
                    code { (leader) }
                    @if i_am_leader {
                        " " span class="pill enabled" { "this node" }
                    }
                }
                dt { "Leader heartbeat" } dd { (updated) }
                dt { "Pinned (config.acme_leader)" } dd {
                    @if pinned.is_empty() {
                        span class="muted" { "(automatic election)" }
                    } @else {
                        code { (pinned) }
                        @if pin_disagrees {
                            " " span class="pill disabled" {
                                "election hasn't converged yet"
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UploadBody;

    const SECRET_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
        stable-private-key-prefix-0123456789\n\
        c2VjcmV0LWJhc2U2NC1ib2R5LWZyYWdtZW50\n\
        -----END PRIVATE KEY-----";
    const SECRET_PREFIX: &str = "stable-private-key-prefix";
    const SECRET_MARKER: &str = "BEGIN PRIVATE KEY";
    const SECRET_BODY: &str = "c2VjcmV0LWJhc2U2NC1ib2R5LWZyYWdtZW50";

    #[test]
    fn upload_body_debug_redacts_real_and_empty_keys_identically() {
        let real = UploadBody {
            domain: "app.example.com".to_string(),
            cert_pem: "safe-certificate-pem".to_string(),
            key_pem: SECRET_KEY.to_string(),
        };
        let empty = UploadBody {
            domain: "app.example.com".to_string(),
            cert_pem: "safe-certificate-pem".to_string(),
            key_pem: String::new(),
        };

        let real_debug = format!("{real:?}");
        let empty_debug = format!("{empty:?}");

        assert!(
            real_debug == empty_debug,
            "redacted Debug output differs for equivalent safe fields"
        );
        assert!(
            real_debug.contains("UploadBody")
                && real_debug.contains("domain")
                && real_debug.contains("app.example.com")
                && real_debug.contains("cert_pem")
                && real_debug.contains("safe-certificate-pem")
                && real_debug.contains("key_pem")
                && real_debug.contains("<redacted>"),
            "redacted Debug output omits expected safe fields"
        );
        assert!(
            !real_debug.contains(SECRET_KEY)
                && !real_debug.contains(SECRET_PREFIX)
                && !real_debug.contains(SECRET_MARKER)
                && !real_debug.contains(SECRET_BODY),
            "redacted Debug output exposes private-key material"
        );
    }
}
