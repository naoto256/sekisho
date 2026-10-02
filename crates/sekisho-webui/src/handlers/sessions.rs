//! Read-only session list plus revocation. Sessions don't fit the generic
//! CRUD shape because they are created by Sekisho's auth flows, not by the
//! admin UI.

use axum::{
    Extension,
    extract::{Path, State},
    response::Response,
};
use maud::html;

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
    let items = match s.client.get_list(api_paths::SESSIONS).await {
        Ok(v) => v,
        Err(e) => return err_page(&s, u, "Session list failed", &e),
    };
    let body = html! {
        hgroup {
            h2 { "Sessions" }
            p class="muted" { (items.len()) " active end-user session(s)." }
        }
        table class="resource-list striped" {
            thead {
                tr { th { "ID" } th { "User" } th { "IdP" } th { "Expires" } th class="actions" { "Actions" } }
            }
            tbody {
                @for item in &items {
                    tr {
                        td { code class="mono" { (render_cell(item, "id")) } }
                        td { (render_cell(item, "user_id")) }
                        td { code class="mono" { (render_cell(item, "idp_id")) } }
                        td { (render_cell(item, "expires_at")) }
                        td class="actions" {
                            @if let Some(id) = extract_id(item) {
                                button
                                    class="destructive"
                                    hx-delete=(format!("/sessions/{id}"))
                                    hx-confirm="Revoke this session?"
                                    hx-target="closest tr"
                                    hx-swap="outerHTML"
                                    { "Revoke" }
                            }
                        }
                    }
                }
                @if items.is_empty() {
                    tr { td colspan="5" class="muted center" { "No active sessions." } }
                }
            }
        }
    };
    render_page(&s, u, "Sessions", body)
}

pub async fn delete(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    match s.client.delete(&format!("/sessions/{id}")).await {
        Ok(()) => Response::new(axum::body::Body::empty()),
        Err(e) => err_page(&s, user.as_deref(), "Revoke failed", &e),
    }
}
