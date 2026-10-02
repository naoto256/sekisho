//! Policy CRUD handlers. Server-side the data is just `{name, expr}`;
//! the form is a straight mapping.

use axum::{
    Extension, Form,
    extract::{Path, State},
    response::{IntoResponse, Redirect, Response},
};
use sekisho_api_protocol::api_paths;
use serde::Deserialize;
use serde_json::{Value, json};

use super::common::{err_page, render_page};
use crate::AppState;
use crate::auth::guard::AuthenticatedUser;
use crate::views::policies as view;

pub async fn list(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let u = user.as_deref();
    let items = match s.client.get_list(api_paths::POLICIES).await {
        Ok(v) => v,
        Err(e) => return err_page(&s, u, "Policy list failed", &e),
    };
    render_page(&s, u, "Policies", view::list(&items))
}

pub async fn new_form(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    render_page(&s, user.as_deref(), "Create policy", view::new_form())
}

pub async fn edit(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    let u = user.as_deref();
    let item: Value = match s.client.get_json(&format!("/policies/{id}")).await {
        Ok(v) => v,
        Err(e) => return err_page(&s, u, "Policy fetch failed", &e),
    };
    render_page(&s, u, "Edit policy", view::edit_form(&item))
}

#[derive(Debug, Deserialize)]
pub struct PolicyFormBody {
    pub name: String,
    #[serde(default)]
    pub expr: String,
}

pub async fn create(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Form(form): Form<PolicyFormBody>,
) -> Response {
    let body = form_to_json(&form);
    match s
        .client
        .post_json::<Value>(api_paths::POLICIES, &body)
        .await
    {
        Ok(_) => Redirect::to("/policies").into_response(),
        Err(e) => err_page(&s, user.as_deref(), "Create failed", &e),
    }
}

pub async fn update(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
    Form(form): Form<PolicyFormBody>,
) -> Response {
    let body = form_to_json(&form);
    match s
        .client
        .patch_json::<Value>(&format!("/policies/{id}"), &body)
        .await
    {
        Ok(_) => Redirect::to("/policies").into_response(),
        Err(e) => err_page(&s, user.as_deref(), "Update failed", &e),
    }
}

pub async fn delete(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(id): Path<String>,
) -> Response {
    match s.client.delete(&format!("/policies/{id}")).await {
        Ok(()) => Response::new(axum::body::Body::empty()),
        Err(e) => err_page(&s, user.as_deref(), "Delete failed", &e),
    }
}

fn form_to_json(form: &PolicyFormBody) -> Value {
    json!({
        "name": form.name.trim(),
        "expr": form.expr,
    })
}
