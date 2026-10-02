//! Dashboard handler. No data fetch — see [`crate::views::home`].

use axum::{Extension, extract::State, response::Response};

use crate::AppState;
use crate::auth::guard::AuthenticatedUser;

use super::common::render_page;

pub async fn index(
    State(state): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let user = user.as_ref().map(|u| &u.0);
    let body = crate::views::home::index(user);
    render_page(&state, user, "Dashboard", body)
}
