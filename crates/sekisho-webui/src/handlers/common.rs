//! Shared helpers used by several handler modules: HTML rendering and
//! canonical error / not-found pages.

use axum::response::Response;
use maud::{Markup, html};

use crate::AppState;
use crate::auth::guard::AuthenticatedUser;
use crate::views::Page;

/// Wrap a Maud `Markup` value in an axum HTML response.
pub fn render_html(m: Markup) -> Response {
    use axum::response::IntoResponse;
    axum::response::Html(m.into_string()).into_response()
}

/// Render a full page, wiring the CSRF token so HTMX requests from this
/// page carry the right header.
///
/// The server-version snapshot is read from `AppState` and passed through so
/// the layout's nav badge reflects the startup handshake outcome. Read-locking
/// once per render is cheap; the state is fixed after startup today.
pub fn render_page(
    state: &AppState,
    user: Option<&AuthenticatedUser>,
    title: &str,
    body: Markup,
) -> Response {
    // `std::sync::RwLock`'s read guard never yields, so calling it from an
    // async handler is fine. If another thread ever poisons the lock, retain
    // the compatibility verdict established before the listener was bound.
    let version = state
        .server_version
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    // The CSRF token comes from the per-request task_local set by
    // `csrf::middleware`, *not* from `AppState`. The middleware wrote
    // the cookie value (or a freshly generated one) into the
    // task_local on the way in, so the meta tag we stamp here will
    // match what the browser will send back as `X-CSRF-Token` on the
    // next mutating click. Falling back to an empty string when no
    // scope is present (e.g. an isolated unit test) renders a meta
    // tag with empty content; the layout's `@if let Some(t)` then
    // skips it, which is correct — no scope means no request, which
    // means no CSRF context to protect.
    let csrf = crate::csrf::CSRF_TOKEN
        .try_with(|t| t.clone())
        .unwrap_or_default();
    let page = Page::new(title)
        .with_user(user)
        .with_csrf(&csrf)
        .with_server_version(&version);
    render_html(page.render(body))
}

/// Like `render_page`, but without the nav bar — used by the pre-credential
/// setup screen.
pub fn render_setup_page(_state: &AppState, title: &str, body: Markup) -> Response {
    let csrf = crate::csrf::CSRF_TOKEN
        .try_with(|t| t.clone())
        .unwrap_or_default();
    let page = Page::new(title).hide_nav().with_csrf(&csrf);
    render_html(page.render(body))
}

/// Render an error page. The full error chain (which can include upstream
/// URLs, HTTP status codes, and raw response bodies) is logged server-side;
/// the user only sees a generic message plus a short correlation ID so an
/// operator can grep the logs. This avoids leaking internals of the Sekisho
/// management API into the browser (and into any screenshot that ends up in
/// a ticket or chat).
pub fn err_page(
    state: &AppState,
    user: Option<&AuthenticatedUser>,
    title: &str,
    e: &anyhow::Error,
) -> Response {
    let correlation_id = new_correlation_id();
    tracing::error!(
        correlation_id = %correlation_id,
        title,
        error = ?e,
        "handler failed",
    );
    let body = html! {
        article {
            h3 { (title) }
            p { "Something went wrong. Check the server log for details." }
            p { small { "Correlation ID: " code { (correlation_id) } } }
            p { a href="/" { "Back home" } }
        }
    };
    render_page(state, user, title, body)
}

fn new_correlation_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 8];
    rand::rng().fill_bytes(&mut buf);
    hex_encode(&buf)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// 404 response in the same chrome as the rest of the UI. Wired as
/// the router's fallback so an unknown path lands on a page that
/// still has the nav bar rather than axum's bare "Not Found" default.
pub fn not_found(state: &AppState, user: Option<&AuthenticatedUser>) -> Response {
    let body = html! {
        article {
            h3 { "Unknown resource" }
            p { a href="/" { "Back home" } }
        }
    };
    let mut resp = render_page(state, user, "Not found", body);
    *resp.status_mut() = axum::http::StatusCode::NOT_FOUND;
    resp
}
