//! Bundled assets. Shipped in-binary via `include_bytes!` so sekisho-webui has
//! no runtime dependency on a public CDN — a compromised CDN would
//! otherwise have free JS execution on the admin UI.
//!
//! Everything the browser loads (Pico, htmx, our CSS, our JS glue) is served
//! from `/_assets/…` under the same origin. That lets the CSP stay a strict
//! `script-src 'self'; style-src 'self'` with no nonce plumbing.

use std::sync::OnceLock;

use axum::{
    Router,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

use crate::AppState;

const PICO_CSS: &[u8] = include_bytes!("../assets/vendor/pico.min.css");
const HTMX_JS: &[u8] = include_bytes!("../assets/vendor/htmx.min.js");
const SEKISHO_WEBUI_CSS: &[u8] = include_bytes!("../assets/sekisho-webui.css");
const SEKISHO_WEBUI_JS: &[u8] = include_bytes!("../assets/sekisho-webui.js");
const LOGO_SVG: &[u8] = include_bytes!("../assets/logo.svg");
const WORDMARK_SVG: &[u8] = include_bytes!("../assets/wordmark.svg");

/// Cache-busting version derived from the contents of every bundled
/// asset. Computed once on first access and threaded into every asset
/// URL via `?v=<hash>`. Without this, the aggressive
/// `Cache-Control: immutable` below would pin a browser to a stale
/// CSS / JS bundle across upgrades — a CSS fix wouldn't reach an
/// already-loaded admin tab even after a redeploy.
fn asset_version() -> &'static str {
    static V: OnceLock<String> = OnceLock::new();
    V.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(PICO_CSS);
        h.update(HTMX_JS);
        h.update(SEKISHO_WEBUI_CSS);
        h.update(SEKISHO_WEBUI_JS);
        h.update(LOGO_SVG);
        h.update(WORDMARK_SVG);
        // 8 hex chars = 32 bits; plenty for cache-bust uniqueness.
        hex::encode(&h.finalize()[..4])
    })
    .as_str()
}

/// Append `?v=<asset_version>` to a base path. Pure helper so the
/// layout `link` / `script` calls stay declarative.
fn versioned(base: &str) -> String {
    format!("{base}?v={}", asset_version())
}

const PICO_BASE: &str = "/_assets/vendor/pico.min.css";
const HTMX_BASE: &str = "/_assets/vendor/htmx.min.js";
const SEKISHO_WEBUI_CSS_BASE: &str = "/_assets/sekisho-webui.css";
const SEKISHO_WEBUI_JS_BASE: &str = "/_assets/sekisho-webui.js";
const LOGO_BASE: &str = "/_assets/logo.svg";
const WORDMARK_BASE: &str = "/_assets/wordmark.svg";

// One accessor per asset rather than a generic `asset_path(name)`: the layout
// then references assets by symbol, so a renamed or removed file is a compile
// error instead of a 404 discovered in a browser.
pub fn pico_path() -> String {
    versioned(PICO_BASE)
}
pub fn htmx_path() -> String {
    versioned(HTMX_BASE)
}
pub fn sekisho_webui_css_path() -> String {
    versioned(SEKISHO_WEBUI_CSS_BASE)
}
pub fn sekisho_webui_js_path() -> String {
    versioned(SEKISHO_WEBUI_JS_BASE)
}
pub fn logo_path() -> String {
    versioned(LOGO_BASE)
}
pub fn wordmark_path() -> String {
    versioned(WORDMARK_BASE)
}

/// Routes for the two asset families. Vendor and app assets are separate
/// prefixes with separate handlers so each serves only from its own fixed
/// match list — the path segment is never used to index a filesystem, which is
/// what makes traversal impossible here rather than merely guarded against.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/_assets/vendor/{file}", get(vendor))
        .route("/_assets/{file}", get(app))
}

async fn vendor(Path(file): Path<String>) -> Response {
    match file.as_str() {
        "pico.min.css" => serve(PICO_CSS, "text/css; charset=utf-8"),
        "htmx.min.js" => serve(HTMX_JS, "application/javascript; charset=utf-8"),
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn app(Path(file): Path<String>) -> Response {
    match file.as_str() {
        "sekisho-webui.css" => serve(SEKISHO_WEBUI_CSS, "text/css; charset=utf-8"),
        "sekisho-webui.js" => serve(SEKISHO_WEBUI_JS, "application/javascript; charset=utf-8"),
        "logo.svg" => serve(LOGO_SVG, "image/svg+xml"),
        "wordmark.svg" => serve(WORDMARK_SVG, "image/svg+xml"),
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn serve(bytes: &'static [u8], content_type: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            // Bundled assets are versioned by the binary, so they can be
            // cached aggressively. A new sekisho-webui build naturally changes
            // the binary (and any deploy that pins a version will re-roll
            // the upstream path or header anyway).
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        bytes,
    )
        .into_response()
}
