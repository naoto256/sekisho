//! Cross-site request forgery protection — stateless double-submit cookie.
//!
//! When sekisho-webui is fronted by Basic auth, browsers attach the
//! `Authorization` header automatically — a third-party page can submit a
//! cross-origin form and the admin's credentials ride along. To block that,
//! every state-changing request must carry a matching `X-CSRF-Token`
//! header that matches the value of an opaque `_sekisho_csrf` cookie the
//! browser already holds. The token is rendered into
//! `<meta name="csrf-token">` from the cookie value so an HTMX hook can
//! copy it into every mutating request.
//!
//! ## Why double-submit cookie (and not a server-stored token)
//!
//! sekisho-webui runs across HA peers behind a load balancer and gets
//! restarted on every deploy. A token that lives in `AppState` would:
//!
//! 1. Differ across HA peers — a page rendered by one peer with token-A
//!    would 403 if the load balancer sent the next click to another peer
//!    (which only knows token-B).
//! 2. Rotate on every restart — every redeploy would invalidate the
//!    meta tag in any tab the operator already had open, surfacing as
//!    "the Revoke button silently does nothing".
//!
//! Persisting the token to `/var/lib/sekisho-webui/csrf.token` fixes (2)
//! but not (1). The right answer is no server-side state at all: the
//! cookie *is* the token. All peers see the same browser cookie, and
//! no peer needs to remember anything across restarts. RFC 6265 cookie
//! semantics handle replication, expiry, and recovery for free.
//!
//! Attackers on a foreign origin cannot read the cookie (HttpOnly +
//! same-origin policy on JS) and cannot guess 256 bits of random, so
//! the equality check is sufficient without session binding.
//!
//! ## Token propagation to handlers
//!
//! The cookie value is mirrored into a `tokio::task_local` that
//! `render_page` reads when it stamps the `<meta>` tag. Handlers
//! themselves don't see the token — the layout grabs it implicitly so
//! we don't have to touch every handler signature.

use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::Next,
    response::Response,
};
use base64::Engine;
use rand::RngCore;

/// CSRF cookie name. The leading underscore is a "host-only" hint;
/// browsers don't enforce anything off it but the convention pairs
/// with `_sekisho_session` and reads as "internal cookie".
pub const COOKIE_NAME: &str = "_sekisho_csrf";

tokio::task_local! {
    /// The current request's CSRF token (= the value of the
    /// `_sekisho_csrf` cookie, or freshly generated if the request
    /// arrived without one). The middleware sets the scope; the
    /// layout reads it when rendering `<meta name="csrf-token">`.
    pub static CSRF_TOKEN: String;
}

/// 256-bit random token, base64url-encoded. 43 chars without padding.
pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// One middleware that handles **both** sides of double-submit:
///
/// * On a safe (GET / HEAD / OPTIONS / TRACE) request, take the
///   incoming `_sekisho_csrf` cookie if present and well-formed,
///   otherwise mint a new value. Either way, scope the value into
///   `CSRF_TOKEN` so the page render emits a meta tag with it, and
///   issue (or refresh) the cookie via `Set-Cookie` on the response.
/// * On a mutating request, require the cookie *and* the
///   `X-CSRF-Token` header to be present and equal. Reject with 403
///   on any failure mode (no cookie, no header, mismatch).
///
/// Combining the two halves keeps the cookie value a single source
/// of truth — by the time a mutating request reaches a handler, we
/// already proved its `X-CSRF-Token` matches the cookie, and the
/// same value is in `CSRF_TOKEN` if anything downstream wants it.
pub async fn middleware(request: Request, next: Next) -> Response {
    let cookie_token = read_csrf_cookie(&request);
    let mutating = !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    );

    if mutating {
        let header_token = request
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let cookie_v = cookie_token.as_deref().unwrap_or_default();
        // Empty values must always reject — constant_time_eq("", "")
        // would return true otherwise (zero-length matches zero-length).
        if cookie_v.is_empty()
            || header_token.is_empty()
            || !constant_time_eq(cookie_v.as_bytes(), header_token.as_bytes())
        {
            tracing::warn!(
                method = %request.method(),
                path = %request.uri().path(),
                cookie_present = !cookie_v.is_empty(),
                header_present = !header_token.is_empty(),
                "CSRF cookie/header missing or mismatched; rejecting mutating request"
            );
            let mut resp = Response::new(Body::from("CSRF token missing or invalid"));
            *resp.status_mut() = StatusCode::FORBIDDEN;
            return resp;
        }
        // The cookie is the source of truth; we don't need to set it
        // again on a mutating response (the browser already has it,
        // and re-sending would just thrash the cache).
        let token = cookie_v.to_string();
        return CSRF_TOKEN.scope(token, next.run(request)).await;
    }

    // Safe method: keep existing cookie or mint a new one. Always
    // (re-)set the Set-Cookie header so a fresh navigation seeds it
    // and a continued navigation keeps it alive (cookies without
    // Max-Age are session cookies — which is fine; the next browser
    // restart can mint a new one).
    let token = cookie_token.unwrap_or_else(new_token);
    let token_for_cookie = token.clone();
    let mut response = CSRF_TOKEN.scope(token, next.run(request)).await;
    let cookie_value =
        format!("{COOKIE_NAME}={token_for_cookie}; Path=/; Secure; HttpOnly; SameSite=Lax");
    if let Ok(v) = cookie_value.parse() {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
    response
}

/// Pull the `_sekisho_csrf` cookie value out of an incoming request.
/// Tolerates the standard `name=value; name=value` Cookie header form.
fn read_csrf_cookie(request: &Request) -> Option<String> {
    let raw = request
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=')
            && name.trim().eq_ignore_ascii_case(COOKIE_NAME)
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn tokens_are_unique_and_well_formed() {
        let a = new_token();
        let b = new_token();
        assert_ne!(a, b);
        assert!(a.len() >= 40); // 32 bytes base64url no pad = 43 chars
    }

    #[test]
    fn constant_time_eq_matches_only_identical_bytes() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"hellx"));
        assert!(!constant_time_eq(b"hello", b"hello!"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn read_csrf_cookie_extracts_named_value() {
        let mut req = Request::new(Body::empty());
        req.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("foo=1; _sekisho_csrf=abc123; bar=2"),
        );
        assert_eq!(read_csrf_cookie(&req), Some("abc123".into()));
    }

    #[test]
    fn read_csrf_cookie_returns_none_when_absent() {
        let mut req = Request::new(Body::empty());
        req.headers_mut()
            .insert(header::COOKIE, HeaderValue::from_static("foo=1; bar=2"));
        assert_eq!(read_csrf_cookie(&req), None);
    }

    #[test]
    fn read_csrf_cookie_returns_none_for_empty_value() {
        // Defensive: an explicit empty value (browsers shouldn't send
        // this, but a stray client could) must not be treated as a
        // valid token.
        let mut req = Request::new(Body::empty());
        req.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("_sekisho_csrf=; foo=bar"),
        );
        assert_eq!(read_csrf_cookie(&req), None);
    }
}
