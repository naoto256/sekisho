//! Security-header middleware. Adds the standard defence-in-depth set
//! (CSP, HSTS, nosniff, frame-ancestors via X-Frame-Options, Referrer-Policy,
//! Permissions-Policy) to every response.
//!
//! The CSP is strict: `script-src 'self'` with no `'unsafe-inline'`,
//! `'unsafe-eval'`, or `'nonce-…'`. This is only viable because the page
//! layout has no inline scripts or styles — everything goes through
//! `/_assets/…`. See `layout.rs` and `assets.rs`.

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};

const CSP: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self'; \
     img-src 'self' data:; \
     font-src 'self'; \
     connect-src 'self'; \
     frame-ancestors 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     object-src 'none'";

const STATIC_HEADERS: &[(&str, &str)] = &[
    ("content-security-policy", CSP),
    (
        "strict-transport-security",
        "max-age=63072000; includeSubDomains",
    ),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    // Deny every modern sink the admin UI has no business using. Covers
    // media / sensors / device APIs / identity features plus the
    // current privacy-budget proposals so sekisho-webui doesn't quietly
    // gain access when a browser ships a new default-allow permission.
    (
        "permissions-policy",
        "accelerometer=(), autoplay=(), bluetooth=(), browsing-topics=(), \
         camera=(), display-capture=(), encrypted-media=(), fullscreen=(), \
         geolocation=(), gyroscope=(), hid=(), idle-detection=(), \
         interest-cohort=(), magnetometer=(), microphone=(), midi=(), \
         payment=(), picture-in-picture=(), publickey-credentials-get=(), \
         screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()",
    ),
];

pub async fn middleware(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    for (name, value) in STATIC_HEADERS {
        if let Ok(v) = HeaderValue::from_str(value) {
            headers.insert(axum::http::HeaderName::from_static(name), v);
        }
    }
    resp
}
