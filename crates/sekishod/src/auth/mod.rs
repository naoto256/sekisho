//! Authentication: protocol entry points, sign-out, and the redirect guard.
//!
//! Protocol specifics live in [`oidc`] and [`saml`], behind the [`strategy`]
//! dispatch; [`middleware`] is the per-request session check and [`handoff`]
//! carries a session across hosts. What stays here is the part both protocols
//! share.
//!
//! ## Sign-out is two independent steps
//!
//! Revoking the local session and telling the IdP are separate, because only
//! the first is under this daemon's control. The local session is destroyed
//! and the cookie cleared regardless of what the IdP does; the redirect to a
//! protocol logout endpoint is attempted only when the session's IdP supports
//! one. A caller can also arrive at `/signed-out` directly — from an IdP
//! redirect, or a bookmark — so that handler assumes no prior revocation and
//! clears the cookie again rather than trusting that something upstream did.
//!
//! ## `safe_redirect` is an allowlist, not a sanitizer
//!
//! Post-login return URLs are attacker-supplied. The rule is "relative path,
//! or an HTTPS URL whose host is one this daemon actually fronts" — anything
//! else collapses to `/`. Deciding against the live route table rather than a
//! configured pattern means the allowlist cannot drift from what is deployed,
//! and `//` is rejected explicitly because a protocol-relative URL reads as a
//! path and resolves as an absolute one.

pub mod handoff;
pub mod middleware;
pub mod oidc;
pub mod saml;
pub mod strategy;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode, header};
use metrics::counter;

use crate::state::AppState;

/// Count a logout by kind. Separate counters for local-only versus
/// protocol logout is the distinction that matters in an incident: it says
/// whether sessions are actually being torn down at the IdP or only here.
fn record_logout(kind: &'static str) {
    counter!("sekisho_auth_logout_total", "kind" => kind).increment(1);
}

#[allow(unused_imports)]
pub use auth_idp::http::limited_response;

/// Validate and sanitize a redirect URL. Only allows:
/// - Relative paths (starting with "/" but not "//")
/// - Absolute https URLs whose hostname matches a registered route's `from` domain
pub async fn safe_redirect(url: &str, store: &crate::store::Store) -> String {
    if url.starts_with('/') && !url.starts_with("//") {
        return url.to_string();
    }

    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => {
            tracing::warn!(url = %url, "rejected unparseable redirect URL");
            return "/".to_string();
        }
    };

    if parsed.scheme() != "https" {
        tracing::warn!(url = %url, "rejected non-https redirect URL");
        return "/".to_string();
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        tracing::warn!(url = %url, "rejected redirect URL with credentials");
        return "/".to_string();
    }

    let redirect_host = match parsed.host_str() {
        Some(h) => h,
        None => {
            tracing::warn!(url = %url, "rejected redirect URL with no host");
            return "/".to_string();
        }
    };

    let allowed = match store.list_routes().await {
        Ok(routes) => routes.iter().any(|r| {
            url::Url::parse(&r.from)
                .ok()
                .and_then(|u| u.host_str().map(|h| h == redirect_host))
                .unwrap_or(false)
        }),
        Err(_) => false,
    };

    if allowed {
        url.to_string()
    } else {
        tracing::warn!(url = %url, host = %redirect_host, "rejected redirect to unregistered domain");
        "/".to_string()
    }
}

/// Terminal HTML used by `sign_out` when the strategy did not
/// return an IdP logout URL, and by the `/signed-out` landing
/// handler.
pub(crate) const SIGNED_OUT_BODY: &str = r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Signed out</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font-family:system-ui,-apple-system,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#222;line-height:1.5}h1{font-size:1.5rem;margin-bottom:.5rem}p{color:#555}</style></head><body><h1>Signed out</h1><p>Your Sekisho session has been ended. Close this tab, or navigate to a protected resource to sign in again.</p></body></html>"#;

/// Return the `Host` header value split at the first `:`. This value is
/// diagnostic only: protocol URLs are derived from the immutable boot-time
/// identity authority and never from request headers.
fn request_host(req: &axum::http::Request<Body>) -> Option<String> {
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .filter(|h| !h.is_empty())
}

/// Handle sign-out.
///
/// If a session cookie is present and resolves to a session,
/// revocation of the server-side session is attempted. The session
/// cookie is cleared unconditionally. What happens next depends on
/// whether the per-strategy `build_logout_url` returns a URL:
///
/// * Strategy returns `Some(url)` (OIDC IdP with
///   `end_session_endpoint`, or SAML IdP whose metadata advertises
///   SLO) → 302 the browser to that URL for IdP-side logout.
/// * Strategy returns `None` (no session, OIDC IdP without
///   `end_session_endpoint`, SAML metadata without SLO, session
///   lookup failure, etc.) → serve the terminal signed-out HTML
///   directly.
///
/// A terminal page (not a 302 back into a protected route) is used
/// because the common reason to sign out is "access denied by
/// policy" — a redirect home would loop back through the IdP and
/// re-deny.
pub async fn sign_out(
    State(state): State<AppState>,
    req: axum::http::Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let cookie_header = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());
    let host_for_log = request_host(&req).unwrap_or_else(|| "<none>".into());
    let had_cookie = cookie_header.is_some();

    let clear_cookie = state.cookie_manager.clear_cookie();

    // Snapshot the session *before* revoking — we need its idp_id and
    // id_token_encrypted to build the IdP logout URL after revocation succeeds.
    let session = match state.cookie_manager.get_session_id(cookie_header) {
        Some(sid) => match state.session_manager.validate(sid).await {
            Ok(session) => Some(session),
            Err(crate::error::Error::NotFound) => None,
            Err(_) => {
                tracing::warn!(
                    target: crate::audit::TARGET,
                    event = "auth.logout.session_lookup_failed",
                    category = "auth",
                    result = "failure",
                    reason = "session_store_unavailable",
                    "session lookup failed during sign-out"
                );
                record_logout("session_lookup_failed");
                return terminal_signed_out_response(
                    &clear_cookie,
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            }
        },
        None => None,
    };

    tracing::info!(
        host = %host_for_log,
        had_cookie,
        session_found = session.is_some(),
        "sign_out handler invoked"
    );

    if let Some(ref s) = session
        && state.session_manager.revoke(s.id).await.is_err()
    {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.logout.revoke_failed",
            category = "auth",
            result = "failure",
            actor_type = "user",
            actor_id = %s.user_id,
            target_resource = "session",
            target_id = %s.id,
            reason = "session_revoke_failed",
            "session revocation failed during sign-out"
        );
        record_logout("revoke_failed");
        return terminal_signed_out_response(&clear_cookie, StatusCode::SERVICE_UNAVAILABLE);
    }

    // Try to build an IdP-side logout redirect. Any failure along
    // this path (IdP not found or missing endpoint)
    // falls through to the local-only terminal page — we never want
    // a sign-out click to error on the user's face.
    if let Some(ref s) = session {
        match build_idp_logout_url(&state, s).await {
            Some(url) => {
                tracing::info!(
                    target: crate::audit::TARGET,
                    event = "auth.logout.idp_redirect",
                    category = "auth",
                    result = "success",
                    actor_type = "user",
                    actor_id = %s.user_id,
                    target_resource = "session",
                    target_id = %s.id,
                    idp_id = %s.idp_id,
                    "redirecting to IdP logout endpoint"
                );
                record_logout("idp_redirect");
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header(header::SET_COOKIE, clear_cookie)
                    .header(header::LOCATION, url)
                    .header("cache-control", "no-store")
                    // Keep id_token_hint / SAMLRequest off any downstream
                    // Referer — both can identify the user.
                    .header("Referrer-Policy", "no-referrer")
                    .body(Body::empty())
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
            }
            None => {
                tracing::info!(
                    target: crate::audit::TARGET,
                    event = "auth.logout.local_only",
                    category = "auth",
                    result = "success",
                    actor_type = "user",
                    actor_id = %s.user_id,
                    target_resource = "session",
                    target_id = %s.id,
                    idp_id = %s.idp_id,
                    reason = "no_idp_logout_url",
                    "IdP-side logout URL not available; falling back to local terminal"
                );
            }
        }
    }

    record_logout("local_only");
    terminal_signed_out_response(&clear_cookie, StatusCode::OK)
}

/// Landing handler served at `/.sekisho/signed-out`. Returns the
/// terminal signed-out HTML and issues a delete-cookie header. The
/// landing may be reached with or without a preceding `/sign-out`
/// flow (e.g. IdP redirect, direct navigation, bookmark), so this
/// handler does not assume any prior revocation or cookie clearing.
pub async fn signed_out(State(state): State<AppState>) -> Result<Response<Body>, StatusCode> {
    terminal_signed_out_response(&state.cookie_manager.clear_cookie(), StatusCode::OK)
}

/// Build the terminal signed-out page.
///
/// Always carries the cookie-clearing header and `cache-control: no-store`.
/// The status is a parameter because the page is served both as a normal
/// ending and as the degraded outcome when protocol logout could not be
/// reached — the body is the same, and duplicating it per caller is how the
/// two drift apart.
pub(crate) fn terminal_signed_out_response(
    clear_cookie: &str,
    status: StatusCode,
) -> Result<Response<Body>, StatusCode> {
    Response::builder()
        .status(status)
        .header(header::SET_COOKIE, clear_cookie)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from(SIGNED_OUT_BODY))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Returns `Some(logout_url)` when the session's IdP supports a
/// protocol-level logout (OIDC RP-Initiated Logout or SAML
/// SP-initiated SLO), `None` otherwise so the caller falls back to
/// the local-only terminal page.
///
/// The per-strategy synthesis lives in `auth::strategy`; this
/// function is just the IdP-lookup wrapper around
/// `Strategy::build_logout_url`.
async fn build_idp_logout_url(
    state: &AppState,
    session: &crate::models::session::Session,
) -> Option<String> {
    let idp = state.store.get_idp(session.idp_id).await.ok()?;
    crate::auth::strategy::Strategy::for_idp_type(idp.idp_type)
        .build_logout_url(state, session)
        .await
}

/// Return current session info
pub async fn userinfo(
    State(state): State<AppState>,
    req: axum::http::Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let cookie_header = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());

    let session_id = state
        .cookie_manager
        .get_session_id(cookie_header)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let session = state
        .session_manager
        .validate(session_id)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Explicit `.timestamp()` casts: `json!` would otherwise route the
    // DateTime fields through their default Serialize impl (RFC 3339)
    // and bypass the `#[serde(with = "ts_seconds")]` annotation on
    // `Session`. The rest of the API ships integer epoch.
    let body = serde_json::json!({
        "id": session.id,
        "user_id": session.user_id,
        "idp_id": session.idp_id,
        "claims": session.claims,
        "groups": session.groups,
        "created_at": session.created_at.timestamp(),
        "expires_at": session.expires_at.timestamp(),
        "last_accessed_at": session.last_accessed_at.timestamp(),
    });
    let body = serde_json::to_string(&body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_proxy(store: crate::store::Store) -> axum::Router {
        use std::sync::Arc;

        let challenge = Arc::new(crate::tls::acme::challenge::Http01Provider::new(
            store.clone(),
        ));
        let acme_manager = Arc::new(crate::tls::acme::AcmeManager::new(
            store.clone(),
            challenge,
            "https://acme.invalid/directory",
            None,
        ));
        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;
        crate::proxy::router(
            store,
            route_generation,
            &[0x24; 32],
            acme_manager,
            crate::crypto::MasterKey::from_test_bytes([0x42; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([0x81; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            100,
            Arc::new(crate::shutdown::ShutdownController::new()),
        )
    }

    async fn assert_terminal_response(response: Response<Body>, status: StatusCode) {
        assert_eq!(response.status(), status);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        assert!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("Max-Age=0"))
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        assert_eq!(body.as_ref(), SIGNED_OUT_BODY.as_bytes());
    }

    #[test]
    fn request_host_strips_port() {
        let req = axum::http::Request::builder()
            .header(header::HOST, "proxy-a.example.com:8443")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_host(&req).as_deref(), Some("proxy-a.example.com"));
    }

    #[test]
    fn request_host_absent_returns_none() {
        let req = axum::http::Request::builder().body(Body::empty()).unwrap();
        assert!(request_host(&req).is_none());
    }

    #[test]
    fn terminal_signed_out_response_clears_cookie_and_is_no_store() {
        let resp = terminal_signed_out_response("clear=; Max-Age=0", StatusCode::OK).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "no-store",
            "terminal page must not be cached — a back/forward hit would otherwise render 'Signed out' for a user who then re-signed in on another tab"
        );
        assert!(
            resp.headers()
                .get(header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0"),
            "terminal response must reassert the cookie-clear so the /.sekisho/signed-out landing is idempotent"
        );
    }

    #[tokio::test]
    async fn sign_out_session_lookup_failure_is_terminal_503() {
        use crate::session::cookie_manager::{CookieManager, DEFAULT_SAME_SITE};
        use crate::store::Store;
        use tower::ServiceExt;

        let store = Store::new_for_test_degraded("session lookup unavailable")
            .await
            .expect("degraded store");
        let app = test_proxy(store).await;
        let cookie = CookieManager::new(&[0x24; 32])
            .with_name("sekisho_session".into())
            .create_cookie(uuid::Uuid::new_v4(), DEFAULT_SAME_SITE);
        let cookie = cookie.split(';').next().expect("cookie name-value pair");

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.sekisho/sign-out")
                    .header(header::HOST, "hostile.example")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .expect("sign-out request"),
            )
            .await
            .expect("sign-out response");

        assert_terminal_response(response, StatusCode::SERVICE_UNAVAILABLE).await;
    }

    #[tokio::test]
    async fn sign_out_invalid_cookie_is_terminal_200_without_store_access() {
        use crate::store::Store;
        use tower::ServiceExt;

        let store = Store::new_for_test_degraded("must not be read")
            .await
            .expect("degraded store");
        let response = test_proxy(store)
            .await
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.sekisho/sign-out")
                    .header(header::HOST, "hostile.example")
                    .header(header::COOKIE, "sekisho_session=invalid")
                    .body(Body::empty())
                    .expect("sign-out request"),
            )
            .await
            .expect("sign-out response");

        assert_terminal_response(response, StatusCode::OK).await;
    }

    #[tokio::test]
    async fn sign_out_missing_session_is_terminal_200() {
        use crate::session::cookie_manager::{CookieManager, DEFAULT_SAME_SITE};
        use crate::store::Store;
        use tower::ServiceExt;

        let store = Store::new_for_test("sqlite::memory:", [0x42; 32], None)
            .await
            .expect("store");
        let cookie = CookieManager::new(&[0x24; 32])
            .with_name("sekisho_session".into())
            .create_cookie(uuid::Uuid::new_v4(), DEFAULT_SAME_SITE);
        let cookie = cookie.split(';').next().expect("cookie name-value pair");
        let response = test_proxy(store)
            .await
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.sekisho/sign-out")
                    .header(header::HOST, "hostile.example")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .expect("sign-out request"),
            )
            .await
            .expect("sign-out response");

        assert_terminal_response(response, StatusCode::OK).await;
    }

    // Session-level integration tests for the decrypt path. The
    // full sign_out handler is exercised manually against Entra;
    // unit tests cover the observable seams (end_session_url,
    // decrypt_id_token).
    #[tokio::test]
    async fn decrypt_id_token_roundtrips_via_session_manager() {
        use crate::session::manager::SessionManager;
        use crate::store::Store;

        let store = Store::new_for_test("sqlite::memory:", [0x42u8; 32], None)
            .await
            .unwrap();
        // Need a real IdP row so the session FK is satisfied.
        let idp = crate::models::idp::IdentityProvider {
            id: uuid::Uuid::new_v4(),
            name: "test-idp".into(),
            idp_type: crate::models::idp::IdpType::Oidc,
            oidc_config: Some(crate::models::idp::OidcConfig {
                issuer_url: "https://issuer.test/".into(),
                client_id: "cid".into(),
                client_secret_encrypted: store.encrypt_active_to_base64(b"plain").await.unwrap(),
                scopes: vec!["openid".into()],
                prompt: None,
            }),
            saml_config: None,
        };
        store.create_idp(&idp).await.unwrap();

        let mgr = SessionManager::new(store.clone(), 8);
        let session = mgr
            .create(
                "u@x.com",
                idp.id,
                Default::default(),
                vec![],
                None,
                Some("header.payload.sig"),
                None,
                None,
            )
            .await
            .unwrap();
        let recovered = mgr.decrypt_id_token(&session).await;
        assert_eq!(recovered.as_deref(), Some("header.payload.sig"));
    }

    #[tokio::test]
    async fn decrypt_id_token_returns_none_when_ciphertext_uses_wrong_key() {
        // Key rotation / corruption must not panic the sign-out path.
        let store = crate::store::Store::new_for_test("sqlite::memory:", [0x44u8; 32], None)
            .await
            .unwrap();
        let mgr = crate::session::manager::SessionManager::new(store.clone(), 8);
        // A v3 blob from an unrelated DEK ring — its key_id 0 will resolve
        // in this Store's ring but the AEAD tag will mismatch, exactly
        // matching the operator-facing "rotated to a different DEK" case.
        let other = crate::store::Store::new_for_test("sqlite::memory:", [0xAAu8; 32], None)
            .await
            .unwrap();
        let bogus = other.encrypt_active_to_base64(b"whatever").await.unwrap();
        let session = crate::models::session::Session {
            id: uuid::Uuid::new_v4(),
            user_id: "u".into(),
            idp_id: uuid::Uuid::new_v4(),
            upstream_identity: None,
            claims: Default::default(),
            groups: vec![],
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            refresh_token_encrypted: None,
            id_token_encrypted: Some(bogus),
            saml_name_id: None,
            saml_session_index: None,
            last_accessed_at: chrono::Utc::now(),
        };
        assert!(mgr.decrypt_id_token(&session).await.is_none());
    }
}
