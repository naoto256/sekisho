//! OIDC callback handler — processes the IdP redirect after authentication.
//!
//! Everything arriving here is attacker-influenceable: the query string comes
//! from a browser redirect, so each parameter is checked against server-side
//! state rather than trusted.
//!
//! `state` is matched against a pending record before the authorization code
//! is exchanged — an unsolicited callback must cost nothing — and the `nonce`
//! is carried in a per-flow cookie rather than only in the ID token, so a token
//! minted for a different login attempt cannot be replayed into this one. The
//! per-flow cookie name is also what lets two concurrent logins from the same
//! browser both succeed.
//!
//! Token validation is delegated to `auth-idp`, which enforces the
//! `alg` from JWKS with no fallback. What this module adds is the decision
//! about what becomes session identity: only claims the IdP asserted
//! explicitly populate [`crate::models::session::UpstreamIdentity`], and any
//! value that had to be inferred stays in the compatibility claims map. Signed
//! identity assertions read only the strict view, so an inferred email can
//! never become something an upstream authorizes on.
//!
//! The ID token is retained, sealed, so sign-out can replay it as
//! `id_token_hint` at the IdP's RP-initiated logout endpoint — which otherwise
//! cannot tell which session to end.

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Response, StatusCode, header};
use metrics::counter;
use serde::Deserialize;

use crate::models::session::{UpstreamIdentity, UpstreamIdentityProvenance};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

pub async fn oidc_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Result<Response<Body>, StatusCode> {
    // Track idp_id as we learn it so the failure metric attributes the
    // outcome to a real IdP whenever possible. Pre-state-resolution
    // failures (CSRF state expired / DB unreachable) get bucketed under
    // 'unknown' since the request never produced an IdP context.
    let mut idp_id_for_metric: String = "unknown".to_string();
    let result = oidc_callback_inner(state, headers, params, &mut idp_id_for_metric).await;
    let outcome = if result.is_ok() { "success" } else { "failure" };
    counter!(
        "sekisho_auth_login_total",
        "idp_id" => idp_id_for_metric,
        "kind" => "oidc",
        "result" => outcome
    )
    .increment(1);
    result
}

// `idp_id` is recorded onto the current span after PendingAuth lookup
// resolves it. Any `tracing::info!(...)` events emitted from within
// auth_idp during exchange_code / id-token validation inherit this
// field via span propagation, so operator-facing logs still carry the
// IdP context even though auth_idp itself does not know about Uuid.
#[tracing::instrument(
    skip(state, headers, params, idp_id_for_metric),
    fields(idp_id = tracing::field::Empty)
)]
async fn oidc_callback_inner(
    state: AppState,
    headers: HeaderMap,
    params: CallbackParams,
    idp_id_for_metric: &mut String,
) -> Result<Response<Body>, StatusCode> {
    let auth_state = state
        .auth_state_store
        .get(&params.state)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "pending-auth lookup failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!("invalid or expired CSRF state");
            StatusCode::BAD_REQUEST
        })?;
    if auth_state.kind != crate::auth::middleware::PendingAuthKind::Login {
        tracing::warn!("OIDC callback rejected: PendingAuth kind mismatch");
        return Err(StatusCode::BAD_REQUEST);
    }
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok());
    let browser_nonce = state
        .cookie_manager
        .pre_auth_nonce(cookie_header, &params.state);
    if !crate::auth::middleware::browser_nonce_matches(
        auth_state.browser_nonce_hash.as_deref(),
        browser_nonce.as_deref(),
    ) {
        tracing::warn!("OIDC callback rejected: browser nonce mismatch");
        return Err(StatusCode::BAD_REQUEST);
    }
    tracing::Span::current().record("idp_id", tracing::field::display(&auth_state.idp_id));
    *idp_id_for_metric = auth_state.idp_id.to_string();

    let oidc_client = state
        .get_oidc_client(auth_state.idp_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to get OIDC client");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let user_info = oidc_client
        .exchange_code(&params.code, &auth_state.code_verifier, &auth_state.nonce)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "OIDC code exchange failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // The IdP response and browser nonce are both valid. Atomic take is the
    // commit point; concurrent callbacks cannot both create sessions.
    state
        .auth_state_store
        .take(&params.state)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "pending-auth consume failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!("OIDC callback rejected: PendingAuth already consumed");
            StatusCode::BAD_REQUEST
        })?;

    // Retry session creation — the user already authenticated at the IdP,
    // so losing this due to a transient DB error would force a full re-login.
    let mut session = None;
    let mut last_err = None;
    for attempt in 1..=3u64 {
        match state
            .session_manager
            .create_with_upstream_identity(
                &user_info.email,
                auth_state.idp_id,
                user_info.claims.clone(),
                user_info.groups.clone(),
                Some(UpstreamIdentity {
                    subject: user_info.subject.clone(),
                    explicit_email: user_info.explicit_email.clone(),
                    provenance: UpstreamIdentityProvenance::Oidc,
                }),
                user_info
                    .refresh_token
                    .as_ref()
                    .map(|token| token.expose_secret()),
                user_info
                    .id_token
                    .as_ref()
                    .map(|token| token.expose_secret()),
                None,
                None,
            )
            .await
        {
            Ok(s) => {
                session = Some(s);
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, attempt, "session creation failed, retrying");
                last_err = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(200 * attempt)).await;
            }
        }
    }
    let session = session.ok_or_else(|| {
        tracing::error!(error = %last_err.unwrap(), "session creation failed after 3 retries");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!(
        user = %session.user_id,
        idp = %auth_state.idp_id,
        session_id = %session.id,
        "OIDC login successful"
    );

    let clear_pre_auth = state.cookie_manager.clear_pre_auth_cookie(&params.state);
    build_post_auth_response(
        &state,
        &headers,
        session.id,
        &auth_state.redirect_url,
        &clear_pre_auth,
    )
    .await
}

/// After the IdP callback creates a session, decide whether to:
///   - set the cookie here and redirect (target host == callback host), or
///   - mint a handoff token and redirect the browser to the target host's
///     `/.sekisho/session-handoff`, which will set the cookie there.
///
/// Shared by OIDC and SAML because the post-auth logic is identical;
/// only how the session was created differs.
pub(crate) async fn build_post_auth_response(
    state: &AppState,
    headers: &HeaderMap,
    session_id: uuid::Uuid,
    redirect_url: &str,
    clear_pre_auth_cookie: &str,
) -> Result<Response<Body>, StatusCode> {
    // Run the URL through `safe_redirect` *first*, before deciding
    // same-host vs cross-host. Any URL pointing at an unregistered
    // domain is rewritten to `/` here — that prevents IdP-initiated
    // SAML flows (where RelayState is attacker-controlled) or a
    // corrupted OIDC state entry from sending the authenticated user
    // to an arbitrary host via the handoff redirect.
    let safe_url = crate::auth::safe_redirect(redirect_url, &state.store).await;

    let callback_host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();

    // After sanitization: a relative path means "redirect on this
    // host" (either the original was relative, or it was rewritten
    // to `/` because it pointed off-registry). An absolute URL means
    // `safe_redirect` confirmed its host is a registered route.
    let target_host = if safe_url.starts_with('/') {
        None
    } else {
        url::Url::parse(&safe_url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
    };

    let same_host = target_host
        .as_deref()
        .map(|h| h.eq_ignore_ascii_case(&callback_host))
        .unwrap_or(true);

    if same_host {
        // Auth-domain cookie has no associated route (it's the
        // proxy's own callback path). Use the conservative
        // SameSite=Lax default. Per-route SameSite overrides apply
        // only at the session-handoff step on each app's host.
        let cookie_value = state.cookie_manager.create_cookie(
            session_id,
            crate::session::cookie_manager::DEFAULT_SAME_SITE,
        );
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::SET_COOKIE, cookie_value)
            .header(header::SET_COOKIE, clear_pre_auth_cookie)
            .header(header::LOCATION, safe_url)
            // `no-referrer` on auth redirects keeps any ?code=/?state=
            // query parameters from leaking to downstream pages.
            .header("Referrer-Policy", "no-referrer")
            .body(Body::empty())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Cross-host: cookies are host-only, so we cannot set a cookie for
    // the target host from here. Bounce the browser through the
    // target's `/.sekisho/session-handoff` with an encrypted, single-
    // use token that lets it mint its own cookie. `safe_url` is known
    // to point at a registered route by this point.
    match state
        .handoff_cipher
        .build_redirect_url(session_id, &safe_url)
    {
        Ok((target, handoff_url)) => {
            tracing::info!(
                session_id = %session_id,
                target_host = %target,
                "redirecting to session-handoff on target host"
            );
            Response::builder()
                .status(StatusCode::FOUND)
                .header(header::SET_COOKIE, clear_pre_auth_cookie)
                .header(header::LOCATION, handoff_url)
                // Prevent the handoff URL (with its short-lived token
                // in the query string) from reaching downstream pages
                // or third-party trackers via Referer.
                .header("Referrer-Policy", "no-referrer")
                .body(Body::empty())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to build handoff URL");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::middleware::{PendingAuth, PendingAuthKind};
    use crate::models::idp::{IdentityProvider, IdpType, OidcConfig};
    use crate::store::Store;
    use crate::tls::acme::AcmeManager;
    use crate::tls::acme::challenge::Http01Provider;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    #[tokio::test]
    async fn oidc_browser_nonce_mismatch_precedes_protocol_and_preserves_state() {
        let store = Store::new_for_test("sqlite::memory:", [0x42; 32], None)
            .await
            .unwrap();
        let idp_id = Uuid::new_v4();
        let client_secret_encrypted = store
            .encrypt_active_to_base64(b"client-secret")
            .await
            .unwrap();
        store
            .create_idp(&IdentityProvider {
                id: idp_id,
                name: "oidc".into(),
                idp_type: IdpType::Oidc,
                oidc_config: Some(OidcConfig {
                    issuer_url: "http://127.0.0.1:9".into(),
                    client_id: "client".into(),
                    client_secret_encrypted,
                    scopes: vec!["openid".into()],
                    prompt: None,
                }),
                saml_config: None,
            })
            .await
            .unwrap();
        let state_token = "oidc-state";
        store
            .pending_auth_insert(
                state_token,
                &PendingAuth {
                    idp_id,
                    nonce: "oidc-nonce".into(),
                    code_verifier: "verifier".into(),
                    redirect_url: "/after".into(),
                    created_at: chrono::Utc::now(),
                    saml_authn_request_id: None,
                    kind: PendingAuthKind::Login,
                    browser_nonce_hash: Some(crate::auth::middleware::browser_nonce_hash(
                        "correct-browser-nonce",
                    )),
                },
            )
            .await
            .unwrap();
        let challenge = Arc::new(Http01Provider::new(store.clone()));
        let acme_manager = Arc::new(AcmeManager::new(
            store.clone(),
            challenge,
            "https://acme.invalid/directory",
            None,
        ));
        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;
        let router = crate::proxy::router(
            store.clone(),
            route_generation,
            &[0x24; 32],
            acme_manager,
            crate::crypto::MasterKey::from_test_bytes([0x42; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([0x81; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.test",
            )),
            true,
            "sekisho_session".into(),
            100,
            Arc::new(crate::shutdown::ShutdownController::new()),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/.sekisho/callback?code=unused&state=oidc-state")
                    .header(header::HOST, "auth.example.test")
                    .header(
                        header::COOKIE,
                        "__Secure-sekisho_pre_oidc-state=wrong-browser-nonce",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(store.pending_auth_get(state_token).await.unwrap().is_some());
    }
}
