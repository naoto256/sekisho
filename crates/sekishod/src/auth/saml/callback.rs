//! SAML ACS (Assertion Consumer Service), SLO callback, and SP metadata handlers.
//!
//! The endpoints an IdP posts back to. Signature verification and
//! canonicalization live in the `auth-idp` crate; what happens here is
//! everything around it — deciding whether an assertion may be turned into a
//! session, and what that session remembers.
//!
//! ## An assertion is only accepted in the context that asked for it
//!
//! The ACS handler does not treat a validly signed assertion as sufficient. It
//! must also correspond to a flow this daemon started: `RelayState` has to
//! resolve to a pending request, and the matching per-flow nonce cookie has to
//! be present in the browser. The pending record is then *consumed* rather
//! than read, so a captured POST replayed a second time finds nothing to match
//! and is refused. Accepting on signature alone is what makes an
//! IdP-initiated or replayed assertion work, and the extra cost here is one
//! lookup.
//!
//! `RelayState` deliberately carries nothing but that opaque lookup key. It is
//! attacker-controllable and echoed back through the IdP, so putting a return
//! URL in it would be handing an open redirect to anyone who can craft a
//! login link.
//!
//! ## SP identity is derived, never configured
//!
//! Entity ID and ACS URL come from `auth_domain` at request time rather than
//! from stored fields. Operators previously set them by hand and they drifted
//! from the endpoint actually listening, producing signature-audience failures
//! that looked like IdP faults. Deriving them means the metadata document this
//! module serves and the URL the IdP posts to cannot disagree.
//!
//! ## Logout state is captured at login because it cannot be reconstructed
//!
//! `NameID` and `SessionIndex` are stored on the session at ACS time. SLO
//! needs both to build a `LogoutRequest` the IdP will accept — Entra rejects
//! one without `SessionIndex` outright — and neither value is recoverable
//! afterwards. A session that missed them degrades to local-only sign-out.
//!
//! Both SLO bindings (Redirect and POST) are registered on one URL because
//! IdPs differ in which they choose and the spec permits either.

use axum::Form;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Response, StatusCode, header};
use base64::Engine;
use metrics::counter;
use serde::Deserialize;

use crate::auth::oidc::callback::build_post_auth_response;
use crate::models::session::{UpstreamIdentity, UpstreamIdentityProvenance};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SamlAcsParams {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

const RELAY_STATE_DECODED_LEN: usize = 32;
const RELAY_STATE_ENCODED_LEN: usize = 43;

/// Accept only the canonical unpadded base64url encoding of a 32-byte
/// opaque PendingAuth key. Keeping RelayState to the random lookup key
/// makes the stored row the authority for the IdP, redirect, request ID,
/// and flow kind while staying below SAML HTTP-Redirect's 80-byte limit.
fn validate_relay_state(raw: &str) -> Option<&str> {
    if raw.len() != RELAY_STATE_ENCODED_LEN {
        return None;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .ok()?;
    if bytes.len() != RELAY_STATE_DECODED_LEN
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != raw
    {
        return None;
    }
    Some(raw)
}

pub async fn saml_acs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(params): Form<SamlAcsParams>,
) -> Result<Response<Body>, StatusCode> {
    let mut idp_id_for_metric: String = "unknown".to_string();
    let result = saml_acs_inner(state, headers, params, &mut idp_id_for_metric).await;
    let outcome = if result.is_ok() { "success" } else { "failure" };
    counter!(
        "sekisho_auth_login_total",
        "idp_id" => idp_id_for_metric,
        "kind" => "saml",
        "result" => outcome
    )
    .increment(1);
    result
}

#[tracing::instrument(
    skip(state, headers, params, idp_id_for_metric),
    fields(idp_id = tracing::field::Empty)
)]
async fn saml_acs_inner(
    state: AppState,
    headers: HeaderMap,
    params: SamlAcsParams,
    idp_id_for_metric: &mut String,
) -> Result<Response<Body>, StatusCode> {
    // SP-initiated flow: RelayState is only the opaque PendingAuth lookup
    // key. The stored row supplies every protocol field after the lookup.
    // We refuse requests without a canonical token — IdP-initiated flow is
    // not supported because it sidesteps `InResponseTo` and CSRF-binding.
    let relay_state = params
        .relay_state
        .as_deref()
        .and_then(validate_relay_state)
        .ok_or_else(|| {
            tracing::warn!("SAML ACS rejected: RelayState missing or invalid");
            StatusCode::BAD_REQUEST
        })?;

    // Read without consuming so malformed or mismatched responses cannot
    // invalidate the browser's still-live authentication attempt.
    let pending = state
        .auth_state_store
        .get(relay_state)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "pending-auth lookup failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!("SAML ACS rejected: no PendingAuth for RelayState (expired or forged)");
            StatusCode::BAD_REQUEST
        })?;

    tracing::Span::current().record("idp_id", tracing::field::display(&pending.idp_id));
    *idp_id_for_metric = pending.idp_id.to_string();

    if pending.kind != crate::auth::middleware::PendingAuthKind::Login {
        tracing::warn!(
            idp_id = %pending.idp_id,
            "SAML ACS rejected: PendingAuth kind mismatch (expected Login)"
        );
        return Err(StatusCode::BAD_REQUEST);
    }
    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok());
    let browser_nonce = state
        .cookie_manager
        .pre_auth_nonce(cookie_header, relay_state);
    if !crate::auth::middleware::browser_nonce_matches(
        pending.browser_nonce_hash.as_deref(),
        browser_nonce.as_deref(),
    ) {
        tracing::warn!(
            idp_id = %pending.idp_id,
            "SAML ACS rejected: browser nonce mismatch"
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let Some(expected_request_id) = pending.saml_authn_request_id.as_deref() else {
        tracing::warn!(
            idp_id = %pending.idp_id,
            "SAML ACS rejected: PendingAuth has no AuthnRequest ID"
        );
        return Err(StatusCode::BAD_REQUEST);
    };

    let idp = state.store.get_idp(pending.idp_id).await.map_err(|e| {
        tracing::warn!(error = %e, idp_id = %pending.idp_id, "SAML ACS rejected: IdP not found");
        StatusCode::BAD_REQUEST
    })?;
    if idp.idp_type != crate::models::idp::IdpType::Saml {
        tracing::warn!(
            idp_id = %pending.idp_id,
            idp_type = ?idp.idp_type,
            "SAML ACS rejected: IdP is not of SAML type"
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let saml_client = state.get_saml_client(pending.idp_id).await.map_err(|e| {
        tracing::error!(error = %e, idp_id = %pending.idp_id, "failed to create SAML client");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let user_info = saml_client
        .process_response(&params.saml_response, Some(expected_request_id))
        .map_err(|e| {
            tracing::warn!(error = %e, idp_id = %pending.idp_id, "SAML response processing failed");
            StatusCode::BAD_REQUEST
        })?;

    // Validation is complete. The atomic take is the commit point: only one
    // concurrent valid callback may proceed to create a session.
    state
        .auth_state_store
        .take(relay_state)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, idp_id = %pending.idp_id, "pending-auth consume failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!(
                idp_id = %pending.idp_id,
                "SAML ACS rejected: PendingAuth already consumed"
            );
            StatusCode::BAD_REQUEST
        })?;

    let session = state
        .session_manager
        .create_with_upstream_identity(
            &user_info.email,
            pending.idp_id,
            user_info.claims,
            user_info.groups,
            Some(UpstreamIdentity {
                subject: user_info.name_id.clone(),
                explicit_email: user_info.explicit_email,
                provenance: UpstreamIdentityProvenance::Saml,
            }),
            None,
            None,
            Some(user_info.name_id.clone()),
            user_info.session_index.clone(),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to create session");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!(
        user = %session.user_id,
        idp = %pending.idp_id,
        session_id = %session.id,
        "SAML login successful"
    );

    let clear_pre_auth = state.cookie_manager.clear_pre_auth_cookie(relay_state);
    build_post_auth_response(
        &state,
        &headers,
        session.id,
        &pending.redirect_url,
        &clear_pre_auth,
    )
    .await
}

pub async fn saml_metadata(State(state): State<AppState>) -> Result<Response<Body>, StatusCode> {
    let idps = state
        .store
        .list_idps()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let saml_idp = idps
        .iter()
        .find(|idp| idp.idp_type == crate::models::idp::IdpType::Saml)
        .ok_or(StatusCode::NOT_FOUND)?;

    let saml_client = state.get_saml_client(saml_idp.id).await.map_err(|e| {
        tracing::error!(error = %e, "failed to create SAML client");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let metadata = saml_client.sp_metadata();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(metadata))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Query parameters for the HTTP-Redirect binding at `/saml/slo`.
/// Both `SAMLResponse` (our normal case — IdP replying to our SP-initiated
/// LogoutRequest) and `SAMLRequest` (IdP-initiated logout) are
/// defined here, but only the former is accepted right now.
#[derive(Deserialize)]
pub struct SamlSloQuery {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: Option<String>,
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// Form body for the HTTP-POST binding.
#[derive(Deserialize)]
pub struct SamlSloForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: Option<String>,
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// SAML SLO endpoint — HTTP-Redirect binding (GET).
/// Handles the IdP's LogoutResponse to our SP-initiated LogoutRequest.
///
/// The raw query string is threaded through via [`axum::extract::RawQuery`]
/// because auth-idp v0.2.0's `verify_redirect_binding_signature` needs
/// the exact octets the IdP signed — re-serializing the parsed
/// parameters would perturb the signature input.
pub async fn saml_slo_redirect(
    State(state): State<AppState>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
    Query(params): Query<SamlSloQuery>,
) -> Result<Response<Body>, StatusCode> {
    let raw_query = raw_query.unwrap_or_default();
    handle_saml_slo(
        &state,
        params.saml_response.as_deref(),
        params.saml_request.as_deref(),
        params.relay_state.as_deref(),
        SloBinding::Redirect(raw_query),
    )
    .await
}

/// SAML SLO endpoint — HTTP-POST binding.
pub async fn saml_slo_post(
    State(state): State<AppState>,
    Form(params): Form<SamlSloForm>,
) -> Result<Response<Body>, StatusCode> {
    handle_saml_slo(
        &state,
        params.saml_response.as_deref(),
        params.saml_request.as_deref(),
        params.relay_state.as_deref(),
        SloBinding::Post,
    )
    .await
}

/// Internal marker for which SAML binding delivered the SLO callback.
/// The `Redirect` variant carries the raw query string so
/// [`auth_idp::saml::SamlClient::process_logout_response`]'s auth-idp v0.2.0 API can
/// verify the detached signature against the exact bytes the IdP signed.
///
/// `Debug` deliberately redacts the raw query — the query carries the
/// user's opaque `SAMLResponse` blob and could hit tracing output via
/// `#[tracing::instrument]`.
enum SloBinding {
    Post,
    Redirect(String),
}

impl std::fmt::Debug for SloBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Post => f.write_str("SloBinding::Post"),
            Self::Redirect(_) => f.write_str("SloBinding::Redirect(<redacted>)"),
        }
    }
}

impl SloBinding {
    fn is_redirect(&self) -> bool {
        matches!(self, Self::Redirect(_))
    }

    fn as_auth_idp(&self) -> auth_idp::saml::LogoutResponseBinding<'_> {
        match self {
            Self::Post => auth_idp::saml::LogoutResponseBinding::Post,
            Self::Redirect(q) => auth_idp::saml::LogoutResponseBinding::Redirect { raw_query: q },
        }
    }
}

/// Common SLO callback body. A preceding `/sign-out` attempts local
/// revocation and clears the session cookie; this callback does not
/// guarantee that either step succeeded. Serves the terminal
/// signed-out HTML on every exit — whatever the IdP replies here is
/// informational. Anomalies (missing or invalid RelayState, wrong kind,
/// signature failure, unmatched PendingAuth, and storage failures) are logged
/// safely to the audit stream but do not turn this user-facing callback into a
/// redirect or an error page.
#[tracing::instrument(
    skip(state, saml_response, saml_request, relay_state),
    fields(idp_id = tracing::field::Empty)
)]
async fn handle_saml_slo(
    state: &AppState,
    saml_response: Option<&str>,
    saml_request: Option<&str>,
    relay_state: Option<&str>,
    binding: SloBinding,
) -> Result<Response<Body>, StatusCode> {
    counter!("sekisho_auth_logout_total", "kind" => "saml_slo").increment(1);
    // IdP-initiated logout is out of scope — we refuse incoming
    // SAMLRequests explicitly so an attacker can't flip a user's
    // session closed by calling our SLO URL directly.
    if saml_request.is_some() {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.logout.saml_slo_request_refused",
            category = "auth",
            result = "failure",
            reason = "idp_initiated_slo_not_supported",
            "SAML SLO refused: IdP-initiated LogoutRequest not supported"
        );
        return terminal_response_from_state(state);
    }

    let Some(saml_response) = saml_response else {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.logout.saml_slo_missing_response",
            category = "auth",
            result = "failure",
            "SAML SLO call with neither SAMLResponse nor SAMLRequest"
        );
        return terminal_response_from_state(state);
    };

    let Some(relay_state) = relay_state.and_then(validate_relay_state) else {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.logout.saml_slo_invalid_relay_state",
            category = "auth",
            result = "failure",
            reason = "missing_or_invalid_relay_state",
            "SAML SLO rejected: RelayState missing or invalid"
        );
        return terminal_response_from_state(state);
    };

    // Read without consuming. Every validation below is side-effect free;
    // the atomic take after validation decides the single successful caller.
    let pending = match state.auth_state_store.get(relay_state).await {
        Ok(pending) => pending,
        Err(_) => {
            tracing::warn!(
                target: crate::audit::TARGET,
                event = "auth.logout.saml_slo_state_lookup_failed",
                category = "auth",
                result = "failure",
                reason = "pending_auth_unavailable",
                "SAML SLO pending-auth lookup failed"
            );
            return terminal_response_from_state(state);
        }
    };

    let Some(pending) = pending else {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.logout.saml_slo_no_pending",
            category = "auth",
            result = "failure",
            reason = "no_pending_auth",
            "SAML SLO: no PendingAuth for RelayState (expired or forged)"
        );
        return terminal_response_from_state(state);
    };
    tracing::Span::current().record("idp_id", tracing::field::display(&pending.idp_id));

    if pending.kind != crate::auth::middleware::PendingAuthKind::SamlLogout {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.logout.saml_slo_wrong_kind",
            category = "auth",
            result = "failure",
            idp_id = %pending.idp_id,
            "SAML SLO: PendingAuth kind mismatch (expected SamlLogout)"
        );
        return terminal_response_from_state(state);
    }

    let Some(expected_request_id) = pending.saml_authn_request_id else {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.logout.saml_slo_no_request_id",
            category = "auth",
            result = "failure",
            idp_id = %pending.idp_id,
            "SAML SLO: PendingAuth has no LogoutRequest ID"
        );
        return terminal_response_from_state(state);
    };

    let saml_client = match state.get_saml_client(pending.idp_id).await {
        Ok(c) => c,
        Err(_) => {
            tracing::warn!(
                target: crate::audit::TARGET,
                event = "auth.logout.saml_slo_client_unavailable",
                category = "auth",
                result = "failure",
                idp_id = %pending.idp_id,
                reason = "saml_client_unavailable",
                "SAML SLO client creation failed"
            );
            return terminal_response_from_state(state);
        }
    };

    if saml_client
        .process_logout_response(saml_response, &expected_request_id, binding.as_auth_idp())
        .is_err()
    {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.logout.saml_slo_response_invalid",
            category = "auth",
            result = "failure",
            idp_id = %pending.idp_id,
            reason = "invalid_logout_response",
            "SAML LogoutResponse rejected; serving terminal page anyway"
        );
        return terminal_response_from_state(state);
    }

    let consumed = match state.auth_state_store.take(relay_state).await {
        Ok(consumed) => consumed,
        Err(_) => {
            tracing::warn!(
                target: crate::audit::TARGET,
                event = "auth.logout.saml_slo_state_consume_failed",
                category = "auth",
                result = "failure",
                idp_id = %pending.idp_id,
                reason = "pending_auth_unavailable",
                "SAML SLO pending-auth consume failed"
            );
            return terminal_response_from_state(state);
        }
    };
    if consumed.is_none() {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "auth.logout.saml_slo_no_pending",
            category = "auth",
            result = "failure",
            idp_id = %pending.idp_id,
            reason = "already_consumed",
            "SAML SLO: PendingAuth already consumed"
        );
        return terminal_response_from_state(state);
    }

    tracing::info!(
        target: crate::audit::TARGET,
        event = "auth.logout.saml_slo_success",
        category = "auth",
        result = "success",
        idp_id = %pending.idp_id,
        binding = if binding.is_redirect() { "redirect" } else { "post" },
        "SAML LogoutResponse accepted"
    );

    terminal_response_from_state(state)
}

fn terminal_response_from_state(state: &AppState) -> Result<Response<Body>, StatusCode> {
    crate::auth::terminal_signed_out_response(&state.cookie_manager.clear_cookie(), StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::middleware::{PendingAuth, PendingAuthKind};
    use crate::models::idp::{IdentityProvider, IdpType, SamlConfig};
    use crate::models::route::Route;
    use crate::session::cookie_manager::{CookieManager, DEFAULT_SAME_SITE};
    use crate::session::manager::SessionManager;
    use crate::store::Store;
    use crate::tls::acme::AcmeManager;
    use crate::tls::acme::challenge::Http01Provider;
    use axum::Router;
    use axum::http::Request;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use ring::rand::SystemRandom;
    use ring::signature::RsaKeyPair;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;
    use uuid::Uuid;

    const TEST_KEY_PKCS8_DER: &[u8] =
        include_bytes!("../../../../../vendor/auth-idp/src/saml/testdata/saml_test.p8.der");
    const TEST_CERT_DER: &[u8] =
        include_bytes!("../../../../../vendor/auth-idp/src/saml/testdata/saml_test.crt.der");
    const AUTH_DOMAIN: &str = "sp.example.com";
    const ACS_URL: &str = "https://sp.example.com/.sekisho/saml/acs";
    const SLO_URL: &str = "https://sp.example.com/.sekisho/saml/slo";
    const IDP_ENTITY_ID: &str = "https://idp.example.com";
    const TEST_BROWSER_NONCE: &str = "test-browser-nonce";

    struct TestSamlApp {
        store: Store,
        router: Router,
        idp_id: Uuid,
        metadata_task: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestSamlApp {
        fn drop(&mut self) {
            self.metadata_task.abort();
        }
    }

    impl TestSamlApp {
        async fn new() -> Self {
            Self::new_with_slo(true).await
        }

        async fn new_without_slo() -> Self {
            Self::new_with_slo(false).await
        }

        async fn new_with_slo(has_slo: bool) -> Self {
            let cert_b64 = STANDARD.encode(TEST_CERT_DER);
            let slo_service = has_slo.then(|| {
                format!(
                    r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{IDP_ENTITY_ID}/slo"/>"#
                )
            });
            let metadata = format!(
                r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY_ID}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{IDP_ENTITY_ID}/sso"/>
    {}
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
                slo_service.as_deref().unwrap_or_default()
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind metadata server");
            let metadata_url = format!(
                "http://{}/metadata",
                listener.local_addr().expect("metadata address")
            );
            let metadata_task = tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        break;
                    };
                    let metadata = metadata.clone();
                    tokio::spawn(async move {
                        let mut request = [0_u8; 2048];
                        let _ = socket.read(&mut request).await;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/samlmetadata+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            metadata.len(),
                            metadata
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    });
                }
            });

            let store = Store::new_for_test("sqlite::memory:", [0x42; 32], None)
                .await
                .expect("test store");
            store
                .update_config(serde_json::json!({ "auth_domain": AUTH_DOMAIN }))
                .await
                .expect("configure auth domain");
            let idp_id = Uuid::new_v4();
            store
                .create_idp(&IdentityProvider {
                    id: idp_id,
                    name: "test-saml".into(),
                    idp_type: IdpType::Saml,
                    oidc_config: None,
                    saml_config: Some(SamlConfig {
                        metadata_url,
                        slo_url: None,
                        name_id_format: None,
                        attribute_mapping: HashMap::new(),
                    }),
                })
                .await
                .expect("create SAML IdP");
            let route: Route = serde_json::from_value(serde_json::json!({
                "id": Uuid::new_v4(),
                "name": "protected",
                "from": format!("https://{AUTH_DOMAIN}"),
                "to": ["http://127.0.0.1:9"],
                "idp_id": idp_id,
                "enabled": true
            }))
            .expect("build protected route");
            store.create_route(&route).await.expect("create route");

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
                Arc::new(crate::identity::IdentityAuthority::for_test(AUTH_DOMAIN)),
                true,
                "sekisho_session".into(),
                100,
                Arc::new(crate::shutdown::ShutdownController::new()),
            );

            Self {
                store,
                router,
                idp_id,
                metadata_task,
            }
        }

        async fn session_cookie(&self) -> String {
            let session = SessionManager::new(self.store.clone(), 8)
                .create(
                    "alice@example.com",
                    self.idp_id,
                    HashMap::new(),
                    Vec::new(),
                    None,
                    None,
                    Some("alice@example.com".into()),
                    Some("_session".into()),
                )
                .await
                .expect("create SAML session");
            CookieManager::new(&[0x24; 32])
                .with_name("sekisho_session".into())
                .create_cookie(session.id, DEFAULT_SAME_SITE)
                .split(';')
                .next()
                .expect("created cookie has a name-value pair")
                .to_string()
        }

        async fn insert_pending(
            &self,
            label: &str,
            idp_id: Uuid,
            kind: PendingAuthKind,
            request_id: Option<&str>,
        ) {
            self.insert_pending_at(label, idp_id, kind, request_id, Utc::now())
                .await;
        }

        async fn insert_pending_at(
            &self,
            label: &str,
            idp_id: Uuid,
            kind: PendingAuthKind,
            request_id: Option<&str>,
            created_at: chrono::DateTime<Utc>,
        ) {
            let relay_state = relay(label);
            self.insert_pending_raw(&relay_state, idp_id, kind, request_id, created_at)
                .await;
        }

        async fn insert_pending_raw(
            &self,
            relay_state: &str,
            idp_id: Uuid,
            kind: PendingAuthKind,
            request_id: Option<&str>,
            created_at: chrono::DateTime<Utc>,
        ) {
            self.store
                .pending_auth_insert(
                    relay_state,
                    &PendingAuth {
                        idp_id,
                        nonce: String::new(),
                        code_verifier: String::new(),
                        redirect_url: "/after-login".into(),
                        created_at,
                        saml_authn_request_id: request_id.map(str::to_owned),
                        kind,
                        browser_nonce_hash: (kind == PendingAuthKind::Login).then(|| {
                            crate::auth::middleware::browser_nonce_hash(TEST_BROWSER_NONCE)
                        }),
                    },
                )
                .await
                .expect("insert pending auth");
        }

        async fn assert_pending(&self, label: &str) {
            let relay_state = relay(label);
            self.assert_pending_raw(&relay_state).await;
        }

        async fn assert_pending_raw(&self, relay_state: &str) {
            assert!(
                self.store
                    .pending_auth_get(relay_state)
                    .await
                    .expect("get pending auth")
                    .is_some(),
                "validation failure consumed PendingAuth"
            );
        }
    }

    fn relay(label: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(label.as_bytes()))
    }

    fn invalid_alphabet_relay_state() -> String {
        format!("{}!", "A".repeat(RELAY_STATE_ENCODED_LEN - 1))
    }

    fn assert_opaque_relay_state(relay_state: &str) {
        assert_eq!(
            relay_state.len(),
            RELAY_STATE_ENCODED_LEN,
            "RelayState length differs"
        );
        assert!(
            relay_state
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
            "RelayState is not unpadded base64url"
        );
        assert!(
            validate_relay_state(relay_state).is_some(),
            "RelayState is not a canonical opaque token"
        );
    }

    async fn post_acs_response(
        router: Router,
        saml_response: &str,
        relay_state: &str,
    ) -> Response<Body> {
        let body = format!(
            "SAMLResponse={}&RelayState={}",
            urlencoding::encode(saml_response),
            urlencoding::encode(relay_state)
        );
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.sekisho/saml/acs")
                    .header(header::HOST, AUTH_DOMAIN)
                    .header(
                        header::COOKIE,
                        format!("__Secure-sekisho_pre_{relay_state}={TEST_BROWSER_NONCE}"),
                    )
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .expect("ACS request"),
            )
            .await
            .expect("ACS response")
    }

    async fn post_acs(router: Router, saml_response: &str, relay_state: &str) -> StatusCode {
        post_acs_response(router, saml_response, relay_state)
            .await
            .status()
    }

    async fn get_slo_response(router: Router, query: &str) -> Response<Body> {
        router
            .oneshot(
                Request::builder()
                    .uri(format!("/.sekisho/saml/slo?{query}"))
                    .header(header::HOST, AUTH_DOMAIN)
                    .body(Body::empty())
                    .expect("SLO request"),
            )
            .await
            .expect("SLO response")
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
                .is_some_and(|value| value.contains("Max-Age=0")),
            "terminal response must clear the session cookie"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read terminal body");
        assert_eq!(body.as_ref(), crate::auth::SIGNED_OUT_BODY.as_bytes());
    }

    fn relay_state_from_location(response: &Response<Body>) -> String {
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("response has a valid Location");
        url::Url::parse(location)
            .expect("Location is a URL")
            .query_pairs()
            .find_map(|(name, value)| (name == "RelayState").then(|| value.into_owned()))
            .expect("Location has RelayState")
    }

    fn signed_info_block(digest_b64: &str, assertion_id: &str) -> String {
        format!(
            r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
        )
    }

    fn signed_acs_response(request_id: &str) -> String {
        let assertion_id = "_assertion";
        let assertion = format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="2026-07-27T00:00:00Z"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="{ACS_URL}" NotOnOrAfter="2099-01-01T00:00:00Z" InResponseTo="{request_id}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>https://{AUTH_DOMAIN}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement SessionIndex="_session"/></saml:Assertion>"#
        );
        let assertion_tree =
            auth_idp::saml::c14n::parse_xml_tree(&assertion).expect("parse assertion");
        let digest = Sha256::digest(auth_idp::saml::c14n::exclusive_c14n(
            &assertion_tree,
            &HashMap::new(),
        ));
        let signed_info = signed_info_block(&STANDARD.encode(digest), assertion_id);
        let signed_info_tree =
            auth_idp::saml::c14n::parse_xml_tree(&signed_info).expect("parse SignedInfo");
        let canonical_signed_info =
            auth_idp::saml::c14n::exclusive_c14n(&signed_info_tree, &HashMap::new());
        let key = RsaKeyPair::from_pkcs8(TEST_KEY_PKCS8_DER).expect("test signing key");
        let mut signature = vec![0_u8; key.public().modulus_len()];
        key.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            &canonical_signed_info,
            &mut signature,
        )
        .expect("sign SAML response");
        let signature_b64 = STANDARD.encode(signature);
        // Place the Signature inside `</saml:Assertion>` so the fixture
        // binds the signature to the exact Assertion that semantic
        // validation consumes. The enveloped-signature transform removes
        // this Signature from the target at digest time.
        let signature = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{signature_b64}</ds:SignatureValue></ds:Signature>"#
        );
        let assertion = assertion.replacen(
            "</saml:Assertion>",
            &format!("{signature}</saml:Assertion>"),
            1,
        );
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="2026-07-27T00:00:00Z" Destination="{ACS_URL}" InResponseTo="{request_id}"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{assertion}</samlp:Response>"#
        );
        STANDARD.encode(xml)
    }

    fn logout_response_xml(request_id: &str) -> String {
        format!(
            r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout_response" Version="2.0" IssueInstant="2026-07-27T00:00:00Z" Destination="{SLO_URL}" InResponseTo="{request_id}"><saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#
        )
    }

    fn deflate_b64(xml: &str) -> String {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes()).expect("deflate SAML");
        STANDARD.encode(encoder.finish().expect("finish deflate"))
    }

    fn signed_slo_query(request_id: &str, relay_state: &str) -> String {
        let payload = deflate_b64(&logout_response_xml(request_id));
        let sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        let signed_input = format!(
            "SAMLResponse={}&RelayState={}&SigAlg={}",
            urlencoding::encode(&payload),
            urlencoding::encode(relay_state),
            urlencoding::encode(sig_alg)
        );
        let key = RsaKeyPair::from_pkcs8(TEST_KEY_PKCS8_DER).expect("test signing key");
        let mut signature = vec![0_u8; key.public().modulus_len()];
        key.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signed_input.as_bytes(),
            &mut signature,
        )
        .expect("sign SLO query");
        format!(
            "{signed_input}&Signature={}",
            urlencoding::encode(&STANDARD.encode(signature))
        )
    }

    #[derive(Clone)]
    struct SamlSloSuccessCounter(Arc<AtomicUsize>);

    struct AuditEventVisitor {
        success: bool,
    }

    impl Visit for AuditEventVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "event"
                && format!("{value:?}").trim_matches('"') == "auth.logout.saml_slo_success"
            {
                self.success = true;
            }
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "event" && value == "auth.logout.saml_slo_success" {
                self.success = true;
            }
        }
    }

    impl<S> Layer<S> for SamlSloSuccessCounter
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = AuditEventVisitor { success: false };
            event.record(&mut visitor);
            if visitor.success {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[tokio::test]
    async fn login_and_logout_urls_carry_bounded_opaque_relay_state() {
        let app = TestSamlApp::new().await;
        let login_response = app
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/protected?next=1")
                    .header(header::HOST, AUTH_DOMAIN)
                    .body(Body::empty())
                    .expect("login request"),
            )
            .await
            .expect("login response");
        assert_eq!(login_response.status(), StatusCode::FOUND);
        let auth_start_location = login_response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("auth-start location");
        let auth_start_url = url::Url::parse(auth_start_location).expect("auth-start URL");
        assert_eq!(auth_start_url.host_str(), Some(AUTH_DOMAIN));
        let ticket = auth_start_url
            .query_pairs()
            .find_map(|(name, value)| (name == "t").then(|| value.into_owned()))
            .expect("auth-start ticket");
        assert_eq!(
            app.store
                .pending_auth_get(&ticket)
                .await
                .unwrap()
                .unwrap()
                .kind,
            PendingAuthKind::AuthStart
        );

        let auth_start_response = app
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/.sekisho/auth-start?t={ticket}"))
                    .header(header::HOST, AUTH_DOMAIN)
                    .body(Body::empty())
                    .expect("auth-start request"),
            )
            .await
            .expect("auth-start response");
        assert_eq!(auth_start_response.status(), StatusCode::FOUND);
        let login_relay = relay_state_from_location(&auth_start_response);
        assert_opaque_relay_state(&login_relay);
        let pre_cookie = auth_start_response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("pre-auth cookie");
        assert!(pre_cookie.starts_with(&format!("__Secure-sekisho_pre_{login_relay}=")));
        assert!(pre_cookie.contains("SameSite=None"));
        assert!(pre_cookie.contains("Path=/.sekisho/"));
        assert!(pre_cookie.contains("Max-Age=600"));
        assert!(app.store.pending_auth_get(&ticket).await.unwrap().is_none());
        let login_pending = app
            .store
            .pending_auth_get(&login_relay)
            .await
            .expect("read login PendingAuth")
            .expect("login PendingAuth exists");
        assert_eq!(login_pending.kind, PendingAuthKind::Login);
        assert_eq!(login_pending.idp_id, app.idp_id);
        assert_eq!(
            login_pending.redirect_url,
            format!("https://{AUTH_DOMAIN}/protected?next=1")
        );

        let cookie = app.session_cookie().await;
        let logout_response = app
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.sekisho/sign-out")
                    .header(header::HOST, "attacker.example")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .expect("logout request"),
            )
            .await
            .expect("logout response");
        assert_eq!(logout_response.status(), StatusCode::FOUND);
        let logout_relay = relay_state_from_location(&logout_response);
        assert_opaque_relay_state(&logout_relay);
        let logout_pending = app
            .store
            .pending_auth_get(&logout_relay)
            .await
            .expect("read logout PendingAuth")
            .expect("logout PendingAuth exists");
        assert_eq!(logout_pending.kind, PendingAuthKind::SamlLogout);
        assert_eq!(logout_pending.idp_id, app.idp_id);
        assert_eq!(
            logout_pending.redirect_url,
            format!("https://{AUTH_DOMAIN}/.sekisho/signed-out")
        );
    }

    #[tokio::test]
    async fn sign_out_revoke_failure_is_terminal_503_without_idp_redirect() {
        let app = TestSamlApp::new().await;
        let cookie = app.session_cookie().await;
        sqlx::query(
            "CREATE TRIGGER reject_session_revoke BEFORE DELETE ON sessions \
             BEGIN SELECT RAISE(ABORT, 'injected revoke failure'); END",
        )
        .execute(app.store.sqlite_pool())
        .await
        .expect("install revoke failure trigger");

        let response = app
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.sekisho/sign-out")
                    .header(header::HOST, "attacker.example")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .expect("logout request"),
            )
            .await
            .expect("logout response");

        assert_terminal_response(response, StatusCode::SERVICE_UNAVAILABLE).await;
    }

    #[tokio::test]
    async fn sign_out_without_idp_logout_support_is_terminal_200() {
        let app = TestSamlApp::new_without_slo().await;
        let cookie = app.session_cookie().await;
        let response = app
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.sekisho/sign-out")
                    .header(header::HOST, "attacker.example")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .expect("logout request"),
            )
            .await
            .expect("logout response");

        assert_terminal_response(response, StatusCode::OK).await;
    }

    #[tokio::test]
    async fn ninth_parallel_auth_start_is_429_without_consuming_ticket() {
        let app = TestSamlApp::new().await;
        let ticket = relay("ninth-auth-start");
        app.insert_pending_raw(
            &ticket,
            app.idp_id,
            PendingAuthKind::AuthStart,
            None,
            Utc::now(),
        )
        .await;
        let cookies = (0..8)
            .map(|index| format!("__Secure-sekisho_pre_flow{index}=nonce{index}"))
            .collect::<Vec<_>>()
            .join("; ");

        let response = app
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/.sekisho/auth-start?t={ticket}"))
                    .header(header::HOST, AUTH_DOMAIN)
                    .header(header::COOKIE, cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            app.store.pending_auth_get(&ticket).await.unwrap().is_some(),
            "cap rejection must not consume the one-time ticket"
        );
    }

    #[tokio::test]
    async fn browser_nonce_mismatch_is_rejected_and_preserves_state() {
        let app = TestSamlApp::new().await;
        let label = "browser-nonce-mismatch";
        let relay_state = relay(label);
        app.insert_pending(label, app.idp_id, PendingAuthKind::Login, Some("_request"))
            .await;
        let body = format!(
            "SAMLResponse={}&RelayState={}",
            urlencoding::encode(&signed_acs_response("_request")),
            urlencoding::encode(&relay_state)
        );
        let response = app
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.sekisho/saml/acs")
                    .header(header::HOST, AUTH_DOMAIN)
                    .header(
                        header::COOKIE,
                        format!("__Secure-sekisho_pre_{relay_state}=wrong-browser-nonce"),
                    )
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        app.assert_pending(label).await;
    }

    #[test]
    fn relay_state_accepts_only_canonical_32_byte_opaque_tokens() {
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42; 32]);
        assert_opaque_relay_state(&token);
        assert!(
            validate_relay_state(&token).is_some(),
            "canonical RelayState was rejected"
        );
        let legacy_json = serde_json::json!({
            "idp_id": Uuid::nil(),
            "csrf": token,
            "redirect": "/legacy"
        });
        let legacy = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&legacy_json).expect("serialize legacy fixture"));
        for malformed in [
            String::new(),
            "not-base64!!".to_string(),
            invalid_alphabet_relay_state(),
            "A".repeat(RELAY_STATE_ENCODED_LEN - 1),
            "A".repeat(RELAY_STATE_ENCODED_LEN + 1),
            "A".repeat(81),
            legacy,
        ] {
            assert!(
                validate_relay_state(&malformed).is_none(),
                "non-canonical RelayState was accepted"
            );
        }
    }

    #[tokio::test]
    async fn acs_validation_failures_preserve_pending_auth() {
        let app = TestSamlApp::new().await;

        assert_eq!(
            post_acs(app.router.clone(), "not-a-response", &relay("acs-missing"),).await,
            StatusCode::BAD_REQUEST
        );

        let invalid_alphabet = invalid_alphabet_relay_state();
        app.insert_pending_raw(
            &invalid_alphabet,
            app.idp_id,
            PendingAuthKind::Login,
            Some("_request"),
            Utc::now(),
        )
        .await;
        assert_eq!(
            post_acs(
                app.router.clone(),
                &signed_acs_response("_request"),
                &invalid_alphabet,
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        app.assert_pending_raw(&invalid_alphabet).await;
        assert!(
            app.store
                .list_sessions(None, 10, 0)
                .await
                .expect("list sessions")
                .is_empty(),
            "invalid RelayState alphabet must not create a session"
        );

        app.insert_pending_at(
            "acs-expired",
            app.idp_id,
            PendingAuthKind::Login,
            Some("_request"),
            Utc::now() - crate::auth::middleware::PENDING_AUTH_TTL - chrono::Duration::minutes(1),
        )
        .await;
        assert_eq!(
            post_acs(app.router.clone(), "not-a-response", &relay("acs-expired"),).await,
            StatusCode::BAD_REQUEST
        );

        app.insert_pending(
            "acs-legacy-json",
            app.idp_id,
            PendingAuthKind::Login,
            Some("_request"),
        )
        .await;
        let legacy_json = serde_json::json!({
            "idp_id": app.idp_id,
            "csrf": relay("acs-legacy-json"),
            "redirect": "/browser-carried"
        });
        let legacy_relay = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&legacy_json).expect("serialize legacy fixture"));
        assert_eq!(
            post_acs(app.router.clone(), "not-a-response", &legacy_relay).await,
            StatusCode::BAD_REQUEST
        );
        app.assert_pending("acs-legacy-json").await;

        app.insert_pending(
            "acs-wrong-kind",
            app.idp_id,
            PendingAuthKind::SamlLogout,
            Some("_request"),
        )
        .await;
        assert_eq!(
            post_acs(
                app.router.clone(),
                "not-a-response",
                &relay("acs-wrong-kind"),
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        app.assert_pending("acs-wrong-kind").await;

        let other_idp = Uuid::new_v4();
        app.insert_pending(
            "acs-idp-mismatch",
            other_idp,
            PendingAuthKind::Login,
            Some("_request"),
        )
        .await;
        assert_eq!(
            post_acs(
                app.router.clone(),
                "not-a-response",
                &relay("acs-idp-mismatch"),
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        app.assert_pending("acs-idp-mismatch").await;

        app.insert_pending(
            "acs-missing-request-id",
            app.idp_id,
            PendingAuthKind::Login,
            None,
        )
        .await;
        assert_eq!(
            post_acs(
                app.router.clone(),
                &signed_acs_response("_request"),
                &relay("acs-missing-request-id"),
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        app.assert_pending("acs-missing-request-id").await;
        assert!(
            app.store
                .list_sessions(None, 10, 0)
                .await
                .expect("list sessions")
                .is_empty(),
            "missing request ID must not create a session"
        );

        app.insert_pending(
            "acs-invalid-signature",
            app.idp_id,
            PendingAuthKind::Login,
            Some("_request"),
        )
        .await;
        assert_eq!(
            post_acs(
                app.router.clone(),
                &STANDARD.encode("<not-signed/>"),
                &relay("acs-invalid-signature"),
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        app.assert_pending("acs-invalid-signature").await;

        app.insert_pending(
            "acs-request-mismatch",
            app.idp_id,
            PendingAuthKind::Login,
            Some("_expected"),
        )
        .await;
        assert_eq!(
            post_acs(
                app.router.clone(),
                &signed_acs_response("_different"),
                &relay("acs-request-mismatch"),
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        app.assert_pending("acs-request-mismatch").await;
    }

    #[tokio::test]
    async fn acs_success_redirect_comes_from_pending_auth() {
        let app = TestSamlApp::new().await;
        app.insert_pending(
            "acs-stored-redirect",
            app.idp_id,
            PendingAuthKind::Login,
            Some("_request"),
        )
        .await;
        let response = post_acs_response(
            app.router.clone(),
            &signed_acs_response("_request"),
            &relay("acs-stored-redirect"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/after-login")
        );
        let relay_state = relay("acs-stored-redirect");
        let set_cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert!(set_cookies.iter().any(|cookie| {
            cookie.starts_with(&format!("__Secure-sekisho_pre_{relay_state}="))
                && cookie.contains("Max-Age=0")
                && cookie.contains("Path=/.sekisho/")
        }));
    }

    #[tokio::test]
    async fn concurrent_valid_acs_consumes_once_and_creates_one_session() {
        let app = TestSamlApp::new().await;
        app.insert_pending(
            "acs-concurrent",
            app.idp_id,
            PendingAuthKind::Login,
            Some("_request"),
        )
        .await;
        let response = signed_acs_response("_request");
        let relay_state = relay("acs-concurrent");

        let (left, right) = tokio::join!(
            post_acs(app.router.clone(), &response, &relay_state),
            post_acs(app.router.clone(), &response, &relay_state)
        );
        let successes = [left, right]
            .into_iter()
            .filter(|status| status.is_redirection())
            .count();
        assert_eq!(successes, 1, "only the atomic-take winner may log in");
        assert!(
            app.store
                .pending_auth_get(&relay_state)
                .await
                .expect("get pending")
                .is_none(),
            "valid ACS must consume PendingAuth"
        );
        let sessions = app
            .store
            .list_sessions(None, 10, 0)
            .await
            .expect("list sessions");
        assert_eq!(sessions.len(), 1, "only one session side effect is allowed");
    }

    #[tokio::test]
    async fn slo_validation_failures_preserve_pending_auth() {
        let app = TestSamlApp::new().await;
        let success_count = Arc::new(AtomicUsize::new(0));
        let subscriber =
            tracing_subscriber::registry().with(SamlSloSuccessCounter(success_count.clone()));
        let _guard = subscriber.set_default();

        assert_terminal_response(
            get_slo_response(app.router.clone(), "").await,
            StatusCode::OK,
        )
        .await;
        assert_terminal_response(
            get_slo_response(app.router.clone(), "SAMLRequest=unsupported").await,
            StatusCode::OK,
        )
        .await;
        assert_terminal_response(
            get_slo_response(app.router.clone(), "SAMLResponse=invalid").await,
            StatusCode::OK,
        )
        .await;

        let relay_state = relay("slo-missing");
        let query = format!("SAMLResponse=invalid&RelayState={relay_state}");
        assert_terminal_response(
            get_slo_response(app.router.clone(), &query).await,
            StatusCode::OK,
        )
        .await;

        let invalid_alphabet = invalid_alphabet_relay_state();
        app.insert_pending_raw(
            &invalid_alphabet,
            app.idp_id,
            PendingAuthKind::SamlLogout,
            Some("_logout"),
            Utc::now(),
        )
        .await;
        let query = signed_slo_query("_logout", &invalid_alphabet);
        assert_terminal_response(
            get_slo_response(app.router.clone(), &query).await,
            StatusCode::OK,
        )
        .await;
        app.assert_pending_raw(&invalid_alphabet).await;
        assert_eq!(
            success_count.load(Ordering::Relaxed),
            0,
            "invalid RelayState alphabet must not emit SLO success"
        );

        app.insert_pending_at(
            "slo-expired",
            app.idp_id,
            PendingAuthKind::SamlLogout,
            Some("_logout"),
            Utc::now() - crate::auth::middleware::PENDING_AUTH_TTL - chrono::Duration::minutes(1),
        )
        .await;
        let relay_state = relay("slo-expired");
        let query = format!("SAMLResponse=invalid&RelayState={relay_state}");
        assert_terminal_response(
            get_slo_response(app.router.clone(), &query).await,
            StatusCode::OK,
        )
        .await;

        app.insert_pending(
            "slo-wrong-kind",
            app.idp_id,
            PendingAuthKind::Login,
            Some("_logout"),
        )
        .await;
        let relay_state = relay("slo-wrong-kind");
        let query = format!("SAMLResponse=invalid&RelayState={relay_state}");
        assert_terminal_response(
            get_slo_response(app.router.clone(), &query).await,
            StatusCode::OK,
        )
        .await;
        app.assert_pending("slo-wrong-kind").await;

        let other_idp = Uuid::new_v4();
        app.insert_pending(
            "slo-idp-mismatch",
            other_idp,
            PendingAuthKind::SamlLogout,
            Some("_logout"),
        )
        .await;
        let relay_state = relay("slo-idp-mismatch");
        let query = format!("SAMLResponse=invalid&RelayState={relay_state}");
        assert_terminal_response(
            get_slo_response(app.router.clone(), &query).await,
            StatusCode::OK,
        )
        .await;
        app.assert_pending("slo-idp-mismatch").await;

        app.insert_pending(
            "slo-request-mismatch",
            app.idp_id,
            PendingAuthKind::SamlLogout,
            Some("_expected"),
        )
        .await;
        let relay_state = relay("slo-request-mismatch");
        let query = signed_slo_query("_different", &relay_state);
        assert_terminal_response(
            get_slo_response(app.router.clone(), &query).await,
            StatusCode::OK,
        )
        .await;
        app.assert_pending("slo-request-mismatch").await;

        app.insert_pending(
            "slo-invalid-signature",
            app.idp_id,
            PendingAuthKind::SamlLogout,
            Some("_logout"),
        )
        .await;
        let relay_state = relay("slo-invalid-signature");
        let payload = deflate_b64(&logout_response_xml("_logout"));
        let query = format!(
            "SAMLResponse={}&RelayState={}&SigAlg={}&Signature=forged",
            urlencoding::encode(&payload),
            urlencoding::encode(&relay_state),
            urlencoding::encode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        );
        assert_terminal_response(
            get_slo_response(app.router.clone(), &query).await,
            StatusCode::OK,
        )
        .await;
        app.assert_pending("slo-invalid-signature").await;
        assert_eq!(
            success_count.load(Ordering::Relaxed),
            0,
            "invalid SLO callbacks must not emit success"
        );
    }

    #[tokio::test]
    async fn concurrent_valid_slo_consumes_once_and_emits_one_success() {
        let app = TestSamlApp::new().await;
        app.insert_pending(
            "slo-concurrent",
            app.idp_id,
            PendingAuthKind::SamlLogout,
            Some("_logout"),
        )
        .await;
        let relay_state = relay("slo-concurrent");
        let query = signed_slo_query("_logout", &relay_state);
        let success_count = Arc::new(AtomicUsize::new(0));
        let subscriber =
            tracing_subscriber::registry().with(SamlSloSuccessCounter(success_count.clone()));
        let _guard = subscriber.set_default();

        let (left, right) = tokio::join!(
            get_slo_response(app.router.clone(), &query),
            get_slo_response(app.router.clone(), &query)
        );
        assert_terminal_response(left, StatusCode::OK).await;
        assert_terminal_response(right, StatusCode::OK).await;
        assert_eq!(
            success_count.load(Ordering::Relaxed),
            1,
            "only the atomic-take winner may emit the success audit"
        );
        assert!(
            app.store
                .pending_auth_get(&relay_state)
                .await
                .expect("get pending")
                .is_none(),
            "valid SLO must consume PendingAuth"
        );
    }

    #[tokio::test]
    async fn slo_pending_lookup_failure_converges_to_terminal_response() {
        let app = TestSamlApp::new().await;
        app.store.close().await;
        let relay_state = relay("slo-store-closed");
        let query = format!("SAMLResponse=invalid&RelayState={relay_state}");

        assert_terminal_response(
            get_slo_response(app.router.clone(), &query).await,
            StatusCode::OK,
        )
        .await;
    }

    #[tokio::test]
    async fn slo_pending_take_failure_converges_to_terminal_and_preserves_state() {
        let app = TestSamlApp::new().await;
        app.insert_pending(
            "slo-take-failure",
            app.idp_id,
            PendingAuthKind::SamlLogout,
            Some("_logout"),
        )
        .await;
        sqlx::query(
            "CREATE TRIGGER reject_pending_take BEFORE DELETE ON pending_auth \
             BEGIN SELECT RAISE(ABORT, 'injected pending-auth take failure'); END",
        )
        .execute(app.store.sqlite_pool())
        .await
        .expect("install pending-auth take failure trigger");
        let relay_state = relay("slo-take-failure");
        let query = signed_slo_query("_logout", &relay_state);

        assert_terminal_response(
            get_slo_response(app.router.clone(), &query).await,
            StatusCode::OK,
        )
        .await;
        app.assert_pending("slo-take-failure").await;
    }
}
