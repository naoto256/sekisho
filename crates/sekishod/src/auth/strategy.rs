//! Authentication strategy dispatch.
//!
//! `AuthStrategy` abstracts over IdP types (OIDC, SAML, …). The trait
//! carries every piece of behaviour that varies between IdP kinds —
//! login initiation, IdP-side logout URL synthesis, create-payload
//! validation, and the display tag emitted in audit / API responses —
//! so adding a third type means writing one struct that implements the
//! trait and wiring it into the dispatch enum below.
//!
//! Static dispatch (via the `Strategy` enum) is used instead of `dyn
//! AuthStrategy` because the trait has `async fn`-shaped methods, which
//! aren't object-safe without a Pin<Box<…>> ceremony that buys nothing
//! here. The enum keeps every dispatch site to a single line.

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Response, StatusCode, header};
use cookie::SameSite;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::models::idp::{IdentityProvider, IdpType, OidcConfig, OidcConfigInput, SamlConfig};
use crate::models::session::Session;
use crate::state::AppState;

const MAX_PARALLEL_AUTH_FLOWS: usize = 8;

/// A protocol-agnostic authentication start: where to send the browser, the
/// `state` that ties the eventual callback back to this attempt, and the
/// pending server-side record.
///
/// `pending` stays private so a caller cannot construct a `PreparedAuth` whose
/// redirect and stored state disagree — the pairing is the anti-CSRF property
/// the callback later checks.
pub struct PreparedAuth {
    pub redirect_url: String,
    pub state: String,
    pending: super::middleware::PendingAuth,
}

/// Behaviour that varies between IdP kinds. Each variant of
/// [`Strategy`] holds a unit struct implementing this trait. New IdP
/// types add a struct + a `Strategy` variant + arms in the delegating
/// methods on `Strategy`; nothing else outside this module needs to
/// change.
pub trait AuthStrategy: Send + Sync {
    /// Stable string used in audit events and the API surface to name
    /// this strategy. Must match the serde tag of the corresponding
    /// `IdpType` variant.
    fn display_kind(&self) -> &'static str;

    /// Validate the create-IdP payload for this strategy. Receives both
    /// config blocks (only one of which is meaningful per IdP type) so
    /// callers don't have to pre-route based on type.
    fn validate_create_config(
        &self,
        oidc_config: Option<&OidcConfigInput>,
        saml_config: Option<&SamlConfig>,
    ) -> Result<()>;

    fn validate_update_config(
        &self,
        oidc_config: Option<&OidcConfig>,
        saml_config: Option<&SamlConfig>,
    ) -> Result<()>;

    /// Prepare the IdP redirect and callback state without mutating the
    /// database. The caller atomically transitions the one-time AuthStart
    /// ticket to the returned Login state only after this succeeds.
    fn prepare(
        &self,
        state: &AppState,
        idp: &IdentityProvider,
        original_url: &str,
        browser_nonce_hash: String,
    ) -> impl std::future::Future<Output = Result<PreparedAuth>> + Send;

    /// Build the IdP's protocol-level logout URL when one is available
    /// for the given session. `None` means the strategy can't produce
    /// one (e.g. OIDC IdP without `end_session_endpoint`, or a SAML
    /// session pre-dating SLO support); callers fall back to the local
    /// signed-out terminal page.
    fn build_logout_url<'a>(
        &'a self,
        state: &'a AppState,
        session: &'a Session,
    ) -> impl std::future::Future<Output = Option<String>> + Send + 'a;

    /// URL to GET as a startup-time discovery sanity probe, or `None`
    /// when the strategy has no discovery endpoint to hit.
    ///
    /// OIDC: synthesised from `issuer_url` per RFC 8414 (the `.well-
    /// known/openid-configuration` document). SAML: the IdP's
    /// `metadata_url` from the configuration. The probe asserts only
    /// that the document is reachable + 2xx — the parse happens
    /// lazily on first real login. Owning the URL synthesis on the
    /// strategy keeps `startup.rs` from re-doing the IdP-type dispatch
    /// outside this module, which is what `Strategy`'s contract
    /// promises.
    fn discovery_probe_url(&self, idp: &IdentityProvider) -> Option<String>;
}

/// OIDC behaviour for [`AuthStrategy`]. Unit struct: all state lives on the
/// IdP record, so the strategy is pure dispatch.
pub struct OidcStrategy;

/// SAML behaviour for [`AuthStrategy`]. Same shape as [`OidcStrategy`].
pub struct SamlStrategy;

impl AuthStrategy for OidcStrategy {
    fn display_kind(&self) -> &'static str {
        "oidc"
    }

    fn validate_create_config(
        &self,
        oidc_config: Option<&OidcConfigInput>,
        _saml_config: Option<&SamlConfig>,
    ) -> Result<()> {
        let config = oidc_config
            .ok_or_else(|| Error::BadRequest("oidc_config is required when type is oidc".into()))?;
        crate::validation::validate_oidc_config_fields(&config.issuer_url, &config.client_id)?;
        // POST requires a non-empty plaintext secret. PATCH passes
        // through `update_oidc_secret_in_patch`, which treats an
        // empty/absent value as "leave the stored secret alone".
        if config.client_secret.as_ref().is_none_or(|s| s.is_empty()) {
            return Err(Error::BadRequest("client_secret must not be empty".into()));
        }
        Ok(())
    }

    fn validate_update_config(
        &self,
        oidc_config: Option<&OidcConfig>,
        _saml_config: Option<&SamlConfig>,
    ) -> Result<()> {
        if let Some(config) = oidc_config {
            crate::validation::validate_oidc_config_fields(&config.issuer_url, &config.client_id)?;
        }
        Ok(())
    }

    async fn prepare(
        &self,
        state: &AppState,
        idp: &IdentityProvider,
        original_url: &str,
        browser_nonce_hash: String,
    ) -> Result<PreparedAuth> {
        let oidc_client = state.get_oidc_client(idp.id).await?;
        let (auth_url, csrf_state, nonce, code_verifier) = oidc_client.authorize_url();

        Ok(PreparedAuth {
            redirect_url: auth_url,
            state: csrf_state,
            pending: super::middleware::PendingAuth {
                idp_id: idp.id,
                nonce,
                code_verifier,
                redirect_url: original_url.to_string(),
                created_at: chrono::Utc::now(),
                saml_authn_request_id: None,
                kind: super::middleware::PendingAuthKind::Login,
                browser_nonce_hash: Some(browser_nonce_hash),
            },
        })
    }

    /// OIDC RP-Initiated Logout. Returns `Some(url)` only when
    /// discovery yields an `end_session_endpoint`; IdPs without it
    /// degrade to local-only.
    ///
    /// The `post_logout_redirect_uri` is built from the immutable boot-time
    /// identity authority.
    async fn build_logout_url<'a>(
        &'a self,
        state: &'a AppState,
        session: &'a Session,
    ) -> Option<String> {
        let oidc_client = state.get_oidc_client(session.idp_id).await.ok()?;
        let post_logout_redirect_uri = state
            .identity_authority
            .auth_origin()
            .ok()?
            .url("/.sekisho/signed-out");
        let id_token_hint = state.session_manager.decrypt_id_token(session).await;
        oidc_client.end_session_url(id_token_hint.as_deref(), &post_logout_redirect_uri)
    }

    fn discovery_probe_url(&self, idp: &IdentityProvider) -> Option<String> {
        idp.oidc_config.as_ref().map(|c| {
            // Trim trailing slash so the join is stable regardless of
            // how the operator wrote the issuer in the create payload.
            // RFC 8414 mandates the `.well-known/...` path is appended
            // to the issuer with exactly one separator.
            let issuer = c.issuer_url.trim_end_matches('/');
            format!("{issuer}/.well-known/openid-configuration")
        })
    }
}

impl AuthStrategy for SamlStrategy {
    fn display_kind(&self) -> &'static str {
        "saml"
    }

    fn validate_create_config(
        &self,
        _oidc_config: Option<&OidcConfigInput>,
        saml_config: Option<&SamlConfig>,
    ) -> Result<()> {
        let config = saml_config
            .ok_or_else(|| Error::BadRequest("saml_config is required when type is saml".into()))?;
        crate::validation::validate_saml_config_fields(&config.metadata_url)?;
        Ok(())
    }

    fn validate_update_config(
        &self,
        _oidc_config: Option<&OidcConfig>,
        saml_config: Option<&SamlConfig>,
    ) -> Result<()> {
        if let Some(config) = saml_config {
            crate::validation::validate_saml_config_fields(&config.metadata_url)?;
        }
        Ok(())
    }

    async fn prepare(
        &self,
        state: &AppState,
        idp: &IdentityProvider,
        original_url: &str,
        browser_nonce_hash: String,
    ) -> Result<PreparedAuth> {
        let saml_client = state.get_saml_client(idp.id).await?;

        // CSRF token — random 256-bit value used as the PendingAuth key.
        let csrf_token = {
            use rand::Rng;
            let bytes: [u8; 32] = rand::rng().random();
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
        };

        // Build the AuthnRequest *before* inserting PendingAuth so we can
        // record the request ID. The ACS handler needs this ID to verify
        // the Response's `InResponseTo`.
        let (authn_url, authn_request_id) = saml_client.authn_request_url(&csrf_token)?;

        Ok(PreparedAuth {
            redirect_url: authn_url,
            state: csrf_token,
            pending: super::middleware::PendingAuth {
                idp_id: idp.id,
                nonce: String::new(),
                code_verifier: String::new(),
                redirect_url: original_url.to_string(),
                created_at: chrono::Utc::now(),
                saml_authn_request_id: Some(authn_request_id),
                kind: super::middleware::PendingAuthKind::Login,
                browser_nonce_hash: Some(browser_nonce_hash),
            },
        })
    }

    /// SAML SP-initiated Single Logout. Returns `Some(url)` only when:
    ///   - the session has a `saml_name_id` (sessions minted by pre-SLO
    ///     binaries lack this and degrade to local-only),
    ///   - the IdP metadata advertised a SingleLogoutService,
    ///   - the PendingAuth row persists successfully.
    ///
    /// The RelayState is the CSRF token keying a `SamlLogout`-kind
    /// PendingAuth row: the SLO callback checks both the CSRF and the
    /// LogoutResponse's `InResponseTo` before accepting it.
    async fn build_logout_url<'a>(
        &'a self,
        state: &'a AppState,
        session: &'a Session,
    ) -> Option<String> {
        let name_id = session.saml_name_id.as_deref()?;
        let session_index = session.saml_session_index.as_deref();
        let saml_client = state.get_saml_client(session.idp_id).await.ok()?;
        // Presence probe for the SLO endpoint. The returned URL is
        // discarded here; the actual redirect URL is built by
        // `logout_request_redirect_url` below. `slo_redirect_url`
        // returns `None` when the IdP metadata did not advertise a
        // SingleLogoutService, in which case `?` short-circuits and
        // this function returns `None` — the caller then degrades
        // to local-only sign-out.
        saml_client.slo_redirect_url()?;

        // CSRF binds this logout flow to this browser tab — same shape
        // as SamlStrategy.initiate uses for login.
        let csrf_token = {
            use rand::Rng;
            let bytes: [u8; 32] = rand::rng().random();
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
        };

        let (url, request_id) = saml_client
            .logout_request_redirect_url(name_id, session_index, &csrf_token)
            .ok()?;
        let post_logout_redirect = state
            .identity_authority
            .auth_origin()
            .ok()?
            .url("/.sekisho/signed-out");

        state
            .auth_state_store
            .insert(
                &csrf_token,
                super::middleware::PendingAuth {
                    idp_id: session.idp_id,
                    nonce: String::new(),
                    code_verifier: String::new(),
                    redirect_url: post_logout_redirect,
                    created_at: chrono::Utc::now(),
                    saml_authn_request_id: Some(request_id),
                    kind: super::middleware::PendingAuthKind::SamlLogout,
                    browser_nonce_hash: None,
                },
            )
            .await
            .ok()?;

        Some(url)
    }

    fn discovery_probe_url(&self, idp: &IdentityProvider) -> Option<String> {
        // Operator-supplied metadata URL is the document we'd parse on
        // first login; probing it at startup catches "wrong host /
        // typoed path / TLS not yet trusted" before a user sees a
        // 500.
        idp.saml_config.as_ref().map(|c| c.metadata_url.clone())
    }
}

/// Single dispatch point for every IdP-typed operation. Adding a third
/// IdP type means: define a new strategy struct + add a variant here +
/// add an arm to each delegating method below. Outside this file
/// nothing else changes.
pub enum Strategy {
    Oidc(OidcStrategy),
    Saml(SamlStrategy),
}

impl Strategy {
    pub fn for_idp_type(idp_type: IdpType) -> Self {
        match idp_type {
            IdpType::Oidc => Self::Oidc(OidcStrategy),
            IdpType::Saml => Self::Saml(SamlStrategy),
        }
    }

    pub fn display_kind(&self) -> &'static str {
        match self {
            Self::Oidc(s) => s.display_kind(),
            Self::Saml(s) => s.display_kind(),
        }
    }

    pub fn validate_create_config(
        &self,
        oidc_config: Option<&OidcConfigInput>,
        saml_config: Option<&SamlConfig>,
    ) -> Result<()> {
        match self {
            Self::Oidc(s) => s.validate_create_config(oidc_config, saml_config),
            Self::Saml(s) => s.validate_create_config(oidc_config, saml_config),
        }
    }

    pub fn validate_update_config(
        &self,
        oidc_config: Option<&OidcConfig>,
        saml_config: Option<&SamlConfig>,
    ) -> Result<()> {
        match self {
            Self::Oidc(s) => s.validate_update_config(oidc_config, saml_config),
            Self::Saml(s) => s.validate_update_config(oidc_config, saml_config),
        }
    }

    pub async fn prepare(
        &self,
        state: &AppState,
        idp: &IdentityProvider,
        original_url: &str,
        browser_nonce_hash: String,
    ) -> Result<PreparedAuth> {
        match self {
            Self::Oidc(s) => {
                s.prepare(state, idp, original_url, browser_nonce_hash)
                    .await
            }
            Self::Saml(s) => {
                s.prepare(state, idp, original_url, browser_nonce_hash)
                    .await
            }
        }
    }

    pub async fn build_logout_url(&self, state: &AppState, session: &Session) -> Option<String> {
        match self {
            Self::Oidc(s) => s.build_logout_url(state, session).await,
            Self::Saml(s) => s.build_logout_url(state, session).await,
        }
    }

    pub fn discovery_probe_url(&self, idp: &IdentityProvider) -> Option<String> {
        match self {
            Self::Oidc(s) => s.discovery_probe_url(idp),
            Self::Saml(s) => s.discovery_probe_url(idp),
        }
    }
}

/// Create a one-time ticket that bounces the browser through the canonical
/// auth domain before any protocol state is created. The auth-domain hop is
/// where the per-flow browser nonce cookie is scoped and issued.
pub async fn initiate_auth(
    state: &AppState,
    idp_id: Uuid,
    original_url: &str,
) -> std::result::Result<Response<Body>, StatusCode> {
    state.store.get_idp(idp_id).await.map_err(|e| {
        tracing::error!(error = %e, idp_id = %idp_id, "failed to get IdP for auth redirect");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let auth_origin = state.identity_authority.auth_origin().map_err(|error| {
        tracing::error!(%error, "auth domain unavailable for authentication initiation");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let ticket = super::middleware::new_browser_nonce();
    state
        .auth_state_store
        .insert(
            &ticket,
            super::middleware::PendingAuth {
                idp_id,
                nonce: String::new(),
                code_verifier: String::new(),
                redirect_url: original_url.to_owned(),
                created_at: chrono::Utc::now(),
                saml_authn_request_id: None,
                kind: super::middleware::PendingAuthKind::AuthStart,
                browser_nonce_hash: None,
            },
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to persist auth-start ticket");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let redirect_url = auth_origin.url(&format!(
        "/.sekisho/auth-start?t={}",
        urlencoding::encode(&ticket)
    ));

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, redirect_url)
        .header("Referrer-Policy", "no-referrer")
        .body(Body::empty())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Query string of `/.sekisho/auth-start`: a single-use ticket.
///
/// The field is private, so the ticket can only be consumed through the
/// handler that validates it rather than read out and reused elsewhere.
#[derive(serde::Deserialize)]
pub struct AuthStartParams {
    t: String,
}

/// Consume an auth-start ticket on the canonical auth domain, enforce the
/// per-browser parallel-flow cap, then create protocol state bound to an
/// independent nonce cookie.
pub async fn auth_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuthStartParams>,
) -> std::result::Result<Response<Body>, StatusCode> {
    let auth_origin = state.identity_authority.auth_origin().map_err(|error| {
        tracing::error!(%error, "auth domain unavailable for auth-start");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let request_host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !auth_origin.matches_host_header(request_host) {
        tracing::warn!(actual = %request_host, expected = %auth_origin.authority(), "auth-start host mismatch");
        return Err(StatusCode::BAD_REQUEST);
    }

    let pending = state
        .auth_state_store
        .get(&params.t)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth-start ticket lookup failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .filter(|pending| pending.kind == super::middleware::PendingAuthKind::AuthStart)
        .ok_or(StatusCode::BAD_REQUEST)?;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok());
    if state.cookie_manager.pre_auth_cookie_count(cookie_header) >= MAX_PARALLEL_AUTH_FLOWS {
        tracing::warn!(
            limit = MAX_PARALLEL_AUTH_FLOWS,
            "parallel authentication flow cap reached"
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let idp = state.store.get_idp(pending.idp_id).await.map_err(|e| {
        tracing::error!(error = %e, idp_id = %pending.idp_id, "failed to get IdP for auth-start");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let browser_nonce = super::middleware::new_browser_nonce();
    let nonce_hash = super::middleware::browser_nonce_hash(&browser_nonce);
    let prepared = Strategy::for_idp_type(idp.idp_type)
        .prepare(&state, &idp, &pending.redirect_url, nonce_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, idp_type = ?idp.idp_type, "auth preparation failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let same_site = match idp.idp_type {
        crate::models::idp::IdpType::Oidc => SameSite::Lax,
        crate::models::idp::IdpType::Saml => SameSite::None,
    };
    let pre_auth_cookie =
        state
            .cookie_manager
            .create_pre_auth_cookie(&prepared.state, &browser_nonce, same_site);
    let response = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::SET_COOKIE, pre_auth_cookie)
        .header(header::LOCATION, &prepared.redirect_url)
        .header("Referrer-Policy", "no-referrer")
        .body(Body::empty())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let transitioned = state
        .auth_state_store
        .transition_auth_start(&params.t, &prepared.state, prepared.pending)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth-start transition failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    if !transitioned {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::idp::{IdpType, OidcConfig, SamlConfig};
    use axum::http::Request;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    fn oidc_idp(issuer: &str) -> IdentityProvider {
        IdentityProvider {
            id: Uuid::new_v4(),
            name: "test".into(),
            idp_type: IdpType::Oidc,
            oidc_config: Some(OidcConfig {
                issuer_url: issuer.into(),
                client_id: "cid".into(),
                client_secret_encrypted: String::new(),
                scopes: vec!["openid".into()],
                prompt: None,
            }),
            saml_config: None,
        }
    }

    fn saml_idp(metadata_url: &str) -> IdentityProvider {
        IdentityProvider {
            id: Uuid::new_v4(),
            name: "test-saml".into(),
            idp_type: IdpType::Saml,
            oidc_config: None,
            saml_config: Some(SamlConfig {
                metadata_url: metadata_url.into(),
                slo_url: None,
                name_id_format: None,
                attribute_mapping: Default::default(),
            }),
        }
    }

    #[test]
    fn oidc_discovery_probe_url_appends_well_known() {
        let idp = oidc_idp("https://issuer.example");
        let url = Strategy::for_idp_type(idp.idp_type)
            .discovery_probe_url(&idp)
            .expect("OIDC IdP must yield a probe URL");
        assert_eq!(
            url,
            "https://issuer.example/.well-known/openid-configuration"
        );
    }

    #[test]
    fn oidc_discovery_probe_url_strips_trailing_slash() {
        // Operators sometimes write the issuer with a trailing slash
        // (`https://issuer/`); RFC 8414 wants exactly one separator
        // before the well-known path. Trimming keeps the joined URL
        // stable regardless of the create-payload's exact form.
        let idp = oidc_idp("https://issuer.example/");
        let url = Strategy::for_idp_type(idp.idp_type)
            .discovery_probe_url(&idp)
            .unwrap();
        assert_eq!(
            url,
            "https://issuer.example/.well-known/openid-configuration"
        );
    }

    #[test]
    fn saml_discovery_probe_url_returns_metadata_url_verbatim() {
        let idp = saml_idp("https://idp.example/saml/metadata");
        let url = Strategy::for_idp_type(idp.idp_type)
            .discovery_probe_url(&idp)
            .expect("SAML IdP must yield a probe URL");
        assert_eq!(url, "https://idp.example/saml/metadata");
    }

    #[test]
    fn discovery_probe_url_returns_none_when_config_missing() {
        // Defensive: an IdP row that lost its config block (corruption,
        // future schema migration glitch) must not crash the startup
        // probe — `None` is the documented "no probe to do" signal.
        let mut idp = oidc_idp("https://issuer.example");
        idp.oidc_config = None;
        assert!(
            Strategy::for_idp_type(idp.idp_type)
                .discovery_probe_url(&idp)
                .is_none()
        );
    }

    #[tokio::test]
    async fn failed_prepare_retains_auth_start_and_retry_transitions_once() {
        const AUTH_DOMAIN: &str = "auth.example.com";
        const TEST_CERT_DER: &[u8] =
            include_bytes!("../../../../vendor/auth-idp/src/saml/testdata/saml_test.crt.der");

        let cert_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, TEST_CERT_DER);
        let metadata = format!(
            r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#
        );
        let requests = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind metadata server");
        let metadata_url = format!("http://{}/metadata", listener.local_addr().unwrap());
        let server_requests = requests.clone();
        let metadata_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let attempt = server_requests.fetch_add(1, Ordering::SeqCst);
                let body = if attempt == 0 {
                    "temporarily unavailable".to_owned()
                } else {
                    metadata.clone()
                };
                let status = if attempt == 0 {
                    "500 Internal Server Error"
                } else {
                    "200 OK"
                };
                tokio::spawn(async move {
                    let mut request = [0_u8; 2048];
                    let _ = socket.read(&mut request).await;
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/samlmetadata+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });

        let store = crate::store::Store::new_for_test("sqlite::memory:", [0x42; 32], None)
            .await
            .expect("test store");
        store
            .update_config(serde_json::json!({ "auth_domain": AUTH_DOMAIN }))
            .await
            .unwrap();
        let idp_id = Uuid::new_v4();
        store
            .create_idp(&IdentityProvider {
                id: idp_id,
                name: "retry-saml".into(),
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
            .unwrap();
        let route: crate::models::route::Route = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "name": "protected",
            "from": format!("https://{AUTH_DOMAIN}"),
            "to": ["http://127.0.0.1:9"],
            "idp_id": idp_id,
            "enabled": true
        }))
        .unwrap();
        store.create_route(&route).await.unwrap();
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
        let app = crate::proxy::router(
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

        let bounce = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header(header::HOST, AUTH_DOMAIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bounce_url = url::Url::parse(
            bounce
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let ticket = bounce_url
            .query_pairs()
            .find_map(|(name, value)| (name == "t").then(|| value.into_owned()))
            .expect("auth-start ticket");

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/.sekisho/auth-start?t={ticket}"))
                    .header(header::HOST, AUTH_DOMAIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(first.headers().get(header::SET_COOKIE).is_none());
        assert!(first.headers().get(header::LOCATION).is_none());
        assert_eq!(
            store
                .pending_auth_get(&ticket)
                .await
                .unwrap()
                .expect("prepare failure must retain ticket")
                .kind,
            super::super::middleware::PendingAuthKind::AuthStart
        );

        let retry = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/.sekisho/auth-start?t={ticket}"))
                    .header(header::HOST, AUTH_DOMAIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::FOUND);
        assert!(retry.headers().get(header::SET_COOKIE).is_some());
        let login_state = url::Url::parse(
            retry
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap()
        .query_pairs()
        .find_map(|(name, value)| (name == "RelayState").then(|| value.into_owned()))
        .expect("SAML RelayState");
        assert!(store.pending_auth_get(&ticket).await.unwrap().is_none());
        assert_eq!(
            store
                .pending_auth_get(&login_state)
                .await
                .unwrap()
                .expect("retry publishes Login")
                .kind,
            super::super::middleware::PendingAuthKind::Login
        );
        assert_eq!(requests.load(Ordering::SeqCst), 2);

        let second_bounce = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/protected?concurrent=1")
                    .header(header::HOST, AUTH_DOMAIN)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let concurrent_ticket = url::Url::parse(
            second_bounce
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap()
        .query_pairs()
        .find_map(|(name, value)| (name == "t").then(|| value.into_owned()))
        .expect("concurrent AuthStart ticket");
        let request = || {
            Request::builder()
                .uri(format!("/.sekisho/auth-start?t={concurrent_ticket}"))
                .header(header::HOST, AUTH_DOMAIN)
                .body(Body::empty())
                .unwrap()
        };
        let (left, right) = tokio::join!(
            app.clone().oneshot(request()),
            app.clone().oneshot(request())
        );
        let responses = [left.unwrap(), right.unwrap()];
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.status() == StatusCode::FOUND)
                .count(),
            1,
            "exactly one concurrent auth-start may redirect"
        );
        let loser = responses
            .iter()
            .find(|response| response.status() != StatusCode::FOUND)
            .expect("one transition loser");
        assert_eq!(loser.status(), StatusCode::BAD_REQUEST);
        assert!(loser.headers().get(header::SET_COOKIE).is_none());
        assert!(loser.headers().get(header::LOCATION).is_none());
        let winner = responses
            .iter()
            .find(|response| response.status() == StatusCode::FOUND)
            .unwrap();
        let concurrent_login = url::Url::parse(
            winner
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap()
        .query_pairs()
        .find_map(|(name, value)| (name == "RelayState").then(|| value.into_owned()))
        .expect("winner RelayState");
        assert!(
            store
                .pending_auth_get(&concurrent_ticket)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .pending_auth_get(&concurrent_login)
                .await
                .unwrap()
                .expect("winner publishes one Login")
                .kind,
            super::super::middleware::PendingAuthKind::Login
        );
        metadata_task.abort();
    }
}
