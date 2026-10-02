//! OIDC (OpenID Connect) client implementation.
//!
//! - `mod.rs` — OidcClient facade (new, authorize_url, exchange_code)
//! - `discovery.rs` — OIDC Discovery, JWKS fetch/cache, JWK → DecodingKey
//! - `token.rs` — JWT ID token verification and claims extraction

pub mod discovery;
mod token;

use crate::error::{Error, Result};
use base64::Engine;
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// IdP-side OIDC config. Caller assembles this from whatever storage
/// it uses.
#[derive(Debug, Clone)]
pub struct OidcIdpConfig {
    pub issuer_url: String,
}

/// SP-side OIDC client config (the half that is *not* the secret).
#[derive(Debug, Clone)]
pub struct OidcClientConfig {
    pub client_id: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
}

pub struct OidcClient {
    discovery: discovery::OidcDiscovery,
    client_id: String,
    client_secret: Zeroizing<String>,
    redirect_url: String,
    scopes: Vec<String>,
    /// Configured issuer URL (fallback for issuer validation if discovery omits it).
    issuer_url: String,
    http: reqwest::Client,
    jwks_manager: discovery::JwksManager,
}

impl OidcClient {
    /// Create a new OIDC client. The `decrypted_client_secret` is the
    /// plaintext client_secret — the caller is responsible for any
    /// at-rest decryption.
    ///
    /// # Trust boundary — `idp.issuer_url` must be operator-controlled
    ///
    /// The crate fetches `<issuer_url>/.well-known/openid-configuration`
    /// and then trusts the `authorization_endpoint`, `token_endpoint`,
    /// `jwks_uri`, and `end_session_endpoint` from the returned document.
    /// A malicious discovery response can therefore redirect subsequent
    /// server-side `POST`s (including `client_secret` and the
    /// authorization code) to an attacker-controlled URL, and steer the
    /// user's browser through `authorize_url` / `end_session_url` to
    /// a phishing page.
    ///
    /// For deployments where `issuer_url` is set by an operator, this
    /// removes untrusted-configuration selection: the configured issuer
    /// and its discovery endpoint become the trusted boundary. A
    /// compromised or misbehaving discovery endpoint still exhibits the
    /// steering above; operator control does not neutralize it. If the
    /// caller accepts `issuer_url` from untrusted input (multi-tenant
    /// IdP discovery, self-service IdP registration), it MUST validate
    /// the value before passing it in — `https://` scheme, no private /
    /// link-local / loopback address, redirect policy fixed, etc. The
    /// `reqwest::Client` passed in also carries the caller's chosen
    /// redirect policy and network access rules; this crate does not
    /// override them.
    pub async fn new(
        http: reqwest::Client,
        idp: &OidcIdpConfig,
        client: &OidcClientConfig,
        decrypted_client_secret: String,
    ) -> Result<Self> {
        // Establish the zeroizing owner before discovery performs the first
        // await, so every constructor error path drops the plaintext secret.
        let decrypted_client_secret = Zeroizing::new(decrypted_client_secret);
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            idp.issuer_url.trim_end_matches('/')
        );

        let discovery_resp = http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| Error::ExternalServiceError(format!("OIDC discovery failed: {e}")))?;
        let discovery_bytes = crate::http::limited_response(discovery_resp, 1024 * 1024)
            .await
            .map_err(|e| Error::ExternalServiceError(format!("OIDC discovery: {e}")))?;
        let discovery: discovery::OidcDiscovery = serde_json::from_slice(&discovery_bytes)
            .map_err(|e| {
                Error::ExternalServiceError(format!("OIDC discovery parse failed: {e}"))
            })?;

        // OIDC Discovery §4.3: `issuer` MUST equal the URL used to
        // fetch the configuration. Verifying this at fetch time is what
        // makes the discovery document a trust anchor at all — without
        // the check an attacker who can serve a well-formed
        // openid-configuration on our issuer host can pivot to any
        // token / userinfo endpoint they like. A missing `issuer`
        // field is also refused: it is REQUIRED by the spec.
        let configured_issuer = idp.issuer_url.trim_end_matches('/');
        match discovery.issuer.as_deref() {
            Some(advertised) if advertised.trim_end_matches('/') == configured_issuer => {}
            Some(advertised) => {
                return Err(Error::ExternalServiceError(format!(
                    "OIDC discovery issuer {advertised:?} does not match configured issuer {:?}",
                    idp.issuer_url
                )));
            }
            None => {
                return Err(Error::ExternalServiceError(
                    "OIDC discovery document missing required `issuer` field".into(),
                ));
            }
        }

        Ok(Self {
            discovery,
            client_id: client.client_id.clone(),
            client_secret: decrypted_client_secret,
            redirect_url: client.redirect_url.clone(),
            scopes: client.scopes.clone(),
            // Store the same canonicalisation (trailing-slash trimmed)
            // that gated `new()` above. `verify_id_token` then keys
            // the JWT `iss` check off the exact string we accepted the
            // discovery document under, avoiding the case where
            // `idp.issuer_url = "https://idp.example.com/"` passed
            // construction (because `discovery.issuer = "https://idp.example.com"`
            // matched after trimming) yet ID tokens with `iss =
            // "https://idp.example.com"` failed verification because
            // the un-trimmed configured value was used as the trust
            // anchor.
            issuer_url: configured_issuer.to_string(),
            http,
            jwks_manager: discovery::JwksManager::new(),
        })
    }

    /// Generate the authorization URL with PKCE
    pub fn authorize_url(&self) -> (String, String, String, String) {
        let state = generate_random_string();
        let nonce = generate_random_string();
        let (code_verifier, code_challenge) = generate_pkce();

        let scope = self.scopes.join(" ");
        let url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            self.discovery.authorization_endpoint,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_url),
            urlencoding::encode(&scope),
            urlencoding::encode(&state),
            urlencoding::encode(&nonce),
            urlencoding::encode(&code_challenge),
        );

        (url, state, nonce, code_verifier)
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        expected_nonce: &str,
    ) -> Result<OidcUserInfo> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_url),
            ("client_id", &self.client_id),
            ("client_secret", self.client_secret.as_str()),
            ("code_verifier", code_verifier),
        ];

        let token_resp = self
            .http
            .post(&self.discovery.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| Error::ExternalServiceError(format!("token exchange failed: {e}")))?;
        // The OIDC-local reader owns its buffer as zeroizing from allocation,
        // including partial-body, oversize, and transport-error paths.
        let token_bytes = limited_token_response(token_resp)
            .await
            .map_err(|e| Error::ExternalServiceError(format!("token response: {e}")))?;
        let mut resp: token::TokenResponse = serde_json::from_slice(&token_bytes).map_err(|e| {
            Error::ExternalServiceError(format!("token response parse failed: {e}"))
        })?;

        let id_token = resp
            .id_token
            .take()
            .ok_or_else(|| Error::ExternalServiceError("missing id_token".into()))?;

        let claims = token::verify_id_token(
            id_token.as_str(),
            &self.client_id,
            &self.issuer_url,
            &self.discovery,
            &self.jwks_manager,
            &self.http,
        )
        .await?;

        // Verify nonce to prevent token replay attacks
        match &claims.nonce {
            Some(nonce) if nonce == expected_nonce => {}
            Some(_) => {
                return Err(Error::AuthenticationFailed(
                    "ID token nonce mismatch".into(),
                ));
            }
            None => {
                return Err(Error::AuthenticationFailed(
                    "ID token missing nonce claim".into(),
                ));
            }
        }

        let subject = claims.sub.clone();
        let explicit_email = claims.email.clone();
        let email = explicit_email.clone().unwrap_or_else(|| subject.clone());

        let mut extra_claims = HashMap::new();
        extra_claims.insert(
            "sub".to_string(),
            serde_json::Value::String(subject.clone()),
        );
        extra_claims.insert(
            "email".to_string(),
            serde_json::Value::String(email.clone()),
        );
        if let Some(name) = claims.name {
            extra_claims.insert("name".to_string(), serde_json::Value::String(name));
        }

        Ok(OidcUserInfo {
            subject,
            explicit_email,
            email,
            groups: claims.groups.unwrap_or_default(),
            claims: extra_claims,
            // Both capabilities take ownership of the deserialized buffers;
            // no token String is copied on the return path.
            refresh_token: resp.refresh_token.take().map(OidcToken::from_zeroizing),
            id_token: Some(OidcToken::from_zeroizing(id_token)),
        })
    }

    /// Build an OIDC RP-Initiated Logout 1.0 URL pointing at the IdP's
    /// `end_session_endpoint`, or return `None` if the IdP does not
    /// advertise one. Callers should fall back to the local-only
    /// signout flow on `None`.
    ///
    /// Spec: <https://openid.net/specs/openid-connect-rpinitiated-1_0.html>
    ///
    /// `id_token_hint` is the full ID token issued at login. Some
    /// IdPs require it, others accept it optionally. Pass `None` if
    /// the IdP didn't return one — the URL is still valid per spec,
    /// but some IdPs will display a "sign out of which account?"
    /// interstitial.
    pub fn end_session_url(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: &str,
    ) -> Option<String> {
        let endpoint = self.discovery.end_session_endpoint.as_ref()?;
        let mut params: Vec<(&str, &str)> = Vec::with_capacity(3);
        params.push(("client_id", self.client_id.as_str()));
        params.push(("post_logout_redirect_uri", post_logout_redirect_uri));
        if let Some(hint) = id_token_hint {
            params.push(("id_token_hint", hint));
        }
        let query = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let sep = if endpoint.contains('?') { '&' } else { '?' };
        Some(format!("{endpoint}{sep}{query}"))
    }
}

/// Read a secret-bearing token response into a bounded zeroizing owner.
///
/// This deliberately remains OIDC-local: unlike general discovery or JWKS
/// documents, every byte accumulated here may contain bearer credentials.
/// The buffer is zeroizing from allocation, so success and every early return
/// wipe the bytes owned by this crate. Buffers inside reqwest or other
/// dependencies remain outside that ownership guarantee.
async fn limited_token_response(
    mut response: reqwest::Response,
) -> std::result::Result<Zeroizing<Vec<u8>>, String> {
    const MAX_BYTES: usize = 1024 * 1024;
    if let Some(len) = response.content_length()
        && len as usize > MAX_BYTES
    {
        return Err(format!("response too large: {len} bytes (max {MAX_BYTES})"));
    }

    // One fixed allocation avoids leaving a grown-away allocation containing
    // a partial token response outside this owner's final wipe.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BYTES));
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => return Err(error.to_string()),
        };
        if bytes.len().saturating_add(chunk.len()) > MAX_BYTES {
            return Err(format!(
                "response too large: exceeded {MAX_BYTES} bytes while reading"
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// An owned OIDC token capability.
///
/// Borrowing is explicit through [`OidcToken::expose_secret`]. Ownership can
/// be transferred without copying through [`OidcToken::into_zeroizing`]. The
/// zeroizing owner covers buffers explicitly owned by this crate; it cannot
/// wipe copies that a caller or an upstream dependency creates separately.
pub struct OidcToken {
    secret: Zeroizing<String>,
}

impl OidcToken {
    /// Take ownership of a plaintext token and immediately make it zeroizing.
    pub fn new(secret: String) -> Self {
        Self {
            secret: Zeroizing::new(secret),
        }
    }

    fn from_zeroizing(secret: Zeroizing<String>) -> Self {
        Self { secret }
    }

    /// Borrow the token plaintext at an explicit secret-exposure boundary.
    pub fn expose_secret(&self) -> &str {
        self.secret.as_str()
    }

    /// Transfer ownership of the zeroizing buffer without copying it.
    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.secret
    }

    /// Wipe this token before its owner reaches its normal drop boundary.
    pub fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for OidcToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OidcToken").field(&"<redacted>").finish()
    }
}

pub struct OidcUserInfo {
    /// Protocol-native subject, kept separate from the compatibility email
    /// fallback so downstream consumers never need to reverse-engineer it
    /// from the claims map.
    pub subject: String,
    /// Email exactly as asserted by the IdP. `None` means `email` below fell
    /// back to `subject` for login compatibility.
    pub explicit_email: Option<String>,
    pub email: String,
    pub groups: Vec<String>,
    pub claims: HashMap<String, serde_json::Value>,
    pub refresh_token: Option<OidcToken>,
    /// The raw ID token JWT. Preserved so sign-out can supply
    /// `id_token_hint` to the IdP's RP-Initiated Logout endpoint.
    pub id_token: Option<OidcToken>,
}

fn generate_random_string() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::rng().random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_pkce() -> (String, String) {
    use sha2::{Digest, Sha256};
    let verifier = generate_random_string();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_token_response(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener should bind");
        let address = listener
            .local_addr()
            .expect("loopback listener should have an address");
        tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .expect("loopback client should connect");
            let mut request = [0_u8; 2048];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(&response)
                .await
                .expect("loopback response should write");
            socket
                .shutdown()
                .await
                .expect("loopback response should close");
        });
        format!("http://{address}")
    }

    async fn fetch_token_response(raw: Vec<u8>) -> reqwest::Response {
        reqwest::get(spawn_token_response(raw).await)
            .await
            .expect("loopback response headers should parse")
    }

    fn mk_client_for_logout(end_session_endpoint: Option<&str>, client_id: &str) -> OidcClient {
        OidcClient {
            discovery: discovery::OidcDiscovery {
                authorization_endpoint: "https://idp.example.com/authorize".into(),
                token_endpoint: "https://idp.example.com/token".into(),
                jwks_uri: "https://idp.example.com/jwks".into(),
                userinfo_endpoint: None,
                issuer: Some("https://idp.example.com".into()),
                end_session_endpoint: end_session_endpoint.map(str::to_string),
            },
            client_id: client_id.into(),
            client_secret: Zeroizing::new(String::new()),
            redirect_url: "https://app.example.com/.auth/callback".into(),
            scopes: vec!["openid".into()],
            issuer_url: "https://idp.example.com".into(),
            http: reqwest::Client::new(),
            jwks_manager: discovery::JwksManager::new(),
        }
    }

    #[test]
    fn oidc_token_redacts_and_transfers_ownership_without_copying() {
        let secret = "oidc-token-secret-sentinel".to_string();
        let original_ptr = secret.as_ptr();
        let original_len = secret.len();
        let token = OidcToken::new(secret);
        assert_eq!(token.expose_secret().as_ptr(), original_ptr);

        let rendered = format!("{token:?}");
        assert_eq!(rendered, "OidcToken(\"<redacted>\")");
        assert!(!rendered.contains("secret-sentinel"));

        let transferred = token.into_zeroizing();
        assert_eq!(transferred.as_ptr(), original_ptr);
        assert_eq!(transferred.len(), original_len);
    }

    #[test]
    fn oidc_token_accepts_deserialized_owner_without_copying() {
        let secret = Zeroizing::new("deserialized-token-secret-sentinel".to_string());
        let original_ptr = secret.as_ptr();
        let original_len = secret.len();
        let token = OidcToken::from_zeroizing(secret);

        assert_eq!(token.expose_secret().as_ptr(), original_ptr);
        assert_eq!(token.expose_secret().len(), original_len);
    }

    #[test]
    fn oidc_token_supports_explicit_early_zeroize() {
        let mut token = OidcToken::new("early-wipe-secret-sentinel".to_string());
        token.zeroize();
        assert!(token.expose_secret().is_empty());
        assert_eq!(format!("{token:?}"), "OidcToken(\"<redacted>\")");
    }

    #[tokio::test]
    async fn token_response_reader_returns_zeroizing_owner() {
        let body = b"token-success-secret-sentinel";
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);

        let response = fetch_token_response(raw).await;
        let bytes = limited_token_response(response)
            .await
            .expect("bounded token response should succeed");
        fn assert_zeroizing_bytes(_: &Zeroizing<Vec<u8>>) {}
        assert_zeroizing_bytes(&bytes);
        assert_eq!(bytes.len(), body.len());
        assert!(bytes.as_slice() == body);
    }

    #[tokio::test]
    async fn token_response_reader_rejects_oversized_content_length() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n".to_vec();
        let response = fetch_token_response(raw).await;
        let error = match limited_token_response(response).await {
            Ok(_) => panic!("oversized Content-Length must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("response too large"));
        assert!(!error.contains("secret-sentinel"));
    }

    #[tokio::test]
    async fn token_response_reader_rejects_chunked_mid_read_overflow() {
        let sentinel = b"chunked-token-secret-sentinel";
        let mut body = Vec::with_capacity(1024 * 1024 + sentinel.len());
        while body.len() < 1024 * 1024 + 1 {
            body.extend_from_slice(sentinel);
        }
        let mut raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        raw.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        raw.extend_from_slice(&body);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");

        let response = fetch_token_response(raw).await;
        let error = match limited_token_response(response).await {
            Ok(_) => panic!("chunked token response overflow must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("response too large"));
        assert!(!error.contains("secret-sentinel"));
    }

    #[tokio::test]
    async fn token_response_reader_rejects_truncated_transport_body() {
        let body = b"truncated-token-secret-sentinel";
        let mut raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\nConnection: close\r\n\r\n".to_vec();
        raw.extend_from_slice(body);

        let response = fetch_token_response(raw).await;
        let error = match limited_token_response(response).await {
            Ok(_) => panic!("truncated token response must be rejected"),
            Err(error) => error,
        };
        assert!(!error.is_empty());
        assert!(!error.contains("secret-sentinel"));
    }

    #[test]
    fn end_session_url_returns_none_when_endpoint_absent() {
        let client = mk_client_for_logout(None, "client-xyz");
        assert!(
            client
                .end_session_url(
                    Some("ey.fake.jwt"),
                    "https://app.example.com/.auth/signed-out"
                )
                .is_none()
        );
    }

    #[test]
    fn end_session_url_encodes_params_and_appends_query() {
        let client = mk_client_for_logout(
            Some("https://login.microsoftonline.com/tenant-id/oauth2/v2.0/logout"),
            "client id with space",
        );
        let url = client
            .end_session_url(
                Some("ey.jwt"),
                "https://app.example.com/.auth/signed-out?foo=bar",
            )
            .unwrap();

        assert!(url.starts_with("https://login.microsoftonline.com/"));
        // `?` appended since endpoint has no query.
        assert!(url.contains("?client_id=client%20id%20with%20space"));
        // Space/? in redirect URI must be encoded.
        assert!(url.contains(
            "&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F.auth%2Fsigned-out%3Ffoo%3Dbar"
        ));
        assert!(url.ends_with("&id_token_hint=ey.jwt"));
    }

    #[test]
    fn end_session_url_uses_ampersand_when_endpoint_has_query() {
        let client = mk_client_for_logout(Some("https://idp.example.com/logout?tenant=foo"), "cid");
        let url = client
            .end_session_url(None, "https://app.example.com/.auth/signed-out")
            .unwrap();
        // Starts with the original query preserved, then `&` before our params.
        assert!(url.starts_with("https://idp.example.com/logout?tenant=foo&client_id=cid"));
        // No id_token_hint since None was supplied.
        assert!(!url.contains("id_token_hint"));
    }

    #[test]
    fn end_session_url_handles_non_ascii_redirect() {
        let client = mk_client_for_logout(Some("https://idp.example.com/logout"), "cid");
        let url = client
            .end_session_url(
                None,
                "https://app.example.com/.auth/signed-out?msg=こんにちは",
            )
            .unwrap();
        // Japanese encoded as UTF-8 percent-encoding.
        assert!(url.contains("msg%3D%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF"));
    }
}
