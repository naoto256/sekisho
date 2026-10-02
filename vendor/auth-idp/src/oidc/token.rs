//! JWT ID token verification and claims extraction.

use crate::error::{Error, Result};
use base64::Engine;
use jsonwebtoken::{Algorithm, Validation, decode};
use serde::Deserialize;
use std::fmt;
use zeroize::Zeroizing;

use super::discovery::{JwksManager, OidcDiscovery};

#[derive(Deserialize)]
pub struct TokenResponse {
    #[allow(dead_code)]
    pub access_token: Zeroizing<String>,
    pub id_token: Option<Zeroizing<String>>,
    pub refresh_token: Option<Zeroizing<String>>,
    #[allow(dead_code)]
    pub token_type: String,
}

// Manual Debug redacts the three secret-bearing fields (`access_token`,
// `id_token`, `refresh_token`) so an accidental `tracing::debug!(?resp)` /
// `dbg!(resp)` cannot leak full bearer tokens. Presence is preserved
// (`Some(<redacted>)` vs `None`) so the debug output still distinguishes
// "IdP returned no refresh token" from "IdP returned a refresh token" —
// useful when triaging an end_session_url that lacked id_token_hint.
impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("token_type", &self.token_type)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    kid: Option<String>,
    alg: Option<String>,
}

#[derive(Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Option<Vec<String>>,
    #[allow(dead_code)]
    pub nonce: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum IdTokenAudience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Deserialize)]
struct VerifiedIdTokenClaims {
    iss: String,
    sub: String,
    email: Option<String>,
    name: Option<String>,
    groups: Option<Vec<String>>,
    nonce: Option<String>,
    aud: IdTokenAudience,
    azp: Option<String>,
}

// Manual Debug redacts user identity fields (sub / email / name / groups)
// — these are PII that callers should never pull into log lines via
// `{:?}`. `groups` keeps its length so triage of "is the IdP returning
// any groups at all?" stays possible. `nonce` is not secret post-
// validation but is still redacted for symmetry (it's a flow secret
// before validation).
impl fmt::Debug for IdTokenClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdTokenClaims")
            .field("sub", &"<redacted>")
            .field("email", &self.email.as_ref().map(|_| "<redacted>"))
            .field("name", &self.name.as_ref().map(|_| "<redacted>"))
            .field(
                "groups",
                &self
                    .groups
                    .as_ref()
                    .map(|g| format!("<{} groups>", g.len())),
            )
            .field("nonce", &self.nonce.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Verify and decode a JWT ID token using the cached JWKS.
pub async fn verify_id_token(
    token: &str,
    client_id: &str,
    issuer_url: &str,
    discovery: &OidcDiscovery,
    jwks_manager: &JwksManager,
    http: &reqwest::Client,
) -> Result<IdTokenClaims> {
    let header = decode_jwt_header(token)?;

    let algorithm = match header.alg.as_deref() {
        Some("RS256") => Algorithm::RS256,
        Some("RS384") => Algorithm::RS384,
        Some("RS512") => Algorithm::RS512,
        Some("ES256") => Algorithm::ES256,
        Some("ES384") => Algorithm::ES384,
        Some(other) => {
            return Err(Error::AuthenticationFailed(format!(
                "unsupported JWT algorithm: {other}"
            )));
        }
        // Reject tokens with missing alg header — require explicit algorithm.
        // Note: "none" alg is caught by the Some(other) arm above.
        None => {
            return Err(Error::AuthenticationFailed("JWT missing alg header".into()));
        }
    };

    let decoding_key = jwks_manager
        .find_key(http, &discovery.jwks_uri, header.kid.as_deref())
        .await?;

    let mut validation = Validation::new(algorithm);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_audience(&[client_id]);
    validation.leeway = 60;
    // The trust anchor is the operator-configured issuer URL that
    // `OidcClient::new` already canonicalized (trailing slash trimmed).
    // Accept both the canonical form and the slash-suffixed form for
    // JWT `iss`, mirroring the trailing-slash tolerance applied to the
    // discovery document check.
    let issuer_forms = accepted_issuer_forms(issuer_url);
    validation.set_issuer(&issuer_forms);

    let token_data = decode::<VerifiedIdTokenClaims>(token, &decoding_key, &validation)
        .map_err(|e| Error::AuthenticationFailed(format!("JWT verification failed: {e}")))?;

    if !issuer_forms.contains(&token_data.claims.iss) {
        return Err(Error::AuthenticationFailed(
            "JWT issuer does not match configured issuer".into(),
        ));
    }

    let multiple_audiences = match &token_data.claims.aud {
        IdTokenAudience::Single(audience) => {
            let _ = audience;
            false
        }
        IdTokenAudience::Multiple(audiences) => audiences.len() > 1,
    };
    if multiple_audiences && token_data.claims.azp.as_deref() != Some(client_id) {
        return Err(Error::AuthenticationFailed(
            "JWT authorized party is required for multiple audiences".into(),
        ));
    }
    if token_data
        .claims
        .azp
        .as_deref()
        .is_some_and(|azp| azp != client_id)
    {
        return Err(Error::AuthenticationFailed(
            "JWT authorized party does not match client ID".into(),
        ));
    }

    Ok(IdTokenClaims {
        sub: token_data.claims.sub,
        email: token_data.claims.email,
        name: token_data.claims.name,
        groups: token_data.claims.groups,
        nonce: token_data.claims.nonce,
    })
}

/// Return the pair of acceptable `iss` values for the
/// trust anchor, tolerant to a trailing slash on either the caller's
/// configured issuer URL or the JWT's `iss` claim. Extracted so the
/// canonicalisation can be unit-tested without spinning up an
/// end-to-end discovery + JWKS + JWT fixture.
fn accepted_issuer_forms(issuer_url: &str) -> [String; 2] {
    let canonical = issuer_url.trim_end_matches('/').to_string();
    let with_slash = format!("{canonical}/");
    [canonical, with_slash]
}

fn decode_jwt_header(jwt: &str) -> Result<JwtHeader> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::AuthenticationFailed("invalid JWT format".into()));
    }
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| {
            Error::AuthenticationFailed(format!("JWT header base64 decode failed: {e}"))
        })?;
    serde_json::from_slice(&header_bytes)
        .map_err(|e| Error::AuthenticationFailed(format!("JWT header parse failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::RsaKeyPair;
    use serde_json::{Value, json};
    use x509_parser::prelude::{FromDer, X509Certificate};

    const TEST_KEY_PKCS8_DER: &[u8] = include_bytes!("../saml/testdata/saml_test.p8.der");
    const TEST_CERT_DER: &[u8] = include_bytes!("../saml/testdata/saml_test.crt.der");

    async fn verify_test_claims(claims: Value) -> Result<IdTokenClaims> {
        use x509_parser::public_key::PublicKey;

        let (_, certificate) = X509Certificate::from_der(TEST_CERT_DER).expect("test certificate");
        let PublicKey::RSA(rsa) = certificate
            .public_key()
            .parsed()
            .expect("test RSA public key")
        else {
            panic!("test certificate must carry an RSA key");
        };
        let modulus = rsa.modulus.strip_prefix(&[0]).unwrap_or(rsa.modulus);
        let manager = JwksManager::new();
        *manager.jwks.write().await = Some(super::super::discovery::Jwks {
            keys: vec![super::super::discovery::Jwk {
                kty: "RSA".into(),
                use_: Some("sig".into()),
                kid: Some("test-key".into()),
                alg: Some("RS256".into()),
                n: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(modulus)),
                e: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rsa.exponent)),
                x: None,
                y: None,
                crv: None,
            }],
        });
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"RS256","kid":"test-key","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).expect("claims JSON"));
        let signing_input = format!("{header}.{payload}");
        let key = RsaKeyPair::from_pkcs8(TEST_KEY_PKCS8_DER).expect("test RSA private key");
        let mut signature = vec![0; key.public().modulus_len()];
        key.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature,
        )
        .expect("sign test token");
        let token = format!(
            "{signing_input}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
        );
        let discovery = OidcDiscovery {
            authorization_endpoint: "https://idp.example.com/authorize".into(),
            token_endpoint: "https://idp.example.com/token".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            userinfo_endpoint: None,
            issuer: Some("https://idp.example.com".into()),
            end_session_endpoint: None,
        };
        verify_id_token(
            &token,
            "client-id",
            "https://idp.example.com",
            &discovery,
            &manager,
            &reqwest::Client::new(),
        )
        .await
    }

    fn valid_claims() -> Value {
        json!({
            "exp": 4_102_444_800_u64,
            "iss": "https://idp.example.com",
            "aud": "client-id",
            "sub": "subject-1"
        })
    }

    #[test]
    fn token_response_deserializes_secrets_into_zeroizing_owners() {
        let response: TokenResponse = serde_json::from_str(
            r#"{
                "access_token": "access-secret-sentinel",
                "id_token": "id-secret-sentinel",
                "refresh_token": "refresh-secret-sentinel",
                "token_type": "Bearer"
            }"#,
        )
        .expect("token response should deserialize");

        fn assert_zeroizing_string(_: &Zeroizing<String>) {}
        assert_zeroizing_string(&response.access_token);
        assert_zeroizing_string(response.id_token.as_ref().expect("id token should exist"));
        assert_zeroizing_string(
            response
                .refresh_token
                .as_ref()
                .expect("refresh token should exist"),
        );

        let rendered = format!("{response:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("access-secret"));
        assert!(!rendered.contains("id-secret"));
        assert!(!rendered.contains("refresh-secret"));
    }

    /// Same trailing-slash tolerance the OIDC construction check
    /// applies must reach the ID token issuer validation, so that a
    /// caller who configured `"https://idp.example.com/"` still accepts
    /// tokens whose `iss` claim omits the trailing slash (and vice
    /// versa). Pins issuer trailing-slash tolerance parity between
    /// the OIDC constructor and the ID token issuer check.
    #[test]
    fn accepted_issuer_forms_carries_trailing_slash_tolerance() {
        // Configured without slash: both forms accepted.
        let forms = accepted_issuer_forms("https://idp.example.com");
        assert!(forms.iter().any(|s| s == "https://idp.example.com"));
        assert!(forms.iter().any(|s| s == "https://idp.example.com/"));
        // Configured with slash: same two forms accepted (canonicalised).
        let forms = accepted_issuer_forms("https://idp.example.com/");
        assert!(forms.iter().any(|s| s == "https://idp.example.com"));
        assert!(forms.iter().any(|s| s == "https://idp.example.com/"));
    }

    #[tokio::test]
    async fn id_token_requires_issuer_audience_and_subject() {
        for claim in ["iss", "aud", "sub"] {
            let mut claims = valid_claims();
            claims.as_object_mut().expect("claims object").remove(claim);
            assert!(
                verify_test_claims(claims).await.is_err(),
                "missing {claim} must be rejected"
            );
        }

        for (claim, value) in [
            ("iss", json!("https://other.example.com")),
            ("aud", json!("other-client")),
        ] {
            let mut claims = valid_claims();
            claims[claim] = value;
            assert!(
                verify_test_claims(claims).await.is_err(),
                "mismatched {claim} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn id_token_requires_string_issuer_shape() {
        for issuer in [
            json!(["https://idp.example.com", "https://other.example.com"]),
            json!(42),
            json!({"value": "https://idp.example.com"}),
            Value::Null,
        ] {
            let mut claims = valid_claims();
            claims["iss"] = issuer;
            assert!(verify_test_claims(claims).await.is_err());
        }

        assert!(verify_test_claims(valid_claims()).await.is_ok());
        let mut slash_suffixed = valid_claims();
        slash_suffixed["iss"] = json!("https://idp.example.com/");
        assert!(verify_test_claims(slash_suffixed).await.is_ok());
    }

    #[tokio::test]
    async fn id_token_enforces_authorized_party_for_single_and_multiple_audiences() {
        let single = valid_claims();
        assert!(verify_test_claims(single.clone()).await.is_ok());
        let mut single_matching_azp = single.clone();
        single_matching_azp["azp"] = json!("client-id");
        assert!(verify_test_claims(single_matching_azp).await.is_ok());
        let mut single_wrong_azp = single;
        single_wrong_azp["azp"] = json!("other-client");
        assert!(verify_test_claims(single_wrong_azp).await.is_err());

        let mut multiple = valid_claims();
        multiple["aud"] = json!(["client-id", "second-audience"]);
        assert!(verify_test_claims(multiple.clone()).await.is_err());
        let mut multiple_wrong_azp = multiple.clone();
        multiple_wrong_azp["azp"] = json!("other-client");
        assert!(verify_test_claims(multiple_wrong_azp).await.is_err());
        multiple["azp"] = json!("client-id");
        assert!(verify_test_claims(multiple).await.is_ok());
    }
}
