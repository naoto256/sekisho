//! Strict Ed25519 JWT verification using Sekisho's public JWKS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;

use super::{IdentityClaims, JwtConstraints};

/// The daemon's verified signing keys, indexed by `kid`.
///
/// Only Ed25519 signing keys are ever stored — see [`Jwks::parse`].
#[derive(Clone, Debug)]
pub struct Jwks {
    keys: HashMap<String, [u8; 32]>,
}

/// The key set as held at runtime: shared, and swapped wholesale by the
/// refresh loop so a rotation is observed atomically rather than key by key.
pub type SharedJwks = Arc<RwLock<Jwks>>;

impl Jwks {
    /// Parse a JWKS document, rejecting the whole thing on anything
    /// unexpected.
    ///
    /// Strict rather than lenient on purpose. The usual JWKS parser skips keys
    /// it does not understand, which here would mean silently accepting a
    /// document where an algorithm was downgraded or an extra key injected,
    /// and carrying on with whatever remained. Since the only legitimate
    /// producer is a sekisho daemon that emits exactly one shape — `OKP` /
    /// `Ed25519` / `EdDSA` / `use: sig` — anything else means the document is
    /// not the one we think it is, and the right response is to keep the
    /// previously verified key set.
    ///
    /// A duplicate `kid` is an error for the same reason: it makes key
    /// selection depend on iteration order, which is exactly the ambiguity an
    /// attacker would want.
    pub(super) fn parse(value: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Document {
            keys: Vec<Key>,
        }
        #[derive(Deserialize)]
        struct Key {
            kty: String,
            crv: String,
            alg: String,
            #[serde(rename = "use")]
            use_: String,
            kid: String,
            x: String,
        }

        let document: Document = serde_json::from_slice(value).context("JWKS body not JSON")?;
        let mut keys = HashMap::with_capacity(document.keys.len());
        for key in document.keys {
            if key.kty != "OKP"
                || key.crv != "Ed25519"
                || key.alg != "EdDSA"
                || key.use_ != "sig"
                || key.kid.is_empty()
            {
                return Err(anyhow!("JWKS contains an unsupported key"));
            }
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(key.x)
                .context("JWKS contains an invalid public key")?;
            let public: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("JWKS contains an invalid Ed25519 public key"))?;
            if keys.insert(key.kid, public).is_some() {
                return Err(anyhow!("JWKS contains a duplicate kid"));
            }
        }
        if keys.is_empty() {
            return Err(anyhow!("JWKS contains no usable keys"));
        }
        Ok(Self { keys })
    }
}

/// Wrap a parsed key set for sharing with the refresh loop.
pub fn shared(keys: Jwks) -> SharedJwks {
    Arc::new(RwLock::new(keys))
}

pub(super) fn verify_local(
    headers: &axum::http::HeaderMap,
    keys: &Jwks,
    constraints: &JwtConstraints,
) -> Result<IdentityClaims> {
    let raw = headers
        .get("x-sekisho-jwt")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow!("no X-Sekisho-Jwt header"))?;
    let header = jsonwebtoken::decode_header(raw).context("decode JWT header")?;
    if header.alg != Algorithm::EdDSA {
        return Err(anyhow!("JWT algorithm is not EdDSA"));
    }
    let kid = header.kid.ok_or_else(|| anyhow!("JWT has no kid"))?;
    let public = keys
        .keys
        .get(&kid)
        .ok_or_else(|| anyhow!("JWT kid is not in the current JWKS"))?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.required_spec_claims = ["exp", "sub", "email", "groups", "iss", "aud", "iat", "nbf"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    validation.set_audience(&[constraints.expected_aud.as_str()]);
    validation.set_issuer(&[constraints.expected_iss.as_str()]);
    validation.validate_aud = true;
    validation.validate_nbf = true;

    let data =
        jsonwebtoken::decode::<IdentityClaims>(raw, &DecodingKey::from_ed_der(public), &validation)
            .context("JWT verification failed")?;
    Ok(data.claims)
}

pub async fn fetch_jwks(
    api_url: &str,
    management_rpk_pin: &sekisho_api_protocol::management_rpk::ManagementRpkPin,
) -> Result<Jwks> {
    let url = format!(
        "{}/.sekisho/api/v1/auth/jwks",
        api_url.trim_end_matches('/')
    );
    let response = crate::client::http_client(management_rpk_pin)?
        .get(url)
        .send()
        .await
        .context("fetch identity JWKS")?
        .error_for_status()
        .context("identity JWKS request rejected")?;
    let (_, bytes) =
        crate::client::read_bounded(response, crate::client::MAX_UPSTREAM_BODY).await?;
    Jwks::parse(&bytes)
}

pub fn spawn_refresh_loop(
    keys: SharedJwks,
    api_url: String,
    management_rpk_pin: sekisho_api_protocol::management_rpk::ManagementRpkPin,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            match fetch_jwks(&api_url, &management_rpk_pin).await {
                Ok(replacement) => {
                    *keys.write().await = replacement;
                    tracing::info!("refreshed public identity JWKS");
                }
                Err(error) => {
                    tracing::warn!(%error, "JWKS refresh failed; retaining previous keys");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    const PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL2MOtYQb2Z9wJrtkrL8tZ2H0LGgEqKnBN46MrVivE0V
-----END PRIVATE KEY-----
"#;

    fn key_set() -> Jwks {
        let x = "1_EqSxWHGu97Epc5QXKRABez7q3F2L21RPEHQq8LsPQ";
        Jwks::parse(
            serde_json::json!({"keys":[{
                "kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig",
                "kid":"current","x":x
            }]})
            .to_string()
            .as_bytes(),
        )
        .unwrap()
    }

    fn token(kid: &str, exp: i64, aud: &str, iss: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut header = jsonwebtoken::Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "sub":"alice@example.com",
                "email":"alice@example.com",
                "groups":["admins"],
                "exp":exp,
                "iat":now,
                "nbf":now,
                "aud":aud,
                "iss":iss
            }),
            &jsonwebtoken::EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap()
    }

    fn headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-sekisho-jwt", token.parse().unwrap());
        headers
    }

    #[test]
    fn jwks_requires_supported_unique_eddsa_keys() {
        let public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let valid = serde_json::json!({
            "keys": [{
                "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                "kid": "current", "x": public
            }]
        });
        assert!(Jwks::parse(valid.to_string().as_bytes()).is_ok());

        let duplicate = serde_json::json!({
            "keys": [
                {"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"same","x":public},
                {"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"same","x":public}
            ]
        });
        assert!(Jwks::parse(duplicate.to_string().as_bytes()).is_err());
        assert!(Jwks::parse(br#"{"keys":[]}"#).is_err());
    }

    #[test]
    fn verifies_only_matching_kid_issuer_audience_and_lifetime() {
        let constraints = JwtConstraints {
            expected_aud: "https://admin.example.com".into(),
            expected_iss: "https://auth.example.com".into(),
        };
        let now = chrono::Utc::now().timestamp();
        let valid = token(
            "current",
            now + 300,
            &constraints.expected_aud,
            &constraints.expected_iss,
        );
        assert!(verify_local(&headers(&valid), &key_set(), &constraints).is_ok());

        let unknown = token(
            "unknown",
            now + 300,
            &constraints.expected_aud,
            &constraints.expected_iss,
        );
        assert!(verify_local(&headers(&unknown), &key_set(), &constraints).is_err());
        let expired = token(
            "current",
            now - 300,
            &constraints.expected_aud,
            &constraints.expected_iss,
        );
        assert!(verify_local(&headers(&expired), &key_set(), &constraints).is_err());
        let wrong_aud = token(
            "current",
            now + 300,
            "https://other.example.com",
            &constraints.expected_iss,
        );
        assert!(verify_local(&headers(&wrong_aud), &key_set(), &constraints).is_err());
    }
}
