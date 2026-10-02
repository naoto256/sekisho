//! OIDC Discovery and JWKS (JSON Web Key Set) management.

use crate::error::{Error, Result};
use jsonwebtoken::DecodingKey;
use serde::Deserialize;

/// OIDC Discovery Document
#[derive(Debug, Deserialize)]
pub struct OidcDiscovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[allow(dead_code)]
    pub userinfo_endpoint: Option<String>,
    #[allow(dead_code)]
    pub issuer: Option<String>,
    /// RP-Initiated Logout 1.0 endpoint. Some IdPs (e.g. Google) omit
    /// this; callers can detect `None` and fall back to local-only
    /// sign-out.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// JSON Web Key Set
#[derive(Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Individual JSON Web Key
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub kid: Option<String>,
    #[allow(dead_code)]
    pub alg: Option<String>,
    /// RSA modulus (base64url)
    pub n: Option<String>,
    /// RSA exponent (base64url)
    pub e: Option<String>,
    /// EC x coordinate (base64url)
    pub x: Option<String>,
    /// EC y coordinate (base64url)
    pub y: Option<String>,
    /// EC curve name
    #[allow(dead_code)]
    pub crv: Option<String>,
}

/// Fetch and cache JWKS, find keys by kid, and convert to DecodingKey.
pub struct JwksManager {
    pub jwks: tokio::sync::RwLock<Option<Jwks>>,
}

impl Default for JwksManager {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksManager {
    pub fn new() -> Self {
        Self {
            jwks: tokio::sync::RwLock::new(None),
        }
    }

    /// Fetch JWKS from the IdP and cache it.
    pub async fn fetch(&self, http: &reqwest::Client, jwks_uri: &str) -> Result<()> {
        let jwks_resp = http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| Error::ExternalServiceError(format!("JWKS fetch failed: {e}")))?;
        let jwks_bytes = crate::http::limited_response(jwks_resp, 1024 * 1024)
            .await
            .map_err(|e| Error::ExternalServiceError(format!("JWKS: {e}")))?;
        let jwks: Jwks = serde_json::from_slice(&jwks_bytes)
            .map_err(|e| Error::ExternalServiceError(format!("JWKS parse failed: {e}")))?;

        *self.jwks.write().await = Some(jwks);
        Ok(())
    }

    /// Find a JWK by kid. Re-fetches JWKS once on cache miss (key rotation support).
    pub async fn find_key(
        &self,
        http: &reqwest::Client,
        jwks_uri: &str,
        kid: Option<&str>,
    ) -> Result<DecodingKey> {
        // Ensure JWKS is loaded
        {
            let jwks = self.jwks.read().await;
            if jwks.is_none() {
                drop(jwks);
                self.fetch(http, jwks_uri).await?;
            }
        }

        if let Some(key) = self.lookup_jwk(kid).await {
            return jwk_to_decoding_key(&key);
        }

        // kid not found — re-fetch once (key rotation)
        if kid.is_some() {
            tracing::info!("JWK kid not found in cache, re-fetching JWKS (possible key rotation)");
            self.fetch(http, jwks_uri).await?;
            if let Some(key) = self.lookup_jwk(kid).await {
                return jwk_to_decoding_key(&key);
            }
        }

        Err(Error::KidNotFound(kid.map(String::from)))
    }

    /// Re-fetch the JWKS, replacing any cached value. Use when the
    /// caller knows the key has rotated (e.g. after a kid lookup
    /// miss that warrants more than the one-shot retry baked into
    /// `find_key`).
    pub async fn force_refresh(&self, http: &reqwest::Client, jwks_uri: &str) -> Result<()> {
        self.fetch(http, jwks_uri).await
    }

    async fn lookup_jwk(&self, kid: Option<&str>) -> Option<Jwk> {
        let jwks = self.jwks.read().await;
        let jwks = jwks.as_ref()?;

        if let Some(kid) = kid {
            jwks.keys
                .iter()
                .find(|k| k.kid.as_deref() == Some(kid))
                .cloned()
        } else {
            let signing_keys: Vec<_> = jwks
                .keys
                .iter()
                .filter(|k| k.use_.as_deref() == Some("sig") || k.use_.is_none())
                .collect();
            if signing_keys.len() == 1 {
                Some(signing_keys[0].clone())
            } else {
                None
            }
        }
    }
}

fn jwk_to_decoding_key(key: &Jwk) -> Result<DecodingKey> {
    match key.kty.as_str() {
        "RSA" => {
            let n = key
                .n
                .as_ref()
                .ok_or_else(|| Error::ExternalServiceError("RSA key missing 'n'".into()))?;
            let e = key
                .e
                .as_ref()
                .ok_or_else(|| Error::ExternalServiceError("RSA key missing 'e'".into()))?;
            DecodingKey::from_rsa_components(n, e)
                .map_err(|e| Error::ExternalServiceError(format!("invalid RSA key: {e}")))
        }
        "EC" => {
            let x = key
                .x
                .as_ref()
                .ok_or_else(|| Error::ExternalServiceError("EC key missing 'x'".into()))?;
            let y = key
                .y
                .as_ref()
                .ok_or_else(|| Error::ExternalServiceError("EC key missing 'y'".into()))?;
            DecodingKey::from_ec_components(x, y)
                .map_err(|e| Error::ExternalServiceError(format!("invalid EC key: {e}")))
        }
        other => Err(Error::ExternalServiceError(format!(
            "unsupported key type: {other}"
        ))),
    }
}
