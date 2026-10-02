//! Durable Ed25519 identity-signing key authority.

use base64::Engine;
use zeroize::Zeroizing;

use crate::crypto::{IdentityKeyRingSnapshot, IdentityPublicKey, IdentitySigningKey};
use crate::error::{Error, Result};

use super::backend::{
    IdentitySigningKeyRow, IdentitySigningReencryptOutcome, IdentitySigningRotateOutcome,
};
use super::{Store, dispatch};

pub(crate) const RETIRING_GRACE_SECS: i64 = 420;

impl Store {
    async fn identity_signing_load_rows(
        &self,
    ) -> Result<(
        u64,
        Vec<IdentitySigningKeyRow>,
        crate::crypto::MasterKeyRing,
    )> {
        dispatch!(self, identity_signing_load)
    }

    pub(crate) async fn identity_signing_version_current(&self) -> Result<u64> {
        dispatch!(self, identity_signing_version_current)
    }

    pub(crate) async fn identity_signing_reencrypt_current(
        &self,
    ) -> Result<IdentitySigningReencryptOutcome> {
        dispatch!(self, identity_signing_reencrypt_current)
    }

    pub(crate) async fn identity_signing_scan_key_id(&self, key_id: u8) -> Result<u64> {
        dispatch!(self, identity_signing_scan_key_id, key_id)
    }

    pub(crate) async fn ensure_identity_signing_ring(
        &self,
    ) -> Result<std::sync::Arc<IdentityKeyRingSnapshot>> {
        let candidate = IdentitySigningKey::generate().map_err(Error::ConfigurationError)?;
        let public_jwk = candidate.public_key().jwk().to_string();
        let _ = dispatch!(
            self,
            identity_signing_bootstrap,
            candidate.kid(),
            candidate.pkcs8(),
            &public_jwk
        )?;
        let snapshot = std::sync::Arc::new(self.load_identity_signing_ring().await?);
        self.replace_identity_key_ring(std::sync::Arc::clone(&snapshot))
            .await;
        Ok(snapshot)
    }

    pub(crate) async fn rotate_identity_signing_ring(
        &self,
    ) -> Result<IdentitySigningRotateOutcome> {
        let candidate = IdentitySigningKey::generate().map_err(Error::ConfigurationError)?;
        let public_jwk = candidate.public_key().jwk().to_string();
        let outcome = dispatch!(
            self,
            identity_signing_rotate,
            candidate.kid(),
            candidate.pkcs8(),
            &public_jwk,
            RETIRING_GRACE_SECS
        )?;
        if outcome == IdentitySigningRotateOutcome::Rotated {
            let snapshot = std::sync::Arc::new(self.load_identity_signing_ring().await?);
            self.replace_identity_key_ring(snapshot).await;
        }
        Ok(outcome)
    }

    pub(crate) async fn refresh_identity_signing_ring(&self) -> Result<()> {
        let snapshot = std::sync::Arc::new(self.load_identity_signing_ring().await?);
        self.replace_identity_key_ring(snapshot).await;
        Ok(())
    }

    async fn load_identity_signing_ring(&self) -> Result<IdentityKeyRingSnapshot> {
        let (version, rows, dek_ring) = self.identity_signing_load_rows().await?;
        let mut current = None;
        let mut retiring = None;
        for row in rows {
            let public = parse_public_jwk(&row.public_jwk, row.retire_until)?;
            if public.kid != row.kid {
                return Err(Error::ConfigurationError(
                    "identity signing kid/public JWK mismatch".into(),
                ));
            }
            match row.state.as_str() {
                "current" => {
                    if current.is_some() {
                        return Err(Error::ConfigurationError(
                            "multiple current identity signing keys".into(),
                        ));
                    }
                    let encrypted = row.private_key_encrypted.ok_or_else(|| {
                        Error::ConfigurationError(
                            "current identity signing key is missing private material".into(),
                        )
                    })?;
                    let plaintext = dek_ring.decrypt_from_base64(&encrypted).map_err(|e| {
                        Error::ConfigurationError(format!(
                            "identity signing key decrypt failed: {e}"
                        ))
                    })?;
                    let signer = IdentitySigningKey::from_pkcs8(Zeroizing::new(
                        plaintext.as_slice().to_vec(),
                    ))
                    .map_err(Error::ConfigurationError)?;
                    if signer.kid() != row.kid {
                        return Err(Error::ConfigurationError(
                            "identity signing private/public key mismatch".into(),
                        ));
                    }
                    current = Some(signer);
                }
                "retiring" => {
                    if retiring.replace(public).is_some() {
                        return Err(Error::ConfigurationError(
                            "multiple retiring identity signing keys".into(),
                        ));
                    }
                }
                _ => {
                    return Err(Error::ConfigurationError(
                        "invalid identity signing key state".into(),
                    ));
                }
            }
        }
        let current = current.ok_or_else(|| {
            Error::ConfigurationError("identity signing ring has no current key".into())
        })?;
        Ok(IdentityKeyRingSnapshot::new(version, current, retiring))
    }
}

fn parse_public_jwk(value: &str, retire_until: Option<i64>) -> Result<IdentityPublicKey> {
    let value: serde_json::Value = serde_json::from_str(value)
        .map_err(|_| Error::ConfigurationError("invalid identity public JWK".into()))?;
    if value.get("kty").and_then(|v| v.as_str()) != Some("OKP")
        || value.get("crv").and_then(|v| v.as_str()) != Some("Ed25519")
        || value.get("alg").and_then(|v| v.as_str()) != Some("EdDSA")
    {
        return Err(Error::ConfigurationError(
            "unsupported identity public JWK".into(),
        ));
    }
    let kid = value
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::ConfigurationError("identity public JWK missing kid".into()))?
        .to_owned();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(
            value
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::ConfigurationError("identity public JWK missing x".into()))?,
        )
        .map_err(|_| Error::ConfigurationError("invalid identity public JWK x".into()))?;
    let public_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::ConfigurationError("invalid Ed25519 public key length".into()))?;
    Ok(IdentityPublicKey {
        kid,
        public_bytes,
        retire_until,
    })
}
