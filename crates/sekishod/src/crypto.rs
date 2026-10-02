//! Envelope-encryption shim over [`envelope_aead`].
//!
//! sekisho was previously coupled to `auth_idp::crypto`; that surface
//! has been extracted to the standalone [`envelope_aead`] crate. This
//! module owns the process-wide root-key capability and the narrow
//! operations that require access to its bytes.

pub use envelope_aead::{
    DekKeyId, DekPlaintext, DekRing as MasterKeyRing, EncryptedDekBlob, EncryptedDekRecord,
    Error as CryptoError, RewrapOutcome, peek_key_id, peek_key_id_from_base64,
};

use envelope_aead::Kek;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Public half of an Ed25519 identity-signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IdentityPublicKey {
    pub(crate) kid: String,
    pub(crate) public_bytes: [u8; 32],
    pub(crate) retire_until: Option<i64>,
}

impl IdentityPublicKey {
    pub(crate) fn jwk(&self) -> serde_json::Value {
        use base64::Engine;
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.public_bytes),
            "kid": self.kid,
            "alg": "EdDSA",
            "use": "sig",
        })
    }

    fn eligible_at(&self, now: i64) -> bool {
        self.retire_until.is_none_or(|until| now <= until)
    }
}

/// Process-owned Ed25519 signer. PKCS#8 bytes zeroize on drop and are never
/// exported through an API.
pub(crate) struct IdentitySigningKey {
    kid: String,
    pkcs8: Zeroizing<Vec<u8>>,
    public_bytes: [u8; 32],
}

impl fmt::Debug for IdentitySigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentitySigningKey")
            .field("kid", &self.kid)
            .field("pkcs8", &"[REDACTED]")
            .finish()
    }
}

impl IdentitySigningKey {
    pub(crate) fn generate() -> Result<Self, String> {
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| "failed to generate Ed25519 key".to_owned())?;
        Self::from_pkcs8(Zeroizing::new(pkcs8.as_ref().to_vec()))
    }

    pub(crate) fn from_pkcs8(pkcs8: Zeroizing<Vec<u8>>) -> Result<Self, String> {
        use base64::Engine;
        use ring::signature::KeyPair;
        use sha2::Digest;
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_slice())
            .map_err(|_| "invalid Ed25519 PKCS#8 key".to_owned())?;
        let public_bytes: [u8; 32] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| "invalid Ed25519 public key length".to_owned())?;
        let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(public_bytes));
        Ok(Self {
            kid,
            pkcs8,
            public_bytes,
        })
    }

    pub(crate) fn kid(&self) -> &str {
        &self.kid
    }

    pub(crate) fn pkcs8(&self) -> &[u8] {
        self.pkcs8.as_slice()
    }

    pub(crate) fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            kid: self.kid.clone(),
            public_bytes: self.public_bytes,
            retire_until: None,
        }
    }

    pub(crate) fn sign<T: Serialize>(
        &self,
        claims: &T,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(
            &header,
            claims,
            &EncodingKey::from_ed_der(self.pkcs8.as_slice()),
        )
    }
}

/// Atomically published identity-key snapshot. This is the sole authority for
/// signing, JWKS membership, and verifier eligibility.
#[derive(Debug)]
pub(crate) struct IdentityKeyRingSnapshot {
    inner: std::sync::RwLock<IdentityKeyRingData>,
}

#[derive(Clone, Debug)]
struct IdentityKeyRingData {
    version: u64,
    current: Arc<IdentitySigningKey>,
    retiring: Option<IdentityPublicKey>,
}

impl IdentityKeyRingSnapshot {
    pub(crate) fn new(
        version: u64,
        current: IdentitySigningKey,
        retiring: Option<IdentityPublicKey>,
    ) -> Self {
        Self {
            inner: std::sync::RwLock::new(IdentityKeyRingData {
                version,
                current: Arc::new(current),
                retiring,
            }),
        }
    }

    pub(crate) fn replace_with(&self, replacement: &Self) {
        let replacement = replacement
            .inner
            .read()
            .expect("identity key-ring read lock poisoned")
            .clone();
        *self
            .inner
            .write()
            .expect("identity key-ring write lock poisoned") = replacement;
    }

    pub(crate) fn version(&self) -> u64 {
        self.inner
            .read()
            .expect("identity key-ring read lock poisoned")
            .version
    }

    pub(crate) fn current_kid(&self) -> String {
        self.inner
            .read()
            .expect("identity key-ring read lock poisoned")
            .current
            .kid()
            .to_owned()
    }

    pub(crate) fn sign<T: Serialize>(
        &self,
        claims: &T,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        self.inner
            .read()
            .expect("identity key-ring read lock poisoned")
            .current
            .sign(claims)
    }

    pub(crate) fn jwks(&self, now: i64) -> serde_json::Value {
        let ring = self
            .inner
            .read()
            .expect("identity key-ring read lock poisoned");
        let mut keys = vec![ring.current.public_key().jwk()];
        if let Some(key) = ring.retiring.as_ref().filter(|key| key.eligible_at(now)) {
            keys.push(key.jwk());
        }
        serde_json::json!({ "keys": keys })
    }

    pub(crate) fn verify<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        validation: &jsonwebtoken::Validation,
        now: i64,
    ) -> Result<jsonwebtoken::TokenData<T>, jsonwebtoken::errors::Error> {
        use jsonwebtoken::Algorithm;
        let header = jsonwebtoken::decode_header(token)?;
        if header.alg != Algorithm::EdDSA {
            return Err(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidAlgorithm,
            ));
        }
        let kid = header.kid.ok_or_else(|| {
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
        })?;
        let ring = self
            .inner
            .read()
            .expect("identity key-ring read lock poisoned");
        let current = ring.current.public_key();
        let key = if current.kid == kid {
            current
        } else if let Some(retiring) = ring
            .retiring
            .as_ref()
            .filter(|key| key.kid == kid && key.eligible_at(now))
        {
            retiring.clone()
        } else {
            return Err(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            ));
        };
        jsonwebtoken::decode::<T>(
            token,
            &jsonwebtoken::DecodingKey::from_ed_der(&key.public_bytes),
            validation,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(_bytes: [u8; 32]) -> Arc<Self> {
        Arc::new(Self::new(
            1,
            IdentitySigningKey::generate().expect("test Ed25519 key"),
            None,
        ))
    }
}

/// Test-only alias kept so test code can name the signing capability without
/// depending on the ring type's current name. Production code uses
/// [`IdentityKeyRingSnapshot`] directly.
#[cfg(test)]
pub(crate) type JwtSigningKey = IdentityKeyRingSnapshot;

/// Process-owned root key for at-rest encryption.
///
/// Long-lived users share this concrete capability through `Arc`; raw key
/// bytes are never exposed. Dependency-owned [`Kek`] scratch copies remain
/// short-lived and zeroize on drop.
pub(crate) struct MasterKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

impl MasterKey {
    /// Consume the sole decoded root-key buffer.
    pub(crate) fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self { bytes }
    }

    /// Explicit test-only bridge from deterministic fixture bytes.
    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; 32]) -> Arc<Self> {
        Arc::new(Self::new(Zeroizing::new(bytes)))
    }

    /// Construct a short-lived dependency capability for DEK ring work.
    pub(crate) fn kek_capability(&self) -> Kek {
        Kek::from_bytes(Zeroizing::new(*self.bytes))
    }

    /// KEK-direct encrypt (v2 envelope).
    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.kek_capability().seal(plaintext)
    }

    /// KEK-direct decrypt (v2 envelope).
    pub(crate) fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.kek_capability().open(data).map(|z| z.to_vec())
    }

    /// Base64-wrapped KEK-direct encrypt.
    pub(crate) fn encrypt_to_base64(&self, plaintext: &[u8]) -> Result<String, CryptoError> {
        self.kek_capability().seal_to_base64(plaintext)
    }

    /// Base64-wrapped KEK-direct decrypt.
    pub(crate) fn decrypt_from_base64(&self, encoded: &str) -> Result<Vec<u8>, CryptoError> {
        self.kek_capability()
            .open_from_base64(encoded)
            .map(|z| z.to_vec())
    }

    /// Compute the fixed API-key HMAC tag without exposing root-key bytes.
    pub(crate) fn api_key_hmac_tag(&self, raw_key: &str) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.bytes)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(raw_key.as_bytes());
        mac.finalize().into_bytes().into()
    }

    #[cfg(test)]
    pub(crate) fn matches_test_bytes(&self, expected: &[u8; 32]) -> bool {
        self.bytes.as_ref() == expected
    }
}

#[cfg(test)]
fn test_master_key(bytes: &[u8; 32]) -> MasterKey {
    MasterKey::new(Zeroizing::new(*bytes))
}

/// Test-only raw-byte adapter for historical crypto fixtures.
#[cfg(test)]
pub fn encrypt(kek_bytes: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    test_master_key(kek_bytes).encrypt(plaintext)
}

/// Test-only raw-byte adapter for historical crypto fixtures.
#[cfg(test)]
pub fn decrypt(kek_bytes: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    test_master_key(kek_bytes).decrypt(data)
}

/// Test-only raw-byte adapter for historical crypto fixtures.
#[cfg(test)]
pub fn encrypt_to_base64(kek_bytes: &[u8; 32], plaintext: &[u8]) -> Result<String, CryptoError> {
    test_master_key(kek_bytes).encrypt_to_base64(plaintext)
}

/// Build a boot-time placeholder ring holding a single freshly-generated
/// DEK. `Store::new` installs it before loading the persisted ring and,
/// after a successful load, overwrites the lock directly. Later runtime
/// refreshes and key-management handlers use `Store::replace_key_ring`.
/// A fresh random DEK avoids reusing one fixed deterministic placeholder
/// across constructions.
pub fn placeholder_ring() -> MasterKeyRing {
    let dek = DekPlaintext::generate().expect("system RNG must be available at boot");
    MasterKeyRing::placeholder_single(dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn master_key_has_drop_owned_redacted_shared_identity() {
        assert!(std::mem::needs_drop::<MasterKey>());

        let owner = MasterKey::from_test_bytes([0xA5; 32]);
        let shared = Arc::clone(&owner);

        assert!(Arc::ptr_eq(&owner, &shared));
        assert_eq!(Arc::strong_count(&owner), 2);
        assert_eq!(format!("{owner:?}"), "MasterKey([REDACTED])");
    }

    #[test]
    fn identity_key_ring_signs_and_verifies_eddsa_with_kid() {
        use jsonwebtoken::{Algorithm, Validation};
        let owner = IdentitySigningKey::generate().unwrap();
        let claims = serde_json::json!({
            "sub": "alice@example.com",
            "exp": chrono::Utc::now().timestamp() + 60,
        });
        let snapshot = IdentityKeyRingSnapshot::new(1, owner, None);
        let token = snapshot.sign(&claims).expect("sign claims");
        let current_kid = snapshot.current_kid();
        assert_eq!(
            jsonwebtoken::decode_header(&token).unwrap().kid.as_deref(),
            Some(current_kid.as_str())
        );
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        validation.required_spec_claims.insert("exp".into());
        let decoded = snapshot
            .verify::<serde_json::Value>(&token, &validation, chrono::Utc::now().timestamp())
            .expect("verify claims");
        assert_eq!(decoded.claims["sub"], "alice@example.com");
    }
}
