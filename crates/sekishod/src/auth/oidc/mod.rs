//! sekisho OIDC — HTTP-level handlers, `IdentityProvider` config bridge,
//! and `Store`-bound client_secret decryption.
//!
//! Protocol implementation lives in `auth_idp::oidc`. Call sites import
//! from there directly.

pub mod callback;

use crate::error::{Error, Result};
use crate::models::idp::IdentityProvider;
use auth_idp::oidc::OidcIdpConfig;

impl From<&IdentityProvider> for OidcIdpConfig {
    fn from(idp: &IdentityProvider) -> Self {
        let cfg = idp.oidc_config.as_ref().expect("expected OIDC IdP");
        OidcIdpConfig {
            issuer_url: cfg.issuer_url.clone(),
        }
    }
}

/// Decrypt the stored OIDC client_secret, surfacing any failure as a
/// `ConfigurationError`. Lives in sekisho because it needs `Store`;
/// the result is passed plaintext to auth-idp's `OidcClient::new`.
///
/// We used to silently fall back to treating the stored bytes as
/// plaintext when decryption failed, which hid master key rotation /
/// corruption behind an opaque "upstream refused our credentials"
/// error at token-exchange time.
pub async fn decrypt_oidc_client_secret(
    store: &crate::store::Store,
    encrypted: &str,
) -> Result<String> {
    let bytes = store
        .decrypt_any_from_base64(encrypted)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "failed to decrypt OIDC client_secret; KEK rotation or corrupted record?"
            );
            Error::ConfigurationError(format!(
                "failed to decrypt OIDC client_secret (KEK rotation or corruption?): {e}"
            ))
        })?;
    String::from_utf8(bytes).map_err(|e| {
        Error::ConfigurationError(format!("OIDC client_secret is not valid UTF-8: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store_with_kek(kek: [u8; 32]) -> crate::store::Store {
        crate::store::Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn decrypt_roundtrip_returns_plaintext() {
        let kek = [0x42u8; 32];
        let store = store_with_kek(kek).await;
        let encrypted = store.encrypt_active_to_base64(b"s3cret").await.unwrap();
        let got = decrypt_oidc_client_secret(&store, &encrypted)
            .await
            .unwrap();
        assert_eq!(got, "s3cret");
    }

    #[tokio::test]
    async fn wrong_master_key_surfaces_configuration_error() {
        // Encrypt under one Store, attempt to decrypt under a Store with a
        // different KEK and a different DEK ring — the v3 ring lookup
        // succeeds at finding key_id 0 but the AEAD authentication tag
        // mismatches because the DEK bytes differ.
        let store_a = store_with_kek([0x42u8; 32]).await;
        let store_b = store_with_kek([0x43u8; 32]).await;
        let encrypted = store_a.encrypt_active_to_base64(b"s3cret").await.unwrap();

        let err = decrypt_oidc_client_secret(&store_b, &encrypted)
            .await
            .unwrap_err();
        match err {
            Error::ConfigurationError(msg) => assert!(
                msg.contains("failed to decrypt OIDC client_secret"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected ConfigurationError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn corrupted_base64_surfaces_configuration_error() {
        let store = store_with_kek([0x42u8; 32]).await;
        let err = decrypt_oidc_client_secret(&store, "not-actually-base64!!!")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ConfigurationError(_)));
    }

    #[tokio::test]
    async fn plaintext_legacy_secret_no_longer_silently_accepted() {
        // Pre-fix, a short plaintext value was taken as-is. Now any input
        // that cannot be decrypted must fail loudly so the operator notices.
        let store = store_with_kek([0x42u8; 32]).await;
        let err = decrypt_oidc_client_secret(&store, "plaintext-secret")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ConfigurationError(_)));
    }
}
