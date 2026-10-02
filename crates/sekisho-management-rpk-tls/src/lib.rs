//! Shared TLS transport predicate for the Sekisho management RPK.
//!
//! A crate of its own, rather than a module in the daemon, because the pin is
//! a contract between four binaries — `sekishod` serves it, `sekisho-cli` and
//! `sekishoweb` verify it, and the integration tests assert on it. Both sides
//! deriving the pin the same way is the whole guarantee, and two
//! implementations of "the same" derivation is exactly the kind of thing that
//! drifts silently.
//!
//! Holds the SPKI validation, the pin format, and the rustls client and server
//! configs — no key generation and no storage, both of which belong to
//! whichever process owns the key material.

use std::{fmt, sync::Arc};

use rustls::{
    DigitallySignedStruct, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls13_signature_with_raw_key},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
};
use sekisho_api_protocol::management_rpk::ManagementRpkPin;

/// Canonical DER prefix for an Ed25519 SubjectPublicKeyInfo followed by its
/// 32-byte public key. Parameters are deliberately absent.
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
pub const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

pub fn validate_ed25519_spki(spki: &[u8]) -> Result<(), InvalidManagementRpk> {
    if spki.len() != ED25519_SPKI_LEN || !spki.starts_with(ED25519_SPKI_PREFIX) {
        return Err(InvalidManagementRpk);
    }
    Ok(())
}

pub fn ed25519_spki_from_public_key(public_key: &[u8]) -> Result<Vec<u8>, InvalidManagementRpk> {
    if public_key.len() != 32 {
        return Err(InvalidManagementRpk);
    }
    let mut spki = Vec::with_capacity(ED25519_SPKI_LEN);
    spki.extend_from_slice(ED25519_SPKI_PREFIX);
    spki.extend_from_slice(public_key);
    Ok(spki)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidManagementRpk;

impl fmt::Display for InvalidManagementRpk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Ed25519 management raw public key")
    }
}

impl std::error::Error for InvalidManagementRpk {}

#[derive(Debug)]
struct PinnedRpkServerVerifier {
    expected_spki: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedRpkServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if !intermediates.is_empty()
            || end_entity.as_ref() != self.expected_spki
            || validate_ed25519_spki(end_entity.as_ref()).is_err()
        {
            return Err(TlsError::General(
                "management raw public key did not match the configured pin".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General(
            "management transport requires TLS 1.3".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        if cert.as_ref() != self.expected_spki {
            return Err(TlsError::General(
                "management raw public key changed during the handshake".into(),
            ));
        }
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

pub fn client_config(pin: &ManagementRpkPin) -> Result<rustls::ClientConfig, InvalidManagementRpk> {
    validate_ed25519_spki(pin.as_bytes())?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinnedRpkServerVerifier {
        expected_spki: pin.as_bytes().to_vec(),
        provider: Arc::clone(&provider),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| InvalidManagementRpk)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_ed25519_spki() {
        let spki = ed25519_spki_from_public_key(&[7; 32]).unwrap();
        validate_ed25519_spki(&spki).unwrap();

        let mut wrong_oid = spki.clone();
        wrong_oid[8] ^= 1;
        assert!(validate_ed25519_spki(&wrong_oid).is_err());
        assert!(validate_ed25519_spki(&spki[..spki.len() - 1]).is_err());
    }

    #[test]
    fn client_config_rejects_non_spki_pin() {
        let pin = ManagementRpkPin::from_opaque_bytes(vec![1; 32]).unwrap();
        assert!(client_config(&pin).is_err());
    }
}
