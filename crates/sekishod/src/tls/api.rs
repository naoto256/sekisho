//! TLS 1.3 raw-public-key transport for the management listener.
//!
//! RFC 7250 raw public keys instead of X.509. The management API's clients are
//! the operator's own tools, configured with a pin printed by the daemon — so
//! a certificate would only be a wrapper around a key both ends already agree
//! on, and it would drag in an expiry date, a name to get wrong, and a CA
//! decision that has no good answer for a loopback service.
//!
//! What the pin buys: the management listener is authenticated even on first
//! connection, with no trust-on-first-use window and nothing for a local
//! attacker to substitute. TLS 1.3 only, because raw public keys are not
//! negotiable below it.

use std::sync::Arc;

use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::AlwaysResolvesServerRawPublicKeys,
    sign::CertifiedKey,
};

use crate::{
    error::{Error, Result},
    store::instance::ManagementRpkMaterial,
};

/// Build an immutable TLS 1.3 server snapshot from validated local material.
/// Rotation replaces only durable storage; a running listener keeps this
/// snapshot until the process restarts.
pub(crate) fn server_config(material: &ManagementRpkMaterial) -> Result<ServerConfig> {
    sekisho_management_rpk_tls::validate_ed25519_spki(material.public_spki())
        .map_err(|error| Error::Internal(error.to_string()))?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.private_pkcs8().to_vec()));
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|error| Error::Internal(format!("management RPK key unsupported: {error}")))?;
    let derived = signing_key
        .public_key()
        .ok_or_else(|| Error::Internal("management RPK key has no public key".into()))?;
    if derived.as_ref() != material.public_spki() {
        return Err(Error::Internal(
            "management RPK private/public material does not match".into(),
        ));
    }

    let certified_key = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(material.public_spki().to_vec())],
        signing_key,
    ));
    let resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified_key));
    let config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| Error::Internal(format!("management RPK TLS unsupported: {error}")))?
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_tls13_only_rpk_server_config() {
        let material = ManagementRpkMaterial::generate().unwrap();
        let config = server_config(&material).unwrap();
        assert_eq!(config.alpn_protocols, Vec::<Vec<u8>>::new());
    }
}
