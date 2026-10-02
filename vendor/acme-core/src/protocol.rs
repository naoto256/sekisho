//! ACME order driver for a durable [`crate::AcmeAccount`].

use std::{fmt, sync::Arc, time::Duration};

use instant_acme::{
    Account, AuthorizationStatus, CertificateIdentifier, ChallengeType, Identifier, NewOrder,
    Order, OrderStatus, RetryPolicy,
};
use rustls_pki_types::CertificateDer;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{ChallengeProvider, Error, Result, account::map_instant_error};

const POLL_TIMEOUT: Duration = Duration::from_secs(60);

/// Explicit owner of a freshly issued PEM-encoded private key.
///
/// The owned PEM buffer is wiped on drop. Borrowing or transferring it requires
/// an explicitly named operation so secret exposure remains visible at call
/// sites. This best-effort guarantee covers only this capability's buffer;
/// callers own any copies they create, and dependency-internal temporary
/// buffers are outside this contract.
///
/// `IssuedPrivateKey` intentionally implements none of the common implicit
/// exposure or duplication traits:
///
/// ```compile_fail,E0277
/// use acme_core::IssuedPrivateKey;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<IssuedPrivateKey>();
/// ```
///
/// ```compile_fail,E0277
/// use acme_core::IssuedPrivateKey;
/// fn requires_display<T: std::fmt::Display>() {}
/// requires_display::<IssuedPrivateKey>();
/// ```
///
/// ```compile_fail,E0277
/// use acme_core::IssuedPrivateKey;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<IssuedPrivateKey>();
/// ```
///
/// ```compile_fail,E0277
/// use acme_core::IssuedPrivateKey;
/// fn requires_partial_eq<T: PartialEq>() {}
/// requires_partial_eq::<IssuedPrivateKey>();
/// ```
///
/// ```compile_fail,E0277
/// use acme_core::IssuedPrivateKey;
/// fn requires_deref<T: std::ops::Deref<Target = str>>() {}
/// requires_deref::<IssuedPrivateKey>();
/// ```
///
/// ```compile_fail,E0277
/// use acme_core::IssuedPrivateKey;
/// fn requires_as_ref<T: AsRef<str>>() {}
/// requires_as_ref::<IssuedPrivateKey>();
/// ```
///
/// ```compile_fail,E0277
/// use acme_core::IssuedPrivateKey;
/// fn requires_borrow<T: std::borrow::Borrow<str>>() {}
/// requires_borrow::<IssuedPrivateKey>();
/// ```
pub struct IssuedPrivateKey {
    pem: Zeroizing<String>,
}

impl IssuedPrivateKey {
    fn new(pem: String) -> Self {
        Self {
            pem: Zeroizing::new(pem),
        }
    }

    /// Borrow the PEM without creating a copy.
    pub fn expose_secret(&self) -> &str {
        self.pem.as_str()
    }

    /// Transfer ownership of the zeroizing PEM buffer without copying it.
    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.pem
    }

    /// Wipe the PEM before its normal drop point.
    pub fn zeroize(&mut self) {
        self.pem.zeroize();
    }
}

impl ZeroizeOnDrop for IssuedPrivateKey {}

impl fmt::Debug for IssuedPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedPrivateKey([REDACTED])")
    }
}

/// Certificate chain and private key produced by one successful order.
pub struct IssuedCertificate {
    /// PEM-encoded certificate chain returned by the ACME directory.
    pub certificate_pem: String,
    /// PEM-encoded freshly generated private key with zeroizing ownership.
    pub private_key_pem: IssuedPrivateKey,
}

impl fmt::Debug for IssuedCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedCertificate")
            .field("certificate_pem", &self.certificate_pem)
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

pub(crate) async fn issue<C: ChallengeProvider>(
    account: &Account,
    domain: &str,
    challenge: &Arc<C>,
    predecessor_der: Option<&[u8]>,
    timeout: Option<Duration>,
) -> Result<IssuedCertificate> {
    if challenge.challenge_type() != ChallengeType::Http01 {
        return Err(Error::Internal(
            "only the HTTP-01 challenge is supported".into(),
        ));
    }

    let predecessor = predecessor_der.map(certificate_identifier).transpose()?;
    let mut set_called = false;
    let order = issue_inner(
        account,
        domain,
        challenge,
        predecessor.as_ref(),
        &mut set_called,
    );
    let result = match timeout {
        Some(timeout) => match tokio::time::timeout(timeout, order).await {
            Ok(result) => result,
            Err(_) => Err(Error::Transient("ACME order timed out".into())),
        },
        None => order.await,
    };
    if set_called && challenge.cleanup(domain).await.is_err() {
        tracing::warn!("ACME challenge cleanup failed");
    }
    result
}

async fn issue_inner<C: ChallengeProvider>(
    account: &Account,
    domain: &str,
    challenge: &Arc<C>,
    predecessor: Option<&CertificateIdentifier<'_>>,
    set_called: &mut bool,
) -> Result<IssuedCertificate> {
    let identifiers = [Identifier::Dns(domain.to_owned())];
    let mut order = new_order(account, &identifiers, predecessor).await?;

    {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization.map_err(map_instant_error)?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => {
                    return Err(Error::Rejected(
                        "ACME authorization entered a terminal state".into(),
                    ));
                }
            }
            let mut acme_challenge = authorization
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| Error::Rejected("HTTP-01 challenge unavailable".into()))?;
            let key_authorization = acme_challenge.key_authorization();
            *set_called = true;
            challenge
                .set(domain, &acme_challenge.token, key_authorization.as_str())
                .await
                .map_err(Error::Challenge)?;
            acme_challenge
                .set_ready()
                .await
                .map_err(map_instant_error)?;
        }
    }

    let retries = RetryPolicy::new()
        .initial_delay(Duration::from_secs(2))
        .backoff(1.0)
        .timeout(POLL_TIMEOUT);
    match order
        .poll_ready(&retries)
        .await
        .map_err(map_instant_error)?
    {
        OrderStatus::Ready | OrderStatus::Valid => {}
        OrderStatus::Invalid => {
            return Err(Error::Rejected("ACME order was rejected".into()));
        }
        _ => return Err(Error::Transient("ACME order did not become ready".into())),
    }

    let mut parameters = rcgen::CertificateParams::new(vec![domain.to_owned()])
        .map_err(|_| Error::Internal("failed to construct certificate parameters".into()))?;
    parameters.distinguished_name = rcgen::DistinguishedName::new();
    let private_key = rcgen::KeyPair::generate()
        .map_err(|_| Error::Internal("failed to generate certificate key".into()))?;
    let request = parameters
        .serialize_request(&private_key)
        .map_err(|_| Error::Internal("failed to construct certificate request".into()))?;
    order
        .finalize_csr(request.der())
        .await
        .map_err(map_instant_error)?;
    let certificate_pem = order
        .poll_certificate(&retries)
        .await
        .map_err(map_instant_error)?;
    Ok(IssuedCertificate {
        certificate_pem,
        private_key_pem: IssuedPrivateKey::new(private_key.serialize_pem()),
    })
}

pub(crate) async fn new_order(
    account: &Account,
    identifiers: &[Identifier],
    predecessor: Option<&CertificateIdentifier<'_>>,
) -> Result<Order> {
    if let Some(predecessor) = predecessor {
        let replacement = NewOrder::new(identifiers).replaces(predecessor.clone());
        match account.new_order(&replacement).await {
            Ok(order) => return Ok(order),
            Err(instant_acme::Error::Unsupported(_)) => {}
            Err(error) => return Err(map_instant_error(error)),
        }
    }
    account
        .new_order(&NewOrder::new(identifiers))
        .await
        .map_err(map_instant_error)
}

fn certificate_identifier(certificate_der: &[u8]) -> Result<CertificateIdentifier<'static>> {
    CertificateIdentifier::try_from(&CertificateDer::from(certificate_der))
        .map(CertificateIdentifier::into_owned)
        .map_err(|_| Error::InvalidPredecessorCertificate)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct RecordingProvider {
        calls: Mutex<Vec<&'static str>>,
    }

    impl ChallengeProvider for RecordingProvider {
        fn challenge_type(&self) -> ChallengeType {
            ChallengeType::Http01
        }

        async fn set(
            &self,
            _domain: &str,
            _token: &str,
            _key_auth: &str,
        ) -> std::result::Result<(), crate::ProviderError> {
            self.calls.lock().unwrap().push("set");
            Ok(())
        }

        async fn cleanup(&self, _domain: &str) -> std::result::Result<(), crate::ProviderError> {
            self.calls.lock().unwrap().push("cleanup");
            Ok(())
        }
    }

    #[tokio::test]
    async fn challenge_provider_records_set_and_cleanup() {
        let provider = RecordingProvider {
            calls: Mutex::new(Vec::new()),
        };
        provider.set("d", "tok", "ka").await.unwrap();
        provider.cleanup("d").await.unwrap();
        assert_eq!(*provider.calls.lock().unwrap(), vec!["set", "cleanup"]);
    }

    #[test]
    fn malformed_predecessor_is_rejected_before_order_creation() {
        let error = certificate_identifier(b"not-a-certificate").unwrap_err();
        assert!(matches!(error, Error::InvalidPredecessorCertificate));
    }

    #[test]
    fn issued_certificate_debug_redacts_private_key() {
        let issued = IssuedCertificate {
            certificate_pem: "public-certificate".into(),
            private_key_pem: IssuedPrivateKey::new("private-key-sentinel".into()),
        };
        let debug = format!("{issued:?}");
        assert!(debug.contains("public-certificate"));
        assert!(!debug.contains("private-key-sentinel"));
    }

    #[test]
    fn issued_private_key_has_explicit_zeroizing_ownership() {
        fn requires_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        requires_zeroize_on_drop::<IssuedPrivateKey>();
        assert!(std::mem::needs_drop::<IssuedPrivateKey>());

        let mut key = IssuedPrivateKey::new("private-key-sentinel".into());
        assert_eq!(key.expose_secret(), "private-key-sentinel");
        assert!(!format!("{key:?}").contains("private-key-sentinel"));
        key.zeroize();
        assert!(key.expose_secret().is_empty());
    }

    #[test]
    fn issued_private_key_transfer_reuses_the_owned_allocation() {
        let key = IssuedPrivateKey::new("private-key-sentinel".into());
        let allocation = key.expose_secret().as_ptr();
        let transferred = key.into_zeroizing();

        assert_eq!(allocation, transferred.as_ptr());
        assert_eq!(transferred.as_str(), "private-key-sentinel");
    }
}
