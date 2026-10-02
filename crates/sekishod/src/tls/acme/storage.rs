//! Persistence layer for ACME-issued certificates.
//!
//! Owns the encryption of the private key, the `Certificate` row
//! assembly, and the 3-retry upsert against the service DB. Kept
//! separate from `protocol.rs` so the protocol code stays pure
//! (no `Store` dependency) and the orchestrator in `mod.rs` reads as
//! a tiny three-step recipe.
//!
//! Behaviour preserved exactly from the pre-refactor inline path:
//! - 3 attempts at the upsert, with linear backoff (500ms × attempt)
//! - on final failure the cert PEM is logged at error so the operator
//!   can manually recover the issued cert (the ACME directory will
//!   not re-issue without burning another rate-limit slot)
//! - validity is read from the issued leaf certificate, so renewal timing
//!   follows the authority's actual not-before/not-after interval.

use crate::error::{Error, Result};
use crate::models::cert::{CertSource, Certificate};
use crate::store::Store;
use acme_core::IssuedPrivateKey;
use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;

/// Persist a freshly issued ACME cert: encrypt the key, build the
/// `Certificate` row, retry the upsert up to 3 times, and return the
/// row on success. On exhausted retries the cert PEM is logged at
/// `error` and the underlying `sqlx::Error` is returned.
pub(crate) async fn persist_acme_cert(
    store: &Store,
    domain: &str,
    cert_pem: String,
    mut key_pem: IssuedPrivateKey,
) -> Result<Certificate> {
    let (issued_at, expires_at) = parse_validity(&cert_pem)?;
    let encryption = store
        .encrypt_active_to_base64(key_pem.expose_secret().as_bytes())
        .await;
    // Encryption has produced the only value needed by the retrying DB path.
    // Wipe the capability before interpreting the result so both success and
    // error returns release plaintext here; cancellation or panic during the
    // await still falls back to IssuedPrivateKey's drop-time wipe.
    key_pem.zeroize();
    let key_pem_encrypted = encryption.map_err(|e| match e {
        Error::Crypto(inner) => Error::Internal(format!("failed to encrypt private key: {inner}")),
        other => other,
    })?;

    let certificate = Certificate {
        id: Uuid::new_v4(),
        domain: domain.to_string(),
        cert_pem,
        key_pem_encrypted,
        issued_at,
        expires_at,
        source: CertSource::Acme,
    };

    // Retry DB save up to 3 times
    let mut save_err = None;
    for attempt in 1..=3 {
        match store.upsert_cert(&certificate).await {
            Ok(()) => {
                save_err = None;
                break;
            }
            Err(e) => {
                tracing::warn!(domain, attempt, error = %e, "certificate DB save failed, retrying");
                save_err = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(500 * attempt)).await;
            }
        }
    }
    if let Some(e) = save_err {
        tracing::error!(
            domain,
            cert_pem = %certificate.cert_pem,
            "certificate DB save failed after 3 retries — PEM logged for manual recovery"
        );
        return Err(e);
    }

    Ok(certificate)
}

fn parse_validity(pem: &str) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    use x509_parser::prelude::*;
    let (_, parsed_pem) = parse_x509_pem(pem.as_bytes())
        .map_err(|_| Error::Internal("issued ACME certificate PEM is invalid".into()))?;
    if parsed_pem.label != "CERTIFICATE" {
        return Err(Error::Internal(
            "issued ACME certificate PEM has an invalid label".into(),
        ));
    }
    let (_, certificate) = X509Certificate::from_der(&parsed_pem.contents)
        .map_err(|_| Error::Internal("issued ACME certificate DER is invalid".into()))?;
    let validity = certificate.validity();
    let issued_at = Utc
        .timestamp_opt(validity.not_before.timestamp(), 0)
        .single()
        .ok_or_else(|| Error::Internal("issued ACME not-before is out of range".into()))?;
    let expires_at = Utc
        .timestamp_opt(validity.not_after.timestamp(), 0)
        .single()
        .ok_or_else(|| Error::Internal("issued ACME not-after is out of range".into()))?;
    Ok((issued_at, expires_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_validity_comes_from_leaf_certificate() {
        let mut params = rcgen::CertificateParams::new(vec!["validity.example".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2025, 1, 2);
        params.not_after = rcgen::date_time_ymd(2025, 2, 17);
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();

        let (issued_at, expires_at) = parse_validity(&pem).unwrap();
        assert_eq!(
            issued_at,
            Utc.with_ymd_and_hms(2025, 1, 2, 0, 0, 0).unwrap()
        );
        assert_eq!(
            expires_at,
            Utc.with_ymd_and_hms(2025, 2, 17, 0, 0, 0).unwrap()
        );
    }

    /// The public capability has no constructor by design, so keep a source
    /// projection for the consumer boundary itself. The canonical crate tests
    /// the capability's wipe and allocation-transfer behavior; this guard fixes
    /// Sekisho's ownership order across every result path.
    #[test]
    fn issued_private_key_is_wiped_before_result_mapping_and_db_retries() {
        let source = include_str!("storage.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must precede the test module");
        let signature = production
            .find("mut key_pem: IssuedPrivateKey")
            .expect("storage must own the capability by value");
        assert_eq!(production.matches("key_pem.expose_secret()").count(), 1);
        assert!(
            production.contains("encrypt_active_to_base64(key_pem.expose_secret().as_bytes())")
        );
        let borrow = production
            .find("key_pem.expose_secret().as_bytes()")
            .expect("encryption must borrow explicitly without a String copy");
        let encrypted = production[borrow..]
            .find(".await;")
            .map(|offset| borrow + offset)
            .expect("encryption must finish before the key is wiped");
        let wipe = production
            .find("key_pem.zeroize();")
            .expect("plaintext capability must be wiped explicitly");
        let map = production
            .find("encryption.map_err")
            .expect("encryption errors must be mapped after the wipe");
        let certificate = production
            .find("let certificate = Certificate")
            .expect("ciphertext must be retained for persistence");
        let retry = production
            .find("for attempt in 1..=3")
            .expect("DB retry behavior must remain present");

        assert!(signature < borrow);
        assert!(borrow < encrypted);
        assert!(encrypted < wipe);
        assert!(wipe < map);
        assert!(production.contains("Error::Crypto(inner)"));
        assert!(production.contains("other => other"));
        assert!(map < certificate);
        assert!(certificate < retry);
        assert!(!production.contains("key_pem.to_string()"));
        assert!(!production.contains("key_pem.clone()"));
        assert!(!production.contains("format!(\"{key_pem}"));
        assert!(!production.contains("key_pem.into_zeroizing"));
    }
}
