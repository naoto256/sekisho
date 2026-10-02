//! Downstream TLS certificates: the stored form and its redacted projection.

use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A certificate and its private key as held in the store.
///
/// This type never reaches an API response — [`CertificateInfo`] does.
/// `key_pem_encrypted` is sealed with the daemon's master key, so even the
/// stored form does not hold usable key material on its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: Uuid,
    pub domain: String,
    pub cert_pem: String,
    pub key_pem_encrypted: String,
    #[serde(with = "ts_seconds")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub expires_at: DateTime<Utc>,
    pub source: CertSource,
}

/// How a certificate came to exist. Kept because renewal only applies to
/// certificates the daemon issued itself — an uploaded one must be replaced by
/// the operator, and renewing it automatically would silently discard a cert
/// they chose deliberately.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertSource {
    /// Issued by the daemon's ACME client.
    Acme,
    /// Supplied by an operator through the management API.
    Upload,
    /// Generated internally on first startup when no certificate was found.
    /// Only used by the management-API certificate today; never produced by
    /// the ACME / upload paths for proxy-domain certs.
    SelfSigned,
}

/// The API-visible view: every field of [`Certificate`] except the PEM bodies.
///
/// A separate struct rather than `#[serde(skip)]` on the original, so that
/// adding a field to the stored type cannot accidentally publish it — the new
/// field has to be copied here on purpose.
#[derive(Debug, Serialize)]
pub struct CertificateInfo {
    pub id: Uuid,
    pub domain: String,
    #[serde(with = "ts_seconds")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub expires_at: DateTime<Utc>,
    pub source: CertSource,
}

impl From<&Certificate> for CertificateInfo {
    fn from(cert: &Certificate) -> Self {
        Self {
            id: cert.id,
            domain: cert.domain.clone(),
            issued_at: cert.issued_at,
            expires_at: cert.expires_at,
            source: cert.source.clone(),
        }
    }
}
