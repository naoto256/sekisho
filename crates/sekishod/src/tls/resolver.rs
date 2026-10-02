//! Per-SNI certificate selection for the proxy listener.
//!
//! Implements rustls's [`ResolvesServerCert`], so this code runs inside the
//! TLS handshake. That constraint shapes everything here: the lookup must be
//! synchronous, must never block on I/O, and must always return *something*
//! rather than failing the handshake in a way the client cannot interpret.
//!
//! ## Everything expensive happens at publish time
//!
//! PEM parsing, key-pair verification, SAN extraction and validity-window
//! extraction all happen when a snapshot is built, and the handshake path only
//! reads a prepared map. A certificate that cannot be used is rejected there,
//! where the failure produces a log line an operator can act on, instead of
//! per handshake where it would produce noise and latency.
//!
//! ## Validity is checked on lookup, not only on load
//!
//! Cached entries keep their `not_before` / `not_after` and are compared
//! against the current time at selection. A daemon can outlive a certificate,
//! and serving an expired one is worse than falling back — the browser error
//! for an expired certificate is indistinguishable, to a user, from a
//! compromise.
//!
//! ## The self-signed fallback
//!
//! With no usable certificate for the requested name, a self-signed one is
//! served rather than aborting the handshake. The client gets a warning page
//! it can read, and the daemon stays diagnosable; refusing the handshake
//! outright surfaces as an opaque connection failure with nothing pointing at
//! the certificate as the cause. It is a fallback, never a default — every
//! path that produces one is counted.
//!
//! ## Key/certificate agreement is enforced before anything is stored
//!
//! [`parse_cert_and_key`] compares the leaf's SPKI against the private key's
//! public key. A mismatched pair parses cleanly and only fails during a
//! handshake, which turns an operator's upload typo into an outage discovered
//! by users; checking at admission turns it into a 400.

use crate::store::Store;
use chrono::{DateTime, TimeZone, Utc};
use metrics::{counter, gauge};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// What a published snapshot amounts to.
///
/// Distinguishes the three cases that would otherwise all look like "no
/// certificate available" at lookup time, and which mean very different things
/// to an operator reading metrics: nothing configured yet, at least one usable
/// certificate, or certificates configured but every one of them rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CertCacheOutcome {
    /// No certificates are configured.
    Empty,
    /// At least one certificate loaded and is usable.
    Usable,
    /// Certificates exist but none survived validation — a configuration
    /// fault, not an empty configuration.
    AllInvalid,
}

/// A ready-to-serve certificate plus the validity window needed to re-check
/// it at handshake time. Parsing has already happened; this is what the
/// handshake path is allowed to touch.
struct CachedCertificate {
    certified_key: Arc<CertifiedKey>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

/// An atomically published snapshot: the whole map plus its outcome. Swapped
/// as a unit so a handshake never observes a half-built map.
struct PublishedCertCache {
    entries: HashMap<String, CachedCertificate>,
    outcome: CertCacheOutcome,
}

/// A certificate that has passed every check — pair agreement, validity
/// window, SAN coverage of the intended domain. Returned by
/// [`validate_proxy_certificate`] so the caller stores the already-extracted
/// dates rather than re-parsing the PEM to find them.
pub(crate) struct ValidatedProxyCertificate {
    pub(crate) certified_key: CertifiedKey,
    pub(crate) not_before: DateTime<Utc>,
    pub(crate) not_after: DateTime<Utc>,
}

/// Parse a proxy certificate/key pair and reject an SPKI mismatch before any
/// caller persists or publishes it.
pub(crate) fn parse_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> crate::error::Result<CertifiedKey> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| crate::error::Error::Internal(format!("cert PEM parse: {error}")))?;
    if certs.is_empty() {
        return Err(crate::error::Error::Internal(
            "cert PEM contains no CERTIFICATE block".into(),
        ));
    }
    let private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|error| crate::error::Error::Internal(format!("key PEM parse: {error}")))?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)
        .map_err(|error| crate::error::Error::Internal(format!("key unsupported: {error}")))?;
    let cert_spki = leaf_spki_der(certs[0].as_ref())?;
    let key_spki = signing_key.public_key().ok_or_else(|| {
        crate::error::Error::Internal("private key has no retrievable public key".into())
    })?;
    if cert_spki != key_spki.as_ref() {
        return Err(crate::error::Error::BadRequest(
            "certificate public key does not match the supplied private key".into(),
        ));
    }
    Ok(CertifiedKey::new(certs, signing_key))
}

/// Extract the leaf certificate's SubjectPublicKeyInfo, for comparison
/// against the private key's public half.
fn leaf_spki_der(cert_der: &[u8]) -> crate::error::Result<Vec<u8>> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|error| crate::error::Error::Internal(format!("X509 parse: {error}")))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// SNI-based certificate resolver that loads certificates from the store.
/// Falls back to a self-signed certificate if no matching cert is found.
pub struct CertResolver {
    store: Store,
    cache: RwLock<Option<PublishedCertCache>>,
    fallback: Option<Arc<CertifiedKey>>,
    /// Last `cert_version` we have reloaded against. Compared with
    /// `Store::cert_version_current` by `reload_if_stale` to decide
    /// whether a peer node's write makes the current cache stale.
    /// Zero on startup; incremented by every cert mutation (ACME renew,
    /// mgmt-API upload/delete), so a mismatch after the first reload
    /// reliably signals "someone else moved the DB".
    cert_version_seen: AtomicU64,
}

impl CertResolver {
    pub fn new(store: Store) -> Self {
        let fallback = generate_self_signed_cert().ok().map(Arc::new);
        if fallback.is_some() {
            // Warn rather than info: any TLS handshake that lands on
            // this cert is one a real client should refuse, so the
            // operator wants the event to stand out in the audit
            // stream.
            tracing::warn!(
                target: crate::audit::TARGET,
                event = "tls.fallback.self_signed",
                category = "system",
                result = "success",
                actor_type = "system",
                actor_id = "system",
                "generated self-signed fallback certificate"
            );
        }
        Self {
            store,
            cache: RwLock::new(None),
            fallback,
            cert_version_seen: AtomicU64::new(0),
        }
    }

    /// Whether the last atomically published snapshot is usable now.
    /// Empty stores are ready after their first successful load; a non-empty
    /// store needs at least one certificate whose leaf is still time-valid.
    pub fn is_ready(&self) -> bool {
        self.is_ready_at(Utc::now())
    }

    fn is_ready_at(&self, now: DateTime<Utc>) -> bool {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        match cache.as_ref() {
            None
            | Some(PublishedCertCache {
                outcome: CertCacheOutcome::AllInvalid,
                ..
            }) => false,
            Some(PublishedCertCache {
                outcome: CertCacheOutcome::Empty,
                ..
            }) => true,
            Some(PublishedCertCache {
                entries,
                outcome: CertCacheOutcome::Usable,
            }) => entries
                .values()
                .any(|entry| entry.not_before <= now && now < entry.not_after),
        }
    }

    /// Preload certificates from the database into the cache.
    pub async fn reload(
        &self,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.reload_at(Utc::now()).await
    }

    async fn reload_at(
        &self,
        now: DateTime<Utc>,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Snapshot the version *before* the list read so a concurrent
        // writer doesn't leave us recording a version higher than what
        // we actually loaded. Worst case we under-record by one and
        // reload again on the next tick — safe; over-recording would
        // hide a legitimately stale cache.
        let observed_version = self.store.cert_version_current().await.ok();

        let certs = match self.store.list_certs().await {
            Ok(certs) => certs,
            Err(error) => {
                if self
                    .cache
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_some()
                {
                    tracing::warn!(
                        error = %error,
                        "certificate reload failed; retaining previous cache and readiness outcome"
                    );
                }
                return Err(Box::new(error));
            }
        };
        let row_count = certs.len();
        // Decrypt-and-parse outside the cache lock: the lock is sync
        // (`std::sync::RwLock`) and cannot be held across an `.await`,
        // and the ring decrypt is async because it grabs a tokio lock
        // on the ring snapshot. Pre-build a Vec of (domain, certified
        // key) and bulk-install once everything is ready.
        let mut prepared = HashMap::with_capacity(row_count);
        for cert in certs {
            // sekisho_cert_expiry_seconds is signed: a fresh cert reads
            // positive, an expired one negative. Alert rules fire on
            // `< 7*86400` for "renew imminent" without needing a custom
            // notion of "now" in the query.
            let secs_until_expiry = cert
                .expires_at
                .signed_duration_since(chrono::Utc::now())
                .num_seconds() as f64;
            gauge!("sekisho_cert_expiry_seconds", "domain" => cert.domain.clone())
                .set(secs_until_expiry);

            // Decrypt the private key through the DEK ring. Stored private
            // keys are supported only in the current v3 envelope format.
            let key_pem = match self
                .store
                .decrypt_any_from_base64(&cert.key_pem_encrypted)
                .await
            {
                Ok(decrypted) => match String::from_utf8(decrypted) {
                    Ok(pem) => pem,
                    Err(e) => {
                        tracing::error!(domain = %cert.domain, error = %e, "decrypted key is not valid UTF-8");
                        continue;
                    }
                },
                Err(e) => {
                    tracing::error!(
                        domain = %cert.domain,
                        error = %e,
                        "failed to decrypt certificate private key"
                    );
                    continue;
                }
            };
            match validate_proxy_certificate(&cert.domain, &cert.cert_pem, &key_pem, now) {
                Ok(validated) => {
                    prepared.insert(
                        cert.domain.clone(),
                        CachedCertificate {
                            certified_key: Arc::new(validated.certified_key),
                            not_before: validated.not_before,
                            not_after: validated.not_after,
                        },
                    );
                    tracing::debug!(domain = %cert.domain, "loaded certificate");
                }
                Err(e) => {
                    tracing::error!(domain = %cert.domain, error = %e, "failed to load certificate");
                }
            }
        }

        let outcome = if row_count == 0 {
            CertCacheOutcome::Empty
        } else if prepared.is_empty() {
            CertCacheOutcome::AllInvalid
        } else {
            CertCacheOutcome::Usable
        };
        let loaded_count = prepared.len();
        self.publish(PublishedCertCache {
            entries: prepared,
            outcome,
        });
        tracing::info!(count = loaded_count, ?outcome, "certificates loaded");
        // One bucket per reload regardless of trigger; the audit log
        // already records the trigger (peer_version_bump / acme_finish
        // / boot) for the cases where the distinction matters.
        counter!("sekisho_cert_cache_reloads_total").increment(1);
        if let Some(v) = observed_version {
            self.cert_version_seen.store(v, Ordering::Relaxed);
        }
        Ok(())
    }

    fn publish(&self, snapshot: PublishedCertCache) {
        *self.cache.write().unwrap_or_else(|e| e.into_inner()) = Some(snapshot);
    }

    /// Compare the DB-sourced `cert_version` with our last-loaded
    /// value; attempt a cache reload on mismatch. A peer write bumps
    /// the version, and a later invocation on this node can observe
    /// that mismatch. Only rows that the reload decrypts and parses
    /// successfully are installed.
    ///
    /// On a DB error we keep the existing cache; a wrong (but real)
    /// cert is a better user experience than tearing the table down
    /// because the service DB hiccuped. A later tick can retry.
    pub async fn reload_if_stale(
        &self,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let current = match self.store.cert_version_current().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "cert_version read failed; keeping cache");
                return Ok(false);
            }
        };
        let seen = self.cert_version_seen.load(Ordering::Relaxed);
        if current == seen {
            return Ok(false);
        }
        tracing::info!(
            target: crate::audit::TARGET,
            event = "cert.cache.reload",
            category = "system",
            result = "success",
            actor_type = "system",
            actor_id = "system",
            trigger = "peer_version_bump",
            seen,
            current,
            "cert_version advanced — reloading certificate cache"
        );
        self.reload().await?;
        Ok(true)
    }
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver").finish()
    }
}

impl ResolvesServerCert for CertResolver {
    /// SNI-based lookup: on a hit, return the cached `CertifiedKey`
    /// (`Arc::clone` is the hot-path cost). On a miss — SNI absent,
    /// or SNI present but not in the cache — return the self-signed
    /// `fallback` if `new()` succeeded in generating one, else
    /// `None`.
    ///
    /// This method does not call `reload_if_stale` or otherwise
    /// touch the DB; freshness of the cache is driven by the
    /// caller-side `reload()` / `reload_if_stale()` paths (boot
    /// preload, mgmt-API post-write reload, and the periodic
    /// peer-version tick registered in `runtime::run`).
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name) = client_hello.server_name() {
            let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = cache
                .as_ref()
                .and_then(|snapshot| snapshot.entries.get(server_name))
            {
                return Some(entry.certified_key.clone());
            }
        }
        // Fall back to self-signed cert
        self.fallback.clone()
    }
}

/// Full admission check for a certificate intended to serve `domain`.
///
/// Rejects on any of: an unusable or mismatched key pair, a PEM block that is
/// not a certificate, a validity window that does not contain `now`, or a SAN
/// set that does not cover the domain. `now` is a parameter rather than read
/// here so a caller pins one instant across a batch and tests are
/// deterministic.
///
/// Returns `String` errors rather than [`crate::error::Error`]: every one of
/// them is an operator-facing explanation of what is wrong with their
/// certificate, and the caller decides whether that becomes a 400 or a log
/// line.
pub(crate) fn validate_proxy_certificate(
    domain: &str,
    cert_pem: &str,
    key_pem: &str,
    now: DateTime<Utc>,
) -> std::result::Result<ValidatedProxyCertificate, String> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::*;

    let certified_key = parse_cert_and_key(cert_pem, key_pem)
        .map_err(|error| format!("certificate/key pair invalid: {error}"))?;
    let (_, parsed_pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|error| format!("certificate PEM invalid: {error}"))?;
    if parsed_pem.label != "CERTIFICATE" {
        return Err(format!(
            "certificate PEM invalid: expected CERTIFICATE, got {}",
            parsed_pem.label
        ));
    }
    let (_, leaf) = X509Certificate::from_der(&parsed_pem.contents)
        .map_err(|error| format!("certificate DER invalid: {error}"))?;
    let not_before = Utc
        .timestamp_opt(leaf.validity().not_before.timestamp(), 0)
        .single()
        .ok_or_else(|| "certificate not_before is out of range".to_string())?;
    let not_after = Utc
        .timestamp_opt(leaf.validity().not_after.timestamp(), 0)
        .single()
        .ok_or_else(|| "certificate not_after is out of range".to_string())?;
    if now < not_before {
        return Err(format!("certificate is not valid before {not_before}"));
    }
    if now >= not_after {
        return Err(format!("certificate expired at {not_after}"));
    }

    let san = leaf
        .subject_alternative_name()
        .map_err(|error| format!("certificate SAN invalid: {error}"))?
        .ok_or_else(|| "certificate has no subject alternative name".to_string())?;
    let matches = match domain.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => san.value.general_names.iter().any(
            |name| matches!(name, GeneralName::IPAddress(bytes) if *bytes == address.octets()),
        ),
        Ok(IpAddr::V6(address)) => san.value.general_names.iter().any(
            |name| matches!(name, GeneralName::IPAddress(bytes) if *bytes == address.octets()),
        ),
        Err(_) => san.value.general_names.iter().any(|name| match name {
            GeneralName::DNSName(pattern) => dns_name_matches(pattern, domain),
            _ => false,
        }),
    };
    if !matches {
        return Err("certificate SAN does not cover domain".to_string());
    }

    Ok(ValidatedProxyCertificate {
        certified_key,
        not_before,
        not_after,
    })
}

/// RFC 6125-style SAN matching: exact, or a single leading `*` that covers
/// exactly one label.
///
/// Wildcards deliberately do not nest — `*.example.com` matches
/// `app.example.com` but not `a.b.example.com` — and the empty left label is
/// rejected so `.example.com` cannot match. Non-ASCII input is refused
/// outright rather than case-folded: Unicode case folding is not the
/// comparison DNS names are defined under, and attempting it is how homograph
/// confusions get in.
fn dns_name_matches(pattern: &str, domain: &str) -> bool {
    if !pattern.is_ascii() || !domain.is_ascii() {
        return false;
    }
    if pattern.eq_ignore_ascii_case(domain) {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let Some((left_label, domain_suffix)) = domain.split_once('.') else {
        return false;
    };
    !left_label.is_empty() && domain_suffix.eq_ignore_ascii_case(suffix)
}

/// Generate a self-signed certificate for fallback TLS.
fn generate_self_signed_cert()
-> std::result::Result<CertifiedKey, Box<dyn std::error::Error + Send + Sync>> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "sekisho self-signed");

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    Ok(parse_cert_and_key(&cert_pem, &key_pem)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::cert::{CertSource, Certificate};
    use chrono::{Duration, Utc};
    use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use uuid::Uuid;

    const MASTER_KEY: [u8; 32] = [0x31; 32];

    fn certificate(domain: &str, cert_pem: &str, key_pem_encrypted: String) -> Certificate {
        Certificate {
            id: Uuid::new_v4(),
            domain: domain.to_string(),
            cert_pem: cert_pem.to_string(),
            key_pem_encrypted,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(30),
            source: CertSource::Upload,
        }
    }

    fn certificate_material() -> (String, String) {
        let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        certificate_material_with_params(params)
    }

    fn certificate_material_with_params(params: CertificateParams) -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    fn certificate_material_with_sans(sans: Vec<SanType>) -> (String, String) {
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans;
        certificate_material_with_params(params)
    }

    async fn encrypted_certificate(
        store: &Store,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Certificate {
        let encrypted_key = store
            .encrypt_active_to_base64(key_pem.as_bytes())
            .await
            .unwrap();
        certificate(domain, cert_pem, encrypted_key)
    }

    #[tokio::test]
    async fn reload_skips_plaintext_private_key_and_continues() {
        let store = Store::new_for_test("sqlite::memory:", MASTER_KEY, None)
            .await
            .unwrap();
        let (cert_pem, key_pem) = certificate_material_with_sans(vec![
            SanType::DnsName("a-plaintext.example.com".try_into().unwrap()),
            SanType::DnsName("z-encrypted.example.com".try_into().unwrap()),
        ]);
        let encrypted_key = store
            .encrypt_active_to_base64(key_pem.as_bytes())
            .await
            .unwrap();
        store
            .upsert_cert(&certificate("a-plaintext.example.com", &cert_pem, key_pem))
            .await
            .unwrap();
        store
            .upsert_cert(&certificate(
                "z-encrypted.example.com",
                &cert_pem,
                encrypted_key,
            ))
            .await
            .unwrap();

        let resolver = CertResolver::new(store);
        resolver.reload().await.unwrap();

        let cache = resolver.cache.read().unwrap();
        let entries = &cache.as_ref().unwrap().entries;
        assert!(!entries.contains_key("a-plaintext.example.com"));
        assert!(entries.contains_key("z-encrypted.example.com"));
        assert_eq!(cache.as_ref().unwrap().outcome, CertCacheOutcome::Usable);
        assert!(resolver.is_ready());
    }

    #[tokio::test]
    async fn reload_installs_active_dek_encrypted_private_key() {
        let store = Store::new_for_test("sqlite::memory:", MASTER_KEY, None)
            .await
            .unwrap();
        let (cert_pem, key_pem) = certificate_material_with_sans(vec![SanType::DnsName(
            "encrypted.example.com".try_into().unwrap(),
        )]);
        let encrypted_key = store
            .encrypt_active_to_base64(key_pem.as_bytes())
            .await
            .unwrap();
        store
            .upsert_cert(&certificate(
                "encrypted.example.com",
                &cert_pem,
                encrypted_key,
            ))
            .await
            .unwrap();

        let resolver = CertResolver::new(store);
        resolver.reload().await.unwrap();

        assert!(
            resolver
                .cache
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .entries
                .contains_key("encrypted.example.com")
        );
    }

    #[tokio::test]
    async fn empty_reload_is_ready_and_all_invalid_reload_is_not_ready() {
        let empty_store = Store::new_for_test("sqlite::memory:", MASTER_KEY, None)
            .await
            .unwrap();
        let empty_resolver = CertResolver::new(empty_store);
        assert!(!empty_resolver.is_ready());
        empty_resolver.reload().await.unwrap();
        assert!(empty_resolver.is_ready());
        assert_eq!(
            empty_resolver
                .cache
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .outcome,
            CertCacheOutcome::Empty
        );

        let invalid_store = Store::new_for_test("sqlite::memory:", MASTER_KEY, None)
            .await
            .unwrap();
        let (cert_pem, key_pem) = certificate_material();
        invalid_store
            .upsert_cert(&certificate("example.com", &cert_pem, key_pem))
            .await
            .unwrap();
        let invalid_resolver = CertResolver::new(invalid_store);
        invalid_resolver.reload().await.unwrap();
        assert!(!invalid_resolver.is_ready());
        assert_eq!(
            invalid_resolver
                .cache
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .outcome,
            CertCacheOutcome::AllInvalid
        );
    }

    #[tokio::test]
    async fn reload_rejects_non_utf8_empty_and_mismatched_material() {
        let store = Store::new_for_test("sqlite::memory:", MASTER_KEY, None)
            .await
            .unwrap();
        let (cert_pem, _key_pem) = certificate_material();
        let (_, other_key) = certificate_material();
        let non_utf8 = store.encrypt_active_to_base64(&[0xff, 0xfe]).await.unwrap();
        let empty_key = store.encrypt_active_to_base64(b"").await.unwrap();
        let mismatched_key = store
            .encrypt_active_to_base64(other_key.as_bytes())
            .await
            .unwrap();
        store
            .upsert_cert(&certificate("non-utf8.example.com", &cert_pem, non_utf8))
            .await
            .unwrap();
        store
            .upsert_cert(&certificate("empty.example.com", "", empty_key))
            .await
            .unwrap();
        store
            .upsert_cert(&certificate(
                "mismatch.example.com",
                &cert_pem,
                mismatched_key,
            ))
            .await
            .unwrap();

        let resolver = CertResolver::new(store);
        resolver.reload().await.unwrap();

        let cache = resolver.cache.read().unwrap();
        assert!(cache.as_ref().unwrap().entries.is_empty());
        assert_eq!(
            cache.as_ref().unwrap().outcome,
            CertCacheOutcome::AllInvalid
        );
    }

    #[test]
    fn proxy_predicate_enforces_dns_san_rules_without_cn_fallback() {
        let now = Utc::now();
        let dns = |name: &str| SanType::DnsName(name.try_into().unwrap());

        let (exact_cert, exact_key) = certificate_material_with_sans(vec![dns("Example.COM")]);
        assert!(validate_proxy_certificate("example.com", &exact_cert, &exact_key, now).is_ok());

        let (wild_cert, wild_key) = certificate_material_with_sans(vec![dns("*.example.com")]);
        assert!(validate_proxy_certificate("a.example.com", &wild_cert, &wild_key, now).is_ok());
        assert!(validate_proxy_certificate("example.com", &wild_cert, &wild_key, now).is_err());
        assert!(validate_proxy_certificate("a.b.example.com", &wild_cert, &wild_key, now).is_err());
        assert!(validate_proxy_certificate("badexample.com", &wild_cert, &wild_key, now).is_err());

        let mut cn_only = CertificateParams::default();
        cn_only.distinguished_name = DistinguishedName::new();
        cn_only
            .distinguished_name
            .push(DnType::CommonName, "example.com");
        let (cn_cert, cn_key) = certificate_material_with_params(cn_only);
        assert!(validate_proxy_certificate("example.com", &cn_cert, &cn_key, now).is_err());
    }

    #[test]
    fn proxy_predicate_matches_ip_san_octets_not_textual_dns_san() {
        let now = Utc::now();
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let (ip_cert, ip_key) =
            certificate_material_with_sans(vec![SanType::IpAddress(v4), SanType::IpAddress(v6)]);
        assert!(validate_proxy_certificate("192.0.2.10", &ip_cert, &ip_key, now).is_ok());
        assert!(validate_proxy_certificate("192.0.2.11", &ip_cert, &ip_key, now).is_err());
        assert!(validate_proxy_certificate("::1", &ip_cert, &ip_key, now).is_ok());
        assert!(validate_proxy_certificate("::2", &ip_cert, &ip_key, now).is_err());

        let (text_cert, text_key) = certificate_material_with_sans(vec![SanType::DnsName(
            "192.0.2.10".try_into().unwrap(),
        )]);
        assert!(validate_proxy_certificate("192.0.2.10", &text_cert, &text_key, now).is_err());
    }

    #[test]
    fn proxy_predicate_treats_not_after_as_exclusive() {
        let (cert_pem, key_pem) = certificate_material();
        let valid =
            validate_proxy_certificate("example.com", &cert_pem, &key_pem, Utc::now()).unwrap();
        assert!(
            validate_proxy_certificate(
                "example.com",
                &cert_pem,
                &key_pem,
                valid.not_after - Duration::seconds(1),
            )
            .is_ok()
        );
        assert!(
            validate_proxy_certificate("example.com", &cert_pem, &key_pem, valid.not_after,)
                .is_err()
        );
    }

    #[tokio::test]
    async fn readiness_rechecks_expiry_without_a_database_change() {
        let store = Store::new_for_test("sqlite::memory:", MASTER_KEY, None)
            .await
            .unwrap();
        let (cert_pem, key_pem) = certificate_material();
        let cert = encrypted_certificate(&store, "example.com", &cert_pem, &key_pem).await;
        store.upsert_cert(&cert).await.unwrap();
        let resolver = CertResolver::new(store);
        let loaded_at = Utc::now();
        resolver.reload_at(loaded_at).await.unwrap();
        let not_after = resolver
            .cache
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .entries
            .get("example.com")
            .unwrap()
            .not_after;

        assert!(resolver.is_ready_at(not_after - Duration::seconds(1)));
        assert!(!resolver.is_ready_at(not_after));
    }

    #[tokio::test]
    async fn initial_reload_failure_is_unready() {
        let store = Store::new_for_test_degraded("certificate store unavailable")
            .await
            .unwrap();
        let resolver = CertResolver::new(store);

        assert!(resolver.reload().await.is_err());
        assert!(resolver.cache.read().unwrap().is_none());
        assert!(!resolver.is_ready());
        assert_eq!(resolver.cert_version_seen.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn later_reload_failure_retains_snapshot_and_version() {
        let store = Store::new_for_test("sqlite::memory:", MASTER_KEY, None)
            .await
            .unwrap();
        let (cert_pem, key_pem) = certificate_material();
        let cert = encrypted_certificate(&store, "example.com", &cert_pem, &key_pem).await;
        store.upsert_cert(&cert).await.unwrap();
        let resolver = CertResolver::new(store.clone());
        let now = Utc::now();
        resolver.reload_at(now).await.unwrap();
        let version = resolver.cert_version_seen.load(Ordering::Relaxed);
        let original_key = resolver
            .cache
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .entries
            .get("example.com")
            .unwrap()
            .certified_key
            .clone();

        store.close().await;
        assert!(resolver.reload_at(now).await.is_err());

        let retained_key = resolver
            .cache
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .entries
            .get("example.com")
            .unwrap()
            .certified_key
            .clone();
        assert!(Arc::ptr_eq(&original_key, &retained_key));
        assert!(resolver.is_ready_at(now));
        assert_eq!(resolver.cert_version_seen.load(Ordering::Relaxed), version);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_readers_never_observe_a_mixed_snapshot() {
        let store = Store::new_for_test("sqlite::memory:", MASTER_KEY, None)
            .await
            .unwrap();
        let resolver = Arc::new(CertResolver::new(store));
        let (cert_pem, key_pem) = certificate_material();
        let validated =
            validate_proxy_certificate("example.com", &cert_pem, &key_pem, Utc::now()).unwrap();
        let key = Arc::new(validated.certified_key);
        let barrier = Arc::new(Barrier::new(5));
        let mixed_snapshots = Arc::new(AtomicUsize::new(0));

        let writer = {
            let resolver = resolver.clone();
            let barrier = barrier.clone();
            let key = key.clone();
            std::thread::spawn(move || {
                barrier.wait();
                for index in 0..10_000 {
                    if index % 2 == 0 {
                        resolver.publish(PublishedCertCache {
                            entries: HashMap::new(),
                            outcome: CertCacheOutcome::Empty,
                        });
                    } else {
                        resolver.publish(PublishedCertCache {
                            entries: HashMap::from([(
                                "example.com".to_string(),
                                CachedCertificate {
                                    certified_key: key.clone(),
                                    not_before: validated.not_before,
                                    not_after: validated.not_after,
                                },
                            )]),
                            outcome: CertCacheOutcome::Usable,
                        });
                    }
                }
            })
        };
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let resolver = resolver.clone();
                let barrier = barrier.clone();
                let mixed_snapshots = mixed_snapshots.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..10_000 {
                        let cache = resolver.cache.read().unwrap();
                        let mixed = cache
                            .as_ref()
                            .is_some_and(|snapshot| match snapshot.outcome {
                                CertCacheOutcome::Empty | CertCacheOutcome::AllInvalid => {
                                    !snapshot.entries.is_empty()
                                }
                                CertCacheOutcome::Usable => snapshot.entries.len() != 1,
                            });
                        mixed_snapshots.fetch_add(usize::from(mixed), AtomicOrdering::Relaxed);
                    }
                })
            })
            .collect();

        writer.join().unwrap();
        for reader in readers {
            reader.join().unwrap();
        }
        assert_eq!(mixed_snapshots.load(AtomicOrdering::Relaxed), 0);
    }
}
