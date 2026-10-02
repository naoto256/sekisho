//! In-memory snapshot of the data-encryption-key ring.

use crate::dek::{DekKeyId, DekPlaintext, EncryptedDekBlob};
use crate::error::{Error, Result};
use crate::format;
use crate::kek::Kek;
use base64::Engine;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// One row's worth of information about a stored DEK, generic over the
/// byte container so callers can pass `Vec<u8>`, `&[u8]`, `Bytes`, or
/// whatever their storage layer produces.
///
/// The `active` and `retired` flags are **mutually exclusive**: a row
/// is either **active** (exactly one per ring — the one new encrypts
/// use), **retired** (kept for decrypt only), or neither (staged,
/// waiting to be activated). A row flagged with both is refused by
/// [`DekRing::from_encrypted_records`] as storage corruption.
///
/// The ring itself does not track retired-vs-staged separately; both
/// are just "known DEKs available for decrypt". Daemons that need
/// operational visibility into staging vs. retirement keep that
/// bookkeeping in their storage layer.
#[derive(Debug, Clone)]
pub struct EncryptedDekRecord<B> {
    /// One-byte identifier, range-checked by [`DekKeyId::new`].
    pub key_id: u16,
    /// The KEK-sealed DEK bytes (v2 wire format).
    pub encrypted_blob: B,
    /// `true` for the one DEK new encrypts should target. Must not be
    /// set together with `retired`.
    pub active: bool,
    /// `true` for retired DEKs kept for decrypt only. Must not be set
    /// together with `active`.
    pub retired: bool,
}

/// Outcome of a rotation walk over a stored blob — see
/// [`crate::rotation::rewrap_if_not_active`].
#[derive(Debug)]
pub enum RewrapOutcome {
    /// The blob's `key_id` already matches the ring's active key. No
    /// rewrap performed; the caller can leave the stored row as-is.
    AlreadyActive,
    /// The blob was decrypted under a non-active DEK and re-encrypted
    /// under the active DEK. The caller should replace the stored row
    /// with the returned bytes.
    Rewrapped(Vec<u8>),
}

/// In-process, immutable snapshot of the DEK ring.
///
/// Cheap to `Clone`: internally a `HashMap<DekKeyId, Zeroizing<[u8;32]>>`
/// with a handful of entries plus the active id and a version tag.
/// `Send + Sync + 'static`, so daemons can share it via
/// `Arc<RwLock<DekRing>>` or `Arc<DekRing>` depending on refresh policy.
///
/// **Immutability contract.** A `DekRing` has no interior mutability
/// and no mutation methods: rotation happens by loading a new
/// [`DekRing`] from updated storage records and swapping the caller's
/// held reference. Callers holding an `Arc<DekRing>` see a consistent
/// view for the duration of their read; refreshing the shared handle
/// is a daemon concern.
#[derive(Clone)]
pub struct DekRing {
    /// All DEKs known to this snapshot (active + retired). Lookups by
    /// `key_id`.
    keys: HashMap<DekKeyId, DekPlaintext>,
    /// `key_id` of the DEK that new encrypts go through. Always
    /// present in `keys`.
    active: DekKeyId,
    /// Caller-supplied version tag observed when this snapshot was
    /// built. Useful for staleness detection in a polling refresh
    /// loop, but never interpreted by this crate.
    version: u64,
}

impl std::fmt::Debug for DekRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DekRing")
            .field("active", &self.active)
            .field("version", &self.version)
            .field("keys", &format_args!("<{} redacted DEKs>", self.keys.len()))
            .finish()
    }
}

impl DekRing {
    /// Build a ring from encrypted records already fetched from
    /// storage. Each row's `encrypted_blob` is decrypted with the
    /// supplied `kek`, its length validated (32 bytes), and inserted
    /// into the snapshot.
    ///
    /// Fails closed on ambiguous ring state:
    ///
    /// - a row's `key_id` is outside the u8 range → [`Error::KeyIdOutOfRange`]
    /// - the KEK cannot decrypt a row (wrong KEK, tampered blob) → [`Error::DecryptionFailed`]
    /// - a row decrypts to a plaintext that is not 32 bytes → [`Error::DekPlaintextLength`]
    /// - two or more rows share the same `key_id` → [`Error::DuplicateKeyId`]
    /// - a row is flagged both `active` and `retired` → [`Error::ActiveKeyMarkedRetired`]
    /// - more than one row is marked `active` → [`Error::MultipleActiveKeys`]
    /// - no row is marked `active` → [`Error::NoActiveKey`]
    ///
    /// `version` is opaque metadata (typically a `key_ring_version`
    /// counter the daemon polls); pass `0` if not tracked.
    pub fn from_encrypted_records<B, I>(kek: &Kek, records: I, version: u64) -> Result<Self>
    where
        B: AsRef<[u8]>,
        I: IntoIterator<Item = EncryptedDekRecord<B>>,
    {
        let mut keys: HashMap<DekKeyId, DekPlaintext> = HashMap::new();
        let mut active: Option<DekKeyId> = None;
        for record in records {
            let key_id = DekKeyId::new(record.key_id)?;
            // Reject duplicate key_ids explicitly — a later row silently
            // overwriting an earlier one could hide an active row behind
            // a stale entry, or vice versa. See `Error::DuplicateKeyId`.
            if keys.contains_key(&key_id) {
                return Err(Error::DuplicateKeyId(key_id.get()));
            }
            // `active` and `retired` are mutually exclusive states by
            // contract; both true means storage corruption, not "the
            // ring picks one".
            if record.active && record.retired {
                return Err(Error::ActiveKeyMarkedRetired(key_id.get()));
            }
            let blob = EncryptedDekBlob::from_bytes(record.encrypted_blob.as_ref().to_vec())?;
            let dek = blob.open(kek)?;
            keys.insert(key_id, dek);
            if record.active {
                if active.is_some() {
                    return Err(Error::MultipleActiveKeys);
                }
                active = Some(key_id);
            }
        }
        let active = active.ok_or(Error::NoActiveKey)?;
        // Loop invariant: `active` is only set after `keys.insert(key_id, ..)`
        // succeeds, so a `keys.contains_key(&active)` check here is
        // unreachable in practice. It stayed in an earlier draft as a
        // belt-and-suspenders guard; removed because the public error
        // contract shouldn't advertise unreachable variants.
        Ok(Self {
            keys,
            active,
            version,
        })
    }

    /// Build a ring containing a single DEK at `key_id` 0, active.
    ///
    /// Intended for tests and for caller bootstrap paths where a
    /// fully populated ring is not yet available. Callers should
    /// swap in their real ring once it has been loaded.
    pub fn placeholder_single(dek: DekPlaintext) -> Self {
        let key_id = DekKeyId::new(0).expect("0 is always in range");
        let mut keys = HashMap::new();
        keys.insert(key_id, dek);
        Self {
            keys,
            active: key_id,
            version: 0,
        }
    }

    /// `key_id` of the active DEK (target for new encrypts).
    pub fn active_key_id(&self) -> DekKeyId {
        self.active
    }

    /// Ring version observed when this snapshot was built.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// All `key_id`s currently in the ring. Order is unspecified
    /// (`HashMap`). Useful for caller-side rotation / audit tooling
    /// that needs to detect blobs referencing a key the ring no
    /// longer knows about (a caller config error — see
    /// [`Error::UnknownKeyId`]).
    pub fn known_key_ids(&self) -> Vec<DekKeyId> {
        self.keys.keys().copied().collect()
    }

    /// `true` if the ring holds a DEK for `key_id`.
    pub fn contains(&self, key_id: DekKeyId) -> bool {
        self.keys.contains_key(&key_id)
    }

    /// Encrypt with the active DEK, producing a v3 blob
    /// (`0x03 || key_id || nonce || ciphertext+tag`).
    pub fn encrypt_active(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let dek = self
            .keys
            .get(&self.active)
            .ok_or(Error::UnknownKeyId(self.active.get()))?;
        format::encrypt_v3(dek.as_bytes(), self.active.get(), plaintext)
    }

    /// Encrypt with a specific (typically non-active) DEK. Useful for
    /// caller-side rotation tooling or tests that need to verify
    /// round-trip behaviour against an older key. Normal new encrypts
    /// should use [`Self::encrypt_active`].
    pub fn encrypt_with(&self, key_id: DekKeyId, plaintext: &[u8]) -> Result<Vec<u8>> {
        let dek = self
            .keys
            .get(&key_id)
            .ok_or(Error::UnknownKeyId(key_id.get()))?;
        format::encrypt_v3(dek.as_bytes(), key_id.get(), plaintext)
    }

    /// Decrypt a v3 blob. The blob's `key_id` byte is used to look up
    /// the correct DEK; anything not v3 (e.g. a KEK-sealed v2 blob)
    /// is rejected with [`Error::VersionMismatch`].
    ///
    /// The decrypted plaintext is wrapped in [`Zeroizing`] so it
    /// wipes on drop — since this crate targets at-rest secret
    /// storage (session tokens, TLS private keys, OIDC client
    /// secrets, etc.), callers get memory hygiene for the payload by
    /// default. `Deref` and `AsRef<[u8]>` on the return value read
    /// through to `Vec<u8>`, so existing byte-slice call sites keep
    /// working.
    ///
    /// v3 dispatch is the ring's job. v2 blobs — KEK-sealed
    /// short-lived tokens and bootstrap secrets — belong to
    /// [`Kek::open`] and never come through the ring.
    pub fn decrypt(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if data.len() < 2 + format::NONCE_LEN + format::TAG_LEN {
            return Err(Error::CiphertextTooShort);
        }
        if data[0] != format::V3 {
            return Err(Error::VersionMismatch {
                expected: format::V3,
                actual: data[0],
            });
        }
        let key_id = DekKeyId::new(u16::from(data[1]))?;
        let dek = self
            .keys
            .get(&key_id)
            .ok_or(Error::UnknownKeyId(key_id.get()))?;
        format::decrypt_v3_with(dek.as_bytes(), data).map(Zeroizing::new)
    }

    /// Base64 wrapper around [`Self::encrypt_active`].
    pub fn encrypt_active_to_base64(&self, plaintext: &[u8]) -> Result<String> {
        Ok(base64::engine::general_purpose::STANDARD.encode(self.encrypt_active(plaintext)?))
    }

    /// Base64 wrapper around [`Self::decrypt`]. Return type matches —
    /// the plaintext is wrapped in [`Zeroizing`].
    pub fn decrypt_from_base64(&self, encoded: &str) -> Result<Zeroizing<Vec<u8>>> {
        let data = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        self.decrypt(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> Kek {
        Kek::from_bytes(Zeroizing::new([0x11; 32]))
    }

    /// Round-trip: build a small ring from encrypted records, encrypt
    /// with it, decrypt with it.
    #[test]
    fn ring_round_trip_via_records() {
        let kek = kek();
        let dek_a = DekPlaintext::generate().unwrap();
        let dek_b = DekPlaintext::generate().unwrap();
        let blob_a = dek_a.seal_under(&kek).unwrap();
        let blob_b = dek_b.seal_under(&kek).unwrap();
        let records = vec![
            EncryptedDekRecord {
                key_id: 0,
                encrypted_blob: blob_a.into_bytes(),
                active: false,
                retired: true,
            },
            EncryptedDekRecord {
                key_id: 1,
                encrypted_blob: blob_b.into_bytes(),
                active: true,
                retired: false,
            },
        ];
        let ring = DekRing::from_encrypted_records(&kek, records, 42).unwrap();
        assert_eq!(ring.active_key_id().get(), 1);
        assert_eq!(ring.version(), 42);
        assert!(ring.contains(DekKeyId::new(0).unwrap()));
        assert!(ring.contains(DekKeyId::new(1).unwrap()));

        let blob = ring.encrypt_active(b"payload").unwrap();
        assert_eq!(blob[0], format::V3);
        assert_eq!(blob[1], 1);
        assert_eq!(&*ring.decrypt(&blob).unwrap(), b"payload");
    }

    #[test]
    fn ring_rejects_duplicate_key_id() {
        // Two rows sharing key_id=0: the loader must not let the last
        // one silently win because that would let a later inactive row
        // hide an earlier active row.
        let kek = kek();
        let dek_a = DekPlaintext::generate().unwrap();
        let dek_b = DekPlaintext::generate().unwrap();
        let records = vec![
            EncryptedDekRecord {
                key_id: 0,
                encrypted_blob: dek_a.seal_under(&kek).unwrap().into_bytes(),
                active: true,
                retired: false,
            },
            EncryptedDekRecord {
                key_id: 0,
                encrypted_blob: dek_b.seal_under(&kek).unwrap().into_bytes(),
                active: false,
                retired: true,
            },
        ];
        assert!(matches!(
            DekRing::from_encrypted_records(&kek, records, 0).unwrap_err(),
            Error::DuplicateKeyId(0)
        ));
    }

    #[test]
    fn ring_rejects_active_and_retired_row() {
        // Both flags set on the same row is corrupt storage state.
        // The ring must refuse rather than pick a state silently.
        let kek = kek();
        let dek = DekPlaintext::generate().unwrap();
        let records = vec![EncryptedDekRecord {
            key_id: 0,
            encrypted_blob: dek.seal_under(&kek).unwrap().into_bytes(),
            active: true,
            retired: true,
        }];
        assert!(matches!(
            DekRing::from_encrypted_records(&kek, records, 0).unwrap_err(),
            Error::ActiveKeyMarkedRetired(0)
        ));
    }

    #[test]
    fn ring_rejects_multiple_active_keys() {
        // Two active=true rows: the ring must not silently pick one.
        // Missing uniqueness constraints in the storage layer surface
        // here rather than as "last-loaded wins".
        let kek = kek();
        let dek_a = DekPlaintext::generate().unwrap();
        let dek_b = DekPlaintext::generate().unwrap();
        let records = vec![
            EncryptedDekRecord {
                key_id: 0,
                encrypted_blob: dek_a.seal_under(&kek).unwrap().into_bytes(),
                active: true,
                retired: false,
            },
            EncryptedDekRecord {
                key_id: 1,
                encrypted_blob: dek_b.seal_under(&kek).unwrap().into_bytes(),
                active: true,
                retired: false,
            },
        ];
        assert!(matches!(
            DekRing::from_encrypted_records(&kek, records, 0).unwrap_err(),
            Error::MultipleActiveKeys
        ));
    }

    #[test]
    fn ring_rejects_missing_active() {
        let kek = kek();
        let dek = DekPlaintext::generate().unwrap();
        let blob = dek.seal_under(&kek).unwrap();
        let records = vec![EncryptedDekRecord {
            key_id: 0,
            encrypted_blob: blob.into_bytes(),
            active: false,
            retired: true,
        }];
        assert!(matches!(
            DekRing::from_encrypted_records(&kek, records, 0).unwrap_err(),
            Error::NoActiveKey
        ));
    }

    #[test]
    fn ring_rejects_v2_blob_on_decrypt() {
        let kek = kek();
        let ring = DekRing::placeholder_single(DekPlaintext::generate().unwrap());
        let v2 = kek.seal(b"handoff").unwrap();
        assert!(matches!(
            ring.decrypt(&v2).unwrap_err(),
            Error::VersionMismatch { .. }
        ));
    }

    #[test]
    fn ring_reports_unknown_key_id() {
        let ring = DekRing::placeholder_single(DekPlaintext::generate().unwrap());
        // v3 blob claiming key_id = 5 — not in the placeholder ring.
        let mut fake = vec![format::V3, 0x05];
        fake.extend_from_slice(&[0u8; format::NONCE_LEN + format::TAG_LEN]);
        assert!(matches!(
            ring.decrypt(&fake).unwrap_err(),
            Error::UnknownKeyId(5)
        ));
    }

    #[test]
    fn ring_base64_helpers_round_trip() {
        let ring = DekRing::placeholder_single(DekPlaintext::generate().unwrap());
        let encoded = ring.encrypt_active_to_base64(b"payload").unwrap();
        assert_eq!(&*ring.decrypt_from_base64(&encoded).unwrap(), b"payload");
    }

    #[test]
    fn ring_debug_redacts_dek_material() {
        let ring = DekRing::placeholder_single(DekPlaintext::from_bytes([0xDD; 32]));
        let s = format!("{ring:?}");
        assert!(s.contains("<") && s.contains("redacted DEK"));
        assert!(!s.contains("dddd"));
    }
}
