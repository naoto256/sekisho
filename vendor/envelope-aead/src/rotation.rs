//! Blob-level rotation primitives — peek and per-blob rewrap.

use crate::dek::DekKeyId;
use crate::error::{Error, Result};
use crate::format;
use crate::ring::{DekRing, RewrapOutcome};
use base64::Engine;

/// Peek at the `key_id` of a v3 blob without decrypting.
///
/// Returns `Ok(None)` for v2 (KEK-direct) blobs and `Err` for
/// malformed input. A blob is considered malformed if it is not at
/// least the minimum well-formed length for the version it claims.
/// Useful when bulk-rotating stored blobs: callers can skip entries
/// already on the active DEK without paying a decrypt round-trip.
pub fn peek_key_id(data: &[u8]) -> Result<Option<DekKeyId>> {
    let Some(&version) = data.first() else {
        return Err(Error::CiphertextTooShort);
    };
    match version {
        format::V2 => {
            if data.len() < 1 + format::NONCE_LEN + format::TAG_LEN {
                return Err(Error::CiphertextTooShort);
            }
            Ok(None)
        }
        format::V3 => {
            if data.len() < 2 + format::NONCE_LEN + format::TAG_LEN {
                return Err(Error::CiphertextTooShort);
            }
            let key_id = DekKeyId::new(u16::from(data[1]))?;
            Ok(Some(key_id))
        }
        other => Err(Error::UnknownVersion(other)),
    }
}

/// Base64-column variant of [`peek_key_id`].
pub fn peek_key_id_from_base64(encoded: &str) -> Result<Option<DekKeyId>> {
    let data = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    peek_key_id(&data)
}

/// Decide whether a stored v3 blob needs to be rewrapped under the
/// ring's active DEK, and do so if necessary.
///
/// - Returns [`RewrapOutcome::AlreadyActive`] when the blob's `key_id`
///   already matches the ring's active key — the caller can leave
///   the stored row untouched.
/// - Returns [`RewrapOutcome::Rewrapped`] when the blob was decrypted
///   under a non-active DEK and re-encrypted under the active DEK.
///   The caller should replace the stored row with the returned bytes.
///
/// The per-blob decision is a pure function of the ring and the blob
/// bytes — no storage semantics are baked in. Callers own the outer
/// loop (which table, which row set, which transaction, which audit
/// event), which is why this helper deliberately stops at "one blob".
///
/// v2 (KEK-sealed) blobs are refused with [`Error::VersionMismatch`]
/// — those are ring-independent by design and should never appear in
/// a bulk re-encrypt sweep. If a caller has a v2 blob mixed in, it
/// belongs to a different rotation policy (KEK rotation) that this
/// crate does not currently model.
pub fn rewrap_if_not_active(ring: &DekRing, blob: &[u8]) -> Result<RewrapOutcome> {
    let key_id = match peek_key_id(blob)? {
        Some(id) => id,
        None => {
            return Err(Error::VersionMismatch {
                expected: format::V3,
                actual: blob.first().copied().unwrap_or(0),
            });
        }
    };
    // The blob's DEK must be present in the ring; if the daemon has
    // dropped it (config error), we surface `UnknownKeyId` rather
    // than silently skipping the row.
    let plaintext = ring.decrypt(blob)?;
    if key_id == ring.active_key_id() {
        return Ok(RewrapOutcome::AlreadyActive);
    }
    let rewrapped = ring.encrypt_active(&plaintext)?;
    Ok(RewrapOutcome::Rewrapped(rewrapped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dek::DekPlaintext;
    use crate::kek::Kek;
    use crate::ring::{DekRing, EncryptedDekRecord};
    use zeroize::Zeroizing;

    fn kek() -> Kek {
        Kek::from_bytes(Zeroizing::new([0x77; 32]))
    }

    #[test]
    fn peek_key_id_returns_none_for_v2() {
        let kek = kek();
        let blob = kek.seal(b"handoff").unwrap();
        assert!(peek_key_id(&blob).unwrap().is_none());
    }

    #[test]
    fn peek_key_id_reads_v3_byte() {
        let ring = DekRing::placeholder_single(DekPlaintext::generate().unwrap());
        let blob = ring.encrypt_active(b"payload").unwrap();
        assert_eq!(peek_key_id(&blob).unwrap().unwrap(), ring.active_key_id());
    }

    #[test]
    fn peek_rejects_below_minimum_length() {
        assert!(matches!(
            peek_key_id(&[format::V3, 0x00]).unwrap_err(),
            Error::CiphertextTooShort
        ));
        assert!(matches!(
            peek_key_id(&[format::V2]).unwrap_err(),
            Error::CiphertextTooShort
        ));
    }

    #[test]
    fn peek_rejects_unknown_version() {
        let mut blob = vec![0xFF];
        blob.extend_from_slice(&[0u8; format::NONCE_LEN + format::TAG_LEN]);
        assert!(matches!(
            peek_key_id(&blob).unwrap_err(),
            Error::UnknownVersion(0xFF)
        ));
    }

    /// Two-key ring where an old-key blob rewraps to the new active
    /// key. Confirms `Rewrapped` is returned and the returned bytes
    /// decrypt to the original plaintext under the new active key.
    #[test]
    fn rewrap_moves_blob_from_old_to_active() {
        let kek = kek();
        let dek_old = DekPlaintext::generate().unwrap();
        let dek_new = DekPlaintext::generate().unwrap();

        // Build ring where 0=retired, 1=active.
        let records = vec![
            EncryptedDekRecord {
                key_id: 0,
                encrypted_blob: dek_old.seal_under(&kek).unwrap().into_bytes(),
                active: false,
                retired: true,
            },
            EncryptedDekRecord {
                key_id: 1,
                encrypted_blob: dek_new.seal_under(&kek).unwrap().into_bytes(),
                active: true,
                retired: false,
            },
        ];
        let ring = DekRing::from_encrypted_records(&kek, records, 0).unwrap();

        // Encrypt a payload under the old key (as if it were written
        // before rotation), then rewrap.
        let old_blob = ring
            .encrypt_with(DekKeyId::new(0).unwrap(), b"secret")
            .unwrap();
        let outcome = rewrap_if_not_active(&ring, &old_blob).unwrap();
        match outcome {
            RewrapOutcome::AlreadyActive => panic!("expected Rewrapped"),
            RewrapOutcome::Rewrapped(bytes) => {
                assert_eq!(bytes[1], 1, "rewrapped blob must carry key_id=1");
                assert_eq!(&*ring.decrypt(&bytes).unwrap(), b"secret");
            }
        }
    }

    #[test]
    fn rewrap_returns_already_active_for_current_key() {
        let ring = DekRing::placeholder_single(DekPlaintext::generate().unwrap());
        let blob = ring.encrypt_active(b"payload").unwrap();
        assert!(matches!(
            rewrap_if_not_active(&ring, &blob).unwrap(),
            RewrapOutcome::AlreadyActive
        ));
    }

    #[test]
    fn rewrap_rejects_old_blob_with_active_key_id() {
        let kek = kek();
        let dek_old = DekPlaintext::generate().unwrap();
        let dek_new = DekPlaintext::generate().unwrap();
        let records = vec![
            EncryptedDekRecord {
                key_id: 0,
                encrypted_blob: dek_old.seal_under(&kek).unwrap().into_bytes(),
                active: false,
                retired: true,
            },
            EncryptedDekRecord {
                key_id: 1,
                encrypted_blob: dek_new.seal_under(&kek).unwrap().into_bytes(),
                active: true,
                retired: false,
            },
        ];
        let ring = DekRing::from_encrypted_records(&kek, records, 0).unwrap();
        let mut blob = ring
            .encrypt_with(DekKeyId::new(0).unwrap(), b"secret")
            .unwrap();
        blob[1] = ring.active_key_id().get();

        assert!(matches!(
            rewrap_if_not_active(&ring, &blob).unwrap_err(),
            Error::DecryptionFailed
        ));
    }

    #[test]
    fn rewrap_rejects_tampered_active_blob() {
        let ring = DekRing::placeholder_single(DekPlaintext::generate().unwrap());
        let blob = ring.encrypt_active(b"payload").unwrap();

        let mut nonce_tampered = blob.clone();
        nonce_tampered[2] ^= 0x01;
        let mut tag_tampered = blob;
        let last = tag_tampered.len() - 1;
        tag_tampered[last] ^= 0x01;

        for tampered in [nonce_tampered, tag_tampered] {
            assert!(matches!(
                rewrap_if_not_active(&ring, &tampered).unwrap_err(),
                Error::DecryptionFailed
            ));
        }
    }

    #[test]
    fn rewrap_refuses_v2_blob() {
        // A KEK-sealed blob has ring-independent lifecycle; refusing
        // it here catches the "someone dumped a handoff cookie into
        // the ring rotation walker" bug loudly.
        let kek = kek();
        let ring = DekRing::placeholder_single(DekPlaintext::generate().unwrap());
        let v2 = kek.seal(b"handoff").unwrap();
        assert!(matches!(
            rewrap_if_not_active(&ring, &v2).unwrap_err(),
            Error::VersionMismatch { .. }
        ));
    }

    #[test]
    fn peek_key_id_from_base64_round_trip() {
        let ring = DekRing::placeholder_single(DekPlaintext::generate().unwrap());
        let encoded = ring.encrypt_active_to_base64(b"payload").unwrap();
        assert_eq!(
            peek_key_id_from_base64(&encoded).unwrap().unwrap(),
            ring.active_key_id()
        );
    }
}
