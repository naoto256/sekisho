//! Data encryption key (DEK) types and the KEK-sealed DEK blob.

use crate::error::{Error, Result};
use crate::format;
use crate::kek::Kek;
use rand::TryRngCore;
use zeroize::Zeroizing;

/// A 32-byte data encryption key, held in [`Zeroizing`] storage so the
/// plaintext bytes are wiped from memory on drop.
///
/// Callers never construct a `DekPlaintext` from bytes they typed
/// themselves — this crate produces DEKs via [`DekPlaintext::generate`]
/// or by KEK-decrypting an [`EncryptedDekBlob`]. That way every DEK in
/// circulation has a known provenance.
#[derive(Clone)]
pub struct DekPlaintext {
    bytes: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for DekPlaintext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DekPlaintext")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl DekPlaintext {
    /// Generate a fresh 32-byte DEK using the OS random source.
    ///
    /// Errors only if the underlying RNG fails to produce entropy — on
    /// modern platforms this indicates a serious system problem
    /// (unseeded /dev/urandom, missing `getrandom`), so the caller
    /// should refuse to boot.
    ///
    /// The RNG fills a [`Zeroizing`]-wrapped `[u8; 32]` directly, so
    /// no plain-stack copy of the generated DEK ever exists.
    pub fn generate() -> Result<Self> {
        let mut bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(bytes.as_mut_slice())
            .map_err(|e| Error::Rng(e.to_string()))?;
        Ok(Self { bytes })
    }

    /// Wrap already-obtained DEK bytes. Test-only — production paths
    /// build a `DekPlaintext` either via [`DekPlaintext::generate`] or
    /// by KEK-decrypting an [`EncryptedDekBlob`], both of which fill a
    /// [`Zeroizing`]-wrapped buffer directly without a caller-supplied
    /// array.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Access the raw DEK bytes. Private to the crate.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Seal this DEK under a KEK, producing an [`EncryptedDekBlob`]
    /// ready to be persisted alongside its `key_id`.
    pub fn seal_under(&self, kek: &Kek) -> Result<EncryptedDekBlob> {
        let blob = format::encrypt_v2(kek.as_bytes(), self.as_bytes())?;
        Ok(EncryptedDekBlob { bytes: blob })
    }
}

/// One-byte identifier for a DEK inside a [`DekRing`](crate::ring::DekRing).
///
/// Wire-format constrains the on-the-wire representation to a single
/// byte, so the space is `0..=255`. The type accepts `u16` at the API
/// boundary purely to make range validation explicit; the byte on the
/// wire is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DekKeyId(u8);

impl DekKeyId {
    /// Range-checked constructor.
    pub fn new(id: u16) -> Result<Self> {
        u8::try_from(id)
            .map(Self)
            .map_err(|_| Error::KeyIdOutOfRange(id))
    }

    /// Underlying byte value.
    pub fn get(self) -> u8 {
        self.0
    }
}

impl std::fmt::Display for DekKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A v2 envelope blob whose plaintext is required to be exactly a
/// 32-byte DEK.
///
/// Wraps a `Vec<u8>` at the byte level with the layout
/// `0x02 || nonce(24) || ciphertext+tag(48)` for a total length of
/// `1 + 24 + 32 + 16 = 73` bytes. Any other length is rejected by
/// [`EncryptedDekBlob::from_bytes`].
///
/// The type exists so daemons that persist DEK records get a real
/// invariant on what "an encrypted DEK" is — a naked `Vec<u8>`
/// column value could be a v2 blob carrying arbitrary plaintext (the
/// `Kek::seal` shape) and the ring loader would only find out at
/// decrypt time, then too late.
#[derive(Clone, Debug)]
pub struct EncryptedDekBlob {
    bytes: Vec<u8>,
}

impl EncryptedDekBlob {
    /// Length of a well-formed encrypted DEK blob:
    /// `version(1) || nonce(24) || ct+tag(48)`.
    pub const LEN: usize = 1 + format::NONCE_LEN + 32 + format::TAG_LEN;

    /// Take ownership of raw bytes and enforce the length + version
    /// invariants. Wrong-length input surfaces as
    /// [`Error::InvalidDekBlobLength`] (distinct from
    /// [`Error::CiphertextTooShort`] so callers can tell "too short to
    /// even parse" apart from "wrong size for a DEK blob").
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != Self::LEN {
            return Err(Error::InvalidDekBlobLength {
                actual: bytes.len(),
                expected: Self::LEN,
            });
        }
        if bytes[0] != format::V2 {
            return Err(Error::VersionMismatch {
                expected: format::V2,
                actual: bytes[0],
            });
        }
        Ok(Self { bytes })
    }

    /// Immutable view of the encrypted bytes. Suitable for writing
    /// into a `BLOB` / `bytea` column or base64-encoding into a `TEXT`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the blob and return the owned byte buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Decrypt back to the DEK plaintext under the supplied KEK.
    ///
    /// The intermediate `Vec<u8>` produced by the AEAD is wrapped in
    /// [`Zeroizing`] so the decrypted DEK bytes are wiped as soon as
    /// they have been copied into the [`DekPlaintext`] return value.
    pub fn open(&self, kek: &Kek) -> Result<DekPlaintext> {
        let plaintext: Zeroizing<Vec<u8>> =
            Zeroizing::new(format::decrypt_v2(kek.as_bytes(), &self.bytes)?);
        // The blob-length invariant guarantees this, but re-check
        // defensively in case a caller circumvented `from_bytes`
        // (constructed via serde, unsafe transmute, etc.).
        if plaintext.len() != 32 {
            return Err(Error::DekPlaintextLength(plaintext.len()));
        }
        let mut dek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        dek_bytes.copy_from_slice(&plaintext);
        Ok(DekPlaintext { bytes: dek_bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_distinct_deks() {
        // Sanity: two generations should differ with overwhelming
        // probability. A collision would either mean the RNG is
        // constant (bug) or something extraordinary.
        let a = DekPlaintext::generate().unwrap();
        let b = DekPlaintext::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn dek_seal_round_trip() {
        let kek = Kek::from_bytes(Zeroizing::new([0x42; 32]));
        let dek = DekPlaintext::generate().unwrap();
        let original_bytes = *dek.as_bytes();
        let blob = dek.seal_under(&kek).unwrap();
        assert_eq!(blob.as_bytes().len(), EncryptedDekBlob::LEN);
        let opened = blob.open(&kek).unwrap();
        assert_eq!(opened.as_bytes(), &original_bytes);
    }

    #[test]
    fn encrypted_dek_blob_rejects_wrong_length() {
        // Both too-short (72) and too-long (74) must be refused before
        // any AEAD work, and both must surface as InvalidDekBlobLength
        // (not CiphertextTooShort) so callers can tell them apart from
        // a truncated blob at the low-level decoder.
        let short = vec![format::V2; EncryptedDekBlob::LEN - 1];
        assert!(matches!(
            EncryptedDekBlob::from_bytes(short).unwrap_err(),
            Error::InvalidDekBlobLength { actual, expected }
                if actual == EncryptedDekBlob::LEN - 1 && expected == EncryptedDekBlob::LEN
        ));
        let long = vec![format::V2; EncryptedDekBlob::LEN + 1];
        assert!(matches!(
            EncryptedDekBlob::from_bytes(long).unwrap_err(),
            Error::InvalidDekBlobLength { actual, expected }
                if actual == EncryptedDekBlob::LEN + 1 && expected == EncryptedDekBlob::LEN
        ));
    }

    #[test]
    fn encrypted_dek_blob_rejects_v3_version_byte() {
        let mut bytes = vec![0u8; EncryptedDekBlob::LEN];
        bytes[0] = format::V3;
        assert!(matches!(
            EncryptedDekBlob::from_bytes(bytes).unwrap_err(),
            Error::VersionMismatch { .. }
        ));
    }

    #[test]
    fn dek_key_id_range_check() {
        assert_eq!(DekKeyId::new(0).unwrap().get(), 0);
        assert_eq!(DekKeyId::new(255).unwrap().get(), 255);
        assert!(matches!(
            DekKeyId::new(256).unwrap_err(),
            Error::KeyIdOutOfRange(256)
        ));
    }

    #[test]
    fn dek_debug_does_not_leak() {
        let dek = DekPlaintext::from_bytes([0xEE; 32]);
        let s = format!("{dek:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("eeee"));
    }
}
