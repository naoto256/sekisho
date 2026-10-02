//! Error type for envelope AEAD operations.

use thiserror::Error;

/// Failure modes for the envelope AEAD helpers.
///
/// Deliberately narrow. Callers wrapping this crate into a daemon-level
/// error enum should implement `From<envelope_aead::Error>` at the
/// boundary.
#[derive(Debug, Error)]
pub enum Error {
    /// The input bytes are too short for the format they claim.
    #[error("ciphertext too short")]
    CiphertextTooShort,

    /// The version byte is not one this crate implements.
    #[error("unknown envelope version byte: 0x{0:02x}")]
    UnknownVersion(u8),

    /// The version byte did not match the specific decoder the caller
    /// dispatched to (e.g. calling `decrypt_v3_with` on a v2 blob).
    #[error("version mismatch: expected 0x{expected:02x}, got 0x{actual:02x}")]
    VersionMismatch { expected: u8, actual: u8 },

    /// The DEK ring does not carry the `key_id` referenced by a v3 blob.
    #[error("unknown key_id: {0}")]
    UnknownKeyId(u8),

    /// AEAD authentication failed. Deliberately opaque — a per-blob
    /// error message would tell an attacker distinguishing information.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Hex decoding of a KEK failed (wrong length, non-hex characters).
    #[error("KEK hex decode failed: {0}")]
    KekHexDecode(String),

    /// Base64 decoding of a blob failed.
    #[error("base64 decode failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// A key id outside the u8 range was supplied to `DekKeyId::new`.
    #[error("key_id {0} exceeds the u8 range (0..=255)")]
    KeyIdOutOfRange(u16),

    /// The plaintext of a v2 DEK blob did not decode to exactly 32
    /// bytes (i.e. the blob claims to hold a DEK but does not).
    #[error("v2 DEK plaintext is {0} bytes, expected 32")]
    DekPlaintextLength(usize),

    /// A `Vec<u8>` handed to [`EncryptedDekBlob::from_bytes`](crate::dek::EncryptedDekBlob::from_bytes)
    /// did not match the fixed on-the-wire length of a v2 DEK blob.
    /// Distinct from [`Error::CiphertextTooShort`] so callers can
    /// distinguish "too short to even parse" from "wrong size for a
    /// DEK blob specifically".
    #[error("v2 DEK blob is {actual} bytes, expected {expected}")]
    InvalidDekBlobLength { actual: usize, expected: usize },

    /// The [`DekRing`](crate::ring::DekRing) was constructed without any active row.
    #[error("no active key_id present in ring entries")]
    NoActiveKey,

    /// Two or more `EncryptedDekRecord`s share the same `key_id`.
    /// Silently letting one win would let a later inactive row hide
    /// an earlier active one, and vice versa — so this is refused.
    #[error("duplicate key_id {0} in ring entries")]
    DuplicateKeyId(u8),

    /// More than one `EncryptedDekRecord` was marked `active = true`.
    /// The ring accepts exactly one active DEK; multiple actives is a
    /// caller-storage-layer bug (missing uniqueness constraint) that
    /// must not surface as "the last-loaded row wins".
    #[error("multiple active key_ids in ring entries")]
    MultipleActiveKeys,

    /// An `EncryptedDekRecord` was flagged both `active = true` and
    /// `retired = true`. Those two states are mutually exclusive by
    /// contract; a row in both is storage corruption and must not
    /// silently participate in the ring.
    #[error("key_id {0} is marked both active and retired")]
    ActiveKeyMarkedRetired(u8),

    /// A random-number-generator error surfaced from the OS.
    #[error("RNG failure: {0}")]
    Rng(String),
}

/// Result alias for envelope AEAD operations.
pub type Result<T> = std::result::Result<T, Error>;
