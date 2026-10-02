//! Low-level wire-format constants and primitive AEAD helpers.
//!
//! Deliberately **private**. Callers use the typed API in [`crate::kek`]
//! ([`Kek::seal`](crate::kek::Kek::seal) / [`open`](crate::kek::Kek::open))
//! and [`crate::ring`] ([`DekRing`](crate::ring::DekRing) methods); the
//! raw `[u8; 32]` entry points below never appear in the public surface.
//!
//! # On-the-wire formats
//!
//! ```text
//! v2: 0x02 || nonce(24) || ciphertext+tag
//! v3: 0x03 || key_id(1) || nonce(24) || ciphertext+tag
//! ```
//!
//! Both use XChaCha20-Poly1305 with a 24-byte random nonce and 16-byte
//! Poly1305 tag appended by the AEAD. AAD is empty in both formats —
//! this matches the byte-level layout used by every existing consumer,
//! so envelope-aead can decode blobs written by any of them.
//!
//! # AAD note
//!
//! The header bytes (version, key_id) are NOT authenticated as AAD.
//! Changing the version byte routes to a different decoder, and
//! changing the `key_id` selects a different DEK whose decryption
//! ordinarily fails — so header tampering is caught by AEAD rejection
//! in the normal case. Callers who need explicit header integrity
//! should compose their own AAD scheme above this layer.

use crate::error::{Error, Result};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::Rng;

/// Version byte prefixing every v2 blob (KEK-direct, no key_id).
pub const V2: u8 = 0x02;
/// Version byte prefixing every v3 blob (DEK-routed via a
/// [`DekRing`](crate::ring::DekRing)). Followed by a 1-byte `key_id`.
pub const V3: u8 = 0x03;

/// Length of the XChaCha20 nonce in bytes.
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length, appended to the ciphertext by
/// the AEAD.
pub const TAG_LEN: usize = 16;

/// Encrypt `plaintext` with `key`, producing a v2 blob.
///
/// Layout: `0x02 || nonce(24) || ciphertext+tag`. AAD is empty.
pub(crate) fn encrypt_v2(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce_bytes[..]);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::DecryptionFailed)?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(V2);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a v2 blob with `key`.
///
/// Rejects anything whose first byte is not [`V2`]. Legacy pre-versioned
/// blobs (raw ChaCha20 with a 12-byte nonce, no discriminator) are
/// intentionally unsupported — this crate has never emitted them.
pub(crate) fn decrypt_v2(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 1 + NONCE_LEN + TAG_LEN {
        return Err(Error::CiphertextTooShort);
    }
    if data[0] != V2 {
        return Err(Error::VersionMismatch {
            expected: V2,
            actual: data[0],
        });
    }
    let nonce = XNonce::from_slice(&data[1..1 + NONCE_LEN]);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, &data[1 + NONCE_LEN..])
        .map_err(|_| Error::DecryptionFailed)
}

/// Encrypt `plaintext` with `dek`, producing a v3 blob that records
/// `key_id` for later ring-based dispatch.
///
/// Layout: `0x03 || key_id(1) || nonce(24) || ciphertext+tag`. AAD is
/// empty.
pub(crate) fn encrypt_v3(dek: &[u8; 32], key_id: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(dek.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce_bytes[..]);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::DecryptionFailed)?;
    let mut out = Vec::with_capacity(2 + NONCE_LEN + ct.len());
    out.push(V3);
    out.push(key_id);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a v3 blob with the supplied `dek`. The caller is responsible
/// for having looked up the right DEK by `key_id` (see
/// [`crate::rotation::peek_key_id`]).
///
/// The version byte is re-validated so this entry point is safe even
/// when a caller reaches it without going through the ring dispatch: a
/// v2 blob (or anything else) is rejected with [`Error::VersionMismatch`]
/// rather than silently decrypted with a DEK.
pub(crate) fn decrypt_v3_with(dek: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 2 + NONCE_LEN + TAG_LEN {
        return Err(Error::CiphertextTooShort);
    }
    if data[0] != V3 {
        return Err(Error::VersionMismatch {
            expected: V3,
            actual: data[0],
        });
    }
    let nonce = XNonce::from_slice(&data[2..2 + NONCE_LEN]);
    let cipher = XChaCha20Poly1305::new(dek.into());
    cipher
        .decrypt(nonce, &data[2 + NONCE_LEN..])
        .map_err(|_| Error::DecryptionFailed)
}
