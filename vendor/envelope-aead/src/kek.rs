//! Key-encryption key (KEK) — the long-lived 32-byte root secret that
//! wraps every DEK the daemon uses.

use crate::error::{Error, Result};
use crate::format;
use base64::Engine;
use zeroize::Zeroizing;

/// A 32-byte root key used to wrap Data Encryption Keys (DEKs) and to
/// seal a small class of ring-independent secrets.
///
/// The key material is stored in a `Zeroizing<[u8; 32]>` so it is
/// wiped from memory when the [`Kek`] is dropped. `Debug` is redacted
/// so key bytes never surface in `tracing` output or panic backtraces.
///
/// A `Kek` is `Clone` only if the caller opts in — in practice you
/// hold one and pass `&Kek` down; the type does not implement `Clone`
/// to keep the number of copies of the key material minimal.
pub struct Kek {
    bytes: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Kek {
    // Redact key material so `tracing` / panic backtraces never spill
    // KEK bytes into logs. No non-secret metadata to include — the KEK
    // carries none.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kek").field("bytes", &"<redacted>").finish()
    }
}

impl Kek {
    /// Build a KEK from raw bytes. The caller passes a
    /// [`Zeroizing`]-wrapped array so the *entire* lifetime of the
    /// bytes — including the caller's own buffer — is under the same
    /// wipe-on-drop discipline this crate maintains internally.
    ///
    /// Taking `[u8; 32]` by value would ABI-copy the 32 bytes onto
    /// the callee stack and leave a plain array behind; forcing
    /// [`Zeroizing<[u8; 32]>`] at the boundary makes it impossible to
    /// spell a plain-copy KEK ingress.
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self { bytes }
    }

    /// Parse a 64-character hex string (case-insensitive) into a KEK.
    ///
    /// The env-var name and source policy (env / file / KMS) is a
    /// daemon decision; this crate deliberately takes the parsed hex
    /// string. Non-hex characters and wrong-length inputs surface as
    /// [`Error::KekHexDecode`].
    ///
    /// Intermediate buffers (the `Vec<u8>` produced by `hex::decode`
    /// and the staged `[u8; 32]`) are wrapped in [`Zeroizing`] so the
    /// parsed key bytes never sit in stray memory after the call
    /// returns.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let raw: Zeroizing<Vec<u8>> =
            Zeroizing::new(hex::decode(hex).map_err(|e| Error::KekHexDecode(e.to_string()))?);
        if raw.len() != 32 {
            return Err(Error::KekHexDecode(format!(
                "KEK must be exactly 32 bytes, got {}",
                raw.len()
            )));
        }
        let mut arr: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&raw);
        Ok(Self { bytes: arr })
    }

    /// Seal `plaintext` directly under the KEK, producing a v2 envelope
    /// blob (`0x02 || nonce || ciphertext+tag`).
    ///
    /// # When to use
    ///
    /// Intended for a **narrow, deliberate** class of secrets:
    ///
    /// - **Bootstrap-time configuration** that must decrypt before a
    ///   [`DekRing`](crate::ring::DekRing) is loadable (e.g. the
    ///   instance-level config that says where the DEK ring lives).
    /// - **Short-lived tokens** whose lifetime is measured in seconds
    ///   and gain nothing from DEK rotation (e.g. in-flight handoff
    ///   cookies).
    ///
    /// # When NOT to use
    ///
    /// General at-rest secrets — session tokens, TLS private keys,
    /// OIDC client secrets, etc. — should go through the DEK ring
    /// ([`DekRing::encrypt_active`](crate::ring::DekRing::encrypt_active))
    /// so they rotate without touching the KEK. Using `seal` for those
    /// pins them to the KEK and defeats the point of an envelope
    /// scheme.
    ///
    /// The output byte layout is the same v2 wire format used by the
    /// DEK-storage records the ring loader consumes, so a `seal`-ed
    /// blob is byte-compatible with any pre-existing KEK-direct blob
    /// carrying the same wire format.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        format::encrypt_v2(self.as_bytes(), plaintext)
    }

    /// Base64 wrapper around [`Self::seal`] — convenient when the
    /// storage column is a `TEXT` / VARCHAR.
    pub fn seal_to_base64(&self, plaintext: &[u8]) -> Result<String> {
        Ok(base64::engine::general_purpose::STANDARD.encode(self.seal(plaintext)?))
    }

    /// Open a v2 blob produced by [`Self::seal`] (or by legacy
    /// KEK-direct code emitting the same wire format).
    ///
    /// The returned plaintext is wrapped in `Zeroizing` so it wipes on
    /// drop — callers using it for short-lived secret handling get
    /// that memory hygiene for free.
    pub fn open(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        format::decrypt_v2(self.as_bytes(), blob).map(Zeroizing::new)
    }

    /// Base64 wrapper around [`Self::open`].
    pub fn open_from_base64(&self, encoded: &str) -> Result<Zeroizing<Vec<u8>>> {
        let data = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        self.open(&data)
    }

    /// Access the raw KEK bytes. Private to the crate so downstream
    /// callers cannot bypass the typed API and encrypt with a naked
    /// `[u8; 32]`.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> Kek {
        Kek::from_bytes(Zeroizing::new([0x42; 32]))
    }

    #[test]
    fn seal_open_round_trip() {
        let kek = test_kek();
        let blob = kek.seal(b"bootstrap-config").unwrap();
        assert_eq!(blob[0], format::V2);
        let opened = kek.open(&blob).unwrap();
        assert_eq!(&*opened, b"bootstrap-config");
    }

    #[test]
    fn seal_to_base64_round_trip() {
        let kek = test_kek();
        let encoded = kek.seal_to_base64(b"handoff").unwrap();
        let opened = kek.open_from_base64(&encoded).unwrap();
        assert_eq!(&*opened, b"handoff");
    }

    #[test]
    fn open_rejects_v3_blob() {
        // A blob whose first byte is 0x03 (v3) must not be treated as
        // a v2 KEK-sealed secret — the KEK doesn't decrypt v3 (that's
        // ring territory), and confusing the two would mask a bug.
        let kek = test_kek();
        let mut fake_v3 = vec![crate::format::V3, 0x00];
        fake_v3.extend_from_slice(&[0u8; format::NONCE_LEN + format::TAG_LEN]);
        let err = kek.open(&fake_v3).unwrap_err();
        assert!(matches!(err, Error::VersionMismatch { .. }));
    }

    #[test]
    fn debug_does_not_leak_key_bytes() {
        let kek = Kek::from_bytes(Zeroizing::new([0xCC; 32]));
        let debug_repr = format!("{kek:?}");
        assert!(debug_repr.contains("<redacted>"));
        assert!(!debug_repr.contains("cccccc"));
        assert!(!debug_repr.contains("204")); // 0xCC as decimal
    }

    #[test]
    fn from_hex_accepts_valid_input() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let kek = Kek::from_hex(hex).unwrap();
        // Sanity: seal / open round-trips with the parsed key.
        let blob = kek.seal(b"x").unwrap();
        assert_eq!(&*kek.open(&blob).unwrap(), b"x");
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        assert!(matches!(
            Kek::from_hex("0102").unwrap_err(),
            Error::KekHexDecode(_)
        ));
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        assert!(matches!(
            Kek::from_hex("zz").unwrap_err(),
            Error::KekHexDecode(_)
        ));
    }
}
