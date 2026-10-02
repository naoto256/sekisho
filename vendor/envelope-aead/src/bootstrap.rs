//! Initial-DEK bootstrap helper.

use crate::dek::{DekKeyId, DekPlaintext, EncryptedDekBlob};
use crate::error::Result;
use crate::kek::Kek;
use crate::ring::DekRing;

/// Result of [`bootstrap_initial_dek`]: everything a daemon needs to
/// persist its first DEK row and start encrypting.
///
/// The `encrypted_blob` is the bytes to store in the daemon's
/// `master_keys` / `dek_ring` row; the `ring` is a ready-to-use
/// snapshot the daemon can install so it does not need to reload from
/// storage immediately after inserting.
#[derive(Debug)]
pub struct InitialDekBootstrap {
    /// The key_id used for the seed DEK. Always 0.
    pub key_id: DekKeyId,
    /// KEK-sealed DEK, ready to persist.
    pub encrypted_blob: EncryptedDekBlob,
    /// Ready-to-use ring snapshot carrying the same DEK as its active
    /// key.
    pub ring: DekRing,
}

/// Generate a fresh DEK, seal it under the KEK, and return both the
/// blob (for the daemon to persist) and a ready `DekRing` snapshot.
///
/// The daemon owns the persistence + race semantics of the insert:
/// this helper deliberately does not touch storage. In a typical HA
/// setup the caller inserts on the assumption that no other peer has
/// won the same race, and reloads the ring from storage if the insert
/// fails.
///
/// Errors only if the RNG fails to generate a DEK.
pub fn bootstrap_initial_dek(kek: &Kek) -> Result<InitialDekBootstrap> {
    let dek = DekPlaintext::generate()?;
    let encrypted_blob = dek.seal_under(kek)?;
    let ring = DekRing::placeholder_single(dek);
    let key_id = ring.active_key_id();
    Ok(InitialDekBootstrap {
        key_id,
        encrypted_blob,
        ring,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn bootstrap_produces_matching_blob_and_ring() {
        let kek = Kek::from_bytes(Zeroizing::new([0x33; 32]));
        let boot = bootstrap_initial_dek(&kek).unwrap();
        assert_eq!(boot.key_id.get(), 0);
        assert_eq!(boot.ring.active_key_id(), boot.key_id);

        // The encrypted blob decrypts back to a DEK whose bytes match
        // the ring's active key (round-trip via encrypt/decrypt).
        let payload = b"envelope-aead-bootstrap-test";
        let ct = boot.ring.encrypt_active(payload).unwrap();

        // Reconstruct the ring by re-decrypting the blob through the
        // KEK — should decrypt the same ciphertext.
        let dek = boot.encrypted_blob.open(&kek).unwrap();
        let rebuilt = DekRing::placeholder_single(dek);
        assert_eq!(&*rebuilt.decrypt(&ct).unwrap(), payload);
    }
}
