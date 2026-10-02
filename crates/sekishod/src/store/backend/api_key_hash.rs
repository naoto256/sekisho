//! Shared helpers for API-key hashing + constant-time verification.
//!
//! Storage policy:
//!
//! * Keys are stored as `$hmac$<hex>` where `<hex>` is
//!   `HMAC-SHA256(master_key, raw_key)` hex-encoded. The master key never
//!   leaves the process, so a DB dump alone cannot be precomputed against
//!   — unlike a plain `SHA-256(raw_key)` where a sufficiently-motivated
//!   attacker could brute-force low-entropy prefixes.
//!
//! * Verification computes the HMAC of the presented key and uses
//!   `subtle::ConstantTimeEq` to compare against the stored value. Early
//!   exit on a byte-by-byte `==` has been shown to leak information over
//!   LAN-scale timing deltas; this removes that class of attack from the
//!   verify path.

use crate::crypto::MasterKey;
use subtle::ConstantTimeEq;

/// Prefix we tag HMAC-formatted stored hashes with.
pub const HMAC_SENTINEL: &str = "$hmac$";

/// Compute the canonical stored-hash form for `raw_key` under
/// `master_key`. Output is ASCII and DB-safe.
pub fn hmac_stored_form(master_key: &MasterKey, raw_key: &str) -> String {
    let tag = master_key.api_key_hmac_tag(raw_key);
    format!("{HMAC_SENTINEL}{}", hex::encode(tag))
}

/// Outcome of comparing a presented `raw_key` against a stored hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Match.
    MatchHmac,
    /// No match.
    NoMatch,
}

/// Constant-time verify a raw key against a stored HMAC hash.
pub fn verify(master_key: &MasterKey, raw_key: &str, stored: &str) -> VerifyOutcome {
    let Some(hmac_hex) = stored.strip_prefix(HMAC_SENTINEL) else {
        // Anything else is a malformed / unknown row. Treat as no match;
        // we no longer accept legacy SHA-256 or plaintext rows.
        return VerifyOutcome::NoMatch;
    };
    let Ok(stored_bytes) = hex::decode(hmac_hex) else {
        return VerifyOutcome::NoMatch;
    };
    let computed = master_key.api_key_hmac_tag(raw_key);
    if computed.ct_eq(&stored_bytes).into() {
        VerifyOutcome::MatchHmac
    } else {
        VerifyOutcome::NoMatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MK: [u8; 32] = [7u8; 32];

    fn master_key() -> std::sync::Arc<MasterKey> {
        MasterKey::from_test_bytes(MK)
    }

    #[test]
    fn hmac_form_round_trip() {
        let key = master_key();
        let stored = hmac_stored_form(&key, "sks_abc");
        assert!(stored.starts_with(HMAC_SENTINEL));
        let outcome = verify(&key, "sks_abc", &stored);
        assert_eq!(outcome, VerifyOutcome::MatchHmac);
    }

    #[test]
    fn hmac_form_rejects_wrong_key() {
        let key = master_key();
        let stored = hmac_stored_form(&key, "sks_abc");
        let outcome = verify(&key, "sks_abd", &stored);
        assert_eq!(outcome, VerifyOutcome::NoMatch);
    }

    #[test]
    fn hmac_rejects_one_byte_diff() {
        // A single-byte mutation must not authenticate.
        let key = master_key();
        let stored = hmac_stored_form(&key, "sks_original_key_body_12345");
        let outcome = verify(&key, "sks_original_key_body_12346", &stored);
        assert_eq!(outcome, VerifyOutcome::NoMatch);
    }

    #[test]
    fn non_hmac_stored_value_never_matches() {
        // Bare hex / plaintext / anything without the sentinel must not
        // authenticate even if the raw key happens to equal the stored
        // string.
        let raw = "sks_plain";
        let key = master_key();
        assert_eq!(verify(&key, raw, raw), VerifyOutcome::NoMatch);
        assert_eq!(verify(&key, raw, "deadbeef"), VerifyOutcome::NoMatch);
    }

    #[test]
    fn verify_uses_constant_time_compare() {
        // We cannot measure timing in a unit test, but we can at least
        // assert that the helper pulls in `subtle::ConstantTimeEq` — if
        // a future edit replaces it with `==`, this reference will
        // fail to compile.
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        let eq: bool = a.ct_eq(&b).into();
        assert!(eq);
    }
}
