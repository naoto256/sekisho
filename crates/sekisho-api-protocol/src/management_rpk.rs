//! Canonical wire representation for the management raw-public-key pin.
//!
//! This module intentionally treats the decoded payload as opaque bytes.
//! SPKI and TLS semantics belong to the transport crate.

use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const PREFIX: &str = "sekisho-rpk-v1:ed25519:";

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ManagementRpkPin(Vec<u8>);

impl ManagementRpkPin {
    pub fn from_opaque_bytes(bytes: Vec<u8>) -> Result<Self, PinParseError> {
        if bytes.is_empty() {
            return Err(PinParseError);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ManagementRpkPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagementRpkPin")
            .field("encoded_len", &URL_SAFE_NO_PAD.encode(&self.0).len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ManagementRpkPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}", URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl FromStr for ManagementRpkPin {
    type Err = PinParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded = value.strip_prefix(PREFIX).ok_or(PinParseError)?;
        if encoded.is_empty() || encoded.contains('=') {
            return Err(PinParseError);
        }
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| PinParseError)?;
        if bytes.is_empty() || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            return Err(PinParseError);
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinParseError;

impl fmt::Display for PinParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid management RPK pin")
    }
}

impl std::error::Error for PinParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_round_trip_preserves_opaque_bytes() {
        let pin = ManagementRpkPin::from_opaque_bytes(vec![0, 1, 2, 0xfe, 0xff]).unwrap();
        let encoded = pin.to_string();
        assert_eq!(encoded.parse::<ManagementRpkPin>().unwrap(), pin);
    }

    #[test]
    fn rejects_noncanonical_or_wrong_contract() {
        for value in [
            "",
            "sekisho-rpk-v1:ed25519:",
            "sekisho-rpk-v1:ed448:AA",
            "sekisho-rpk-v1:ed25519:AA==",
            "sekisho-rpk-v2:ed25519:AA",
        ] {
            assert!(value.parse::<ManagementRpkPin>().is_err(), "{value}");
        }
    }
}
