//! ACME protocol primitives.
//!
//! Pure library: no HTTP framework, no persistence, no DB. Callers
//! provide a `ChallengeProvider` (HTTP-01 token storage) and persist an
//! opaque account credential capability; the crate drives orders and hands
//! back the issued certificate PEM plus the freshly generated
//! private-key PEM.
//!
//! Persistence, encryption at rest, and audit logging are
//! intentionally out of scope — those belong in the caller. Keeping
//! the protocol code separate is what lets multiple callers share it
//! without dragging each other's storage layer along.
//!
//! Currently HTTP-01 only. [`AcmeAccount::issue`] passes the HTTP-01-form key
//! authorization (`instant_acme::KeyAuthorization::as_str`) to
//! `ChallengeProvider::set`; DNS-01 needs the `dns_value()` form
//! instead, so it requires an API extension and is not yet wired.

mod account;
mod ari;
pub mod challenge;
pub mod error;
pub mod protocol;

pub use account::{AcmeAccount, AcmeAccountCredentials};
pub use ari::{RenewalAdvice, RenewalInformation};
pub use challenge::{ChallengeProvider, ProviderError};
pub use error::{Error, RenewalInformationFailure, Result};
pub use protocol::{IssuedCertificate, IssuedPrivateKey};

/// Re-exported so callers don't need a direct `instant-acme` dep just
/// to name the challenge type their `ChallengeProvider` handles.
pub use instant_acme::ChallengeType;
