//! `ChallengeProvider` trait.
//!
//! Abstracts the side-channel that proves domain control to the ACME
//! directory. The current API targets HTTP-01: implementations store
//! `token → key_authorization` somewhere the public
//! `/.well-known/acme-challenge/{token}` handler can read it.
//!
//! The trait is intentionally narrow — `set` + `cleanup` only — so
//! the protocol code can call it during the order without knowing
//! how the side-channel is realised. The error type is opaque so
//! callers aren't forced to translate their internal error enum into
//! a protocol-specific one.
//!
//! DNS-01 is **not** supported by the current API: `AcmeAccount::issue`
//! passes the HTTP-01-form key authorization, whereas DNS-01 needs the
//! SHA-256 / base64url digest. Adding DNS-01 requires an API extension,
//! not just a new `ChallengeProvider` impl.

use instant_acme::ChallengeType;

/// Opaque error returned by `ChallengeProvider` methods. Boxed so
/// each caller can supply its own error enum without leaking the
/// shape into this crate.
pub type ProviderError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Abstraction over the side-channel used to prove domain control
/// during an ACME order. HTTP-01 only in the current API; see the
/// module-level docs for the DNS-01 caveat.
pub trait ChallengeProvider: Send + Sync {
    /// The instant-acme challenge type this provider handles.
    /// Today only `ChallengeType::Http01` is supported — `AcmeAccount::issue`
    /// rejects any other value at startup with `Error::Internal`.
    fn challenge_type(&self) -> ChallengeType;

    /// Set the HTTP-01 challenge response: store `token → key_auth`
    /// somewhere the public `/.well-known/acme-challenge/{token}`
    /// responder can read it (shared storage if multiple responder
    /// nodes serve the path).
    fn set(
        &self,
        domain: &str,
        token: &str,
        key_auth: &str,
    ) -> impl std::future::Future<Output = std::result::Result<(), ProviderError>> + Send;

    /// Remove all challenge state for a domain after the order
    /// finishes (success or failure). Failures here are non-fatal —
    /// the protocol code logs and continues.
    fn cleanup(
        &self,
        domain: &str,
    ) -> impl std::future::Future<Output = std::result::Result<(), ProviderError>> + Send;
}
