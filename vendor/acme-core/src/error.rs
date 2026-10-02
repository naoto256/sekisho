//! Error type for the ACME protocol layer.
//!
//! Deliberately small. Callers typically own richer error enums tied
//! to HTTP responses, audit categorisation, and DB failure modes —
//! none of those belong in a protocol library. Implement
//! `From<acme_core::Error>` on the caller side to map these variants
//! into the caller's enum at the boundary.
//!
//! The split between [`Error::Transient`] and [`Error::Rejected`] is
//! intentional: it lets callers branch retry policy without parsing
//! error strings. See [`Error::is_retryable`] for the canonical check.

use std::time::Duration;

use thiserror::Error;

/// RFC 9773 retry authority for a failed RenewalInfo request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalInformationFailure {
    /// Timeout, HTTP 408, or 5xx response. Retry with bounded exponential backoff;
    /// exhaustion transitions to the long-term interval.
    Temporary {
        /// Delay before the first retry.
        initial_delay: Duration,
        /// Maximum delay between attempts.
        maximum_delay: Duration,
        /// Maximum number of retry attempts.
        maximum_attempts: u8,
        /// Retry interval after bounded attempts are exhausted.
        exhausted_retry_after: Duration,
    },
    /// Non-temporary failure. Retry once the fixed local interval passes.
    LongTerm {
        /// Local interval before the next RenewalInfo request.
        retry_after: Duration,
    },
}

impl std::fmt::Display for RenewalInformationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Temporary { .. } => formatter.write_str("temporary renewal information failure"),
            Self::LongTerm { .. } => formatter.write_str("long-term renewal information failure"),
        }
    }
}

impl std::error::Error for RenewalInformationFailure {}

/// Errors raised by the ACME protocol layer.
#[derive(Debug, Error)]
pub enum Error {
    /// Transient ACME / transport failure — connection error, timeout,
    /// 5xx, or any non-policy directory failure that may succeed on
    /// retry. Includes the post-finalize "still no certificate after N
    /// polls" timeout and the order-ready poll timeout. Caller MAY
    /// retry the whole order.
    #[error("transient ACME error: {0}")]
    Transient(String),

    /// Permanent rejection by the ACME directory — order status
    /// `Invalid`, unexpected authorization status, identifier rejected,
    /// etc. Retrying with the same input will fail again; caller must
    /// change inputs or abandon.
    #[error("ACME directory rejected the request: {0}")]
    Rejected(String),

    /// Local failure unrelated to the ACME directory — CSR
    /// construction, key generation, unsupported `ChallengeProvider`
    /// configuration, etc. Anything where the bug is on our side, not
    /// the directory's.
    #[error("internal error: {0}")]
    Internal(String),

    /// The caller-supplied `ChallengeProvider::set` returned an error.
    /// Wrapped opaquely so the protocol crate doesn't need to know
    /// what storage the caller uses. Errors from `cleanup` never
    /// surface here — they are logged at `warn` inside `protocol::issue`
    /// and do not mask the underlying issuance result.
    #[error("challenge provider failed")]
    Challenge(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The ACME directory does not advertise the requested optional
    /// protocol capability. Callers may apply the documented fallback.
    #[error("ACME capability unsupported: {0}")]
    Unsupported(&'static str),

    /// Persisted account credentials are malformed or use an unknown
    /// envelope version. Existing invalid credentials are never replaced
    /// by silently creating a new account.
    #[error("invalid ACME account credentials")]
    InvalidCredentials,

    /// Persisted credentials belong to a different normalized directory.
    #[error("ACME account credentials belong to a different directory")]
    CredentialDirectoryMismatch,

    /// The predecessor certificate cannot be identified for ARI.
    #[error("invalid predecessor certificate")]
    InvalidPredecessorCertificate,

    /// RFC 9773 RenewalInfo failure with canonical retry authority.
    #[error(transparent)]
    RenewalInformation(#[from] RenewalInformationFailure),
}

impl Error {
    /// `true` for transport-shaped failures and invalid ARI responses
    /// that may be corrected by a later fetch. Callers SHOULD use this
    /// to gate retry policy instead of matching on variants directly.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Transient(_) | Error::RenewalInformation(_))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
