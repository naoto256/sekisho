//! Authentication state for sekisho-webui.
//!
//! sekisho-webui authenticates to the Sekisho management API in one of two ways:
//!
//! * `--local-auth` — obtain a management token via the Unix control socket
//!   challenge. Tokens expire after 1 hour, so a background task rebuilds them
//!   every ~55 minutes. The socket round-trip is proof that the process has
//!   local access to the Sekisho host, which is already an admin-equivalent
//!   position, so auto-refresh is safe.
//! * Web setup — on first request, an administrator pastes an API key into a
//!   form at `/setup`. The key is held in memory for the lifetime of the
//!   process. Restarting sekisho-webui means re-entering the key.

pub mod apikey;
pub mod guard;
pub mod local;

use std::sync::Arc;
use tokio::sync::RwLock;

/// Active credential used on outbound requests to the Sekisho management API.
#[derive(Clone)]
pub enum Credential {
    /// No credential yet — requests must redirect to `/setup`.
    None,
    /// Admin-entered API key, valid until the process restarts.
    ApiKey(String),
    /// Locally minted management token (prefix `mgmt_`).
    LocalSession {
        token: String,
        /// Monotonic wall-clock instant after which we refuse to use the token.
        /// Used by the refresh loop to schedule the next challenge.
        expires_at: chrono::DateTime<chrono::Utc>,
    },
}

impl std::fmt::Debug for Credential {
    // Both bearer values are full credentials; never let them surface through
    // `{:?}` (tracing fields, panic backtraces, anyhow chains).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::None => f.write_str("Credential::None"),
            Credential::ApiKey(_) => f.write_str("Credential::ApiKey(<redacted>)"),
            Credential::LocalSession { expires_at, .. } => f
                .debug_struct("Credential::LocalSession")
                .field("token", &"<redacted>")
                .field("expires_at", expires_at)
                .finish(),
        }
    }
}

impl Credential {
    pub fn bearer(&self) -> Option<&str> {
        match self {
            Credential::None => None,
            Credential::ApiKey(k) => Some(k.as_str()),
            Credential::LocalSession { token, .. } => Some(token.as_str()),
        }
    }

    pub fn is_set(&self) -> bool {
        !matches!(self, Credential::None)
    }
}

pub type SharedCredential = Arc<RwLock<Credential>>;

pub fn new_shared(initial: Credential) -> SharedCredential {
    Arc::new(RwLock::new(initial))
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_api_key() {
        let c = Credential::ApiKey("sk_super_secret_value_42".into());
        let s = format!("{c:?}");
        assert!(!s.contains("super_secret_value"), "leak: {s}");
        assert!(s.contains("redacted"), "should mark: {s}");
    }

    #[test]
    fn debug_does_not_leak_local_session_token() {
        let c = Credential::LocalSession {
            token: "mgmt_super_secret_token_42".into(),
            expires_at: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap(),
        };
        let s = format!("{c:?}");
        assert!(!s.contains("super_secret_token"), "leak: {s}");
        assert!(s.contains("redacted"), "should mark: {s}");
    }
}
