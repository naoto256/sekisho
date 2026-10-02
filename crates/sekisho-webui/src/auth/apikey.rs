//! Minimal helpers for the admin-entered API key flow.

use super::{Credential, SharedCredential};

/// Store a user-supplied API key into the shared credential slot. Called by
/// the `/setup` POST handler after a successful connectivity check.
pub async fn install(cred: &SharedCredential, key: String) {
    *cred.write().await = Credential::ApiKey(key);
}
