//! ACME HTTP-01 challenge facade.
//!
//! The challenge token → key-authorization binding is stored in the
//! service DB so any node sharing that DB can serve
//! `/.well-known/acme-challenge/{token}` — which is the foundation of
//! HA-safe ACME issuance when DNS round-robin can steer the Let's
//! Encrypt validator to any node regardless of which one initiated
//! the order.
//!
//! Nothing here is cached in-process: the rows are short-lived (seconds
//! to a minute) and every read goes straight to the backend.

use crate::error::Result;

use super::Store;
use super::dispatch;

impl Store {
    /// Record a `token → key_auth` binding tagged with `domain`. The
    /// `domain` label is what `delete_acme_challenges_for_domain`
    /// scopes on at cleanup time.
    pub async fn set_acme_challenge(
        &self,
        token: &str,
        key_auth: &str,
        domain: &str,
    ) -> Result<()> {
        dispatch!(self, set_acme_challenge, token, key_auth, domain)
    }

    /// Fetch the `key_auth` for a token, or `None` if unknown. The
    /// HTTP-01 responder turns `None` into a 404.
    pub async fn get_acme_challenge(&self, token: &str) -> Result<Option<String>> {
        dispatch!(self, get_acme_challenge, token)
    }

    /// Clear every challenge row recorded for `domain`. Called at the
    /// tail of an ACME order (success or failure) so the table doesn't
    /// leak entries across runs.
    pub async fn delete_acme_challenges_for_domain(&self, domain: &str) -> Result<u64> {
        dispatch!(self, delete_acme_challenges_for_domain, domain)
    }
}
