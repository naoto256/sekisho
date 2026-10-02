//! sekishod's `ChallengeProvider` implementations.
//!
//! The trait lives in `acme_core::ChallengeProvider` — this module
//! only carries the daemon-specific implementations, which depend on
//! `Store` (and therefore can't move into the protocol crate).
//!
//! Currently HTTP-01 only. DNS-01 providers can be added by
//! implementing the trait against whatever DNS API the operator
//! configures, then wiring the choice through `GlobalConfig.acme_challenge_type`.

use crate::store::Store;
use acme_core::{ChallengeProvider, ChallengeType, ProviderError};

/// HTTP-01 challenge provider. Persists challenge tokens in the service
/// DB (via `Store`) so every node in an HA deployment can answer
/// `/.well-known/acme-challenge/{token}`, regardless of which one
/// initiated the ACME order. Cheap to clone — the `Store` itself is
/// `Clone` and holds pool handles only.
pub struct Http01Provider {
    store: Store,
}

impl Http01Provider {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Look up a key authorization by token, used by the HTTP challenge
    /// handler. Returns `None` when the token isn't registered — the
    /// handler maps that to 404. `async` because the lookup goes through
    /// the service DB; in HA topologies that's a Postgres round trip.
    pub async fn get_response(&self, token: &str) -> Option<String> {
        match self.store.get_acme_challenge(token).await {
            Ok(v) => v,
            Err(e) => {
                // DB failure here is functionally indistinguishable from
                // "token unknown" — either way we can't serve the
                // response. Log so the operator can see it in the HTTP
                // responder's context rather than it surfacing as a
                // bare 404 to Let's Encrypt.
                tracing::warn!(token = %token, error = %e, "ACME challenge lookup failed");
                None
            }
        }
    }
}

impl ChallengeProvider for Http01Provider {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::Http01
    }

    async fn set(
        &self,
        domain: &str,
        token: &str,
        key_auth: &str,
    ) -> std::result::Result<(), ProviderError> {
        self.store
            .set_acme_challenge(token, key_auth, domain)
            .await
            .map_err(|e| Box::new(e) as ProviderError)
    }

    async fn cleanup(&self, domain: &str) -> std::result::Result<(), ProviderError> {
        self.store
            .delete_acme_challenges_for_domain(domain)
            .await
            .map(|_| ())
            .map_err(|e| Box::new(e) as ProviderError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    const TEST_MASTER_KEY: [u8; 32] = [0u8; 32];

    #[tokio::test]
    async fn http01_provider_stores_via_service_db() {
        let store = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .expect("store");
        let provider = Http01Provider::new(store.clone());

        // Unknown token -> None.
        assert!(provider.get_response("ghost").await.is_none());

        // set() persists via the store, get_response() reads from it.
        provider
            .set("example.test", "token-xyz", "key-auth-xyz")
            .await
            .expect("set");
        assert_eq!(
            provider.get_response("token-xyz").await.as_deref(),
            Some("key-auth-xyz")
        );

        // A second Http01Provider pointed at the same Store sees the
        // same binding — this is the HA property: whichever node the
        // HTTP-01 handler runs on, it can answer. Pure same-process
        // proxy here, but the read path is the shared DB table so the
        // invariant holds on Postgres too.
        let peer_view = Http01Provider::new(store.clone());
        assert_eq!(
            peer_view.get_response("token-xyz").await.as_deref(),
            Some("key-auth-xyz")
        );

        // cleanup() clears the whole domain.
        provider.cleanup("example.test").await.expect("cleanup");
        assert!(provider.get_response("token-xyz").await.is_none());
    }
}
