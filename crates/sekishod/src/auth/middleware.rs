//! Pending-auth state storage.
//!
//! A `PendingAuth` is what we remember between the `/saml/login` (or
//! `/.sekisho/callback` for OIDC) redirect going out and the IdP's
//! response coming back. It carries the per-flow CSRF / nonce /
//! `InResponseTo` values the callback handler needs to prove the
//! response belongs to *this* browser session.
//!
//! # Why this is split
//!
//! In single-node mode the obvious implementation is a process-local
//! `HashMap`. That breaks under HA: a load balancer that sends the
//! `/saml/login` to node A and the ACS POST to node B results in node
//! B having no record of the flow and rejecting the assertion with
//! "no PendingAuth for CSRF token". The production fix is to move the
//! store into the shared service DB.
//!
//! `AuthStateStore` persists in-flight state through the `Store`
//! facade, backed by whichever operational DB is configured (SQLite
//! single-node or Postgres HA). This is what survives a node flip
//! mid-flow.

use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::error::Result;
use crate::store::Store;

/// State carried across the IdP round-trip for one in-flight login.
///
/// Shape covers both OIDC (PKCE + nonce) and SAML (`InResponseTo`) —
/// the fields for the other protocol are left blank / `None`. Keeping
/// a single struct beats two mostly-overlapping types because the
/// store then stays protocol-agnostic and the DB schema needs one
/// table, not two.
#[derive(Clone, Debug)]
pub struct PendingAuth {
    pub idp_id: Uuid,
    pub nonce: String,
    pub code_verifier: String,
    pub redirect_url: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// SAML AuthnRequest ID (for login) or LogoutRequest ID (for SLO)
    /// we generated for the SP-initiated round-trip. The callback
    /// checks the Response's `InResponseTo` against this to ensure the
    /// reply targets *our* request. None for OIDC flows.
    pub saml_authn_request_id: Option<String>,
    /// Which protocol round-trip is pending. Needed so the SAML SLO
    /// callback and the SAML ACS callback do not cross-wire — both
    /// hit the same `PendingAuth` store, but a login RelayState must
    /// not be consumable by the SLO endpoint and vice versa.
    #[cfg_attr(test, allow(dead_code))]
    pub kind: PendingAuthKind,
    /// SHA-256 of the independent nonce carried by this flow's browser
    /// cookie. `None` is retained only so migration-v3 can add the column
    /// without rewriting in-flight rows; coordinated upgrades reject those
    /// legacy rows rather than silently bypassing browser binding.
    pub browser_nonce_hash: Option<String>,
}

/// Discriminator for what kind of IdP round-trip is in flight.
///
/// Stored as a string column (`'login'` / `'saml_logout'`) rather than
/// as an integer enum because it shows up in operator-readable
/// `pending_auth` rows and a typo in a migration would be silent under
/// a numeric encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingAuthKind {
    /// One-time bounce from an application host to the canonical auth
    /// domain. Consumed before an OIDC/SAML flow is created.
    AuthStart,
    /// OIDC authorization-code or SAML AuthnRequest flow.
    Login,
    /// SAML SP-initiated LogoutRequest awaiting the IdP's LogoutResponse.
    SamlLogout,
}

impl PendingAuthKind {
    /// Stable string encoding used by the DB `kind` column. Keep in
    /// sync with `from_db_str`; any mismatch would silently drop one
    /// side of the protocol.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::AuthStart => "auth_start",
            Self::Login => "login",
            Self::SamlLogout => "saml_logout",
        }
    }

    /// Inverse of `as_db_str`. Unknown strings map to `Login` rather
    /// than erroring because a forward-compat DB row (written by a
    /// newer peer) must not crash this node mid-flow; the worst case
    /// is an SLO response being rejected with "wrong kind", which is
    /// the same outcome as any other mismatched token.
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "auth_start" => Self::AuthStart,
            "saml_logout" => Self::SamlLogout,
            _ => Self::Login,
        }
    }
}

/// TTL after which a PendingAuth row is considered expired. Matches the
/// old in-memory retention window so the user-visible "you took too
/// long" behaviour doesn't shift across the refactor.
pub const PENDING_AUTH_TTL: chrono::Duration = chrono::Duration::minutes(10);

/// Browser-visible nonce for one authentication flow. The returned value is
/// independent of OIDC state / SAML RelayState and is never stored in clear.
pub fn new_browser_nonce() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn browser_nonce_hash(nonce: &str) -> String {
    let digest = Sha256::digest(nonce.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

pub fn browser_nonce_matches(expected_hash: Option<&str>, nonce: Option<&str>) -> bool {
    let (Some(expected), Some(nonce)) = (expected_hash, nonce) else {
        return false;
    };
    let computed = browser_nonce_hash(nonce);
    expected.len() == computed.len() && bool::from(expected.as_bytes().ct_eq(computed.as_bytes()))
}

/// Storage for in-flight `PendingAuth` entries, keyed by CSRF token
/// (OIDC `state` parameter / SAML RelayState `csrf` field).
///
/// Provides at-most-once semantics for `take`: once a callback pops a
/// pending entry it must not be returned to any other caller. That's
/// the CSRF-binding guarantee the ACS / OIDC-callback handlers lean
/// on.
///
/// Delegates straight through `Store` so the same code path works for
/// SQLite (single-node) and Postgres (HA). The persistence concern —
/// including TTL cleanup, which turns into a `DELETE WHERE expires_at
/// < now()` — lives in the backend; we're just forwarding here.
pub struct AuthStateStore {
    store: Store,
}

impl AuthStateStore {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Record a pending flow under `csrf_token`. An existing entry
    /// with the same key is overwritten — the callsites use 256-bit
    /// random tokens so collisions are a cryptographic non-event.
    pub async fn insert(&self, csrf_token: &str, state: PendingAuth) -> Result<()> {
        self.store.pending_auth_insert(csrf_token, &state).await
    }

    /// Non-destructive, expiry-aware lookup. Validation can inspect the
    /// pending flow without consuming it; successful callbacks must still
    /// call [`Self::take`] before producing side effects.
    pub async fn get(&self, csrf_token: &str) -> Result<Option<PendingAuth>> {
        self.store.pending_auth_get(csrf_token).await
    }

    /// Atomic read-and-delete. Returns `None` if the token is unknown
    /// or already consumed; returning it twice would break CSRF binding.
    pub async fn take(&self, csrf_token: &str) -> Result<Option<PendingAuth>> {
        self.store.pending_auth_take(csrf_token).await
    }

    /// Commit the auth-domain bounce as one database transition. Protocol
    /// preparation happens before this call and is deliberately write-free;
    /// only the transaction winner consumes the one-time ticket and publishes
    /// the callback state.
    pub async fn transition_auth_start(
        &self,
        auth_start_token: &str,
        login_token: &str,
        login_state: PendingAuth,
    ) -> Result<bool> {
        crate::store::backend::pending_auth_transition(
            &self.store,
            auth_start_token,
            login_token,
            &login_state,
        )
        .await
    }

    /// Drop every entry older than `PENDING_AUTH_TTL`. Called on a
    /// background interval; the count is returned for logging only.
    pub async fn cleanup_expired(&self) -> Result<u64> {
        self.store.pending_auth_cleanup_expired().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_nonce_requires_exact_present_hash_and_value() {
        let hash = browser_nonce_hash("browser-nonce");
        assert!(browser_nonce_matches(Some(&hash), Some("browser-nonce")));
        assert!(!browser_nonce_matches(Some(&hash), Some("other")));
        assert!(!browser_nonce_matches(None, Some("browser-nonce")));
        assert!(!browser_nonce_matches(Some(&hash), None));
    }

    #[test]
    fn pending_auth_kind_roundtrips_auth_start() {
        assert_eq!(PendingAuthKind::AuthStart.as_db_str(), "auth_start");
        assert_eq!(
            PendingAuthKind::from_db_str("auth_start"),
            PendingAuthKind::AuthStart
        );
    }
}
