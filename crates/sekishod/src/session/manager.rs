//! Server-side session lifecycle.
//!
//! Create, validate, and expire. The browser holds only a signed id, so every
//! question about a session is answered from the database — which is what makes
//! revocation take effect on the next request rather than at cookie expiry.
//!
//! ## Idle expiry is enforced, access time is throttled
//!
//! A session dies from absolute expiry (`expires_at`, fixed at creation) or
//! from idleness. Idleness is derived from `last_accessed_at`, which would
//! otherwise mean a database write on every single proxied request. Instead the
//! touch is coalesced: the update is only dispatched once per
//! [`crate::models::session::SESSION_TOUCH_INTERVAL_SECS`], the comparison is
//! made inside the database so every HA node reaches the same verdict from the
//! same durable value rather than from its own clock, and the enforcement
//! threshold carries a grace period so a request arriving near the boundary is
//! not killed by the touch it is itself performing.
//!
//! The persisted/skipped counters exist to make that throttle observable: the
//! ratio is how you tell "sessions are idle" from "the coalescing window is
//! misconfigured and we are writing on every request".

use crate::audit;
use crate::error::{Error, Result};
use crate::models::session::{Session, UpstreamIdentity};
use crate::store::Store;
use crate::store::backend::SessionTouchOutcome;
use chrono::{Duration, Utc};
use metrics::{counter, gauge};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

/// Owns session creation and validation for the process.
///
/// `lifetime_hours` is captured at construction, which is why changing it
/// requires a restart — existing sessions keep the `expires_at` they were
/// created with either way, so re-reading it per request would only affect new
/// sessions while adding a config read to the login path.
pub struct SessionManager {
    store: Store,
    lifetime_hours: u32,
    persisted_count: Arc<AtomicU64>,
    skipped_count: Arc<AtomicU64>,
}

impl SessionManager {
    /// Build a manager with the configured absolute session lifetime.
    pub fn new(store: Store, lifetime_hours: u32) -> Self {
        Self {
            store,
            lifetime_hours,
            persisted_count: Arc::new(AtomicU64::new(0)),
            skipped_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Number of `last_accessed_at` UPDATEs actually dispatched to the
    /// store since process start. Test-only mirror of the
    /// `sekisho_session_access_update_total{result="persisted"}` metric.
    #[cfg(test)]
    pub fn persisted_count(&self) -> u64 {
        self.persisted_count.load(Ordering::Relaxed)
    }

    /// Number of validations that hit the coalescing window and
    /// skipped the UPDATE. Test-only counterpart to `persisted_count`.
    #[cfg(test)]
    pub fn skipped_count(&self) -> u64 {
        self.skipped_count.load(Ordering::Relaxed)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub async fn create(
        &self,
        user_id: &str,
        idp_id: Uuid,
        claims: HashMap<String, serde_json::Value>,
        groups: Vec<String>,
        refresh_token: Option<&str>,
        id_token: Option<&str>,
        saml_name_id: Option<String>,
        saml_session_index: Option<String>,
    ) -> Result<Session> {
        self.create_with_upstream_identity(
            user_id,
            idp_id,
            claims,
            groups,
            None,
            refresh_token,
            id_token,
            saml_name_id,
            saml_session_index,
        )
        .await
    }

    // 9 args is over clippy's default threshold. Refactoring to a
    // builder is tempting, but every caller is a login callback that
    // already has these values as locals; a builder would just move
    // the argument list one method over. Revisit if a fourth
    // protocol-specific parameter lands.
    /// Create a session. The `refresh_token` / `id_token` plaintexts
    /// are received as borrows: they are read only within the
    /// encryption `.await` scope below, and only ciphertext is
    /// retained on the returned `Session`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_upstream_identity(
        &self,
        user_id: &str,
        idp_id: Uuid,
        claims: HashMap<String, serde_json::Value>,
        groups: Vec<String>,
        upstream_identity: Option<UpstreamIdentity>,
        refresh_token: Option<&str>,
        id_token: Option<&str>,
        saml_name_id: Option<String>,
        saml_session_index: Option<String>,
    ) -> Result<Session> {
        let now = Utc::now();
        // Encrypt refresh / id tokens through the active DEK in one shot
        // each — both `await`s before constructing `Session` so the lock
        // hand-off is straightforward.
        let refresh_token_encrypted = match refresh_token {
            Some(t) => Some(
                self.store
                    .encrypt_active_to_base64(t.as_bytes())
                    .await
                    .map_err(|e| match e {
                        crate::error::Error::Crypto(inner) => crate::error::Error::Internal(
                            format!("failed to encrypt refresh token: {inner}"),
                        ),
                        other => other,
                    })?,
            ),
            None => None,
        };
        let id_token_encrypted = match id_token {
            Some(t) => Some(
                self.store
                    .encrypt_active_to_base64(t.as_bytes())
                    .await
                    .map_err(|e| match e {
                        crate::error::Error::Crypto(inner) => crate::error::Error::Internal(
                            format!("failed to encrypt id token: {inner}"),
                        ),
                        other => other,
                    })?,
            ),
            None => None,
        };
        let session = Session {
            id: Uuid::new_v4(),
            user_id: user_id.to_string(),
            idp_id,
            claims,
            groups,
            upstream_identity,
            created_at: now,
            expires_at: now + Duration::hours(self.lifetime_hours as i64),
            refresh_token_encrypted,
            id_token_encrypted,
            saml_name_id,
            saml_session_index,
            last_accessed_at: now,
        };

        self.store.create_session(&session).await?;
        // Process-local counter — sums delta across all nodes via
        // sekisho_session_active{} = create - revoke. Best-effort:
        // sessions expired by background sweep tick the gauge down on
        // this process only when the node also runs the sweep. Good
        // enough for "is login working" dashboards; for ground truth
        // operators query the DB.
        counter!("sekisho_session_create_total").increment(1);
        gauge!("sekisho_session_active").increment(1.0);
        // Audit the lifecycle event in one place rather than each
        // OIDC / SAML callback rolling its own. Group membership goes
        // out as a count — full lists drift unpredictably and aren't
        // useful for the "who has an active session?" question.
        tracing::info!(
            target: audit::TARGET,
            event = "session.create",
            category = "auth",
            result = "success",
            actor_type = "user",
            actor_id = %user_id,
            target_resource = "session",
            target_id = %session.id,
            idp_id = %idp_id,
            group_count = session.groups.len(),
            expires_at = %session.expires_at,
            "user session created"
        );
        Ok(session)
    }

    pub async fn validate(&self, session_id: Uuid) -> Result<Session> {
        let validation = self.store.get_session_for_validation(session_id).await?;
        let mut session = validation.session;
        if !validation.touch_due {
            self.skipped_count.fetch_add(1, Ordering::Relaxed);
            counter!("sekisho_session_access_update_total", "result" => "skipped").increment(1);
            return Ok(session);
        }

        match self
            .store
            .touch_session_if_due(session_id, session.last_accessed_at)
            .await?
        {
            SessionTouchOutcome::Touched(last_accessed_at) => {
                self.persisted_count.fetch_add(1, Ordering::Relaxed);
                counter!("sekisho_session_access_update_total", "result" => "persisted")
                    .increment(1);
                session.last_accessed_at = last_accessed_at;
            }
            SessionTouchOutcome::Current(last_accessed_at) => {
                self.skipped_count.fetch_add(1, Ordering::Relaxed);
                counter!("sekisho_session_access_update_total", "result" => "skipped").increment(1);
                session.last_accessed_at = last_accessed_at;
            }
            SessionTouchOutcome::GoneOrExpired => return Err(Error::NotFound),
        }
        Ok(session)
    }

    /// Decrypt the session's stored OIDC ID token. Returns `Ok(None)`
    /// both when no id_token was persisted (SAML session, or an IdP
    /// that didn't return one) and when the ciphertext is malformed —
    /// the caller is expected to degrade to a local-only signout in
    /// either case, so a hard error here would be worse UX than
    /// skipping the `id_token_hint` parameter.
    pub async fn decrypt_id_token(&self, session: &Session) -> Option<String> {
        let blob = session.id_token_encrypted.as_deref()?;
        match self.store.decrypt_any_from_base64(blob).await {
            Ok(bytes) => String::from_utf8(bytes).ok(),
            Err(e) => {
                tracing::warn!(session_id = %session.id, error = %e, "failed to decrypt stored id_token; falling back to local-only signout");
                None
            }
        }
    }

    pub async fn revoke(&self, session_id: Uuid) -> Result<()> {
        // Best-effort lookup so the audit event can name the user
        // whose session was revoked. A revoke racing with an expiry
        // sweep can land on an already-deleted row; in that case we
        // still log the revoke attempt, just without the user.
        let user_id = self
            .store
            .get_session(session_id)
            .await
            .ok()
            .map(|s| s.user_id)
            .unwrap_or_default();
        self.store.delete_session(session_id).await?;
        counter!("sekisho_session_revoke_total").increment(1);
        gauge!("sekisho_session_active").decrement(1.0);
        tracing::info!(
            target: audit::TARGET,
            event = "session.revoke",
            category = "auth",
            result = "success",
            actor_type = "user",
            actor_id = %user_id,
            target_resource = "session",
            target_id = %session_id,
            "user session revoked"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use auth_idp::oidc::OidcToken;

    async fn fresh_store() -> Store {
        Store::new_for_test("sqlite::memory:", [0x42u8; 32], None)
            .await
            .unwrap()
    }

    async fn make_idp(store: &Store) -> Uuid {
        let idp = crate::models::idp::IdentityProvider {
            id: Uuid::new_v4(),
            name: "test-idp".into(),
            idp_type: crate::models::idp::IdpType::Oidc,
            oidc_config: Some(crate::models::idp::OidcConfig {
                issuer_url: "https://issuer.test/".into(),
                client_id: "cid".into(),
                client_secret_encrypted: store.encrypt_active_to_base64(b"plain").await.unwrap(),
                scopes: vec!["openid".into()],
                prompt: None,
            }),
            saml_config: None,
        };
        store.create_idp(&idp).await.unwrap();
        idp.id
    }

    async fn create_session(mgr: &SessionManager, idp_id: Uuid, user: &str) -> Session {
        mgr.create(user, idp_id, HashMap::new(), vec![], None, None, None, None)
            .await
            .unwrap()
    }

    async fn age_session(store: &Store, id: Uuid, seconds: i64) {
        sqlx::query("UPDATE sessions SET last_accessed_at = unixepoch() - ? WHERE id = ?")
            .bind(seconds)
            .bind(id)
            .execute(store.sqlite_pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn degraded_token_encryption_preserves_service_unavailable() {
        let store = Store::new_for_test_degraded("service DB offline")
            .await
            .unwrap();
        let mgr = SessionManager::new(store, 8);

        let err = mgr
            .create(
                "degraded@example.com",
                Uuid::new_v4(),
                HashMap::new(),
                vec![],
                Some("refresh-token"),
                None,
                None,
                None,
            )
            .await
            .expect_err("degraded encryption must stop session creation");

        assert!(matches!(err, crate::error::Error::ServiceUnavailable(_)));
    }

    #[tokio::test]
    async fn borrowed_oidc_tokens_are_encrypted_without_consuming_the_owner() {
        const REFRESH_TOKEN: &str = "refresh-token-sentinel";
        const ID_TOKEN: &str = "id-token-sentinel";

        let store = fresh_store().await;
        let idp_id = make_idp(&store).await;
        let mgr = SessionManager::new(store.clone(), 8);
        let refresh_token = OidcToken::new(REFRESH_TOKEN.to_string());
        let id_token = OidcToken::new(ID_TOKEN.to_string());

        let session = mgr
            .create(
                "tokens@x.com",
                idp_id,
                HashMap::new(),
                vec![],
                Some(refresh_token.expose_secret()),
                Some(id_token.expose_secret()),
                None,
                None,
            )
            .await
            .unwrap();

        assert!(
            refresh_token.expose_secret() == REFRESH_TOKEN,
            "refresh token owner must remain usable after session creation"
        );
        assert!(
            id_token.expose_secret() == ID_TOKEN,
            "ID token owner must remain usable after session creation"
        );

        let refresh_encrypted = session
            .refresh_token_encrypted
            .as_deref()
            .expect("refresh token ciphertext must be stored");
        let id_encrypted = session
            .id_token_encrypted
            .as_deref()
            .expect("ID token ciphertext must be stored");
        assert!(
            refresh_encrypted != REFRESH_TOKEN,
            "stored refresh token must not be plaintext"
        );
        assert!(
            id_encrypted != ID_TOKEN,
            "stored ID token must not be plaintext"
        );

        let refresh_plaintext = store
            .decrypt_any_from_base64(refresh_encrypted)
            .await
            .expect("refresh token ciphertext must decrypt");
        let id_plaintext = store
            .decrypt_any_from_base64(id_encrypted)
            .await
            .expect("ID token ciphertext must decrypt");
        assert!(
            refresh_plaintext.as_slice() == REFRESH_TOKEN.as_bytes(),
            "decrypted refresh token must match the borrowed input"
        );
        assert!(
            id_plaintext.as_slice() == ID_TOKEN.as_bytes(),
            "decrypted ID token must match the borrowed input"
        );
    }

    #[tokio::test]
    async fn coalesces_burst_validations_to_single_update() {
        let store = fresh_store().await;
        let idp_id = make_idp(&store).await;
        let mgr = SessionManager::new(store, 8);
        let session = create_session(&mgr, idp_id, "burst@x.com").await;

        // 100 back-to-back validations of the same session.
        for _ in 0..100 {
            mgr.validate(session.id).await.unwrap();
        }

        assert_eq!(
            mgr.persisted_count(),
            0,
            "no UPDATEs expected within window"
        );
        assert_eq!(
            mgr.skipped_count(),
            100,
            "all 100 reads should be coalesced"
        );
    }

    #[tokio::test]
    async fn persists_again_after_interval_elapses() {
        let store = fresh_store().await;
        let idp_id = make_idp(&store).await;
        let mgr = SessionManager::new(store.clone(), 8);
        let session = create_session(&mgr, idp_id, "interval@x.com").await;

        // First validation is within the seeded window — skipped.
        mgr.validate(session.id).await.unwrap();
        assert_eq!(mgr.persisted_count(), 0);
        assert_eq!(mgr.skipped_count(), 1);

        age_session(&store, session.id, 61).await;
        mgr.validate(session.id).await.unwrap();
        assert_eq!(
            mgr.persisted_count(),
            1,
            "elapsed-window validate should persist"
        );

        // And the immediately-following one should coalesce again.
        mgr.validate(session.id).await.unwrap();
        assert_eq!(mgr.persisted_count(), 1, "follow-up should re-coalesce");
        assert_eq!(mgr.skipped_count(), 2);
    }

    #[tokio::test]
    async fn distinct_sessions_are_tracked_independently() {
        let store = fresh_store().await;
        let idp_id = make_idp(&store).await;
        let mgr = SessionManager::new(store.clone(), 8);
        let s1 = create_session(&mgr, idp_id, "a@x.com").await;
        let s2 = create_session(&mgr, idp_id, "b@x.com").await;

        age_session(&store, s1.id, 61).await;
        age_session(&store, s2.id, 61).await;
        mgr.validate(s1.id).await.unwrap();
        assert_eq!(mgr.persisted_count(), 1);

        mgr.validate(s2.id).await.unwrap();
        assert_eq!(
            mgr.persisted_count(),
            2,
            "s2 should persist independently of s1"
        );
    }

    #[tokio::test]
    async fn touch_failure_is_awaited_and_next_validation_retries() {
        let store = fresh_store().await;
        let idp_id = make_idp(&store).await;
        let mgr = SessionManager::new(store.clone(), 8);
        let session = create_session(&mgr, idp_id, "retry@example.com").await;
        age_session(&store, session.id, 61).await;
        let aged = store.get_session_for_validation(session.id).await.unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_session_touch BEFORE UPDATE OF last_accessed_at ON sessions \
             BEGIN SELECT RAISE(ABORT, 'injected session touch failure'); END",
        )
        .execute(store.sqlite_pool())
        .await
        .unwrap();

        let error = mgr
            .validate(session.id)
            .await
            .expect_err("touch failure must reach the caller");
        assert!(error.to_string().contains("injected session touch failure"));
        sqlx::query("DROP TRIGGER reject_session_touch")
            .execute(store.sqlite_pool())
            .await
            .unwrap();

        let validated = mgr
            .validate(session.id)
            .await
            .expect("next validation must retry the durable touch");
        assert!(validated.last_accessed_at > aged.session.last_accessed_at);
        assert_eq!(mgr.persisted_count(), 1);
    }

    #[tokio::test]
    async fn revoke_deletes_the_durable_session() {
        let store = fresh_store().await;
        let idp_id = make_idp(&store).await;
        let mgr = SessionManager::new(store.clone(), 8);
        let session = create_session(&mgr, idp_id, "revoke@example.com").await;

        mgr.revoke(session.id).await.unwrap();
        assert!(
            matches!(store.get_session(session.id).await, Err(Error::NotFound)),
            "revoked session must not remain durable"
        );
    }
}
