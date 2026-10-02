//! ACME certificate issuance and renewal.
//!
//! - `mod.rs` — `AcmeManager`: leader gate, orchestration, renewal scheduling
//! - `storage.rs` — service-DB persistence of issued certs
//! - `challenge.rs` — sekishod's `Http01Provider` (impl of
//!   `acme_core::ChallengeProvider`); the trait itself lives in `acme_core`.
//! - `election.rs` / `queue.rs` — HA-specific leader election + work queue
//!
//! Pure ACME protocol code (order/CSR/finalize) lives in the
//! workspace `acme-core` crate. The split keeps DB/audit concerns
//! out of the protocol layer and sets up future sharing with kaido.

pub mod challenge;
pub mod election;
pub mod queue;
pub mod storage;

/// Process-wide lock serializing tests that mutate `SEKISHO_NODE_ID`.
///
/// `node_id()` reads the env var on every call, so two tests flipping
/// it concurrently produce cross-talk (whichever ran second observes
/// the other's value). Both `election::tests` and `leader_tests` reach
/// into the env, so the lock lives here at the shared parent and gets
/// acquired by any test that sets the var. An async mutex is used so
/// the guard can be held across `.await` points without tripping
/// `clippy::await_holding_lock`.
#[cfg(test)]
pub(crate) async fn env_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

use crate::error::{Error, Result};
use crate::models::cert::{CertSource, Certificate};
use crate::store::Store;
use acme_core::{AcmeAccount, ChallengeProvider};
use metrics::counter;
use std::sync::Arc;

#[cfg(test)]
type TestIssueHook = Arc<
    dyn Fn(
            String,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Certificate>> + Send>>
        + Send
        + Sync,
>;

#[cfg(test)]
pub(crate) type TestDrainErrorHook = Arc<dyn Fn() + Send + Sync>;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RenewalScanResult {
    pub inserted: usize,
    pub existing: usize,
    pub full: usize,
}

impl RenewalScanResult {
    pub fn is_empty(&self) -> bool {
        self.inserted == 0 && self.existing == 0 && self.full == 0
    }
}

/// Env var overriding the auto-detected node identifier. Takes
/// precedence over the OS hostname so operators running two daemons
/// on the same host (testing, blue/green) can disambiguate without
/// renaming the box.
pub const ENV_NODE_ID: &str = "SEKISHO_NODE_ID";

/// Resolve this node's identifier for leader comparisons. Preference
/// order:
///   1. `SEKISHO_NODE_ID` env var (trimmed, non-empty)
///   2. OS hostname
///   3. `"unknown"` — a sentinel that will never match a deliberately
///      set `acme_leader`, so a mis-resolve defaults to "not leader"
///      rather than accidentally hijacking issuance.
pub fn node_id() -> String {
    if let Ok(v) = std::env::var(ENV_NODE_ID) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Outcome of a skipped ACME operation on a non-leader node. The
/// leader name is included so the caller (and logs) can point the
/// operator at the node that owns issuance.
#[derive(Debug, Clone)]
pub struct NotLeader {
    pub my_node_id: String,
    pub leader: String,
}

/// Manages ACME certificate issuance and renewal.
/// Challenge handling is delegated to a `ChallengeProvider` implementation.
pub struct AcmeManager<C: ChallengeProvider = challenge::Http01Provider> {
    store: Store,
    challenge: Arc<C>,
    acme_directory: String,
    acme_email: Option<String>,
    /// Process-local owner for the durable account. Initialization is lazy so
    /// a directory outage never turns daemon startup into an ACME dependency.
    account: tokio::sync::OnceCell<AcmeAccount>,
    #[cfg(test)]
    test_issue_hook: Option<TestIssueHook>,
    #[cfg(test)]
    test_drain_error_hook: Option<TestDrainErrorHook>,
}

impl<C: ChallengeProvider + 'static> AcmeManager<C> {
    pub fn new(
        store: Store,
        challenge: Arc<C>,
        acme_directory: &str,
        acme_email: Option<String>,
    ) -> Self {
        Self {
            store,
            challenge,
            acme_directory: acme_directory.to_string(),
            acme_email,
            account: tokio::sync::OnceCell::new(),
            #[cfg(test)]
            test_issue_hook: None,
            #[cfg(test)]
            test_drain_error_hook: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_issue_hook<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Certificate>> + Send + 'static,
    {
        self.test_issue_hook = Some(Arc::new(move |domain| Box::pin(hook(domain))));
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_drain_error_hook<F>(mut self, hook: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.test_drain_error_hook = Some(Arc::new(hook));
        self
    }

    #[cfg(test)]
    pub(crate) fn test_drain_error_hook(&self) -> Option<TestDrainErrorHook> {
        self.test_drain_error_hook.clone()
    }

    /// Restore the durable account, or create it only when no credential row
    /// exists. `OnceCell` serializes concurrent first use within this process;
    /// the service-DB insert below resolves races between processes.
    async fn account(&self) -> Result<&AcmeAccount> {
        self.account
            .get_or_try_init(|| async {
                if let Some(credentials) = self.store.load_acme_account_credentials().await? {
                    return AcmeAccount::restore(&self.acme_directory, credentials)
                        .await
                        .map_err(Error::from);
                }

                let (candidate, credentials) =
                    AcmeAccount::create(&self.acme_directory, self.acme_email.as_deref()).await?;
                match self
                    .store
                    .insert_acme_account_credentials_if_absent(credentials)
                    .await?
                {
                    crate::store::acme_account::AcmeAccountCredentialInsert::Inserted => {
                        Ok(candidate)
                    }
                    crate::store::acme_account::AcmeAccountCredentialInsert::Existing(
                        credentials,
                    ) => {
                        // Another node durably won after our missing-row read.
                        // The local candidate is not authoritative.
                        drop(candidate);
                        AcmeAccount::restore(&self.acme_directory, credentials)
                            .await
                            .map_err(Error::from)
                    }
                }
            })
            .await
    }

    /// Get a reference to the challenge provider (e.g., for the HTTP responder).
    pub fn challenge_provider(&self) -> &Arc<C> {
        &self.challenge
    }

    /// Check whether this node is allowed to run ACME operations right now.
    ///
    /// Two modes, selected by `GlobalConfig.acme_leader`:
    ///
    /// * `Some(leader)` → **static override**. Operator pinned issuance
    ///   to a named node; comparison is against `node_id()` and the
    ///   auto-election row is ignored. Useful for drills and for
    ///   forcing a specific node during incident response.
    /// * `None` → **auto election**. Defer to the row the background
    ///   tick maintains. A missing row means the tick hasn't landed
    ///   yet, which resolves to "not leader" — safer than assuming
    ///   yes on a freshly-started cluster.
    ///
    /// Config is read fresh each call so a mode flip takes effect on
    /// the next issuance attempt without a restart. `get_config` hits
    /// the in-process cache when unchanged, so this is cheap in both
    /// modes.
    pub(crate) async fn leader_check(&self) -> Result<std::result::Result<(), NotLeader>> {
        let cfg = self.store.get_config().await?;
        let me = node_id();

        // Static override: operator named a specific leader; election
        // row is irrelevant even if it disagrees.
        if let Some(pinned) = cfg.acme_leader {
            return if me == pinned {
                Ok(Ok(()))
            } else {
                Ok(Err(NotLeader {
                    my_node_id: me,
                    leader: pinned,
                }))
            };
        }

        // Auto election: trust the background-tick row.
        let election = election::AcmeElection::new(self.store.clone());
        if election.is_leader().await? {
            Ok(Ok(()))
        } else {
            let current = self
                .store
                .acme_election_read()
                .await?
                .map(|row| row.node_id)
                .unwrap_or_else(|| "<not yet elected>".into());
            Ok(Err(NotLeader {
                my_node_id: me,
                leader: current,
            }))
        }
    }

    /// Issue a certificate for the given domain via the configured
    /// challenge type. Applies the leader gate, then delegates to
    /// [`Self::issue_certificate_unchecked`] for the actual order.
    ///
    /// Retained for tests and direct callers that need gate-then-issue
    /// behaviour as one call. Production manual and renewal paths enqueue;
    /// the queue worker owns the gate and calls the unchecked variant.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn issue_certificate(&self, domain: &str) -> Result<Certificate> {
        // Point-in-time leader gate for this issuance attempt. The
        // direct caller receives BadRequest on a failed check.
        // A successful check is not revisited while the order runs.
        if let Err(not_leader) = self.leader_check().await? {
            tracing::info!(
                domain,
                my_node_id = %not_leader.my_node_id,
                leader = %not_leader.leader,
                "refusing ACME issuance: this node is not the configured leader"
            );
            return Err(Error::BadRequest(format!(
                "ACME issuance is pinned to node '{}'; retry the request against that node",
                not_leader.leader
            )));
        }
        self.issue_certificate_unchecked(domain).await
    }

    /// Run the ACME order without the leader gate.
    ///
    /// The production queue worker uses this after its point-in-time leader
    /// check. This function performs no leader check or in-order re-check, so
    /// a started order can continue after election or configuration changes.
    pub(crate) async fn issue_certificate_unchecked(&self, domain: &str) -> Result<Certificate> {
        tracing::info!(domain, "starting ACME certificate issuance");
        #[cfg(test)]
        let result = match &self.test_issue_hook {
            Some(hook) => hook(domain.to_owned()).await,
            None => self.issue_certificate_unchecked_inner(domain).await,
        };
        #[cfg(not(test))]
        let result = self.issue_certificate_unchecked_inner(domain).await;
        let outcome = if result.is_ok() { "success" } else { "failure" };
        counter!("sekisho_acme_issuance_total", "result" => outcome).increment(1);
        result
    }

    async fn issue_certificate_unchecked_inner(&self, domain: &str) -> Result<Certificate> {
        // Three steps, each in its own module:
        //   1. ACME protocol — talk to the directory, get cert + key PEM.
        //   2. Storage       — encrypt the key, build the row, upsert (3 retries).
        //   3. Audit         — emit the `cert.issue.success` event so the
        //                      queue worker's orders share one system stream.
        let issued = self
            .account()
            .await?
            .issue(domain, &self.challenge, None)
            .await?;

        let certificate = storage::persist_acme_cert(
            &self.store,
            domain,
            issued.certificate_pem,
            issued.private_key_pem,
        )
        .await?;

        // All production orders run in the queue worker, without an inbound
        // actor at execution time, so the result is attributed to `system`.
        tracing::info!(
            target: crate::audit::TARGET,
            event = "cert.issue.success",
            category = "system",
            result = "success",
            actor_type = "system",
            actor_id = "system",
            target_resource = "cert",
            target_id = %certificate.id,
            domain = %domain,
            action = "issue",
            expires_at = %certificate.expires_at,
            "certificate issued"
        );

        Ok(certificate)
    }

    /// Enqueue ACME renewals whose actual validity has reached two-thirds.
    ///
    /// Called on a timer from `runtime::run`. In an HA deployment every
    /// node runs this tick and performs one point-in-time leader check.
    /// A passing node does not re-check during the pass; scheduled orders
    /// can continue after a leader change and overlap a later pass on
    /// another node. Non-leader ticks log at `debug` and return empty.
    pub async fn renew_expiring(self: &Arc<Self>) -> Result<RenewalScanResult> {
        if let Err(not_leader) = self.leader_check().await? {
            tracing::debug!(
                my_node_id = %not_leader.my_node_id,
                leader = %not_leader.leader,
                "skipping ACME renewal scan: this node is not the configured leader"
            );
            return Ok(RenewalScanResult::default());
        }

        let now = chrono::Utc::now();
        let due = self
            .store
            .get_expiring_certs((chrono::DateTime::<chrono::Utc>::MAX_UTC - now).num_days())
            .await?
            .into_iter()
            .filter(|cert| matches!(cert.source, CertSource::Acme))
            .filter(|cert| {
                let validity = cert.expires_at - cert.issued_at;
                let elapsed = now - cert.issued_at;
                validity > chrono::Duration::zero()
                    && elapsed.num_seconds().saturating_mul(3)
                        >= validity.num_seconds().saturating_mul(2)
            });

        let mut result = RenewalScanResult::default();
        for cert in due {
            match self
                .store
                .acme_queue_enqueue(&cert.domain, &node_id())
                .await?
            {
                crate::models::acme_queue::AcmeQueueAdmission::Inserted(_) => {
                    result.inserted += 1;
                }
                crate::models::acme_queue::AcmeQueueAdmission::Existing(_) => {
                    result.existing += 1;
                }
                crate::models::acme_queue::AcmeQueueAdmission::Full => {
                    result.full += 1;
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod leader_tests {
    use super::*;
    use crate::store::Store;
    use acme_core::{ChallengeType, ProviderError};
    use zeroize::Zeroizing;

    const TEST_MASTER_KEY: [u8; 32] = [0u8; 32];

    /// No-op challenge provider for leader-gate tests — we never reach
    /// the network path so the trait methods should never be called.
    /// If they are, the assertions fail loudly rather than silently
    /// talking to Let's Encrypt.
    struct PanicProvider;

    impl ChallengeProvider for PanicProvider {
        fn challenge_type(&self) -> ChallengeType {
            ChallengeType::Http01
        }
        async fn set(
            &self,
            _domain: &str,
            _token: &str,
            _key_auth: &str,
        ) -> std::result::Result<(), ProviderError> {
            panic!("challenge.set called — leader gate failed to short-circuit");
        }
        async fn cleanup(&self, _domain: &str) -> std::result::Result<(), ProviderError> {
            panic!("challenge.cleanup called — leader gate failed to short-circuit");
        }
    }

    use super::env_guard;

    async fn manager_with_config(
        acme_leader: Option<&str>,
    ) -> (Store, Arc<AcmeManager<PanicProvider>>) {
        let store = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .expect("store");
        if let Some(leader) = acme_leader {
            store
                .update_config(serde_json::json!({ "acme_leader": leader }))
                .await
                .expect("set leader");
        }
        let mgr = Arc::new(AcmeManager::new(
            store.clone(),
            Arc::new(PanicProvider),
            "https://acme.example.invalid/directory",
            None,
        ));
        (store, mgr)
    }

    #[tokio::test]
    async fn acme_issuance_skipped_on_non_leader() {
        let _g = env_guard().await;
        // SAFETY: tests are serialized on env_guard; the env var is
        // read once inside node_id() and not mutated concurrently.
        unsafe {
            std::env::set_var(ENV_NODE_ID, "node-this");
        }
        let (_store, mgr) = manager_with_config(Some("node-other")).await;

        // The direct gate-then-issue helper refuses with a BadRequest
        // before the provider is reached.
        let err = mgr
            .issue_certificate("gate.example")
            .await
            .expect_err("non-leader should not proceed to ACME");
        assert!(matches!(err, Error::BadRequest(_)), "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("node-other"), "err should name leader: {msg}");

        // Background renewal is a silent skip — returns an empty Vec,
        // not an error, so the periodic task just logs at debug and
        // ticks again.
        let renewed = mgr.renew_expiring().await.expect("renew_expiring");
        assert!(renewed.is_empty());

        unsafe {
            std::env::remove_var(ENV_NODE_ID);
        }
    }

    #[tokio::test]
    async fn acme_denied_when_election_row_is_missing() {
        let _g = env_guard().await;
        unsafe {
            std::env::set_var(ENV_NODE_ID, "node-anything");
        }
        let (_store, mgr) = manager_with_config(None).await;
        let not_leader = mgr
            .leader_check()
            .await
            .expect("leader check")
            .expect_err("a missing election row must fail closed");
        assert_eq!(not_leader.my_node_id, "node-anything");
        assert_eq!(not_leader.leader, "<not yet elected>");

        let err = mgr
            .issue_certificate("missing-election.example")
            .await
            .expect_err("issuance must stop at the missing-row gate");
        assert!(matches!(err, Error::BadRequest(_)), "got {err:?}");
        assert!(err.to_string().contains("<not yet elected>"));
        unsafe {
            std::env::remove_var(ENV_NODE_ID);
        }
    }

    #[tokio::test]
    async fn acme_allowed_when_this_node_is_leader() {
        let _g = env_guard().await;
        unsafe {
            std::env::set_var(ENV_NODE_ID, "this-node");
        }
        let (_store, mgr) = manager_with_config(Some("this-node")).await;
        // leader_check should say yes; renewal passes the gate and
        // returns empty (no certs to renew in the fresh DB). If the
        // gate let through past empty_certs, the PanicProvider would
        // trip in issue_certificate.
        let renewed = mgr.renew_expiring().await.expect("renew_expiring");
        assert!(renewed.is_empty());
        unsafe {
            std::env::remove_var(ENV_NODE_ID);
        }
    }

    #[tokio::test]
    async fn renewal_admission_uses_exact_two_thirds_of_actual_validity() {
        let _g = env_guard().await;
        unsafe {
            std::env::set_var(ENV_NODE_ID, "renewal-node");
        }
        let (store, mgr) = manager_with_config(None).await;
        election::AcmeElection::new(store.clone())
            .tick()
            .await
            .unwrap();
        let now = chrono::Utc::now();
        for (domain, issued_at, expires_at) in [
            (
                "due.example",
                now - chrono::Duration::days(60),
                now + chrono::Duration::days(30),
            ),
            (
                "not-due.example",
                now - chrono::Duration::days(59),
                now + chrono::Duration::days(31),
            ),
        ] {
            store
                .upsert_cert(&Certificate {
                    id: uuid::Uuid::new_v4(),
                    domain: domain.into(),
                    cert_pem: "test-only".into(),
                    key_pem_encrypted: "test-only".into(),
                    issued_at,
                    expires_at,
                    source: CertSource::Acme,
                })
                .await
                .unwrap();
        }

        let result = mgr.renew_expiring().await.unwrap();
        assert_eq!(result.inserted, 1);
        assert_eq!(result.existing, 0);
        assert_eq!(result.full, 0);
        let queued = sqlx::query_scalar::<_, String>("SELECT domain FROM acme_queue")
            .fetch_all(store.sqlite_pool())
            .await
            .unwrap();
        assert_eq!(queued, vec!["due.example"]);
        unsafe {
            std::env::remove_var(ENV_NODE_ID);
        }
    }

    #[tokio::test]
    async fn invalid_persisted_credentials_fail_without_account_replacement() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let store = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .expect("store");
        let invalid = acme_core::AcmeAccountCredentials::from_zeroizing(Zeroizing::new(
            b"invalid-account-envelope-sentinel".to_vec(),
        ));
        assert!(matches!(
            store
                .insert_acme_account_credentials_if_absent(invalid)
                .await
                .unwrap(),
            crate::store::acme_account::AcmeAccountCredentialInsert::Inserted
        ));
        let manager = AcmeManager::new(
            store.clone(),
            Arc::new(PanicProvider),
            "https://acme.example.invalid/directory",
            None,
        );

        let result = tokio::time::timeout(std::time::Duration::from_secs(1), manager.account())
            .await
            .expect("credential validation must happen before network I/O");
        let Err(error) = result else {
            panic!("invalid persisted credentials must fail loudly");
        };
        assert!(matches!(error, Error::ConfigurationError(_)));
        assert!(!error.to_string().contains("sentinel"));
        assert!(store.load_acme_account_credentials().await.is_ok());
        store.close().await;
    }

    /// Static override trumps any auto-election state. Even if this
    /// node is sitting on a winning election row, a config that names
    /// a *different* node as leader should flip us back to non-leader
    /// and surface `NotLeader` on the direct gate path. This is the
    /// operator-escape-hatch property — drills rely on it.
    #[tokio::test]
    async fn leader_check_respects_static_override() {
        let _g = env_guard().await;
        unsafe {
            std::env::set_var(ENV_NODE_ID, "node-self");
        }

        let store = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .expect("store");

        // Seed the election row so this node would be "auto leader"
        // absent any override.
        let election = election::AcmeElection::new(store.clone());
        let outcome = election.tick().await.expect("tick");
        assert!(outcome.i_am_leader, "sanity: tick should elect us");

        // Now pin the override to a different node — we should be
        // refused despite owning the election row.
        store
            .update_config(serde_json::json!({ "acme_leader": "node-other" }))
            .await
            .expect("set override");

        let mgr = Arc::new(AcmeManager::new(
            store.clone(),
            Arc::new(PanicProvider),
            "https://acme.example.invalid/directory",
            None,
        ));

        let err = mgr
            .issue_certificate("override.example")
            .await
            .expect_err("override should refuse issuance");
        let msg = err.to_string();
        assert!(
            msg.contains("node-other"),
            "err should name the pinned leader, got: {msg}"
        );

        unsafe {
            std::env::remove_var(ENV_NODE_ID);
        }
    }

    /// `acme_leader = None` hands the decision to the election row.
    /// After the first tick this node owns that row, so `leader_check`
    /// must say yes — renewal passes the gate and (lacking any
    /// expiring certs) returns empty. If the auto-election path
    /// silently refused, the pre-HA behaviour would regress.
    #[tokio::test]
    async fn leader_check_uses_election_when_config_none() {
        let _g = env_guard().await;
        unsafe {
            std::env::set_var(ENV_NODE_ID, "node-auto");
        }

        let store = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .expect("store");
        // No `update_config` call — `acme_leader` stays `None`,
        // exercising the auto path.

        // Tick once so the election row exists and names us.
        let election = election::AcmeElection::new(store.clone());
        election.tick().await.expect("tick");

        let mgr = Arc::new(AcmeManager::new(
            store,
            Arc::new(PanicProvider),
            "https://acme.example.invalid/directory",
            None,
        ));

        // Renewal passes the gate — empty result, not an error.
        let renewed = mgr.renew_expiring().await.expect("renew_expiring");
        assert!(renewed.is_empty());

        unsafe {
            std::env::remove_var(ENV_NODE_ID);
        }
    }
}
