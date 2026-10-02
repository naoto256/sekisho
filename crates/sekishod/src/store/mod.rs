//! Store facade.
//!
//! `Store` is the only storage type the rest of the crate (API handlers,
//! proxy, middleware) should see. It holds:
//!
//! * a `Backend` — the enum that dispatches persistence calls to a
//!   concrete implementation (`Sqlite` for single-node, `Postgres` for
//!   HA; `Unavailable` when a configured service DB is unreachable),
//! * storage-adjacent process caches such as global config, and
//! * the per-process "last seen" version markers that drive cache
//!   invalidation against the DB-sourced version counters (see
//!   `store::version`).
//!
//! Per-resource method bodies live in `route.rs`, `idp.rs`, etc., each of
//! which does pure dispatch (`match self.backend { ... }`) plus any local
//! cache management.

pub mod backend;
pub mod instance;
pub mod merge;
pub mod route_cache;
pub mod version;

pub(crate) mod acme_account;
pub mod acme_challenge;
pub mod acme_election;
pub mod acme_queue;
pub mod api_key;
pub mod cert;
pub mod config;
pub mod dek_rotation;
pub mod identity_signing;
pub mod idp;
pub mod key_ring_loader;
pub mod master_keys;
pub mod policy;
pub mod route;
pub mod secrets;
pub mod session;

#[cfg(test)]
#[path = "route_cache_test.rs"]
mod route_cache_test;

#[cfg(test)]
#[path = "store_test.rs"]
mod store_test;

#[cfg(test)]
#[path = "ha_test.rs"]
mod ha_test;

use crate::crypto::MasterKey;
use backend::{Backend, PostgresBackend, SqliteBackend};
use instance::InstanceStore;

/// Dispatch a backend method on `&self`, returning the awaited value.
/// Keeps the per-resource facade methods to a single line without
/// borrowing or pattern-match repetition. Each `Backend` variant must
/// have an arm here; missing one is a compile error, which is the
/// entire point of using an enum over `Box<dyn Trait>`.
macro_rules! dispatch {
    ($self:ident, $method:ident $(, $arg:expr)* $(,)?) => {
        match &$self.backend {
            $crate::store::backend::Backend::Sqlite(b) => {
                <$crate::store::backend::SqliteBackend
                    as $crate::store::backend::StorageBackend>::$method(b $(, $arg)*).await
            }
            $crate::store::backend::Backend::Postgres(b) => {
                <$crate::store::backend::PostgresBackend
                    as $crate::store::backend::StorageBackend>::$method(b $(, $arg)*).await
            }
            // Degraded mode: service DB unreachable at startup. Every
            // operational call is short-circuited to 503 so the HTTP
            // layer returns a clean "come back later" without touching
            // a pool we know isn't there. Bootstrap API handlers go
            // through `InstanceStore`, not this dispatch, and stay up.
            $crate::store::backend::Backend::Unavailable { reason } => {
                Err($crate::error::Error::ServiceUnavailable(reason.clone()))
            }
        }
    };
}
pub(crate) use dispatch;

#[derive(Clone)]
pub struct Store {
    pub(super) backend: Backend,
    /// Per-node bootstrap SQLite. Lives alongside the backend regardless
    /// of topology — even when a remote Postgres provides the service
    /// tables, bootstrap state (encrypted service DB URL, future
    /// node-local knobs) still needs a local home.
    pub(super) instance: InstanceStore,
    /// Cached GlobalConfig — invalidated on update.
    pub(super) config_cache:
        std::sync::Arc<std::sync::RwLock<Option<crate::models::config::GlobalConfig>>>,
    /// Last config version observed by this process — drives staleness
    /// detection on the read path. DB sequence is the source of truth; this
    /// is purely a local "did we reload since the last bump" marker.
    pub(super) config_seen_version: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// In-process snapshot of the DEK ring. Encrypt and decrypt clone the
    /// inner `Arc`, then release the lock before doing cryptographic work.
    /// The polling loop replaces that pointer wholesale on a
    /// `key_ring_version` mismatch, so readers see either a complete old
    /// snapshot or a complete new one, never a partial ring.
    ///
    /// Construction starts with a single-DEK placeholder generated from
    /// the system RNG. A reachable backend replaces it before `new`
    /// returns; the degraded branch skips that load and retains it.
    pub(super) key_ring:
        std::sync::Arc<tokio::sync::RwLock<std::sync::Arc<crate::crypto::MasterKeyRing>>>,
    pub(super) identity_key_ring: std::sync::Arc<
        tokio::sync::RwLock<Option<std::sync::Arc<crate::crypto::IdentityKeyRingSnapshot>>>,
    >,
}

impl Store {
    #[cfg(test)]
    pub(crate) fn shares_master_key(&self, expected: &std::sync::Arc<MasterKey>) -> bool {
        let backend_matches = match &self.backend {
            Backend::Sqlite(backend) => backend.shares_master_key(expected),
            Backend::Postgres(backend) => backend.shares_master_key(expected),
            Backend::Unavailable { .. } => true,
        };
        self.instance.shares_master_key(expected) && backend_matches
    }

    /// Open the backends a node needs and return a ready-to-use `Store`.
    ///
    /// Two databases are involved, deliberately separated so a multi-node
    /// (HA) deployment can push operational state into a shared RDBMS
    /// while each node keeps its own local bootstrap file:
    ///
    /// * `bootstrap_path` — always opened as SQLite via `InstanceStore`.
    ///   Holds per-instance bootstrap state, including the encrypted
    ///   `cluster_db_url` entry. When no cluster DB is configured this
    ///   same file also plays the service role (single-node default)
    ///   and operational migrations run against it; when a remote
    ///   service DB is configured the file stays bootstrap-only —
    ///   operational DDL is never executed here.
    /// * Service DB URL — resolved internally from the bootstrap DB's
    ///   encrypted `instance_config` row. A persisted value takes
    ///   precedence while present. On a boot where it is absent, a
    ///   non-empty `SEKISHO_SERVICE_DB` value is persisted and used.
    ///   Resolved values route to a backend by scheme:
    ///     * unset / empty → reuse the bootstrap SQLite (single-node).
    ///     * `postgres://…` / `postgresql://…` → `PostgresBackend` (HA).
    ///     * `sqlite:…` or a bare path → a separate SQLite file.
    ///
    /// `master_key` is the process-wide 32-byte key used to
    /// encrypt/decrypt instance_config entries. Losing it means losing
    /// the service DB pointer with it — which is the intended property
    /// (two-layer defence: DB file alone is useless without the key,
    /// and the key alone is useless without the DB).
    ///
    /// `bootstrap_path` accepts anything `SqliteConnectOptions::from_str`
    /// understands — including the in-memory form `sqlite::memory:`
    /// (for tests) and bare filesystem paths (production). A raw path is
    /// normalised to `sqlite:<path>` automatically.
    pub async fn new(
        bootstrap_path: &str,
        master_key: std::sync::Arc<MasterKey>,
    ) -> std::result::Result<Self, sqlx::Error> {
        let bootstrap_url = to_sqlite_url(bootstrap_path);
        let instance =
            InstanceStore::new(&bootstrap_url, std::sync::Arc::clone(&master_key)).await?;

        // Resolve the effective service DB URL. A persisted value wins;
        // when none exists, a non-empty env value is persisted and used.
        // If both exist, the env value is ignored after a warning.
        let service_db_url = resolve_service_db_url(&instance).await?;

        let backend = match service_db_url.as_deref() {
            // Default: the bootstrap SQLite is also the service backend.
            // Reusing the same pool avoids opening the file twice and
            // keeps cache-invalidation wiring coherent. Operational
            // migrations run here — and only here — so a node configured
            // with a remote service DB never gets those tables created
            // in its bootstrap file.
            //
            // No degraded-mode fallback on this path: we already hold
            // the bootstrap pool, so if the reuse open fails the whole
            // bootstrap file is broken — there is nothing to stay up
            // for, and propagating the error produces a clearer fatal
            // than the vague "service unavailable".
            None => Backend::Sqlite(
                SqliteBackend::from_pool_as_service(
                    instance.pool().clone(),
                    std::sync::Arc::clone(&master_key),
                )
                .await?,
            ),
            Some(url) if is_postgres_url(url) => {
                open_service_backend(url, std::sync::Arc::clone(&master_key)).await
            }
            Some(url) => {
                let sqlite_url = to_sqlite_url(url);
                open_service_backend(&sqlite_url, std::sync::Arc::clone(&master_key)).await
            }
        };

        let store = Self {
            backend,
            instance,
            config_cache: std::sync::Arc::new(std::sync::RwLock::new(None)),
            config_seen_version: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            // Every Store starts with a single-DEK placeholder generated
            // from the system RNG. The reachable branch below replaces it
            // from `master_keys`; the degraded branch retains this ring.
            key_ring: std::sync::Arc::new(tokio::sync::RwLock::new(std::sync::Arc::new(
                crate::crypto::placeholder_ring(),
            ))),
            identity_key_ring: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        };
        // Boot ring load is skipped in degraded mode because no service
        // backend is available. Backend-dispatched operations return 503,
        // and `encrypt_active_to_base64` rejects the degraded Store before
        // reading this ring. Other direct ring methods retain access to
        // the placeholder above.
        if store.is_service_backend_available() {
            match key_ring_loader::load_or_init(&store, &master_key).await {
                Ok(ring) => *store.key_ring.write().await = std::sync::Arc::new(ring),
                Err(e) => {
                    return Err(sqlx::Error::Protocol(format!("DEK ring load failed: {e}")));
                }
            }
            store.ensure_identity_signing_ring().await.map_err(|e| {
                sqlx::Error::Protocol(format!("identity signing ring load failed: {e}"))
            })?;
        }
        Ok(store)
    }

    /// Replace the in-memory key ring with a fresh snapshot. Used by the
    /// runtime version-poll refresh and by the key-management add,
    /// activate, and retire handlers.
    pub async fn replace_key_ring(&self, ring: crate::crypto::MasterKeyRing) {
        *self.key_ring.write().await = std::sync::Arc::new(ring);
    }

    pub(crate) async fn replace_identity_key_ring(
        &self,
        ring: std::sync::Arc<crate::crypto::IdentityKeyRingSnapshot>,
    ) {
        let mut published = self.identity_key_ring.write().await;
        if let Some(current) = published.as_ref() {
            current.replace_with(&ring);
        } else {
            *published = Some(ring);
        }
    }

    pub(crate) async fn identity_key_ring_snapshot(
        &self,
    ) -> crate::error::Result<std::sync::Arc<crate::crypto::IdentityKeyRingSnapshot>> {
        self.identity_key_ring.read().await.clone().ok_or_else(|| {
            crate::error::Error::ServiceUnavailable("identity signing key ring is not ready".into())
        })
    }

    /// Encrypt with the active DEK, returning a base64 v3 blob suitable
    /// for the existing `_encrypted` text columns. Hot path: clones the
    /// shared ring pointer so the read lock isn't held across the AEAD work.
    ///
    /// A degraded Store is rejected before the placeholder ring is read:
    /// that ring is process-local and cannot produce restart-safe storage.
    pub async fn encrypt_active_to_base64(&self, plaintext: &[u8]) -> crate::error::Result<String> {
        if let Backend::Unavailable { reason } = &self.backend {
            return Err(crate::error::Error::ServiceUnavailable(reason.clone()));
        }
        let ring = {
            let current = self.key_ring.read().await;
            std::sync::Arc::clone(&current)
        };
        Ok(ring.encrypt_active_to_base64(plaintext)?)
    }

    /// Decrypt a v3 (ring-routed) blob. v2 (KEK-direct) blobs are
    /// refused here because every ring-routed column is v3; a v2 blob
    /// reaching this path violates the storage contract, so fail loudly
    /// rather than silently KEK-decrypting it.
    ///
    /// `store::instance` and `auth::handoff` use the process-shared
    /// `MasterKey` capability directly, never through the ring.
    pub async fn decrypt_any_from_base64(
        &self,
        encoded: &str,
    ) -> std::result::Result<Vec<u8>, crate::crypto::CryptoError> {
        self.decrypt_any_from_base64_zeroizing(encoded)
            .await
            .map(|plaintext| plaintext.to_vec())
    }

    /// Decrypt a v3 blob while retaining zeroizing ownership of plaintext.
    ///
    /// Secret capabilities that can accept a `Zeroizing<Vec<u8>>` should use
    /// this seam so the store does not create a second full plaintext buffer.
    pub(crate) async fn decrypt_any_from_base64_zeroizing(
        &self,
        encoded: &str,
    ) -> std::result::Result<zeroize::Zeroizing<Vec<u8>>, crate::crypto::CryptoError> {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(crate::crypto::CryptoError::from)?;
        match data.first() {
            Some(&envelope_aead::CIPHER_V3) => {
                let ring = {
                    let current = self.key_ring.read().await;
                    std::sync::Arc::clone(&current)
                };
                ring.decrypt(&data)
            }
            Some(&other) => Err(envelope_aead::Error::UnknownVersion(other)),
            None => Err(envelope_aead::Error::CiphertextTooShort),
        }
    }

    /// Shared snapshot of the current complete ring. The returned `Arc`
    /// remains valid across a later pointer swap. Used by bulk re-encrypt
    /// and by callers that need a coherent ring without holding the lock.
    pub async fn key_ring_snapshot(&self) -> std::sync::Arc<crate::crypto::MasterKeyRing> {
        let current = self.key_ring.read().await;
        std::sync::Arc::clone(&current)
    }

    /// Borrow the instance store so API handlers can read / mutate
    /// the per-node `instance_config` table (encrypted rows for
    /// secrets like the service DB URL, plaintext rows for non-secret
    /// settings — same table, per-row `encrypted` flag). Crate-visible
    /// only; callers outside `sekishod` see bootstrap state through
    /// the management API.
    pub(crate) fn instance(&self) -> &InstanceStore {
        &self.instance
    }

    /// Test helper: open a `Store` whose service DB is explicitly
    /// `service_db_url`, bypassing the env-var / instance_config
    /// resolution path. Used by tests that need to point several
    /// nodes at the same Postgres schema without touching process
    /// env vars (which are inherently global and race-prone).
    #[cfg(test)]
    pub(crate) async fn new_for_test(
        bootstrap_path: &str,
        master_key: [u8; 32],
        service_db_url: Option<&str>,
    ) -> std::result::Result<Self, sqlx::Error> {
        let master_key = MasterKey::from_test_bytes(master_key);
        let bootstrap_url = to_sqlite_url(bootstrap_path);
        let instance =
            InstanceStore::new(&bootstrap_url, std::sync::Arc::clone(&master_key)).await?;

        let backend = match service_db_url {
            None => Backend::Sqlite(
                SqliteBackend::from_pool_as_service(
                    instance.pool().clone(),
                    std::sync::Arc::clone(&master_key),
                )
                .await?,
            ),
            Some(url) if is_postgres_url(url) => {
                open_service_backend(url, std::sync::Arc::clone(&master_key)).await
            }
            Some(url) => {
                let sqlite_url = to_sqlite_url(url);
                open_service_backend(&sqlite_url, std::sync::Arc::clone(&master_key)).await
            }
        };

        let store = Self {
            backend,
            instance,
            config_cache: std::sync::Arc::new(std::sync::RwLock::new(None)),
            config_seen_version: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            key_ring: std::sync::Arc::new(tokio::sync::RwLock::new(std::sync::Arc::new(
                crate::crypto::placeholder_ring(),
            ))),
            identity_key_ring: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        };
        if store.is_service_backend_available() {
            match key_ring_loader::load_or_init(&store, &master_key).await {
                Ok(ring) => *store.key_ring.write().await = std::sync::Arc::new(ring),
                Err(e) => {
                    return Err(sqlx::Error::Protocol(format!("DEK ring load failed: {e}")));
                }
            }
            store.ensure_identity_signing_ring().await.map_err(|e| {
                sqlx::Error::Protocol(format!("identity signing ring load failed: {e}"))
            })?;
        }
        Ok(store)
    }

    /// Test-only view of the routes version row. Production observes this
    /// value together with ordered routes through `observe_routes`.
    #[cfg(test)]
    pub async fn route_version_current(&self) -> crate::error::Result<u64> {
        dispatch!(self, route_version_current)
    }

    /// Current DB-sourced version for the IdP resource. Analogous to
    /// `route_version_current`; used by `AppState::invalidate_idp_clients_if_stale`.
    pub async fn idp_version_current(&self) -> crate::error::Result<u64> {
        dispatch!(self, idp_version_current)
    }

    /// Current DB-sourced version for the config resource. Consumed
    /// internally by `get_config` / `update_config` for local cache
    /// staleness checks.
    pub(super) async fn config_version_current(&self) -> crate::error::Result<u64> {
        dispatch!(self, config_version_current)
    }

    /// Current DB-sourced version for the certificates resource. Read
    /// by the proxy's periodic cert-cache invalidation check; a bump
    /// on any node (ACME renewal, mgmt-API upload/delete) tells every
    /// peer to reload `CertResolver`.
    pub async fn cert_version_current(&self) -> crate::error::Result<u64> {
        dispatch!(self, cert_version_current)
    }

    /// Record a pending-auth flow. Delegates to whichever operational
    /// backend is configured so HA topologies share state automatically.
    pub async fn pending_auth_insert(
        &self,
        csrf_token: &str,
        state: &crate::auth::middleware::PendingAuth,
    ) -> crate::error::Result<()> {
        dispatch!(self, pending_auth_insert, csrf_token, state)
    }

    /// Expiry-aware read that leaves the pending-auth row intact.
    pub async fn pending_auth_get(
        &self,
        csrf_token: &str,
    ) -> crate::error::Result<Option<crate::auth::middleware::PendingAuth>> {
        dispatch!(self, pending_auth_get, csrf_token)
    }

    /// Atomic read-and-delete of a pending-auth row.
    pub async fn pending_auth_take(
        &self,
        csrf_token: &str,
    ) -> crate::error::Result<Option<crate::auth::middleware::PendingAuth>> {
        dispatch!(self, pending_auth_take, csrf_token)
    }

    /// Background sweeper helper — deletes rows past TTL.
    pub async fn pending_auth_cleanup_expired(&self) -> crate::error::Result<u64> {
        dispatch!(self, pending_auth_cleanup_expired)
    }

    /// Atomically claim a handoff nonce in the shared service database.
    pub async fn handoff_nonce_consume(&self, nonce: uuid::Uuid) -> crate::error::Result<bool> {
        dispatch!(self, handoff_nonce_consume, nonce)
    }

    /// Remove handoff nonces older than the fixed replay-retention window.
    pub async fn handoff_nonce_cleanup_expired(&self) -> crate::error::Result<u64> {
        dispatch!(self, handoff_nonce_cleanup_expired)
    }

    /// Test-only pool access used by a version-invalidation test that
    /// has to simulate a peer-node write. Out-of-band of the `Backend`
    /// trait because no production caller should reach past the facade.
    #[cfg(test)]
    pub(crate) fn sqlite_pool(&self) -> &sqlx::SqlitePool {
        match &self.backend {
            Backend::Sqlite(b) => b.pool(),
            Backend::Postgres(_) => {
                panic!("sqlite_pool called on a Postgres-backed Store")
            }
            Backend::Unavailable { reason } => {
                panic!("sqlite_pool called on a degraded Store: {reason}")
            }
        }
    }

    /// Test-only handle to the SQLite config-version counter so the peer
    /// simulation can bump it directly. Same rationale as `sqlite_pool`.
    #[cfg(test)]
    pub(crate) fn sqlite_config_version(&self) -> &version::DbVersion {
        match &self.backend {
            Backend::Sqlite(b) => b.config_version_handle(),
            Backend::Postgres(_) => {
                panic!("sqlite_config_version called on a Postgres-backed Store")
            }
            Backend::Unavailable { reason } => {
                panic!("sqlite_config_version called on a degraded Store: {reason}")
            }
        }
    }

    /// True when the service DB was configured but unreachable at
    /// startup. Consumed by the management API's readiness endpoint so
    /// an external load balancer can steer traffic away from a
    /// degraded node, while bootstrap traffic — which doesn't go
    /// through `Backend` — continues to land here.
    pub fn is_service_backend_available(&self) -> bool {
        !matches!(self.backend, Backend::Unavailable { .. })
    }

    /// Close the service backend pool, then the instance pool. Called
    /// from the runtime shutdown sequence. Pool close calls are
    /// idempotent; on the single-node SQLite topology both references
    /// may point to the same pool.
    pub async fn close(&self) {
        match &self.backend {
            Backend::Sqlite(b) => b.close().await,
            Backend::Postgres(b) => b.close().await,
            Backend::Unavailable { .. } => {}
        }
        self.instance.close().await;
    }

    /// Issue a live `SELECT 1` against the service backend. Used by
    /// `/readyz` to distinguish "pool was live at boot" (the boot-flag
    /// above) from "pool still answers right now" — the second can
    /// silently regress when the DB bounces behind a keepalive-
    /// transparent proxy and the pool's idle connections are stale.
    ///
    /// Surfaces the backend's own error in degraded mode (the dispatch
    /// macro maps `Backend::Unavailable` to `Error::ServiceUnavailable`)
    /// so the handler can treat both cases the same way: return 503.
    pub async fn ping(&self) -> crate::error::Result<()> {
        dispatch!(self, ping)
    }

    /// Test helper: build a `Store` whose operational backend is the
    /// degraded-mode stub. Used by tests that need to exercise the
    /// short-circuit path without paying the real connect timeout
    /// against an unreachable Postgres. The bootstrap file is an
    /// in-memory SQLite, same as the rest of the test suite.
    #[cfg(test)]
    pub(crate) async fn new_for_test_degraded(
        reason: &str,
    ) -> std::result::Result<Self, sqlx::Error> {
        let instance =
            InstanceStore::new("sqlite::memory:", MasterKey::from_test_bytes([0u8; 32])).await?;
        Ok(Self {
            backend: Backend::Unavailable {
                reason: reason.to_string(),
            },
            instance,
            config_cache: std::sync::Arc::new(std::sync::RwLock::new(None)),
            config_seen_version: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            // The degraded test Store retains a freshly generated
            // placeholder. Dispatch-backed operations fail, and
            // `encrypt_active_to_base64` rejects before reading this ring.
            // Other direct ring methods retain access to the placeholder.
            key_ring: std::sync::Arc::new(tokio::sync::RwLock::new(std::sync::Arc::new(
                crate::crypto::placeholder_ring(),
            ))),
            identity_key_ring: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        })
    }
}

/// Name of the env var consulted when no service DB URL is persisted.
/// Declared as a constant so the warning and import paths use the same key.
const ENV_SERVICE_DB: &str = "SEKISHO_SERVICE_DB";

/// Resolve the service DB URL for this boot from persisted and env values.
///
/// Semantics:
/// * persisted value present → return it; a non-empty env value is ignored
///   after a warning.
/// * persisted value absent and env value present → persist the env value,
///   then log and return it; a read or write error propagates.
/// * both absent → return `None`; the caller reuses bootstrap SQLite.
async fn resolve_service_db_url(instance: &InstanceStore) -> Result<Option<String>, sqlx::Error> {
    let env_url = std::env::var(ENV_SERVICE_DB).ok().filter(|s| !s.is_empty());

    let stored = instance.get_cluster_db_url().await.map_err(|e| match e {
        crate::error::Error::Database(db) => db,
        other => sqlx::Error::Protocol(format!("instance_config read failed: {other}")),
    })?;

    match (stored, env_url) {
        (Some(db_url), Some(_)) => {
            tracing::warn!(
                env = ENV_SERVICE_DB,
                "SEKISHO_SERVICE_DB env set but instance_config.cluster_db_url \
                 already populated; env ignored"
            );
            Ok(Some(db_url))
        }
        (Some(db_url), None) => Ok(Some(db_url)),
        (None, Some(env_url)) => {
            instance
                .set_cluster_db_url(&env_url)
                .await
                .map_err(|e| match e {
                    crate::error::Error::Database(db) => db,
                    other => {
                        sqlx::Error::Protocol(format!("instance_config write failed: {other}"))
                    }
                })?;
            tracing::info!(
                env = ENV_SERVICE_DB,
                "imported SEKISHO_SERVICE_DB because instance_config.cluster_db_url was unset"
            );
            Ok(Some(env_url))
        }
        (None, None) => Ok(None),
    }
}

/// Open the service-DB backend for `url`, converting a connection
/// failure into `Backend::Unavailable` rather than propagating the
/// error. Startup stays successful: the daemon boots into degraded
/// mode, bootstrap API remains reachable, and every operational
/// request returns 503 until the operator fixes the DSN and
/// restarts. No auto-reconnect: a restart is the intended recovery.
///
/// A structured `tracing::error!` records the scheme and error without
/// including the DSN, which may contain credentials.
async fn open_service_backend(url: &str, master_key: std::sync::Arc<MasterKey>) -> Backend {
    if is_postgres_url(url) {
        match PostgresBackend::new(url, master_key).await {
            Ok(be) => Backend::Postgres(be),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    scheme = "postgres",
                    "service DB unreachable at startup; entering degraded mode"
                );
                Backend::Unavailable {
                    reason: format!("postgres connection failed: {e}"),
                }
            }
        }
    } else {
        match SqliteBackend::new_service(url, master_key).await {
            Ok(be) => Backend::Sqlite(be),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    scheme = "sqlite",
                    "service DB unreachable at startup; entering degraded mode"
                );
                Backend::Unavailable {
                    reason: format!("sqlite open failed: {e}"),
                }
            }
        }
    }
}

/// Route `database_url` to the right backend based on scheme. Anything
/// that does not look like Postgres falls through to SQLite, which
/// preserves the legacy behaviour of `sqlite::memory:` and bare file
/// paths continuing to work.
fn is_postgres_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("postgres://") || lower.starts_with("postgresql://")
}

/// Normalise a "thing the operator typed for a SQLite DB" into a URL
/// that `SqliteConnectOptions::from_str` will accept. Anything already
/// starting with `sqlite:` passes through untouched so the in-memory
/// form `sqlite::memory:` and URL-form paths continue to work; a bare
/// filesystem path gets the required `sqlite:` prefix.
fn to_sqlite_url(input: &str) -> String {
    if input.starts_with("sqlite:") {
        input.to_string()
    } else {
        format!("sqlite:{input}")
    }
}
