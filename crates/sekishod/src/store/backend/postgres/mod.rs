//! Postgres implementation of `StorageBackend`.
//!
//! Parallels `backend::sqlite`. Differences are isolated to SQL
//! placeholder syntax (`$1` vs `?`), DDL (`uuid` identifiers / epoch
//! timestamp `BIGINT` columns, `NOW()` defaults, `IF NOT EXISTS` on `ADD COLUMN`),
//! isolation framing (standard `BEGIN` / `SELECT FOR UPDATE` where
//! the SQLite side used `BEGIN IMMEDIATE`), and a parallel
//! `PgDbVersion` counter type. Models, cache-version interfaces, and
//! merge-patch semantics are shared through the backend facade.
//!
//! Used when `Store::new` is handed a `postgres://` or
//! `postgresql://` URL. Two `Store` instances pointed at the same
//! DB is the intended HA topology; `schema_versions` carries the
//! peer-visible cache-invalidation signal, same as on SQLite.

mod crud;
mod version;

use crate::crypto::MasterKey;
use crate::error::{Error, Result};
use crate::models::acme_queue::{AcmeQueueAdmission, AcmeQueueRow, AcmeQueueStatus};
use crate::models::api_key::{ApiKey, ApiKeyScopeSet, ApiKeyWithSecret};
use crate::models::cert::Certificate;
use crate::models::config::GlobalConfig;
use crate::models::idp::IdentityProvider;
use crate::models::policy::Policy;
use crate::models::route::Route;
use crate::models::session::{SESSION_IDLE_EXPIRY_SECS, SESSION_TOUCH_INTERVAL_SECS, Session};
use crate::store::version as sqlite_version_consts;
use base64::Engine;
use chrono::Utc;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

use self::version::PgDbVersion;
use super::{
    AcmeElectionOutcome, AcmeElectionRow, ElectionAction, FirstDekInsertOutcome, MasterKeyRow,
    SERVICE_MIGRATIONS, SecretInsertOutcome, SessionTouchOutcome, SessionValidation,
    StorageBackend, Table,
    epoch::{from_epoch, from_epoch_opt, to_epoch},
    evaluate_election_rules, legacy_session_last_accessed_at,
};

fn decode_session_row(data: String, expires_at: i64, last_accessed_at: i64) -> Result<Session> {
    let mut session: Session = serde_json::from_str(&data)
        .map_err(|e| Error::Internal(format!("corrupt session data: {e}")))?;
    session.expires_at = from_epoch(expires_at);
    session.last_accessed_at = from_epoch(last_accessed_at);
    Ok(session)
}

const SERVICE_MIGRATION_LOCK_KEY: i64 = 0x5345_4b49_5348_4f4d;

#[cfg(test)]
pub(crate) mod acme_budget_snapshot_test_hook {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::{Notify, Semaphore};

    pub(super) type HookSlot = Arc<Mutex<Option<Arc<Hook>>>>;

    pub(crate) struct Hook {
        statement_read: Semaphore,
        resume: Semaphore,
        armed: AtomicBool,
        disarmed: Notify,
    }

    impl Hook {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                statement_read: Semaphore::new(0),
                resume: Semaphore::new(0),
                armed: AtomicBool::new(true),
                disarmed: Notify::new(),
            })
        }

        pub(crate) async fn wait_until_statement_read(&self) {
            self.statement_read
                .acquire()
                .await
                .expect("test hook semaphore stays open")
                .forget();
        }

        pub(crate) fn resume_snapshot(&self) {
            self.resume.add_permits(1);
        }

        fn disarm(&self) {
            self.armed.store(false, Ordering::SeqCst);
            self.disarmed.notify_waiters();
        }

        async fn pause(&self) {
            let disarmed = self.disarmed.notified();
            tokio::pin!(disarmed);
            if !self.armed.load(Ordering::SeqCst) {
                return;
            }
            self.statement_read.add_permits(1);
            tokio::select! {
                permit = self.resume.acquire() => {
                    permit.expect("test hook semaphore stays open").forget();
                }
                () = &mut disarmed => {}
            }
        }
    }

    pub(crate) struct Guard {
        slot: HookSlot,
        hook: Arc<Hook>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            self.hook.disarm();
            let mut slot = self.slot.lock().unwrap();
            if slot
                .as_ref()
                .is_some_and(|installed| Arc::ptr_eq(installed, &self.hook))
            {
                *slot = None;
            }
        }
    }

    pub(super) fn new_slot() -> HookSlot {
        Arc::new(Mutex::new(None))
    }

    pub(super) fn install(slot: &HookSlot) -> (Arc<Hook>, Guard) {
        let hook = Hook::new();
        let mut installed = slot.lock().unwrap();
        assert!(installed.is_none(), "snapshot test hook already installed");
        *installed = Some(hook.clone());
        drop(installed);
        (
            hook.clone(),
            Guard {
                slot: slot.clone(),
                hook,
            },
        )
    }

    pub(super) async fn pause_after_statement_read(slot: &HookSlot) {
        let hook = slot.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook.pause().await;
        }
    }
}

#[derive(Clone)]
pub struct PostgresBackend {
    pool: PgPool,
    route_version: PgDbVersion,
    idp_version: PgDbVersion,
    config_version: PgDbVersion,
    cert_version: PgDbVersion,
    /// DEK ring counter — see `SqliteBackend::key_ring_version`.
    key_ring_version: PgDbVersion,
    identity_signing_version: PgDbVersion,
    /// Master key used to HMAC API-key secrets. See
    /// `SqliteBackend::master_key` — same role, same rationale.
    master_key: Arc<MasterKey>,
    #[cfg(test)]
    acme_budget_snapshot_hook: acme_budget_snapshot_test_hook::HookSlot,
}

impl PostgresBackend {
    #[cfg(test)]
    pub(crate) fn shares_master_key(&self, expected: &Arc<MasterKey>) -> bool {
        Arc::ptr_eq(&self.master_key, expected)
    }

    #[cfg(test)]
    pub(crate) fn install_acme_budget_snapshot_test_hook(
        &self,
    ) -> (
        Arc<acme_budget_snapshot_test_hook::Hook>,
        acme_budget_snapshot_test_hook::Guard,
    ) {
        acme_budget_snapshot_test_hook::install(&self.acme_budget_snapshot_hook)
    }

    pub async fn new(
        database_url: &str,
        master_key: Arc<MasterKey>,
    ) -> std::result::Result<Self, sqlx::Error> {
        // acquire_timeout bounds the initial pool handshake in
        // `Store::new`. This sets five seconds instead of the pool's
        // thirty-second default before connection failure reaches the
        // degraded-mode path.
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(database_url)
            .await?;

        let backend = Self {
            pool: pool.clone(),
            route_version: PgDbVersion::new(pool.clone(), sqlite_version_consts::RESOURCE_ROUTES),
            idp_version: PgDbVersion::new(pool.clone(), sqlite_version_consts::RESOURCE_IDPS),
            config_version: PgDbVersion::new(pool.clone(), sqlite_version_consts::RESOURCE_CONFIG),
            cert_version: PgDbVersion::new(pool.clone(), sqlite_version_consts::RESOURCE_CERTS),
            key_ring_version: PgDbVersion::new(
                pool.clone(),
                sqlite_version_consts::RESOURCE_KEY_RING,
            ),
            identity_signing_version: PgDbVersion::new(
                pool,
                sqlite_version_consts::RESOURCE_IDENTITY_SIGNING_KEY_RING,
            ),
            master_key,
            #[cfg(test)]
            acme_budget_snapshot_hook: acme_budget_snapshot_test_hook::new_slot(),
        };
        backend.run_migrations().await?;
        Ok(backend)
    }

    async fn run_migrations(&self) -> std::result::Result<(), sqlx::Error> {
        #[cfg(test)]
        let migration_identity: String = sqlx::query_scalar("SELECT current_schema()::TEXT")
            .fetch_one(&self.pool)
            .await?;

        // DDL mirrors the SQLite side but uses native uuid / BIGINT
        // columns. `data` stays TEXT; consumers deserialize it in Rust,
        // and backend queries do not select individual JSON fields.
        let statements = [
            r#"CREATE TABLE IF NOT EXISTS routes (
                id uuid PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS identity_providers (
                id uuid PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                idp_type TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS global_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT NOT NULL,
                updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS sessions (
                id uuid PRIMARY KEY,
                user_id TEXT NOT NULL,
                idp_id uuid NOT NULL,
                data TEXT NOT NULL,
                expires_at BIGINT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                last_accessed_at BIGINT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",
            r#"CREATE TABLE IF NOT EXISTS certificates (
                id uuid PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                expires_at BIGINT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_certificates_expires_at ON certificates(expires_at)",
            r#"CREATE TABLE IF NOT EXISTS secrets (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS api_keys (
                id uuid PRIMARY KEY,
                name TEXT NOT NULL,
                prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                scopes TEXT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                last_used_at BIGINT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS policies (
                id uuid PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS schema_versions (
                resource TEXT PRIMARY KEY,
                version BIGINT NOT NULL DEFAULT 0,
                updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
            // ACME HTTP-01 challenges. The configured ACME server
            // supplies the token; the HTTP-01 handler uses it as the
            // lookup key, and it is the table's primary key. `domain`
            // supports per-domain cleanup.
            r#"CREATE TABLE IF NOT EXISTS acme_challenges (
                token TEXT PRIMARY KEY,
                key_auth TEXT NOT NULL,
                domain TEXT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_acme_challenges_domain ON acme_challenges(domain)",
            // Same logical election singleton as SQLite. `updated_at`
            // stores epoch seconds in a BIGINT column.
            r#"CREATE TABLE IF NOT EXISTS acme_leader_election (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                node_id TEXT NOT NULL,
                node_hash TEXT NOT NULL,
                updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
            // PendingAuth rows for OIDC/SAML in-flight CSRF state are
            // persisted in the shared service DB, so a callback handled
            // by another node can read the row by its CSRF key.
            r#"CREATE TABLE IF NOT EXISTS pending_auth (
                csrf TEXT PRIMARY KEY,
                idp_id uuid NOT NULL,
                nonce TEXT NOT NULL DEFAULT '',
                code_verifier TEXT NOT NULL DEFAULT '',
                saml_authn_request_id TEXT,
                redirect_url TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'login',
                browser_nonce_hash TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_pending_auth_expires_at ON pending_auth(expires_at)",
            // ACME issuance queue. See the SQLite migration for the
            // rationale; Postgres uses native uuid / BIGINT
            // columns and identical partial unique-index syntax to
            // de-dup on (domain, active status).
            r#"CREATE TABLE IF NOT EXISTS acme_queue (
                id uuid PRIMARY KEY,
                domain TEXT NOT NULL,
                requester_node TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                result_cert_id uuid,
                error_msg TEXT,
                enqueued_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                picked_at BIGINT,
                completed_at BIGINT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_acme_queue_status ON acme_queue(status, enqueued_at)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_acme_queue_domain_active \
             ON acme_queue(domain) WHERE status IN ('pending', 'in_progress')",
            // DEK ring — see the SQLite migration for rationale.
            // Production allocation uses key IDs in 0..=255 for the
            // one-byte v3 header, but this smallint column does not
            // enforce that range. The partial unique index permits at
            // most one active, non-retired row.
            r#"CREATE TABLE IF NOT EXISTS master_keys (
                key_id smallint PRIMARY KEY,
                key_encrypted TEXT NOT NULL,
                active boolean NOT NULL DEFAULT false,
                retired boolean NOT NULL DEFAULT false,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                retired_at BIGINT
            )"#,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_master_keys_one_active \
             ON master_keys(active) WHERE active = true AND retired = false",
        ];

        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(SERVICE_MIGRATION_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        for stmt in statements {
            sqlx::query(stmt).execute(&mut *tx).await?;
        }

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS service_migrations (
                version BIGINT PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
        )
        .execute(&mut *tx)
        .await?;

        let applied: Vec<(i64, String)> =
            sqlx::query_as("SELECT version, name FROM service_migrations ORDER BY version")
                .fetch_all(&mut *tx)
                .await?;
        validate_service_migration_prefix(&applied)?;

        for migration in SERVICE_MIGRATIONS.iter().skip(applied.len()) {
            match migration.version {
                1 => {
                    sqlx::query(
                        "ALTER TABLE pending_auth \
                         ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'login'",
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                2 => {
                    sqlx::query(
                        "UPDATE identity_providers \
                         SET data = (\
                             (data::jsonb) \
                             #- '{saml_config,entity_id}' \
                             #- '{saml_config,acs_url}'\
                         )::text \
                         WHERE idp_type = '\"saml\"'",
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                3 => {
                    sqlx::query(
                        "ALTER TABLE pending_auth \
                         ADD COLUMN IF NOT EXISTS browser_nonce_hash TEXT",
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                4 => {
                    let rows: Vec<(Uuid, String)> = sqlx::query_as(
                        "SELECT id, data FROM sessions WHERE last_accessed_at IS NULL",
                    )
                    .fetch_all(&mut *tx)
                    .await?;
                    for (id, data) in rows {
                        let last_accessed_at = legacy_session_last_accessed_at(&data)?;
                        sqlx::query(
                            "UPDATE sessions SET last_accessed_at = $1 \
                             WHERE id = $2 AND last_accessed_at IS NULL",
                        )
                        .bind(last_accessed_at)
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                    }
                }
                5 => {
                    sqlx::query(
                        "CREATE TABLE IF NOT EXISTS identity_signing_keys (\
                         kid TEXT PRIMARY KEY, state TEXT NOT NULL CHECK (state IN ('current','retiring')), \
                         private_key_encrypted TEXT, public_jwk TEXT NOT NULL, retire_until BIGINT, \
                         created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT), \
                         CHECK ((state = 'current' AND private_key_encrypted IS NOT NULL AND retire_until IS NULL) OR \
                                (state = 'retiring' AND private_key_encrypted IS NULL AND retire_until IS NOT NULL)))",
                    )
                    .execute(&mut *tx)
                    .await?;
                    sqlx::query(
                        "CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_signing_one_state \
                         ON identity_signing_keys(state) WHERE state IN ('current','retiring')",
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                6 => {
                    sqlx::query("DROP TABLE IF EXISTS api_certificate")
                        .execute(&mut *tx)
                        .await?;
                }
                7 => {
                    sqlx::query("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scopes TEXT")
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query(
                        "UPDATE api_keys SET scopes = '[\"management:admin\"]' \
                         WHERE scopes IS NULL",
                    )
                    .execute(&mut *tx)
                    .await?;
                    sqlx::query("ALTER TABLE api_keys ALTER COLUMN scopes SET NOT NULL")
                        .execute(&mut *tx)
                        .await?;
                }
                8 => {
                    sqlx::query(
                        "CREATE TABLE IF NOT EXISTS used_handoff_nonces (\
                         nonce UUID PRIMARY KEY, \
                         consumed_at BIGINT NOT NULL DEFAULT \
                             (EXTRACT(EPOCH FROM NOW())::BIGINT))",
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                version => {
                    return Err(sqlx::Error::Protocol(format!(
                        "unsupported service migration version {version}"
                    )));
                }
            }

            #[cfg(test)]
            migration_test_hook::after_body(migration.version, &migration_identity).await;

            sqlx::query("INSERT INTO service_migrations (version, name) VALUES ($1, $2)")
                .bind(migration.version)
                .bind(migration.name)
                .execute(&mut *tx)
                .await?;
        }

        for resource in sqlite_version_consts::ALL_RESOURCES {
            sqlx::query(
                "INSERT INTO schema_versions (resource, version) VALUES ($1, 0) \
                 ON CONFLICT (resource) DO NOTHING",
            )
            .bind(*resource)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        Ok(())
    }

    /// Pool accessor used exclusively by `store::dek_rotation`. See
    /// the SQLite sibling for the rationale.
    pub(crate) fn pool_for_rotation(&self) -> &PgPool {
        &self.pool
    }

    /// Close the underlying pool. Called from `Store::close` in the
    /// runtime shutdown sequence.
    pub(crate) async fn close(&self) {
        self.pool.close().await;
    }
}

fn validate_service_migration_prefix(
    applied: &[(i64, String)],
) -> std::result::Result<(), sqlx::Error> {
    if applied.len() > SERVICE_MIGRATIONS.len() {
        return Err(sqlx::Error::Protocol(
            "service migration ledger contains an unknown version".to_owned(),
        ));
    }

    for ((version, name), expected) in applied.iter().zip(SERVICE_MIGRATIONS) {
        if *version != expected.version || name != expected.name {
            return Err(sqlx::Error::Protocol(format!(
                "invalid service migration ledger entry at version {version}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
pub(in crate::store) mod migration_test_hook {
    use std::sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::Notify;

    pub(in crate::store) struct Hook {
        version: i64,
        migration_identity: String,
        pub(in crate::store) reached: Notify,
        pub(in crate::store) release: Notify,
        pub(in crate::store) panic_after_release: AtomicBool,
    }

    fn slot() -> &'static Mutex<Option<Arc<Hook>>> {
        static SLOT: OnceLock<Mutex<Option<Arc<Hook>>>> = OnceLock::new();
        SLOT.get_or_init(|| Mutex::new(None))
    }

    pub(in crate::store) fn install(version: i64, migration_identity: &str) -> Arc<Hook> {
        let hook = Arc::new(Hook {
            version,
            migration_identity: migration_identity.to_owned(),
            reached: Notify::new(),
            release: Notify::new(),
            panic_after_release: AtomicBool::new(false),
        });
        let mut slot = slot().lock().expect("migration hook lock");
        assert!(slot.is_none(), "migration hook already installed");
        *slot = Some(hook.clone());
        hook
    }

    pub(in crate::store) fn clear() {
        *slot().lock().expect("migration hook lock") = None;
    }

    pub(super) async fn after_body(version: i64, migration_identity: &str) {
        let hook = slot().lock().expect("migration hook lock").clone();
        let Some(hook) = hook.filter(|hook| {
            hook.version == version && hook.migration_identity == migration_identity
        }) else {
            return;
        };
        hook.reached.notify_one();
        hook.release.notified().await;
        if hook.panic_after_release.load(Ordering::SeqCst) {
            panic!("injected migration panic");
        }
    }
}

/// Commit or roll back a Postgres transaction based on a pre-computed
/// result. Transaction-backed mutations that call this helper build a
/// `tx`, run the work inside an `async` block, then hand the outcome
/// here for the commit/rollback decision.
///
/// A successful work result propagates a COMMIT error. For a failed
/// work result, ROLLBACK is attempted and its error is discarded so
/// the caller can return the original work error.
async fn finalize_pg_tx<T>(
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    result: &Result<T>,
) -> Result<()> {
    match result {
        Ok(_) => tx.commit().await.map_err(Error::Database),
        Err(_) => {
            let _ = tx.rollback().await;
            Ok(())
        }
    }
}

async fn lock_key_ring_version(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<()> {
    sqlx::query_scalar::<_, i64>(
        "SELECT version FROM schema_versions \
         WHERE resource = $1 FOR UPDATE",
    )
    .bind(sqlite_version_consts::RESOURCE_IDENTITY_SIGNING_KEY_RING)
    .fetch_one(&mut **tx)
    .await
    .map_err(Error::Database)?;
    sqlx::query_scalar::<_, i64>(
        "SELECT version FROM schema_versions \
         WHERE resource = $1 FOR UPDATE",
    )
    .bind(sqlite_version_consts::RESOURCE_KEY_RING)
    .fetch_one(&mut **tx)
    .await
    .map_err(Error::Database)?;
    Ok(())
}

impl StorageBackend for PostgresBackend {
    // ───── Routes ─────
    async fn observe_routes(&self) -> Result<crate::store::route::RouteObservation> {
        let rows = sqlx::query_as::<_, (i64, Option<String>)>(
            "SELECT sv.version, r.data FROM schema_versions sv \
             LEFT JOIN routes r ON TRUE WHERE sv.resource = $1 ORDER BY r.name",
        )
        .bind(sqlite_version_consts::RESOURCE_ROUTES)
        .fetch_all(&self.pool)
        .await
        .map_err(Error::Database)?;
        let Some((version, _)) = rows.first() else {
            return Err(Error::Internal("missing routes version row".into()));
        };
        let version = u64::try_from(*version)
            .map_err(|_| Error::Internal("invalid routes version row".into()))?;
        let routes = rows
            .into_iter()
            .filter_map(|(_, data)| data)
            .map(|data| crud::parse_json(&data, Table::Routes.kind()))
            .collect::<Result<Vec<_>>>()?;
        Ok(crate::store::route::RouteObservation { version, routes })
    }

    async fn list_routes(&self) -> Result<Vec<Route>> {
        crud::list_json(&self.pool, Table::Routes).await
    }

    async fn list_routes_page(&self, limit: i64, offset: i64) -> Result<Vec<Route>> {
        crud::list_json_page(&self.pool, Table::Routes, limit, offset).await
    }

    async fn get_route(&self, id: Uuid) -> Result<Route> {
        crud::get_json_by_id(&self.pool, Table::Routes, id).await
    }

    async fn create_route(&self, route: &Route) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<()> = async {
            crate::identity::validate_route(route.signed_identity_input())
                .map_err(|_| Error::BadRequest(crate::identity::INVALID_SIGNED_ROUTE.into()))?;
            crate::validation::validate_route_policy(&route.access)?;
            crud::insert_named_exec(&mut *tx, Table::Routes, route.id, route, &[]).await?;
            // Bump in-tx so peers never see the new row at the old
            // version. Postgres's default READ COMMITTED is enough:
            // the INSERT already takes the row lock we need, and the
            // bump is a single-row UPDATE against `schema_versions`.
            self.route_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn update_route(&self, id: Uuid, update: serde_json::Value) -> Result<Route> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<Route> = async {
            let current =
                sqlx::query_scalar::<_, String>("SELECT data FROM routes WHERE id = $1 FOR UPDATE")
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(Error::NotFound)?;
            let merged: Route = crud::apply_merge(&current, &update, Table::Routes.kind())?;
            crate::identity::validate_route(merged.signed_identity_input())
                .map_err(|_| Error::BadRequest(crate::identity::INVALID_SIGNED_ROUTE.into()))?;
            crate::validation::validate_route_policy(&merged.access)?;
            let serialized = crud::to_json_string(&merged)?;
            sqlx::query(
                "UPDATE routes SET name = $1, data = $2, \
                 updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = $3",
            )
            .bind(&merged.name)
            .bind(serialized)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                crud::map_unique_violation(error, Table::Routes.kind(), &merged.name)
            })?;
            self.route_version.bump(&mut *tx).await?;
            Ok(merged)
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn delete_route(&self, id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<()> = async {
            crud::delete_by_id_exec(&mut *tx, Table::Routes, id).await?;
            self.route_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    // ───── IdPs ─────
    async fn list_idps(&self) -> Result<Vec<IdentityProvider>> {
        crud::list_json(&self.pool, Table::IdentityProviders).await
    }

    async fn list_idps_page(&self, limit: i64, offset: i64) -> Result<Vec<IdentityProvider>> {
        crud::list_json_page(&self.pool, Table::IdentityProviders, limit, offset).await
    }

    async fn get_idp(&self, id: Uuid) -> Result<IdentityProvider> {
        crud::get_json_by_id(&self.pool, Table::IdentityProviders, id).await
    }

    async fn create_idp(&self, idp: &IdentityProvider) -> Result<()> {
        let idp_type = crud::to_json_string(&idp.idp_type)?;
        let type_trim = idp_type.trim_matches('"');
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<()> = async {
            crud::insert_named_exec(
                &mut *tx,
                Table::IdentityProviders,
                idp.id,
                idp,
                &[("idp_type", type_trim)],
            )
            .await?;
            self.idp_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn update_idp(&self, id: Uuid, update: serde_json::Value) -> Result<IdentityProvider> {
        crud::update_named_by_id::<IdentityProvider>(
            &self.pool,
            Table::IdentityProviders,
            id,
            &update,
            Some(&self.idp_version),
        )
        .await
    }

    async fn delete_idp(&self, id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<()> = async {
            crud::delete_by_id_exec(&mut *tx, Table::IdentityProviders, id).await?;
            self.idp_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    // ───── Policies ─────
    async fn list_policies(&self) -> Result<Vec<Policy>> {
        crud::list_json(&self.pool, Table::Policies).await
    }

    async fn list_policies_page(&self, limit: i64, offset: i64) -> Result<Vec<Policy>> {
        crud::list_json_page(&self.pool, Table::Policies, limit, offset).await
    }

    async fn get_policy(&self, id: Uuid) -> Result<Policy> {
        crud::get_json_by_id(&self.pool, Table::Policies, id).await
    }

    async fn get_policy_by_name(&self, name: &str) -> Result<Policy> {
        let s = sqlx::query_scalar::<_, String>("SELECT data FROM policies WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::NotFound)?;
        crud::parse_json(&s, "policy")
    }

    async fn create_policy(&self, p: &Policy) -> Result<()> {
        crate::validation::validate_policy_expression(&p.expr)?;
        crud::insert_named(&self.pool, Table::Policies, p.id, p, &[]).await
    }

    async fn update_policy(&self, id: Uuid, update: serde_json::Value) -> Result<Policy> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<Policy> = async {
            let current = sqlx::query_scalar::<_, String>(
                "SELECT data FROM policies WHERE id = $1 FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::NotFound)?;
            let merged: Policy = crud::apply_merge(&current, &update, Table::Policies.kind())?;
            crate::validation::validate_policy_expression(&merged.expr)?;
            let serialized = crud::to_json_string(&merged)?;
            sqlx::query(
                "UPDATE policies SET name = $1, data = $2, \
                 updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = $3",
            )
            .bind(&merged.name)
            .bind(serialized)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                crud::map_unique_violation(error, Table::Policies.kind(), &merged.name)
            })?;
            Ok(merged)
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn delete_policy(&self, id: Uuid) -> Result<()> {
        crud::delete_by_id(&self.pool, Table::Policies, id).await
    }

    // ───── Config ─────
    async fn load_config(&self) -> Result<GlobalConfig> {
        let json_str =
            crud::fetch_json_scalar(&self.pool, "SELECT data FROM global_config WHERE id = 1")
                .await?;
        match json_str {
            Some(json_str) => serde_json::from_str(&json_str)
                .map_err(|e| Error::Internal(format!("corrupt config data: {e}"))),
            None => Ok(GlobalConfig::default()),
        }
    }

    async fn update_config(&self, update: serde_json::Value) -> Result<GlobalConfig> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;

        let result: Result<GlobalConfig> = async {
            let default = serde_json::to_string(&GlobalConfig::default())
                .map_err(|e| Error::Internal(format!("serialize default config: {e}")))?;
            sqlx::query(
                "INSERT INTO global_config (id, data) VALUES (1, $1) \
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(default)
            .execute(&mut *tx)
            .await?;

            let json_str = sqlx::query_scalar::<_, String>(
                "SELECT data FROM global_config WHERE id = 1 FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await?;
            let mut base = serde_json::from_str(&json_str)
                .map_err(|e| Error::Internal(format!("corrupt config data: {e}")))?;

            crate::store::merge::json_merge(&mut base, &update);

            let config: GlobalConfig = serde_json::from_value(base)
                .map_err(|e| Error::Internal(format!("invalid config after merge: {e}")))?;

            let serialized = serde_json::to_string(&config)
                .map_err(|e| Error::Internal(format!("serialize error: {e}")))?;

            sqlx::query(
                "UPDATE global_config \
                 SET data = $1, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT \
                 WHERE id = 1",
            )
            .bind(&serialized)
            .execute(&mut *tx)
            .await?;

            self.config_version.bump(&mut *tx).await?;

            Ok(config)
        }
        .await;

        match &result {
            Ok(_) => {
                tx.commit().await.map_err(Error::Database)?;
            }
            Err(_) => {
                let _ = tx.rollback().await;
            }
        }
        result
    }

    // ───── Sessions ─────
    async fn create_session(&self, session: &Session) -> Result<()> {
        let serialized = serde_json::to_string(session)
            .map_err(|e| Error::Internal(format!("serialize error: {e}")))?;

        sqlx::query(
            "INSERT INTO sessions \
             (id, user_id, idp_id, data, expires_at, last_accessed_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(session.id)
        .bind(&session.user_id)
        .bind(session.idp_id)
        .bind(&serialized)
        .bind(to_epoch(session.expires_at))
        .bind(to_epoch(session.last_accessed_at))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_session(&self, id: Uuid) -> Result<Session> {
        let (data, expires_at, last_accessed_at): (String, i64, i64) = sqlx::query_as(
            "SELECT data, expires_at, last_accessed_at FROM sessions \
             WHERE id = $1 AND expires_at > EXTRACT(EPOCH FROM NOW())::BIGINT \
             AND last_accessed_at > EXTRACT(EPOCH FROM NOW())::BIGINT - $2",
        )
        .bind(id)
        .bind(SESSION_IDLE_EXPIRY_SECS)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::NotFound)?;
        decode_session_row(data, expires_at, last_accessed_at)
    }

    async fn get_session_for_validation(&self, id: Uuid) -> Result<SessionValidation> {
        let (data, expires_at, last_accessed_at, touch_due): (String, i64, i64, bool) =
            sqlx::query_as(
                "SELECT data, expires_at, last_accessed_at, \
                 last_accessed_at <= EXTRACT(EPOCH FROM NOW())::BIGINT - $2 AS touch_due \
                 FROM sessions WHERE id = $1 \
                 AND expires_at > EXTRACT(EPOCH FROM NOW())::BIGINT \
                 AND last_accessed_at > EXTRACT(EPOCH FROM NOW())::BIGINT - $3",
            )
            .bind(id)
            .bind(SESSION_TOUCH_INTERVAL_SECS)
            .bind(SESSION_IDLE_EXPIRY_SECS)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::NotFound)?;
        Ok(SessionValidation {
            session: decode_session_row(data, expires_at, last_accessed_at)?,
            touch_due,
        })
    }

    async fn touch_session_if_due(
        &self,
        id: Uuid,
        expected_last_accessed_at: chrono::DateTime<Utc>,
    ) -> Result<SessionTouchOutcome> {
        let touched = sqlx::query_scalar::<_, i64>(
            "UPDATE sessions SET last_accessed_at = EXTRACT(EPOCH FROM NOW())::BIGINT \
             WHERE id = $1 AND last_accessed_at = $2 \
             AND expires_at > EXTRACT(EPOCH FROM NOW())::BIGINT \
             AND last_accessed_at > EXTRACT(EPOCH FROM NOW())::BIGINT - $3 \
             AND last_accessed_at <= EXTRACT(EPOCH FROM NOW())::BIGINT - $4 \
             RETURNING last_accessed_at",
        )
        .bind(id)
        .bind(to_epoch(expected_last_accessed_at))
        .bind(SESSION_IDLE_EXPIRY_SECS)
        .bind(SESSION_TOUCH_INTERVAL_SECS)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(last_accessed_at) = touched {
            return Ok(SessionTouchOutcome::Touched(from_epoch(last_accessed_at)));
        }

        let current = sqlx::query_scalar::<_, i64>(
            "SELECT last_accessed_at FROM sessions \
             WHERE id = $1 AND expires_at > EXTRACT(EPOCH FROM NOW())::BIGINT \
             AND last_accessed_at > EXTRACT(EPOCH FROM NOW())::BIGINT - $2",
        )
        .bind(id)
        .bind(SESSION_IDLE_EXPIRY_SECS)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match current {
            Some(last_accessed_at) => SessionTouchOutcome::Current(from_epoch(last_accessed_at)),
            None => SessionTouchOutcome::GoneOrExpired,
        })
    }

    async fn list_sessions(
        &self,
        user_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Session>> {
        let rows =
            match user_filter {
                Some(user) => {
                    sqlx::query_as::<_, (String, i64, i64)>(
                        "SELECT data, expires_at, last_accessed_at FROM sessions WHERE user_id = $1 \
                     ORDER BY created_at DESC, id ASC LIMIT $2 OFFSET $3",
                    )
                    .bind(user)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(&self.pool)
                    .await?
                }
                None => sqlx::query_as::<_, (String, i64, i64)>(
                    "SELECT data, expires_at, last_accessed_at FROM sessions ORDER BY created_at DESC, id ASC LIMIT $1 OFFSET $2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?,
            };

        rows.into_iter()
            .map(|(data, expires_at, last_accessed_at)| {
                decode_session_row(data, expires_at, last_accessed_at)
            })
            .collect()
    }

    async fn delete_session(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }

        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM sessions \
             WHERE expires_at <= EXTRACT(EPOCH FROM NOW())::BIGINT \
             OR last_accessed_at <= EXTRACT(EPOCH FROM NOW())::BIGINT - $1",
        )
        .bind(SESSION_IDLE_EXPIRY_SECS)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ───── Certificates ─────
    async fn list_certs(&self) -> Result<Vec<Certificate>> {
        let rows = sqlx::query_scalar::<_, String>("SELECT data FROM certificates ORDER BY domain")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|json_str| {
                serde_json::from_str(&json_str)
                    .map_err(|e| Error::Internal(format!("corrupt cert data: {e}")))
            })
            .collect()
    }

    async fn list_certs_page(&self, limit: i64, offset: i64) -> Result<Vec<Certificate>> {
        let rows = sqlx::query_scalar::<_, String>(
            "SELECT data FROM certificates ORDER BY domain LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|json_str| {
                serde_json::from_str(&json_str)
                    .map_err(|e| Error::Internal(format!("corrupt cert data: {e}")))
            })
            .collect()
    }

    async fn get_cert(&self, id: Uuid) -> Result<Certificate> {
        let json_str =
            sqlx::query_scalar::<_, String>("SELECT data FROM certificates WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(Error::NotFound)?;

        serde_json::from_str(&json_str)
            .map_err(|e| Error::Internal(format!("corrupt cert data: {e}")))
    }

    async fn upsert_cert(&self, cert: &Certificate) -> Result<()> {
        let serialized = serde_json::to_string(cert)
            .map_err(|e| Error::Internal(format!("serialize error: {e}")))?;

        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<()> = async {
            sqlx::query(
                r#"
                INSERT INTO certificates (id, domain, data, expires_at)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT(domain) DO UPDATE SET
                    id = excluded.id,
                    data = excluded.data,
                    expires_at = excluded.expires_at,
                    updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT
                "#,
            )
            .bind(cert.id)
            .bind(&cert.domain)
            .bind(&serialized)
            .bind(to_epoch(cert.expires_at))
            .execute(&mut *tx)
            .await?;
            // In-tx bump so a peer on another connection can't read the
            // new cert row at the old version.
            self.cert_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn delete_cert(&self, id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<()> = async {
            let r = sqlx::query("DELETE FROM certificates WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            if r.rows_affected() == 0 {
                return Err(Error::NotFound);
            }
            self.cert_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn get_expiring_certs(&self, days_before: i64) -> Result<Vec<Certificate>> {
        let cutoff = chrono::Utc::now() + chrono::Duration::days(days_before);
        let rows =
            sqlx::query_scalar::<_, String>("SELECT data FROM certificates WHERE expires_at < $1")
                .bind(to_epoch(cutoff))
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter()
            .map(|json_str| {
                serde_json::from_str(&json_str)
                    .map_err(|e| Error::Internal(format!("corrupt cert data: {e}")))
            })
            .collect()
    }

    // ───── API keys ─────
    async fn create_api_key(
        &self,
        name: &str,
        scopes: &ApiKeyScopeSet,
    ) -> Result<ApiKeyWithSecret> {
        let scopes_json = scopes
            .to_storage()
            .map_err(|_| Error::Internal("failed to encode API key scopes".into()))?;
        let id = Uuid::new_v4();
        let raw_key = generate_raw_key();
        let prefix = raw_key.get(..8).unwrap_or(&raw_key);
        let key_hash = super::api_key_hash::hmac_stored_form(&self.master_key, &raw_key);
        let now = Utc::now();

        sqlx::query(
            "INSERT INTO api_keys (id, name, prefix, key_hash, scopes, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(name)
        .bind(prefix)
        .bind(&key_hash)
        .bind(&scopes_json)
        .bind(to_epoch(now))
        .execute(&self.pool)
        .await?;

        let api_key = ApiKey {
            id,
            name: name.to_string(),
            prefix: prefix.to_string(),
            key_hash,
            scopes: scopes.clone(),
            created_at: now,
            last_used_at: None,
        };

        Ok(ApiKeyWithSecret {
            api_key,
            key: raw_key,
        })
    }

    async fn get_api_key(&self, id: Uuid) -> Result<ApiKey> {
        sqlx::query_as::<_, ApiKeyRow>(
            "SELECT id, name, prefix, key_hash, scopes, created_at, last_used_at \
             FROM api_keys WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::NotFound)?
        .into_model()
    }

    async fn lookup_api_key(&self, raw_key: &str) -> Result<ApiKey> {
        // Query by the presented key's prefix, invoke the verifier for
        // every fetched candidate, and retain the first HMAC match
        // without breaking out of the loop.
        use super::api_key_hash::{self, VerifyOutcome};

        let prefix = raw_key.get(..8).unwrap_or(raw_key);
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            "SELECT id, name, prefix, key_hash, scopes, created_at, last_used_at \
             FROM api_keys WHERE prefix = $1",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await?;

        let mut matched: Option<ApiKeyRow> = None;
        for row in rows {
            let outcome = api_key_hash::verify(&self.master_key, raw_key, &row.key_hash);
            if outcome == VerifyOutcome::MatchHmac && matched.is_none() {
                matched = Some(row);
            }
        }

        matched.ok_or(Error::Unauthorized)?.into_model()
    }

    async fn touch_api_key_usage(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query(
            "UPDATE api_keys SET last_used_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    async fn list_api_keys(&self) -> Result<Vec<ApiKey>> {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            "SELECT id, name, prefix, key_hash, scopes, created_at, last_used_at \
             FROM api_keys ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(ApiKeyRow::into_model).collect()
    }

    async fn list_api_keys_page(&self, limit: i64, offset: i64) -> Result<Vec<ApiKey>> {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            "SELECT id, name, prefix, key_hash, scopes, created_at, last_used_at \
             FROM api_keys ORDER BY created_at ASC, id ASC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(ApiKeyRow::into_model).collect()
    }

    async fn delete_api_key(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }

        Ok(())
    }

    async fn api_key_count(&self) -> Result<i64> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_keys")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    // ───── Secrets ─────
    async fn get_secret(&self, key: &str) -> Result<Option<String>> {
        let value = sqlx::query_scalar::<_, String>("SELECT value FROM secrets WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(value)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO secrets (key, value) VALUES ($1, $2)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_secret_if_absent(&self, key: &str, value: &str) -> Result<SecretInsertOutcome> {
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO secrets (key, value) VALUES ($1, $2) \
             ON CONFLICT(key) DO NOTHING",
        )
        .bind(key)
        .bind(value)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        let durable = sqlx::query_scalar::<_, String>("SELECT value FROM secrets WHERE key = $1")
            .bind(key)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(SecretInsertOutcome {
            inserted,
            value: durable,
        })
    }

    // ───── ACME challenges ─────
    async fn set_acme_challenge(&self, token: &str, key_auth: &str, domain: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO acme_challenges (token, key_auth, domain)
            VALUES ($1, $2, $3)
            ON CONFLICT(token) DO UPDATE SET
                key_auth = excluded.key_auth,
                domain = excluded.domain,
                created_at = EXTRACT(EPOCH FROM NOW())::BIGINT
            "#,
        )
        .bind(token)
        .bind(key_auth)
        .bind(domain)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_acme_challenge(&self, token: &str) -> Result<Option<String>> {
        let value = sqlx::query_scalar::<_, String>(
            "SELECT key_auth FROM acme_challenges WHERE token = $1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(value)
    }

    async fn delete_acme_challenges_for_domain(&self, domain: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM acme_challenges WHERE domain = $1")
            .bind(domain)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    // ───── ACME leader election ─────
    async fn acme_election_read(&self) -> Result<Option<AcmeElectionRow>> {
        let row = sqlx::query_as::<_, PgAcmeElectionRow>(
            "SELECT node_id, node_hash, updated_at \
             FROM acme_leader_election WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| AcmeElectionRow {
            node_id: r.node_id,
            node_hash: r.node_hash,
            updated_at: from_epoch(r.updated_at),
        }))
    }

    async fn acme_election_try_promote_or_refresh(
        &self,
        my_node_id: &str,
        my_node_hash: &str,
        stale_after: chrono::Duration,
    ) -> Result<AcmeElectionOutcome> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<AcmeElectionOutcome> = async {
            let now = Utc::now();
            let mut existing = sqlx::query_as::<_, PgAcmeElectionRow>(
                "SELECT node_id, node_hash, updated_at \
                 FROM acme_leader_election WHERE id = 1 FOR UPDATE",
            )
            .fetch_optional(&mut *tx)
            .await?;

            if existing.is_none() {
                let inserted = sqlx::query_scalar::<_, i32>(
                    "INSERT INTO acme_leader_election \
                     (id, node_id, node_hash, updated_at) \
                     VALUES (1, $1, $2, $3) \
                     ON CONFLICT (id) DO NOTHING \
                     RETURNING id",
                )
                .bind(my_node_id)
                .bind(my_node_hash)
                .bind(to_epoch(now))
                .fetch_optional(&mut *tx)
                .await?;
                if inserted.is_some() {
                    return Ok(AcmeElectionOutcome {
                        current_leader_node_id: my_node_id.to_string(),
                        i_am_leader: true,
                        action_taken: ElectionAction::Initial,
                    });
                }
                existing = Some(
                    sqlx::query_as::<_, PgAcmeElectionRow>(
                        "SELECT node_id, node_hash, updated_at \
                         FROM acme_leader_election WHERE id = 1 FOR UPDATE",
                    )
                    .fetch_one(&mut *tx)
                    .await?,
                );
            }

            let outcome = evaluate_election_rules(
                existing.map(|r| AcmeElectionRow {
                    node_id: r.node_id,
                    node_hash: r.node_hash,
                    updated_at: from_epoch(r.updated_at),
                }),
                my_node_id,
                my_node_hash,
                stale_after,
                now,
            );

            let now_epoch = to_epoch(now);
            match outcome.action_taken {
                ElectionAction::Initial => unreachable!("empty election insert returned above"),
                ElectionAction::Takeover | ElectionAction::Preempt | ElectionAction::Refresh => {
                    sqlx::query(
                        "UPDATE acme_leader_election \
                         SET node_id = $1, node_hash = $2, updated_at = $3 \
                         WHERE id = 1",
                    )
                    .bind(my_node_id)
                    .bind(my_node_hash)
                    .bind(now_epoch)
                    .execute(&mut *tx)
                    .await?;
                }
                ElectionAction::None => {}
            }

            Ok(outcome)
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    // ───── ACME issuance queue ─────
    async fn acme_queue_enqueue(
        &self,
        domain: &str,
        requester_node: &str,
    ) -> Result<AcmeQueueAdmission> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<AcmeQueueAdmission> = async {
            let default = serde_json::to_string(&GlobalConfig::default())
                .map_err(|e| Error::Internal(format!("serialize default config: {e}")))?;
            sqlx::query(
                "INSERT INTO global_config (id, data) VALUES (1, $1) \
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(default)
            .execute(&mut *tx)
            .await?;
            // An exclusive row lock serializes the config snapshot, dedup,
            // active count, and insert across all cluster nodes. Config
            // updates lock the same singleton row.
            let config_json = sqlx::query_scalar::<_, String>(
                "SELECT data FROM global_config WHERE id = 1 FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await?;
            let config = serde_json::from_str::<GlobalConfig>(&config_json)
                .map_err(|e| Error::Internal(format!("corrupt config data: {e}")))?;

            if let Some(existing) = sqlx::query_as::<_, PgAcmeQueueRow>(
                "SELECT id, domain, requester_node, status, result_cert_id, \
                        error_msg, enqueued_at, picked_at, completed_at \
                 FROM acme_queue \
                 WHERE domain = $1 AND status IN ('pending', 'in_progress') \
                 LIMIT 1 FOR UPDATE",
            )
            .bind(domain)
            .fetch_optional(&mut *tx)
            .await?
            {
                return existing.into_model().map(AcmeQueueAdmission::Existing);
            }

            let active = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM acme_queue \
                 WHERE status IN ('pending', 'in_progress')",
            )
            .fetch_one(&mut *tx)
            .await?;
            if active >= i64::from(config.acme_queue_capacity) {
                return Ok(AcmeQueueAdmission::Full);
            }

            let id = Uuid::new_v4();
            let now = Utc::now();
            let candidate = AcmeQueueRow {
                id,
                domain: domain.to_owned(),
                requester_node: requester_node.to_owned(),
                status: AcmeQueueStatus::Pending,
                result_cert_id: None,
                error_msg: None,
                enqueued_at: now,
                picked_at: None,
                completed_at: None,
            };
            let persisted = sqlx::query_as::<_, PgAcmeQueueRow>(
                "INSERT INTO acme_queue \
                 (id, domain, requester_node, status, enqueued_at) \
                 VALUES ($1, $2, $3, 'pending', $4) \
                 ON CONFLICT (domain) \
                   WHERE status IN ('pending', 'in_progress') \
                 DO UPDATE SET domain = acme_queue.domain \
                 RETURNING id, domain, requester_node, status, result_cert_id, \
                           error_msg, enqueued_at, picked_at, completed_at",
            )
            .bind(id)
            .bind(domain)
            .bind(requester_node)
            .bind(to_epoch(now))
            .fetch_one(&mut *tx)
            .await?;
            select_acme_queue_insert_result(candidate, persisted)
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn acme_budget_snapshot(
        &self,
        stale_before: chrono::DateTime<Utc>,
    ) -> Result<super::AcmeBudgetSnapshot> {
        let (queue_active, issuance_in_progress, config_json) =
            sqlx::query_as::<_, (i64, i64, Option<String>)>(
                "SELECT \
                   (SELECT COUNT(*) FROM acme_queue \
                    WHERE status IN ('pending', 'in_progress')), \
                   (SELECT COUNT(*) FROM acme_queue \
                    WHERE status = 'in_progress' \
                      AND (picked_at IS NULL OR picked_at >= $1)), \
                   (SELECT data FROM global_config WHERE id = 1)",
            )
            .bind(to_epoch(stale_before))
            .fetch_one(&self.pool)
            .await?;
        #[cfg(test)]
        acme_budget_snapshot_test_hook::pause_after_statement_read(&self.acme_budget_snapshot_hook)
            .await;
        let config = match config_json {
            Some(json) => serde_json::from_str::<GlobalConfig>(&json)
                .map_err(|e| Error::Internal(format!("corrupt config data: {e}")))?,
            None => GlobalConfig::default(),
        };
        Ok(super::AcmeBudgetSnapshot {
            queue_active: queue_active
                .try_into()
                .map_err(|_| Error::Internal("negative ACME queue count".into()))?,
            queue_capacity: config.acme_queue_capacity,
            issuance_in_progress: issuance_in_progress
                .try_into()
                .map_err(|_| Error::Internal("negative ACME issuance count".into()))?,
        })
    }

    async fn acme_queue_get(&self, id: Uuid) -> Result<Option<AcmeQueueRow>> {
        let row = sqlx::query_as::<_, PgAcmeQueueRow>(
            "SELECT id, domain, requester_node, status, result_cert_id, \
                    error_msg, enqueued_at, picked_at, completed_at \
             FROM acme_queue WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(PgAcmeQueueRow::into_model).transpose()
    }

    async fn acme_queue_pick_next(
        &self,
        stale_after: chrono::Duration,
        concurrency_limit: u32,
    ) -> Result<Option<AcmeQueueRow>> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<Option<AcmeQueueRow>> = async {
            let now = Utc::now();
            let stale_before = now - stale_after;

            let default = serde_json::to_string(&GlobalConfig::default())
                .map_err(|e| Error::Internal(format!("serialize default config: {e}")))?;
            sqlx::query(
                "INSERT INTO global_config (id, data) VALUES (1, $1) \
                 ON CONFLICT(id) DO NOTHING",
            )
            .bind(default)
            .execute(&mut *tx)
            .await?;

            // The singleton config row is the existing cluster-wide
            // serialization point for queue admission. Reuse it here so two
            // nodes cannot both observe a free durable issuance slot.
            sqlx::query_scalar::<_, i32>("SELECT id FROM global_config WHERE id = 1 FOR UPDATE")
                .fetch_one(&mut *tx)
                .await?;

            // Reset every `in_progress` row whose `picked_at` precedes
            // the stale threshold. Age alone does not establish whether
            // its order task stopped, so a still-running order can be
            // made pending again.
            sqlx::query(
                "UPDATE acme_queue SET status = 'pending', picked_at = NULL \
                 WHERE status = 'in_progress' AND picked_at IS NOT NULL \
                       AND picked_at < $1",
            )
            .bind(to_epoch(stale_before))
            .execute(&mut *tx)
            .await?;

            let in_progress = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM acme_queue WHERE status = 'in_progress'",
            )
            .fetch_one(&mut *tx)
            .await?;
            if in_progress >= i64::from(concurrency_limit) {
                return Ok(None);
            }

            // The singleton row lock above serializes the slot count and this
            // claim. SKIP LOCKED remains defensive for direct maintenance
            // transactions that may lock an individual queue row.
            let candidate = sqlx::query_as::<_, PgAcmeQueueRow>(
                "SELECT id, domain, requester_node, status, result_cert_id, \
                        error_msg, enqueued_at, picked_at, completed_at \
                 FROM acme_queue \
                 WHERE status = 'pending' \
                 ORDER BY enqueued_at ASC \
                 LIMIT 1 FOR UPDATE SKIP LOCKED",
            )
            .fetch_optional(&mut *tx)
            .await?;

            let Some(row) = candidate else {
                return Ok(None);
            };

            sqlx::query(
                "UPDATE acme_queue \
                 SET status = 'in_progress', picked_at = $1 \
                 WHERE id = $2 AND status = 'pending'",
            )
            .bind(to_epoch(now))
            .bind(row.id)
            .execute(&mut *tx)
            .await?;

            let mut model = row.into_model()?;
            model.status = AcmeQueueStatus::InProgress;
            model.picked_at = Some(now);
            Ok(Some(model))
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn acme_queue_mark_completed(&self, id: Uuid, result_cert_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let r = sqlx::query(
            "UPDATE acme_queue \
             SET status = 'completed', result_cert_id = $1, completed_at = $2 \
             WHERE id = $3",
        )
        .bind(result_cert_id)
        .bind(to_epoch(now))
        .bind(id)
        .execute(&self.pool)
        .await?;
        if r.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    async fn acme_queue_mark_failed(&self, id: Uuid, error_msg: &str) -> Result<()> {
        let now = Utc::now();
        let r = sqlx::query(
            "UPDATE acme_queue \
             SET status = 'failed', error_msg = $1, completed_at = $2 \
             WHERE id = $3",
        )
        .bind(error_msg)
        .bind(to_epoch(now))
        .bind(id)
        .execute(&self.pool)
        .await?;
        if r.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    // ───── Version counters ─────
    #[cfg(test)]
    async fn route_version_current(&self) -> Result<u64> {
        self.route_version.current().await
    }

    async fn idp_version_current(&self) -> Result<u64> {
        self.idp_version.current().await
    }

    async fn config_version_current(&self) -> Result<u64> {
        self.config_version.current().await
    }

    async fn cert_version_current(&self) -> Result<u64> {
        self.cert_version.current().await
    }

    // ───── DEK ring (master_keys) ─────
    async fn master_keys_load_active_set(&self) -> Result<Vec<MasterKeyRow>> {
        let rows: Vec<(i16, String, bool, bool)> = sqlx::query_as(
            "SELECT key_id, key_encrypted, active, retired \
             FROM master_keys WHERE retired = false ORDER BY key_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Error::Database)?;
        Ok(rows
            .into_iter()
            .map(|(key_id, key_encrypted, active, retired)| MasterKeyRow {
                key_id,
                key_encrypted,
                active,
                retired,
            })
            .collect())
    }

    #[cfg(test)]
    async fn master_keys_insert_first_active_if_empty(
        &self,
        key_encrypted: &str,
    ) -> Result<FirstDekInsertOutcome> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<FirstDekInsertOutcome> = async {
            lock_key_ring_version(&mut tx).await?;
            let inserted: Option<i16> = sqlx::query_scalar(
                "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
                 SELECT 0, $1, true, false \
                 WHERE NOT EXISTS (SELECT 1 FROM master_keys) \
                 ON CONFLICT DO NOTHING \
                 RETURNING key_id",
            )
            .bind(key_encrypted)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Error::Database)?;
            // No returned row means either the table was already nonempty
            // at the statement snapshot or a concurrent unique-key writer
            // won the initialization race.
            if inserted.is_none() {
                return Ok(FirstDekInsertOutcome::AlreadyInitialized);
            }
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(FirstDekInsertOutcome::Inserted)
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn master_keys_insert_first_active_plaintext(
        &self,
        key_plaintext: &[u8],
        master_key: &crate::crypto::MasterKey,
    ) -> Result<FirstDekInsertOutcome> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<FirstDekInsertOutcome> = async {
            lock_key_ring_version(&mut tx).await?;
            let initialized: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM master_keys")
                .fetch_one(&mut *tx)
                .await
                .map_err(Error::Database)?;
            if initialized != 0 {
                return Ok(FirstDekInsertOutcome::AlreadyInitialized);
            }
            let key_encrypted = master_key
                .encrypt_to_base64(key_plaintext)
                .map_err(|error| Error::Internal(format!("KEK-encrypt initial DEK: {error}")))?;
            sqlx::query(
                "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
                 VALUES (0, $1, true, false)",
            )
            .bind(key_encrypted)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(FirstDekInsertOutcome::Inserted)
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    #[cfg(test)]
    async fn master_keys_insert(&self, key_id: i16, key_encrypted: &str) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<()> = async {
            lock_key_ring_version(&mut tx).await?;
            sqlx::query(
                "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
                 VALUES ($1, $2, false, false)",
            )
            .bind(key_id)
            .bind(key_encrypted)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    #[cfg(test)]
    async fn master_keys_allocate_inactive(&self, key_encrypted: &str) -> Result<i16> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<i16> = async {
            // This durable singleton is already the publication authority for
            // the ring. Lock it before reading IDs so allocators on different
            // nodes serialize even when the smallest free slot is the same.
            lock_key_ring_version(&mut tx).await?;

            let used: Vec<(i16,)> =
                sqlx::query_as("SELECT key_id FROM master_keys ORDER BY key_id")
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            let used: std::collections::HashSet<i16> =
                used.into_iter().map(|(key_id,)| key_id).collect();
            let key_id = (0i16..=255)
                .find(|candidate| !used.contains(candidate))
                .ok_or(Error::KeyRingFull)?;

            sqlx::query(
                "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
                 VALUES ($1, $2, false, false)",
            )
            .bind(key_id)
            .bind(key_encrypted)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(key_id)
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn master_keys_allocate_inactive_plaintext(
        &self,
        key_plaintext: &[u8],
        master_key: &crate::crypto::MasterKey,
    ) -> Result<i16> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<i16> = async {
            lock_key_ring_version(&mut tx).await?;
            let used: Vec<(i16,)> =
                sqlx::query_as("SELECT key_id FROM master_keys ORDER BY key_id")
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            let used: std::collections::HashSet<i16> =
                used.into_iter().map(|(key_id,)| key_id).collect();
            let key_id = (0i16..=255)
                .find(|candidate| !used.contains(candidate))
                .ok_or(Error::KeyRingFull)?;
            let key_encrypted = master_key
                .encrypt_to_base64(key_plaintext)
                .map_err(|error| Error::Internal(format!("KEK-encrypt new DEK: {error}")))?;
            sqlx::query(
                "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
                 VALUES ($1, $2, false, false)",
            )
            .bind(key_id)
            .bind(key_encrypted)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(key_id)
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn master_keys_activate(&self, key_id: i16) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<()> = async {
            lock_key_ring_version(&mut tx).await?;
            // SELECT FOR UPDATE locks only the requested key row.
            // Activations of different key IDs can pass this check
            // concurrently; later updates may contend, while the partial
            // unique index remains the one-active-row constraint.
            let row: Option<(bool,)> =
                sqlx::query_as("SELECT retired FROM master_keys WHERE key_id = $1 FOR UPDATE")
                    .bind(key_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            match row {
                None => return Err(Error::NotFound),
                Some((retired,)) if retired => {
                    return Err(Error::ConfigurationError(format!(
                        "cannot activate retired key_id {key_id}"
                    )));
                }
                _ => {}
            }
            sqlx::query(
                "UPDATE master_keys SET active = false \
                 WHERE active = true AND retired = false",
            )
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            sqlx::query("UPDATE master_keys SET active = true WHERE key_id = $1")
                .bind(key_id)
                .execute(&mut *tx)
                .await
                .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn master_keys_retire(&self, key_id: i16) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<()> = async {
            lock_key_ring_version(&mut tx).await?;
            let row: Option<(bool, bool)> = sqlx::query_as(
                "SELECT active, retired FROM master_keys WHERE key_id = $1 FOR UPDATE",
            )
            .bind(key_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Error::Database)?;
            match row {
                None => return Err(Error::NotFound),
                Some((_, retired)) if retired => return Ok(()), // idempotent
                Some((active, _)) if active => {
                    return Err(Error::ConfigurationError(format!(
                        "refusing to retire active key_id {key_id}; \
                         activate another key first"
                    )));
                }
                _ => {}
            }
            sqlx::query(
                "UPDATE master_keys SET retired = true, retired_at = EXTRACT(EPOCH FROM NOW())::BIGINT \
                 WHERE key_id = $1",
            )
            .bind(key_id)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn identity_signing_load(
        &self,
    ) -> Result<(
        u64,
        Vec<super::IdentitySigningKeyRow>,
        crate::crypto::MasterKeyRing,
    )> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let version: i64 =
            sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = $1 FOR SHARE")
                .bind(sqlite_version_consts::RESOURCE_IDENTITY_SIGNING_KEY_RING)
                .fetch_one(&mut *tx)
                .await
                .map_err(Error::Database)?;
        let ring_version: i64 =
            sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = $1 FOR SHARE")
                .bind(sqlite_version_consts::RESOURCE_KEY_RING)
                .fetch_one(&mut *tx)
                .await
                .map_err(Error::Database)?;
        let rows = sqlx::query_as::<_, (String, String, Option<String>, String, Option<i64>)>(
            "SELECT kid, state, private_key_encrypted, public_jwk, retire_until \
             FROM identity_signing_keys ORDER BY state, kid",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(Error::Database)?
        .into_iter()
        .map(
            |(kid, state, private_key_encrypted, public_jwk, retire_until)| {
                super::IdentitySigningKeyRow {
                    kid,
                    state,
                    private_key_encrypted,
                    public_jwk,
                    retire_until,
                }
            },
        )
        .collect();
        let master_rows = sqlx::query_as::<_, (i16, String, bool, bool)>(
            "SELECT key_id, key_encrypted, active, retired FROM master_keys \
             WHERE retired = false ORDER BY key_id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(Error::Database)?
        .into_iter()
        .map(
            |(key_id, key_encrypted, active, retired)| super::MasterKeyRow {
                key_id,
                key_encrypted,
                active,
                retired,
            },
        )
        .collect();
        let ring =
            super::build_master_key_ring(&self.master_key, master_rows, ring_version as u64)?;
        tx.commit().await.map_err(Error::Database)?;
        Ok((version as u64, rows, ring))
    }

    async fn identity_signing_bootstrap(
        &self,
        kid: &str,
        private_pkcs8: &[u8],
        public_jwk: &str,
    ) -> Result<super::IdentitySigningBootstrapOutcome> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<super::IdentitySigningBootstrapOutcome> = async {
            lock_key_ring_version(&mut tx).await?;
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_signing_keys")
                .fetch_one(&mut *tx)
                .await
                .map_err(Error::Database)?;
            if count != 0 {
                let deleted = sqlx::query("DELETE FROM secrets WHERE key = 'jwt_signing_key'")
                    .execute(&mut *tx)
                    .await
                    .map_err(Error::Database)?
                    .rows_affected();
                if deleted != 0 {
                    self.identity_signing_version.bump(&mut *tx).await?;
                }
                return Ok(super::IdentitySigningBootstrapOutcome::Existing);
            }
            let ring_version: i64 =
                sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = $1")
                    .bind(sqlite_version_consts::RESOURCE_KEY_RING)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            let master_rows = sqlx::query_as::<_, (i16, String, bool, bool)>(
                "SELECT key_id, key_encrypted, active, retired FROM master_keys \
                 WHERE retired = false ORDER BY key_id FOR UPDATE",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(Error::Database)?
            .into_iter()
            .map(
                |(key_id, key_encrypted, active, retired)| super::MasterKeyRow {
                    key_id,
                    key_encrypted,
                    active,
                    retired,
                },
            )
            .collect();
            let ring =
                super::build_master_key_ring(&self.master_key, master_rows, ring_version as u64)?;
            let encrypted = ring.encrypt_active_to_base64(private_pkcs8)?;
            sqlx::query(
                "INSERT INTO identity_signing_keys \
                 (kid, state, private_key_encrypted, public_jwk, retire_until) \
                 VALUES ($1, 'current', $2, $3, NULL)",
            )
            .bind(kid)
            .bind(encrypted)
            .bind(public_jwk)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            sqlx::query("DELETE FROM secrets WHERE key = 'jwt_signing_key'")
                .execute(&mut *tx)
                .await
                .map_err(Error::Database)?;
            self.identity_signing_version.bump(&mut *tx).await?;
            Ok(super::IdentitySigningBootstrapOutcome::Inserted)
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn identity_signing_rotate(
        &self,
        kid: &str,
        private_pkcs8: &[u8],
        public_jwk: &str,
        grace_secs: i64,
    ) -> Result<super::IdentitySigningRotateOutcome> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<super::IdentitySigningRotateOutcome> = async {
            lock_key_ring_version(&mut tx).await?;
            let now: i64 = sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM NOW())::BIGINT")
                .fetch_one(&mut *tx)
                .await
                .map_err(Error::Database)?;
            let retiring_until: Option<i64> = sqlx::query_scalar(
                "SELECT retire_until FROM identity_signing_keys \
                 WHERE state = 'retiring' FOR UPDATE",
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(Error::Database)?
            .flatten();
            if retiring_until.is_some_and(|until| now <= until) {
                return Ok(super::IdentitySigningRotateOutcome::RetiringStillEligible);
            }
            let current_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM identity_signing_keys WHERE state = 'current'",
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(Error::Database)?;
            if current_count != 1 {
                return Err(Error::ConfigurationError(
                    "identity signing ring must contain exactly one current key".into(),
                ));
            }
            sqlx::query(
                "DELETE FROM identity_signing_keys WHERE state = 'retiring' AND retire_until < $1",
            )
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            let ring_version: i64 =
                sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = $1")
                    .bind(sqlite_version_consts::RESOURCE_KEY_RING)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            let master_rows = sqlx::query_as::<_, (i16, String, bool, bool)>(
                "SELECT key_id, key_encrypted, active, retired FROM master_keys \
                 WHERE retired = false ORDER BY key_id FOR UPDATE",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(Error::Database)?
            .into_iter()
            .map(
                |(key_id, key_encrypted, active, retired)| super::MasterKeyRow {
                    key_id,
                    key_encrypted,
                    active,
                    retired,
                },
            )
            .collect();
            let ring =
                super::build_master_key_ring(&self.master_key, master_rows, ring_version as u64)?;
            let encrypted = ring.encrypt_active_to_base64(private_pkcs8)?;
            sqlx::query(
                "UPDATE identity_signing_keys SET state = 'retiring', \
                 private_key_encrypted = NULL, retire_until = $1 WHERE state = 'current'",
            )
            .bind(now + grace_secs)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            sqlx::query(
                "INSERT INTO identity_signing_keys \
                 (kid, state, private_key_encrypted, public_jwk, retire_until) \
                 VALUES ($1, 'current', $2, $3, NULL)",
            )
            .bind(kid)
            .bind(encrypted)
            .bind(public_jwk)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            sqlx::query("DELETE FROM secrets WHERE key = 'jwt_signing_key'")
                .execute(&mut *tx)
                .await
                .map_err(Error::Database)?;
            self.identity_signing_version.bump(&mut *tx).await?;
            Ok(super::IdentitySigningRotateOutcome::Rotated)
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn identity_signing_version_current(&self) -> Result<u64> {
        self.identity_signing_version.current().await
    }

    async fn identity_signing_reencrypt_current(
        &self,
    ) -> Result<super::IdentitySigningReencryptOutcome> {
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<super::IdentitySigningReencryptOutcome> = async {
            lock_key_ring_version(&mut tx).await?;
            let ring_version: i64 =
                sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = $1")
                    .bind(sqlite_version_consts::RESOURCE_KEY_RING)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            let Some(encrypted): Option<String> = sqlx::query_scalar(
                "SELECT private_key_encrypted FROM identity_signing_keys \
                 WHERE state = 'current' FOR UPDATE",
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(Error::Database)?
            .flatten() else {
                return Ok(super::IdentitySigningReencryptOutcome::default());
            };
            let master_rows = sqlx::query_as::<_, (i16, String, bool, bool)>(
                "SELECT key_id, key_encrypted, active, retired FROM master_keys \
                 WHERE retired = false ORDER BY key_id FOR UPDATE",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(Error::Database)?
            .into_iter()
            .map(
                |(key_id, key_encrypted, active, retired)| super::MasterKeyRow {
                    key_id,
                    key_encrypted,
                    active,
                    retired,
                },
            )
            .collect();
            let ring =
                super::build_master_key_ring(&self.master_key, master_rows, ring_version as u64)?;
            if crate::crypto::peek_key_id_from_base64(&encrypted)
                .ok()
                .flatten()
                == Some(ring.active_key_id())
            {
                return Ok(super::IdentitySigningReencryptOutcome {
                    examined: 1,
                    reencrypted: 0,
                    skipped: 1,
                });
            }
            let plaintext = ring.decrypt_from_base64(&encrypted)?;
            let replacement = ring.encrypt_active_to_base64(&plaintext)?;
            sqlx::query(
                "UPDATE identity_signing_keys SET private_key_encrypted = $1 \
                 WHERE state = 'current'",
            )
            .bind(replacement)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            self.identity_signing_version.bump(&mut *tx).await?;
            Ok(super::IdentitySigningReencryptOutcome {
                examined: 1,
                reencrypted: 1,
                skipped: 0,
            })
        }
        .await;
        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn identity_signing_scan_key_id(&self, key_id: u8) -> Result<u64> {
        let encrypted: Option<String> = sqlx::query_scalar(
            "SELECT private_key_encrypted FROM identity_signing_keys WHERE state = 'current'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::Database)?
        .flatten();
        Ok(u64::from(
            encrypted
                .as_deref()
                .and_then(|value| crate::crypto::peek_key_id_from_base64(value).ok().flatten())
                .is_some_and(|id| id.get() == key_id),
        ))
    }

    async fn key_ring_version_current(&self) -> Result<u64> {
        self.key_ring_version.current().await
    }

    // ───── Pending auth ─────
    async fn pending_auth_insert(
        &self,
        csrf_token: &str,
        state: &crate::auth::middleware::PendingAuth,
    ) -> Result<()> {
        let expires_at = state.created_at + crate::auth::middleware::PENDING_AUTH_TTL;
        sqlx::query(
            r#"
            INSERT INTO pending_auth (
                csrf, idp_id, nonce, code_verifier,
                saml_authn_request_id, redirect_url, created_at, expires_at, kind,
                browser_nonce_hash
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT(csrf) DO UPDATE SET
                idp_id = excluded.idp_id,
                nonce = excluded.nonce,
                code_verifier = excluded.code_verifier,
                saml_authn_request_id = excluded.saml_authn_request_id,
                redirect_url = excluded.redirect_url,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                kind = excluded.kind,
                browser_nonce_hash = excluded.browser_nonce_hash
            "#,
        )
        .bind(csrf_token)
        .bind(state.idp_id)
        .bind(&state.nonce)
        .bind(&state.code_verifier)
        .bind(state.saml_authn_request_id.as_deref())
        .bind(&state.redirect_url)
        .bind(to_epoch(state.created_at))
        .bind(to_epoch(expires_at))
        .bind(state.kind.as_db_str())
        .bind(state.browser_nonce_hash.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn pending_auth_get(
        &self,
        csrf_token: &str,
    ) -> Result<Option<crate::auth::middleware::PendingAuth>> {
        let row = sqlx::query_as::<_, PgPendingAuthRow>(
            "SELECT idp_id, nonce, code_verifier, saml_authn_request_id, \
                    redirect_url, created_at, expires_at, kind, browser_nonce_hash \
             FROM pending_auth WHERE csrf = $1 AND expires_at >= $2",
        )
        .bind(csrf_token)
        .bind(to_epoch(chrono::Utc::now()))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(PgPendingAuthRow::into_model))
    }

    async fn pending_auth_take(
        &self,
        csrf_token: &str,
    ) -> Result<Option<crate::auth::middleware::PendingAuth>> {
        // DELETE ... RETURNING keeps read-and-delete atomic in a single
        // round trip; no need for an explicit transaction wrapper.
        let row = sqlx::query_as::<_, PgPendingAuthRow>(
            "DELETE FROM pending_auth WHERE csrf = $1 \
             RETURNING idp_id, nonce, code_verifier, saml_authn_request_id, \
                       redirect_url, created_at, expires_at, kind, browser_nonce_hash",
        )
        .bind(csrf_token)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        if row.expires_at < to_epoch(chrono::Utc::now()) {
            // Row was past TTL; treat as absent. The DELETE already
            // cleaned it up, which is the side effect we want.
            return Ok(None);
        }
        Ok(Some(row.into_model()))
    }

    async fn pending_auth_transition(
        &self,
        auth_start_token: &str,
        login_token: &str,
        login_state: &crate::auth::middleware::PendingAuth,
    ) -> Result<bool> {
        if login_state.kind != crate::auth::middleware::PendingAuthKind::Login {
            return Err(Error::Internal(
                "auth-start transition requires Login state".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(Error::Database)?;
        let result: Result<bool> = async {
            let deleted = sqlx::query(
                "DELETE FROM pending_auth \
                 WHERE csrf = $1 AND kind = $2 AND expires_at >= $3 \
                   AND idp_id = $4 AND redirect_url = $5",
            )
            .bind(auth_start_token)
            .bind(crate::auth::middleware::PendingAuthKind::AuthStart.as_db_str())
            .bind(to_epoch(chrono::Utc::now()))
            .bind(login_state.idp_id)
            .bind(&login_state.redirect_url)
            .execute(&mut *tx)
            .await?;
            if deleted.rows_affected() != 1 {
                return Ok(false);
            }

            let expires_at = login_state.created_at + crate::auth::middleware::PENDING_AUTH_TTL;
            sqlx::query(
                r#"
                INSERT INTO pending_auth (
                    csrf, idp_id, nonce, code_verifier,
                    saml_authn_request_id, redirect_url, created_at, expires_at, kind,
                    browser_nonce_hash
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                "#,
            )
            .bind(login_token)
            .bind(login_state.idp_id)
            .bind(&login_state.nonce)
            .bind(&login_state.code_verifier)
            .bind(login_state.saml_authn_request_id.as_deref())
            .bind(&login_state.redirect_url)
            .bind(to_epoch(login_state.created_at))
            .bind(to_epoch(expires_at))
            .bind(login_state.kind.as_db_str())
            .bind(login_state.browser_nonce_hash.as_deref())
            .execute(&mut *tx)
            .await?;
            Ok(true)
        }
        .await;

        finalize_pg_tx(tx, &result).await?;
        result
    }

    async fn pending_auth_cleanup_expired(&self) -> Result<u64> {
        let r = sqlx::query(
            "DELETE FROM pending_auth WHERE expires_at < EXTRACT(EPOCH FROM NOW())::BIGINT",
        )
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected())
    }

    /// `ON CONFLICT DO NOTHING` is the Postgres spelling of the same claim the
    /// SQLite backend makes with `INSERT OR IGNORE`: the primary key decides,
    /// and `rows_affected` reports the winner. This is the path that matters in
    /// HA, where the two redemptions may arrive at different nodes.
    async fn handoff_nonce_consume(&self, nonce: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO used_handoff_nonces (nonce) VALUES ($1) \
             ON CONFLICT (nonce) DO NOTHING",
        )
        .bind(nonce)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Retention only. `NOW()` is the shared database clock, which is what
    /// keeps nodes with drifting local clocks from pruning each other's rows
    /// early.
    async fn handoff_nonce_cleanup_expired(&self) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM used_handoff_nonces \
             WHERE consumed_at < EXTRACT(EPOCH FROM NOW())::BIGINT - $1",
        )
        .bind(super::HANDOFF_NONCE_RETENTION_SECONDS)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn ping(&self) -> Result<()> {
        // `SELECT 1` is the canonical "prove the pool still round-trips"
        // probe: no table, no lock, no sequence bump. `fetch_one` forces
        // a real server round-trip rather than satisfying the query from
        // the client library's state.
        sqlx::query("SELECT 1").fetch_one(&self.pool).await?;
        Ok(())
    }
}

// ═══════════════════════ Helpers ═══════════════════════

/// `FromRow` target for the Postgres ACME queue. Separate from the
/// cross-backend `AcmeQueueRow` so the sqlx derive stays out of the
/// model.
#[derive(sqlx::FromRow)]
struct PgAcmeQueueRow {
    id: Uuid,
    domain: String,
    requester_node: String,
    status: String,
    result_cert_id: Option<Uuid>,
    error_msg: Option<String>,
    enqueued_at: i64,
    picked_at: Option<i64>,
    completed_at: Option<i64>,
}

impl PgAcmeQueueRow {
    fn into_model(self) -> Result<AcmeQueueRow> {
        Ok(AcmeQueueRow {
            id: self.id,
            domain: self.domain,
            requester_node: self.requester_node,
            status: AcmeQueueStatus::from_db_str(&self.status),
            result_cert_id: self.result_cert_id,
            error_msg: self.error_msg,
            enqueued_at: from_epoch(self.enqueued_at),
            picked_at: from_epoch_opt(self.picked_at),
            completed_at: from_epoch_opt(self.completed_at),
        })
    }
}

fn select_acme_queue_insert_result(
    candidate: AcmeQueueRow,
    persisted: PgAcmeQueueRow,
) -> Result<AcmeQueueAdmission> {
    if persisted.id == candidate.id {
        Ok(AcmeQueueAdmission::Inserted(candidate))
    } else {
        persisted.into_model().map(AcmeQueueAdmission::Existing)
    }
}

#[cfg(test)]
mod acme_queue_insert_result_tests {
    use super::*;

    fn admitted(admission: AcmeQueueAdmission) -> AcmeQueueRow {
        match admission {
            AcmeQueueAdmission::Inserted(row) | AcmeQueueAdmission::Existing(row) => row,
            AcmeQueueAdmission::Full => panic!("queue unexpectedly full"),
        }
    }

    fn candidate(id: Uuid, enqueued_at: chrono::DateTime<Utc>) -> AcmeQueueRow {
        AcmeQueueRow {
            id,
            domain: "candidate.example".to_owned(),
            requester_node: "candidate-node".to_owned(),
            status: AcmeQueueStatus::Pending,
            result_cert_id: None,
            error_msg: None,
            enqueued_at,
            picked_at: None,
            completed_at: None,
        }
    }

    fn persisted(id: Uuid, enqueued_at: i64) -> PgAcmeQueueRow {
        PgAcmeQueueRow {
            id,
            domain: "persisted.example".to_owned(),
            requester_node: "persisted-node".to_owned(),
            status: "pending".to_owned(),
            result_cert_id: None,
            error_msg: None,
            enqueued_at,
            picked_at: None,
            completed_at: None,
        }
    }

    #[test]
    fn queue_insert_result_preserves_candidate_only_for_winning_id() {
        let winner_id = Uuid::from_u128(1);
        let candidate_time =
            chrono::DateTime::<Utc>::from_timestamp(1_700_000_000, 123_456_789).unwrap();
        let winner = admitted(
            select_acme_queue_insert_result(
                candidate(winner_id, candidate_time),
                persisted(winner_id, 1_600_000_000),
            )
            .unwrap(),
        );
        assert_eq!(winner.id, winner_id);
        assert_eq!(winner.domain, "candidate.example");
        assert_eq!(winner.enqueued_at, candidate_time);

        let persisted_winner_id = Uuid::from_u128(3);
        let loser = admitted(
            select_acme_queue_insert_result(
                candidate(Uuid::from_u128(2), candidate_time),
                persisted(persisted_winner_id, 1_600_000_000),
            )
            .unwrap(),
        );
        assert_eq!(loser.id, persisted_winner_id);
        assert_eq!(loser.domain, "persisted.example");
        assert_eq!(
            loser.enqueued_at,
            chrono::DateTime::<Utc>::from_timestamp(1_600_000_000, 0).unwrap()
        );
    }
}

/// `FromRow` target for the Postgres election singleton. Separate from
/// the backend-trait's `AcmeElectionRow` so the sqlx derive stays in
/// the backend module.
#[derive(sqlx::FromRow)]
struct PgAcmeElectionRow {
    node_id: String,
    node_hash: String,
    updated_at: i64,
}

/// Postgres row shape for `pending_auth`. Kept parallel to the SQLite
/// helper so the cross-backend shape stays sqlx-free.
#[derive(sqlx::FromRow)]
struct PgPendingAuthRow {
    idp_id: Uuid,
    nonce: String,
    code_verifier: String,
    saml_authn_request_id: Option<String>,
    redirect_url: String,
    created_at: i64,
    expires_at: i64,
    kind: String,
    browser_nonce_hash: Option<String>,
}

impl PgPendingAuthRow {
    fn into_model(self) -> crate::auth::middleware::PendingAuth {
        crate::auth::middleware::PendingAuth {
            idp_id: self.idp_id,
            nonce: self.nonce,
            code_verifier: self.code_verifier,
            redirect_url: self.redirect_url,
            created_at: from_epoch(self.created_at),
            saml_authn_request_id: self.saml_authn_request_id,
            kind: crate::auth::middleware::PendingAuthKind::from_db_str(&self.kind),
            browser_nonce_hash: self.browser_nonce_hash,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    id: Uuid,
    name: String,
    prefix: String,
    key_hash: String,
    scopes: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

impl ApiKeyRow {
    fn into_model(self) -> Result<ApiKey> {
        let scopes = ApiKeyScopeSet::from_storage(&self.scopes)
            .map_err(|_| Error::Internal("corrupt API key scopes".into()))?;
        Ok(ApiKey {
            id: self.id,
            name: self.name,
            prefix: self.prefix,
            key_hash: self.key_hash,
            scopes,
            created_at: from_epoch(self.created_at),
            last_used_at: from_epoch_opt(self.last_used_at),
        })
    }
}

fn generate_raw_key() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    format!(
        "sks_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}
