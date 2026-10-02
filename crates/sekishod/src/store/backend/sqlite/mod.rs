//! SQLite implementation of `StorageBackend`.
//!
//! Everything SQLite-specific lives here: migrations, `BEGIN IMMEDIATE`
//! transaction framing, the JSON-blob CRUD helpers, and the DbVersion
//! counters. Callers interact with this backend through `Store`, not
//! directly — the one place that pokes at `SqliteBackend::new_service`
//! / `SqliteBackend::from_pool_as_service` is the `Store::new` bootstrap.
//!
//! The Postgres backend lives as a sibling module (`backend::postgres`),
//! implements the same trait, and is dispatched as another `Backend` enum
//! variant. The trait definition in `backend::mod` is the contract both
//! sides have to match.

mod crud;

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
use crate::store::version::{self, DbVersion};
use base64::Engine;
use chrono::Utc;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Sqlite, SqlitePool, Transaction};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

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

/// SQLite-backed implementation. Cheap to clone — holds an `Arc`-backed
/// pool and `DbVersion` instances, each of which is also cheap
/// to clone.
#[derive(Clone)]
pub struct SqliteBackend {
    pool: SqlitePool,
    route_version: DbVersion,
    idp_version: DbVersion,
    config_version: DbVersion,
    cert_version: DbVersion,
    /// DEK ring counter. Bumped on every `master_keys` mutation
    /// (`add` / `activate` / `retire`); each daemon's polling loop
    /// compares against the last value it observed and refreshes the
    /// in-memory `MasterKeyRing` on a mismatch.
    key_ring_version: DbVersion,
    identity_signing_version: DbVersion,
    /// Shared master-key capability used to HMAC API-key secrets.
    master_key: Arc<MasterKey>,
}

#[cfg(test)]
fn test_master_key() -> Arc<MasterKey> {
    MasterKey::from_test_bytes([0u8; 32])
}

#[cfg(test)]
mod service_migration_tests {
    use super::{SqliteBackend, migration_test_hook as sqlite_migration_hook, test_master_key};
    use crate::store::backend::SERVICE_MIGRATIONS;
    use sqlx::SqlitePool;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::{str::FromStr, sync::atomic::Ordering};
    use uuid::Uuid;

    struct TempSqliteDb {
        path: std::path::PathBuf,
        url: String,
    }

    impl TempSqliteDb {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sekisho-migration-{label}-{}-{sequence}.sqlite3",
                std::process::id()
            ));
            let url = format!("sqlite://{}?mode=rwc", path.display());
            Self { path, url }
        }
    }

    impl Drop for TempSqliteDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(format!("{}-shm", self.path.display()));
            let _ = std::fs::remove_file(format!("{}-wal", self.path.display()));
        }
    }

    async fn migration_sqlite_pool(database_url: &str) -> SqlitePool {
        let options = SqliteConnectOptions::from_str(database_url)
            .unwrap()
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5));
        SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .unwrap()
    }

    async fn seed_legacy_sqlite(db: &TempSqliteDb) {
        let pool = SqlitePool::connect(&db.url).await.expect("legacy sqlite");
        sqlx::query(
            r#"CREATE TABLE identity_providers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                idp_type TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy identity_providers");
        sqlx::query(
            r#"CREATE TABLE pending_auth (
                csrf TEXT PRIMARY KEY,
                idp_id TEXT NOT NULL,
                nonce TEXT NOT NULL DEFAULT '',
                code_verifier TEXT NOT NULL DEFAULT '',
                saml_authn_request_id TEXT,
                redirect_url TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy pending_auth");
        sqlx::query(
            r#"CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                idp_id TEXT NOT NULL,
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                last_accessed_at INTEGER
            )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy sessions");
        sqlx::query(
            r#"CREATE TABLE api_certificate (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy management certificate table");
        sqlx::query(
            r#"CREATE TABLE api_keys (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                last_used_at INTEGER
            )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy API-key table");
        sqlx::query(
            "INSERT INTO api_keys \
             (id, name, prefix, key_hash, created_at, last_used_at) \
             VALUES (?, 'legacy-admin', 'sks_lega', 'legacy-api-key-hash', 1, NULL)",
        )
        .bind(Uuid::from_u128(0x102))
        .execute(&pool)
        .await
        .expect("legacy API-key row");
        sqlx::query(
            "INSERT INTO api_certificate (id, data, expires_at) VALUES (1, '{}', 2000000000)",
        )
        .execute(&pool)
        .await
        .expect("legacy management certificate row");
        let session_id = Uuid::from_u128(0x101);
        let idp_id = Uuid::from_u128(0x100);
        let session_data = serde_json::json!({
            "id": session_id,
            "user_id": "legacy@example.com",
            "idp_id": idp_id,
            "claims": {},
            "groups": [],
            "created_at": 1_699_999_000_i64,
            "expires_at": 2_000_000_000_i64,
            "refresh_token_encrypted": null,
            "id_token_encrypted": null,
            "saml_name_id": null,
            "saml_session_index": null,
            "last_accessed_at": 1_700_000_000_i64
        });
        sqlx::query(
            "INSERT INTO sessions \
             (id, user_id, idp_id, data, expires_at, last_accessed_at) \
             VALUES (?, 'legacy@example.com', ?, ?, 2000000000, NULL)",
        )
        .bind(session_id)
        .bind(idp_id)
        .bind(session_data.to_string())
        .execute(&pool)
        .await
        .expect("legacy session row");
        sqlx::query(
            r#"INSERT INTO identity_providers (id, name, idp_type, data)
               VALUES (?, 'legacy-saml', '"saml"', ?)"#,
        )
        .bind(Uuid::from_u128(0x100).to_string())
        .bind(
            r#"{"name":"legacy-saml","saml_config":{"metadata_url":"https://idp.example/metadata","entity_id":"dead-entity","acs_url":"https://dead.example/acs"}}"#,
        )
        .execute(&pool)
        .await
        .expect("legacy SAML row");
        sqlx::query(
            r#"INSERT INTO pending_auth (
                   csrf, idp_id, redirect_url, created_at, expires_at
               ) VALUES ('legacy-csrf', ?, '/', 1, 2)"#,
        )
        .bind(Uuid::from_u128(0x100).to_string())
        .execute(&pool)
        .await
        .expect("legacy pending auth");
        sqlx::query("CREATE TABLE migration_effects (count INTEGER NOT NULL)")
            .execute(&pool)
            .await
            .expect("migration counter table");
        sqlx::query("INSERT INTO migration_effects (count) VALUES (0)")
            .execute(&pool)
            .await
            .expect("migration counter seed");
        sqlx::query(
            r#"CREATE TRIGGER count_saml_cleanup
               AFTER UPDATE ON identity_providers
               BEGIN
                   UPDATE migration_effects SET count = count + 1;
               END"#,
        )
        .execute(&pool)
        .await
        .expect("migration counter trigger");
        pool.close().await;
    }

    async fn sqlite_ledger(pool: &SqlitePool) -> Vec<(i64, String)> {
        sqlx::query_as("SELECT version, name FROM service_migrations ORDER BY version")
            .fetch_all(pool)
            .await
            .expect("SQLite migration ledger")
    }

    async fn sqlite_kind_columns(pool: &SqlitePool) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('pending_auth') WHERE name = 'kind'",
        )
        .fetch_one(pool)
        .await
        .expect("pending_auth kind count")
    }

    async fn sqlite_api_key_scope_columns(pool: &SqlitePool) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name = 'scopes'",
        )
        .fetch_one(pool)
        .await
        .expect("API-key scope column count")
    }

    async fn sqlite_handoff_nonce_tables(pool: &SqlitePool) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND name = 'used_handoff_nonces'",
        )
        .fetch_one(pool)
        .await
        .expect("handoff nonce table count")
    }

    async fn restore_api_keys_v6_shape(pool: &SqlitePool) {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "CREATE TABLE api_keys_v6 (\
             id TEXT PRIMARY KEY, name TEXT NOT NULL, prefix TEXT NOT NULL, \
             key_hash TEXT NOT NULL UNIQUE, \
             created_at INTEGER NOT NULL DEFAULT (unixepoch()), last_used_at INTEGER)",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO api_keys_v6 \
             (id, name, prefix, key_hash, created_at, last_used_at) \
             SELECT id, name, prefix, key_hash, created_at, last_used_at FROM api_keys",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("DROP TABLE api_keys")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE api_keys_v6 RENAME TO api_keys")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("DROP TABLE used_handoff_nonces")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM service_migrations WHERE version >= 7")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    fn expected_migration_ledger() -> Vec<(i64, String)> {
        SERVICE_MIGRATIONS
            .iter()
            .map(|migration| (migration.version, migration.name.to_owned()))
            .collect()
    }

    #[tokio::test]
    async fn sqlite_service_migrations_cover_fresh_upgrade_and_repeat_boot() {
        let fresh = TempSqliteDb::new("fresh");
        let backend = SqliteBackend::new_service(&fresh.url, test_master_key())
            .await
            .expect("fresh SQLite migrations");
        assert_eq!(
            sqlite_ledger(backend.pool()).await,
            expected_migration_ledger()
        );
        assert_eq!(sqlite_handoff_nonce_tables(backend.pool()).await, 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schema_versions")
                .fetch_one(backend.pool())
                .await
                .unwrap(),
            crate::store::version::ALL_RESOURCES.len() as i64
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COALESCE(SUM(version), 0) FROM schema_versions")
                .fetch_one(backend.pool())
                .await
                .unwrap(),
            0
        );
        backend.close().await;

        let fresh_reopen = SqliteBackend::new_service(&fresh.url, test_master_key())
            .await
            .expect("fresh SQLite repeat boot");
        assert_eq!(
            sqlite_ledger(fresh_reopen.pool()).await,
            expected_migration_ledger()
        );
        fresh_reopen.close().await;

        let upgraded = TempSqliteDb::new("upgrade");
        seed_legacy_sqlite(&upgraded).await;
        let backend = SqliteBackend::new_service(&upgraded.url, test_master_key())
            .await
            .expect("legacy SQLite upgrade");
        assert_eq!(sqlite_kind_columns(backend.pool()).await, 1);
        let kind: String =
            sqlx::query_scalar("SELECT kind FROM pending_auth WHERE csrf = 'legacy-csrf'")
                .fetch_one(backend.pool())
                .await
                .expect("backfilled pending-auth kind");
        assert_eq!(kind, "login");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'api_certificate'",
            )
            .fetch_one(backend.pool())
            .await
            .unwrap(),
            0,
            "v6 must drop the legacy management certificate table"
        );
        let last_accessed_at: i64 = sqlx::query_scalar(
            "SELECT last_accessed_at FROM sessions WHERE user_id = 'legacy@example.com'",
        )
        .fetch_one(backend.pool())
        .await
        .expect("backfilled session last_accessed_at");
        assert_eq!(last_accessed_at, 1_700_000_000);
        let scopes: String =
            sqlx::query_scalar("SELECT scopes FROM api_keys WHERE name = 'legacy-admin'")
                .fetch_one(backend.pool())
                .await
                .expect("backfilled legacy API-key scopes");
        assert_eq!(scopes, r#"["management:admin"]"#);
        let data: String =
            sqlx::query_scalar("SELECT data FROM identity_providers WHERE name = 'legacy-saml'")
                .fetch_one(backend.pool())
                .await
                .expect("migrated SAML row");
        let data: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert!(data.pointer("/saml_config/entity_id").is_none());
        assert!(data.pointer("/saml_config/acs_url").is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count FROM migration_effects")
                .fetch_one(backend.pool())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlite_ledger(backend.pool()).await,
            expected_migration_ledger()
        );
        backend.close().await;

        let reopened = SqliteBackend::new_service(&upgraded.url, test_master_key())
            .await
            .expect("legacy SQLite repeat boot");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count FROM migration_effects")
                .fetch_one(reopened.pool())
                .await
                .unwrap(),
            1,
            "the data migration ran again after its ledger entry"
        );
        reopened.close().await;

        let adopted = TempSqliteDb::new("pre-ledger-latest");
        seed_legacy_sqlite(&adopted).await;
        let pool = SqlitePool::connect(&adopted.url).await.unwrap();
        sqlx::query("ALTER TABLE pending_auth ADD COLUMN kind TEXT NOT NULL DEFAULT 'login'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            r#"UPDATE identity_providers
               SET data = json_remove(data, '$.saml_config.entity_id', '$.saml_config.acs_url')
               WHERE idp_type = '"saml"'"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE migration_effects SET count = 0")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let backend = SqliteBackend::new_service(&adopted.url, test_master_key())
            .await
            .expect("pre-ledger latest SQLite adoption");
        assert_eq!(
            sqlite_ledger(backend.pool()).await,
            expected_migration_ledger()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count FROM migration_effects")
                .fetch_one(backend.pool())
                .await
                .unwrap(),
            1,
            "ledger adoption must execute and record the migration body once"
        );
        let data: String =
            sqlx::query_scalar("SELECT data FROM identity_providers WHERE name = 'legacy-saml'")
                .fetch_one(backend.pool())
                .await
                .unwrap();
        assert!(!data.contains("dead-entity"));
        assert!(!data.contains("dead.example"));
        backend.close().await;

        let v6 = TempSqliteDb::new("v6-rollback");
        let backend = SqliteBackend::new_service(&v6.url, test_master_key())
            .await
            .expect("prepare current SQLite schema for v6 rollback fixture");
        backend.close().await;
        let pool = SqlitePool::connect(&v6.url).await.unwrap();
        sqlx::query(
            r#"CREATE TABLE api_certificate (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM service_migrations WHERE version >= 6")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            r#"CREATE TRIGGER reject_v6_ledger
               BEFORE INSERT ON service_migrations
               WHEN NEW.version = 6
               BEGIN
                   SELECT RAISE(ABORT, 'injected v6 ledger failure');
               END"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
        let error = match SqliteBackend::new_service(&v6.url, test_master_key()).await {
            Ok(_) => panic!("v6 SQLite migration failure was swallowed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("injected v6 ledger failure"));
        let pool = SqlitePool::connect(&v6.url).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'api_certificate'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1,
            "failed v6 ledger write must roll back the table drop"
        );
        sqlx::query("DROP TRIGGER reject_v6_ledger")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let backend = SqliteBackend::new_service(&v6.url, test_master_key())
            .await
            .expect("retry v6 after SQLite failure");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'api_certificate'",
            )
            .fetch_one(backend.pool())
            .await
            .unwrap(),
            0
        );
        backend.close().await;
    }

    #[tokio::test]
    async fn sqlite_service_migrations_propagate_real_errors_and_retry() {
        let db = TempSqliteDb::new("real-error");
        seed_legacy_sqlite(&db).await;
        let pool = SqlitePool::connect(&db.url).await.unwrap();
        sqlx::query(
            r#"CREATE TRIGGER reject_saml_cleanup
               BEFORE UPDATE ON identity_providers
               BEGIN
                   SELECT RAISE(ABORT, 'already exists injected real failure');
               END"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let error = match SqliteBackend::new_service(&db.url, test_master_key()).await {
            Ok(_) => panic!("real SQLite migration error was swallowed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("already exists injected real failure")
        );

        let pool = SqlitePool::connect(&db.url).await.unwrap();
        assert_eq!(sqlite_kind_columns(&pool).await, 0);
        let ledger_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND name = 'service_migrations'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ledger_exists, 0);
        sqlx::query("DROP TRIGGER reject_saml_cleanup")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let backend = SqliteBackend::new_service(&db.url, test_master_key())
            .await
            .expect("SQLite migration retry");
        assert_eq!(
            sqlite_ledger(backend.pool()).await,
            expected_migration_ledger()
        );
        backend.close().await;
    }

    #[tokio::test]
    async fn sqlite_session_authority_migration_rejects_bad_json_and_retries_cleanly() {
        let db = TempSqliteDb::new("session-v4-invalid");
        seed_legacy_sqlite(&db).await;
        let pool = SqlitePool::connect(&db.url).await.unwrap();
        sqlx::query(
            "UPDATE sessions SET data = json_remove(data, '$.last_accessed_at') \
             WHERE user_id = 'legacy@example.com'",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let error = match SqliteBackend::new_service(&db.url, test_master_key()).await {
            Ok(_) => panic!("invalid legacy session timestamp was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("missing or malformed"));

        let pool = SqlitePool::connect(&db.url).await.unwrap();
        let last_accessed_at: Option<i64> = sqlx::query_scalar(
            "SELECT last_accessed_at FROM sessions WHERE user_id = 'legacy@example.com'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(last_accessed_at, None, "failed v4 must roll back backfill");
        let ledger_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND name = 'service_migrations'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ledger_exists, 0, "failed startup must roll back the ledger");
        sqlx::query(
            "UPDATE sessions SET data = json_set(data, '$.last_accessed_at', 1700000000) \
             WHERE user_id = 'legacy@example.com'",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let backend = SqliteBackend::new_service(&db.url, test_master_key())
            .await
            .expect("retry after fixing legacy session JSON");
        assert_eq!(
            sqlite_ledger(backend.pool()).await,
            expected_migration_ledger()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT last_accessed_at FROM sessions WHERE user_id = 'legacy@example.com'",
            )
            .fetch_one(backend.pool())
            .await
            .unwrap(),
            1_700_000_000
        );
        backend.close().await;
    }

    #[tokio::test]
    async fn sqlite_service_migration_cancel_and_panic_roll_back() {
        let cancelled = TempSqliteDb::new("cancel");
        seed_legacy_sqlite(&cancelled).await;
        let hook = sqlite_migration_hook::install(1, cancelled.path.to_string_lossy().as_ref());
        let url = cancelled.url.clone();
        let task =
            tokio::spawn(async move { SqliteBackend::new_service(&url, test_master_key()).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), hook.reached.notified())
            .await
            .expect("cancel hook was not reached");
        task.abort();
        let join_error = match task.await {
            Err(error) => error,
            Ok(_) => panic!("cancelled migration task completed"),
        };
        assert!(join_error.is_cancelled());
        sqlite_migration_hook::clear();

        let pool = SqlitePool::connect(&cancelled.url).await.unwrap();
        assert_eq!(sqlite_kind_columns(&pool).await, 0);
        pool.close().await;
        let backend = SqliteBackend::new_service(&cancelled.url, test_master_key())
            .await
            .expect("retry after cancelled migration");
        backend.close().await;

        let panicked = TempSqliteDb::new("panic");
        seed_legacy_sqlite(&panicked).await;
        let hook = sqlite_migration_hook::install(2, panicked.path.to_string_lossy().as_ref());
        hook.panic_after_release.store(true, Ordering::SeqCst);
        let url = panicked.url.clone();
        let task =
            tokio::spawn(async move { SqliteBackend::new_service(&url, test_master_key()).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), hook.reached.notified())
            .await
            .expect("panic hook was not reached");
        hook.release.notify_one();
        let join_error = match task.await {
            Err(error) => error,
            Ok(_) => panic!("panicked migration task completed"),
        };
        assert!(join_error.is_panic());
        sqlite_migration_hook::clear();

        let pool = SqlitePool::connect(&panicked.url).await.unwrap();
        assert_eq!(sqlite_kind_columns(&pool).await, 0);
        let data: String =
            sqlx::query_scalar("SELECT data FROM identity_providers WHERE name = 'legacy-saml'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(data.contains("dead-entity"));
        pool.close().await;
        let backend = SqliteBackend::new_service(&panicked.url, test_master_key())
            .await
            .expect("retry after panicked migration");
        backend.close().await;

        let v7_cancelled = TempSqliteDb::new("api-key-scope-v7-cancel");
        let backend = SqliteBackend::new_service(&v7_cancelled.url, test_master_key())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO api_keys \
             (id, name, prefix, key_hash, scopes, created_at) \
             VALUES (?, 'legacy-admin', 'sks_lega', 'legacy-admin-hash', \
                     '[\"management:admin\"]', 1)",
        )
        .bind(Uuid::from_u128(0x701))
        .execute(backend.pool())
        .await
        .unwrap();
        backend.close().await;
        let pool = SqlitePool::connect(&v7_cancelled.url).await.unwrap();
        restore_api_keys_v6_shape(&pool).await;
        pool.close().await;

        let hook = sqlite_migration_hook::install(7, v7_cancelled.path.to_string_lossy().as_ref());
        let url = v7_cancelled.url.clone();
        let task =
            tokio::spawn(async move { SqliteBackend::new_service(&url, test_master_key()).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), hook.reached.notified())
            .await
            .expect("v7 cancel hook was not reached");
        task.abort();
        let join_error = match task.await {
            Err(error) => error,
            Ok(_) => panic!("cancelled v7 migration task completed"),
        };
        assert!(join_error.is_cancelled());
        sqlite_migration_hook::clear();

        let pool = SqlitePool::connect(&v7_cancelled.url).await.unwrap();
        assert_eq!(sqlite_api_key_scope_columns(&pool).await, 0);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM api_keys WHERE name = 'legacy-admin'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        pool.close().await;
        let backend = SqliteBackend::new_service(&v7_cancelled.url, test_master_key())
            .await
            .expect("retry v7 after cancellation");
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT scopes FROM api_keys WHERE name = 'legacy-admin'"
            )
            .fetch_one(backend.pool())
            .await
            .unwrap(),
            r#"["management:admin"]"#
        );
        backend.close().await;

        let v8_cancelled = TempSqliteDb::new("handoff-nonce-v8-cancel");
        let backend = SqliteBackend::new_service(&v8_cancelled.url, test_master_key())
            .await
            .unwrap();
        backend.close().await;
        let pool = SqlitePool::connect(&v8_cancelled.url).await.unwrap();
        sqlx::query("DROP TABLE used_handoff_nonces")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM service_migrations WHERE version = 8")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let hook = sqlite_migration_hook::install(8, v8_cancelled.path.to_string_lossy().as_ref());
        let url = v8_cancelled.url.clone();
        let task =
            tokio::spawn(async move { SqliteBackend::new_service(&url, test_master_key()).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), hook.reached.notified())
            .await
            .expect("v8 cancel hook was not reached");
        task.abort();
        let join_error = match task.await {
            Err(error) => error,
            Ok(_) => panic!("cancelled v8 migration task completed"),
        };
        assert!(join_error.is_cancelled());
        sqlite_migration_hook::clear();

        let pool = SqlitePool::connect(&v8_cancelled.url).await.unwrap();
        assert_eq!(sqlite_handoff_nonce_tables(&pool).await, 0);
        pool.close().await;
        let backend = SqliteBackend::new_service(&v8_cancelled.url, test_master_key())
            .await
            .expect("retry v8 after cancellation");
        assert_eq!(sqlite_handoff_nonce_tables(backend.pool()).await, 1);
        backend.close().await;
    }

    #[tokio::test]
    async fn sqlite_api_key_scope_v7_failure_rolls_back_then_retry() {
        let failed = TempSqliteDb::new("api-key-scope-v7-failure");
        let backend = SqliteBackend::new_service(&failed.url, test_master_key())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO api_keys \
             (id, name, prefix, key_hash, scopes, created_at) \
             VALUES (?, 'legacy-admin', 'sks_legb', 'legacy-admin-hash-2', \
                     '[\"management:admin\"]', 1)",
        )
        .bind(Uuid::from_u128(0x702))
        .execute(backend.pool())
        .await
        .unwrap();
        backend.close().await;
        let pool = SqlitePool::connect(&failed.url).await.unwrap();
        restore_api_keys_v6_shape(&pool).await;
        sqlx::query(
            "CREATE TRIGGER reject_v7_ledger BEFORE INSERT ON service_migrations \
             WHEN NEW.version = 7 BEGIN \
             SELECT RAISE(ABORT, 'injected v7 ledger failure'); END",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let error = match SqliteBackend::new_service(&failed.url, test_master_key()).await {
            Ok(_) => panic!("v7 SQLite failure was swallowed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("injected v7 ledger failure"));
        let pool = SqlitePool::connect(&failed.url).await.unwrap();
        assert_eq!(sqlite_api_key_scope_columns(&pool).await, 0);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM api_keys WHERE name = 'legacy-admin'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        sqlx::query("DROP TRIGGER reject_v7_ledger")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let backend = SqliteBackend::new_service(&failed.url, test_master_key())
            .await
            .expect("retry v7 after injected failure");
        assert_eq!(sqlite_api_key_scope_columns(backend.pool()).await, 1);
        backend.close().await;
    }

    #[tokio::test]
    async fn sqlite_handoff_nonce_v8_failure_rolls_back_then_retry() {
        let failed = TempSqliteDb::new("handoff-nonce-v8-failure");
        let backend = SqliteBackend::new_service(&failed.url, test_master_key())
            .await
            .unwrap();
        backend.close().await;
        let pool = SqlitePool::connect(&failed.url).await.unwrap();
        sqlx::query("DROP TABLE used_handoff_nonces")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM service_migrations WHERE version = 8")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_v8_ledger BEFORE INSERT ON service_migrations \
             WHEN NEW.version = 8 BEGIN \
             SELECT RAISE(ABORT, 'injected v8 ledger failure'); END",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let error = match SqliteBackend::new_service(&failed.url, test_master_key()).await {
            Ok(_) => panic!("v8 SQLite failure was swallowed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("injected v8 ledger failure"));
        let pool = SqlitePool::connect(&failed.url).await.unwrap();
        assert_eq!(sqlite_handoff_nonce_tables(&pool).await, 0);
        sqlx::query("DROP TRIGGER reject_v8_ledger")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let backend = SqliteBackend::new_service(&failed.url, test_master_key())
            .await
            .expect("retry v8 after injected failure");
        assert_eq!(sqlite_handoff_nonce_tables(backend.pool()).await, 1);
        backend.close().await;
    }

    #[tokio::test]
    async fn sqlite_parallel_service_migrations_apply_effect_once() {
        let db = TempSqliteDb::new("parallel");
        seed_legacy_sqlite(&db).await;
        let left_pool = migration_sqlite_pool(&db.url).await;
        let right_pool = migration_sqlite_pool(&db.url).await;
        let (left, right) = tokio::join!(
            SqliteBackend::from_pool_as_service(left_pool, test_master_key()),
            SqliteBackend::from_pool_as_service(right_pool, test_master_key())
        );
        let left = left.expect("left SQLite constructor");
        let right = right.expect("right SQLite constructor");
        assert_eq!(
            sqlite_ledger(left.pool()).await,
            expected_migration_ledger()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count FROM migration_effects")
                .fetch_one(right.pool())
                .await
                .unwrap(),
            1
        );
        left.close().await;
        right.close().await;
    }

    #[tokio::test]
    async fn sqlite_invalid_service_migration_ledgers_fail_closed() {
        async fn fresh_db(label: &str) -> (TempSqliteDb, SqlitePool) {
            let db = TempSqliteDb::new(label);
            let backend = SqliteBackend::new_service(&db.url, test_master_key())
                .await
                .unwrap();
            backend.close().await;
            let pool = SqlitePool::connect(&db.url).await.unwrap();
            (db, pool)
        }

        let (name_mismatch, pool) = fresh_db("name-mismatch").await;
        sqlx::query("UPDATE service_migrations SET name = 'wrong' WHERE version = 1")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let error = match SqliteBackend::new_service(&name_mismatch.url, test_master_key()).await {
            Ok(_) => panic!("name-mismatched migration ledger was accepted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("invalid service migration ledger entry")
        );

        let (unknown, pool) = fresh_db("unknown-version").await;
        sqlx::query(
            "INSERT INTO service_migrations (version, name) VALUES (9, 'unknown_migration')",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
        let error = match SqliteBackend::new_service(&unknown.url, test_master_key()).await {
            Ok(_) => panic!("unknown migration ledger version was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unknown version"));

        let (gap, pool) = fresh_db("gap").await;
        sqlx::query("DELETE FROM service_migrations WHERE version = 1")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let error = match SqliteBackend::new_service(&gap.url, test_master_key()).await {
            Ok(_) => panic!("gapped migration ledger was accepted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("invalid service migration ledger entry")
        );
    }
}

impl SqliteBackend {
    #[cfg(test)]
    pub(crate) fn shares_master_key(&self, expected: &Arc<MasterKey>) -> bool {
        Arc::ptr_eq(&self.master_key, expected)
    }

    /// Open a separate SQLite file as the operational (service) backend
    /// and run the service migrations against it. Used when
    /// `instance_config.cluster_db_url` points at a distinct SQLite
    /// path; the bootstrap file is untouched by operational DDL in that
    /// topology.
    pub async fn new_service(
        database_url: &str,
        master_key: Arc<MasterKey>,
    ) -> std::result::Result<Self, sqlx::Error> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        Self::from_pool_as_service(pool, master_key).await
    }

    /// Build a service backend around a pool that's already open, running
    /// the service migrations against it. Used in single-node mode where
    /// the bootstrap (instance) SQLite also serves as the service
    /// backend — `InstanceStore` opens the file, and this path reuses
    /// that pool rather than opening a second pool for the same file.
    /// The service migration sequence runs on the shared pool.
    ///
    /// When a remote service DB (Postgres, or a separate SQLite file) is
    /// configured, `Store::new` skips this path entirely so the
    /// bootstrap file never grows vestigial operational DDL.
    pub(crate) async fn from_pool_as_service(
        pool: SqlitePool,
        master_key: Arc<MasterKey>,
    ) -> std::result::Result<Self, sqlx::Error> {
        let backend = Self {
            pool: pool.clone(),
            route_version: DbVersion::new(pool.clone(), version::RESOURCE_ROUTES),
            idp_version: DbVersion::new(pool.clone(), version::RESOURCE_IDPS),
            config_version: DbVersion::new(pool.clone(), version::RESOURCE_CONFIG),
            cert_version: DbVersion::new(pool.clone(), version::RESOURCE_CERTS),
            key_ring_version: DbVersion::new(pool.clone(), version::RESOURCE_KEY_RING),
            identity_signing_version: DbVersion::new(
                pool.clone(),
                version::RESOURCE_IDENTITY_SIGNING_KEY_RING,
            ),
            master_key,
        };
        backend.run_migrations().await?;
        Ok(backend)
    }

    async fn run_migrations(&self) -> std::result::Result<(), sqlx::Error> {
        #[cfg(test)]
        let migration_identity: String =
            sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name = 'main'")
                .fetch_one(&self.pool)
                .await?;

        let statements = [
            r#"CREATE TABLE IF NOT EXISTS routes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
            r#"CREATE TABLE IF NOT EXISTS identity_providers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                idp_type TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
            r#"CREATE TABLE IF NOT EXISTS global_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
            r#"CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                idp_id TEXT NOT NULL,
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                last_accessed_at INTEGER
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",
            r#"CREATE TABLE IF NOT EXISTS certificates (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_certificates_expires_at ON certificates(expires_at)",
            r#"CREATE TABLE IF NOT EXISTS secrets (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
            r#"CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                scopes TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                last_used_at INTEGER
            )"#,
            r#"CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
            // DB-sourced cache-invalidation versions, one row per resource
            // kind. Writers bump inside the same tx as their mutation;
            // readers compare against their last-seen value.
            r#"CREATE TABLE IF NOT EXISTS schema_versions (
                resource TEXT PRIMARY KEY,
                version INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
            // ACME HTTP-01 challenges. The configured ACME server
            // supplies the token; the HTTP-01 handler uses it as the
            // lookup key, and it is the table's primary key. `domain`
            // supports per-domain cleanup.
            r#"CREATE TABLE IF NOT EXISTS acme_challenges (
                token TEXT PRIMARY KEY,
                key_auth TEXT NOT NULL,
                domain TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_acme_challenges_domain ON acme_challenges(domain)",
            // Singleton row recording which node currently owns ACME
            // issuance. `node_hash` is SHA-256(node_id)[..8] as hex so
            // peers can deterministically pick a winner without needing
            // to know each other by name. `updated_at` is the heartbeat
            // — if it falls behind by more than the configured stale
            // window a rival can take over, which is how we survive a
            // leader going dark without manual intervention.
            r#"CREATE TABLE IF NOT EXISTS acme_leader_election (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                node_id TEXT NOT NULL,
                node_hash TEXT NOT NULL,
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
            // PendingAuth is stored under the callback's CSRF lookup
            // key. OIDC fields `nonce` and `code_verifier` use empty-
            // string defaults for non-OIDC rows;
            // `saml_authn_request_id` is nullable.
            r#"CREATE TABLE IF NOT EXISTS pending_auth (
                csrf TEXT PRIMARY KEY,
                idp_id TEXT NOT NULL,
                nonce TEXT NOT NULL DEFAULT '',
                code_verifier TEXT NOT NULL DEFAULT '',
                saml_authn_request_id TEXT,
                redirect_url TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                kind TEXT NOT NULL DEFAULT 'login',
                browser_nonce_hash TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_pending_auth_expires_at ON pending_auth(expires_at)",
            // ACME issuance queue. Any node that receives `POST /certs`
            // inserts or reuses a row here and returns 202 — the
            // effective leader's background tick pulls pending rows,
            // runs issuance, and writes the result back. De-dup on
            // (domain, status in pending/in_progress) via a partial
            // unique index so a client retrying the same request
            // doesn't stack ACME orders for the same FQDN.
            r#"CREATE TABLE IF NOT EXISTS acme_queue (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                requester_node TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                result_cert_id TEXT,
                error_msg TEXT,
                enqueued_at INTEGER NOT NULL DEFAULT (unixepoch()),
                picked_at INTEGER,
                completed_at INTEGER
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_acme_queue_status ON acme_queue(status, enqueued_at)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_acme_queue_domain_active \
             ON acme_queue(domain) WHERE status IN ('pending', 'in_progress')",
            // DEK ring. Each row carries one Data Encryption Key, itself
            // KEK-encrypted (v2 blob, base64) so the row at rest is
            // unusable without the KEK. At most one row may have
            // `active = 1 AND retired = 0` at any time — the partial
            // unique index enforces it.
            //
            // Production allocation uses key IDs in 0..=255 because the
            // v3 blob header carries one byte. This INTEGER schema does
            // not enforce that range.
            r#"CREATE TABLE IF NOT EXISTS master_keys (
                key_id INTEGER PRIMARY KEY,
                key_encrypted TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 0,
                retired INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                retired_at INTEGER
            )"#,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_master_keys_one_active \
             ON master_keys(active) WHERE active = 1 AND retired = 0",
        ];

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        for stmt in statements {
            sqlx::query(stmt).execute(&mut *tx).await?;
        }

        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS service_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at INTEGER NOT NULL DEFAULT (unixepoch())
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
                    let kind_columns: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM pragma_table_info('pending_auth') \
                         WHERE name = 'kind'",
                    )
                    .fetch_one(&mut *tx)
                    .await?;
                    if kind_columns == 0 {
                        sqlx::query(
                            "ALTER TABLE pending_auth \
                             ADD COLUMN kind TEXT NOT NULL DEFAULT 'login'",
                        )
                        .execute(&mut *tx)
                        .await?;
                    }
                }
                2 => {
                    sqlx::query(
                        "UPDATE identity_providers \
                         SET data = json_remove(\
                             data, \
                             '$.saml_config.entity_id', \
                             '$.saml_config.acs_url'\
                         ) \
                         WHERE idp_type = '\"saml\"'",
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                3 => {
                    let columns: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM pragma_table_info('pending_auth') \
                         WHERE name = 'browser_nonce_hash'",
                    )
                    .fetch_one(&mut *tx)
                    .await?;
                    if columns == 0 {
                        sqlx::query(
                            "ALTER TABLE pending_auth \
                             ADD COLUMN browser_nonce_hash TEXT",
                        )
                        .execute(&mut *tx)
                        .await?;
                    }
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
                            "UPDATE sessions SET last_accessed_at = ? \
                             WHERE id = ? AND last_accessed_at IS NULL",
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
                         private_key_encrypted TEXT, public_jwk TEXT NOT NULL, retire_until INTEGER, \
                         created_at INTEGER NOT NULL DEFAULT (unixepoch()), \
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
                    let columns: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM pragma_table_info('api_keys') \
                         WHERE name = 'scopes'",
                    )
                    .fetch_one(&mut *tx)
                    .await?;
                    if columns == 0 {
                        sqlx::query(
                            "CREATE TABLE api_keys_v7 (\
                             id TEXT PRIMARY KEY, name TEXT NOT NULL, prefix TEXT NOT NULL, \
                             key_hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL, \
                             created_at INTEGER NOT NULL DEFAULT (unixepoch()), \
                             last_used_at INTEGER)",
                        )
                        .execute(&mut *tx)
                        .await?;
                        sqlx::query(
                            "INSERT INTO api_keys_v7 \
                             (id, name, prefix, key_hash, scopes, created_at, last_used_at) \
                             SELECT id, name, prefix, key_hash, '[\"management:admin\"]', \
                                    created_at, last_used_at FROM api_keys",
                        )
                        .execute(&mut *tx)
                        .await?;
                        sqlx::query("DROP TABLE api_keys").execute(&mut *tx).await?;
                        sqlx::query("ALTER TABLE api_keys_v7 RENAME TO api_keys")
                            .execute(&mut *tx)
                            .await?;
                    }
                }
                8 => {
                    sqlx::query(
                        "CREATE TABLE IF NOT EXISTS used_handoff_nonces (\
                         nonce TEXT PRIMARY KEY, \
                         consumed_at INTEGER NOT NULL DEFAULT (unixepoch()))",
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

            sqlx::query("INSERT INTO service_migrations (version, name) VALUES (?, ?)")
                .bind(migration.version)
                .bind(migration.name)
                .execute(&mut *tx)
                .await?;
        }

        // Seed one row per tracked resource. INSERT OR IGNORE so repeated
        // migrations on an existing DB are a no-op.
        for resource in version::ALL_RESOURCES {
            sqlx::query("INSERT OR IGNORE INTO schema_versions (resource, version) VALUES (?, 0)")
                .bind(*resource)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;

        Ok(())
    }

    /// Test-only pool access so the version-invalidation test can
    /// simulate a peer-node write. Production code goes through the
    /// facade `Store`, which doesn't expose this.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Pool accessor used exclusively by `store::dek_rotation`. The
    /// rotation routine sweeps every encrypted column with raw SQL so
    /// adding a new at-rest field doesn't need a per-column trait
    /// method; the trade-off is one narrowly-scoped escape hatch out
    /// of the backend abstraction.
    pub(crate) fn pool_for_rotation(&self) -> &SqlitePool {
        &self.pool
    }

    #[cfg(test)]
    pub(crate) fn config_version_handle(&self) -> &DbVersion {
        &self.config_version
    }

    /// Close the underlying pool. `SqlitePool::close` is idempotent.
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

    fn normalize_identity(identity: &str) -> String {
        std::path::Path::new(identity)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(identity)
            .to_owned()
    }

    pub(in crate::store) fn install(version: i64, migration_identity: &str) -> Arc<Hook> {
        let hook = Arc::new(Hook {
            version,
            migration_identity: normalize_identity(migration_identity),
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
            hook.version == version
                && hook.migration_identity == normalize_identity(migration_identity)
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

pub(super) async fn begin_immediate(pool: &SqlitePool) -> Result<Transaction<'static, Sqlite>> {
    pool.begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(Error::Database)
}

pub(super) async fn finish_immediate<T>(
    tx: Transaction<'static, Sqlite>,
    result: Result<T>,
) -> Result<T> {
    match result {
        Ok(value) => {
            tx.commit().await.map_err(Error::Database)?;
            Ok(value)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

#[cfg(test)]
mod first_dek_test_hook {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex, OnceLock},
    };
    use tokio::sync::Notify;

    pub(super) struct Hook {
        pub(super) inserted: Notify,
        pub(super) release: Notify,
    }

    fn hooks() -> &'static Mutex<HashMap<String, Arc<Hook>>> {
        static HOOKS: OnceLock<Mutex<HashMap<String, Arc<Hook>>>> = OnceLock::new();
        HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(super) fn install(blob: &str) -> Arc<Hook> {
        let hook = Arc::new(Hook {
            inserted: Notify::new(),
            release: Notify::new(),
        });
        hooks()
            .lock()
            .expect("first-DEK hook lock must not be poisoned")
            .insert(blob.to_owned(), hook.clone());
        hook
    }

    pub(super) fn get(blob: &str) -> Option<Arc<Hook>> {
        hooks()
            .lock()
            .expect("first-DEK hook lock must not be poisoned")
            .get(blob)
            .cloned()
    }

    pub(super) fn remove(blob: &str) {
        hooks()
            .lock()
            .expect("first-DEK hook lock must not be poisoned")
            .remove(blob);
    }
}

#[cfg(test)]
mod dek_allocation_test_hook {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex, OnceLock},
    };
    use tokio::sync::Notify;

    pub(super) struct Hook {
        pub(super) inserted: Notify,
        pub(super) release: Notify,
    }

    fn hooks() -> &'static Mutex<HashMap<String, Arc<Hook>>> {
        static HOOKS: OnceLock<Mutex<HashMap<String, Arc<Hook>>>> = OnceLock::new();
        HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(super) fn install(blob: &str) -> Arc<Hook> {
        let hook = Arc::new(Hook {
            inserted: Notify::new(),
            release: Notify::new(),
        });
        hooks()
            .lock()
            .expect("DEK allocation hook lock must not be poisoned")
            .insert(blob.to_owned(), hook.clone());
        hook
    }

    pub(super) fn get(blob: &str) -> Option<Arc<Hook>> {
        hooks()
            .lock()
            .expect("DEK allocation hook lock must not be poisoned")
            .get(blob)
            .cloned()
    }

    pub(super) fn remove(blob: &str) {
        hooks()
            .lock()
            .expect("DEK allocation hook lock must not be poisoned")
            .remove(blob);
    }
}

impl StorageBackend for SqliteBackend {
    // ───── Routes ─────
    async fn observe_routes(&self) -> Result<crate::store::route::RouteObservation> {
        let rows = sqlx::query_as::<_, (i64, Option<String>)>(
            "SELECT sv.version, r.data FROM schema_versions sv \
             LEFT JOIN routes r ON TRUE WHERE sv.resource = ? ORDER BY r.name",
        )
        .bind(version::RESOURCE_ROUTES)
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
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<()> = async {
            crate::identity::validate_route(route.signed_identity_input())
                .map_err(|_| Error::BadRequest(crate::identity::INVALID_SIGNED_ROUTE.into()))?;
            crate::validation::validate_route_policy(&route.access)?;
            crud::insert_named_exec(&mut *tx, Table::Routes, route.id, route, &[]).await?;
            // Same tx so a writer crash between INSERT and bump is
            // impossible: commit is atomic, and a peer never sees the
            // new row at the old version.
            self.route_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finish_immediate(tx, result).await
    }

    async fn update_route(&self, id: Uuid, update: serde_json::Value) -> Result<Route> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<Route> = async {
            let current = crud::fetch_json_tx(&mut *tx, Table::Routes, id).await?;
            let merged: Route = crud::apply_merge(&current, &update, Table::Routes.kind())?;
            crate::identity::validate_route(merged.signed_identity_input())
                .map_err(|_| Error::BadRequest(crate::identity::INVALID_SIGNED_ROUTE.into()))?;
            crate::validation::validate_route_policy(&merged.access)?;
            let serialized = crud::to_json_string(&merged)?;
            sqlx::query(
                "UPDATE routes SET name = ?, data = ?, updated_at = unixepoch() WHERE id = ?",
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
        finish_immediate(tx, result).await
    }

    async fn delete_route(&self, id: Uuid) -> Result<()> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<()> = async {
            crud::delete_by_id_exec(&mut *tx, Table::Routes, id).await?;
            self.route_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finish_immediate(tx, result).await
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
        // `idp_type` is a dedicated column rather than part of the
        // `data` JSON so list views and cache invalidation can filter
        // on it cheaply.
        let type_trim = idp_type.trim_matches('"');
        let mut tx = begin_immediate(&self.pool).await?;
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
        finish_immediate(tx, result).await
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
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<()> = async {
            crud::delete_by_id_exec(&mut *tx, Table::IdentityProviders, id).await?;
            self.idp_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finish_immediate(tx, result).await
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
        let s = sqlx::query_scalar::<_, String>("SELECT data FROM policies WHERE name = ?")
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
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<Policy> = async {
            let current = crud::fetch_json_tx(&mut *tx, Table::Policies, id).await?;
            let merged: Policy = crud::apply_merge(&current, &update, Table::Policies.kind())?;
            crate::validation::validate_policy_expression(&merged.expr)?;
            let serialized = crud::to_json_string(&merged)?;
            sqlx::query(
                "UPDATE policies SET name = ?, data = ?, updated_at = unixepoch() WHERE id = ?",
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
        finish_immediate(tx, result).await
    }

    async fn delete_policy(&self, id: Uuid) -> Result<()> {
        crud::delete_by_id(&self.pool, Table::Policies, id).await
    }

    // ───── Config ─────
    async fn load_config(&self) -> Result<GlobalConfig> {
        let json_str =
            sqlx::query_scalar::<_, String>("SELECT data FROM global_config WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?;
        match json_str {
            Some(json_str) => serde_json::from_str(&json_str)
                .map_err(|e| Error::Internal(format!("corrupt config data: {e}"))),
            None => Ok(GlobalConfig::default()),
        }
    }

    async fn update_config(&self, update: serde_json::Value) -> Result<GlobalConfig> {
        let mut tx = begin_immediate(&self.pool).await?;

        let result: Result<GlobalConfig> = async {
            let json_str =
                sqlx::query_scalar::<_, String>("SELECT data FROM global_config WHERE id = 1")
                    .fetch_optional(&mut *tx)
                    .await?;

            let mut base = match json_str {
                Some(json_str) => serde_json::from_str(&json_str)
                    .map_err(|e| Error::Internal(format!("corrupt config data: {e}")))?,
                None => serde_json::to_value(GlobalConfig::default())
                    .map_err(|e| Error::Internal(format!("serialize default config: {e}")))?,
            };

            crate::store::merge::json_merge(&mut base, &update);

            let config: GlobalConfig = serde_json::from_value(base)
                .map_err(|e| Error::Internal(format!("invalid config after merge: {e}")))?;

            let serialized = serde_json::to_string(&config)
                .map_err(|e| Error::Internal(format!("serialize error: {e}")))?;

            sqlx::query(
                r#"
                INSERT INTO global_config (id, data) VALUES (1, ?)
                ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = unixepoch()
                "#,
            )
            .bind(&serialized)
            .execute(&mut *tx)
            .await?;

            // Bump the version in the same tx so peers see the change.
            self.config_version.bump(&mut *tx).await?;

            Ok(config)
        }
        .await;

        finish_immediate(tx, result).await
    }

    // ───── Sessions ─────
    async fn create_session(&self, session: &Session) -> Result<()> {
        let serialized = serde_json::to_string(session)
            .map_err(|e| Error::Internal(format!("serialize error: {e}")))?;

        sqlx::query(
            "INSERT INTO sessions \
             (id, user_id, idp_id, data, expires_at, last_accessed_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
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
             WHERE id = ? AND expires_at > unixepoch() \
             AND last_accessed_at > unixepoch() - ?",
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
                 last_accessed_at <= unixepoch() - ? AS touch_due \
                 FROM sessions WHERE id = ? AND expires_at > unixepoch() \
                 AND last_accessed_at > unixepoch() - ?",
            )
            .bind(SESSION_TOUCH_INTERVAL_SECS)
            .bind(id)
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
            "UPDATE sessions SET last_accessed_at = unixepoch() \
             WHERE id = ? AND last_accessed_at = ? \
             AND expires_at > unixepoch() \
             AND last_accessed_at > unixepoch() - ? \
             AND last_accessed_at <= unixepoch() - ? \
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
             WHERE id = ? AND expires_at > unixepoch() \
             AND last_accessed_at > unixepoch() - ?",
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
        let rows = match user_filter {
            Some(user) => {
                sqlx::query_as::<_, (String, i64, i64)>(
                    "SELECT data, expires_at, last_accessed_at FROM sessions WHERE user_id = ? ORDER BY created_at DESC, id ASC LIMIT ? OFFSET ?",
                )
                .bind(user)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, (String, i64, i64)>(
                    "SELECT data, expires_at, last_accessed_at FROM sessions ORDER BY created_at DESC, id ASC LIMIT ? OFFSET ?",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
        };

        rows.into_iter()
            .map(|(data, expires_at, last_accessed_at)| {
                decode_session_row(data, expires_at, last_accessed_at)
            })
            .collect()
    }

    async fn delete_session(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM sessions WHERE id = ?")
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
            "DELETE FROM sessions WHERE expires_at <= unixepoch() \
             OR last_accessed_at <= unixepoch() - ?",
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
            "SELECT data FROM certificates ORDER BY domain LIMIT ? OFFSET ?",
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
            sqlx::query_scalar::<_, String>("SELECT data FROM certificates WHERE id = ?")
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

        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<()> = async {
            sqlx::query(
                r#"
                INSERT INTO certificates (id, domain, data, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    id = excluded.id,
                    data = excluded.data,
                    expires_at = excluded.expires_at,
                    updated_at = unixepoch()
                "#,
            )
            .bind(cert.id)
            .bind(&cert.domain)
            .bind(&serialized)
            .bind(to_epoch(cert.expires_at))
            .execute(&mut *tx)
            .await?;
            // Same tx as the mutation so peers never see the new cert
            // at the old version. Drives HA cert-cache invalidation.
            self.cert_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finish_immediate(tx, result).await
    }

    async fn delete_cert(&self, id: Uuid) -> Result<()> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<()> = async {
            let r = sqlx::query("DELETE FROM certificates WHERE id = ?")
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
        finish_immediate(tx, result).await
    }

    async fn get_expiring_certs(&self, days_before: i64) -> Result<Vec<Certificate>> {
        let cutoff = chrono::Utc::now() + chrono::Duration::days(days_before);
        let rows =
            sqlx::query_scalar::<_, String>("SELECT data FROM certificates WHERE expires_at < ?")
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
             VALUES (?, ?, ?, ?, ?, ?)",
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
             FROM api_keys WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::NotFound)?
        .into_model()
    }

    async fn lookup_api_key(&self, raw_key: &str) -> Result<ApiKey> {
        // `raw_key.get(..8)` supplies the lookup prefix when that byte
        // range is a valid string slice; otherwise the whole input is
        // used. Each fetched candidate's full stored HMAC is then
        // verified.
        use super::api_key_hash::{self, VerifyOutcome};

        let prefix = raw_key.get(..8).unwrap_or(raw_key);
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            "SELECT id, name, prefix, key_hash, scopes, created_at, last_used_at \
             FROM api_keys WHERE prefix = ?",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await?;

        // Visit every fetched candidate and invoke the verifier. Record
        // the first HMAC match without breaking out of the loop; the
        // candidate count and surrounding work still affect observable
        // request timing.
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
        let result = sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(to_epoch(Utc::now()))
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
             FROM api_keys ORDER BY created_at ASC, id ASC LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(ApiKeyRow::into_model).collect()
    }

    async fn delete_api_key(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = ?")
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
        let value = sqlx::query_scalar::<_, String>("SELECT value FROM secrets WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(value)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO secrets (key, value) VALUES (?, ?)
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
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<SecretInsertOutcome> = async {
            let inserted = sqlx::query(
                "INSERT INTO secrets (key, value) VALUES (?, ?) \
                 ON CONFLICT(key) DO NOTHING",
            )
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await?
            .rows_affected()
                == 1;
            let durable =
                sqlx::query_scalar::<_, String>("SELECT value FROM secrets WHERE key = ?")
                    .bind(key)
                    .fetch_one(&mut *tx)
                    .await?;
            Ok(SecretInsertOutcome {
                inserted,
                value: durable,
            })
        }
        .await;
        finish_immediate(tx, result).await
    }

    // ───── ACME challenges ─────
    async fn set_acme_challenge(&self, token: &str, key_auth: &str, domain: &str) -> Result<()> {
        // ON CONFLICT(token) DO UPDATE replaces the binding and refreshes
        // created_at when the token row already exists.
        sqlx::query(
            r#"
            INSERT INTO acme_challenges (token, key_auth, domain)
            VALUES (?, ?, ?)
            ON CONFLICT(token) DO UPDATE SET
                key_auth = excluded.key_auth,
                domain = excluded.domain,
                created_at = unixepoch()
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
        let value =
            sqlx::query_scalar::<_, String>("SELECT key_auth FROM acme_challenges WHERE token = ?")
                .bind(token)
                .fetch_optional(&self.pool)
                .await?;
        Ok(value)
    }

    async fn delete_acme_challenges_for_domain(&self, domain: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM acme_challenges WHERE domain = ?")
            .bind(domain)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    // ───── ACME leader election ─────
    async fn acme_election_read(&self) -> Result<Option<AcmeElectionRow>> {
        let row = sqlx::query_as::<_, AcmeElectionRowDb>(
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
        let mut tx = begin_immediate(&self.pool).await?;
        // The immediate transaction grabs the write lock up front so a peer on
        // another connection can't slip a mutation in between our read
        // and our write. Same framing the config updater uses.

        let result: Result<AcmeElectionOutcome> = async {
            let now = Utc::now();
            let existing = sqlx::query_as::<_, AcmeElectionRowDb>(
                "SELECT node_id, node_hash, updated_at \
                 FROM acme_leader_election WHERE id = 1",
            )
            .fetch_optional(&mut *tx)
            .await?;

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
                ElectionAction::Initial => {
                    sqlx::query(
                        "INSERT INTO acme_leader_election (id, node_id, node_hash, updated_at) \
                         VALUES (1, ?, ?, ?)",
                    )
                    .bind(my_node_id)
                    .bind(my_node_hash)
                    .bind(now_epoch)
                    .execute(&mut *tx)
                    .await?;
                }
                ElectionAction::Takeover | ElectionAction::Preempt | ElectionAction::Refresh => {
                    sqlx::query(
                        "UPDATE acme_leader_election \
                         SET node_id = ?, node_hash = ?, updated_at = ? \
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

        finish_immediate(tx, result).await
    }

    // ───── ACME issuance queue ─────
    async fn acme_queue_enqueue(
        &self,
        domain: &str,
        requester_node: &str,
    ) -> Result<AcmeQueueAdmission> {
        let mut tx = begin_immediate(&self.pool).await?;
        // The immediate transaction keeps the "maybe an active row exists, maybe
        // we need to insert" decision atomic against a second caller
        // racing the same domain.

        let result: Result<AcmeQueueAdmission> = async {
            let config_json =
                sqlx::query_scalar::<_, String>("SELECT data FROM global_config WHERE id = 1")
                    .fetch_optional(&mut *tx)
                    .await?;
            let config = match config_json {
                Some(json) => serde_json::from_str::<GlobalConfig>(&json)
                    .map_err(|e| Error::Internal(format!("corrupt config data: {e}")))?,
                None => GlobalConfig::default(),
            };

            // De-dup: if a pending / in_progress row already exists for
            // this domain, return it instead of inserting a second one.
            // The partial unique index permits at most one such row;
            // this read-first path returns that row without attempting
            // another insert.
            if let Some(existing) = sqlx::query_as::<_, AcmeQueueRowDb>(
                "SELECT id, domain, requester_node, status, result_cert_id, \
                        error_msg, enqueued_at, picked_at, completed_at \
                 FROM acme_queue \
                 WHERE domain = ? AND status IN ('pending', 'in_progress') \
                 LIMIT 1",
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
            sqlx::query(
                "INSERT INTO acme_queue \
                 (id, domain, requester_node, status, enqueued_at) \
                 VALUES (?, ?, ?, 'pending', ?)",
            )
            .bind(id)
            .bind(domain)
            .bind(requester_node)
            .bind(to_epoch(now))
            .execute(&mut *tx)
            .await?;

            Ok(AcmeQueueAdmission::Inserted(AcmeQueueRow {
                id,
                domain: domain.to_string(),
                requester_node: requester_node.to_string(),
                status: crate::models::acme_queue::AcmeQueueStatus::Pending,
                result_cert_id: None,
                error_msg: None,
                enqueued_at: now,
                picked_at: None,
                completed_at: None,
            }))
        }
        .await;

        finish_immediate(tx, result).await
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
                      AND (picked_at IS NULL OR picked_at >= ?)), \
                   (SELECT data FROM global_config WHERE id = 1)",
            )
            .bind(to_epoch(stale_before))
            .fetch_one(&self.pool)
            .await?;
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
        let row = sqlx::query_as::<_, AcmeQueueRowDb>(
            "SELECT id, domain, requester_node, status, result_cert_id, \
                    error_msg, enqueued_at, picked_at, completed_at \
             FROM acme_queue WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(AcmeQueueRowDb::into_model).transpose()
    }

    async fn acme_queue_pick_next(
        &self,
        stale_after: chrono::Duration,
        concurrency_limit: u32,
    ) -> Result<Option<AcmeQueueRow>> {
        let mut tx = begin_immediate(&self.pool).await?;

        let result: Result<Option<AcmeQueueRow>> = async {
            let now = Utc::now();
            let stale_before = now - stale_after;

            // Reset every `in_progress` row whose `picked_at` precedes
            // the stale threshold. Age alone does not establish whether
            // its order task stopped, so a still-running order can be
            // made pending again.
            sqlx::query(
                "UPDATE acme_queue SET status = 'pending', picked_at = NULL \
                 WHERE status = 'in_progress' AND picked_at IS NOT NULL \
                       AND picked_at < ?",
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

            let candidate = sqlx::query_as::<_, AcmeQueueRowDb>(
                "SELECT id, domain, requester_node, status, result_cert_id, \
                        error_msg, enqueued_at, picked_at, completed_at \
                 FROM acme_queue \
                 WHERE status = 'pending' \
                 ORDER BY enqueued_at ASC LIMIT 1",
            )
            .fetch_optional(&mut *tx)
            .await?;

            let Some(row) = candidate else {
                return Ok(None);
            };

            sqlx::query(
                "UPDATE acme_queue \
                 SET status = 'in_progress', picked_at = ? \
                 WHERE id = ? AND status = 'pending'",
            )
            .bind(to_epoch(now))
            .bind(row.id)
            .execute(&mut *tx)
            .await?;

            let mut model = row.into_model()?;
            model.status = crate::models::acme_queue::AcmeQueueStatus::InProgress;
            model.picked_at = Some(now);
            Ok(Some(model))
        }
        .await;

        finish_immediate(tx, result).await
    }

    async fn acme_queue_mark_completed(&self, id: Uuid, result_cert_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let r = sqlx::query(
            "UPDATE acme_queue \
             SET status = 'completed', result_cert_id = ?, completed_at = ? \
             WHERE id = ?",
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
             SET status = 'failed', error_msg = ?, completed_at = ? \
             WHERE id = ?",
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
        let rows: Vec<(i64, String, i64, i64)> = sqlx::query_as(
            "SELECT key_id, key_encrypted, active, retired \
             FROM master_keys WHERE retired = 0 ORDER BY key_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Error::Database)?;
        Ok(rows
            .into_iter()
            .map(|(id, blob, active, retired)| MasterKeyRow {
                key_id: id as i16,
                key_encrypted: blob,
                active: active != 0,
                retired: retired != 0,
            })
            .collect())
    }

    #[cfg(test)]
    async fn master_keys_insert_first_active_if_empty(
        &self,
        key_encrypted: &str,
    ) -> Result<FirstDekInsertOutcome> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<FirstDekInsertOutcome> = async {
            let inserted = sqlx::query(
                "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
                 SELECT 0, ?, 1, 0 \
                 WHERE NOT EXISTS (SELECT 1 FROM master_keys)",
            )
            .bind(key_encrypted)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?
            .rows_affected();
            if inserted == 0 {
                return Ok(FirstDekInsertOutcome::AlreadyInitialized);
            }
            #[cfg(test)]
            if let Some(hook) = first_dek_test_hook::get(key_encrypted) {
                hook.inserted.notify_one();
                hook.release.notified().await;
            }
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(FirstDekInsertOutcome::Inserted)
        }
        .await;
        finish_immediate(tx, result).await
    }

    async fn master_keys_insert_first_active_plaintext(
        &self,
        key_plaintext: &[u8],
        master_key: &crate::crypto::MasterKey,
    ) -> Result<FirstDekInsertOutcome> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<FirstDekInsertOutcome> = async {
            let _: i64 =
                sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = ?")
                    .bind(version::RESOURCE_IDENTITY_SIGNING_KEY_RING)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
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
                 VALUES (0, ?, 1, 0)",
            )
            .bind(key_encrypted)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(FirstDekInsertOutcome::Inserted)
        }
        .await;
        finish_immediate(tx, result).await
    }

    #[cfg(test)]
    async fn master_keys_insert(&self, key_id: i16, key_encrypted: &str) -> Result<()> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<()> = async {
            sqlx::query(
                "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
                 VALUES (?, ?, 0, 0)",
            )
            .bind(key_id as i64)
            .bind(key_encrypted)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finish_immediate(tx, result).await
    }

    #[cfg(test)]
    async fn master_keys_allocate_inactive(&self, key_encrypted: &str) -> Result<i16> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<i16> = async {
            let used: Vec<(i64,)> =
                sqlx::query_as("SELECT key_id FROM master_keys ORDER BY key_id")
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            let used: std::collections::HashSet<i64> =
                used.into_iter().map(|(key_id,)| key_id).collect();
            let key_id = (0i64..=255)
                .find(|candidate| !used.contains(candidate))
                .ok_or(Error::KeyRingFull)?;

            sqlx::query(
                "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
                 VALUES (?, ?, 0, 0)",
            )
            .bind(key_id)
            .bind(key_encrypted)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            #[cfg(test)]
            if let Some(hook) = dek_allocation_test_hook::get(key_encrypted) {
                hook.inserted.notify_one();
                hook.release.notified().await;
            }
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(key_id as i16)
        }
        .await;
        finish_immediate(tx, result).await
    }

    async fn master_keys_allocate_inactive_plaintext(
        &self,
        key_plaintext: &[u8],
        master_key: &crate::crypto::MasterKey,
    ) -> Result<i16> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<i16> = async {
            let _: i64 =
                sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = ?")
                    .bind(version::RESOURCE_IDENTITY_SIGNING_KEY_RING)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            let used: Vec<(i64,)> =
                sqlx::query_as("SELECT key_id FROM master_keys ORDER BY key_id")
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            let used: std::collections::HashSet<i64> =
                used.into_iter().map(|(key_id,)| key_id).collect();
            let key_id = (0i64..=255)
                .find(|candidate| !used.contains(candidate))
                .ok_or(Error::KeyRingFull)?;
            let key_encrypted = master_key
                .encrypt_to_base64(key_plaintext)
                .map_err(|error| Error::Internal(format!("KEK-encrypt new DEK: {error}")))?;
            sqlx::query(
                "INSERT INTO master_keys (key_id, key_encrypted, active, retired) \
                 VALUES (?, ?, 0, 0)",
            )
            .bind(key_id)
            .bind(key_encrypted)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(key_id as i16)
        }
        .await;
        finish_immediate(tx, result).await
    }

    async fn master_keys_activate(&self, key_id: i16) -> Result<()> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<()> = async {
            // Validate the target before the demote and promote steps;
            // all three operations run in this immediate transaction.
            let row: Option<(i64,)> =
                sqlx::query_as("SELECT retired FROM master_keys WHERE key_id = ?")
                    .bind(key_id as i64)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            match row {
                None => return Err(Error::NotFound),
                Some((retired,)) if retired != 0 => {
                    return Err(Error::ConfigurationError(format!(
                        "cannot activate retired key_id {key_id}"
                    )));
                }
                _ => {}
            }
            // Demote before promoting the target. The partial unique
            // index permits at most one active, non-retired row, and
            // this order avoids promoting while another row is active.
            sqlx::query("UPDATE master_keys SET active = 0 WHERE active = 1 AND retired = 0")
                .execute(&mut *tx)
                .await
                .map_err(Error::Database)?;
            sqlx::query("UPDATE master_keys SET active = 1 WHERE key_id = ?")
                .bind(key_id as i64)
                .execute(&mut *tx)
                .await
                .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finish_immediate(tx, result).await
    }

    async fn master_keys_retire(&self, key_id: i16) -> Result<()> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<()> = async {
            // Active key must be rotated away from before retirement —
            // refuse here so the daemon never lands in a state where the
            // active key is also retired.
            let row: Option<(i64, i64)> =
                sqlx::query_as("SELECT active, retired FROM master_keys WHERE key_id = ?")
                    .bind(key_id as i64)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            match row {
                None => return Err(Error::NotFound),
                Some((_, retired)) if retired != 0 => return Ok(()), // idempotent
                Some((active, _)) if active != 0 => {
                    return Err(Error::ConfigurationError(format!(
                        "refusing to retire active key_id {key_id}; \
                         activate another key first"
                    )));
                }
                _ => {}
            }
            sqlx::query(
                "UPDATE master_keys SET retired = 1, retired_at = unixepoch() \
                 WHERE key_id = ?",
            )
            .bind(key_id as i64)
            .execute(&mut *tx)
            .await
            .map_err(Error::Database)?;
            self.key_ring_version.bump(&mut *tx).await?;
            Ok(())
        }
        .await;
        finish_immediate(tx, result).await
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
            sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = ?")
                .bind(version::RESOURCE_IDENTITY_SIGNING_KEY_RING)
                .fetch_one(&mut *tx)
                .await
                .map_err(Error::Database)?;
        let ring_version: i64 =
            sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = ?")
                .bind(version::RESOURCE_KEY_RING)
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
        let master_rows = sqlx::query_as::<_, (i16, String, i64, i64)>(
            "SELECT key_id, key_encrypted, active, retired FROM master_keys \
             WHERE retired = 0 ORDER BY key_id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(Error::Database)?
        .into_iter()
        .map(
            |(key_id, key_encrypted, active, retired)| super::MasterKeyRow {
                key_id,
                key_encrypted,
                active: active != 0,
                retired: retired != 0,
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
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<super::IdentitySigningBootstrapOutcome> = async {
            let _: i64 = sqlx::query_scalar(
                "SELECT version FROM schema_versions WHERE resource = ?",
            )
            .bind(version::RESOURCE_IDENTITY_SIGNING_KEY_RING)
            .fetch_one(&mut *tx)
            .await
            .map_err(Error::Database)?;
            let _: i64 = sqlx::query_scalar(
                "SELECT version FROM schema_versions WHERE resource = ?",
            )
            .bind(version::RESOURCE_KEY_RING)
            .fetch_one(&mut *tx)
            .await
            .map_err(Error::Database)?;
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
            let ring_version: i64 = sqlx::query_scalar(
                "SELECT version FROM schema_versions WHERE resource = ?",
            )
            .bind(version::RESOURCE_KEY_RING)
            .fetch_one(&mut *tx)
            .await
            .map_err(Error::Database)?;
            let master_rows = sqlx::query_as::<_, (i64, String, i64, i64)>(
                "SELECT key_id, key_encrypted, active, retired FROM master_keys WHERE retired = 0 ORDER BY key_id",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(Error::Database)?
            .into_iter()
            .map(|(key_id, key_encrypted, active, retired)| super::MasterKeyRow {
                key_id: key_id as i16,
                key_encrypted,
                active: active != 0,
                retired: retired != 0,
            })
            .collect();
            let ring = super::build_master_key_ring(&self.master_key, master_rows, ring_version as u64)?;
            let encrypted = ring.encrypt_active_to_base64(private_pkcs8)?;
            sqlx::query(
                "INSERT INTO identity_signing_keys \
                 (kid, state, private_key_encrypted, public_jwk, retire_until) \
                 VALUES (?, 'current', ?, ?, NULL)",
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
        finish_immediate(tx, result).await
    }

    async fn identity_signing_rotate(
        &self,
        kid: &str,
        private_pkcs8: &[u8],
        public_jwk: &str,
        grace_secs: i64,
    ) -> Result<super::IdentitySigningRotateOutcome> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<super::IdentitySigningRotateOutcome> = async {
            let _: i64 = sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = ?")
                .bind(version::RESOURCE_IDENTITY_SIGNING_KEY_RING)
                .fetch_one(&mut *tx).await.map_err(Error::Database)?;
            let _: i64 = sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = ?")
                .bind(version::RESOURCE_KEY_RING)
                .fetch_one(&mut *tx).await.map_err(Error::Database)?;
            let now: i64 = sqlx::query_scalar("SELECT unixepoch()")
                .fetch_one(&mut *tx).await.map_err(Error::Database)?;
            let retiring_until: Option<i64> = sqlx::query_scalar(
                "SELECT retire_until FROM identity_signing_keys WHERE state = 'retiring'",
            )
            .fetch_optional(&mut *tx).await.map_err(Error::Database)?.flatten();
            if retiring_until.is_some_and(|until| now <= until) {
                return Ok(super::IdentitySigningRotateOutcome::RetiringStillEligible);
            }
            let current_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM identity_signing_keys WHERE state = 'current'",
            ).fetch_one(&mut *tx).await.map_err(Error::Database)?;
            if current_count != 1 {
                return Err(Error::ConfigurationError("identity signing ring must contain exactly one current key".into()));
            }
            sqlx::query("DELETE FROM identity_signing_keys WHERE state = 'retiring' AND retire_until < ?")
                .bind(now).execute(&mut *tx).await.map_err(Error::Database)?;
            let ring_version: i64 = sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = ?")
                .bind(version::RESOURCE_KEY_RING).fetch_one(&mut *tx).await.map_err(Error::Database)?;
            let master_rows = sqlx::query_as::<_, (i64, String, i64, i64)>(
                "SELECT key_id, key_encrypted, active, retired FROM master_keys WHERE retired = 0 ORDER BY key_id",
            ).fetch_all(&mut *tx).await.map_err(Error::Database)?.into_iter()
                .map(|(key_id, key_encrypted, active, retired)| super::MasterKeyRow { key_id: key_id as i16, key_encrypted, active: active != 0, retired: retired != 0 })
                .collect();
            let ring = super::build_master_key_ring(&self.master_key, master_rows, ring_version as u64)?;
            let encrypted = ring.encrypt_active_to_base64(private_pkcs8)?;
            sqlx::query(
                "UPDATE identity_signing_keys SET state = 'retiring', \
                 private_key_encrypted = NULL, retire_until = ? WHERE state = 'current'",
            ).bind(now + grace_secs).execute(&mut *tx).await.map_err(Error::Database)?;
            sqlx::query(
                "INSERT INTO identity_signing_keys \
                 (kid, state, private_key_encrypted, public_jwk, retire_until) \
                 VALUES (?, 'current', ?, ?, NULL)",
            ).bind(kid).bind(encrypted).bind(public_jwk)
                .execute(&mut *tx).await.map_err(Error::Database)?;
            sqlx::query("DELETE FROM secrets WHERE key = 'jwt_signing_key'")
                .execute(&mut *tx).await.map_err(Error::Database)?;
            self.identity_signing_version.bump(&mut *tx).await?;
            Ok(super::IdentitySigningRotateOutcome::Rotated)
        }.await;
        finish_immediate(tx, result).await
    }

    async fn identity_signing_version_current(&self) -> Result<u64> {
        self.identity_signing_version.current().await
    }

    async fn identity_signing_reencrypt_current(
        &self,
    ) -> Result<super::IdentitySigningReencryptOutcome> {
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<super::IdentitySigningReencryptOutcome> = async {
            let _: i64 =
                sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = ?")
                    .bind(version::RESOURCE_IDENTITY_SIGNING_KEY_RING)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            let ring_version: i64 =
                sqlx::query_scalar("SELECT version FROM schema_versions WHERE resource = ?")
                    .bind(version::RESOURCE_KEY_RING)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(Error::Database)?;
            let Some(encrypted): Option<String> = sqlx::query_scalar(
                "SELECT private_key_encrypted FROM identity_signing_keys WHERE state = 'current'",
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(Error::Database)?
            .flatten() else {
                return Ok(super::IdentitySigningReencryptOutcome::default());
            };
            let master_rows = sqlx::query_as::<_, (i64, String, i64, i64)>(
                "SELECT key_id, key_encrypted, active, retired FROM master_keys \
                 WHERE retired = 0 ORDER BY key_id",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(Error::Database)?
            .into_iter()
            .map(
                |(key_id, key_encrypted, active, retired)| super::MasterKeyRow {
                    key_id: key_id as i16,
                    key_encrypted,
                    active: active != 0,
                    retired: retired != 0,
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
                "UPDATE identity_signing_keys SET private_key_encrypted = ? \
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
        finish_immediate(tx, result).await
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
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        let row = sqlx::query_as::<_, PendingAuthRow>(
            "SELECT idp_id, nonce, code_verifier, saml_authn_request_id, \
                    redirect_url, created_at, expires_at, kind, browser_nonce_hash \
             FROM pending_auth WHERE csrf = ? AND expires_at >= ?",
        )
        .bind(csrf_token)
        .bind(to_epoch(chrono::Utc::now()))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(PendingAuthRow::into_model))
    }

    async fn pending_auth_take(
        &self,
        csrf_token: &str,
    ) -> Result<Option<crate::auth::middleware::PendingAuth>> {
        // Atomic read-and-delete inside a single immediate transaction
        // takes the write lock so a peer process (or a second tab
        // racing the same csrf) can't win the delete from under us.
        let mut tx = begin_immediate(&self.pool).await?;

        let result: Result<Option<crate::auth::middleware::PendingAuth>> = async {
            let row = sqlx::query_as::<_, PendingAuthRow>(
                "SELECT idp_id, nonce, code_verifier, saml_authn_request_id, \
                        redirect_url, created_at, expires_at, kind, browser_nonce_hash \
                 FROM pending_auth WHERE csrf = ?",
            )
            .bind(csrf_token)
            .fetch_optional(&mut *tx)
            .await?;

            let row = match row {
                Some(r) => r,
                None => return Ok(None),
            };

            sqlx::query("DELETE FROM pending_auth WHERE csrf = ?")
                .bind(csrf_token)
                .execute(&mut *tx)
                .await?;

            // Expired rows are equivalent to absent. We drop them on
            // the way past — a cleanup task also sweeps, but inline
            // enforcement here is what guarantees the TTL even if the
            // sweeper fell behind.
            if row.expires_at < to_epoch(chrono::Utc::now()) {
                return Ok(None);
            }

            Ok(Some(row.into_model()))
        }
        .await;

        finish_immediate(tx, result).await
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
        let mut tx = begin_immediate(&self.pool).await?;
        let result: Result<bool> = async {
            let deleted = sqlx::query(
                "DELETE FROM pending_auth \
                 WHERE csrf = ? AND kind = ? AND expires_at >= ? \
                   AND idp_id = ? AND redirect_url = ?",
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
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

        finish_immediate(tx, result).await
    }

    async fn pending_auth_cleanup_expired(&self) -> Result<u64> {
        let r = sqlx::query("DELETE FROM pending_auth WHERE expires_at < ?")
            .bind(to_epoch(chrono::Utc::now()))
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// `INSERT OR IGNORE` makes the primary key the arbiter: the row either
    /// appears now or it already existed, and `rows_affected` says which. There
    /// is no read before the write, so two redemptions racing cannot both
    /// observe an empty table and both conclude they are first.
    async fn handoff_nonce_consume(&self, nonce: Uuid) -> Result<bool> {
        let result = sqlx::query("INSERT OR IGNORE INTO used_handoff_nonces (nonce) VALUES (?)")
            .bind(nonce)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Retention only; correctness lives in the primary key. The cutoff uses
    /// the database's clock rather than the daemon's so that every node prunes
    /// against the same time base as the rows were written with.
    async fn handoff_nonce_cleanup_expired(&self) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM used_handoff_nonces \
             WHERE consumed_at < unixepoch() - ?",
        )
        .bind(super::HANDOFF_NONCE_RETENTION_SECONDS)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn ping(&self) -> Result<()> {
        // Execute `SELECT 1` and fetch its row as a pool/query liveness
        // probe. This does not exercise a WAL write or detect read-only
        // storage.
        sqlx::query("SELECT 1").fetch_one(&self.pool).await?;
        Ok(())
    }
}

// ═══════════════════════ Helpers ═══════════════════════

/// `FromRow` target for the ACME queue. Kept local to the backend so
/// the cross-backend `AcmeQueueRow` model stays sqlx-free.
#[derive(sqlx::FromRow)]
struct AcmeQueueRowDb {
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

impl AcmeQueueRowDb {
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

/// `FromRow` target for the election singleton. Separate from
/// `AcmeElectionRow` in the backend trait so the sqlx derive only
/// lives here and the cross-backend shape stays sqlx-free.
#[derive(sqlx::FromRow)]
struct AcmeElectionRowDb {
    node_id: String,
    node_hash: String,
    updated_at: i64,
}

/// SQLite row shape for `pending_auth`. Separated from the in-memory
/// `PendingAuth` type so the sqlx derive stays out of the auth module.
#[derive(sqlx::FromRow)]
struct PendingAuthRow {
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

impl PendingAuthRow {
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

#[cfg(test)]
mod immediate_tx_tests {
    use super::*;
    use crate::crypto::{EncryptedDekRecord, MasterKeyRing};
    use base64::Engine;
    use std::{future::pending, path::PathBuf, sync::Arc, time::Duration};
    use tokio::sync::oneshot;

    const HANG_GUARD: Duration = Duration::from_secs(3);

    struct TestDb {
        pool_a: SqlitePool,
        pool_b: SqlitePool,
        path: PathBuf,
    }

    impl TestDb {
        async fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("sekishod-immediate-tx-{}.sqlite3", Uuid::new_v4()));
            let url = format!("sqlite://{}", path.display());
            let options = SqliteConnectOptions::from_str(&url)
                .expect("test database URL must be valid")
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(2));

            let pool_a = SqlitePoolOptions::new()
                .max_connections(3)
                .connect_with(options.clone())
                .await
                .expect("first test pool must connect");
            let pool_b = SqlitePoolOptions::new()
                .max_connections(3)
                .connect_with(options)
                .await
                .expect("second test pool must connect");

            sqlx::query(
                "CREATE TABLE tx_probe (
                    id TEXT PRIMARY KEY
                )",
            )
            .execute(&pool_a)
            .await
            .expect("probe table must be created");
            sqlx::query(
                "CREATE TABLE tx_parent (
                    id INTEGER PRIMARY KEY
                )",
            )
            .execute(&pool_a)
            .await
            .expect("parent table must be created");
            sqlx::query(
                "CREATE TABLE tx_child (
                    id INTEGER PRIMARY KEY,
                    parent_id INTEGER NOT NULL,
                    FOREIGN KEY (parent_id) REFERENCES tx_parent(id)
                        DEFERRABLE INITIALLY DEFERRED
                )",
            )
            .execute(&pool_a)
            .await
            .expect("child table must be created");

            Self {
                pool_a,
                pool_b,
                path,
            }
        }

        async fn close(self) {
            let Self {
                pool_a,
                pool_b,
                path,
            } = self;
            pool_a.close().await;
            pool_b.close().await;
            drop(pool_a);
            drop(pool_b);

            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(format!("{}-wal", path.display()));
            let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        }
    }

    async fn insert_probe(pool: &SqlitePool, id: &str) -> Result<()> {
        tokio::time::timeout(HANG_GUARD, async {
            let mut tx = begin_immediate(pool).await?;
            let result = sqlx::query("INSERT INTO tx_probe (id) VALUES (?)")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map(|_| ())
                .map_err(Error::Database);
            finish_immediate(tx, result).await
        })
        .await
        .expect("next writer must not hang")
    }

    async fn assert_probe_absent(pool: &SqlitePool, id: &str) {
        let count = tokio::time::timeout(
            HANG_GUARD,
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tx_probe WHERE id = ?")
                .bind(id)
                .fetch_one(pool),
        )
        .await
        .expect("absence check must not hang")
        .expect("absence check must succeed");
        assert_eq!(count, 0, "rolled-back probe row must be absent");
    }

    #[tokio::test]
    async fn cancelled_immediate_transaction_rolls_back_before_pool_reuse() {
        let db = TestDb::new().await;
        let task_pool = db.pool_a.clone();
        let (inserted_tx, inserted_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut tx = begin_immediate(&task_pool).await?;
            sqlx::query("INSERT INTO tx_probe (id) VALUES ('cancelled')")
                .execute(&mut *tx)
                .await?;
            let _ = inserted_tx.send(());
            pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<(), Error>(())
        });

        inserted_rx
            .await
            .expect("transaction task must reach the inserted state");
        task.abort();
        let join_error = task.await.expect_err("aborted task must not complete");
        assert!(join_error.is_cancelled(), "task must report cancellation");

        assert_probe_absent(&db.pool_b, "cancelled").await;
        insert_probe(&db.pool_b, "after-cancel")
            .await
            .expect("separate-pool writer must commit after cancellation");
        db.close().await;
    }

    #[tokio::test]
    async fn panicked_immediate_transaction_rolls_back_before_pool_reuse() {
        let db = TestDb::new().await;
        let task_pool = db.pool_a.clone();
        let task = tokio::spawn(async move {
            let mut tx = begin_immediate(&task_pool).await?;
            sqlx::query("INSERT INTO tx_probe (id) VALUES ('panicked')")
                .execute(&mut *tx)
                .await?;
            panic!("intentional immediate transaction test panic");
            #[allow(unreachable_code)]
            Ok::<(), Error>(())
        });

        let join_error = task.await.expect_err("panicked task must not complete");
        assert!(join_error.is_panic(), "task must report panic");

        assert_probe_absent(&db.pool_b, "panicked").await;
        insert_probe(&db.pool_b, "after-panic")
            .await
            .expect("separate-pool writer must commit after panic");
        db.close().await;
    }

    #[tokio::test]
    async fn dropped_immediate_transaction_releases_same_and_separate_pools() {
        let db = TestDb::new().await;
        let mut tx = begin_immediate(&db.pool_a)
            .await
            .expect("transaction must begin");
        sqlx::query("INSERT INTO tx_probe (id) VALUES ('dropped')")
            .execute(&mut *tx)
            .await
            .expect("probe row must be inserted");
        drop(tx);

        assert_probe_absent(&db.pool_a, "dropped").await;
        insert_probe(&db.pool_a, "same-pool")
            .await
            .expect("same-pool writer must commit after drop");
        insert_probe(&db.pool_b, "separate-pool")
            .await
            .expect("separate-pool writer must commit after drop");
        db.close().await;
    }

    #[tokio::test]
    async fn body_error_is_preserved_and_transaction_is_rolled_back() {
        let db = TestDb::new().await;
        let mut tx = begin_immediate(&db.pool_a)
            .await
            .expect("transaction must begin");
        sqlx::query("INSERT INTO tx_probe (id) VALUES ('body-error')")
            .execute(&mut *tx)
            .await
            .expect("probe row must be inserted");

        let error = finish_immediate::<()>(
            tx,
            Err(Error::Internal("immediate body sentinel".to_string())),
        )
        .await
        .expect_err("body error must be returned");
        assert!(
            matches!(error, Error::Internal(ref message) if message == "immediate body sentinel"),
            "the original body error must be preserved"
        );

        assert_probe_absent(&db.pool_b, "body-error").await;
        insert_probe(&db.pool_b, "after-body-error")
            .await
            .expect("next writer must commit after body rollback");
        db.close().await;
    }

    #[tokio::test]
    async fn deferred_foreign_key_commit_error_rolls_back_and_releases_writer() {
        let db = TestDb::new().await;
        let mut tx = begin_immediate(&db.pool_a)
            .await
            .expect("transaction must begin");
        sqlx::query("INSERT INTO tx_child (id, parent_id) VALUES (1, 999)")
            .execute(&mut *tx)
            .await
            .expect("deferred constraint must permit the body write");

        let error = finish_immediate(tx, Ok(())).await;
        assert!(
            matches!(error, Err(Error::Database(_))),
            "deferred foreign-key failure must propagate from commit"
        );

        let child_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tx_child WHERE id = 1")
                .fetch_one(&db.pool_b)
                .await
                .expect("invalid child lookup must succeed");
        assert_eq!(child_count, 0, "failed commit must not retain invalid row");
        insert_probe(&db.pool_b, "after-commit-error")
            .await
            .expect("next writer must commit after failed commit rollback");
        db.close().await;
    }

    struct FirstDekDb {
        a: SqliteBackend,
        b: SqliteBackend,
        path: PathBuf,
    }

    impl FirstDekDb {
        async fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sekishod-first-dek-bootstrap-{}.sqlite3",
                Uuid::new_v4()
            ));
            let url = format!("sqlite://{}", path.display());
            let a = SqliteBackend::new_service(&url, test_master_key())
                .await
                .expect("first bootstrap backend must open");
            let b = SqliteBackend::new_service(&url, test_master_key())
                .await
                .expect("second bootstrap backend must open");
            Self { a, b, path }
        }

        async fn close(self) {
            let Self { a, b, path } = self;
            a.close().await;
            b.close().await;
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(format!("{}-wal", path.display()));
            let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        }
    }

    fn bootstrap_blob(kek: &[u8; 32]) -> String {
        let kek = envelope_aead::Kek::from_bytes(zeroize::Zeroizing::new(*kek));
        let boot =
            envelope_aead::bootstrap_initial_dek(&kek).expect("bootstrap candidate must generate");
        base64::engine::general_purpose::STANDARD.encode(boot.encrypted_blob.as_bytes())
    }

    async fn reload_ring(backend: &SqliteBackend, kek: &[u8; 32]) -> MasterKeyRing {
        let rows = backend
            .master_keys_load_active_set()
            .await
            .expect("persisted bootstrap rows must load");
        let records: Vec<EncryptedDekRecord<Vec<u8>>> = rows
            .into_iter()
            .map(|row| EncryptedDekRecord {
                key_id: row.key_id.try_into().expect("test key ID must fit"),
                encrypted_blob: base64::engine::general_purpose::STANDARD
                    .decode(row.key_encrypted)
                    .expect("persisted bootstrap blob must decode"),
                active: row.active,
                retired: row.retired,
            })
            .collect();
        let kek_handle = envelope_aead::Kek::from_bytes(zeroize::Zeroizing::new(*kek));
        MasterKeyRing::from_encrypted_records(
            &kek_handle,
            records,
            backend
                .key_ring_version_current()
                .await
                .expect("ring version must load"),
        )
        .expect("persisted bootstrap ring must rebuild")
    }

    #[tokio::test]
    async fn first_dek_bootstrap_race_has_one_winner_and_one_persisted_ring() {
        let db = FirstDekDb::new().await;
        let kek = [0x91; 32];
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let a = db.a.clone();
        let a_barrier = barrier.clone();
        let a_blob = bootstrap_blob(&kek);
        let a_task = tokio::spawn(async move {
            a_barrier.wait().await;
            a.master_keys_insert_first_active_if_empty(&a_blob).await
        });
        let b = db.b.clone();
        let b_barrier = barrier.clone();
        let b_blob = bootstrap_blob(&kek);
        let b_task = tokio::spawn(async move {
            b_barrier.wait().await;
            b.master_keys_insert_first_active_if_empty(&b_blob).await
        });
        barrier.wait().await;

        let outcomes = [
            a_task.await.expect("first peer must join").unwrap(),
            b_task.await.expect("second peer must join").unwrap(),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|&&outcome| outcome == FirstDekInsertOutcome::Inserted)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|&&outcome| outcome == FirstDekInsertOutcome::AlreadyInitialized)
                .count(),
            1
        );

        let rows = db.a.master_keys_load_active_set().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key_id, 0);
        assert!(rows[0].active);
        assert!(!rows[0].retired);
        assert_eq!(db.a.key_ring_version_current().await.unwrap(), 1);

        let ring_a = reload_ring(&db.a, &kek).await;
        let ring_b = reload_ring(&db.b, &kek).await;
        let ciphertext = ring_a.encrypt_active(b"shared bootstrap ring").unwrap();
        assert_eq!(
            &*ring_b.decrypt(&ciphertext).unwrap(),
            b"shared bootstrap ring"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn first_dek_bootstrap_propagates_database_errors_without_masking() {
        let db = FirstDekDb::new().await;
        sqlx::query(
            "CREATE TRIGGER reject_first_dek \
             BEFORE INSERT ON master_keys \
             BEGIN SELECT RAISE(ABORT, 'bootstrap database failure'); END",
        )
        .execute(db.a.pool())
        .await
        .unwrap();

        let error =
            db.a.master_keys_insert_first_active_if_empty(&bootstrap_blob(&[0x92; 32]))
                .await
                .expect_err("trigger failure must propagate");
        assert!(matches!(error, Error::Database(_)));
        let row_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM master_keys")
            .fetch_one(db.a.pool())
            .await
            .unwrap();
        assert_eq!(row_count, 0);
        assert_eq!(db.a.key_ring_version_current().await.unwrap(), 0);

        sqlx::query("DROP TRIGGER reject_first_dek")
            .execute(db.a.pool())
            .await
            .unwrap();
        assert_eq!(
            db.b.master_keys_insert_first_active_if_empty(&bootstrap_blob(&[0x93; 32]))
                .await
                .unwrap(),
            FirstDekInsertOutcome::Inserted
        );
        assert_eq!(db.b.key_ring_version_current().await.unwrap(), 1);
        db.close().await;
    }

    #[tokio::test]
    async fn cancelled_first_dek_bootstrap_rolls_back_before_pool_reuse() {
        let db = FirstDekDb::new().await;
        let blob = bootstrap_blob(&[0x95; 32]);
        let hook = first_dek_test_hook::install(&blob);
        let backend = db.a.clone();
        let task_blob = blob.clone();
        let task = tokio::spawn(async move {
            backend
                .master_keys_insert_first_active_if_empty(&task_blob)
                .await
        });
        tokio::time::timeout(HANG_GUARD, hook.inserted.notified())
            .await
            .expect("bootstrap must insert before cancellation");

        task.abort();
        let join_error = task.await.expect_err("bootstrap task must be cancelled");
        assert!(join_error.is_cancelled());
        first_dek_test_hook::remove(&blob);

        let row_count = tokio::time::timeout(
            HANG_GUARD,
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM master_keys").fetch_one(db.b.pool()),
        )
        .await
        .expect("rollback visibility must not hang")
        .unwrap();
        assert_eq!(row_count, 0);
        assert_eq!(db.b.key_ring_version_current().await.unwrap(), 0);
        assert_eq!(
            tokio::time::timeout(
                HANG_GUARD,
                db.b.master_keys_insert_first_active_if_empty(&bootstrap_blob(&[0x96; 32])),
            )
            .await
            .expect("next writer must not hang")
            .unwrap(),
            FirstDekInsertOutcome::Inserted
        );
        db.close().await;
    }

    #[tokio::test]
    async fn first_dek_bootstrap_treats_any_existing_row_as_initialized() {
        let db = FirstDekDb::new().await;
        sqlx::query(
            "INSERT INTO master_keys \
             (key_id, key_encrypted, active, retired) VALUES (7, 'retired', 0, 1)",
        )
        .execute(db.a.pool())
        .await
        .unwrap();

        assert_eq!(
            db.a.master_keys_insert_first_active_if_empty(&bootstrap_blob(&[0x94; 32]))
                .await
                .unwrap(),
            FirstDekInsertOutcome::AlreadyInitialized
        );
        let all_rows = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM master_keys")
            .fetch_one(db.a.pool())
            .await
            .unwrap();
        assert_eq!(all_rows, 1);
        assert!(db.a.master_keys_load_active_set().await.unwrap().is_empty());
        assert_eq!(db.a.key_ring_version_current().await.unwrap(), 0);
        db.close().await;
    }

    #[tokio::test]
    async fn cancelled_dek_allocation_rolls_back_row_and_version() {
        let db = FirstDekDb::new().await;
        let blob = "cancelled-allocation";
        let hook = dek_allocation_test_hook::install(blob);
        let backend = db.a.clone();
        let task = tokio::spawn(async move { backend.master_keys_allocate_inactive(blob).await });

        tokio::time::timeout(HANG_GUARD, hook.inserted.notified())
            .await
            .expect("allocation must insert before cancellation");
        task.abort();
        let join_error = task.await.expect_err("allocation task must be cancelled");
        assert!(join_error.is_cancelled());
        dek_allocation_test_hook::remove(blob);

        let row_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM master_keys")
            .fetch_one(db.b.pool())
            .await
            .unwrap();
        assert_eq!(row_count, 0);
        assert_eq!(db.b.key_ring_version_current().await.unwrap(), 0);
        assert_eq!(
            db.b.master_keys_allocate_inactive("next-allocation")
                .await
                .unwrap(),
            0
        );
        assert_eq!(db.b.key_ring_version_current().await.unwrap(), 1);
        db.close().await;
    }

    #[tokio::test]
    async fn failed_dek_allocation_rolls_back_without_version_drift() {
        let db = FirstDekDb::new().await;
        sqlx::query(
            "CREATE TRIGGER reject_dek_allocation \
             BEFORE INSERT ON master_keys \
             BEGIN SELECT RAISE(ABORT, 'allocation database failure'); END",
        )
        .execute(db.a.pool())
        .await
        .unwrap();

        let error =
            db.a.master_keys_allocate_inactive("rejected-allocation")
                .await
                .expect_err("trigger failure must propagate");
        assert!(matches!(error, Error::Database(_)));
        let row_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM master_keys")
            .fetch_one(db.b.pool())
            .await
            .unwrap();
        assert_eq!(row_count, 0);
        assert_eq!(db.b.key_ring_version_current().await.unwrap(), 0);
        db.close().await;
    }
}
