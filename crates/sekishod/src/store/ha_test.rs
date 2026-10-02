//! Cross-node cache-invalidation scenarios against a shared Postgres.
//!
//! These tests spin up two independent `Store` instances pointed at the
//! same Postgres schema — exactly the HA topology the version
//! counters exist to serve. They're the acid test that a mutation on
//! one node is visible to readers on the other node, both in raw DB
//! state and (for the cached resources) in the local cache via the
//! DB-sourced version bump.
//!
//! SQLite is excluded by design: the single-writer WAL isolation
//! inside one process doesn't generalise to two processes sharing a
//! file, so the HA guarantees we assert here aren't ones SQLite
//! itself promises.
//!
//! Gated on `TEST_POSTGRES_URL`. When that variable isn't set the
//! module compiles but every test becomes a no-op `return` so the
//! default `cargo test` run on a dev machine isn't blocked on
//! having Postgres available.

#[cfg(test)]
mod tests {
    use crate::crypto::{EncryptedDekRecord, MasterKey, MasterKeyRing};
    use crate::models::api_key::ApiKeyScopeSet;
    use crate::models::config::GlobalConfig;
    use crate::models::idp::{IdentityProvider, IdpType, OidcConfig, SamlConfig};
    use crate::models::policy::Policy;
    use crate::models::route::{CreateRoute, HeaderModifications, RouteAccess};
    use crate::models::session::{Session, UpstreamIdentity, UpstreamIdentityProvenance};
    use crate::store::Store;
    use crate::store::acme_account::{ACCOUNT_CREDENTIALS_KEY, AcmeAccountCredentialInsert};
    use crate::store::backend::{
        Backend, ElectionAction, FirstDekInsertOutcome, IdentitySigningRotateOutcome,
        PostgresBackend, SERVICE_MIGRATIONS, SessionTouchOutcome, StorageBackend,
        postgres::migration_test_hook as pg_migration_hook, sqlite::SqliteBackend,
    };
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use base64::Engine;
    use cookie::SameSite;
    use http_body_util::BodyExt;
    use sqlx::{PgPool, Row, SqlitePool};
    use std::time::Duration;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    fn admitted(
        admission: crate::models::acme_queue::AcmeQueueAdmission,
    ) -> crate::models::acme_queue::AcmeQueueRow {
        match admission {
            crate::models::acme_queue::AcmeQueueAdmission::Inserted(row)
            | crate::models::acme_queue::AcmeQueueAdmission::Existing(row) => row,
            crate::models::acme_queue::AcmeQueueAdmission::Full => {
                panic!("queue unexpectedly full")
            }
        }
    }

    fn expected_migration_ledger() -> Vec<(i64, String)> {
        SERVICE_MIGRATIONS
            .iter()
            .map(|migration| (migration.version, migration.name.to_owned()))
            .collect()
    }

    /// Helper: two Stores wired to the same Postgres schema. Returns
    /// `None` — and callers early-return — when the env var isn't set,
    /// so the suite transparently skips without gating at cfg time.
    async fn two_nodes() -> Option<(Store, Store)> {
        let url = std::env::var("TEST_POSTGRES_URL").ok()?;
        let schema = unique_schema();

        // Schema bootstrap: create a blank schema on a throwaway
        // connection before either Store runs its migrations.
        let setup = sqlx::PgPool::connect(&url).await.expect("connect");
        sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .execute(&setup)
            .await
            .expect("drop schema");
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&setup)
            .await
            .expect("create schema");
        drop(setup);

        let scoped = with_search_path(&url, &schema);

        // Each node gets its own in-memory SQLite bootstrap DB — that
        // mirrors the real HA topology where every node has a local
        // bootstrap file. The service backend is the shared Postgres
        // schema we just created. Node A runs the PG migrations; node
        // B connects after and re-runs the idempotent DDL (which is
        // fine — CREATE TABLE IF NOT EXISTS, ON CONFLICT DO NOTHING
        // on the version rows).
        let a = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, Some(&scoped))
            .await
            .expect("node a");
        let b = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, Some(&scoped))
            .await
            .expect("node b");
        Some((a, b))
    }

    /// Master key fixed for reproducibility; not a secret.
    const TEST_MASTER_KEY: [u8; 32] = [0u8; 32];

    fn test_master_key() -> Arc<MasterKey> {
        MasterKey::from_test_bytes(TEST_MASTER_KEY)
    }

    #[tokio::test]
    async fn postgres_identity_signing_m1_migration_bootstrap_and_legacy_cleanup() {
        let Some((a, _b)) = two_nodes().await else {
            return;
        };
        let backend = match &a.backend {
            Backend::Postgres(backend) => backend,
            _ => unreachable!(),
        };
        assert_eq!(
            pg_ledger(backend.pool_for_rotation()).await,
            expected_migration_ledger()
        );
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_signing_keys")
            .fetch_one(backend.pool_for_rotation())
            .await
            .unwrap();
        assert_eq!(rows, 1);
        a.set_secret("jwt_signing_key", "obsolete-hs-material")
            .await
            .unwrap();
        a.ensure_identity_signing_ring().await.unwrap();
        assert!(a.get_secret("jwt_signing_key").await.unwrap().is_none());
        println!("LIVE_POSTGRES_FIXTURE_ACQUIRED:identity_signing_m1_migration_bootstrap");
    }

    #[tokio::test]
    async fn postgres_identity_signing_m2_concurrent_rotate_has_one_winner() {
        let Some((a, b)) = two_nodes().await else {
            return;
        };
        let (left, right) = tokio::join!(
            a.rotate_identity_signing_ring(),
            b.rotate_identity_signing_ring()
        );
        let outcomes = [left.unwrap(), right.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == IdentitySigningRotateOutcome::Rotated)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    **outcome == IdentitySigningRotateOutcome::RetiringStillEligible
                })
                .count(),
            1
        );
        let backend = match &a.backend {
            Backend::Postgres(backend) => backend,
            _ => unreachable!(),
        };
        let states: Vec<String> =
            sqlx::query_scalar("SELECT state FROM identity_signing_keys ORDER BY state")
                .fetch_all(backend.pool_for_rotation())
                .await
                .unwrap();
        assert_eq!(states, vec!["current", "retiring"]);
        println!("LIVE_POSTGRES_FIXTURE_ACQUIRED:identity_signing_m2_concurrent_rotate");
    }

    #[tokio::test]
    async fn postgres_identity_signing_m3_failed_rotate_rolls_back_and_retains_snapshot() {
        let Some((a, _b)) = two_nodes().await else {
            return;
        };
        let backend = match &a.backend {
            Backend::Postgres(backend) => backend,
            _ => unreachable!(),
        };
        let snapshot = a.identity_key_ring_snapshot().await.unwrap();
        let kid = snapshot.current_kid();
        let version = snapshot.version();
        let statement = format!(
            "ALTER TABLE identity_signing_keys ADD CONSTRAINT identity_test_reject_rotation \
             CHECK (kid = '{kid}') NOT VALID"
        );
        sqlx::query(&statement)
            .execute(backend.pool_for_rotation())
            .await
            .unwrap();
        assert!(a.rotate_identity_signing_ring().await.is_err());
        sqlx::query(
            "ALTER TABLE identity_signing_keys DROP CONSTRAINT identity_test_reject_rotation",
        )
        .execute(backend.pool_for_rotation())
        .await
        .unwrap();
        assert_eq!(snapshot.current_kid(), kid);
        assert_eq!(snapshot.version(), version);
        assert_eq!(a.identity_signing_version_current().await.unwrap(), version);
        let states: Vec<String> =
            sqlx::query_scalar("SELECT state FROM identity_signing_keys ORDER BY state")
                .fetch_all(backend.pool_for_rotation())
                .await
                .unwrap();
        assert_eq!(states, vec!["current"]);
        println!("LIVE_POSTGRES_FIXTURE_ACQUIRED:identity_signing_m3_rollback");
    }

    #[tokio::test]
    async fn postgres_identity_signing_m4_dek_rewrap_and_rotate_share_lock_order() {
        let Some((a, b)) = two_nodes().await else {
            return;
        };
        let master_key = test_master_key();
        let new_id = a
            .master_keys_allocate_inactive_plaintext(&[0x44; 32], master_key.as_ref())
            .await
            .unwrap();
        a.master_keys_activate(new_id).await.unwrap();
        let joined = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                a.rotate_identity_signing_ring(),
                crate::store::dek_rotation::reencrypt_all(&b)
            )
        })
        .await
        .expect("I→D writers must not deadlock");
        joined.0.unwrap();
        joined.1.unwrap();
        assert_eq!(a.identity_signing_scan_key_id(0).await.unwrap(), 0);
        println!("LIVE_POSTGRES_FIXTURE_ACQUIRED:identity_signing_m4_dek_rewrap_lock_order");
    }

    #[tokio::test]
    async fn postgres_identity_signing_m5_peer_refresh_publishes_after_commit() {
        let Some((a, b)) = two_nodes().await else {
            return;
        };
        let peer_snapshot = b.identity_key_ring_snapshot().await.unwrap();
        let previous = peer_snapshot.current_kid();
        assert_eq!(
            a.rotate_identity_signing_ring().await.unwrap(),
            IdentitySigningRotateOutcome::Rotated
        );
        assert_eq!(peer_snapshot.current_kid(), previous);
        b.refresh_identity_signing_ring().await.unwrap();
        assert_ne!(peer_snapshot.current_kid(), previous);
        assert_eq!(
            peer_snapshot.jwks(chrono::Utc::now().timestamp())["keys"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        println!("LIVE_POSTGRES_FIXTURE_ACQUIRED:identity_signing_m5_peer_publish");
    }

    fn with_search_path(url: &str, schema: &str) -> String {
        let sep = if url.contains('?') { '&' } else { '?' };
        format!("{url}{sep}options=-csearch_path%3D{schema}")
    }

    fn unique_schema() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        format!("sekisho_ha_{pid}_{n}")
    }

    fn unique_advisory_key() -> i64 {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        7_300_000_000 + COUNTER.fetch_add(1, Ordering::Relaxed) as i64
    }

    fn account_credentials(bytes: &[u8]) -> acme_core::AcmeAccountCredentials {
        acme_core::AcmeAccountCredentials::from_zeroizing(Zeroizing::new(bytes.to_vec()))
    }

    async fn hold_advisory_lock(
        pool: &PgPool,
        key: i64,
    ) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
        let mut connection = pool.acquire().await.expect("advisory lock connection");
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(key)
            .execute(&mut *connection)
            .await
            .expect("advisory lock must be acquired");
        connection
    }

    async fn release_advisory_lock(
        connection: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
        key: i64,
    ) {
        let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .fetch_one(&mut **connection)
            .await
            .expect("advisory lock release must execute");
        assert!(unlocked, "test advisory lock must be held by this session");
    }

    async fn wait_for_blocked_query(
        observer: &PgPool,
        application_name: &str,
        query_fragment: &str,
        expected: i64,
    ) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let blocked = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM pg_stat_activity \
                     WHERE application_name = $1 \
                       AND wait_event_type = 'Lock' \
                       AND query LIKE $2",
                )
                .bind(application_name)
                .bind(format!("%{query_fragment}%"))
                .fetch_one(observer)
                .await
                .expect("blocked-query observation must succeed");
                if blocked >= expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("expected queries must reach the database lock barrier");
    }

    async fn install_insert_barrier(
        pool: &PgPool,
        table: &str,
        trigger_name: &str,
        function_name: &str,
        advisory_key: i64,
    ) {
        sqlx::query(&format!(
            "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN PERFORM pg_advisory_xact_lock({advisory_key}); RETURN NEW; END $$",
        ))
        .execute(pool)
        .await
        .expect("insert barrier function must be installed");
        sqlx::query(&format!(
            "CREATE TRIGGER {trigger_name} BEFORE INSERT ON {table} \
             FOR EACH ROW EXECUTE FUNCTION {function_name}()",
        ))
        .execute(pool)
        .await
        .expect("insert barrier trigger must be installed");
    }

    fn bootstrap_blob(kek: &[u8; 32]) -> String {
        let kek = envelope_aead::Kek::from_bytes(zeroize::Zeroizing::new(*kek));
        let boot =
            envelope_aead::bootstrap_initial_dek(&kek).expect("bootstrap candidate must generate");
        base64::engine::general_purpose::STANDARD.encode(boot.encrypted_blob.as_bytes())
    }

    struct PgBootstrapFixture {
        a: PostgresBackend,
        b: PostgresBackend,
        base_url: String,
        scoped_url: String,
        schema: String,
    }

    impl PgBootstrapFixture {
        async fn new(application_name: &str) -> Option<Self> {
            let base_url = std::env::var("TEST_POSTGRES_URL").ok()?;
            let schema = unique_schema();
            let setup = sqlx::PgPool::connect(&base_url)
                .await
                .expect("bootstrap fixture must connect");
            sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
                .execute(&setup)
                .await
                .expect("bootstrap fixture schema drop must succeed");
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&setup)
                .await
                .expect("bootstrap fixture schema create must succeed");
            setup.close().await;

            let mut scoped_url = with_search_path(&base_url, &schema);
            scoped_url.push_str("&application_name=");
            scoped_url.push_str(application_name);
            let a = PostgresBackend::new(&scoped_url, test_master_key())
                .await
                .expect("first bootstrap backend must open");
            let b = PostgresBackend::new(&scoped_url, test_master_key())
                .await
                .expect("second bootstrap backend must open");
            Some(Self {
                a,
                b,
                base_url,
                scoped_url,
                schema,
            })
        }

        async fn reset_first_dek_trial(&self) {
            let mut tx = sqlx::PgPool::connect(&self.scoped_url)
                .await
                .expect("bootstrap trial reset must connect")
                .begin()
                .await
                .expect("bootstrap trial reset must begin");
            sqlx::query("DELETE FROM master_keys")
                .execute(&mut *tx)
                .await
                .expect("bootstrap trial rows must reset");
            sqlx::query(
                "UPDATE schema_versions SET version = 0 \
                 WHERE resource = 'key_ring'",
            )
            .execute(&mut *tx)
            .await
            .expect("bootstrap trial version must reset");
            tx.commit()
                .await
                .expect("bootstrap trial reset must commit");
        }

        async fn close(self) {
            self.a.close().await;
            self.b.close().await;
            let setup = sqlx::PgPool::connect(&self.base_url)
                .await
                .expect("bootstrap cleanup must connect");
            sqlx::query(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema))
                .execute(&setup)
                .await
                .expect("bootstrap fixture schema cleanup must succeed");
            setup.close().await;
        }
    }

    struct PgStoreFixture {
        a: Store,
        b: Store,
        observer: PgPool,
        base_url: String,
        schema: String,
        app_a: String,
        app_b: String,
    }

    impl PgStoreFixture {
        async fn new(application_prefix: &str) -> Option<Self> {
            let base_url = std::env::var("TEST_POSTGRES_URL").ok()?;
            let schema = unique_schema();
            let setup = PgPool::connect(&base_url)
                .await
                .expect("store fixture must connect");
            sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
                .execute(&setup)
                .await
                .expect("store fixture schema drop must succeed");
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&setup)
                .await
                .expect("store fixture schema create must succeed");
            setup.close().await;

            let app_a = format!("{application_prefix}_a");
            let app_b = format!("{application_prefix}_b");
            let scoped = with_search_path(&base_url, &schema);
            let url_a = format!("{scoped}&application_name={app_a}");
            let url_b = format!("{scoped}&application_name={app_b}");
            let a = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, Some(&url_a))
                .await
                .expect("first store fixture node must open");
            let b = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, Some(&url_b))
                .await
                .expect("second store fixture node must open");
            let observer = PgPool::connect(&scoped)
                .await
                .expect("store fixture observer must connect");
            eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:{application_prefix}");
            Some(Self {
                a,
                b,
                observer,
                base_url,
                schema,
                app_a,
                app_b,
            })
        }

        async fn close(self) {
            self.a.close().await;
            self.b.close().await;
            self.observer.close().await;
            let setup = PgPool::connect(&self.base_url)
                .await
                .expect("store fixture cleanup must connect");
            sqlx::query(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema))
                .execute(&setup)
                .await
                .expect("store fixture schema cleanup must succeed");
            setup.close().await;
        }
    }

    async fn reload_pg_ring(backend: &PostgresBackend, kek: &[u8; 32]) -> MasterKeyRing {
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

    fn sample_route(name: &str, from: &str) -> crate::models::route::Route {
        CreateRoute {
            name: name.into(),
            from: from.into(),
            to: vec!["http://backend:8080".into()],
            access: RouteAccess::default(),
            load_balancing: None,
            preserve_host_header: None,
            timeout_ms: None,
            response_idle_timeout_ms: None,
            enable_websocket: None,
            enable_grpc: None,
            enable_signed_identity: None,
            tls_downstream: None,
            path: None,
            redirect: None,
            idp_id: None,
            host_rewrite: None,
            regex_rewrite_pattern: None,
            regex_rewrite_substitution: None,
            tls_skip_verify: None,
            headers: HeaderModifications::default(),
            session_cookie_samesite: None,
            response_location_rewrite: None,
            enabled: None,
            concurrency_limit: None,
        }
        .into_route()
    }

    fn sample_idp(name: &str) -> IdentityProvider {
        IdentityProvider {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            idp_type: IdpType::Oidc,
            oidc_config: Some(OidcConfig {
                issuer_url: "https://accounts.google.com".into(),
                client_id: "client".into(),
                client_secret_encrypted: "secret".into(),
                scopes: vec!["openid".into()],
                prompt: None,
            }),
            saml_config: None,
        }
    }

    fn identity_session(user_id: &str, upstream_identity: Option<UpstreamIdentity>) -> Session {
        let now = chrono::Utc::now();
        Session {
            id: Uuid::new_v4(),
            user_id: user_id.into(),
            idp_id: Uuid::new_v4(),
            claims: Default::default(),
            groups: vec!["operators".into()],
            upstream_identity,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            refresh_token_encrypted: None,
            id_token_encrypted: None,
            saml_name_id: None,
            saml_session_index: None,
            last_accessed_at: now,
        }
    }

    #[tokio::test]
    async fn postgres_identity_legacy_session_cross_node_decode() {
        let Some(fixture) = PgStoreFixture::new("identity_legacy_session_cross_node").await else {
            return;
        };
        let session = identity_session("legacy@example.com", None);
        fixture.a.create_session(&session).await.unwrap();

        let data: String = sqlx::query_scalar("SELECT data FROM sessions WHERE id = $1")
            .bind(session.id)
            .fetch_one(&fixture.observer)
            .await
            .unwrap();
        let mut legacy: serde_json::Value = serde_json::from_str(&data).unwrap();
        legacy.as_object_mut().unwrap().remove("upstream_identity");
        sqlx::query("UPDATE sessions SET data = $1 WHERE id = $2")
            .bind(serde_json::to_string(&legacy).unwrap())
            .bind(session.id)
            .execute(&fixture.observer)
            .await
            .unwrap();

        let decoded = fixture.b.get_session(session.id).await.unwrap();
        assert!(decoded.upstream_identity.is_none());
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_session_touch_cas_is_monotonic_across_nodes() {
        let Some(fixture) = PgStoreFixture::new("session_cross_node_cas_monotonic").await else {
            return;
        };
        let session = identity_session("cas@example.com", None);
        fixture.a.create_session(&session).await.unwrap();
        let old: i64 = sqlx::query_scalar(
            "UPDATE sessions SET last_accessed_at = EXTRACT(EPOCH FROM NOW())::BIGINT - 61 \
             WHERE id = $1 RETURNING last_accessed_at",
        )
        .bind(session.id)
        .fetch_one(&fixture.observer)
        .await
        .unwrap();
        let left = fixture
            .a
            .get_session_for_validation(session.id)
            .await
            .unwrap();
        let right = fixture
            .b
            .get_session_for_validation(session.id)
            .await
            .unwrap();
        assert!(left.touch_due && right.touch_due);
        assert_eq!(left.session.last_accessed_at.timestamp(), old);
        assert_eq!(right.session.last_accessed_at.timestamp(), old);

        let (left, right) = tokio::join!(
            fixture
                .a
                .touch_session_if_due(session.id, left.session.last_accessed_at),
            fixture
                .b
                .touch_session_if_due(session.id, right.session.last_accessed_at),
        );
        let outcomes = [left.unwrap(), right.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, SessionTouchOutcome::Touched(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, SessionTouchOutcome::Current(_)))
                .count(),
            1
        );
        let (last_accessed_at, expires_at): (i64, i64) =
            sqlx::query_as("SELECT last_accessed_at, expires_at FROM sessions WHERE id = $1")
                .bind(session.id)
                .fetch_one(&fixture.observer)
                .await
                .unwrap();
        assert!(
            last_accessed_at > old,
            "touch must move the timestamp forward"
        );
        assert_eq!(expires_at, session.expires_at.timestamp());
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_session_touch_cleanup_race_never_resurrects_or_deletes_active() {
        let Some(fixture) = PgStoreFixture::new("session_touch_cleanup_race").await else {
            return;
        };

        let active = identity_session("active-race@example.com", None);
        fixture.a.create_session(&active).await.unwrap();
        let active_old: i64 = sqlx::query_scalar(
            "UPDATE sessions SET last_accessed_at = EXTRACT(EPOCH FROM NOW())::BIGINT - 100 \
             WHERE id = $1 RETURNING last_accessed_at",
        )
        .bind(active.id)
        .fetch_one(&fixture.observer)
        .await
        .unwrap();
        let active_old = chrono::DateTime::from_timestamp(active_old, 0).unwrap();
        let (touch, cleanup) = tokio::join!(
            fixture.a.touch_session_if_due(active.id, active_old),
            fixture.b.cleanup_expired_sessions(),
        );
        assert!(matches!(touch.unwrap(), SessionTouchOutcome::Touched(_)));
        let _ = cleanup.unwrap();
        assert!(fixture.b.get_session(active.id).await.is_ok());

        let expired = identity_session("expired-race@example.com", None);
        fixture.a.create_session(&expired).await.unwrap();
        let expired_old: i64 = sqlx::query_scalar(
            "UPDATE sessions SET last_accessed_at = \
             EXTRACT(EPOCH FROM NOW())::BIGINT - 1860 \
             WHERE id = $1 RETURNING last_accessed_at",
        )
        .bind(expired.id)
        .fetch_one(&fixture.observer)
        .await
        .unwrap();
        let expired_old = chrono::DateTime::from_timestamp(expired_old, 0).unwrap();
        let (touch, cleanup) = tokio::join!(
            fixture.a.touch_session_if_due(expired.id, expired_old),
            fixture.b.cleanup_expired_sessions(),
        );
        assert_eq!(touch.unwrap(), SessionTouchOutcome::GoneOrExpired);
        let _ = cleanup.unwrap();
        assert!(fixture.a.get_session(expired.id).await.is_err());
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE id = $1")
            .bind(expired.id)
            .fetch_one(&fixture.observer)
            .await
            .unwrap();
        assert_eq!(rows, 0, "expired session must not be resurrected");
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_session_absolute_idle_and_equality_boundaries_use_db_time() {
        let Some(fixture) = PgStoreFixture::new("session_expiry_db_time_boundaries").await else {
            return;
        };
        let absolute = identity_session("absolute-boundary@example.com", None);
        let idle = identity_session("idle-boundary@example.com", None);
        let active = identity_session("active-boundary@example.com", None);
        fixture.a.create_session(&absolute).await.unwrap();
        fixture.a.create_session(&idle).await.unwrap();
        fixture.a.create_session(&active).await.unwrap();
        sqlx::query(
            "UPDATE sessions SET expires_at = EXTRACT(EPOCH FROM NOW())::BIGINT \
             WHERE id = $1",
        )
        .bind(absolute.id)
        .execute(&fixture.observer)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE sessions SET last_accessed_at = \
             EXTRACT(EPOCH FROM NOW())::BIGINT - 1860 WHERE id = $1",
        )
        .bind(idle.id)
        .execute(&fixture.observer)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE sessions SET last_accessed_at = \
             EXTRACT(EPOCH FROM NOW())::BIGINT - 1800 WHERE id = $1",
        )
        .bind(active.id)
        .execute(&fixture.observer)
        .await
        .unwrap();

        assert!(fixture.a.get_session(absolute.id).await.is_err());
        assert!(fixture.a.get_session(idle.id).await.is_err());
        assert!(fixture.a.get_session(active.id).await.is_ok());
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_session_touch_failure_is_awaited_and_retryable() {
        let Some(fixture) = PgStoreFixture::new("session_touch_failure_retry").await else {
            return;
        };
        let session = identity_session("retry@example.com", None);
        fixture.a.create_session(&session).await.unwrap();
        sqlx::query(
            "UPDATE sessions SET last_accessed_at = EXTRACT(EPOCH FROM NOW())::BIGINT - 61 \
             WHERE id = $1",
        )
        .bind(session.id)
        .execute(&fixture.observer)
        .await
        .unwrap();
        let snapshot = fixture
            .a
            .get_session_for_validation(session.id)
            .await
            .unwrap();
        sqlx::query(
            "CREATE FUNCTION reject_session_touch_fn() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'injected session touch failure'; END $$",
        )
        .execute(&fixture.observer)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_session_touch BEFORE UPDATE ON sessions \
             FOR EACH ROW EXECUTE FUNCTION reject_session_touch_fn()",
        )
        .execute(&fixture.observer)
        .await
        .unwrap();
        let error = fixture
            .a
            .touch_session_if_due(session.id, snapshot.session.last_accessed_at)
            .await
            .expect_err("touch failure must be returned to the request");
        assert!(error.to_string().contains("injected session touch failure"));
        sqlx::query("DROP TRIGGER reject_session_touch ON sessions")
            .execute(&fixture.observer)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION reject_session_touch_fn()")
            .execute(&fixture.observer)
            .await
            .unwrap();
        assert!(matches!(
            fixture
                .a
                .touch_session_if_due(session.id, snapshot.session.last_accessed_at)
                .await
                .unwrap(),
            SessionTouchOutcome::Touched(_)
        ));
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_identity_canonical_claims_cross_node() {
        let Some(fixture) = PgStoreFixture::new("identity_canonical_claims_cross_node").await
        else {
            return;
        };
        let session = identity_session(
            "alice@example.com",
            Some(UpstreamIdentity {
                subject: "stable-opaque-subject".into(),
                explicit_email: Some("alice@example.com".into()),
                provenance: UpstreamIdentityProvenance::Oidc,
            }),
        );
        fixture.a.create_session(&session).await.unwrap();
        let decoded = fixture.b.get_session(session.id).await.unwrap();
        let mut route = sample_route("identity-claims", "https://app.example.com");
        route.enable_signed_identity = true;
        let authority = crate::identity::IdentityAuthority::from_boot(
            &GlobalConfig {
                auth_domain: Some("AUTH.example.com:443".into()),
                ..GlobalConfig::default()
            },
            std::slice::from_ref(&route),
        )
        .unwrap();
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let claims = authority
            .prepare_claims(
                route.signed_identity_input(),
                decoded.upstream_identity.as_ref().unwrap(),
                &decoded.groups,
                now,
            )
            .unwrap();
        assert_eq!(claims.sub, "stable-opaque-subject");
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.groups, ["operators"]);
        assert_eq!(claims.iss, "https://auth.example.com");
        assert_eq!(claims.aud, "https://app.example.com");
        assert_eq!(
            (claims.iat, claims.nbf, claims.exp),
            (1_700_000_000, 1_700_000_000, 1_700_000_300)
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_identity_fatal_before_listener() {
        let Some(fixture) = PgStoreFixture::new("identity_fatal_before_listener").await else {
            return;
        };
        fixture
            .a
            .update_config(serde_json::json!({"auth_domain": "auth.example.com"}))
            .await
            .unwrap();
        let mut legacy = sample_route("legacy-invalid", "http://legacy.example.com");
        fixture.a.create_route(&legacy).await.unwrap();
        legacy.enable_signed_identity = true;
        sqlx::query("UPDATE routes SET data = $1 WHERE id = $2")
            .bind(serde_json::to_string(&legacy).unwrap())
            .bind(legacy.id)
            .execute(&fixture.observer)
            .await
            .unwrap();

        let error = crate::startup::run_sync_checks(&fixture.b)
            .await
            .unwrap_err();
        assert!(matches!(error, crate::error::Error::ConfigurationError(_)));
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_identity_missing_email_has_no_side_effect() {
        let Some(fixture) = PgStoreFixture::new("identity_missing_email_no_side_effect").await
        else {
            return;
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut route = sample_route("missing-email", "https://missing-email.example.com");
        route.to = vec![format!("http://{}", listener.local_addr().unwrap())];
        route.access.allow_public_unauthenticated_access = true;
        route.enable_signed_identity = true;
        route.enabled = true;
        fixture.a.create_route(&route).await.unwrap();
        let session = identity_session(
            "fallback-subject",
            Some(UpstreamIdentity {
                subject: "fallback-subject".into(),
                explicit_email: None,
                provenance: UpstreamIdentityProvenance::Saml,
            }),
        );
        fixture.a.create_session(&session).await.unwrap();

        let provider = Arc::new(crate::tls::acme::challenge::Http01Provider::new(
            fixture.b.clone(),
        ));
        let acme = Arc::new(crate::tls::acme::AcmeManager::new(
            fixture.b.clone(),
            provider,
            "https://acme.invalid/directory",
            None,
        ));
        let generation =
            crate::route_generation::RouteGeneration::new_for_test(fixture.b.clone()).await;
        let cookie_secret = [0x76; 64];
        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let app = crate::proxy::router(
            fixture.b.clone(),
            generation,
            &cookie_secret,
            acme,
            MasterKey::from_test_bytes([0x77; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([0x78; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            100,
            Arc::clone(&shutdown),
        );
        let cookie = crate::session::cookie_manager::CookieManager::new(&cookie_secret)
            .with_name("sekisho_session".into())
            .create_cookie(session.id, SameSite::Lax);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "missing-email.example.com")
                    .header(header::COOKIE, cookie.split(';').next().unwrap())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], br#"{"error":"access denied"}"#);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        shutdown.signal();
        drop(app);
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_identity_route_concurrent_validation() {
        let Some(fixture) = PgStoreFixture::new("identity_route_concurrent_validation").await
        else {
            return;
        };
        let mut route = sample_route("concurrent-identity", "http://legacy.example.com");
        fixture.a.create_route(&route).await.unwrap();
        let version0 = fixture.a.route_version_current().await.unwrap();

        let update_origin = fixture.a.update_route(
            route.id,
            serde_json::json!({"from": "https://canonical.example.com"}),
        );
        let enable = fixture.b.update_route(
            route.id,
            serde_json::json!({"enable_signed_identity": true}),
        );
        let (origin_result, enable_result) = tokio::join!(update_origin, enable);
        assert!(origin_result.is_ok());
        if let Err(error) = &enable_result {
            assert!(matches!(error, crate::error::Error::BadRequest(_)));
        }

        route = fixture.b.get_route(route.id).await.unwrap();
        crate::identity::validate_route(route.signed_identity_input()).unwrap();
        assert_eq!(route.from, "https://canonical.example.com");
        let successes = 1 + usize::from(enable_result.is_ok());
        assert_eq!(
            fixture.b.route_version_current().await.unwrap(),
            version0 + successes as u64
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_policy_header_boundary_rejects_concurrent_writer_bypasses() {
        const UNSAFE: &str = r#"request.header.x_sekisho_user == "admin""#;
        const SAFE: &str = r#"claim.groups in ["operators"]"#;

        let Some(fixture) = PgStoreFixture::new("policy_header_boundary").await else {
            return;
        };

        let rejected_policy = Policy {
            id: Uuid::new_v4(),
            name: "rejected-policy".into(),
            expr: UNSAFE.into(),
        };
        assert!(matches!(
            fixture.a.create_policy(&rejected_policy).await,
            Err(crate::error::Error::BadRequest(_))
        ));
        let rejected_policy_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM policies WHERE id = $1")
                .bind(rejected_policy.id)
                .fetch_one(&fixture.observer)
                .await
                .unwrap();
        assert_eq!(rejected_policy_rows, 0);

        let policy = Policy {
            id: Uuid::new_v4(),
            name: "safe-policy".into(),
            expr: SAFE.into(),
        };
        fixture.a.create_policy(&policy).await.unwrap();
        let unsafe_update = fixture
            .a
            .update_policy(policy.id, serde_json::json!({"expr": UNSAFE}));
        let safe_update = fixture.b.update_policy(
            policy.id,
            serde_json::json!({"name": "safe-policy-updated"}),
        );
        let (unsafe_result, safe_result) = tokio::join!(unsafe_update, safe_update);
        assert!(matches!(
            unsafe_result,
            Err(crate::error::Error::BadRequest(_))
        ));
        assert_eq!(safe_result.unwrap().name, "safe-policy-updated");
        let stored_policy = fixture.a.get_policy(policy.id).await.unwrap();
        assert_eq!(stored_policy.expr, SAFE);
        assert_eq!(stored_policy.name, "safe-policy-updated");

        let mut route = sample_route("safe-route", "https://safe-route.example.com");
        route.access.policy = Some(SAFE.into());
        fixture.a.create_route(&route).await.unwrap();
        let version = fixture.a.route_version_current().await.unwrap();
        let unsafe_route_update = fixture.a.update_route(
            route.id,
            serde_json::json!({
                "access": {
                    "policy": UNSAFE,
                    "allow_public_unauthenticated_access": false
                }
            }),
        );
        let safe_route_update = fixture
            .b
            .update_route(route.id, serde_json::json!({"enabled": true}));
        let (unsafe_result, safe_result) = tokio::join!(unsafe_route_update, safe_route_update);
        assert!(matches!(
            unsafe_result,
            Err(crate::error::Error::BadRequest(_))
        ));
        assert!(safe_result.unwrap().enabled);
        let stored_route = fixture.a.get_route(route.id).await.unwrap();
        assert_eq!(stored_route.access.policy.as_deref(), Some(SAFE));
        assert!(stored_route.enabled);
        assert_eq!(
            fixture.a.route_version_current().await.unwrap(),
            version + 1
        );

        println!("LIVE_POSTGRES_FIXTURE_ACQUIRED:policy_header_boundary");
        fixture.close().await;
    }

    #[tokio::test]
    async fn two_nodes_see_peer_route_create() {
        let Some((a, b)) = two_nodes().await else {
            return;
        };

        let b_v0 = b.route_version_current().await.unwrap();
        let route = sample_route("peer-route", "https://peer.test.io");
        a.create_route(&route).await.unwrap();

        // Direct DB read sees it.
        let list_on_b = b.list_routes().await.unwrap();
        assert_eq!(list_on_b.len(), 1);
        assert_eq!(list_on_b[0].name, "peer-route");

        // Version counter on B moved — the background route observer reads it
        // with the route rows and publishes a replacement generation.
        let b_v1 = b.route_version_current().await.unwrap();
        assert!(
            b_v1 > b_v0,
            "peer route create should bump version seen by B (v0={b_v0}, v1={b_v1})"
        );
    }

    #[tokio::test]
    async fn postgres_route_observation_returns_version_and_rows_from_one_snapshot() {
        let Some((a, b)) = two_nodes().await else {
            return;
        };
        let empty = b.observe_routes().await.unwrap();
        assert_eq!(empty.version, 0);
        assert!(empty.routes.is_empty());

        let route = sample_route("coherent-route", "https://coherent.test.io");
        a.create_route(&route).await.unwrap();
        let observed = b.observe_routes().await.unwrap();
        assert_eq!(observed.version, 1);
        assert_eq!(observed.routes.len(), 1);
        assert_eq!(observed.routes[0].id, route.id);
    }

    #[tokio::test]
    async fn postgres_route_observation_is_one_correlated_old_or_new_tuple() {
        let Some((a, b)) = two_nodes().await else {
            return;
        };
        let mut route = sample_route("coherent-old", "https://old.test.io");
        a.create_route(&route).await.unwrap();
        let old = b.observe_routes().await.unwrap();
        assert_eq!(
            (old.version, old.routes[0].name.as_str()),
            (1, "coherent-old")
        );

        let pool = match &a.backend {
            Backend::Postgres(backend) => backend.pool_for_rotation(),
            _ => panic!("shared fixture must use Postgres"),
        };
        let mut transaction = pool.begin().await.unwrap();
        route.name = "coherent-new".into();
        route.from = "https://new.test.io".into();
        sqlx::query("UPDATE routes SET name = $1, data = $2 WHERE id = $3")
            .bind(&route.name)
            .bind(serde_json::to_string(&route).unwrap())
            .bind(route.id)
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("UPDATE schema_versions SET version = version + 1 WHERE resource = $1")
            .bind("routes")
            .execute(&mut *transaction)
            .await
            .unwrap();

        // The peer's single statement runs while the complete replacement is
        // uncommitted, so its statement snapshot must return the complete old
        // tuple rather than a new row paired with the old version.
        let during = b.observe_routes().await.unwrap();
        assert_eq!(
            (during.version, during.routes[0].name.as_str()),
            (1, "coherent-old")
        );

        transaction.commit().await.unwrap();
        let after = b.observe_routes().await.unwrap();
        assert_eq!(
            (after.version, after.routes[0].name.as_str()),
            (2, "coherent-new")
        );
        assert_eq!(after.routes[0].from, "https://new.test.io");
    }

    #[tokio::test]
    async fn route_generation_shutdown_cancels_active_pool_wait_and_returns_connections() {
        let Some((store, _peer)) = two_nodes().await else {
            return;
        };
        let pool = match &store.backend {
            Backend::Postgres(backend) => backend.pool_for_rotation().clone(),
            _ => panic!("shared fixture must use Postgres"),
        };
        let mut held = Vec::new();
        for _ in 0..10 {
            held.push(pool.acquire().await.unwrap());
        }

        let shutdown = Arc::new(crate::shutdown::ShutdownController::new());
        let generation = crate::route_generation::RouteGeneration::new(store.clone());
        generation.spawn(&shutdown);
        assert_eq!(shutdown.tracked_task_count(), 1);
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        shutdown.signal();
        tokio::time::timeout(
            Duration::from_secs(1),
            shutdown.join_tracked_tasks(Duration::from_secs(1)),
        )
        .await
        .expect("route observer must cancel its active pool acquisition");
        drop(held);

        tokio::time::timeout(Duration::from_secs(1), store.ping())
            .await
            .expect("pool must remain reusable after observer cancellation")
            .unwrap();
    }

    #[tokio::test]
    async fn two_nodes_see_peer_idp_update() {
        let Some((a, b)) = two_nodes().await else {
            return;
        };

        let idp = sample_idp("peer-idp");
        a.create_idp(&idp).await.unwrap();
        let b_v0 = b.idp_version_current().await.unwrap();

        a.update_idp(idp.id, serde_json::json!({"name": "peer-idp-renamed"}))
            .await
            .unwrap();

        // B reads the renamed record.
        let fetched = b.get_idp(idp.id).await.unwrap();
        assert_eq!(fetched.name, "peer-idp-renamed");

        // And B's version moved so its IdP client cache invalidates
        // on the next proxy generation check.
        let b_v1 = b.idp_version_current().await.unwrap();
        assert!(b_v1 > b_v0, "update on A should bump version on B");
    }

    #[tokio::test]
    async fn two_nodes_see_peer_config_change() {
        let Some((a, b)) = two_nodes().await else {
            return;
        };

        // Prime B's config cache so we can observe it getting
        // invalidated — without this the first read after A's write
        // would load the new value simply because there was no cache
        // yet, which wouldn't prove anything.
        let _ = b.get_config().await.unwrap();

        a.update_config(serde_json::json!({"session_lifetime_hours": 42}))
            .await
            .unwrap();

        let reloaded = b.get_config().await.unwrap();
        assert_eq!(
            reloaded.session_lifetime_hours, 42,
            "B should see A's config update after version-check reload"
        );
    }

    #[tokio::test]
    async fn version_bump_is_tx_bound() {
        // When an update fails — here via a unique-name conflict on
        // rename — the tx rolls back and the version counter must stay
        // put. Otherwise readers would needlessly invalidate their cache
        // and peers would see spurious version movement.
        let Some((a, _b)) = two_nodes().await else {
            return;
        };

        let r1 = sample_route("keep", "https://k.test.io");
        let r2 = sample_route("taken", "https://t.test.io");
        a.create_route(&r1).await.unwrap();
        a.create_route(&r2).await.unwrap();

        let v_before = a.route_version_current().await.unwrap();

        // Try to rename r1 to the name r2 already holds — the UNIQUE
        // constraint must reject the UPDATE and the tx must roll back.
        let result = a
            .update_route(r1.id, serde_json::json!({"name": "taken"}))
            .await;
        assert!(result.is_err(), "rename onto existing name should fail");

        let v_after = a.route_version_current().await.unwrap();
        assert_eq!(
            v_after, v_before,
            "failed update must not bump version (before={v_before}, after={v_after})"
        );
    }

    #[tokio::test]
    async fn concurrent_node_reads_same_challenge() {
        // The whole point of moving ACME challenges into the service DB
        // is so a Let's Encrypt validator that hits the non-leader via
        // DNS round-robin still gets a 200. The minimal guarantee: a
        // challenge written by node A is visible to node B immediately,
        // with no cache-warming or version-bump required (challenges
        // are short-lived and don't participate in the version machinery).
        let Some((a, b)) = two_nodes().await else {
            return;
        };

        a.set_acme_challenge("shared-token", "shared-auth", "ha.example")
            .await
            .unwrap();

        let seen_by_b = b.get_acme_challenge("shared-token").await.unwrap();
        assert_eq!(
            seen_by_b.as_deref(),
            Some("shared-auth"),
            "challenge written on A must be readable on B (DNS round-robin safety)"
        );

        // Cleanup on B clears it for A too — same underlying row.
        b.delete_acme_challenges_for_domain("ha.example")
            .await
            .unwrap();
        assert!(
            a.get_acme_challenge("shared-token")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn concurrent_account_credentials_have_one_durable_winner() {
        let Some(fixture) = PgStoreFixture::new("sekisho_acme_account_race").await else {
            return;
        };
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let a = fixture.a.clone();
        let a_barrier = barrier.clone();
        let a_task = tokio::spawn(async move {
            a_barrier.wait().await;
            a.insert_acme_account_credentials_if_absent(account_credentials(b"candidate-a"))
                .await
        });
        let b = fixture.b.clone();
        let b_barrier = barrier.clone();
        let b_task = tokio::spawn(async move {
            b_barrier.wait().await;
            b.insert_acme_account_credentials_if_absent(account_credentials(b"candidate-b"))
                .await
        });
        barrier.wait().await;

        let outcomes = [
            a_task.await.unwrap().unwrap(),
            b_task.await.unwrap().unwrap(),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, AcmeAccountCredentialInsert::Inserted))
                .count(),
            1
        );
        let durable = fixture
            .a
            .load_acme_account_credentials()
            .await
            .unwrap()
            .unwrap();
        let loser = outcomes
            .iter()
            .find_map(|outcome| match outcome {
                AcmeAccountCredentialInsert::Existing(credentials) => Some(credentials.as_bytes()),
                AcmeAccountCredentialInsert::Inserted => None,
            })
            .unwrap();
        assert_eq!(loser, durable.as_bytes());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM secrets WHERE key = $1",)
                .bind(ACCOUNT_CREDENTIALS_KEY)
                .fetch_one(&fixture.observer)
                .await
                .unwrap(),
            1
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn cancelled_account_credential_insert_rolls_back() {
        let Some(fixture) = PgStoreFixture::new("sekisho_acme_account_cancel").await else {
            return;
        };
        let advisory_key = unique_advisory_key();
        let mut blocker = hold_advisory_lock(&fixture.observer, advisory_key).await;
        install_insert_barrier(
            &fixture.observer,
            "secrets",
            "block_acme_account_insert",
            "block_acme_account_insert_fn",
            advisory_key,
        )
        .await;

        let store = fixture.a.clone();
        let task = tokio::spawn(async move {
            store
                .insert_acme_account_credentials_if_absent(account_credentials(b"cancelled"))
                .await
        });
        wait_for_blocked_query(&fixture.observer, &fixture.app_a, "INSERT INTO secrets", 1).await;
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        release_advisory_lock(&mut blocker, advisory_key).await;

        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(5),
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM secrets WHERE key = $1",)
                    .bind(ACCOUNT_CREDENTIALS_KEY)
                    .fetch_one(&fixture.observer),
            )
            .await
            .expect("cancelled insert rollback must become visible")
            .unwrap(),
            0
        );
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(5),
                fixture
                    .b
                    .insert_acme_account_credentials_if_absent(account_credentials(
                        b"recovery-winner",
                    )),
            )
            .await
            .expect("next writer must not hang")
            .unwrap(),
            AcmeAccountCredentialInsert::Inserted
        ));
        fixture.close().await;
    }

    #[tokio::test]
    async fn concurrent_route_create() {
        // Two nodes creating different routes simultaneously should
        // both succeed, and the version counter should advance by
        // exactly two — one per committed mutation. This is the
        // minimum sanity check for the read-committed + row-lock
        // story on the Postgres side.
        let Some((a, b)) = two_nodes().await else {
            return;
        };

        let v_before = a.route_version_current().await.unwrap();

        let fa = {
            let a = a.clone();
            tokio::spawn(async move {
                let r = sample_route("conc-a", "https://a.test.io");
                a.create_route(&r).await
            })
        };
        let fb = {
            let b = b.clone();
            tokio::spawn(async move {
                let r = sample_route("conc-b", "https://b2.test.io");
                b.create_route(&r).await
            })
        };

        fa.await.unwrap().unwrap();
        fb.await.unwrap().unwrap();

        let v_after = a.route_version_current().await.unwrap();
        assert_eq!(
            v_after - v_before,
            2,
            "two commits should bump version by 2 (before={v_before}, after={v_after})"
        );

        assert_eq!(b.list_routes().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn two_nodes_share_pending_auth() {
        // This is the regression test for the PendingAuth HA bug:
        // `/saml/login` lands on node A, ACS POST comes back to node B,
        // and we need B to find the record A wrote. With the old
        // process-local HashMap this test would have been impossible
        // (each node had its own empty map). With the DB-backed store
        // B should now see it.
        let Some((a, b)) = two_nodes().await else {
            return;
        };

        let idp_id = uuid::Uuid::new_v4();
        let state = crate::auth::middleware::PendingAuth {
            idp_id,
            nonce: "n-value".into(),
            code_verifier: "v-value".into(),
            redirect_url: "https://app.example.com/dash".into(),
            created_at: chrono::Utc::now(),
            saml_authn_request_id: Some("_abc123".into()),
            kind: crate::auth::middleware::PendingAuthKind::Login,
            browser_nonce_hash: Some("browser-hash".into()),
        };

        a.pending_auth_insert("csrf-token-xyz", &state)
            .await
            .expect("insert on A");

        let read_on_b = b
            .pending_auth_get("csrf-token-xyz")
            .await
            .expect("get on B")
            .expect("B must see the row A wrote");

        assert_eq!(read_on_b.idp_id, idp_id);
        assert_eq!(read_on_b.nonce, "n-value");
        assert_eq!(read_on_b.code_verifier, "v-value");
        assert_eq!(read_on_b.redirect_url, "https://app.example.com/dash");
        assert_eq!(read_on_b.saml_authn_request_id.as_deref(), Some("_abc123"));
        assert_eq!(
            read_on_b.browser_nonce_hash.as_deref(),
            Some("browser-hash")
        );
        assert!(
            a.pending_auth_get("csrf-token-xyz")
                .await
                .expect("get on A")
                .is_some(),
            "peer get must leave the shared row intact"
        );

        let (taken_on_a, taken_on_b) = tokio::join!(
            a.pending_auth_take("csrf-token-xyz"),
            b.pending_auth_take("csrf-token-xyz")
        );
        let winners = [taken_on_a, taken_on_b]
            .into_iter()
            .map(|result| result.expect("concurrent take"))
            .filter(Option::is_some)
            .count();
        assert_eq!(winners, 1, "exactly one peer may consume the row");
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:pre_auth_two_node_concurrent_callback");
    }

    #[tokio::test]
    async fn two_nodes_transition_auth_start_exactly_once() {
        use crate::auth::middleware::{AuthStateStore, PendingAuth, PendingAuthKind};

        let Some((a, b)) = two_nodes().await else {
            return;
        };
        const AUTH_DOMAIN: &str = "auth-ha.example.com";
        const TEST_CERT_DER: &[u8] =
            include_bytes!("../../../../vendor/auth-idp/src/saml/testdata/saml_test.crt.der");
        let cert_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, TEST_CERT_DER);
        let metadata = format!(
            r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp-ha.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp-ha.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind metadata server");
        let metadata_url = format!("http://{}/metadata", listener.local_addr().unwrap());
        let metadata_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let metadata = metadata.clone();
                tokio::spawn(async move {
                    let mut request = [0_u8; 2048];
                    let _ = socket.read(&mut request).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/samlmetadata+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        metadata.len(),
                        metadata
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });

        a.update_config(serde_json::json!({ "auth_domain": AUTH_DOMAIN }))
            .await
            .unwrap();
        let idp_id = uuid::Uuid::new_v4();
        a.create_idp(&IdentityProvider {
            id: idp_id,
            name: "ha-saml".into(),
            idp_type: IdpType::Saml,
            oidc_config: None,
            saml_config: Some(SamlConfig {
                metadata_url,
                slo_url: None,
                name_id_format: None,
                attribute_mapping: Default::default(),
            }),
        })
        .await
        .unwrap();
        let auth_start = PendingAuth {
            idp_id,
            nonce: String::new(),
            code_verifier: String::new(),
            redirect_url: "https://app.example.com/dash".into(),
            created_at: chrono::Utc::now(),
            saml_authn_request_id: None,
            kind: PendingAuthKind::AuthStart,
            browser_nonce_hash: None,
        };
        a.pending_auth_insert("auth-start-ha", &auth_start)
            .await
            .unwrap();

        let challenge_a = Arc::new(crate::tls::acme::challenge::Http01Provider::new(a.clone()));
        let acme_a = Arc::new(crate::tls::acme::AcmeManager::new(
            a.clone(),
            challenge_a,
            "https://acme.invalid/directory",
            None,
        ));
        let generation_a = crate::route_generation::RouteGeneration::new_for_test(a.clone()).await;
        let router_a = crate::proxy::router(
            a.clone(),
            generation_a,
            &[0x24; 32],
            acme_a,
            crate::crypto::MasterKey::from_test_bytes([0x42; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([0x81; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(AUTH_DOMAIN)),
            true,
            "sekisho_session".into(),
            100,
            Arc::new(crate::shutdown::ShutdownController::new()),
        );
        let challenge_b = Arc::new(crate::tls::acme::challenge::Http01Provider::new(b.clone()));
        let acme_b = Arc::new(crate::tls::acme::AcmeManager::new(
            b.clone(),
            challenge_b,
            "https://acme.invalid/directory",
            None,
        ));
        let generation_b = crate::route_generation::RouteGeneration::new_for_test(b.clone()).await;
        let router_b = crate::proxy::router(
            b.clone(),
            generation_b,
            &[0x24; 32],
            acme_b,
            crate::crypto::MasterKey::from_test_bytes([0x42; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([0x81; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(AUTH_DOMAIN)),
            true,
            "sekisho_session".into(),
            100,
            Arc::new(crate::shutdown::ShutdownController::new()),
        );
        let request = || {
            Request::builder()
                .uri("/.sekisho/auth-start?t=auth-start-ha")
                .header(header::HOST, AUTH_DOMAIN)
                .body(Body::empty())
                .unwrap()
        };
        let (left, right) = tokio::join!(router_a.oneshot(request()), router_b.oneshot(request()));
        let responses = [left.unwrap(), right.unwrap()];
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.status() == StatusCode::FOUND)
                .count(),
            1,
            "exactly one node may return the IdP redirect"
        );
        let loser = responses
            .iter()
            .find(|response| response.status() != StatusCode::FOUND)
            .expect("one transition loser");
        assert_eq!(loser.status(), StatusCode::BAD_REQUEST);
        assert!(loser.headers().get(header::SET_COOKIE).is_none());
        assert!(loser.headers().get(header::LOCATION).is_none());
        let winner = responses
            .iter()
            .find(|response| response.status() == StatusCode::FOUND)
            .unwrap();
        assert!(winner.headers().get(header::SET_COOKIE).is_some());
        let login_token = url::Url::parse(
            winner
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap()
        .query_pairs()
        .find_map(|(name, value)| (name == "RelayState").then(|| value.into_owned()))
        .expect("winner RelayState");
        assert!(a.pending_auth_get("auth-start-ha").await.unwrap().is_none());
        assert_eq!(
            b.pending_auth_get(&login_token)
                .await
                .unwrap()
                .expect("one shared Login row")
                .kind,
            PendingAuthKind::Login
        );

        let login = PendingAuth {
            idp_id,
            nonce: "occupied".into(),
            code_verifier: "occupied".into(),
            redirect_url: auth_start.redirect_url.clone(),
            created_at: chrono::Utc::now(),
            saml_authn_request_id: None,
            kind: PendingAuthKind::Login,
            browser_nonce_hash: Some("occupied".into()),
        };
        a.pending_auth_insert("auth-start-conflict-ha", &auth_start)
            .await
            .unwrap();
        a.pending_auth_insert("occupied-login-ha", &login)
            .await
            .unwrap();
        AuthStateStore::new(b.clone())
            .transition_auth_start("auth-start-conflict-ha", "occupied-login-ha", login.clone())
            .await
            .expect_err("strict Login collision must fail");
        assert!(
            a.pending_auth_get("auth-start-conflict-ha")
                .await
                .unwrap()
                .is_some(),
            "insert failure must roll back AuthStart consume"
        );
        assert_eq!(
            b.pending_auth_get("occupied-login-ha")
                .await
                .unwrap()
                .expect("collision row remains")
                .nonce,
            "occupied"
        );
        metadata_task.abort();
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:pre_auth_start_atomic_transition");
    }

    #[tokio::test]
    async fn pending_auth_ttl_expired_rows_are_invisible() {
        // A row written with a created_at far in the past must read
        // as absent — the TTL check is load-bearing for the "expired
        // or forged" branch in the ACS handler.
        let Some((a, _b)) = two_nodes().await else {
            return;
        };

        let state = crate::auth::middleware::PendingAuth {
            idp_id: uuid::Uuid::new_v4(),
            nonce: String::new(),
            code_verifier: String::new(),
            redirect_url: "/".into(),
            // One hour in the past — well past the 10-minute TTL.
            created_at: chrono::Utc::now() - chrono::Duration::hours(1),
            saml_authn_request_id: None,
            kind: crate::auth::middleware::PendingAuthKind::Login,
            browser_nonce_hash: None,
        };
        a.pending_auth_insert("stale", &state).await.unwrap();

        let read = a.pending_auth_get("stale").await.unwrap();
        assert!(read.is_none(), "expired row must be invisible to get");
        assert!(
            a.pending_auth_take("stale").await.unwrap().is_none(),
            "expired row must remain invisible to take"
        );

        // Sweeper is the other path to removal; either way the row is
        // gone after this.
        let _ = a.pending_auth_cleanup_expired().await.unwrap();
    }

    #[tokio::test]
    async fn two_nodes_see_peer_cert_upsert() {
        // Cert cache invalidation: a renewal on node A bumps
        // `cert_version`, and a non-leader node B uses that signal
        // to reload its in-process `CertResolver`. We exercise the
        // Store-level piece here (DB write + version bump + peer-side
        // current read); the resolver wiring is glued on top in main.rs
        // and depends on the same contract tested below.
        let Some((a, b)) = two_nodes().await else {
            return;
        };

        let v_before = b.cert_version_current().await.unwrap();

        let cert = crate::models::cert::Certificate {
            id: uuid::Uuid::new_v4(),
            domain: "ha.example".into(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n".into(),
            key_pem_encrypted: "stub-key".into(),
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(90),
            source: crate::models::cert::CertSource::Acme,
        };
        a.upsert_cert(&cert).await.unwrap();

        // B sees the row in the service DB.
        let list_on_b = b.list_certs().await.unwrap();
        assert!(list_on_b.iter().any(|c| c.domain == "ha.example"));

        // And B's version moved — the signal `CertResolver::reload_if_stale`
        // watches to drop its SNI cache.
        let v_after = b.cert_version_current().await.unwrap();
        assert!(
            v_after > v_before,
            "peer cert upsert must bump cert_version on B (before={v_before}, after={v_after})"
        );
    }

    #[tokio::test]
    async fn two_nodes_see_peer_cert_delete() {
        let Some((a, b)) = two_nodes().await else {
            return;
        };

        let cert = crate::models::cert::Certificate {
            id: uuid::Uuid::new_v4(),
            domain: "del.example".into(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n".into(),
            key_pem_encrypted: "stub-key".into(),
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(90),
            source: crate::models::cert::CertSource::Upload,
        };
        a.upsert_cert(&cert).await.unwrap();
        let v_mid = b.cert_version_current().await.unwrap();

        a.delete_cert(cert.id).await.unwrap();
        let v_after = b.cert_version_current().await.unwrap();
        assert!(
            v_after > v_mid,
            "peer cert delete must bump cert_version on B (mid={v_mid}, after={v_after})"
        );
    }

    /// Non-leader enqueues an ACME request; leader picks it up from
    /// the shared queue; a completion write on the leader is visible
    /// to the original requester on its next poll. End-to-end
    /// verification that `POST /certs` → queue → pick → complete
    /// works across two processes sharing Postgres.
    #[tokio::test]
    async fn queue_row_crosses_nodes() {
        let Some((a, b)) = two_nodes().await else {
            return;
        };
        eprintln!("LIVE_POSTGRES_QUEUE_CROSS_NODE_ACQUIRED");

        // A (non-leader here) enqueues; the row must be visible to B
        // immediately without any local cache or version counter.
        let row = admitted(
            a.acme_queue_enqueue("cross.example", "node-a")
                .await
                .unwrap(),
        );

        // B acts as leader and picks the row.
        let picked = b
            .acme_queue_pick_next(chrono::Duration::minutes(10), 5)
            .await
            .unwrap()
            .expect("B should see A's pending row");
        assert_eq!(picked.id, row.id);
        assert_eq!(
            picked.status,
            crate::models::acme_queue::AcmeQueueStatus::InProgress
        );

        // B records completion. The cert id is synthetic here — the
        // test is asserting queue flow, not that a real cert row
        // exists. result_cert_id is just a foreign-ish key today.
        let fake_cert_id = uuid::Uuid::new_v4();
        b.acme_queue_mark_completed(row.id, fake_cert_id)
            .await
            .unwrap();

        // A polls and sees the completion.
        let seen_by_a = a.acme_queue_get(row.id).await.unwrap().expect("row");
        assert_eq!(
            seen_by_a.status,
            crate::models::acme_queue::AcmeQueueStatus::Completed
        );
        assert_eq!(seen_by_a.result_cert_id, Some(fake_cert_id));
    }

    /// Capacity is a cluster-wide active-row limit. Two nodes racing distinct
    /// domains at the last slot must produce one durable winner and one Full;
    /// a duplicate of the winner still resolves to Existing after saturation.
    #[tokio::test]
    async fn concurrent_queue_capacity_has_one_winner_and_dedup_bypasses_full() {
        let Some(fixture) = PgBootstrapFixture::new("sekisho_queue_capacity").await else {
            return;
        };
        eprintln!("LIVE_POSTGRES_QUEUE_CAPACITY_ACQUIRED");
        fixture
            .a
            .update_config(serde_json::json!({"acme_queue_capacity": 1}))
            .await
            .unwrap();

        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let a = fixture.a.clone();
        let a_barrier = barrier.clone();
        let a_task = tokio::spawn(async move {
            a_barrier.wait().await;
            a.acme_queue_enqueue("capacity-a.example", "node-a").await
        });
        let b = fixture.b.clone();
        let b_barrier = barrier.clone();
        let b_task = tokio::spawn(async move {
            b_barrier.wait().await;
            b.acme_queue_enqueue("capacity-b.example", "node-b").await
        });
        barrier.wait().await;

        let first = a_task.await.unwrap().unwrap();
        let second = b_task.await.unwrap().unwrap();
        let winner = match (first, second) {
            (
                crate::models::acme_queue::AcmeQueueAdmission::Inserted(row),
                crate::models::acme_queue::AcmeQueueAdmission::Full,
            )
            | (
                crate::models::acme_queue::AcmeQueueAdmission::Full,
                crate::models::acme_queue::AcmeQueueAdmission::Inserted(row),
            ) => row,
            other => panic!("expected exactly one inserted row and one full result: {other:?}"),
        };

        let duplicate = fixture
            .b
            .acme_queue_enqueue(&winner.domain, "node-after")
            .await
            .unwrap();
        assert!(matches!(
            duplicate,
            crate::models::acme_queue::AcmeQueueAdmission::Existing(ref row)
                if row.id == winner.id
        ));

        let observer = PgPool::connect(&fixture.scoped_url).await.unwrap();
        let active = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM acme_queue WHERE status IN ('pending', 'in_progress')",
        )
        .fetch_one(&observer)
        .await
        .unwrap();
        assert_eq!(active, 1);
        observer.close().await;
        fixture.close().await;
    }

    /// Two nodes racing to claim work share the durable in-progress limit.
    /// The transaction that resets stale rows, counts live slots, and claims
    /// one pending row must serialize cluster-wide.
    #[tokio::test]
    async fn concurrent_queue_picks_never_exceed_the_durable_slot_limit() {
        let Some(fixture) = PgBootstrapFixture::new("sekisho_queue_slots").await else {
            return;
        };
        eprintln!("LIVE_POSTGRES_QUEUE_SLOT_RACE_ACQUIRED");
        fixture
            .a
            .acme_queue_enqueue("slot-a.example", "node-a")
            .await
            .unwrap();
        fixture
            .a
            .acme_queue_enqueue("slot-b.example", "node-a")
            .await
            .unwrap();

        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let a = fixture.a.clone();
        let a_barrier = barrier.clone();
        let a_task = tokio::spawn(async move {
            a_barrier.wait().await;
            a.acme_queue_pick_next(chrono::Duration::minutes(10), 1)
                .await
        });
        let b = fixture.b.clone();
        let b_barrier = barrier.clone();
        let b_task = tokio::spawn(async move {
            b_barrier.wait().await;
            b.acme_queue_pick_next(chrono::Duration::minutes(10), 1)
                .await
        });
        barrier.wait().await;

        let first = a_task.await.unwrap().unwrap();
        let second = b_task.await.unwrap().unwrap();
        assert!(
            matches!((&first, &second), (Some(_), None) | (None, Some(_))),
            "exactly one peer may reserve the only durable slot: {first:?} {second:?}"
        );

        let observer = PgPool::connect(&fixture.scoped_url).await.unwrap();
        let in_progress = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM acme_queue WHERE status = 'in_progress'",
        )
        .fetch_one(&observer)
        .await
        .unwrap();
        assert_eq!(in_progress, 1);
        observer.close().await;
        fixture.close().await;
    }

    #[tokio::test]
    async fn two_nodes_read_the_same_nonmutating_durable_acme_budget_snapshot() {
        let Some(fixture) = PgStoreFixture::new("sekisho_durable_acme_metrics").await else {
            return;
        };
        eprintln!("LIVE_POSTGRES_DURABLE_ACME_METRICS_ACQUIRED");

        let fresh = admitted(
            fixture
                .a
                .acme_queue_enqueue("metrics-fresh.example", "node-a")
                .await
                .unwrap(),
        );
        let stale = admitted(
            fixture
                .a
                .acme_queue_enqueue("metrics-stale.example", "node-a")
                .await
                .unwrap(),
        );
        let missing_pick_time = admitted(
            fixture
                .a
                .acme_queue_enqueue("metrics-missing-time.example", "node-a")
                .await
                .unwrap(),
        );
        fixture
            .a
            .acme_queue_enqueue("metrics-pending.example", "node-a")
            .await
            .unwrap();

        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(10);
        sqlx::query("UPDATE acme_queue SET status = 'in_progress', picked_at = $1 WHERE id = $2")
            .bind((cutoff + chrono::Duration::seconds(1)).timestamp())
            .bind(fresh.id)
            .execute(&fixture.observer)
            .await
            .unwrap();
        sqlx::query("UPDATE acme_queue SET status = 'in_progress', picked_at = $1 WHERE id = $2")
            .bind((cutoff - chrono::Duration::seconds(1)).timestamp())
            .bind(stale.id)
            .execute(&fixture.observer)
            .await
            .unwrap();
        sqlx::query("UPDATE acme_queue SET status = 'in_progress', picked_at = NULL WHERE id = $1")
            .bind(missing_pick_time.id)
            .execute(&fixture.observer)
            .await
            .unwrap();
        sqlx::query("DELETE FROM global_config")
            .execute(&fixture.observer)
            .await
            .unwrap();

        let (a, b) = tokio::join!(
            fixture.a.acme_budget_snapshot(cutoff),
            fixture.b.acme_budget_snapshot(cutoff),
        );
        let a = a.unwrap();
        let b = b.unwrap();
        assert_eq!(a, b);
        assert_eq!(a.queue_active, 4);
        assert_eq!(a.queue_capacity, 1_000);
        assert_eq!(a.issuance_in_progress, 2);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM global_config")
                .fetch_one(&fixture.observer)
                .await
                .unwrap(),
            0,
            "peer scrapes must not seed the default row"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM acme_queue WHERE status = 'in_progress'",
            )
            .fetch_one(&fixture.observer)
            .await
            .unwrap(),
            3,
            "peer scrapes must not recycle stale rows"
        );

        fixture
            .a
            .update_config(serde_json::json!({"acme_queue_capacity": 12}))
            .await
            .unwrap();
        let updated = fixture.b.acme_budget_snapshot(cutoff).await.unwrap();
        assert_eq!(updated.queue_capacity, 12);
        assert_eq!(updated.queue_active, 4);
        assert_eq!(updated.issuance_in_progress, 2);

        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_durable_budget_snapshot_never_returns_a_torn_tuple() {
        const PHASE_TIMEOUT: Duration = Duration::from_secs(5);
        let Some(fixture) = PgStoreFixture::new("sekisho_durable_acme_metrics_atomic").await else {
            return;
        };
        eprintln!("LIVE_POSTGRES_DURABLE_ACME_METRICS_ATOMIC_ACQUIRED");

        fixture
            .a
            .update_config(serde_json::json!({"acme_queue_capacity": 10}))
            .await
            .unwrap();
        fixture
            .a
            .acme_queue_enqueue("metrics-old.example", "node-a")
            .await
            .unwrap();
        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(10);
        let old = crate::store::backend::AcmeBudgetSnapshot {
            queue_active: 1,
            queue_capacity: 10,
            issuance_in_progress: 0,
        };
        let new = crate::store::backend::AcmeBudgetSnapshot {
            queue_active: 2,
            queue_capacity: 20,
            issuance_in_progress: 0,
        };

        let backend = match &fixture.b.backend {
            Backend::Postgres(backend) => backend,
            _ => panic!("live fixture must use Postgres"),
        };
        let (hook, guard) = backend.install_acme_budget_snapshot_test_hook();

        // The hook belongs only to node B. A snapshot from node A must not
        // observe or consume either rendezvous phase.
        let isolated_peer =
            tokio::time::timeout(PHASE_TIMEOUT, fixture.a.acme_budget_snapshot(cutoff))
                .await
                .expect("unhooked peer snapshot must not wait")
                .unwrap();
        assert_eq!(isolated_peer, old);

        let peer = fixture.b.clone();
        let mut snapshot = tokio::spawn(async move { peer.acme_budget_snapshot(cutoff).await });
        let exercise = async {
            tokio::time::timeout(PHASE_TIMEOUT, hook.wait_until_statement_read())
                .await
                .map_err(|_| "snapshot did not reach its terminal statement hook".to_owned())?;

            // The backend session's immediately preceding query is runtime
            // evidence that all three values came from one SELECT. A split
            // implementation leaves its final config-only SELECT here even
            // when the synchronization call remains at this terminal locus.
            let atomic_statement = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                 WHERE application_name = $1 AND state = 'idle' \
                   AND query LIKE 'SELECT %' \
                   AND query LIKE '%acme_queue%' \
                   AND query LIKE '%global_config%' \
                   AND query LIKE '%picked_at%')",
            )
            .bind(&fixture.app_b)
            .fetch_one(&fixture.observer)
            .await
            .map_err(|error| format!("inspect snapshot statement: {error}"))?;

            let mut tx = fixture
                .observer
                .begin()
                .await
                .map_err(|error| format!("begin correlated update: {error}"))?;
            sqlx::query(
                "INSERT INTO acme_queue (id, domain, requester_node, status, enqueued_at) \
                 VALUES ($1, $2, $3, 'pending', $4)",
            )
            .bind(Uuid::new_v4())
            .bind("metrics-new.example")
            .bind("node-a")
            .bind(chrono::Utc::now().timestamp())
            .execute(&mut *tx)
            .await
            .map_err(|error| format!("insert correlated queue row: {error}"))?;
            let new_config = GlobalConfig {
                acme_queue_capacity: 20,
                ..GlobalConfig::default()
            };
            sqlx::query("UPDATE global_config SET data = $1 WHERE id = 1")
                .bind(serde_json::to_string(&new_config).unwrap())
                .execute(&mut *tx)
                .await
                .map_err(|error| format!("update correlated capacity: {error}"))?;
            tx.commit()
                .await
                .map_err(|error| format!("commit correlated update: {error}"))?;
            hook.resume_snapshot();

            let observed = tokio::time::timeout(PHASE_TIMEOUT, &mut snapshot)
                .await
                .map_err(|_| "snapshot task did not finish after resume".to_owned())?
                .map_err(|error| format!("snapshot task join failed: {error}"))?
                .map_err(|error| format!("snapshot method failed: {error}"))?;
            let after = fixture
                .a
                .acme_budget_snapshot(cutoff)
                .await
                .map_err(|error| format!("read committed tuple: {error}"))?;
            Ok::<_, String>((atomic_statement, observed, after))
        }
        .await;

        let snapshot_pending = !snapshot.is_finished();
        if snapshot_pending {
            snapshot.abort();
        }
        drop(guard);
        if snapshot_pending {
            let _ = tokio::time::timeout(PHASE_TIMEOUT, snapshot).await;
        }

        let guard_controls = if exercise.is_ok() {
            async {
                // Dropping an armed guard must wake a snapshot already paused
                // in the backend and leave the slot reusable. The same Drop
                // path runs during ordinary return, error propagation, and
                // panic unwind.
                let (drop_hook, drop_guard) = backend.install_acme_budget_snapshot_test_hook();
                let drop_peer = fixture.b.clone();
                let mut drop_task =
                    tokio::spawn(async move { drop_peer.acme_budget_snapshot(cutoff).await });
                if tokio::time::timeout(PHASE_TIMEOUT, drop_hook.wait_until_statement_read())
                    .await
                    .is_err()
                {
                    drop_task.abort();
                    drop(drop_guard);
                    let _ = tokio::time::timeout(PHASE_TIMEOUT, drop_task).await;
                    return Err("guard-drop snapshot did not reach rendezvous".to_owned());
                }
                drop(drop_guard);
                let drop_result = tokio::time::timeout(PHASE_TIMEOUT, &mut drop_task).await;
                if drop_result.is_err() {
                    drop_task.abort();
                    let _ = tokio::time::timeout(PHASE_TIMEOUT, drop_task).await;
                    return Err("guard Drop did not disarm a paused snapshot".to_owned());
                }
                drop_result
                    .unwrap()
                    .map_err(|error| format!("guard-drop snapshot join failed: {error}"))?
                    .map_err(|error| format!("guard-drop snapshot failed: {error}"))?;

                // Task cancellation followed by guard Drop must also clear
                // the slot; a plain snapshot must then complete unaided.
                let (abort_hook, abort_guard) = backend.install_acme_budget_snapshot_test_hook();
                let abort_peer = fixture.b.clone();
                let abort_task =
                    tokio::spawn(async move { abort_peer.acme_budget_snapshot(cutoff).await });
                if tokio::time::timeout(PHASE_TIMEOUT, abort_hook.wait_until_statement_read())
                    .await
                    .is_err()
                {
                    abort_task.abort();
                    drop(abort_guard);
                    let _ = tokio::time::timeout(PHASE_TIMEOUT, abort_task).await;
                    return Err("abort snapshot did not reach rendezvous".to_owned());
                }
                abort_task.abort();
                drop(abort_guard);
                let aborted = tokio::time::timeout(PHASE_TIMEOUT, abort_task)
                    .await
                    .map_err(|_| "aborted snapshot task did not terminate".to_owned())?;
                if !aborted.is_err_and(|error| error.is_cancelled()) {
                    return Err("snapshot task abort was not observed as cancellation".to_owned());
                }
                tokio::time::timeout(PHASE_TIMEOUT, fixture.b.acme_budget_snapshot(cutoff))
                    .await
                    .map_err(|_| "post-cancel snapshot still observed a hook".to_owned())?
                    .map_err(|error| format!("post-cancel snapshot failed: {error}"))?;
                Ok::<_, String>(())
            }
            .await
        } else {
            Ok(())
        };

        let (atomic_statement, observed, after) = match exercise {
            Ok(values) => values,
            Err(error) => {
                fixture.close().await;
                panic!("bounded snapshot exercise failed: {error}");
            }
        };
        fixture.close().await;

        if let Err(error) = guard_controls {
            panic!("snapshot guard isolation control failed: {error}");
        }

        assert!(
            atomic_statement,
            "snapshot backend did not execute one statement for the complete tuple"
        );
        assert!(
            observed == old || observed == new,
            "one snapshot statement returned a torn tuple: {observed:?}"
        );
        assert_eq!(after, new);
    }

    /// A database created before global configuration was first persisted can
    /// already contain pending queue work. The first picker must seed the
    /// default singleton row and claim that work rather than failing its lock.
    #[tokio::test]
    async fn queue_pick_seeds_missing_global_config_without_overwriting_existing_values() {
        let Some(fixture) = PgBootstrapFixture::new("sekisho_queue_legacy_config").await else {
            return;
        };
        eprintln!("LIVE_POSTGRES_QUEUE_LEGACY_CONFIG_ACQUIRED");
        let pending = admitted(
            fixture
                .a
                .acme_queue_enqueue("legacy-config.example", "node-a")
                .await
                .unwrap(),
        );
        let observer = PgPool::connect(&fixture.scoped_url).await.unwrap();
        sqlx::query("DELETE FROM global_config")
            .execute(&observer)
            .await
            .unwrap();

        let picked = fixture
            .b
            .acme_queue_pick_next(chrono::Duration::minutes(10), 2)
            .await
            .unwrap()
            .expect("legacy pending row must be claimed");
        assert_eq!(picked.id, pending.id);
        let seeded = sqlx::query_scalar::<_, String>("SELECT data FROM global_config WHERE id = 1")
            .fetch_one(&observer)
            .await
            .unwrap();
        let seeded: crate::models::config::GlobalConfig = serde_json::from_str(&seeded).unwrap();
        assert_eq!(
            seeded.acme_queue_capacity,
            crate::models::config::GlobalConfig::default().acme_queue_capacity
        );

        fixture
            .a
            .update_config(serde_json::json!({"acme_queue_capacity": 1234}))
            .await
            .unwrap();
        fixture
            .a
            .acme_queue_enqueue("preserve-config.example", "node-a")
            .await
            .unwrap();
        fixture
            .b
            .acme_queue_pick_next(chrono::Duration::minutes(10), 2)
            .await
            .unwrap()
            .expect("second durable slot");
        let preserved =
            sqlx::query_scalar::<_, String>("SELECT data FROM global_config WHERE id = 1")
                .fetch_one(&observer)
                .await
                .unwrap();
        let preserved: crate::models::config::GlobalConfig =
            serde_json::from_str(&preserved).unwrap();
        assert_eq!(preserved.acme_queue_capacity, 1234);

        observer.close().await;
        fixture.close().await;
    }

    /// Two nodes racing to enqueue the same domain collapse to one
    /// row. The de-dup is what keeps a CLI retry from stacking two
    /// concurrent ACME orders for the same FQDN — a Let's Encrypt
    /// rate-limit footgun we explicitly built the queue to avoid.
    #[tokio::test]
    async fn concurrent_enqueue_dedupes_across_nodes() {
        let application_name = "sekisho_queue_empty_race";
        let Some(fixture) = PgBootstrapFixture::new(application_name).await else {
            return;
        };
        eprintln!("postgres ACME queue empty-row race gate exercised");

        let raw = PgPool::connect(&fixture.scoped_url)
            .await
            .expect("queue race observer must connect");
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let a = fixture.a.clone();
        let a_barrier = barrier.clone();
        let a_task = tokio::spawn(async move {
            a_barrier.wait().await;
            a.acme_queue_enqueue("dup.example", "node-a").await
        });
        let b = fixture.b.clone();
        let b_barrier = barrier.clone();
        let b_task = tokio::spawn(async move {
            b_barrier.wait().await;
            b.acme_queue_enqueue("dup.example", "node-b").await
        });
        barrier.wait().await;

        let ra_admission = a_task
            .await
            .expect("first queue peer must join")
            .expect("first queue peer must converge");
        let rb_admission = b_task
            .await
            .expect("second queue peer must join")
            .expect("second queue peer must converge");
        assert!(matches!(
            (&ra_admission, &rb_admission),
            (
                crate::models::acme_queue::AcmeQueueAdmission::Inserted(_),
                crate::models::acme_queue::AcmeQueueAdmission::Existing(_)
            ) | (
                crate::models::acme_queue::AcmeQueueAdmission::Existing(_),
                crate::models::acme_queue::AcmeQueueAdmission::Inserted(_)
            )
        ));
        let ra = admitted(ra_admission);
        let rb = admitted(rb_admission);
        assert_eq!(ra.id, rb.id);
        assert_eq!(ra.domain, rb.domain);
        assert_eq!(ra.requester_node, rb.requester_node);
        assert_eq!(ra.status, rb.status);
        assert_eq!(ra.result_cert_id, rb.result_cert_id);
        assert_eq!(ra.error_msg, rb.error_msg);
        assert_eq!(ra.enqueued_at.timestamp(), rb.enqueued_at.timestamp());
        assert_eq!(ra.picked_at, rb.picked_at);
        assert_eq!(ra.completed_at, rb.completed_at);
        let (persisted_id, persisted_requester, persisted_enqueued_at) =
            sqlx::query_as::<_, (uuid::Uuid, String, i64)>(
                "SELECT id, requester_node, enqueued_at FROM acme_queue \
                 WHERE domain = 'dup.example' \
                   AND status IN ('pending', 'in_progress')",
            )
            .fetch_one(&raw)
            .await
            .unwrap();
        assert_eq!(persisted_id, ra.id);
        let (winner, loser) = if persisted_requester == "node-a" {
            (&ra, &rb)
        } else {
            assert_eq!(persisted_requester, "node-b");
            (&rb, &ra)
        };
        assert_eq!(loser.enqueued_at.timestamp_subsec_nanos(), 0);
        assert_eq!(winner.enqueued_at.timestamp(), persisted_enqueued_at);
        assert_eq!(loser.enqueued_at.timestamp(), persisted_enqueued_at);

        let subsequent = admitted(
            fixture
                .a
                .acme_queue_enqueue("dup.example", "node-after")
                .await
                .unwrap(),
        );
        assert_eq!(subsequent.id, persisted_id);
        assert_eq!(subsequent.requester_node, persisted_requester);
        assert_eq!(subsequent.enqueued_at.timestamp_subsec_nanos(), 0);
        assert_eq!(subsequent.enqueued_at.timestamp(), persisted_enqueued_at);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM acme_queue \
                 WHERE domain = 'dup.example' \
                   AND status IN ('pending', 'in_progress')",
            )
            .fetch_one(&raw)
            .await
            .unwrap(),
            1
        );

        // Only one pick will come out even though two callers tried
        // to enqueue — partial unique index + the read-first path
        // together collapse the race.
        let first_pick = fixture
            .b
            .acme_queue_pick_next(chrono::Duration::minutes(10), 5)
            .await
            .unwrap();
        assert!(first_pick.is_some());
        let second_pick = fixture
            .b
            .acme_queue_pick_next(chrono::Duration::minutes(10), 5)
            .await
            .unwrap();
        assert!(
            second_pick.is_none(),
            "only one active queue row for the domain should exist"
        );
        raw.close().await;
        fixture.close().await;
    }

    #[tokio::test]
    async fn concurrent_empty_election_converges_by_existing_rules() {
        let application_name = "sekisho_election_empty_race";
        let Some(fixture) = PgBootstrapFixture::new(application_name).await else {
            return;
        };
        eprintln!("postgres ACME election empty-row race gate exercised");

        let raw = PgPool::connect(&fixture.scoped_url)
            .await
            .expect("election race observer must connect");
        let key = unique_advisory_key();
        let mut blocker = hold_advisory_lock(&raw, key).await;
        install_insert_barrier(
            &raw,
            "acme_leader_election",
            "hold_election_insert",
            "hold_election_insert_fn",
            key,
        )
        .await;

        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let a = fixture.a.clone();
        let a_barrier = barrier.clone();
        let a_task = tokio::spawn(async move {
            a_barrier.wait().await;
            a.acme_election_try_promote_or_refresh(
                "node-a",
                "ffffffff",
                chrono::Duration::minutes(10),
            )
            .await
        });
        let b = fixture.b.clone();
        let b_barrier = barrier.clone();
        let b_task = tokio::spawn(async move {
            b_barrier.wait().await;
            b.acme_election_try_promote_or_refresh(
                "node-b",
                "00000000",
                chrono::Duration::minutes(10),
            )
            .await
        });
        barrier.wait().await;
        wait_for_blocked_query(
            &raw,
            application_name,
            "INSERT INTO acme_leader_election",
            2,
        )
        .await;
        release_advisory_lock(&mut blocker, key).await;

        let outcomes = [
            a_task
                .await
                .expect("first election peer must join")
                .expect("first election peer must converge"),
            b_task
                .await
                .expect("second election peer must join")
                .expect("second election peer must converge"),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.action_taken == ElectionAction::Initial)
                .count(),
            1
        );
        assert!(
            outcomes.iter().any(|outcome| matches!(
                outcome.action_taken,
                ElectionAction::None | ElectionAction::Preempt
            )),
            "the insert loser must apply the existing fresh-leader hash rules"
        );
        let final_row = fixture
            .a
            .acme_election_read()
            .await
            .unwrap()
            .expect("election singleton must exist");
        assert_eq!(final_row.node_id, "node-b");
        assert_eq!(final_row.node_hash, "00000000");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM acme_leader_election")
                .fetch_one(&raw)
                .await
                .unwrap(),
            1
        );
        raw.close().await;
        fixture.close().await;
    }

    #[tokio::test]
    async fn concurrent_initial_config_patches_union_and_reload_peer_caches() {
        let application_prefix = format!("sekisho_config_empty_{}", unique_advisory_key());
        let Some(fixture) = PgStoreFixture::new(&application_prefix).await else {
            return;
        };
        eprintln!("postgres global-config empty-row/cache race gate exercised");

        let _ = fixture.a.get_config().await.unwrap();
        let _ = fixture.b.get_config().await.unwrap();

        let key_a = unique_advisory_key();
        let key_b = unique_advisory_key();
        let mut blocker_a = hold_advisory_lock(&fixture.observer, key_a).await;
        let mut blocker_b = hold_advisory_lock(&fixture.observer, key_b).await;
        sqlx::query(&format!(
            "CREATE FUNCTION hold_config_insert_fn() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN \
               IF current_setting('application_name') = '{}' THEN \
                 PERFORM pg_advisory_xact_lock({key_a}); \
               ELSIF current_setting('application_name') = '{}' THEN \
                 PERFORM pg_advisory_xact_lock({key_b}); \
               END IF; \
               RETURN NEW; \
             END $$",
            fixture.app_a, fixture.app_b,
        ))
        .execute(&fixture.observer)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER hold_config_insert BEFORE INSERT ON global_config \
             FOR EACH ROW EXECUTE FUNCTION hold_config_insert_fn()",
        )
        .execute(&fixture.observer)
        .await
        .unwrap();

        let cache = fixture.a.config_cache.clone();
        let (cache_locked_tx, cache_locked_rx) = std::sync::mpsc::sync_channel(1);
        let (cache_release_tx, cache_release_rx) = std::sync::mpsc::sync_channel(1);
        let cache_holder = std::thread::spawn(move || {
            let _guard = cache.write().unwrap_or_else(|e| e.into_inner());
            cache_locked_tx.send(()).unwrap();
            cache_release_rx.recv().unwrap();
        });
        cache_locked_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("config cache lock must be held");

        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let a = fixture.a.clone();
        let a_barrier = barrier.clone();
        let a_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("first config peer runtime must build");
            runtime.block_on(async move {
                a_barrier.wait().await;
                a.update_config(serde_json::json!({"session_lifetime_hours": 42}))
                    .await
            })
        });
        let b = fixture.b.clone();
        let b_barrier = barrier.clone();
        let b_task = tokio::spawn(async move {
            b_barrier.wait().await;
            b.update_config(serde_json::json!({"log_level": "debug"}))
                .await
        });
        barrier.wait().await;
        wait_for_blocked_query(
            &fixture.observer,
            &fixture.app_a,
            "INSERT INTO global_config",
            1,
        )
        .await;
        wait_for_blocked_query(
            &fixture.observer,
            &fixture.app_b,
            "INSERT INTO global_config",
            1,
        )
        .await;

        release_advisory_lock(&mut blocker_a, key_a).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let version = sqlx::query_scalar::<_, i64>(
                    "SELECT version FROM schema_versions WHERE resource = 'config'",
                )
                .fetch_one(&fixture.observer)
                .await
                .unwrap();
                if version == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("first config backend transaction must commit");

        release_advisory_lock(&mut blocker_b, key_b).await;
        let b_result = b_task
            .await
            .expect("second config peer must join")
            .expect("second config peer must update");
        assert_eq!(b_result.session_lifetime_hours, 42);
        assert_eq!(b_result.log_level, "debug");

        cache_release_tx.send(()).unwrap();
        cache_holder.join().unwrap();
        let a_result = a_thread
            .join()
            .expect("first config peer thread must join")
            .expect("first config peer must update");
        assert_eq!(a_result.session_lifetime_hours, 42);

        let persisted: GlobalConfig = serde_json::from_str(
            &sqlx::query_scalar::<_, String>("SELECT data FROM global_config WHERE id = 1")
                .fetch_one(&fixture.observer)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.session_lifetime_hours, 42);
        assert_eq!(persisted.log_level, "debug");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT version FROM schema_versions WHERE resource = 'config'",
            )
            .fetch_one(&fixture.observer)
            .await
            .unwrap(),
            2
        );

        let seen_a = fixture.a.get_config().await.unwrap();
        let seen_b = fixture.b.get_config().await.unwrap();
        assert_eq!(seen_a.session_lifetime_hours, 42);
        assert_eq!(seen_a.log_level, "debug");
        assert_eq!(seen_b.session_lifetime_hours, 42);
        assert_eq!(seen_b.log_level, "debug");
        fixture.close().await;
    }

    #[tokio::test]
    async fn empty_row_mutations_propagate_non_conflict_database_errors() {
        let Some(fixture) = PgBootstrapFixture::new("sekisho_empty_row_errors").await else {
            return;
        };
        eprintln!("postgres empty-row non-conflict error gate exercised");
        let raw = PgPool::connect(&fixture.scoped_url)
            .await
            .expect("empty-row error observer must connect");

        for (table, trigger, function) in [
            (
                "acme_leader_election",
                "reject_election_insert",
                "reject_election_insert_fn",
            ),
            (
                "global_config",
                "reject_config_insert",
                "reject_config_insert_fn",
            ),
            (
                "acme_queue",
                "reject_queue_insert",
                "reject_queue_insert_fn",
            ),
        ] {
            sqlx::query(&format!(
                "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ \
                 BEGIN RAISE EXCEPTION 'empty-row database failure'; END $$",
            ))
            .execute(&raw)
            .await
            .unwrap();
            sqlx::query(&format!(
                "CREATE TRIGGER {trigger} BEFORE INSERT ON {table} \
                 FOR EACH ROW EXECUTE FUNCTION {function}()",
            ))
            .execute(&raw)
            .await
            .unwrap();

            let error = match table {
                "acme_leader_election" => fixture
                    .a
                    .acme_election_try_promote_or_refresh(
                        "node-a",
                        "00000000",
                        chrono::Duration::minutes(10),
                    )
                    .await
                    .map(|_| ()),
                "global_config" => fixture
                    .a
                    .update_config(serde_json::json!({"log_level": "debug"}))
                    .await
                    .map(|_| ()),
                "acme_queue" => fixture
                    .a
                    .acme_queue_enqueue("error.example", "node-a")
                    .await
                    .map(|_| ()),
                _ => unreachable!(),
            }
            .expect_err("trigger error must not be converted into race convergence");
            assert!(matches!(error, crate::error::Error::Database(_)));
            assert_eq!(
                sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                    .fetch_one(&raw)
                    .await
                    .unwrap(),
                0
            );

            sqlx::query(&format!("DROP TRIGGER {trigger} ON {table}"))
                .execute(&raw)
                .await
                .unwrap();
            sqlx::query(&format!("DROP FUNCTION {function}()"))
                .execute(&raw)
                .await
                .unwrap();
        }

        assert_eq!(
            fixture
                .a
                .acme_election_try_promote_or_refresh(
                    "node-a",
                    "00000000",
                    chrono::Duration::minutes(10),
                )
                .await
                .unwrap()
                .action_taken,
            ElectionAction::Initial
        );
        assert_eq!(
            fixture
                .a
                .update_config(serde_json::json!({"log_level": "debug"}))
                .await
                .unwrap()
                .log_level,
            "debug"
        );
        assert_eq!(
            admitted(
                fixture
                    .a
                    .acme_queue_enqueue("error.example", "node-a")
                    .await
                    .unwrap()
            )
            .domain,
            "error.example"
        );
        assert_eq!(fixture.a.config_version_current().await.unwrap(), 1);
        raw.close().await;
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_first_dek_bootstrap_race_has_one_winner() {
        let Some(fixture) = PgBootstrapFixture::new("sekisho_first_dek_race").await else {
            return;
        };
        eprintln!("postgres first-DEK race gate exercised");
        const TRIALS: usize = 16;
        for trial in 0..TRIALS {
            if trial > 0 {
                fixture.reset_first_dek_trial().await;
            }

            let barrier = Arc::new(tokio::sync::Barrier::new(3));
            let a = fixture.a.clone();
            let a_barrier = barrier.clone();
            let a_blob = bootstrap_blob(&TEST_MASTER_KEY);
            let a_task = tokio::spawn(async move {
                a_barrier.wait().await;
                a.master_keys_insert_first_active_if_empty(&a_blob).await
            });
            let b = fixture.b.clone();
            let b_barrier = barrier.clone();
            let b_blob = bootstrap_blob(&TEST_MASTER_KEY);
            let b_task = tokio::spawn(async move {
                b_barrier.wait().await;
                b.master_keys_insert_first_active_if_empty(&b_blob).await
            });
            barrier.wait().await;

            let outcomes = [
                a_task
                    .await
                    .expect("first peer must join")
                    .expect("first peer bootstrap must return a typed outcome"),
                b_task
                    .await
                    .expect("second peer must join")
                    .expect("second peer bootstrap must return a typed outcome"),
            ];
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|&&outcome| outcome == FirstDekInsertOutcome::Inserted)
                    .count(),
                1,
                "trial {trial} must have exactly one bootstrap winner"
            );
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|&&outcome| outcome == FirstDekInsertOutcome::AlreadyInitialized)
                    .count(),
                1,
                "trial {trial} must have exactly one bootstrap loser"
            );

            let rows = fixture.a.master_keys_load_active_set().await.unwrap();
            assert_eq!(rows.len(), 1, "trial {trial} must persist one row");
            assert_eq!(rows[0].key_id, 0, "trial {trial} must persist key zero");
            assert!(rows[0].active, "trial {trial} key must be active");
            assert!(!rows[0].retired, "trial {trial} key must not be retired");
            assert_eq!(
                fixture.a.key_ring_version_current().await.unwrap(),
                1,
                "trial {trial} must bump the ring version once"
            );

            let ring_a = reload_pg_ring(&fixture.a, &TEST_MASTER_KEY).await;
            let ring_b = reload_pg_ring(&fixture.b, &TEST_MASTER_KEY).await;
            let a_ciphertext = ring_a
                .encrypt_active(b"shared postgres bootstrap from a")
                .unwrap();
            assert_eq!(
                &*ring_b.decrypt(&a_ciphertext).unwrap(),
                b"shared postgres bootstrap from a",
                "trial {trial} peer B must load peer A's persisted ring"
            );
            let b_ciphertext = ring_b
                .encrypt_active(b"shared postgres bootstrap from b")
                .unwrap();
            assert_eq!(
                &*ring_a.decrypt(&b_ciphertext).unwrap(),
                b"shared postgres bootstrap from b",
                "trial {trial} peer A must load peer B's persisted ring"
            );
        }
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_first_dek_bootstrap_linearizes_with_operator_insert() {
        let Some(fixture) = PgBootstrapFixture::new("sekisho_first_dek_operator").await else {
            return;
        };
        eprintln!("postgres first-DEK operator-race gate exercised");
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let bootstrap_backend = fixture.a.clone();
        let bootstrap_barrier = barrier.clone();
        let blob = bootstrap_blob(&TEST_MASTER_KEY);
        let bootstrap = tokio::spawn(async move {
            bootstrap_barrier.wait().await;
            bootstrap_backend
                .master_keys_insert_first_active_if_empty(&blob)
                .await
        });
        let operator_backend = fixture.b.clone();
        let operator_barrier = barrier.clone();
        let operator_blob = bootstrap_blob(&TEST_MASTER_KEY);
        let operator = tokio::spawn(async move {
            operator_barrier.wait().await;
            operator_backend.master_keys_insert(1, &operator_blob).await
        });
        barrier.wait().await;

        let bootstrap_outcome = bootstrap
            .await
            .expect("bootstrap peer must join")
            .expect("bootstrap mutation must complete");
        operator
            .await
            .expect("operator peer must join")
            .expect("operator insert must complete");

        let rows = fixture.a.master_keys_load_active_set().await.unwrap();
        match bootstrap_outcome {
            FirstDekInsertOutcome::Inserted => {
                assert_eq!(rows.len(), 2);
                assert_eq!(
                    rows.iter().filter(|row| row.active).count(),
                    1,
                    "bootstrap-first order must retain exactly one active row"
                );
                assert!(rows.iter().any(|row| row.key_id == 0 && row.active));
                assert!(rows.iter().any(|row| row.key_id == 1 && !row.active));
                assert_eq!(fixture.a.key_ring_version_current().await.unwrap(), 2);
            }
            FirstDekInsertOutcome::AlreadyInitialized => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].key_id, 1);
                assert!(!rows[0].active);
                assert_eq!(fixture.a.key_ring_version_current().await.unwrap(), 1);
            }
        }
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_first_dek_bootstrap_propagates_database_errors() {
        let Some(fixture) = PgBootstrapFixture::new("sekisho_first_dek_error").await else {
            return;
        };
        eprintln!("postgres first-DEK database-error gate exercised");
        let raw = sqlx::PgPool::connect(&fixture.scoped_url)
            .await
            .expect("error fixture pool must connect");
        sqlx::query(
            "CREATE FUNCTION reject_first_dek() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'bootstrap database failure'; END $$",
        )
        .execute(&raw)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_first_dek \
             BEFORE INSERT ON master_keys FOR EACH ROW EXECUTE FUNCTION reject_first_dek()",
        )
        .execute(&raw)
        .await
        .unwrap();

        let error = fixture
            .a
            .master_keys_insert_first_active_if_empty(&bootstrap_blob(&TEST_MASTER_KEY))
            .await
            .expect_err("trigger failure must propagate");
        assert!(matches!(error, crate::error::Error::Database(_)));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM master_keys")
                .fetch_one(&raw)
                .await
                .unwrap(),
            0
        );
        assert_eq!(fixture.a.key_ring_version_current().await.unwrap(), 0);

        sqlx::query("DROP TRIGGER reject_first_dek ON master_keys")
            .execute(&raw)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION reject_first_dek()")
            .execute(&raw)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .b
                .master_keys_insert_first_active_if_empty(&bootstrap_blob(&TEST_MASTER_KEY))
                .await
                .unwrap(),
            FirstDekInsertOutcome::Inserted
        );
        assert_eq!(fixture.b.key_ring_version_current().await.unwrap(), 1);
        raw.close().await;
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_cancelled_first_dek_bootstrap_rolls_back_before_reuse() {
        let application_name = "sekisho_first_dek_cancel";
        let Some(fixture) = PgBootstrapFixture::new(application_name).await else {
            return;
        };
        eprintln!("postgres first-DEK cancellation gate exercised");
        let raw = sqlx::PgPool::connect(&fixture.scoped_url)
            .await
            .expect("cancellation fixture pool must connect");
        let mut blocker = raw.begin().await.unwrap();
        sqlx::query(
            "SELECT version FROM schema_versions \
             WHERE resource = 'key_ring' FOR UPDATE",
        )
        .execute(&mut *blocker)
        .await
        .unwrap();

        let backend = fixture.a.clone();
        let blob = bootstrap_blob(&TEST_MASTER_KEY);
        let task = tokio::spawn(async move {
            backend
                .master_keys_insert_first_active_if_empty(&blob)
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS ( \
                       SELECT 1 FROM pg_stat_activity \
                       WHERE application_name = $1 \
                         AND wait_event_type = 'Lock' \
                         AND query LIKE 'UPDATE schema_versions%' \
                     )",
                )
                .bind(application_name)
                .fetch_one(&raw)
                .await
                .unwrap();
                if waiting {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("bootstrap must reach the blocked version bump");

        task.abort();
        let join_error = task.await.expect_err("bootstrap task must be cancelled");
        assert!(join_error.is_cancelled());
        blocker.rollback().await.unwrap();

        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(5),
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM master_keys").fetch_one(&raw),
            )
            .await
            .expect("rollback visibility must not hang")
            .unwrap(),
            0
        );
        assert_eq!(fixture.a.key_ring_version_current().await.unwrap(), 0);
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(5),
                fixture
                    .b
                    .master_keys_insert_first_active_if_empty(&bootstrap_blob(&TEST_MASTER_KEY)),
            )
            .await
            .expect("next writer must not hang")
            .unwrap(),
            FirstDekInsertOutcome::Inserted
        );
        raw.close().await;
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_cancelled_dek_allocation_leaves_no_row_or_version_drift() {
        let application_name = "sekisho_p2_8_cancel";
        let Some(fixture) = PgBootstrapFixture::new(application_name).await else {
            return;
        };
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:p2_8_key_alloc_cancel");
        let raw = PgPool::connect(&fixture.scoped_url).await.unwrap();
        let mut blocker = raw.begin().await.unwrap();
        sqlx::query(
            "SELECT version FROM schema_versions \
             WHERE resource = 'key_ring' FOR UPDATE",
        )
        .execute(&mut *blocker)
        .await
        .unwrap();

        let backend = fixture.a.clone();
        let task = tokio::spawn(async move {
            backend
                .master_keys_allocate_inactive("cancelled-allocation")
                .await
        });
        wait_for_blocked_query(
            &raw,
            application_name,
            "SELECT version FROM schema_versions",
            1,
        )
        .await;
        task.abort();
        assert!(
            task.await
                .expect_err("allocation task must be cancelled")
                .is_cancelled()
        );
        blocker.rollback().await.unwrap();

        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM master_keys")
                .fetch_one(&raw)
                .await
                .unwrap(),
            0
        );
        assert_eq!(fixture.a.key_ring_version_current().await.unwrap(), 0);
        assert_eq!(
            fixture
                .b
                .master_keys_allocate_inactive("next-allocation")
                .await
                .unwrap(),
            0
        );
        assert_eq!(fixture.b.key_ring_version_current().await.unwrap(), 1);
        raw.close().await;
        fixture.close().await;
    }

    #[tokio::test]
    async fn postgres_failed_dek_allocation_rolls_back_without_version_drift() {
        let Some(fixture) = PgBootstrapFixture::new("sekisho_p2_8_error").await else {
            return;
        };
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:p2_8_key_alloc_error");
        let raw = PgPool::connect(&fixture.scoped_url).await.unwrap();
        sqlx::query(
            "CREATE FUNCTION reject_dek_allocation() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'allocation database failure'; END $$",
        )
        .execute(&raw)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_dek_allocation \
             BEFORE INSERT ON master_keys FOR EACH ROW \
             EXECUTE FUNCTION reject_dek_allocation()",
        )
        .execute(&raw)
        .await
        .unwrap();

        let error = fixture
            .a
            .master_keys_allocate_inactive("rejected-allocation")
            .await
            .expect_err("trigger failure must propagate");
        assert!(matches!(error, crate::error::Error::Database(_)));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM master_keys")
                .fetch_one(&raw)
                .await
                .unwrap(),
            0
        );
        assert_eq!(fixture.a.key_ring_version_current().await.unwrap(), 0);
        raw.close().await;
        fixture.close().await;
    }
    struct PgMigrationFixture {
        admin: PgPool,
        schema: String,
        scoped_url: String,
    }

    impl PgMigrationFixture {
        async fn new() -> Option<Self> {
            let base_url = std::env::var("TEST_POSTGRES_URL").ok()?;
            let admin = PgPool::connect(&base_url)
                .await
                .expect("connect to TEST_POSTGRES_URL");
            let schema = unique_schema();
            sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
                .execute(&admin)
                .await
                .expect("drop migration test schema");
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin)
                .await
                .expect("create migration test schema");
            let scoped_url = with_search_path(&base_url, &schema);
            Some(Self {
                admin,
                schema,
                scoped_url,
            })
        }

        async fn pool(&self) -> PgPool {
            PgPool::connect(&self.scoped_url)
                .await
                .expect("connect to scoped migration schema")
        }

        async fn cleanup(self) {
            sqlx::query(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema))
                .execute(&self.admin)
                .await
                .expect("drop migration test schema");
            self.admin.close().await;
        }
    }

    async fn restore_pg_api_keys_v6_shape(pool: &PgPool) {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("ALTER TABLE api_keys DROP COLUMN scopes")
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

    async fn seed_legacy_postgres(fixture: &PgMigrationFixture) {
        let pool = fixture.pool().await;
        sqlx::query(
            r#"CREATE TABLE identity_providers (
                id uuid PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                idp_type TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy PG identity_providers");
        sqlx::query(
            r#"CREATE TABLE pending_auth (
                csrf TEXT PRIMARY KEY,
                idp_id uuid NOT NULL,
                nonce TEXT NOT NULL DEFAULT '',
                code_verifier TEXT NOT NULL DEFAULT '',
                saml_authn_request_id TEXT,
                redirect_url TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL
            )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy PG pending_auth");
        sqlx::query(
            r#"CREATE TABLE sessions (
                id uuid PRIMARY KEY,
                user_id TEXT NOT NULL,
                idp_id uuid NOT NULL,
                data TEXT NOT NULL,
                expires_at BIGINT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                last_accessed_at BIGINT
            )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy PG sessions");
        sqlx::query(
            r#"CREATE TABLE api_certificate (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT NOT NULL,
                expires_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
            )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy PG management certificate table");
        sqlx::query(
            r#"CREATE TABLE api_keys (
                id uuid PRIMARY KEY,
                name TEXT NOT NULL,
                prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
                last_used_at BIGINT
            )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy PG API-key table");
        sqlx::query(
            "INSERT INTO api_keys
             (id, name, prefix, key_hash, created_at, last_used_at)
             VALUES ($1, 'legacy-admin', 'sks_lega', 'legacy-api-key-hash', 1, NULL)",
        )
        .bind(Uuid::from_u128(0x202))
        .execute(&pool)
        .await
        .expect("legacy PG API-key row");
        sqlx::query(
            "INSERT INTO api_certificate (id, data, expires_at) VALUES (1, '{}', 2000000000)",
        )
        .execute(&pool)
        .await
        .expect("legacy PG management certificate row");
        let session_id = Uuid::from_u128(0x201);
        let idp_id = Uuid::from_u128(0x200);
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
             VALUES ($1, 'legacy@example.com', $2, $3, 2000000000, NULL)",
        )
        .bind(session_id)
        .bind(idp_id)
        .bind(session_data.to_string())
        .execute(&pool)
        .await
        .expect("legacy PG session row");
        sqlx::query(
            r#"INSERT INTO identity_providers (id, name, idp_type, data)
               VALUES ($1, 'legacy-saml', '"saml"', $2)"#,
        )
        .bind(Uuid::from_u128(0x200))
        .bind(
            r#"{"name":"legacy-saml","saml_config":{"metadata_url":"https://idp.example/metadata","entity_id":"dead-entity","acs_url":"https://dead.example/acs"}}"#,
        )
        .execute(&pool)
        .await
        .expect("legacy PG SAML row");
        sqlx::query(
            r#"INSERT INTO pending_auth (
                   csrf, idp_id, redirect_url, created_at, expires_at
               ) VALUES ('legacy-csrf', $1, '/', 1, 2)"#,
        )
        .bind(Uuid::from_u128(0x200))
        .execute(&pool)
        .await
        .expect("legacy PG pending auth");
        sqlx::query("CREATE TABLE migration_effects (count BIGINT NOT NULL)")
            .execute(&pool)
            .await
            .expect("PG migration counter table");
        sqlx::query("INSERT INTO migration_effects (count) VALUES (0)")
            .execute(&pool)
            .await
            .expect("PG migration counter seed");
        sqlx::query(
            r#"CREATE FUNCTION count_saml_cleanup_fn() RETURNS trigger
               LANGUAGE plpgsql AS $$
               BEGIN
                   UPDATE migration_effects SET count = count + 1;
                   RETURN NEW;
               END
               $$"#,
        )
        .execute(&pool)
        .await
        .expect("PG migration counter function");
        sqlx::query(
            r#"CREATE TRIGGER count_saml_cleanup
               AFTER UPDATE ON identity_providers
               FOR EACH ROW EXECUTE FUNCTION count_saml_cleanup_fn()"#,
        )
        .execute(&pool)
        .await
        .expect("PG migration counter trigger");
        pool.close().await;
    }

    async fn pg_ledger(pool: &PgPool) -> Vec<(i64, String)> {
        sqlx::query_as("SELECT version, name FROM service_migrations ORDER BY version")
            .fetch_all(pool)
            .await
            .expect("Postgres migration ledger")
    }

    #[tokio::test]
    async fn postgres_service_migrations_cover_fresh_upgrade_repeat_and_parallel_boot() {
        let Some(fresh) = PgMigrationFixture::new().await else {
            return;
        };
        let backend = PostgresBackend::new(&fresh.scoped_url, test_master_key())
            .await
            .expect("fresh PG migrations");
        assert_eq!(
            pg_ledger(backend.pool_for_rotation()).await,
            expected_migration_ledger()
        );
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT to_regclass(current_schema() || '.used_handoff_nonces') IS NOT NULL",
            )
            .fetch_one(backend.pool_for_rotation())
            .await
            .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schema_versions")
                .fetch_one(backend.pool_for_rotation())
                .await
                .unwrap(),
            crate::store::version::ALL_RESOURCES.len() as i64
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COALESCE(SUM(version), 0)::BIGINT FROM schema_versions",
            )
            .fetch_one(backend.pool_for_rotation())
            .await
            .unwrap(),
            0
        );
        backend.close().await;
        let reopened = PostgresBackend::new(&fresh.scoped_url, test_master_key())
            .await
            .expect("fresh PG repeat boot");
        reopened.close().await;
        fresh.cleanup().await;

        let Some(upgraded) = PgMigrationFixture::new().await else {
            unreachable!("TEST_POSTGRES_URL disappeared")
        };
        seed_legacy_postgres(&upgraded).await;
        let backend = PostgresBackend::new(&upgraded.scoped_url, test_master_key())
            .await
            .expect("legacy PG upgrade");
        let kind: String =
            sqlx::query_scalar("SELECT kind FROM pending_auth WHERE csrf = 'legacy-csrf'")
                .fetch_one(backend.pool_for_rotation())
                .await
                .unwrap();
        assert_eq!(kind, "login");
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT to_regclass(current_schema() || '.api_certificate') IS NOT NULL",
            )
            .fetch_one(backend.pool_for_rotation())
            .await
            .unwrap(),
            "v6 must drop the legacy management certificate table"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT last_accessed_at FROM sessions WHERE user_id = 'legacy@example.com'",
            )
            .fetch_one(backend.pool_for_rotation())
            .await
            .unwrap(),
            1_700_000_000
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT scopes FROM api_keys WHERE name = 'legacy-admin'",
            )
            .fetch_one(backend.pool_for_rotation())
            .await
            .unwrap(),
            r#"["management:admin"]"#
        );
        let data: String =
            sqlx::query_scalar("SELECT data FROM identity_providers WHERE name = 'legacy-saml'")
                .fetch_one(backend.pool_for_rotation())
                .await
                .unwrap();
        let data: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert!(data.pointer("/saml_config/entity_id").is_none());
        assert!(data.pointer("/saml_config/acs_url").is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count FROM migration_effects")
                .fetch_one(backend.pool_for_rotation())
                .await
                .unwrap(),
            1
        );
        backend.close().await;
        let reopened = PostgresBackend::new(&upgraded.scoped_url, test_master_key())
            .await
            .expect("legacy PG repeat boot");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count FROM migration_effects")
                .fetch_one(reopened.pool_for_rotation())
                .await
                .unwrap(),
            1
        );
        reopened.close().await;
        upgraded.cleanup().await;

        let Some(adopted) = PgMigrationFixture::new().await else {
            unreachable!("TEST_POSTGRES_URL disappeared")
        };
        seed_legacy_postgres(&adopted).await;
        let pool = adopted.pool().await;
        sqlx::query("ALTER TABLE pending_auth ADD COLUMN kind TEXT NOT NULL DEFAULT 'login'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            r#"UPDATE identity_providers
               SET data = (data::jsonb #- '{saml_config,entity_id}' #- '{saml_config,acs_url}')::text
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
        let backend = PostgresBackend::new(&adopted.scoped_url, test_master_key())
            .await
            .expect("pre-ledger latest PG adoption");
        assert_eq!(
            pg_ledger(backend.pool_for_rotation()).await,
            expected_migration_ledger()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count FROM migration_effects")
                .fetch_one(backend.pool_for_rotation())
                .await
                .unwrap(),
            1,
            "ledger adoption must execute and record the migration body once"
        );
        let data: String =
            sqlx::query_scalar("SELECT data FROM identity_providers WHERE name = 'legacy-saml'")
                .fetch_one(backend.pool_for_rotation())
                .await
                .unwrap();
        assert!(!data.contains("dead-entity"));
        assert!(!data.contains("dead.example"));
        backend.close().await;
        adopted.cleanup().await;

        let Some(parallel) = PgMigrationFixture::new().await else {
            unreachable!("TEST_POSTGRES_URL disappeared")
        };
        seed_legacy_postgres(&parallel).await;
        let (left, right) = tokio::join!(
            PostgresBackend::new(&parallel.scoped_url, test_master_key()),
            PostgresBackend::new(&parallel.scoped_url, test_master_key())
        );
        let left = left.expect("left PG constructor");
        let right = right.expect("right PG constructor");
        assert_eq!(
            pg_ledger(left.pool_for_rotation()).await,
            expected_migration_ledger()
        );
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT to_regclass(current_schema() || '.api_certificate') IS NOT NULL",
            )
            .fetch_one(left.pool_for_rotation())
            .await
            .unwrap(),
            "parallel v6 migration must leave the legacy table absent"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count FROM migration_effects")
                .fetch_one(right.pool_for_rotation())
                .await
                .unwrap(),
            1
        );
        left.close().await;
        right.close().await;
        parallel.cleanup().await;
        eprintln!("postgres service migration contract: exercised");
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:session_expiry_migration_v4");
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:management_rpk_v6_fresh_repeat");
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:management_rpk_v6_upgrade_drop");
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:management_rpk_v6_concurrent_once");
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:api_key_scopes_v7_backfill_repeat");
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:api_key_scopes_v7_concurrent_once");
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:handoff_nonce_migration_v8");
    }

    /// The HA case the guard exists for: two nodes redeem the same token at once
    /// and the primary key, not timing, decides which one succeeds.
    #[tokio::test]
    async fn postgres_handoff_nonce_two_store_race_has_one_winner() {
        let Some(fixture) = PgMigrationFixture::new().await else {
            return;
        };
        let a = Store::new_for_test(
            "sqlite::memory:",
            TEST_MASTER_KEY,
            Some(&fixture.scoped_url),
        )
        .await
        .unwrap();
        let b = Store::new_for_test(
            "sqlite::memory:",
            TEST_MASTER_KEY,
            Some(&fixture.scoped_url),
        )
        .await
        .unwrap();
        let nonce = Uuid::new_v4();
        let (left, right) = tokio::join!(
            a.handoff_nonce_consume(nonce),
            b.handoff_nonce_consume(nonce)
        );
        let mut outcomes = [left.unwrap(), right.unwrap()];
        outcomes.sort_unstable();
        assert_eq!(outcomes, [false, true]);
        a.close().await;
        b.close().await;
        fixture.cleanup().await;
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:handoff_nonce_two_store_race");
    }

    /// A migration that fails partway leaves no half-built table behind, so the
    /// retry starts from a known state rather than from debris.
    #[tokio::test]
    async fn postgres_handoff_nonce_v8_failure_rolls_back_and_retries() {
        let Some(failed) = PgMigrationFixture::new().await else {
            return;
        };
        let backend = PostgresBackend::new(&failed.scoped_url, test_master_key())
            .await
            .unwrap();
        backend.close().await;
        let pool = failed.pool().await;
        sqlx::query("DROP TABLE used_handoff_nonces")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM service_migrations WHERE version = 8")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            r#"CREATE FUNCTION reject_handoff_nonce_v8_fn() RETURNS trigger
               LANGUAGE plpgsql AS $$
               BEGIN
                   RAISE EXCEPTION 'injected handoff nonce v8 failure';
               END
               $$"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"CREATE TRIGGER reject_handoff_nonce_v8
               BEFORE INSERT ON service_migrations
               FOR EACH ROW
               WHEN (NEW.version = 8)
               EXECUTE FUNCTION reject_handoff_nonce_v8_fn()"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
        let error = match PostgresBackend::new(&failed.scoped_url, test_master_key()).await {
            Ok(_) => panic!("PG v8 failure was swallowed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("injected handoff nonce v8 failure")
        );
        let pool = failed.pool().await;
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT to_regclass(current_schema() || '.used_handoff_nonces') IS NOT NULL",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        );
        sqlx::query("DROP TRIGGER reject_handoff_nonce_v8 ON service_migrations")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION reject_handoff_nonce_v8_fn()")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let backend = PostgresBackend::new(&failed.scoped_url, test_master_key())
            .await
            .expect("retry PG v8 after injected failure");
        backend.close().await;
        failed.cleanup().await;
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:handoff_nonce_v8_rollback_retry");
    }

    #[tokio::test]
    async fn postgres_session_authority_migration_rolls_back_and_retries() {
        let Some(fixture) = PgMigrationFixture::new().await else {
            return;
        };
        seed_legacy_postgres(&fixture).await;
        let pool = fixture.pool().await;
        sqlx::query(
            "UPDATE sessions SET data = (data::jsonb - 'last_accessed_at')::text \
             WHERE user_id = 'legacy@example.com'",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let error = match PostgresBackend::new(&fixture.scoped_url, test_master_key()).await {
            Ok(_) => panic!("invalid legacy session timestamp was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("missing or malformed"));
        let pool = fixture.pool().await;
        let last_accessed_at: Option<i64> = sqlx::query_scalar(
            "SELECT last_accessed_at FROM sessions WHERE user_id = 'legacy@example.com'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(last_accessed_at, None);
        let ledger_exists: bool = sqlx::query_scalar(
            "SELECT to_regclass(current_schema() || '.service_migrations') IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!ledger_exists, "failed v4 must roll back the ledger");
        sqlx::query(
            "UPDATE sessions SET data = jsonb_set( \
                 data::jsonb, '{last_accessed_at}', '1700000000'::jsonb \
             )::text WHERE user_id = 'legacy@example.com'",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let backend = PostgresBackend::new(&fixture.scoped_url, test_master_key())
            .await
            .expect("retry after fixing legacy PG session JSON");
        assert_eq!(
            pg_ledger(backend.pool_for_rotation()).await,
            expected_migration_ledger()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT last_accessed_at FROM sessions WHERE user_id = 'legacy@example.com'",
            )
            .fetch_one(backend.pool_for_rotation())
            .await
            .unwrap(),
            1_700_000_000
        );
        backend.close().await;
        fixture.cleanup().await;
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:session_expiry_migration_rollback_retry");
    }

    #[tokio::test]
    async fn postgres_api_key_scope_v7_failure_rolls_back_and_retries() {
        let Some(fixture) = PgMigrationFixture::new().await else {
            return;
        };
        let backend = PostgresBackend::new(&fixture.scoped_url, test_master_key())
            .await
            .unwrap();
        sqlx::query(
            r#"INSERT INTO api_keys
               (id, name, prefix, key_hash, scopes, created_at)
               VALUES ($1, 'legacy-admin', 'sks_legb', 'legacy-admin-hash-2',
                       '["management:admin"]', 1)"#,
        )
        .bind(Uuid::from_u128(0x708))
        .execute(backend.pool_for_rotation())
        .await
        .unwrap();
        backend.close().await;
        let pool = fixture.pool().await;
        restore_pg_api_keys_v6_shape(&pool).await;
        sqlx::query(
            r#"CREATE FUNCTION reject_api_key_scope_v7_fn() RETURNS trigger
               LANGUAGE plpgsql AS $$
               BEGIN
                   IF NEW.version = 7 THEN
                       RAISE EXCEPTION 'injected v7 ledger failure';
                   END IF;
                   RETURN NEW;
               END
               $$"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"CREATE TRIGGER reject_api_key_scope_v7
               BEFORE INSERT ON service_migrations
               FOR EACH ROW EXECUTE FUNCTION reject_api_key_scope_v7_fn()"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let error = match PostgresBackend::new(&fixture.scoped_url, test_master_key()).await {
            Ok(_) => panic!("PG v7 failure was swallowed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("injected v7 ledger failure"));
        let pool = fixture.pool().await;
        let scope_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
             AND table_name = 'api_keys' AND column_name = 'scopes'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(scope_columns, 0);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM api_keys WHERE name = 'legacy-admin'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        sqlx::query("DROP TRIGGER reject_api_key_scope_v7 ON service_migrations")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION reject_api_key_scope_v7_fn()")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let backend = PostgresBackend::new(&fixture.scoped_url, test_master_key())
            .await
            .expect("retry PG v7 after injected failure");
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT scopes FROM api_keys WHERE name = 'legacy-admin'",
            )
            .fetch_one(backend.pool_for_rotation())
            .await
            .unwrap(),
            r#"["management:admin"]"#
        );
        backend.close().await;
        fixture.cleanup().await;
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:api_key_scopes_v7_rollback_retry");
    }

    #[tokio::test]
    async fn postgres_api_key_lookup_is_read_only_and_touch_is_cross_node() {
        let Some(fixture) = PgMigrationFixture::new().await else {
            return;
        };
        let a = Store::new_for_test(
            "sqlite::memory:",
            TEST_MASTER_KEY,
            Some(&fixture.scoped_url),
        )
        .await
        .unwrap();
        let b = Store::new_for_test(
            "sqlite::memory:",
            TEST_MASTER_KEY,
            Some(&fixture.scoped_url),
        )
        .await
        .unwrap();
        let scopes =
            ApiKeyScopeSet::from_storage(r#"["management:write"]"#).expect("canonical scopes");
        let created = a.create_api_key("cross-node", &scopes).await.unwrap();
        let looked_up = b.lookup_api_key(&created.key).await.unwrap();
        assert!(
            looked_up
                .scopes
                .allows(crate::models::api_key::ApiKeyScope::Read)
        );
        assert!(
            !looked_up
                .scopes
                .allows(crate::models::api_key::ApiKeyScope::Admin)
        );
        assert_eq!(
            a.get_api_key(created.api_key.id)
                .await
                .unwrap()
                .last_used_at,
            None
        );
        b.touch_api_key_usage(created.api_key.id).await.unwrap();
        assert!(
            a.get_api_key(created.api_key.id)
                .await
                .unwrap()
                .last_used_at
                .is_some()
        );
        a.close().await;
        b.close().await;
        fixture.cleanup().await;
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:api_key_scopes_two_node_touch");
    }

    #[tokio::test]
    async fn postgres_service_migrations_propagate_errors_and_roll_back_interruptions() {
        let Some(failed) = PgMigrationFixture::new().await else {
            return;
        };
        seed_legacy_postgres(&failed).await;
        let pool = failed.pool().await;
        sqlx::query(
            r#"CREATE FUNCTION reject_saml_cleanup_fn() RETURNS trigger
               LANGUAGE plpgsql AS $$
               BEGIN
                   RAISE EXCEPTION 'already exists injected real failure';
               END
               $$"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"CREATE TRIGGER reject_saml_cleanup
               BEFORE UPDATE ON identity_providers
               FOR EACH ROW EXECUTE FUNCTION reject_saml_cleanup_fn()"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let error = match PostgresBackend::new(&failed.scoped_url, test_master_key()).await {
            Ok(_) => panic!("real PG migration error was swallowed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("already exists injected real failure")
        );
        let pool = failed.pool().await;
        let kind_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() \
             AND table_name = 'pending_auth' AND column_name = 'kind'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kind_columns, 0);
        let ledger_exists: bool = sqlx::query_scalar(
            "SELECT to_regclass(current_schema() || '.service_migrations') IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!ledger_exists);
        sqlx::query("DROP TRIGGER reject_saml_cleanup ON identity_providers")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let backend = PostgresBackend::new(&failed.scoped_url, test_master_key())
            .await
            .expect("PG retry after database error");
        backend.close().await;
        failed.cleanup().await;

        let Some(commit_failed) = PgMigrationFixture::new().await else {
            unreachable!("TEST_POSTGRES_URL disappeared")
        };
        seed_legacy_postgres(&commit_failed).await;
        let pool = commit_failed.pool().await;
        sqlx::query(
            r#"CREATE TABLE service_migrations (
                   version BIGINT PRIMARY KEY,
                   name TEXT NOT NULL,
                   applied_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
               )"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"CREATE FUNCTION reject_migration_commit_fn() RETURNS trigger
               LANGUAGE plpgsql AS $$
               BEGIN
                   RAISE EXCEPTION 'injected deferred migration commit failure';
               END
               $$"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"CREATE CONSTRAINT TRIGGER reject_migration_commit
               AFTER INSERT ON service_migrations
               DEFERRABLE INITIALLY DEFERRED
               FOR EACH ROW EXECUTE FUNCTION reject_migration_commit_fn()"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
        let error = match PostgresBackend::new(&commit_failed.scoped_url, test_master_key()).await {
            Ok(_) => panic!("deferred PG migration commit error was swallowed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("injected deferred migration commit failure")
        );
        let pool = commit_failed.pool().await;
        let kind_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() \
             AND table_name = 'pending_auth' AND column_name = 'kind'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kind_columns, 0);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM service_migrations")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        sqlx::query("DROP TRIGGER reject_migration_commit ON service_migrations")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let backend = PostgresBackend::new(&commit_failed.scoped_url, test_master_key())
            .await
            .expect("PG retry after deferred commit error");
        backend.close().await;
        commit_failed.cleanup().await;

        let Some(v6_commit_failed) = PgMigrationFixture::new().await else {
            unreachable!("TEST_POSTGRES_URL disappeared")
        };
        let backend = PostgresBackend::new(&v6_commit_failed.scoped_url, test_master_key())
            .await
            .expect("prepare current PG schema for v6 rollback fixture");
        backend.close().await;
        let pool = v6_commit_failed.pool().await;
        sqlx::query(
            r#"CREATE TABLE api_certificate (
                   id INTEGER PRIMARY KEY CHECK (id = 1),
                   data TEXT NOT NULL,
                   expires_at BIGINT NOT NULL,
                   updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
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
            r#"CREATE FUNCTION reject_v6_commit_fn() RETURNS trigger
               LANGUAGE plpgsql AS $$
               BEGIN
                   IF NEW.version = 6 THEN
                       RAISE EXCEPTION 'injected v6 commit failure';
                   END IF;
                   RETURN NEW;
               END
               $$"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"CREATE CONSTRAINT TRIGGER reject_v6_commit
               AFTER INSERT ON service_migrations
               DEFERRABLE INITIALLY DEFERRED
               FOR EACH ROW EXECUTE FUNCTION reject_v6_commit_fn()"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
        let error =
            match PostgresBackend::new(&v6_commit_failed.scoped_url, test_master_key()).await {
                Ok(_) => panic!("deferred v6 commit error was swallowed"),
                Err(error) => error,
            };
        assert!(error.to_string().contains("injected v6 commit failure"));
        let pool = v6_commit_failed.pool().await;
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT to_regclass(current_schema() || '.api_certificate') IS NOT NULL",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            "failed v6 commit must roll back the table drop"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM service_migrations WHERE version = 6",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        sqlx::query("DROP TRIGGER reject_v6_commit ON service_migrations")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let backend = PostgresBackend::new(&v6_commit_failed.scoped_url, test_master_key())
            .await
            .expect("retry v6 after deferred commit failure");
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT to_regclass(current_schema() || '.api_certificate') IS NOT NULL",
            )
            .fetch_one(backend.pool_for_rotation())
            .await
            .unwrap()
        );
        backend.close().await;
        v6_commit_failed.cleanup().await;
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:management_rpk_v6_drop_rollback");

        let Some(cancelled) = PgMigrationFixture::new().await else {
            unreachable!("TEST_POSTGRES_URL disappeared")
        };
        seed_legacy_postgres(&cancelled).await;
        let hook = pg_migration_hook::install(1, &cancelled.schema);
        let url = cancelled.scoped_url.clone();
        let task = tokio::spawn(async move { PostgresBackend::new(&url, test_master_key()).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), hook.reached.notified())
            .await
            .expect("PG cancel hook was not reached");
        task.abort();
        let join_error = match task.await {
            Err(error) => error,
            Ok(_) => panic!("cancelled PG migration task completed"),
        };
        assert!(join_error.is_cancelled());
        pg_migration_hook::clear();
        let pool = cancelled.pool().await;
        let kind_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() \
             AND table_name = 'pending_auth' AND column_name = 'kind'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kind_columns, 0);
        pool.close().await;
        let backend = PostgresBackend::new(&cancelled.scoped_url, test_master_key())
            .await
            .expect("PG retry after cancellation");
        backend.close().await;
        cancelled.cleanup().await;

        let Some(panicked) = PgMigrationFixture::new().await else {
            unreachable!("TEST_POSTGRES_URL disappeared")
        };
        seed_legacy_postgres(&panicked).await;
        let hook = pg_migration_hook::install(2, &panicked.schema);
        hook.panic_after_release.store(true, Ordering::SeqCst);
        let url = panicked.scoped_url.clone();
        let task = tokio::spawn(async move { PostgresBackend::new(&url, test_master_key()).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), hook.reached.notified())
            .await
            .expect("PG panic hook was not reached");
        hook.release.notify_one();
        let join_error = match task.await {
            Err(error) => error,
            Ok(_) => panic!("panicked PG migration task completed"),
        };
        assert!(join_error.is_panic());
        pg_migration_hook::clear();
        let pool = panicked.pool().await;
        let kind_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() \
             AND table_name = 'pending_auth' AND column_name = 'kind'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kind_columns, 0);
        pool.close().await;
        let backend = PostgresBackend::new(&panicked.scoped_url, test_master_key())
            .await
            .expect("PG retry after panic");
        backend.close().await;
        panicked.cleanup().await;

        let Some(v7_cancelled) = PgMigrationFixture::new().await else {
            unreachable!("TEST_POSTGRES_URL disappeared")
        };
        let backend = PostgresBackend::new(&v7_cancelled.scoped_url, test_master_key())
            .await
            .unwrap();
        sqlx::query(
            r#"INSERT INTO api_keys
               (id, name, prefix, key_hash, scopes, created_at)
               VALUES ($1, 'legacy-admin', 'sks_lega', 'legacy-admin-hash',
                       '["management:admin"]', 1)"#,
        )
        .bind(Uuid::from_u128(0x707))
        .execute(backend.pool_for_rotation())
        .await
        .unwrap();
        backend.close().await;
        let pool = v7_cancelled.pool().await;
        restore_pg_api_keys_v6_shape(&pool).await;
        pool.close().await;

        let hook = pg_migration_hook::install(7, &v7_cancelled.schema);
        let url = v7_cancelled.scoped_url.clone();
        let task = tokio::spawn(async move { PostgresBackend::new(&url, test_master_key()).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), hook.reached.notified())
            .await
            .expect("PG v7 cancel hook was not reached");
        task.abort();
        let join_error = match task.await {
            Err(error) => error,
            Ok(_) => panic!("cancelled PG v7 migration task completed"),
        };
        assert!(join_error.is_cancelled());
        pg_migration_hook::clear();

        let pool = v7_cancelled.pool().await;
        let scope_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
             AND table_name = 'api_keys' AND column_name = 'scopes'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(scope_columns, 0);
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

        let backend = PostgresBackend::new(&v7_cancelled.scoped_url, test_master_key())
            .await
            .expect("retry PG v7 after cancellation");
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT scopes FROM api_keys WHERE name = 'legacy-admin'",
            )
            .fetch_one(backend.pool_for_rotation())
            .await
            .unwrap(),
            r#"["management:admin"]"#
        );
        backend.close().await;
        v7_cancelled.cleanup().await;
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:api_key_scopes_v7_cancel_retry");

        let Some(v8_cancelled) = PgMigrationFixture::new().await else {
            unreachable!("TEST_POSTGRES_URL disappeared")
        };
        let backend = PostgresBackend::new(&v8_cancelled.scoped_url, test_master_key())
            .await
            .unwrap();
        backend.close().await;
        let pool = v8_cancelled.pool().await;
        sqlx::query("DROP TABLE used_handoff_nonces")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM service_migrations WHERE version = 8")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let hook = pg_migration_hook::install(8, &v8_cancelled.schema);
        let url = v8_cancelled.scoped_url.clone();
        let task = tokio::spawn(async move { PostgresBackend::new(&url, test_master_key()).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), hook.reached.notified())
            .await
            .expect("PG v8 cancel hook was not reached");
        task.abort();
        let join_error = match task.await {
            Err(error) => error,
            Ok(_) => panic!("cancelled PG v8 migration task completed"),
        };
        assert!(join_error.is_cancelled());
        pg_migration_hook::clear();
        let pool = v8_cancelled.pool().await;
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT to_regclass(current_schema() || '.used_handoff_nonces') IS NOT NULL",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        );
        pool.close().await;
        let backend = PostgresBackend::new(&v8_cancelled.scoped_url, test_master_key())
            .await
            .expect("retry PG v8 after cancellation");
        backend.close().await;
        v8_cancelled.cleanup().await;
        eprintln!("LIVE_POSTGRES_FIXTURE_ACQUIRED:handoff_nonce_v8_cancel_retry");
    }
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct LogicalColumn {
        table: String,
        name: String,
        position: i64,
        data_type: String,
        nullable: bool,
        default: Option<String>,
        primary_key_position: i64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct LogicalIndex {
        table: String,
        name: String,
        columns: Vec<String>,
        unique: bool,
        predicate: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct LogicalSchema {
        tables: BTreeSet<String>,
        columns: BTreeSet<LogicalColumn>,
        indexes: BTreeSet<LogicalIndex>,
        checks: BTreeSet<(String, String)>,
    }

    fn expected_service_schema() -> LogicalSchema {
        let tables = [
            "acme_challenges",
            "acme_leader_election",
            "acme_queue",
            "api_keys",
            "certificates",
            "global_config",
            "identity_providers",
            "identity_signing_keys",
            "master_keys",
            "pending_auth",
            "policies",
            "routes",
            "schema_versions",
            "secrets",
            "service_migrations",
            "sessions",
            "used_handoff_nonces",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();

        let columns = [
            ("routes", "id", 1, "uuid", false, None, 1),
            ("routes", "name", 2, "text", false, None, 0),
            ("routes", "data", 3, "text", false, None, 0),
            (
                "routes",
                "created_at",
                4,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            (
                "routes",
                "updated_at",
                5,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("identity_providers", "id", 1, "uuid", false, None, 1),
            ("identity_providers", "name", 2, "text", false, None, 0),
            ("identity_providers", "idp_type", 3, "text", false, None, 0),
            ("identity_providers", "data", 4, "text", false, None, 0),
            (
                "identity_providers",
                "created_at",
                5,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            (
                "identity_providers",
                "updated_at",
                6,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("identity_signing_keys", "kid", 1, "text", false, None, 1),
            ("identity_signing_keys", "state", 2, "text", false, None, 0),
            (
                "identity_signing_keys",
                "private_key_encrypted",
                3,
                "text",
                true,
                None,
                0,
            ),
            (
                "identity_signing_keys",
                "public_jwk",
                4,
                "text",
                false,
                None,
                0,
            ),
            (
                "identity_signing_keys",
                "retire_until",
                5,
                "integer",
                true,
                None,
                0,
            ),
            (
                "identity_signing_keys",
                "created_at",
                6,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("global_config", "id", 1, "integer", false, None, 1),
            ("global_config", "data", 2, "text", false, None, 0),
            (
                "global_config",
                "updated_at",
                3,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("sessions", "id", 1, "uuid", false, None, 1),
            ("sessions", "user_id", 2, "text", false, None, 0),
            ("sessions", "idp_id", 3, "uuid", false, None, 0),
            ("sessions", "data", 4, "text", false, None, 0),
            ("sessions", "expires_at", 5, "integer", false, None, 0),
            (
                "sessions",
                "created_at",
                6,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("sessions", "last_accessed_at", 7, "integer", true, None, 0),
            ("certificates", "id", 1, "uuid", false, None, 1),
            ("certificates", "domain", 2, "text", false, None, 0),
            ("certificates", "data", 3, "text", false, None, 0),
            ("certificates", "expires_at", 4, "integer", false, None, 0),
            (
                "certificates",
                "created_at",
                5,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            (
                "certificates",
                "updated_at",
                6,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("secrets", "key", 1, "text", false, None, 1),
            ("secrets", "value", 2, "text", false, None, 0),
            (
                "secrets",
                "created_at",
                3,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("api_keys", "id", 1, "uuid", false, None, 1),
            ("api_keys", "name", 2, "text", false, None, 0),
            ("api_keys", "prefix", 3, "text", false, None, 0),
            ("api_keys", "key_hash", 4, "text", false, None, 0),
            ("api_keys", "scopes", 5, "text", false, None, 0),
            (
                "api_keys",
                "created_at",
                6,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("api_keys", "last_used_at", 7, "integer", true, None, 0),
            ("policies", "id", 1, "uuid", false, None, 1),
            ("policies", "name", 2, "text", false, None, 0),
            ("policies", "data", 3, "text", false, None, 0),
            (
                "policies",
                "created_at",
                4,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            (
                "policies",
                "updated_at",
                5,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("schema_versions", "resource", 1, "text", false, None, 1),
            (
                "schema_versions",
                "version",
                2,
                "integer",
                false,
                Some("0"),
                0,
            ),
            (
                "schema_versions",
                "updated_at",
                3,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("acme_challenges", "token", 1, "text", false, None, 1),
            ("acme_challenges", "key_auth", 2, "text", false, None, 0),
            ("acme_challenges", "domain", 3, "text", false, None, 0),
            (
                "acme_challenges",
                "created_at",
                4,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("acme_leader_election", "id", 1, "integer", false, None, 1),
            ("acme_leader_election", "node_id", 2, "text", false, None, 0),
            (
                "acme_leader_election",
                "node_hash",
                3,
                "text",
                false,
                None,
                0,
            ),
            (
                "acme_leader_election",
                "updated_at",
                4,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("pending_auth", "csrf", 1, "text", false, None, 1),
            ("pending_auth", "idp_id", 2, "uuid", false, None, 0),
            (
                "pending_auth",
                "nonce",
                3,
                "text",
                false,
                Some("empty-string"),
                0,
            ),
            (
                "pending_auth",
                "code_verifier",
                4,
                "text",
                false,
                Some("empty-string"),
                0,
            ),
            (
                "pending_auth",
                "saml_authn_request_id",
                5,
                "text",
                true,
                None,
                0,
            ),
            ("pending_auth", "redirect_url", 6, "text", false, None, 0),
            ("pending_auth", "created_at", 7, "integer", false, None, 0),
            ("pending_auth", "expires_at", 8, "integer", false, None, 0),
            ("pending_auth", "kind", 9, "text", false, Some("login"), 0),
            (
                "pending_auth",
                "browser_nonce_hash",
                10,
                "text",
                true,
                None,
                0,
            ),
            ("acme_queue", "id", 1, "uuid", false, None, 1),
            ("acme_queue", "domain", 2, "text", false, None, 0),
            ("acme_queue", "requester_node", 3, "text", false, None, 0),
            ("acme_queue", "status", 4, "text", false, Some("pending"), 0),
            ("acme_queue", "result_cert_id", 5, "uuid", true, None, 0),
            ("acme_queue", "error_msg", 6, "text", true, None, 0),
            (
                "acme_queue",
                "enqueued_at",
                7,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("acme_queue", "picked_at", 8, "integer", true, None, 0),
            ("acme_queue", "completed_at", 9, "integer", true, None, 0),
            ("master_keys", "key_id", 1, "key-id", false, None, 1),
            ("master_keys", "key_encrypted", 2, "text", false, None, 0),
            (
                "master_keys",
                "active",
                3,
                "boolean",
                false,
                Some("false"),
                0,
            ),
            (
                "master_keys",
                "retired",
                4,
                "boolean",
                false,
                Some("false"),
                0,
            ),
            (
                "master_keys",
                "created_at",
                5,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("master_keys", "retired_at", 6, "integer", true, None, 0),
            (
                "service_migrations",
                "version",
                1,
                "integer",
                false,
                None,
                1,
            ),
            ("service_migrations", "name", 2, "text", false, None, 0),
            (
                "service_migrations",
                "applied_at",
                3,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
            ("used_handoff_nonces", "nonce", 1, "uuid", false, None, 1),
            (
                "used_handoff_nonces",
                "consumed_at",
                2,
                "integer",
                false,
                Some("epoch-now"),
                0,
            ),
        ]
        .into_iter()
        .map(
            |(table, name, position, data_type, nullable, default, primary_key_position)| {
                LogicalColumn {
                    table: table.to_owned(),
                    name: name.to_owned(),
                    position,
                    data_type: data_type.to_owned(),
                    nullable,
                    default: default.map(str::to_owned),
                    primary_key_position,
                }
            },
        )
        .collect();

        let indexes = [
            (
                "acme_challenges",
                "idx_acme_challenges_domain",
                &["domain"][..],
                false,
                None,
            ),
            (
                "acme_queue",
                "idx_acme_queue_domain_active",
                &["domain"][..],
                true,
                Some("queue-active-status"),
            ),
            (
                "acme_queue",
                "idx_acme_queue_status",
                &["status", "enqueued_at"][..],
                false,
                None,
            ),
            ("api_keys", "<unique>", &["key_hash"][..], true, None),
            ("certificates", "<unique>", &["domain"][..], true, None),
            (
                "certificates",
                "idx_certificates_expires_at",
                &["expires_at"][..],
                false,
                None,
            ),
            ("identity_providers", "<unique>", &["name"][..], true, None),
            (
                "identity_signing_keys",
                "idx_identity_signing_one_state",
                &["state"][..],
                true,
                Some("one-current-and-one-retiring"),
            ),
            (
                "master_keys",
                "idx_master_keys_one_active",
                &["active"][..],
                true,
                Some("one-active-non-retired-key"),
            ),
            (
                "pending_auth",
                "idx_pending_auth_expires_at",
                &["expires_at"][..],
                false,
                None,
            ),
            ("policies", "<unique>", &["name"][..], true, None),
            ("routes", "<unique>", &["name"][..], true, None),
            (
                "sessions",
                "idx_sessions_expires_at",
                &["expires_at"][..],
                false,
                None,
            ),
            (
                "sessions",
                "idx_sessions_user_id",
                &["user_id"][..],
                false,
                None,
            ),
        ]
        .into_iter()
        .map(|(table, name, columns, unique, predicate)| LogicalIndex {
            table: table.to_owned(),
            name: name.to_owned(),
            columns: columns.iter().map(|column| (*column).to_owned()).collect(),
            unique,
            predicate: predicate.map(str::to_owned),
        })
        .collect();

        let checks = [
            ("acme_leader_election", "id=1"),
            ("global_config", "id=1"),
            ("identity_signing_keys", "identity-key-state"),
            ("identity_signing_keys", "identity-private-material-state"),
        ]
        .into_iter()
        .map(|(table, check)| (table.to_owned(), check.to_owned()))
        .collect();

        LogicalSchema {
            tables,
            columns,
            indexes,
            checks,
        }
    }

    type PgLogicalIndexParts = (bool, bool, String, BTreeMap<i64, String>);
    type PgLogicalIndexes = BTreeMap<(String, String), PgLogicalIndexParts>;

    struct TempSqliteCatalogDb {
        path: std::path::PathBuf,
        url: String,
    }

    impl TempSqliteCatalogDb {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sekisho-catalog-parity-{}-{}.sqlite3",
                std::process::id(),
                unique_schema()
            ));
            let url = format!("sqlite://{}?mode=rwc", path.display());
            Self { path, url }
        }
    }

    impl Drop for TempSqliteCatalogDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(format!("{}-shm", self.path.display()));
            let _ = std::fs::remove_file(format!("{}-wal", self.path.display()));
        }
    }

    async fn seed_legacy_sqlite_catalog(db: &TempSqliteCatalogDb) {
        let pool = SqlitePool::connect(&db.url)
            .await
            .expect("open legacy SQLite catalog fixture");
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
        .expect("legacy SQLite identity_providers");
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
        .expect("legacy SQLite pending_auth");
        sqlx::query(
            r#"INSERT INTO identity_providers (id, name, idp_type, data)
               VALUES (
                   '00000000-0000-0000-0000-000000000300',
                   'legacy-saml',
                   '"saml"',
                   '{"name":"legacy-saml","saml_config":{"metadata_url":"https://idp.example/metadata","entity_id":"dead-entity","acs_url":"https://dead.example/acs"}}'
               )"#,
        )
        .execute(&pool)
        .await
        .expect("legacy SQLite SAML row");
        sqlx::query("CREATE TABLE migration_effects (count INTEGER NOT NULL)")
            .execute(&pool)
            .await
            .expect("SQLite migration counter table");
        sqlx::query("INSERT INTO migration_effects (count) VALUES (0)")
            .execute(&pool)
            .await
            .expect("SQLite migration counter seed");
        sqlx::query(
            r#"CREATE TRIGGER count_saml_cleanup
               AFTER UPDATE ON identity_providers
               BEGIN
                   UPDATE migration_effects SET count = count + 1;
               END"#,
        )
        .execute(&pool)
        .await
        .expect("SQLite migration counter trigger");
        pool.close().await;
    }

    #[derive(Clone, Copy)]
    enum CatalogDialect {
        Sqlite,
        Postgres,
    }

    fn is_uuid_column(table: &str, column: &str) -> bool {
        matches!(
            (table, column),
            ("routes", "id")
                | ("identity_providers", "id")
                | ("sessions", "id")
                | ("sessions", "idp_id")
                | ("certificates", "id")
                | ("policies", "id")
                | ("api_keys", "id")
                | ("pending_auth", "idp_id")
                | ("acme_queue", "id")
                | ("acme_queue", "result_cert_id")
                | ("used_handoff_nonces", "nonce")
        )
    }

    fn is_integer_column(table: &str, column: &str) -> bool {
        matches!(
            (table, column),
            ("routes", "created_at" | "updated_at")
                | ("identity_providers", "created_at" | "updated_at")
                | ("identity_signing_keys", "retire_until" | "created_at")
                | ("global_config", "id" | "updated_at")
                | ("sessions", "expires_at" | "created_at" | "last_accessed_at")
                | ("certificates", "expires_at" | "created_at" | "updated_at")
                | ("secrets", "created_at")
                | ("api_keys", "created_at" | "last_used_at")
                | ("policies", "created_at" | "updated_at")
                | ("schema_versions", "version" | "updated_at")
                | ("acme_challenges", "created_at")
                | ("acme_leader_election", "id" | "updated_at")
                | ("pending_auth", "created_at" | "expires_at")
                | ("acme_queue", "enqueued_at" | "picked_at" | "completed_at")
                | ("master_keys", "created_at" | "retired_at")
                | ("service_migrations", "version" | "applied_at")
                | ("used_handoff_nonces", "consumed_at")
        )
    }

    fn logical_data_type(
        dialect: CatalogDialect,
        table: &str,
        column: &str,
        raw_type: &str,
    ) -> String {
        let logical = if is_uuid_column(table, column) {
            "uuid"
        } else if table == "master_keys" && matches!(column, "active" | "retired") {
            "boolean"
        } else if table == "master_keys" && column == "key_id" {
            "key-id"
        } else if is_integer_column(table, column) {
            "integer"
        } else {
            "text"
        };
        let expected_raw = match (dialect, logical, table, column) {
            (CatalogDialect::Sqlite, "uuid" | "text", _, _) => "text",
            (CatalogDialect::Sqlite, "boolean" | "key-id" | "integer", _, _) => "integer",
            (CatalogDialect::Postgres, "uuid", _, _) => "uuid",
            (CatalogDialect::Postgres, "boolean", _, _) => "boolean",
            (CatalogDialect::Postgres, "key-id", _, _) => "smallint",
            (
                CatalogDialect::Postgres,
                "integer",
                "global_config" | "acme_leader_election",
                "id",
            ) => "integer",
            (CatalogDialect::Postgres, "integer", _, _) => "bigint",
            (CatalogDialect::Postgres, "text", _, _) => "text",
            _ => unreachable!(),
        };
        assert_eq!(
            raw_type.to_ascii_lowercase(),
            expected_raw,
            "unapproved service-schema type for {table}.{column}"
        );
        logical.to_owned()
    }

    fn logical_default(
        dialect: CatalogDialect,
        table: &str,
        column: &str,
        raw_default: Option<String>,
    ) -> Option<String> {
        let raw = raw_default?;
        let compact = raw
            .to_ascii_lowercase()
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect::<String>();
        let normalized = match (dialect, compact.as_str(), table, column) {
            (CatalogDialect::Sqlite, "unixepoch()", _, _) => "epoch-now",
            (CatalogDialect::Postgres, "(extract(epochfromnow()))::bigint", _, _) => "epoch-now",
            (CatalogDialect::Sqlite, "0", "master_keys", "active" | "retired")
            | (CatalogDialect::Postgres, "false", "master_keys", "active" | "retired") => "false",
            (_, "0", "schema_versions", "version") => "0",
            (CatalogDialect::Sqlite, "''", "pending_auth", "nonce" | "code_verifier")
            | (CatalogDialect::Postgres, "''::text", "pending_auth", "nonce" | "code_verifier") => {
                "empty-string"
            }
            (CatalogDialect::Sqlite, "'login'", "pending_auth", "kind")
            | (CatalogDialect::Postgres, "'login'::text", "pending_auth", "kind") => "login",
            (CatalogDialect::Sqlite, "'pending'", "acme_queue", "status")
            | (CatalogDialect::Postgres, "'pending'::text", "acme_queue", "status") => "pending",
            _ => panic!("unapproved service-schema default for {table}.{column}: {raw}"),
        };
        Some(normalized.to_owned())
    }

    fn canonical_partial_predicate(
        dialect: CatalogDialect,
        index_name: &str,
        raw: Option<&str>,
    ) -> Option<String> {
        let Some(raw) = raw else {
            assert!(
                !matches!(
                    index_name,
                    "idx_acme_queue_domain_active"
                        | "idx_master_keys_one_active"
                        | "idx_identity_signing_one_state"
                ),
                "missing partial predicate on {index_name}"
            );
            return None;
        };
        let compact = raw
            .to_ascii_lowercase()
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect::<String>();
        match (dialect, index_name, compact.as_str()) {
            (
                CatalogDialect::Sqlite,
                "idx_acme_queue_domain_active",
                "statusin('pending','in_progress')",
            )
            | (
                CatalogDialect::Postgres,
                "idx_acme_queue_domain_active",
                "(status=any(array['pending'::text,'in_progress'::text]))",
            ) => Some("queue-active-status".to_owned()),
            (CatalogDialect::Sqlite, "idx_master_keys_one_active", "active=1andretired=0")
            | (
                CatalogDialect::Postgres,
                "idx_master_keys_one_active",
                "((active=true)and(retired=false))",
            ) => Some("one-active-non-retired-key".to_owned()),
            (
                CatalogDialect::Sqlite,
                "idx_identity_signing_one_state",
                "statein('current','retiring')",
            )
            | (
                CatalogDialect::Postgres,
                "idx_identity_signing_one_state",
                "(state=any(array['current'::text,'retiring'::text]))",
            ) => Some("one-current-and-one-retiring".to_owned()),
            _ => panic!("unapproved partial predicate on {index_name}: {raw}"),
        }
    }

    fn sqlite_check_clauses(create_sql: &str) -> Vec<&str> {
        let lower = create_sql.to_ascii_lowercase();
        let bytes = lower.as_bytes();
        let mut clauses = Vec::new();
        let mut cursor = 0;
        while let Some(relative) = lower[cursor..].find("check") {
            let start = cursor + relative;
            let before_is_identifier = start
                .checked_sub(1)
                .is_some_and(|index| bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_');
            let after = start + "check".len();
            let after_is_identifier = bytes
                .get(after)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
            if before_is_identifier || after_is_identifier {
                cursor = after;
                continue;
            }

            let mut open = after;
            while bytes.get(open).is_some_and(u8::is_ascii_whitespace) {
                open += 1;
            }
            assert_eq!(
                bytes.get(open),
                Some(&b'('),
                "malformed SQLite CHECK in service schema"
            );

            let mut depth = 0usize;
            let mut close = None;
            for (offset, byte) in bytes[open..].iter().enumerate() {
                match byte {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(open + offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let close = close.expect("unterminated SQLite CHECK in service schema");
            clauses.push(&create_sql[open + 1..close]);
            cursor = close + 1;
        }
        clauses
    }

    fn canonical_sqlite_check(table: &str, raw: &str) -> String {
        let compact = raw
            .to_ascii_lowercase()
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect::<String>();
        match (table, compact.as_str()) {
            ("global_config" | "acme_leader_election", "id=1") => "id=1".to_owned(),
            ("identity_signing_keys", "statein('current','retiring')") => {
                "identity-key-state".to_owned()
            }
            (
                "identity_signing_keys",
                "(state='current'andprivate_key_encryptedisnotnullandretire_untilisnull)or(state='retiring'andprivate_key_encryptedisnullandretire_untilisnotnull)",
            ) => "identity-private-material-state".to_owned(),
            _ => panic!("unapproved SQLite CHECK on {table}: {raw}"),
        }
    }

    async fn sqlite_logical_schema(pool: &SqlitePool) -> LogicalSchema {
        let tables: BTreeSet<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .collect();

        let mut columns = BTreeSet::new();
        let mut indexes = BTreeSet::new();
        let mut checks = BTreeSet::new();
        for table in &tables {
            let column_rows = sqlx::query(&format!("PRAGMA table_info(\"{table}\")"))
                .fetch_all(pool)
                .await
                .unwrap();
            for row in column_rows {
                let name: String = row.get("name");
                let raw_type: String = row.get("type");
                let primary_key_position: i64 = row.get("pk");
                let declared_not_null: i64 = row.get("notnull");
                columns.insert(LogicalColumn {
                    table: table.clone(),
                    name: name.clone(),
                    position: row.get::<i64, _>("cid") + 1,
                    data_type: logical_data_type(CatalogDialect::Sqlite, table, &name, &raw_type),
                    nullable: declared_not_null == 0 && primary_key_position == 0,
                    default: logical_default(
                        CatalogDialect::Sqlite,
                        table,
                        &name,
                        row.get("dflt_value"),
                    ),
                    primary_key_position,
                });
            }

            let index_rows = sqlx::query(&format!("PRAGMA index_list(\"{table}\")"))
                .fetch_all(pool)
                .await
                .unwrap();
            for row in index_rows {
                let origin: String = row.get("origin");
                if origin == "pk" {
                    continue;
                }
                let raw_name: String = row.get("name");
                let unique = row.get::<i64, _>("unique") != 0;
                let index_columns = sqlx::query(&format!("PRAGMA index_info(\"{raw_name}\")"))
                    .fetch_all(pool)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|row| (row.get::<i64, _>("seqno"), row.get::<String, _>("name")))
                    .collect::<BTreeMap<_, _>>()
                    .into_values()
                    .collect::<Vec<_>>();
                let sql: Option<String> =
                    sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE name = ?")
                        .bind(&raw_name)
                        .fetch_one(pool)
                        .await
                        .unwrap();
                let predicate = if row.get::<i64, _>("partial") != 0 {
                    let predicate = sql
                        .as_deref()
                        .and_then(|sql| sql.split_once(" WHERE ").map(|(_, predicate)| predicate));
                    canonical_partial_predicate(CatalogDialect::Sqlite, &raw_name, predicate)
                } else {
                    canonical_partial_predicate(CatalogDialect::Sqlite, &raw_name, None)
                };
                indexes.insert(LogicalIndex {
                    table: table.clone(),
                    name: if origin == "u" {
                        "<unique>".to_owned()
                    } else {
                        raw_name
                    },
                    columns: index_columns,
                    unique,
                    predicate,
                });
            }
        }

        for table in &tables {
            let create_sql: String = sqlx::query_scalar(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            )
            .bind(table)
            .fetch_one(pool)
            .await
            .unwrap();
            for clause in sqlite_check_clauses(&create_sql) {
                let logical = canonical_sqlite_check(table, clause);
                assert!(
                    checks.insert((table.clone(), logical)),
                    "duplicate SQLite CHECK on {table}"
                );
            }
        }

        LogicalSchema {
            tables,
            columns,
            indexes,
            checks,
        }
    }

    async fn postgres_logical_schema(pool: &PgPool) -> LogicalSchema {
        let tables: BTreeSet<String> = sqlx::query_scalar(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' \
             ORDER BY table_name",
        )
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .collect();

        let primary_keys: BTreeMap<(String, String), i64> = sqlx::query(
            r#"SELECT tc.table_name, kcu.column_name, kcu.ordinal_position::BIGINT AS key_position
               FROM information_schema.table_constraints tc
               JOIN information_schema.key_column_usage kcu
                 ON tc.constraint_catalog = kcu.constraint_catalog
                AND tc.constraint_schema = kcu.constraint_schema
                AND tc.constraint_name = kcu.constraint_name
               WHERE tc.table_schema = current_schema()
                 AND tc.constraint_type = 'PRIMARY KEY'"#,
        )
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            (
                (row.get("table_name"), row.get("column_name")),
                row.get("key_position"),
            )
        })
        .collect();

        let mut columns = BTreeSet::new();
        for row in sqlx::query(
            r#"SELECT table_name, column_name, ordinal_position::BIGINT AS position,
                      data_type, is_nullable, column_default
               FROM information_schema.columns
               WHERE table_schema = current_schema()
               ORDER BY table_name, ordinal_position"#,
        )
        .fetch_all(pool)
        .await
        .unwrap()
        {
            let table: String = row.get("table_name");
            let name: String = row.get("column_name");
            let primary_key_position = primary_keys
                .get(&(table.clone(), name.clone()))
                .copied()
                .unwrap_or(0);
            columns.insert(LogicalColumn {
                table: table.clone(),
                name: name.clone(),
                position: row.get("position"),
                data_type: logical_data_type(
                    CatalogDialect::Postgres,
                    &table,
                    &name,
                    row.get("data_type"),
                ),
                nullable: row.get::<String, _>("is_nullable") == "YES" && primary_key_position == 0,
                default: logical_default(
                    CatalogDialect::Postgres,
                    &table,
                    &name,
                    row.get("column_default"),
                ),
                primary_key_position,
            });
        }

        let index_rows = sqlx::query(
            r#"SELECT table_class.relname AS table_name,
                      index_class.relname AS index_name,
                      idx.indisunique,
                      idx.indisprimary,
                      COALESCE(pg_get_expr(idx.indpred, idx.indrelid), '') AS predicate,
                      attribute.attname AS column_name,
                      ordinality::BIGINT AS position
               FROM pg_index idx
               JOIN pg_class table_class ON table_class.oid = idx.indrelid
               JOIN pg_namespace namespace ON namespace.oid = table_class.relnamespace
               JOIN pg_class index_class ON index_class.oid = idx.indexrelid
               JOIN LATERAL unnest(idx.indkey)
                    WITH ORDINALITY AS key_column(attnum, ordinality) ON TRUE
               JOIN pg_attribute attribute
                 ON attribute.attrelid = idx.indrelid
                AND attribute.attnum = key_column.attnum
               WHERE namespace.nspname = current_schema()
               ORDER BY table_name, index_name, position"#,
        )
        .fetch_all(pool)
        .await
        .unwrap();
        let mut grouped_indexes = PgLogicalIndexes::new();
        for row in index_rows {
            let table: String = row.get("table_name");
            let name: String = row.get("index_name");
            let entry = grouped_indexes.entry((table, name)).or_insert_with(|| {
                (
                    row.get("indisunique"),
                    row.get("indisprimary"),
                    row.get("predicate"),
                    BTreeMap::new(),
                )
            });
            entry.3.insert(row.get("position"), row.get("column_name"));
        }

        let mut indexes = BTreeSet::new();
        for ((table, raw_name), (unique, primary, predicate, columns_by_position)) in
            grouped_indexes
        {
            if primary {
                continue;
            }
            let predicate = canonical_partial_predicate(
                CatalogDialect::Postgres,
                &raw_name,
                (!predicate.is_empty()).then_some(predicate.as_str()),
            );
            indexes.insert(LogicalIndex {
                table,
                name: if unique && predicate.is_none() {
                    "<unique>".to_owned()
                } else {
                    raw_name
                },
                columns: columns_by_position.into_values().collect(),
                unique,
                predicate,
            });
        }

        let mut checks = BTreeSet::new();
        for row in sqlx::query(
            r#"SELECT tc.table_name, cc.check_clause
               FROM information_schema.table_constraints tc
               JOIN information_schema.check_constraints cc
                 ON tc.constraint_catalog = cc.constraint_catalog
                AND tc.constraint_schema = cc.constraint_schema
                AND tc.constraint_name = cc.constraint_name
               WHERE tc.table_schema = current_schema()
                 AND tc.constraint_type = 'CHECK'"#,
        )
        .fetch_all(pool)
        .await
        .unwrap()
        {
            let table: String = row.get("table_name");
            let clause: String = row.get("check_clause");
            let compact = clause
                .to_ascii_lowercase()
                .chars()
                .filter(|ch| !ch.is_ascii_whitespace() && *ch != '(' && *ch != ')')
                .collect::<String>();
            if compact == "id=1" {
                checks.insert((table, "id=1".to_owned()));
            } else if let Some(column) = compact.strip_suffix("isnotnull") {
                assert!(
                    columns.iter().any(|entry| {
                        entry.table == table && entry.name == column && !entry.nullable
                    }),
                    "Postgres exposed an unmatched NOT NULL check on {table}.{column}"
                );
            } else {
                panic!("unapproved Postgres CHECK on {table}: {clause}");
            }
        }

        LogicalSchema {
            tables,
            columns,
            indexes,
            checks,
        }
    }

    #[tokio::test]
    async fn sqlite_and_postgres_service_catalogs_have_logical_parity() {
        let Some(fresh_postgres) = PgMigrationFixture::new().await else {
            return;
        };
        let fresh_sqlite = TempSqliteCatalogDb::new();
        let fresh_sqlite_backend = SqliteBackend::new_service(&fresh_sqlite.url, test_master_key())
            .await
            .unwrap();
        let fresh_postgres_backend =
            PostgresBackend::new(&fresh_postgres.scoped_url, test_master_key())
                .await
                .unwrap();

        let expected = expected_service_schema();
        let fresh_sqlite_schema = sqlite_logical_schema(fresh_sqlite_backend.pool()).await;
        let fresh_postgres_schema =
            postgres_logical_schema(fresh_postgres_backend.pool_for_rotation()).await;
        assert_eq!(
            fresh_sqlite_schema, expected,
            "fresh SQLite catalog differs from frozen service schema"
        );
        assert_eq!(
            fresh_postgres_schema, expected,
            "fresh Postgres catalog differs from frozen service schema"
        );
        assert_eq!(
            fresh_sqlite_schema, fresh_postgres_schema,
            "fresh service catalogs differ across dialects"
        );

        let upgraded_sqlite = TempSqliteCatalogDb::new();
        seed_legacy_sqlite_catalog(&upgraded_sqlite).await;
        let upgraded_sqlite_backend =
            SqliteBackend::new_service(&upgraded_sqlite.url, test_master_key())
                .await
                .unwrap();
        sqlx::query("DROP TRIGGER count_saml_cleanup")
            .execute(upgraded_sqlite_backend.pool())
            .await
            .expect("drop SQLite migration probe trigger");
        sqlx::query("DROP TABLE migration_effects")
            .execute(upgraded_sqlite_backend.pool())
            .await
            .expect("drop SQLite migration probe table");

        let upgraded_postgres = PgMigrationFixture::new()
            .await
            .expect("TEST_POSTGRES_URL was available for fresh fixture");
        seed_legacy_postgres(&upgraded_postgres).await;
        let upgraded_postgres_backend =
            PostgresBackend::new(&upgraded_postgres.scoped_url, test_master_key())
                .await
                .unwrap();
        sqlx::query("DROP TRIGGER count_saml_cleanup ON identity_providers")
            .execute(upgraded_postgres_backend.pool_for_rotation())
            .await
            .expect("drop Postgres migration probe trigger");
        sqlx::query("DROP FUNCTION count_saml_cleanup_fn()")
            .execute(upgraded_postgres_backend.pool_for_rotation())
            .await
            .expect("drop Postgres migration probe function");
        sqlx::query("DROP TABLE migration_effects")
            .execute(upgraded_postgres_backend.pool_for_rotation())
            .await
            .expect("drop Postgres migration probe table");

        let upgraded_sqlite_schema = sqlite_logical_schema(upgraded_sqlite_backend.pool()).await;
        let upgraded_postgres_schema =
            postgres_logical_schema(upgraded_postgres_backend.pool_for_rotation()).await;
        assert_eq!(
            upgraded_sqlite_schema, expected,
            "upgraded SQLite catalog differs from frozen service schema"
        );
        assert_eq!(
            upgraded_postgres_schema, expected,
            "upgraded Postgres catalog differs from frozen service schema"
        );
        assert_eq!(
            upgraded_sqlite_schema, upgraded_postgres_schema,
            "upgraded service catalogs differ across dialects"
        );

        fresh_sqlite_backend.close().await;
        fresh_postgres_backend.close().await;
        fresh_postgres.cleanup().await;
        upgraded_sqlite_backend.close().await;
        upgraded_postgres_backend.close().await;
        upgraded_postgres.cleanup().await;
    }

    #[tokio::test]
    async fn sqlite_service_catalog_matches_frozen_schema_after_fresh_and_upgrade() {
        let expected = expected_service_schema();
        let fresh = TempSqliteCatalogDb::new();
        let fresh_backend = SqliteBackend::new_service(&fresh.url, test_master_key())
            .await
            .unwrap();
        assert_eq!(
            sqlite_logical_schema(fresh_backend.pool()).await,
            expected,
            "fresh SQLite catalog differs from frozen service schema"
        );

        let upgraded = TempSqliteCatalogDb::new();
        seed_legacy_sqlite_catalog(&upgraded).await;
        let upgraded_backend = SqliteBackend::new_service(&upgraded.url, test_master_key())
            .await
            .unwrap();
        sqlx::query("DROP TRIGGER count_saml_cleanup")
            .execute(upgraded_backend.pool())
            .await
            .expect("drop SQLite migration probe trigger");
        sqlx::query("DROP TABLE migration_effects")
            .execute(upgraded_backend.pool())
            .await
            .expect("drop SQLite migration probe table");
        assert_eq!(
            sqlite_logical_schema(upgraded_backend.pool()).await,
            expected,
            "upgraded SQLite catalog differs from frozen service schema"
        );

        fresh_backend.close().await;
        upgraded_backend.close().await;
    }

    #[test]
    fn catalog_normalization_rejects_unapproved_dialect_drift() {
        assert!(
            std::panic::catch_unwind(|| {
                logical_data_type(CatalogDialect::Postgres, "routes", "id", "text")
            })
            .is_err(),
            "Postgres uuid-to-text drift was accepted"
        );
        assert!(
            std::panic::catch_unwind(|| {
                logical_default(
                    CatalogDialect::Postgres,
                    "routes",
                    "created_at",
                    Some("(EXTRACT(EPOCH FROM NOW()) + 1)::BIGINT".to_owned()),
                )
            })
            .is_err(),
            "computed default drift was accepted"
        );
        assert!(
            std::panic::catch_unwind(|| {
                canonical_partial_predicate(
                    CatalogDialect::Postgres,
                    "idx_acme_queue_domain_active",
                    Some("status NOT IN ('failed') OR status = 'pending'"),
                )
            })
            .is_err(),
            "partial-index predicate drift was accepted"
        );
        assert!(
            std::panic::catch_unwind(|| {
                for clause in sqlite_check_clauses(
                    "CREATE TABLE global_config (\
                     id INTEGER CHECK (id = 1), \
                     data TEXT CHECK (length(data) > 0))",
                ) {
                    canonical_sqlite_check("global_config", clause);
                }
            })
            .is_err(),
            "additional CHECK on a singleton table was accepted"
        );
        assert!(
            std::panic::catch_unwind(|| {
                for clause in sqlite_check_clauses(
                    "CREATE TABLE routes (id TEXT PRIMARY KEY, CHECK (id = 1))",
                ) {
                    canonical_sqlite_check("routes", clause);
                }
            })
            .is_err(),
            "CHECK on an unapproved service table was accepted"
        );
    }
}
