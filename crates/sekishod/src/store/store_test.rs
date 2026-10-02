//! Backend-parity tests for the store facade.
//!
//! Every case runs against both SQLite and Postgres where the backend is
//! available, because the facade's promise is that the two are
//! indistinguishable to callers. A test written against one backend only
//! proves that backend; the divergences worth catching — merge-patch
//! semantics, pagination bounds, timestamp representation, encryption
//! ownership — are exactly the ones that appear when the same operation is
//! asked of a different engine.

#[cfg(test)]
mod tests {
    use crate::crypto::MasterKey;
    use crate::models::api_key::ApiKeyScopeSet;
    use crate::models::cert::CertSource;
    use crate::models::idp::{IdentityProvider, IdpType, OidcConfig};
    use crate::models::policy::Policy;
    use crate::models::route::{CreateRoute, HeaderModifications, RouteAccess};
    use crate::models::session::Session;
    use crate::store::Store;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use uuid::Uuid;

    /// Backends to exercise in each CRUD test.
    ///
    /// SQLite always runs against a fresh in-memory DB. Postgres runs only
    /// when `TEST_POSTGRES_URL` is set. Cargo runs tests in parallel in a
    /// single process, so we can't share one schema and drop-recreate it
    /// per test — that would race. Instead each test gets its own named
    /// schema via a `search_path=<unique>` parameter on the URL, which
    /// sqlx forwards to Postgres as the connection's default schema. All
    /// DDL from `Store::new` lands there, and the tests stay isolated
    /// without needing CREATE DATABASE permissions.
    async fn stores_under_test() -> Vec<(&'static str, Store)> {
        // SQLite case: in-memory bootstrap DB, service backend reuses it.
        let mut out = vec![(
            "sqlite",
            Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
                .await
                .expect("sqlite store"),
        )];

        if let Ok(url) = std::env::var("TEST_POSTGRES_URL") {
            let schema = unique_schema_name();

            // Create the schema up front on a throwaway connection; once
            // it exists, the test's own `Store::new` connects with
            // `search_path=<schema>` and does everything inside it.
            let pool = sqlx::PgPool::connect(&url)
                .await
                .expect("connect to TEST_POSTGRES_URL");
            sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
                .execute(&pool)
                .await
                .expect("drop test schema");
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&pool)
                .await
                .expect("create test schema");
            drop(pool);

            let scoped_url = with_search_path(&url, &schema);
            // Postgres case: a throwaway in-memory SQLite acts as the
            // bootstrap DB so the service backend is exclusively PG.
            // Postgres case: a throwaway in-memory SQLite acts as the
            // bootstrap DB so the service backend is exclusively PG.
            // `new_for_test` bypasses env-var resolution so parallel
            // tests don't race on `SEKISHO_SERVICE_DB`.
            out.push((
                "postgres",
                Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, Some(&scoped_url))
                    .await
                    .expect("postgres store"),
            ));
        }

        out
    }

    enum RelationalTestControl {
        Sqlite(sqlx::SqlitePool),
        Postgres(sqlx::PgPool),
    }

    /// Build stores together with test-only database handles so pagination
    /// assertions can pin the relational ordering column, not just JSON data.
    async fn stores_with_relational_control() -> Vec<(&'static str, Store, RelationalTestControl)> {
        let sqlite = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .expect("sqlite store");
        let sqlite_pool = sqlite.sqlite_pool().clone();
        let mut out = vec![("sqlite", sqlite, RelationalTestControl::Sqlite(sqlite_pool))];

        if let Ok(url) = std::env::var("TEST_POSTGRES_URL") {
            let schema = unique_schema_name();
            let pool = sqlx::PgPool::connect(&url)
                .await
                .expect("connect to TEST_POSTGRES_URL");
            sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
                .execute(&pool)
                .await
                .expect("drop test schema");
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&pool)
                .await
                .expect("create test schema");
            drop(pool);

            let scoped_url = with_search_path(&url, &schema);
            let postgres =
                Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, Some(&scoped_url))
                    .await
                    .expect("postgres store");
            let postgres_pool = sqlx::PgPool::connect(&scoped_url)
                .await
                .expect("connect to scoped Postgres schema");
            out.push((
                "postgres",
                postgres,
                RelationalTestControl::Postgres(postgres_pool),
            ));
        }

        out
    }

    async fn pin_session_created_at(control: &RelationalTestControl, created_at: i64) -> u64 {
        match control {
            RelationalTestControl::Sqlite(pool) => {
                sqlx::query("UPDATE sessions SET created_at = ?")
                    .bind(created_at)
                    .execute(pool)
                    .await
                    .expect("pin SQLite sessions.created_at")
                    .rows_affected()
            }
            RelationalTestControl::Postgres(pool) => {
                sqlx::query("UPDATE sessions SET created_at = $1")
                    .bind(created_at)
                    .execute(pool)
                    .await
                    .expect("pin Postgres sessions.created_at")
                    .rows_affected()
            }
        }
    }

    async fn set_session_authority_times(
        control: &RelationalTestControl,
        id: Uuid,
        expires_at: i64,
        last_accessed_at: i64,
    ) {
        match control {
            RelationalTestControl::Sqlite(pool) => {
                sqlx::query(
                    "UPDATE sessions SET expires_at = ?, last_accessed_at = ? WHERE id = ?",
                )
                .bind(expires_at)
                .bind(last_accessed_at)
                .bind(id)
                .execute(pool)
                .await
                .expect("set SQLite session authority times");
            }
            RelationalTestControl::Postgres(pool) => {
                sqlx::query(
                    "UPDATE sessions SET expires_at = $1, last_accessed_at = $2 WHERE id = $3",
                )
                .bind(expires_at)
                .bind(last_accessed_at)
                .bind(id)
                .execute(pool)
                .await
                .expect("set Postgres session authority times");
            }
        }
    }

    async fn insert_api_key_page_rows(control: &RelationalTestControl) -> Vec<Uuid> {
        let ids = [4_u128, 1, 3, 2].map(Uuid::from_u128);
        for (index, id) in ids.iter().enumerate() {
            let name = format!("page-key-{index}");
            let prefix = format!("page{index:04}");
            let key_hash = format!("page-hash-{index}");
            match control {
                RelationalTestControl::Sqlite(pool) => {
                    sqlx::query(
                        r#"INSERT INTO api_keys
                           (id, name, prefix, key_hash, scopes, created_at, last_used_at)
                           VALUES (?, ?, ?, ?, '["management:admin"]', 1700000000, NULL)"#,
                    )
                    .bind(id)
                    .bind(&name)
                    .bind(&prefix)
                    .bind(&key_hash)
                    .execute(pool)
                    .await
                    .expect("insert SQLite API-key page row");
                }
                RelationalTestControl::Postgres(pool) => {
                    sqlx::query(
                        r#"INSERT INTO api_keys
                           (id, name, prefix, key_hash, scopes, created_at, last_used_at)
                           VALUES ($1, $2, $3, $4, '["management:admin"]', 1700000000, NULL)"#,
                    )
                    .bind(id)
                    .bind(&name)
                    .bind(&prefix)
                    .bind(&key_hash)
                    .execute(pool)
                    .await
                    .expect("insert Postgres API-key page row");
                }
            }
        }
        ids.into_iter().collect()
    }

    fn page_test_route(id: Uuid, name: &str) -> crate::models::route::Route {
        let mut route = CreateRoute {
            name: name.into(),
            from: format!("https://{name}.example"),
            to: vec!["http://upstream.example".into()],
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
        .into_route();
        route.id = id;
        route
    }

    /// Master key used by every test Store. Fixed so tests are
    /// reproducible; the bytes are not a secret.
    const TEST_MASTER_KEY: [u8; 32] = [0u8; 32];

    #[tokio::test]
    async fn store_instance_and_backend_share_one_master_key_owner() {
        let owner = MasterKey::from_test_bytes(TEST_MASTER_KEY);
        let store = Store::new("sqlite::memory:", std::sync::Arc::clone(&owner))
            .await
            .unwrap();
        assert!(store.shares_master_key(&owner));
    }

    /// Append `options=-csearch_path=<schema>` to the URL so every
    /// connection from the pool sees that schema as its default. This is
    /// the standard libpq mechanism and sqlx passes it through unchanged.
    fn with_search_path(url: &str, schema: &str) -> String {
        let sep = if url.contains('?') { '&' } else { '?' };
        // The `-c` flag value uses `%3D` for `=` so it round-trips cleanly
        // through URL parsing.
        format!("{url}{sep}options=-csearch_path%3D{schema}")
    }

    /// Short unique schema id derived from a counter, low enough to fit
    /// inside Postgres's 63-char identifier limit. A static atomic is
    /// enough: tests share the process.
    fn unique_schema_name() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        format!("sekisho_test_{pid}_{n}")
    }

    // ═══════════════════════ Routes ═══════════════════════

    #[tokio::test]
    async fn route_crud() {
        for (label, store) in stores_under_test().await {
            let route = CreateRoute {
                name: "test-app".into(),
                from: "https://app.test.io".into(),
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
            .into_route();
            store
                .create_route(&route)
                .await
                .unwrap_or_else(|e| panic!("[{label}] create_route: {e}"));

            let fetched = store
                .get_route(route.id)
                .await
                .unwrap_or_else(|e| panic!("[{label}] get_route: {e}"));
            assert_eq!(fetched.name, "test-app", "[{label}]");

            let all = store
                .list_routes()
                .await
                .unwrap_or_else(|e| panic!("[{label}] list_routes: {e}"));
            assert_eq!(all.len(), 1, "[{label}]");

            let updated = store
                .update_route(route.id, serde_json::json!({"name": "updated-app"}))
                .await
                .unwrap_or_else(|e| panic!("[{label}] update_route: {e}"));
            assert_eq!(updated.name, "updated-app", "[{label}]");

            store
                .delete_route(route.id)
                .await
                .unwrap_or_else(|e| panic!("[{label}] delete_route: {e}"));
            assert!(store.get_route(route.id).await.is_err(), "[{label}]");
        }
    }

    #[tokio::test]
    async fn route_duplicate_name_rejected() {
        for (label, store) in stores_under_test().await {
            let r1 = CreateRoute {
                name: "dup".into(),
                from: "https://a.test.io".into(),
                to: vec!["http://b:80".into()],
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
            .into_route();
            store
                .create_route(&r1)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));

            let r2 = CreateRoute {
                name: "dup".into(),
                from: "https://b.test.io".into(),
                to: vec!["http://c:80".into()],
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
            .into_route();
            assert!(
                store.create_route(&r2).await.is_err(),
                "[{label}] second insert should conflict"
            );
        }
    }

    #[tokio::test]
    async fn route_not_found() {
        for (label, store) in stores_under_test().await {
            assert!(store.get_route(Uuid::new_v4()).await.is_err(), "[{label}]");
            assert!(
                store.delete_route(Uuid::new_v4()).await.is_err(),
                "[{label}]"
            );
        }
    }

    #[tokio::test]
    async fn signed_identity_route_validation_is_atomic_with_version_writes() {
        for (label, store) in stores_under_test().await {
            let version0 = store.route_version_current().await.unwrap();
            let mut invalid_create = page_test_route(Uuid::new_v4(), "invalid-signed-create");
            invalid_create.from = "http://invalid.example".into();
            invalid_create.enable_signed_identity = true;
            let error = store.create_route(&invalid_create).await.unwrap_err();
            assert!(
                matches!(error, crate::error::Error::BadRequest(_)),
                "[{label}] {error}"
            );
            assert!(store.list_routes().await.unwrap().is_empty(), "[{label}]");
            assert_eq!(
                store.route_version_current().await.unwrap(),
                version0,
                "[{label}] rejected create advanced the route version"
            );

            let mut staged = page_test_route(Uuid::new_v4(), "staged-signed-update");
            staged.from = "http://legacy.example".into();
            store.create_route(&staged).await.unwrap();
            let version1 = store.route_version_current().await.unwrap();
            let error = store
                .update_route(
                    staged.id,
                    serde_json::json!({"enable_signed_identity": true}),
                )
                .await
                .unwrap_err();
            assert!(
                matches!(error, crate::error::Error::BadRequest(_)),
                "[{label}] {error}"
            );
            let unchanged = store.get_route(staged.id).await.unwrap();
            assert!(!unchanged.enable_signed_identity, "[{label}]");
            assert_eq!(unchanged.from, "http://legacy.example", "[{label}]");
            assert_eq!(
                store.route_version_current().await.unwrap(),
                version1,
                "[{label}] rejected update advanced the route version"
            );

            let enabled = store
                .update_route(
                    staged.id,
                    serde_json::json!({
                        "from": "https://canonical.example",
                        "enable_signed_identity": true
                    }),
                )
                .await
                .unwrap();
            assert!(enabled.enable_signed_identity, "[{label}]");
            assert_eq!(enabled.from, "https://canonical.example", "[{label}]");
        }
    }

    #[tokio::test]
    async fn proxy_owned_policy_rejection_is_atomic_for_policy_and_route_writers() {
        const UNSAFE: &str = r#"request.header.x_sekisho_user == "admin""#;
        const SAFE: &str = r#"request.header.x_request_source == "scheduler""#;

        for (label, store) in stores_under_test().await {
            let rejected_policy = Policy {
                id: Uuid::new_v4(),
                name: format!("rejected-policy-{label}"),
                expr: UNSAFE.into(),
            };
            let error = store.create_policy(&rejected_policy).await.unwrap_err();
            assert!(
                matches!(error, crate::error::Error::BadRequest(_)),
                "[{label}] {error}"
            );
            assert!(
                store.get_policy(rejected_policy.id).await.is_err(),
                "[{label}] rejected policy was stored"
            );

            let policy = Policy {
                id: Uuid::new_v4(),
                name: format!("safe-policy-{label}"),
                expr: SAFE.into(),
            };
            store.create_policy(&policy).await.unwrap();
            let error = store
                .update_policy(policy.id, serde_json::json!({"expr": UNSAFE}))
                .await
                .unwrap_err();
            assert!(
                matches!(error, crate::error::Error::BadRequest(_)),
                "[{label}] {error}"
            );
            assert_eq!(
                store.get_policy(policy.id).await.unwrap().expr,
                SAFE,
                "[{label}] rejected policy update mutated the row"
            );

            let version0 = store.route_version_current().await.unwrap();
            let mut rejected_route =
                page_test_route(Uuid::new_v4(), &format!("rejected-route-{label}"));
            rejected_route.access.policy = Some(UNSAFE.into());
            let error = store.create_route(&rejected_route).await.unwrap_err();
            assert!(
                matches!(error, crate::error::Error::BadRequest(_)),
                "[{label}] {error}"
            );
            assert!(
                store.get_route(rejected_route.id).await.is_err(),
                "[{label}] rejected route was stored"
            );
            assert_eq!(
                store.route_version_current().await.unwrap(),
                version0,
                "[{label}] rejected route create advanced the version"
            );

            let mut route = page_test_route(Uuid::new_v4(), &format!("safe-route-{label}"));
            route.access.policy = Some(SAFE.into());
            store.create_route(&route).await.unwrap();
            let version1 = store.route_version_current().await.unwrap();
            let error = store
                .update_route(
                    route.id,
                    serde_json::json!({
                        "access": {
                            "policy": UNSAFE,
                            "allow_public_unauthenticated_access": false
                        },
                        "enabled": true
                    }),
                )
                .await
                .unwrap_err();
            assert!(
                matches!(error, crate::error::Error::BadRequest(_)),
                "[{label}] {error}"
            );
            let unchanged = store.get_route(route.id).await.unwrap();
            assert_eq!(unchanged.access.policy.as_deref(), Some(SAFE), "[{label}]");
            assert!(!unchanged.enabled, "[{label}]");
            assert_eq!(
                store.route_version_current().await.unwrap(),
                version1,
                "[{label}] rejected route update advanced the version"
            );
        }
    }

    #[tokio::test]
    async fn management_resource_pages_are_sql_bounded_and_stably_ordered() {
        let stores = stores_with_relational_control().await;
        let expected_backends = if std::env::var_os("TEST_POSTGRES_URL").is_some() {
            2
        } else {
            1
        };
        assert_eq!(
            stores.len(),
            expected_backends,
            "TEST_POSTGRES_URL must execute the Postgres case"
        );

        for (label, store, control) in stores {
            for (index, name) in ["delta", "alpha", "gamma", "beta"].iter().enumerate() {
                let id = Uuid::from_u128(0x100 + index as u128);
                store
                    .create_route(&page_test_route(id, name))
                    .await
                    .unwrap_or_else(|e| panic!("[{label}] create route: {e}"));
                store
                    .create_idp(&IdentityProvider {
                        id: Uuid::from_u128(0x200 + index as u128),
                        name: (*name).into(),
                        idp_type: IdpType::Oidc,
                        oidc_config: Some(OidcConfig {
                            issuer_url: format!("https://{name}.example"),
                            client_id: format!("client-{name}"),
                            client_secret_encrypted: "encrypted".into(),
                            scopes: vec!["openid".into()],
                            prompt: None,
                        }),
                        saml_config: None,
                    })
                    .await
                    .unwrap_or_else(|e| panic!("[{label}] create IdP: {e}"));
                store
                    .create_policy(&crate::models::policy::Policy {
                        id: Uuid::from_u128(0x300 + index as u128),
                        name: (*name).into(),
                        expr: r#"claim.username == "page@example.com""#.into(),
                    })
                    .await
                    .unwrap_or_else(|e| panic!("[{label}] create policy: {e}"));
                store
                    .upsert_cert(&crate::models::cert::Certificate {
                        id: Uuid::from_u128(0x400 + index as u128),
                        domain: format!("{name}.example"),
                        cert_pem: "certificate".into(),
                        key_pem_encrypted: "encrypted-key".into(),
                        issued_at: Utc::now(),
                        expires_at: Utc::now() + Duration::days(30),
                        source: CertSource::Upload,
                    })
                    .await
                    .unwrap_or_else(|e| panic!("[{label}] create cert: {e}"));
            }

            let routes = store.list_routes_page(3, 0).await.unwrap();
            assert_eq!(routes.len(), 3, "[{label}] route SQL bound");
            assert_eq!(
                routes
                    .iter()
                    .map(|row| row.name.as_str())
                    .collect::<Vec<_>>(),
                ["alpha", "beta", "delta"],
                "[{label}] route order"
            );
            assert_eq!(store.list_routes_page(3, 3).await.unwrap().len(), 1);
            assert_eq!(store.list_routes().await.unwrap().len(), 4);

            let idps = store.list_idps_page(3, 0).await.unwrap();
            assert_eq!(idps.len(), 3, "[{label}] IdP SQL bound");
            assert_eq!(
                idps.iter().map(|row| row.name.as_str()).collect::<Vec<_>>(),
                ["alpha", "beta", "delta"],
                "[{label}] IdP order"
            );
            assert_eq!(store.list_idps().await.unwrap().len(), 4);

            let policies = store.list_policies_page(3, 0).await.unwrap();
            assert_eq!(policies.len(), 3, "[{label}] policy SQL bound");
            assert_eq!(
                policies
                    .iter()
                    .map(|row| row.name.as_str())
                    .collect::<Vec<_>>(),
                ["alpha", "beta", "delta"],
                "[{label}] policy order"
            );
            assert_eq!(store.list_policies().await.unwrap().len(), 4);

            let certs = store.list_certs_page(3, 0).await.unwrap();
            assert_eq!(certs.len(), 3, "[{label}] cert SQL bound");
            assert_eq!(
                certs
                    .iter()
                    .map(|row| row.domain.as_str())
                    .collect::<Vec<_>>(),
                ["alpha.example", "beta.example", "delta.example"],
                "[{label}] cert order"
            );
            assert_eq!(store.list_certs().await.unwrap().len(), 4);

            let inserted_ids = insert_api_key_page_rows(&control).await;
            let mut expected_ids = inserted_ids.clone();
            expected_ids.sort_unstable();
            let keys = store.list_api_keys_page(3, 0).await.unwrap();
            assert_eq!(keys.len(), 3, "[{label}] API-key SQL bound");
            assert_eq!(
                keys.iter().map(|row| row.id).collect::<Vec<_>>(),
                expected_ids[..3],
                "[{label}] equal-created_at API keys need id tie-break"
            );
            let offset_keys = store.list_api_keys_page(2, 1).await.unwrap();
            assert_eq!(
                offset_keys.iter().map(|row| row.id).collect::<Vec<_>>(),
                expected_ids[1..3],
                "[{label}] API-key page must honor its nonzero offset"
            );
            assert_eq!(store.list_api_keys().await.unwrap().len(), 4);
        }
    }

    // ═══════════════════════ IdPs ═══════════════════════

    #[tokio::test]
    async fn idp_crud() {
        for (label, store) in stores_under_test().await {
            let idp = IdentityProvider {
                id: uuid::Uuid::new_v4(),
                name: "google-oidc".into(),
                idp_type: IdpType::Oidc,
                oidc_config: Some(OidcConfig {
                    issuer_url: "https://accounts.google.com".into(),
                    client_id: "client-abc".into(),
                    client_secret_encrypted: "encrypted-secret".into(),
                    scopes: vec!["openid".into(), "email".into()],
                    prompt: None,
                }),
                saml_config: None,
            };
            store
                .create_idp(&idp)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));

            let fetched = store
                .get_idp(idp.id)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(fetched.name, "google-oidc", "[{label}]");
            assert_eq!(fetched.idp_type, IdpType::Oidc, "[{label}]");

            let updated = store
                .update_idp(idp.id, serde_json::json!({"name": "google-updated"}))
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(updated.name, "google-updated", "[{label}]");

            store
                .delete_idp(idp.id)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert!(store.get_idp(idp.id).await.is_err(), "[{label}]");
        }
    }

    // ═══════════════════════ Sessions ═══════════════════════

    #[tokio::test]
    async fn session_create_get_delete() {
        for (label, store) in stores_under_test().await {
            let session = Session {
                id: Uuid::new_v4(),
                user_id: "user@corp.io".into(),
                idp_id: Uuid::new_v4(),
                upstream_identity: None,
                claims: HashMap::new(),
                groups: vec!["eng".into()],
                created_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(8),
                refresh_token_encrypted: None,
                id_token_encrypted: None,
                saml_name_id: None,
                saml_session_index: None,
                last_accessed_at: Utc::now(),
            };
            store
                .create_session(&session)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));

            let fetched = store
                .get_session(session.id)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(fetched.user_id, "user@corp.io", "[{label}]");

            store
                .delete_session(session.id)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert!(store.get_session(session.id).await.is_err(), "[{label}]");
        }
    }

    #[tokio::test]
    async fn session_create_persists_matching_relational_authority() {
        for (label, store, control) in stores_with_relational_control().await {
            let now = Utc::now();
            let session = Session {
                id: Uuid::new_v4(),
                user_id: "create-authority@example.com".into(),
                idp_id: Uuid::new_v4(),
                upstream_identity: None,
                claims: HashMap::new(),
                groups: vec![],
                created_at: now,
                expires_at: now + Duration::hours(12),
                refresh_token_encrypted: None,
                id_token_encrypted: None,
                saml_name_id: None,
                saml_session_index: None,
                last_accessed_at: now,
            };
            store.create_session(&session).await.unwrap();

            let (data, expires_at, last_accessed_at): (String, i64, i64) = match &control {
                RelationalTestControl::Sqlite(pool) => sqlx::query_as(
                    "SELECT data, expires_at, last_accessed_at FROM sessions WHERE id = ?",
                )
                .bind(session.id)
                .fetch_one(pool)
                .await
                .unwrap(),
                RelationalTestControl::Postgres(pool) => sqlx::query_as(
                    "SELECT data, expires_at, last_accessed_at FROM sessions WHERE id = $1",
                )
                .bind(session.id)
                .fetch_one(pool)
                .await
                .unwrap(),
            };
            let json: serde_json::Value = serde_json::from_str(&data).unwrap();
            assert_eq!(expires_at, session.expires_at.timestamp(), "[{label}]");
            assert_eq!(
                last_accessed_at,
                session.last_accessed_at.timestamp(),
                "[{label}]"
            );
            assert_eq!(json["expires_at"].as_i64(), Some(expires_at), "[{label}]");
            assert_eq!(
                json["last_accessed_at"].as_i64(),
                Some(last_accessed_at),
                "[{label}]"
            );
        }
    }

    #[tokio::test]
    async fn session_reads_overwrite_json_times_from_relational_authority() {
        for (label, store, control) in stores_with_relational_control().await {
            let json_now = Utc::now();
            let session = Session {
                id: Uuid::new_v4(),
                user_id: "authority@example.com".into(),
                idp_id: Uuid::new_v4(),
                upstream_identity: None,
                claims: HashMap::new(),
                groups: vec![],
                created_at: json_now,
                expires_at: json_now + Duration::hours(8),
                refresh_token_encrypted: None,
                id_token_encrypted: None,
                saml_name_id: None,
                saml_session_index: None,
                last_accessed_at: json_now,
            };
            store.create_session(&session).await.unwrap();

            let authority_now = Utc::now().timestamp();
            let authority_expires = authority_now + 7_200;
            let authority_access = authority_now - 10;
            set_session_authority_times(&control, session.id, authority_expires, authority_access)
                .await;

            let fetched = store.get_session(session.id).await.unwrap();
            assert_eq!(
                fetched.expires_at.timestamp(),
                authority_expires,
                "[{label}]"
            );
            assert_eq!(
                fetched.last_accessed_at.timestamp(),
                authority_access,
                "[{label}]"
            );
            let listed = store.list_sessions(None, 10, 0).await.unwrap();
            let listed = listed.iter().find(|row| row.id == session.id).unwrap();
            assert_eq!(
                listed.expires_at.timestamp(),
                authority_expires,
                "[{label}]"
            );
            assert_eq!(
                listed.last_accessed_at.timestamp(),
                authority_access,
                "[{label}]"
            );
        }
    }

    #[tokio::test]
    async fn session_absolute_and_idle_grace_equality_are_expired() {
        for (label, store, control) in stores_with_relational_control().await {
            for (suffix, absolute_offset, access_offset) in
                [(1_u128, 0_i64, 0_i64), (2, 7_200, -(30 * 60 + 60))]
            {
                let now = Utc::now();
                let session = Session {
                    id: Uuid::from_u128(0x500 + suffix),
                    user_id: format!("boundary-{suffix}@example.com"),
                    idp_id: Uuid::new_v4(),
                    upstream_identity: None,
                    claims: HashMap::new(),
                    groups: vec![],
                    created_at: now,
                    expires_at: now + Duration::hours(8),
                    refresh_token_encrypted: None,
                    id_token_encrypted: None,
                    saml_name_id: None,
                    saml_session_index: None,
                    last_accessed_at: now,
                };
                store.create_session(&session).await.unwrap();
                let authority_now = Utc::now().timestamp();
                set_session_authority_times(
                    &control,
                    session.id,
                    authority_now + absolute_offset,
                    authority_now + access_offset,
                )
                .await;

                assert!(
                    matches!(
                        store.get_session(session.id).await,
                        Err(crate::error::Error::NotFound)
                    ),
                    "[{label}] boundary row must be expired"
                );
            }
        }
    }

    #[tokio::test]
    async fn session_expired_auto_deleted() {
        for (label, store) in stores_under_test().await {
            let session = Session {
                id: Uuid::new_v4(),
                user_id: "expired@corp.io".into(),
                idp_id: Uuid::new_v4(),
                upstream_identity: None,
                claims: HashMap::new(),
                groups: vec![],
                created_at: Utc::now() - Duration::hours(10),
                expires_at: Utc::now() - Duration::hours(1),
                refresh_token_encrypted: None,
                id_token_encrypted: None,
                saml_name_id: None,
                saml_session_index: None,
                last_accessed_at: Utc::now() - Duration::hours(2),
            };
            store
                .create_session(&session)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert!(store.get_session(session.id).await.is_err(), "[{label}]");
        }
    }

    #[tokio::test]
    async fn session_list_with_pagination() {
        let stores = stores_with_relational_control().await;
        let expected_backends = if std::env::var_os("TEST_POSTGRES_URL").is_some() {
            2
        } else {
            1
        };
        assert_eq!(stores.len(), expected_backends);
        for (label, store, control) in stores {
            const FIXED_CREATED_AT: i64 = 1_700_000_000;
            let created_at = chrono::DateTime::from_timestamp(FIXED_CREATED_AT, 0)
                .expect("fixed session timestamp");
            for suffix in [4_u128, 2, 5, 1, 3] {
                let s = Session {
                    id: Uuid::from_u128(suffix),
                    user_id: "user@x.com".into(),
                    idp_id: Uuid::new_v4(),
                    upstream_identity: None,
                    claims: HashMap::new(),
                    groups: vec![],
                    created_at,
                    expires_at: created_at + Duration::hours(8),
                    refresh_token_encrypted: None,
                    id_token_encrypted: None,
                    saml_name_id: None,
                    saml_session_index: None,
                    last_accessed_at: created_at,
                };
                store
                    .create_session(&s)
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            }

            assert_eq!(
                pin_session_created_at(&control, FIXED_CREATED_AT).await,
                5,
                "[{label}] relational created_at rows"
            );

            let page1 = store
                .list_sessions(None, 3, 0)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(
                page1.iter().map(|session| session.id).collect::<Vec<_>>(),
                [Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3),],
                "[{label}] unfiltered ordering"
            );

            let page2 = store
                .list_sessions(None, 3, 3)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(
                page2.iter().map(|session| session.id).collect::<Vec<_>>(),
                [Uuid::from_u128(4), Uuid::from_u128(5)],
                "[{label}] unfiltered second page"
            );

            let filtered = store
                .list_sessions(Some("user@x.com"), 3, 1)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(
                filtered
                    .iter()
                    .map(|session| session.id)
                    .collect::<Vec<_>>(),
                [Uuid::from_u128(2), Uuid::from_u128(3), Uuid::from_u128(4),],
                "[{label}] filtered ordering"
            );
        }
    }

    #[tokio::test]
    async fn session_list_filter_by_user() {
        for (label, store) in stores_under_test().await {
            for uid in ["alice@x.com", "bob@x.com", "alice@x.com"] {
                let s = Session {
                    id: Uuid::new_v4(),
                    user_id: uid.into(),
                    idp_id: Uuid::new_v4(),
                    upstream_identity: None,
                    claims: HashMap::new(),
                    groups: vec![],
                    created_at: Utc::now(),
                    expires_at: Utc::now() + Duration::hours(8),
                    refresh_token_encrypted: None,
                    id_token_encrypted: None,
                    saml_name_id: None,
                    saml_session_index: None,
                    last_accessed_at: Utc::now(),
                };
                store
                    .create_session(&s)
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            }
            let alice = store
                .list_sessions(Some("alice@x.com"), 100, 0)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(alice.len(), 2, "[{label}]");
        }
    }

    #[tokio::test]
    async fn session_cleanup_expired() {
        for (label, store, control) in stores_with_relational_control().await {
            let expired = Session {
                id: Uuid::new_v4(),
                user_id: "old@x.com".into(),
                idp_id: Uuid::new_v4(),
                upstream_identity: None,
                claims: HashMap::new(),
                groups: vec![],
                created_at: Utc::now() - Duration::hours(20),
                expires_at: Utc::now() - Duration::hours(1),
                refresh_token_encrypted: None,
                id_token_encrypted: None,
                saml_name_id: None,
                saml_session_index: None,
                last_accessed_at: Utc::now() - Duration::hours(10),
            };
            store
                .create_session(&expired)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));

            let idle = Session {
                id: Uuid::new_v4(),
                user_id: "idle@example.com".into(),
                expires_at: Utc::now() + Duration::hours(8),
                last_accessed_at: Utc::now(),
                ..expired.clone()
            };
            let active = Session {
                id: Uuid::new_v4(),
                user_id: "active@example.com".into(),
                expires_at: Utc::now() + Duration::hours(8),
                last_accessed_at: Utc::now(),
                ..expired.clone()
            };
            store.create_session(&idle).await.unwrap();
            store.create_session(&active).await.unwrap();
            let authority_now = Utc::now().timestamp();
            set_session_authority_times(
                &control,
                idle.id,
                authority_now + 7_200,
                authority_now - (30 * 60 + 60),
            )
            .await;
            set_session_authority_times(
                &control,
                active.id,
                authority_now + 7_200,
                authority_now - 30 * 60,
            )
            .await;

            let count = store
                .cleanup_expired_sessions()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(count, 2, "[{label}]");
            assert!(store.get_session(active.id).await.is_ok(), "[{label}]");
        }
    }

    // ═══════════════════════ Config ═══════════════════════

    #[tokio::test]
    async fn config_default_then_update() {
        for (label, store) in stores_under_test().await {
            let config = store
                .get_config()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(config.session_lifetime_hours, 8, "[{label}]");
            assert_eq!(config.log_level, "info", "[{label}]");

            let updated = store
                .update_config(serde_json::json!({
                    "auth_domain": "auth.example.com",
                    "session_lifetime_hours": 24,
                    "log_level": "debug"
                }))
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(updated.session_lifetime_hours, 24, "[{label}]");
            assert_eq!(updated.log_level, "debug", "[{label}]");
            assert_eq!(
                updated.auth_domain.as_deref(),
                Some("auth.example.com"),
                "[{label}]"
            );

            let reloaded = store
                .get_config()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(reloaded.session_lifetime_hours, 24, "[{label}]");
        }
    }

    // ═══════════════════════ API Keys ═══════════════════════

    #[tokio::test]
    async fn api_key_create_verify_delete() {
        for (label, store) in stores_under_test().await {
            let created = store
                .create_api_key(
                    "ci-deploy",
                    &ApiKeyScopeSet::from_storage(r#"["management:write"]"#).unwrap(),
                )
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert!(created.key.starts_with("sks_"), "[{label}]");
            assert_eq!(created.api_key.name, "ci-deploy", "[{label}]");

            let verified = store
                .lookup_api_key(&created.key)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(verified.name, "ci-deploy", "[{label}]");
            assert!(
                verified
                    .scopes
                    .allows(crate::models::api_key::ApiKeyScope::Read),
                "[{label}]"
            );
            assert!(
                !verified
                    .scopes
                    .allows(crate::models::api_key::ApiKeyScope::Admin),
                "[{label}]"
            );
            assert_eq!(
                store
                    .get_api_key(created.api_key.id)
                    .await
                    .unwrap()
                    .last_used_at,
                None,
                "lookup must not mutate last_used_at [{label}]"
            );
            store
                .touch_api_key_usage(created.api_key.id)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert!(
                store
                    .get_api_key(created.api_key.id)
                    .await
                    .unwrap()
                    .last_used_at
                    .is_some(),
                "explicit touch must update last_used_at [{label}]"
            );

            assert!(
                store.lookup_api_key("sks_invalid").await.is_err(),
                "[{label}]"
            );

            store
                .delete_api_key(created.api_key.id)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert!(
                store.lookup_api_key(&created.key).await.is_err(),
                "[{label}]"
            );
        }
    }

    #[tokio::test]
    async fn api_key_count() {
        for (label, store) in stores_under_test().await {
            assert_eq!(
                store
                    .api_key_count()
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}")),
                0,
                "[{label}]"
            );
            store
                .create_api_key("k1", &ApiKeyScopeSet::admin())
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            store
                .create_api_key("k2", &ApiKeyScopeSet::admin())
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(
                store
                    .api_key_count()
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}")),
                2,
                "[{label}]"
            );
        }
    }

    #[tokio::test]
    async fn api_key_stored_form_is_hmac_sentinel() {
        // New rows must never land as plaintext or bare hashes.
        use crate::store::backend::api_key_hash::HMAC_SENTINEL;

        for (label, store) in stores_under_test().await {
            let created = store
                .create_api_key("fmt-check", &ApiKeyScopeSet::admin())
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert!(
                created.api_key.key_hash.starts_with(HMAC_SENTINEL),
                "[{label}]: stored hash must be HMAC-form, got {}",
                created.api_key.key_hash
            );
            // And the returned raw key is not what we stored.
            assert_ne!(created.api_key.key_hash, created.key, "[{label}]");
        }
    }

    #[tokio::test]
    async fn api_key_single_byte_mutation_denied() {
        // Flipping a single byte of a valid key must not authenticate.
        // Pairs with the unit-level `hmac_rejects_one_byte_diff` test in
        // `backend::api_key_hash` but exercises the full DB path.
        for (label, store) in stores_under_test().await {
            let created = store
                .create_api_key("one-byte-diff", &ApiKeyScopeSet::admin())
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            // Mutate the final byte of the raw key. Do it inside the
            // body (past the `sks_` prefix) so the prefix-based lookup
            // still finds the candidate row.
            let mut bytes = created.key.clone().into_bytes();
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            let tampered = String::from_utf8(bytes).expect("valid utf-8");
            assert_ne!(tampered, created.key, "[{label}]: mutation was a no-op");
            assert!(
                store.lookup_api_key(&tampered).await.is_err(),
                "[{label}]: one-byte-mutated key must be rejected"
            );
        }
    }

    // ═══════════════════════ Secrets ═══════════════════════

    #[tokio::test]
    async fn secrets_get_set() {
        for (label, store) in stores_under_test().await {
            assert!(
                store
                    .get_secret("missing")
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}"))
                    .is_none(),
                "[{label}]"
            );

            store
                .set_secret("cookie_secret", "encrypted_value")
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(
                store
                    .get_secret("cookie_secret")
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}"))
                    .as_deref(),
                Some("encrypted_value"),
                "[{label}]"
            );

            store
                .set_secret("cookie_secret", "new_value")
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(
                store
                    .get_secret("cookie_secret")
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}"))
                    .as_deref(),
                Some("new_value"),
                "[{label}]"
            );
        }
    }

    // ═══════════════════════ ACME challenges ═══════════════════════

    #[tokio::test]
    async fn acme_challenge_roundtrip() {
        for (label, store) in stores_under_test().await {
            // Unknown token returns None.
            assert!(
                store
                    .get_acme_challenge("nope")
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}"))
                    .is_none(),
                "[{label}]"
            );

            store
                .set_acme_challenge("tok-a", "auth-a", "foo.example")
                .await
                .unwrap_or_else(|e| panic!("[{label}] set: {e}"));
            store
                .set_acme_challenge("tok-b", "auth-b", "foo.example")
                .await
                .unwrap_or_else(|e| panic!("[{label}] set: {e}"));
            store
                .set_acme_challenge("tok-c", "auth-c", "bar.example")
                .await
                .unwrap_or_else(|e| panic!("[{label}] set: {e}"));

            assert_eq!(
                store
                    .get_acme_challenge("tok-a")
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}"))
                    .as_deref(),
                Some("auth-a"),
                "[{label}]"
            );

            // Re-setting the same token updates the key_auth (ON CONFLICT).
            store
                .set_acme_challenge("tok-a", "auth-a2", "foo.example")
                .await
                .unwrap_or_else(|e| panic!("[{label}] update: {e}"));
            assert_eq!(
                store
                    .get_acme_challenge("tok-a")
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}"))
                    .as_deref(),
                Some("auth-a2"),
                "[{label}]"
            );

            // Scoped cleanup only removes rows for the named domain.
            let deleted = store
                .delete_acme_challenges_for_domain("foo.example")
                .await
                .unwrap_or_else(|e| panic!("[{label}] cleanup: {e}"));
            assert_eq!(deleted, 2, "[{label}]");
            assert!(
                store
                    .get_acme_challenge("tok-a")
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}"))
                    .is_none(),
                "[{label}]"
            );
            assert_eq!(
                store
                    .get_acme_challenge("tok-c")
                    .await
                    .unwrap_or_else(|e| panic!("[{label}]: {e}"))
                    .as_deref(),
                Some("auth-c"),
                "[{label}] other-domain token should survive scoped cleanup"
            );
        }
    }

    // ═══════════════════════ DB-sourced versions (HA-prep) ═══════════════════════

    #[tokio::test]
    async fn route_mutation_bumps_db_version() {
        for (label, store) in stores_under_test().await {
            let v0 = store
                .route_version_current()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));

            let route = CreateRoute {
                name: "versioned".into(),
                from: "https://v.test.io".into(),
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
            .into_route();
            store
                .create_route(&route)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            let v1 = store
                .route_version_current()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert!(v1 > v0, "[{label}] create should bump route version");

            store
                .update_route(route.id, serde_json::json!({"name": "renamed"}))
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            let v2 = store
                .route_version_current()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert!(v2 > v1, "[{label}] update should bump route version");

            store
                .delete_route(route.id)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            let v3 = store
                .route_version_current()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert!(v3 > v2, "[{label}] delete should bump route version");
        }
    }

    /// Create failures must leave the version counter untouched.
    ///
    /// Before the tx-in fix, `create_route` committed the INSERT and then
    /// bumped on the pool as a separate step. That's fine in isolation,
    /// but if the bump itself races with anything (pool contention,
    /// writer crash), a peer could observe the counter diverging from
    /// actual DB state. The correct shape is bump-in-tx: both land or
    /// neither does. The easiest behavioural probe for that is the
    /// failure path — a rejected create must not move the counter.
    #[tokio::test]
    async fn create_route_failure_does_not_bump_version() {
        for (label, store) in stores_under_test().await {
            let r1 = CreateRoute {
                name: "taken".into(),
                from: "https://taken.test.io".into(),
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
            .into_route();
            store
                .create_route(&r1)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            let v_before = store
                .route_version_current()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));

            // Same name → unique violation. The INSERT fails and the tx
            // rolls back before the bump runs.
            let r2 = CreateRoute {
                name: "taken".into(),
                from: "https://other.test.io".into(),
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
            .into_route();
            let err = store.create_route(&r2).await;
            assert!(err.is_err(), "[{label}] duplicate create should fail");

            let v_after = store
                .route_version_current()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(
                v_before, v_after,
                "[{label}] failed create must not bump version",
            );
        }
    }

    /// Delete failures must leave the version counter untouched. Same
    /// rationale as `create_route_failure_does_not_bump_version`.
    #[tokio::test]
    async fn delete_route_failure_does_not_bump_version() {
        for (label, store) in stores_under_test().await {
            let v_before = store
                .route_version_current()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));

            // Deleting an unknown id returns NotFound before any state
            // change; the bump must not fire.
            let missing = Uuid::new_v4();
            let err = store.delete_route(missing).await;
            assert!(err.is_err(), "[{label}] deleting unknown id should fail");

            let v_after = store
                .route_version_current()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(
                v_before, v_after,
                "[{label}] failed delete must not bump version",
            );
        }
    }

    /// Same tx-in invariant for IdPs: a rejected create must not move
    /// the idp-version counter.
    #[tokio::test]
    async fn create_idp_failure_does_not_bump_version() {
        for (label, store) in stores_under_test().await {
            let idp1 = IdentityProvider {
                id: uuid::Uuid::new_v4(),
                name: "idp-taken".into(),
                idp_type: IdpType::Oidc,
                oidc_config: Some(OidcConfig {
                    issuer_url: "https://issuer.test/".into(),
                    client_id: "cid".into(),
                    client_secret_encrypted: "enc".into(),
                    scopes: vec!["openid".into()],
                    prompt: None,
                }),
                saml_config: None,
            };
            store
                .create_idp(&idp1)
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            let v_before = store
                .idp_version_current()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));

            let idp2 = IdentityProvider {
                id: uuid::Uuid::new_v4(),
                name: "idp-taken".into(),
                idp_type: IdpType::Oidc,
                oidc_config: Some(OidcConfig {
                    issuer_url: "https://issuer.test/".into(),
                    client_id: "cid".into(),
                    client_secret_encrypted: "enc".into(),
                    scopes: vec!["openid".into()],
                    prompt: None,
                }),
                saml_config: None,
            };
            let err = store.create_idp(&idp2).await;
            assert!(err.is_err(), "[{label}] duplicate idp should fail");

            let v_after = store
                .idp_version_current()
                .await
                .unwrap_or_else(|e| panic!("[{label}]: {e}"));
            assert_eq!(
                v_before, v_after,
                "[{label}] failed idp create must not bump version",
            );
        }
    }

    /// SQLite-only because the test has to stage a fake peer write at
    /// `sqlx::SqlitePool` level to bypass the write-side cache refresh.
    /// The Postgres equivalent — cross-node cache invalidation — is
    /// covered in `ha_test.rs` with two real `Store` instances.
    #[tokio::test]
    async fn config_version_mismatch_reloads_cache() {
        let store = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .unwrap();
        store
            .update_config(serde_json::json!({
                "session_lifetime_hours": 16,
                "websocket_concurrency_limit": 77
            }))
            .await
            .unwrap();
        assert_eq!(store.get_config().await.unwrap().session_lifetime_hours, 16);
        assert_eq!(
            store
                .get_config()
                .await
                .unwrap()
                .websocket_concurrency_limit,
            77
        );

        let mut peer = store.get_config().await.unwrap();
        peer.session_lifetime_hours = 99;
        let peer_json = serde_json::to_string(&peer).unwrap();
        sqlx::query("UPDATE global_config SET data = ? WHERE id = 1")
            .bind(&peer_json)
            .execute(store.sqlite_pool())
            .await
            .unwrap();
        store.sqlite_config_version().bump_pool().await.unwrap();

        let reloaded = store.get_config().await.unwrap();
        assert_eq!(reloaded.session_lifetime_hours, 99);
    }

    // ═════════ bootstrap_config / first-boot env import ═════════

    /// Env-var tests share a process-global tokio mutex so concurrent
    /// cargo test runs don't race on `SEKISHO_SERVICE_DB`. Tokio's
    /// async-aware mutex is used so the guard can span await points
    /// without tripping `clippy::await_holding_lock`.
    async fn env_guard() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        LOCK.lock().await
    }

    /// Unique filesystem SQLite path so a test can open the same
    /// bootstrap DB across two `Store::new` calls and observe the
    /// persisted bootstrap_config.
    fn temp_sqlite_path(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sekisho-boot-{tag}-{}-{}.db",
            std::process::id(),
            Uuid::new_v4()
        ));
        format!("sqlite:{}", p.display())
    }

    #[tokio::test]
    async fn instance_config_persists_cluster_db_url() {
        // Direct exercise of InstanceStore via the crate-private handle
        // on Store — confirms set/get roundtrip uses the same key/value
        // the management API will read later.
        let store = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .unwrap();
        let inst = store.instance();
        assert_eq!(inst.get_cluster_db_url().await.unwrap(), None);
        inst.set_cluster_db_url("postgres://u:p@h/db")
            .await
            .unwrap();
        assert_eq!(
            inst.get_cluster_db_url().await.unwrap().as_deref(),
            Some("postgres://u:p@h/db"),
        );
    }

    #[tokio::test]
    async fn env_var_imported_on_first_boot() {
        let _guard = env_guard().await;
        // Fresh bootstrap DB with no prior bootstrap_config — the env
        // var should be imported and then observable via the API.
        let path = temp_sqlite_path("first-boot-import");

        // SAFETY: test-only mutation serialized by env_guard above.
        unsafe {
            std::env::set_var("SEKISHO_SERVICE_DB", "sqlite::memory:");
        }
        let store = Store::new(&path, MasterKey::from_test_bytes(TEST_MASTER_KEY))
            .await
            .unwrap();
        unsafe {
            std::env::remove_var("SEKISHO_SERVICE_DB");
        }

        assert_eq!(
            store
                .instance()
                .get_cluster_db_url()
                .await
                .unwrap()
                .as_deref(),
            Some("sqlite::memory:"),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn env_var_reimport_after_clear_logs_unset_condition() {
        use std::fmt::Write as _;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::Context;
        use tracing_subscriber::prelude::*;

        const ENV_NAME: &str = "SEKISHO_SERVICE_DB";
        const ENV_VALUE: &str = "sqlite::memory:";

        struct EnvReset;

        impl Drop for EnvReset {
            fn drop(&mut self) {
                // SAFETY: the test holds env_guard for its entire lifetime.
                unsafe {
                    std::env::remove_var(ENV_NAME);
                }
            }
        }

        #[derive(Clone)]
        struct ImportLogLayer {
            fields: Arc<Mutex<Vec<String>>>,
        }

        impl<S> tracing_subscriber::Layer<S> for ImportLogLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                struct Visitor {
                    fields: String,
                }

                impl tracing::field::Visit for Visitor {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        let _ = write!(&mut self.fields, "{}={value:?};", field.name());
                    }
                }

                let mut visitor = Visitor {
                    fields: String::new(),
                };
                event.record(&mut visitor);
                self.fields
                    .lock()
                    .expect("log capture lock")
                    .push(visitor.fields);
            }
        }

        let _guard = env_guard().await;
        let _env_reset = EnvReset;
        let path = temp_sqlite_path("reimport-after-clear");

        // SAFETY: test-only mutation serialized by env_guard above.
        unsafe {
            std::env::set_var(ENV_NAME, ENV_VALUE);
        }

        let first = Store::new(&path, MasterKey::from_test_bytes(TEST_MASTER_KEY))
            .await
            .expect("initial store");
        first
            .instance()
            .clear_cluster_db_url()
            .await
            .expect("clear cluster DB URL");
        assert!(
            first
                .instance()
                .get_cluster_db_url()
                .await
                .expect("read cleared cluster DB URL")
                .is_none(),
            "cluster DB URL was not cleared"
        );
        first.close().await;
        drop(first);

        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(ImportLogLayer {
            fields: captured.clone(),
        });
        let _subscriber_guard = subscriber.set_default();

        let second = Store::new(&path, MasterKey::from_test_bytes(TEST_MASTER_KEY))
            .await
            .expect("reopened store");
        assert!(
            second
                .instance()
                .get_cluster_db_url()
                .await
                .expect("read reimported cluster DB URL")
                .as_deref()
                == Some(ENV_VALUE),
            "cluster DB URL was not reimported"
        );
        second.close().await;
        drop(second);

        let expected_message = [
            "imported SEKISHO_SERVICE_DB because ",
            "instance_config.cluster_db_url was unset",
        ]
        .concat();
        let fields = captured.lock().expect("log capture lock");
        assert!(
            fields
                .iter()
                .filter(|event| event.contains(&expected_message))
                .count()
                == 1,
            "neutral import log was not emitted exactly once"
        );
        assert!(
            fields.iter().all(|event| !event.contains("on first boot")),
            "stale lifecycle wording was emitted"
        );
        assert!(
            fields.iter().all(|event| !event.contains(ENV_VALUE)),
            "service DB value was emitted"
        );
    }

    /// Fresh single-node install: bootstrap SQLite holds both bootstrap
    /// and operational tables. Guards against a regression where the
    /// reuse path stops running service migrations.
    #[tokio::test]
    async fn single_node_bootstrap_has_both_bootstrap_and_operational_tables() {
        let path = temp_sqlite_path("single-node-tables");
        let _store = Store::new_for_test(&path, TEST_MASTER_KEY, None)
            .await
            .unwrap();

        let tables = list_bootstrap_tables(&path).await;
        assert!(
            tables.contains(&"instance_config".to_string()),
            "instance_config missing: {tables:?}",
        );
        assert!(
            tables.contains(&"routes".to_string()),
            "operational tables should be co-located in single-node mode: {tables:?}",
        );
    }

    /// HA topology (separate service DB): bootstrap SQLite must stay
    /// bootstrap-only. A SQLite-backed separate service DB is the
    /// cheapest way to exercise this without requiring Postgres.
    #[tokio::test]
    async fn separate_service_db_leaves_bootstrap_narrow() {
        let bootstrap_path = temp_sqlite_path("narrow-bootstrap");
        let service_path = temp_sqlite_path("narrow-service");
        let _store = Store::new_for_test(&bootstrap_path, TEST_MASTER_KEY, Some(&service_path))
            .await
            .unwrap();

        let boot_tables = list_bootstrap_tables(&bootstrap_path).await;
        assert!(
            boot_tables.contains(&"instance_config".to_string()),
            "instance_config missing: {boot_tables:?}",
        );
        // Operational tables must NOT leak into the bootstrap file when a
        // separate service DB is configured. Anything here in a fresh
        // install is a regression.
        for forbidden in [
            "routes",
            "identity_providers",
            "policies",
            "sessions",
            "certificates",
            "api_keys",
            "secrets",
            "global_config",
            "schema_versions",
        ] {
            assert!(
                !boot_tables.iter().any(|t| t == forbidden),
                "operational table `{forbidden}` leaked into bootstrap SQLite: {boot_tables:?}",
            );
        }

        // And the service SQLite should have the operational tables.
        let svc_tables = list_bootstrap_tables(&service_path).await;
        assert!(
            svc_tables.contains(&"routes".to_string()),
            "service DB missing operational tables: {svc_tables:?}",
        );
        assert!(
            !svc_tables.contains(&"instance_config".to_string()),
            "instance_config should live only in the bootstrap file: {svc_tables:?}",
        );
    }

    // ═══════════════════════ Degraded mode ═══════════════════════

    /// In degraded mode, every operational dispatch must short-circuit
    /// to `Error::ServiceUnavailable`. Uses the test-only direct stub
    /// (`new_for_test_degraded`) rather than a real unreachable DSN,
    /// which would pay the 30 s default acquire-timeout. The real DSN
    /// path is exercised by `pg_unreachable_enters_degraded_mode`
    /// below, gated behind an env var so the default suite stays fast.
    #[tokio::test]
    async fn operational_dispatch_short_circuits_in_degraded_mode() {
        let store = Store::new_for_test_degraded("simulated boot failure")
            .await
            .unwrap();

        assert!(!store.is_service_backend_available());

        let err = store.list_routes().await.expect_err("expected 503");
        assert!(
            matches!(err, crate::error::Error::ServiceUnavailable(_)),
            "operational dispatch must short-circuit, got: {err:?}",
        );
    }

    #[tokio::test]
    async fn degraded_store_rejects_encryption_before_reading_placeholder_ring() {
        let store = Store::new_for_test_degraded("simulated boot failure")
            .await
            .unwrap();
        let _ring_write = store.key_ring.write().await;

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            store.encrypt_active_to_base64(b"must-not-encrypt"),
        )
        .await;

        let err = result
            .expect("degraded encryption must reject before waiting for the placeholder ring")
            .expect_err("degraded encryption must not produce ciphertext");
        assert!(matches!(
            err,
            crate::error::Error::ServiceUnavailable(reason)
                if reason == "simulated boot failure"
        ));
    }

    #[tokio::test]
    async fn available_store_encryption_roundtrips() {
        let store = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .unwrap();

        let encrypted = store
            .encrypt_active_to_base64(b"healthy-roundtrip")
            .await
            .unwrap();
        let decrypted = store.decrypt_any_from_base64(&encrypted).await.unwrap();

        assert_eq!(decrypted, b"healthy-roundtrip");
    }

    #[tokio::test]
    async fn key_ring_snapshot_clones_the_shared_ring_arc() {
        let store = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, None)
            .await
            .unwrap();

        let first: std::sync::Arc<crate::crypto::MasterKeyRing> = store.key_ring_snapshot().await;
        let count_before_second_snapshot = std::sync::Arc::strong_count(&first);
        let second: std::sync::Arc<crate::crypto::MasterKeyRing> = store.key_ring_snapshot().await;

        assert!(std::sync::Arc::ptr_eq(&first, &second));
        assert_eq!(
            std::sync::Arc::strong_count(&first),
            count_before_second_snapshot + 1
        );
        drop(second);
        assert_eq!(
            std::sync::Arc::strong_count(&first),
            count_before_second_snapshot
        );
    }

    #[tokio::test]
    async fn identity_signing_rotation_publishes_atomically_and_rejects_second_rotation() {
        for (backend, store) in stores_under_test().await {
            let published = store.identity_key_ring_snapshot().await.unwrap();
            let old_kid = published.current_kid();
            let old_version = published.version();
            let claims = serde_json::json!({
                "sub": "alice@example.com",
                "email": "alice@example.com",
                "exp": chrono::Utc::now().timestamp() + 300,
            });
            let old_token = published.sign(&claims).unwrap();

            assert_eq!(
                store.rotate_identity_signing_ring().await.unwrap(),
                crate::store::backend::IdentitySigningRotateOutcome::Rotated,
                "{backend}"
            );
            let after = store.identity_key_ring_snapshot().await.unwrap();
            assert!(std::sync::Arc::ptr_eq(&published, &after), "{backend}");
            assert_ne!(after.current_kid(), old_kid, "{backend}");
            assert_eq!(after.version(), old_version + 1, "{backend}");
            assert_eq!(
                after.jwks(chrono::Utc::now().timestamp())["keys"]
                    .as_array()
                    .unwrap()
                    .len(),
                2,
                "{backend}"
            );
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
            validation.validate_aud = false;
            validation.required_spec_claims = ["exp"].into_iter().map(str::to_owned).collect();
            assert!(
                after
                    .verify::<serde_json::Value>(
                        &old_token,
                        &validation,
                        chrono::Utc::now().timestamp(),
                    )
                    .is_ok(),
                "{backend}"
            );

            let version_before_reject = after.version();
            assert_eq!(
                store.rotate_identity_signing_ring().await.unwrap(),
                crate::store::backend::IdentitySigningRotateOutcome::RetiringStillEligible,
                "{backend}"
            );
            assert_eq!(
                store.identity_signing_version_current().await.unwrap(),
                version_before_reject,
                "{backend}"
            );
        }
    }

    #[tokio::test]
    async fn identity_signing_rotation_recovers_with_a_stale_process_dek_snapshot() {
        for (backend, store) in stores_under_test().await {
            let stale_ring = store.key_ring_snapshot().await;
            let old_key_id = stale_ring.active_key_id();
            let master_key = MasterKey::from_test_bytes(TEST_MASTER_KEY);
            let new_key_id = store
                .master_keys_allocate_inactive_plaintext(&[0x44; 32], master_key.as_ref())
                .await
                .unwrap();
            store.master_keys_activate(new_key_id).await.unwrap();
            assert_eq!(
                store.key_ring_snapshot().await.active_key_id(),
                old_key_id,
                "{backend}: test precondition requires a stale process snapshot"
            );

            assert_eq!(
                store.rotate_identity_signing_ring().await.unwrap(),
                crate::store::backend::IdentitySigningRotateOutcome::Rotated,
                "{backend}"
            );
            assert_eq!(
                store
                    .identity_signing_scan_key_id(old_key_id.get())
                    .await
                    .unwrap(),
                0,
                "{backend}: committed signer must be encrypted with the fresh durable DEK"
            );
            assert_eq!(
                store.key_ring_snapshot().await.active_key_id(),
                old_key_id,
                "{backend}: identity publication must not mutate the DEK snapshot"
            );
        }
    }

    /// Bootstrap API is served by `InstanceStore`, not the operational
    /// backend, so it must keep working even when the service DB is
    /// unreachable. This is the whole point of degraded mode: operator
    /// fixes the DSN through the bootstrap resource and restarts.
    #[tokio::test]
    async fn bootstrap_api_works_in_degraded_mode() {
        let store = Store::new_for_test_degraded("simulated boot failure")
            .await
            .unwrap();

        // Writes through the same code path the `/instance` PATCH
        // handler uses must succeed even when the operational backend
        // is gone.
        store
            .instance()
            .set_cluster_db_url("postgres://fixed@db.example.com/sekisho")
            .await
            .expect("bootstrap write must succeed in degraded mode");

        assert_eq!(
            store
                .instance()
                .get_cluster_db_url()
                .await
                .unwrap()
                .as_deref(),
            Some("postgres://fixed@db.example.com/sekisho"),
        );
    }

    /// End-to-end version of the degraded-mode path, covering the real
    /// `Store::new_for_test` error-swallowing code. Only runs when
    /// `TEST_DEGRADED_MODE=1` is set because it pays the default sqlx
    /// acquire timeout (~30 s) waiting for the bogus Postgres to not
    /// answer.
    #[tokio::test]
    async fn pg_unreachable_enters_degraded_mode() {
        if std::env::var("TEST_DEGRADED_MODE").ok().as_deref() != Some("1") {
            eprintln!("skipped; set TEST_DEGRADED_MODE=1 to run");
            return;
        }
        let bad = "postgres://nobody:nothing@127.0.0.1:1/nope";
        let store = Store::new_for_test("sqlite::memory:", TEST_MASTER_KEY, Some(bad))
            .await
            .expect("degraded startup must still succeed");

        assert!(!store.is_service_backend_available());

        let err = store.list_routes().await.expect_err("expected 503");
        assert!(matches!(err, crate::error::Error::ServiceUnavailable(_)));
    }

    /// The `ServiceUnavailable` variant must map to HTTP 503 so the
    /// management API surfaces degraded-mode cleanly (and so readiness
    /// probes can tell the two failure modes — auth vs unreachable — apart).
    #[test]
    fn service_unavailable_maps_to_503() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        let resp = crate::error::Error::ServiceUnavailable("boom".into()).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Helper: open a SQLite DB read-only and list its user tables.
    async fn list_bootstrap_tables(sqlite_url: &str) -> Vec<String> {
        let pool = sqlx::SqlitePool::connect(sqlite_url)
            .await
            .expect("open sqlite for table inspection");
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .fetch_all(&pool)
        .await
        .expect("list tables");
        pool.close().await;
        tables
    }

    #[tokio::test]
    async fn env_var_ignored_when_bootstrap_config_populated() {
        let _guard = env_guard().await;
        let path = temp_sqlite_path("env-ignored");

        // First boot: populate bootstrap_config directly via InstanceStore
        // (skip env, skip Store::new env interaction).
        {
            let s = Store::new_for_test(&path, TEST_MASTER_KEY, None)
                .await
                .unwrap();
            s.instance()
                .set_cluster_db_url("sqlite::memory:")
                .await
                .unwrap();
        }

        // Sekisho boot: set env to a *different* URL. The DB value must
        // win; env is ignored with a warning (we don't assert on logs).
        unsafe {
            std::env::set_var("SEKISHO_SERVICE_DB", "postgres://overridden@h/db");
        }
        let store = Store::new(&path, MasterKey::from_test_bytes(TEST_MASTER_KEY))
            .await
            .unwrap();
        unsafe {
            std::env::remove_var("SEKISHO_SERVICE_DB");
        }

        assert_eq!(
            store
                .instance()
                .get_cluster_db_url()
                .await
                .unwrap()
                .as_deref(),
            Some("sqlite::memory:"),
            "bootstrap_config must take precedence over env on subsequent boots",
        );
    }

    #[tokio::test]
    async fn pending_auth_get_then_atomic_take_roundtrip() {
        for (label, store) in stores_under_test().await {
            let state = crate::auth::middleware::PendingAuth {
                idp_id: Uuid::new_v4(),
                nonce: "n".into(),
                code_verifier: "v".into(),
                redirect_url: "/home".into(),
                created_at: Utc::now(),
                saml_authn_request_id: None,
                kind: crate::auth::middleware::PendingAuthKind::Login,
                browser_nonce_hash: Some("browser-hash".into()),
            };
            store
                .pending_auth_insert("abc", &state)
                .await
                .unwrap_or_else(|e| panic!("{label}: insert: {e}"));

            let first_read = store
                .pending_auth_get("abc")
                .await
                .unwrap_or_else(|e| panic!("{label}: first get: {e}"))
                .unwrap_or_else(|| panic!("{label}: expected Some"));
            let second_read = store
                .pending_auth_get("abc")
                .await
                .unwrap_or_else(|e| panic!("{label}: second get: {e}"))
                .unwrap_or_else(|| panic!("{label}: non-destructive get removed the row"));
            assert_eq!(first_read.nonce, "n", "{label}");
            assert_eq!(second_read.redirect_url, "/home", "{label}");
            assert_eq!(
                first_read.browser_nonce_hash.as_deref(),
                Some("browser-hash"),
                "{label}"
            );

            let (left, right) = tokio::join!(
                store.pending_auth_take("abc"),
                store.pending_auth_take("abc")
            );
            let winners = [left, right]
                .into_iter()
                .map(|result| result.unwrap_or_else(|e| panic!("{label}: take: {e}")))
                .filter(Option::is_some)
                .count();
            assert_eq!(winners, 1, "{label}: exactly one atomic take must win");
        }
    }

    #[tokio::test]
    async fn auth_start_transition_is_atomic_and_rolls_back_on_insert_conflict() {
        use crate::auth::middleware::{AuthStateStore, PendingAuth, PendingAuthKind};

        for (label, store) in stores_under_test().await {
            let idp_id = Uuid::new_v4();
            let auth_start = PendingAuth {
                idp_id,
                nonce: String::new(),
                code_verifier: String::new(),
                redirect_url: "/home".into(),
                created_at: Utc::now(),
                saml_authn_request_id: None,
                kind: PendingAuthKind::AuthStart,
                browser_nonce_hash: None,
            };
            let login = PendingAuth {
                idp_id,
                nonce: "oidc-nonce".into(),
                code_verifier: "pkce".into(),
                redirect_url: "/home".into(),
                created_at: Utc::now(),
                saml_authn_request_id: None,
                kind: PendingAuthKind::Login,
                browser_nonce_hash: Some("browser-hash".into()),
            };
            store
                .pending_auth_insert("auth-start-transition", &auth_start)
                .await
                .unwrap();
            let left_store = AuthStateStore::new(store.clone());
            let right_store = AuthStateStore::new(store.clone());
            let (left, right) = tokio::join!(
                left_store.transition_auth_start(
                    "auth-start-transition",
                    "login-transition",
                    login.clone(),
                ),
                right_store.transition_auth_start(
                    "auth-start-transition",
                    "login-transition",
                    login.clone(),
                )
            );
            let winners = [left, right]
                .into_iter()
                .map(|result| result.unwrap_or_else(|e| panic!("{label}: transition: {e}")))
                .filter(|transitioned| *transitioned)
                .count();
            assert_eq!(winners, 1, "{label}: exactly one transition must win");
            assert!(
                store
                    .pending_auth_get("auth-start-transition")
                    .await
                    .unwrap()
                    .is_none(),
                "{label}: winner must consume AuthStart"
            );
            assert_eq!(
                store
                    .pending_auth_get("login-transition")
                    .await
                    .unwrap()
                    .expect("winner must create Login")
                    .kind,
                PendingAuthKind::Login,
                "{label}"
            );
            assert!(
                !AuthStateStore::new(store.clone())
                    .transition_auth_start(
                        "auth-start-transition",
                        "replayed-login",
                        login.clone(),
                    )
                    .await
                    .unwrap(),
                "{label}: replayed AuthStart must not create another Login"
            );
            assert!(
                store
                    .pending_auth_get("replayed-login")
                    .await
                    .unwrap()
                    .is_none(),
                "{label}: replay loser must leave no Login row"
            );

            let mut expired = auth_start.clone();
            expired.created_at = Utc::now() - Duration::hours(1);
            store
                .pending_auth_insert("expired-auth-start", &expired)
                .await
                .unwrap();
            assert!(
                !AuthStateStore::new(store.clone())
                    .transition_auth_start("expired-auth-start", "expired-login", login.clone(),)
                    .await
                    .unwrap(),
                "{label}: expired AuthStart must be rejected"
            );
            assert!(
                store
                    .pending_auth_get("expired-login")
                    .await
                    .unwrap()
                    .is_none(),
                "{label}: expired source must not create Login"
            );

            store
                .pending_auth_insert("wrong-kind", &login)
                .await
                .unwrap();
            assert!(
                !AuthStateStore::new(store.clone())
                    .transition_auth_start("wrong-kind", "wrong-kind-login", login.clone())
                    .await
                    .unwrap(),
                "{label}: non-AuthStart source must be rejected"
            );
            assert!(
                store
                    .pending_auth_get("wrong-kind")
                    .await
                    .unwrap()
                    .is_some(),
                "{label}: rejected wrong-kind source must remain untouched"
            );

            store
                .pending_auth_insert("auth-start-conflict", &auth_start)
                .await
                .unwrap();
            store
                .pending_auth_insert("occupied-login", &login)
                .await
                .unwrap();
            let error = AuthStateStore::new(store.clone())
                .transition_auth_start("auth-start-conflict", "occupied-login", login.clone())
                .await
                .expect_err("strict Login insert collision must fail");
            assert!(matches!(error, crate::error::Error::Database(_)), "{label}");
            assert!(
                store
                    .pending_auth_get("auth-start-conflict")
                    .await
                    .unwrap()
                    .is_some(),
                "{label}: failed insert must roll back AuthStart consume"
            );
            assert_eq!(
                store
                    .pending_auth_get("occupied-login")
                    .await
                    .unwrap()
                    .expect("collision row remains")
                    .nonce,
                "oidc-nonce",
                "{label}: strict insert must not overwrite collision"
            );
        }
    }

    #[tokio::test]
    async fn pending_auth_expired_is_invisible() {
        for (label, store) in stores_under_test().await {
            let state = crate::auth::middleware::PendingAuth {
                idp_id: Uuid::new_v4(),
                nonce: String::new(),
                code_verifier: String::new(),
                redirect_url: "/".into(),
                created_at: Utc::now() - Duration::hours(1),
                saml_authn_request_id: None,
                kind: crate::auth::middleware::PendingAuthKind::Login,
                browser_nonce_hash: None,
            };
            store.pending_auth_insert("stale", &state).await.unwrap();
            let read = store.pending_auth_get("stale").await.unwrap();
            assert!(read.is_none(), "{label}: expired get must be invisible");
            assert!(
                store.pending_auth_take("stale").await.unwrap().is_none(),
                "{label}: expired take must remain invisible"
            );
        }
    }

    /// Consuming the same nonce twice yields exactly one winner, and retention is
    /// measured against the database clock rather than the process's.
    #[tokio::test]
    async fn handoff_nonce_consume_is_atomic_and_cleanup_uses_db_time() {
        for (label, store, control) in stores_with_relational_control().await {
            let nonce = Uuid::new_v4();
            assert!(
                store.handoff_nonce_consume(nonce).await.unwrap(),
                "{label}: first consume must win"
            );
            assert!(
                !store.handoff_nonce_consume(nonce).await.unwrap(),
                "{label}: duplicate consume must be rejected"
            );

            match &control {
                RelationalTestControl::Sqlite(pool) => {
                    sqlx::query(
                        "UPDATE used_handoff_nonces \
                         SET consumed_at = unixepoch() - 120 WHERE nonce = ?",
                    )
                    .bind(nonce)
                    .execute(pool)
                    .await
                    .unwrap();
                }
                RelationalTestControl::Postgres(pool) => {
                    sqlx::query(
                        "UPDATE used_handoff_nonces SET consumed_at = \
                         EXTRACT(EPOCH FROM NOW())::BIGINT - 120 WHERE nonce = $1",
                    )
                    .bind(nonce)
                    .execute(pool)
                    .await
                    .unwrap();
                }
            }
            assert_eq!(
                store.handoff_nonce_cleanup_expired().await.unwrap(),
                0,
                "{label}: the 120-second boundary remains protected"
            );
            assert!(
                !store.handoff_nonce_consume(nonce).await.unwrap(),
                "{label}: boundary record must still reject replay"
            );

            match &control {
                RelationalTestControl::Sqlite(pool) => {
                    sqlx::query(
                        "UPDATE used_handoff_nonces \
                         SET consumed_at = unixepoch() - 121 WHERE nonce = ?",
                    )
                    .bind(nonce)
                    .execute(pool)
                    .await
                    .unwrap();
                }
                RelationalTestControl::Postgres(pool) => {
                    sqlx::query(
                        "UPDATE used_handoff_nonces SET consumed_at = \
                         EXTRACT(EPOCH FROM NOW())::BIGINT - 121 WHERE nonce = $1",
                    )
                    .bind(nonce)
                    .execute(pool)
                    .await
                    .unwrap();
                }
            }
            assert_eq!(store.handoff_nonce_cleanup_expired().await.unwrap(), 1);
            assert!(
                store.handoff_nonce_consume(nonce).await.unwrap(),
                "{label}: nonce may be reinserted only after retention cleanup"
            );
        }
    }

    #[tokio::test]
    async fn cert_mutation_bumps_version() {
        for (label, store) in stores_under_test().await {
            let v0 = store.cert_version_current().await.unwrap();
            let cert = crate::models::cert::Certificate {
                id: Uuid::new_v4(),
                domain: format!("{label}.test"),
                cert_pem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n".into(),
                key_pem_encrypted: "k".into(),
                issued_at: Utc::now(),
                expires_at: Utc::now() + Duration::days(30),
                source: crate::models::cert::CertSource::Acme,
            };
            store.upsert_cert(&cert).await.unwrap();
            let v1 = store.cert_version_current().await.unwrap();
            assert!(v1 > v0, "{label}: upsert must bump cert_version");

            store.delete_cert(cert.id).await.unwrap();
            let v2 = store.cert_version_current().await.unwrap();
            assert!(v2 > v1, "{label}: delete must bump cert_version");
        }
    }

    /// `Store::close` must flush the underlying pool so operational
    /// queries issued after it fail fast instead of hanging on a
    /// half-dead connection. Covers the graceful-shutdown contract:
    /// background tasks have joined, listeners have stopped, and
    /// `main.rs` calls `store.close()` as the final DB operation.
    #[tokio::test]
    async fn close_is_idempotent_and_flushes_pool() {
        for (label, store) in stores_under_test().await {
            // Baseline: pool works.
            store.list_routes().await.expect("baseline works");

            store.close().await;
            // Second call must not panic / deadlock — matters because
            // the backend pool and the bootstrap pool are aliased on
            // single-node SQLite, so `close()` observes two close
            // calls on the same underlying pool.
            store.close().await;

            // Operational queries after close must fail rather than
            // hang forever. `sqlx` surfaces a closed pool as
            // `Error::PoolClosed`; we don't pin the exact variant,
            // just that the call returns promptly with an error.
            let res =
                tokio::time::timeout(std::time::Duration::from_secs(2), store.list_routes()).await;
            assert!(
                res.is_ok(),
                "{label}: list_routes hung after close — pool not actually closed"
            );
            assert!(
                res.unwrap().is_err(),
                "{label}: list_routes succeeded after close"
            );
            assert!(
                store.handoff_nonce_consume(Uuid::new_v4()).await.is_err(),
                "{label}: DB failure must not become a successful nonce consume"
            );
        }
    }
}
