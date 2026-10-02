//! Evaluation-semantics tests for the policy DSL.
//!
//! The recurring theme is failing closed. A missing claim must not make a
//! negative comparison succeed, an unresolvable policy reference must not
//! evaluate to "allow", and case sensitivity must match what an operator would
//! expect from an IdP's own matching. Each of these is a case where the
//! permissive answer is the one an implementation naturally falls into, so
//! they are pinned individually rather than trusted to the evaluator's shape.

#[cfg(test)]
mod tests {
    use super::super::evaluator::{EvalContext, evaluate};
    use super::super::parser::parse;
    use crate::models::session::Session;
    use crate::store::Store;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use uuid::Uuid;

    async fn test_store() -> Store {
        Store::new_for_test("sqlite::memory:", [0u8; 32], None)
            .await
            .unwrap()
    }

    fn make_session(
        user_id: &str,
        groups: Vec<&str>,
        claims: Vec<(&str, serde_json::Value)>,
    ) -> Session {
        let mut claim_map = HashMap::new();
        for (k, v) in claims {
            claim_map.insert(k.to_string(), v);
        }
        Session {
            id: Uuid::new_v4(),
            user_id: user_id.into(),
            idp_id: Uuid::new_v4(),
            upstream_identity: None,
            claims: claim_map,
            groups: groups.into_iter().map(String::from).collect(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(8),
            refresh_token_encrypted: None,
            id_token_encrypted: None,
            saml_name_id: None,
            saml_session_index: None,
            last_accessed_at: Utc::now(),
        }
    }

    fn ctx_with<'a>(session: &'a Session, ip: Option<&'a str>) -> EvalContext<'a> {
        EvalContext {
            session: Some(session),
            client_ip: ip.map(|s| s.parse::<IpAddr>().unwrap()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn eq_username() {
        let store = test_store().await;
        let s = make_session("alice@example.com", vec![], vec![]);
        let e = parse(r#"claim.username == "alice@example.com""#).unwrap();
        assert!(evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn eq_username_case_insensitive() {
        let store = test_store().await;
        let s = make_session("Alice@EXAMPLE.com", vec![], vec![]);
        let e = parse(r#"claim.username == "alice@example.com""#).unwrap();
        assert!(evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn group_in_list() {
        let store = test_store().await;
        let s = make_session("a@x", vec!["DL_SOC", "DL_NOC"], vec![]);
        let e = parse(r#"claim.groups in ["DL_SOC", "DL_OPS"]"#).unwrap();
        assert!(evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn group_not_in_denies() {
        let store = test_store().await;
        let s = make_session("a@x", vec!["DL_SOC"], vec![]);
        let e = parse(r#"claim.groups not in ["DL_NOC"]"#).unwrap();
        assert!(evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn missing_claim_negative_comparisons_fail_closed() {
        let store = test_store().await;
        let s = make_session("a@x", vec![], vec![]);
        for source in [
            r#"claim.role not in ["guest"]"#,
            r#"claim.role != "guest""#,
            r#"claim.role !~ "^guest$""#,
        ] {
            let e = parse(source).unwrap();
            assert!(
                !evaluate(&e, &ctx_with(&s, None), &store).await,
                "missing field matched: {source}"
            );
        }
    }

    #[tokio::test]
    async fn not_in_preserves_present_value_semantics() {
        let store = test_store().await;
        let blocked = make_session(
            "blocked@x",
            vec![],
            vec![("role", serde_json::json!("guest"))],
        );
        let allowed = make_session(
            "allowed@x",
            vec![],
            vec![("role", serde_json::json!("member"))],
        );
        let e = parse(r#"claim.role not in ["guest"]"#).unwrap();
        assert!(!evaluate(&e, &ctx_with(&blocked, None), &store).await);
        assert!(evaluate(&e, &ctx_with(&allowed, None), &store).await);
    }

    #[tokio::test]
    async fn cidr_match() {
        let store = test_store().await;
        let s = make_session("a@x", vec![], vec![]);
        let e = parse(r#"client.ip == "192.168.0.0/24""#).unwrap();
        assert!(evaluate(&e, &ctx_with(&s, Some("192.168.0.42")), &store).await);
        assert!(!evaluate(&e, &ctx_with(&s, Some("10.0.0.1")), &store).await);
    }

    #[tokio::test]
    async fn cidr_in_list() {
        let store = test_store().await;
        let s = make_session("a@x", vec![], vec![]);
        let e = parse(r#"client.ip in ["10.0.0.0/8", "192.168.0.0/24"]"#).unwrap();
        assert!(evaluate(&e, &ctx_with(&s, Some("192.168.0.42")), &store).await);
        assert!(evaluate(&e, &ctx_with(&s, Some("10.5.5.5")), &store).await);
        assert!(!evaluate(&e, &ctx_with(&s, Some("172.16.0.1")), &store).await);
    }

    #[tokio::test]
    async fn and_combines() {
        let store = test_store().await;
        let s = make_session("a@x", vec!["DL_SOC"], vec![]);
        let e = parse(r#"claim.groups in ["DL_SOC"] and client.ip in ["192.168.0.0/24"]"#).unwrap();
        assert!(evaluate(&e, &ctx_with(&s, Some("192.168.0.1")), &store).await);
        assert!(!evaluate(&e, &ctx_with(&s, Some("10.0.0.1")), &store).await);
    }

    #[tokio::test]
    async fn or_combines() {
        let store = test_store().await;
        let s = make_session("admin@x", vec!["admin"], vec![]);
        let e = parse(r#"claim.groups in ["DL_SOC"] or claim.username == "admin@x""#).unwrap();
        assert!(evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn claim_lookup() {
        let store = test_store().await;
        let s = make_session(
            "a@x",
            vec![],
            vec![("department", serde_json::json!("SOC"))],
        );
        let e = parse(r#"claim.department == "SOC""#).unwrap();
        assert!(evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn domain_derived() {
        let store = test_store().await;
        let s = make_session("alice@EXAMPLE.COM", vec![], vec![]);
        let e = parse(r#"claim.domain == "example.com""#).unwrap();
        assert!(evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn regex_match_on_path() {
        let store = test_store().await;
        let s = make_session("a@x", vec![], vec![]);
        let mut c = ctx_with(&s, None);
        c.request_path = Some("/admin/users");
        let e = parse(r#"request.path ~= "^/admin""#).unwrap();
        assert!(evaluate(&e, &c, &store).await);
        let e = parse(r#"request.path ~= "^/billing""#).unwrap();
        assert!(!evaluate(&e, &c, &store).await);
    }

    #[tokio::test]
    async fn ordinary_request_headers_and_claims_remain_available() {
        let store = test_store().await;
        let session = make_session(
            "alice@example.com",
            vec![],
            vec![("email", serde_json::json!("alice@example.com"))],
        );
        let headers = HashMap::from([("x-request-source".into(), "cron".into())]);
        let mut ctx = ctx_with(&session, None);
        ctx.request_headers = Some(&headers);
        assert!(
            evaluate(
                &parse(r#"request.header.x_request_source == "cron""#).unwrap(),
                &ctx,
                &store
            )
            .await
        );
        assert!(
            evaluate(
                &parse(r#"claim.email == "alice@example.com""#).unwrap(),
                &ctx,
                &store
            )
            .await
        );
    }

    #[tokio::test]
    async fn manually_constructed_proxy_owned_header_ast_fails_closed() {
        use super::super::ast::{Expr, FieldPath, Op, Operand, Value};

        let store = test_store().await;
        let session = make_session("alice@example.com", vec![], vec![]);
        let headers = HashMap::from([("x-sekisho-user".into(), "admin".into())]);
        let mut ctx = ctx_with(&session, None);
        ctx.request_headers = Some(&headers);
        let expr = Expr::Cmp(
            FieldPath::new(vec![
                "request".into(),
                "header".into(),
                "x_sekisho_user".into(),
            ]),
            Op::Eq,
            Operand::Value(Value::String("admin".into())),
        );
        assert!(!evaluate(&expr, &ctx, &store).await);
    }

    #[tokio::test]
    async fn invalid_regex_fails_closed_for_both_operators() {
        let store = test_store().await;
        let s = make_session("a@x", vec![], vec![]);
        let mut c = ctx_with(&s, None);
        c.request_path = Some("/admin/users");
        for source in [r#"request.path ~= "[""#, r#"request.path !~ "[""#] {
            let e = parse(source).unwrap();
            assert!(
                !evaluate(&e, &c, &store).await,
                "invalid regex matched: {source}"
            );
        }
    }

    #[tokio::test]
    async fn regex_not_match_preserves_valid_semantics() {
        let store = test_store().await;
        let s = make_session("a@x", vec![], vec![]);
        let mut c = ctx_with(&s, None);
        c.request_path = Some("/admin/users");
        let matching = parse(r#"request.path !~ "^/admin""#).unwrap();
        assert!(!evaluate(&matching, &c, &store).await);
        let nonmatching = parse(r#"request.path !~ "^/billing""#).unwrap();
        assert!(evaluate(&nonmatching, &c, &store).await);
    }

    #[tokio::test]
    async fn policy_ref_resolves() {
        use crate::models::policy::CreatePolicy;
        let store = test_store().await;
        let p = CreatePolicy {
            name: "soc".into(),
            expr: r#"claim.groups in ["DL_SOC"]"#.into(),
        }
        .into_policy();
        store.create_policy(&p).await.unwrap();

        let s = make_session("a@x", vec!["DL_SOC"], vec![]);
        let e = parse("policy.soc").unwrap();
        assert!(evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn repeated_policy_ref_is_not_a_cycle() {
        use crate::models::policy::CreatePolicy;
        let store = test_store().await;
        let leaf = CreatePolicy {
            name: "leaf".into(),
            expr: r#"claim.groups in ["DL_SOC"]"#.into(),
        }
        .into_policy();
        store.create_policy(&leaf).await.unwrap();

        let s = make_session("a@x", vec!["DL_SOC"], vec![]);
        let e = parse("policy.leaf and policy.leaf").unwrap();
        assert!(evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn diamond_policy_refs_are_not_a_cycle() {
        use crate::models::policy::CreatePolicy;
        let store = test_store().await;
        for (name, expr) in [
            ("leaf", r#"claim.groups in ["DL_SOC"]"#),
            ("left", "policy.leaf"),
            ("right", "policy.leaf"),
        ] {
            let policy = CreatePolicy {
                name: name.into(),
                expr: expr.into(),
            }
            .into_policy();
            store.create_policy(&policy).await.unwrap();
        }

        let s = make_session("a@x", vec!["DL_SOC"], vec![]);
        let e = parse("policy.left and policy.right").unwrap();
        assert!(evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn policy_ref_cycle_does_not_loop() {
        use crate::models::policy::CreatePolicy;
        let store = test_store().await;
        for (name, expr) in [("a", "policy.b"), ("b", "policy.a")] {
            let p = CreatePolicy {
                name: name.into(),
                expr: expr.into(),
            }
            .into_policy();
            store.create_policy(&p).await.unwrap();
        }
        let s = make_session("a@x", vec![], vec![]);
        let e = parse("policy.a").unwrap();
        // No infinite loop, no panic, denies.
        assert!(!evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn direct_policy_ref_cycle_denies() {
        use crate::models::policy::CreatePolicy;
        let store = test_store().await;
        let policy = CreatePolicy {
            name: "loop".into(),
            expr: "policy.loop".into(),
        }
        .into_policy();
        store.create_policy(&policy).await.unwrap();

        let s = make_session("a@x", vec![], vec![]);
        let e = parse("policy.loop").unwrap();
        assert!(!evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn missing_policy_ref_denies() {
        let store = test_store().await;
        let s = make_session("a@x", vec![], vec![]);
        let e = parse("policy.does-not-exist").unwrap();
        assert!(!evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn malformed_policy_ref_denies() {
        use crate::models::policy::Policy;
        let store = test_store().await;
        let policy = Policy {
            id: Uuid::new_v4(),
            name: "broken".into(),
            expr: "claim.username ==".into(),
        };
        sqlx::query("INSERT INTO policies (id, name, data) VALUES (?, ?, ?)")
            .bind(policy.id)
            .bind(&policy.name)
            .bind(serde_json::to_string(&policy).unwrap())
            .execute(store.sqlite_pool())
            .await
            .unwrap();

        let s = make_session("a@x", vec![], vec![]);
        let e = parse("policy.broken").unwrap();
        assert!(!evaluate(&e, &ctx_with(&s, None), &store).await);
    }

    #[tokio::test]
    async fn legacy_proxy_owned_policy_ref_is_retained_and_denied() {
        use crate::models::policy::Policy;

        let store = test_store().await;
        let policy = Policy {
            id: Uuid::new_v4(),
            name: "legacy-proxy-owned".into(),
            expr: r#"request.header.x_sekisho_user == "admin""#.into(),
        };
        let serialized = serde_json::to_string(&policy).unwrap();
        sqlx::query("INSERT INTO policies (id, name, data) VALUES (?, ?, ?)")
            .bind(policy.id)
            .bind(&policy.name)
            .bind(&serialized)
            .execute(store.sqlite_pool())
            .await
            .unwrap();

        let session = make_session("alice@example.com", vec![], vec![]);
        let headers = HashMap::from([("x-sekisho-user".into(), "admin".into())]);
        let mut ctx = ctx_with(&session, None);
        ctx.request_headers = Some(&headers);
        let reference = parse("policy.legacy-proxy-owned").unwrap();

        assert!(!evaluate(&reference, &ctx, &store).await);
        assert!(!evaluate(&reference, &ctx, &store).await);
        assert_eq!(
            serde_json::to_string(&store.get_policy(policy.id).await.unwrap()).unwrap(),
            serialized
        );
    }

    #[tokio::test]
    async fn legacy_inline_proxy_owned_route_policies_deny_http_and_websocket_before_upstream() {
        use crate::models::route::Route;
        use crate::proxy::handler::evaluate_route_access;
        use crate::session::cookie_manager::CookieManager;
        use crate::tls::acme::AcmeManager;
        use crate::tls::acme::challenge::Http01Provider;
        use axum::body::Body;
        use axum::http::{Request, StatusCode, header};
        use cookie::SameSite;
        use std::sync::Arc;
        use tower::ServiceExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sentinel upstream");
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let store = Store::new_for_test("sqlite::memory:", [0x71; 32], None)
            .await
            .expect("store");

        let cases = [
            (
                "legacy-x-sekisho",
                "legacy-x-sekisho.example.com",
                "x-sekisho-user",
                "admin",
                r#"request.header.x_sekisho_user == "admin""#,
            ),
            (
                "legacy-forwarded",
                "legacy-forwarded.example.com",
                "forwarded",
                "for=192.0.2.10",
                r#"request.header.forwarded == "for=192.0.2.10""#,
            ),
            (
                "legacy-x-forwarded",
                "legacy-x-forwarded.example.com",
                "x-forwarded-for",
                "192.0.2.20",
                r#"request.header.x_forwarded_for == "192.0.2.20""#,
            ),
        ];
        let mut seeded = Vec::new();
        for (name, host, _, _, expression) in cases {
            let route: Route = serde_json::from_value(serde_json::json!({
                "id": Uuid::new_v4(),
                "name": name,
                "from": format!("https://{host}"),
                "to": [upstream.clone()],
                "access": {"policy": expression},
                "enable_websocket": true,
                "enabled": true
            }))
            .unwrap();
            let serialized = serde_json::to_string(&route).unwrap();
            sqlx::query("INSERT INTO routes (id, name, data) VALUES (?, ?, ?)")
                .bind(route.id)
                .bind(&route.name)
                .bind(&serialized)
                .execute(store.sqlite_pool())
                .await
                .unwrap();
            seeded.push((route.id, host, serialized));
        }

        let session = make_session("alice@example.com", vec![], vec![]);
        store.create_session(&session).await.unwrap();
        let route_generation =
            crate::route_generation::RouteGeneration::new_for_test(store.clone()).await;
        let provider = Arc::new(Http01Provider::new(store.clone()));
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            provider,
            "https://acme.invalid/directory",
            None,
        ));
        let cookie_secret = [0x72; 64];
        let app = crate::proxy::router(
            store.clone(),
            route_generation,
            &cookie_secret,
            acme,
            crate::crypto::MasterKey::from_test_bytes([0x73; 32]),
            crate::crypto::JwtSigningKey::from_test_bytes([0x74; 32]),
            Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            true,
            "sekisho_session".into(),
            100,
            Arc::new(crate::shutdown::ShutdownController::new()),
        );
        let cookie = CookieManager::new(&cookie_secret)
            .with_name("sekisho_session".into())
            .create_cookie(session.id, SameSite::Lax);
        let cookie = cookie.split(';').next().unwrap();

        for ((_, host, header_name, header_value, _), (route_id, _, serialized)) in
            cases.into_iter().zip(&seeded)
        {
            let route = store.get_route(*route_id).await.unwrap();
            let headers = HashMap::from([(header_name.to_string(), header_value.to_string())]);
            let mut ctx = ctx_with(&session, None);
            ctx.request_headers = Some(&headers);
            assert!(!evaluate_route_access(&route, &ctx, &store).await);

            let http = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header(header::HOST, host)
                        .header(header::COOKIE, cookie)
                        .header(header_name, header_value)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(http.status(), StatusCode::FORBIDDEN);

            let websocket = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/socket")
                        .header(header::HOST, host)
                        .header(header::COOKIE, cookie)
                        .header(header_name, header_value)
                        .header(header::CONNECTION, "Upgrade")
                        .header(header::UPGRADE, "websocket")
                        .header("sec-websocket-version", "13")
                        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(websocket.status(), StatusCode::FORBIDDEN);

            let stored: String = sqlx::query_scalar("SELECT data FROM routes WHERE id = ?")
                .bind(route_id)
                .fetch_one(store.sqlite_pool())
                .await
                .unwrap();
            assert_eq!(&stored, serialized);
        }

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "legacy inline policy reached the upstream"
        );
    }

    #[tokio::test]
    async fn policy_ref_combines_with_or() {
        // soc grants on group; gate refers to soc — gate should pass when soc passes.
        use crate::models::policy::CreatePolicy;
        let store = test_store().await;
        for (name, expr) in [
            ("soc", r#"claim.groups in ["DL_SOC"]"#),
            ("gate", "policy.soc or claim.username == \"admin@x\""),
        ] {
            let p = CreatePolicy {
                name: name.into(),
                expr: expr.into(),
            }
            .into_policy();
            store.create_policy(&p).await.unwrap();
        }
        // Member of DL_SOC matches via policy.soc.
        let s1 = make_session("alice@x", vec!["DL_SOC"], vec![]);
        assert!(evaluate(&parse("policy.gate").unwrap(), &ctx_with(&s1, None), &store).await);
        // admin@x matches via the OR side.
        let s2 = make_session("admin@x", vec![], vec![]);
        assert!(evaluate(&parse("policy.gate").unwrap(), &ctx_with(&s2, None), &store).await);
    }
}
