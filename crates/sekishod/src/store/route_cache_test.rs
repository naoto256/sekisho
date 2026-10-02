//! Contract tests for the published route snapshot.
//!
//! Concentrated on the cases where "no route" and "broken configuration" must
//! stay distinguishable: an invalid snapshot must not activate partially, a
//! disabled route must be invisible rather than merely unmatched, and path
//! prefixes must only match on segment boundaries. Each of those failing
//! silently would look like a routing quirk while actually being an
//! authorization change.

#[cfg(test)]
mod tests {
    use crate::models::route::{HeaderModifications, LoadBalancing, Route, RouteAccess, TlsMode};
    use crate::store::route_cache::RouteCache;
    use uuid::Uuid;

    fn make_route(name: &str, from: &str) -> Route {
        Route {
            id: Uuid::new_v4(),
            name: name.to_string(),
            from: from.to_string(),
            path: None,
            to: vec!["http://backend:8080".to_string()],
            redirect: None,
            idp_id: None,
            access: RouteAccess::default(),
            load_balancing: LoadBalancing::RoundRobin,
            preserve_host_header: true,
            host_rewrite: None,
            timeout_ms: 30_000,
            response_idle_timeout_ms: 180_000,
            enable_websocket: false,
            enable_grpc: false,
            enable_signed_identity: false,
            regex_rewrite_pattern: None,
            regex_rewrite_substitution: None,
            tls_skip_verify: false,
            tls_downstream: TlsMode::None,
            headers: HeaderModifications::default(),
            session_cookie_samesite: None,
            response_location_rewrite: true,
            enabled: true,
            concurrency_limit: None,
        }
    }

    #[test]
    fn empty_cache_returns_none() {
        let cache = RouteCache::new();
        assert!(cache.get("app.example.com", "/").unwrap().is_none());
        assert!(!cache.is_loaded());
    }

    #[test]
    fn load_and_get() {
        let cache = RouteCache::new();
        cache
            .load(vec![
                make_route("app1", "https://app1.example.com"),
                make_route("app2", "https://app2.example.com"),
            ])
            .unwrap();
        assert!(cache.is_loaded());
        assert!(cache.get("app1.example.com", "/").unwrap().is_some());
        assert!(cache.get("app2.example.com", "/").unwrap().is_some());
        assert!(cache.get("unknown.example.com", "/").unwrap().is_none());
    }

    #[test]
    fn invalidate_clears_cache() {
        let cache = RouteCache::new();
        cache
            .load(vec![make_route("app", "https://app.example.com")])
            .unwrap();
        assert!(cache.get("app.example.com", "/").unwrap().is_some());

        cache.invalidate();
        assert!(!cache.is_loaded());
        assert!(cache.get("app.example.com", "/").unwrap().is_none());
    }

    #[test]
    fn invalid_snapshot_is_not_partially_activated() {
        let cache = RouteCache::new();
        let valid = make_route("valid", "https://valid.example.com");
        assert!(
            cache
                .load(vec![valid, make_route("bad", "not-a-url")])
                .is_err()
        );
        assert!(cache.is_loaded());
        assert!(cache.get("valid.example.com", "/").is_err());

        for path in [
            "/admin?part",
            "/admin#part",
            "/admin%3fpart",
            "/admin%23part",
        ] {
            let mut invalid = make_route("invalid-path", "https://invalid.example.com");
            invalid.path = Some(path.into());
            assert!(cache.load(vec![invalid]).is_err(), "accepted {path}");
            assert!(cache.get("invalid.example.com", "/").is_err());
        }
    }

    #[test]
    fn disabled_route_is_hidden() {
        let cache = RouteCache::new();
        let mut disabled = make_route("staged", "https://staged.example.com");
        disabled.enabled = false;
        let live = make_route("live", "https://live.example.com");
        cache.load(vec![disabled, live]).unwrap();
        assert!(
            cache.get("staged.example.com", "/").unwrap().is_none(),
            "disabled routes must not be served",
        );
        assert!(cache.get("live.example.com", "/").unwrap().is_some());
    }

    #[test]
    fn returned_route_has_correct_data() {
        let cache = RouteCache::new();
        let route = make_route("myapp", "https://myapp.example.com");
        let route_id = route.id;
        cache.load(vec![route]).unwrap();

        let found = cache.get("myapp.example.com", "/").unwrap().unwrap();
        assert_eq!(found.id, route_id);
        assert_eq!(found.name, "myapp");
    }

    #[test]
    fn path_prefix_requires_an_end_or_slash_boundary() {
        let cache = RouteCache::new();
        let mut route = make_route("admin", "https://app.example.com");
        route.path = Some("/admin".into());
        cache.load(vec![route]).unwrap();

        assert!(cache.get("app.example.com", "/admin").unwrap().is_some());
        assert!(cache.get("app.example.com", "/admin/").unwrap().is_some());
        assert!(
            cache
                .get("app.example.com", "/admin/users")
                .unwrap()
                .is_some()
        );
        assert!(
            cache
                .get("app.example.com", "/administrator")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn longer_ascii_casefolded_prefix_blocks_catch_all() {
        let cache = RouteCache::new();
        let catch_all = make_route("catch-all", "https://app.example.com");
        let mut admin = make_route("admin", "https://app.example.com");
        admin.path = Some("/Admin".into());
        cache.load(vec![catch_all, admin]).unwrap();

        assert!(cache.get("app.example.com", "/admin").unwrap().is_none());
    }

    #[test]
    fn same_length_exact_match_wins_over_ascii_casefolded_peer() {
        let cache = RouteCache::new();
        let mut exact = make_route("exact-admin", "https://app.example.com");
        exact.path = Some("/admin".into());
        let exact_id = exact.id;
        let mut folded = make_route("folded-admin", "https://app.example.com");
        folded.path = Some("/Admin".into());
        cache.load(vec![folded, exact]).unwrap();

        let selected = cache
            .get("app.example.com", "/admin")
            .unwrap()
            .expect("same-length exact route");
        assert_eq!(selected.id, exact_id);
        assert_eq!(selected.name, "exact-admin");
    }

    #[test]
    fn shorter_ascii_casefolded_prefix_does_not_shadow_longer_exact_match() {
        let cache = RouteCache::new();
        let mut exact = make_route("exact-users", "https://app.example.com");
        exact.path = Some("/admin/users".into());
        let exact_id = exact.id;
        let mut folded = make_route("folded-admin", "https://app.example.com");
        folded.path = Some("/Admin".into());
        cache.load(vec![folded, exact]).unwrap();

        let selected = cache
            .get("app.example.com", "/admin/users")
            .unwrap()
            .expect("longer exact route");
        assert_eq!(selected.id, exact_id);
        assert_eq!(selected.name, "exact-users");
    }

    #[test]
    fn non_ascii_case_variant_is_not_an_ascii_folded_match() {
        let cache = RouteCache::new();
        let catch_all = make_route("catch-all", "https://app.example.com");
        let catch_all_id = catch_all.id;
        let mut non_ascii = make_route("upper-non-ascii", "https://app.example.com");
        non_ascii.path = Some("/Ädmin".into());
        cache.load(vec![non_ascii, catch_all]).unwrap();

        let selected = cache
            .get("app.example.com", "/ädmin")
            .unwrap()
            .expect("catch-all route");
        assert_eq!(selected.id, catch_all_id);
        assert_eq!(selected.name, "catch-all");
    }

    #[test]
    fn disabled_invalid_routes_do_not_invalidate_enabled_snapshot() {
        let cache = RouteCache::new();
        let valid = make_route("enabled-valid", "https://app.example.com");
        let valid_id = valid.id;

        let mut invalid_from = make_route("disabled-invalid-from", "not-a-url");
        invalid_from.enabled = false;
        let mut invalid_path = make_route("disabled-invalid-path", "https://bad.example.com");
        invalid_path.enabled = false;
        invalid_path.path = Some("/bad//path".into());
        let mut invalid_regex = make_route("disabled-invalid-regex", "https://bad.example.com");
        invalid_regex.enabled = false;
        invalid_regex.regex_rewrite_pattern = Some("(".into());
        invalid_regex.regex_rewrite_substitution = Some("/replacement".into());

        cache
            .load(vec![invalid_from, invalid_path, invalid_regex, valid])
            .expect("disabled invalid routes must be ignored before validation");
        let selected = cache
            .get("app.example.com", "/")
            .unwrap()
            .expect("enabled route");
        assert_eq!(selected.id, valid_id);
        assert_eq!(selected.name, "enabled-valid");
    }

    #[test]
    fn terminal_slash_prefix_remains_distinct() {
        let cache = RouteCache::new();
        let mut route = make_route("admin", "https://app.example.com");
        route.path = Some("/admin/".into());
        cache.load(vec![route]).unwrap();

        assert!(cache.get("app.example.com", "/admin").unwrap().is_none());
        assert!(cache.get("app.example.com", "/admin/").unwrap().is_some());
        assert!(
            cache
                .get("app.example.com", "/admin/users")
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn sqlite_route_observation_is_coherent_and_rejects_invalid_version_rows() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [71; 32], None)
            .await
            .unwrap();
        let empty = store.observe_routes().await.unwrap();
        assert_eq!(empty.version, 0);
        assert!(empty.routes.is_empty());

        let route = make_route("observed", "https://app.example.com");
        store.create_route(&route).await.unwrap();
        let populated = store.observe_routes().await.unwrap();
        assert_eq!(populated.version, 1);
        assert_eq!(populated.routes.len(), 1);
        assert_eq!(populated.routes[0].id, route.id);

        sqlx::query("UPDATE schema_versions SET version = -1 WHERE resource = 'routes'")
            .execute(store.sqlite_pool())
            .await
            .unwrap();
        assert!(matches!(
            store.observe_routes().await,
            Err(crate::error::Error::Internal(_))
        ));

        sqlx::query("DELETE FROM schema_versions WHERE resource = 'routes'")
            .execute(store.sqlite_pool())
            .await
            .unwrap();
        assert!(matches!(
            store.observe_routes().await,
            Err(crate::error::Error::Internal(_))
        ));
    }
}
