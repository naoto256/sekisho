//! The in-memory route snapshot the data plane matches against.
//!
//! Hitting the database on every proxied request is not an option, so routes
//! are held as an immutable map from hostname to routes, rebuilt and published
//! whole. A published snapshot is never mutated in place — that is what lets
//! [`RouteCache::get`] hold only a read lock and hand back an `Arc<Route>` that
//! stays valid for the life of the request even if a rebuild lands mid-flight.
//!
//! ## Three states, because "empty" is ambiguous
//!
//! `Unloaded` (nothing published yet) and `Invalid` (a rebuild failed) must not
//! be conflated with "loaded and empty". The first two answer differently:
//! `Unloaded` yields a 404, while `Invalid` yields an error the caller turns
//! into a 503. A daemon whose route table failed to build should say it is
//! broken, not claim the route does not exist — the difference decides whether
//! an operator goes looking for a typo in their route or for the real fault.
//!
//! The snapshot is validated as a unit and fails as a unit: one unparseable
//! `from`, one bad regex, one non-canonical path and the whole build is
//! rejected. Loading the routes that happened to parse would mean serving a
//! configuration no operator ever wrote.
//!
//! ## Matching, and the case-fold guard
//!
//! Longest path prefix wins, with the route name as a tiebreak so the result is
//! deterministic rather than dependent on map ordering. Matching is
//! case-*sensitive*, because the request path is canonical by the time it gets
//! here and paths are case-sensitive in HTTP.
//!
//! But a case-sensitive match can be a trap: if some route would have matched a
//! *longer* prefix under case folding, the operator almost certainly meant that
//! route, and serving the shorter exact match instead could hand the request to
//! a more permissive route. [`RouteCache::get`] therefore returns `None` in
//! that situation rather than guessing — an unreachable route is a
//! configuration bug the operator can see, whereas a silent downgrade to a
//! different route's policy is one they cannot.
//!
//! ## Reserved headers are dropped at load, not at match
//!
//! Admission validation rejects reserved header operations, but rows written
//! before that gate existed can still be in the database. Filtering them once
//! per snapshot (with a warning) rather than per request keeps the request path
//! free of the check and means an old row degrades to "that header edit is
//! ignored" instead of taking the route down.

use crate::identity::CanonicalHost;
use crate::models::route::Route;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A snapshot could not be built, or the last build attempt failed.
///
/// Carries no detail on purpose: it crosses into the request path, where the
/// only correct response is a flat 503. The reason is logged at the point the
/// build failed, which is where an operator can act on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidRouteSnapshot;

enum RouteCacheState {
    /// No snapshot published yet — startup has not finished. Lookups miss.
    Unloaded,
    /// A validated snapshot, keyed by hostname.
    Loaded(HashMap<String, Vec<Arc<Route>>>),
    /// A rebuild failed. Lookups error rather than miss; see the module docs.
    Invalid,
}

/// In-memory cache of routes, keyed by hostname.
pub struct RouteCache {
    cache: RwLock<RouteCacheState>,
}

impl RouteCache {
    /// A cache with nothing published yet.
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(RouteCacheState::Unloaded),
        }
    }

    /// Look up a route by hostname and canonical request path.
    pub fn get(
        &self,
        hostname: &str,
        request_path: &str,
    ) -> Result<Option<Arc<Route>>, InvalidRouteSnapshot> {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        let routes = match &*cache {
            RouteCacheState::Unloaded => return Ok(None),
            RouteCacheState::Invalid => return Err(InvalidRouteSnapshot),
            RouteCacheState::Loaded(map) => match map.get(hostname) {
                Some(routes) => routes,
                None => return Ok(None),
            },
        };

        let exact = routes
            .iter()
            .filter(|route| path_matches(route.path.as_deref(), request_path, false))
            .min_by(|a, b| {
                b.path
                    .as_deref()
                    .map_or(0, str::len)
                    .cmp(&a.path.as_deref().map_or(0, str::len))
                    .then_with(|| a.name.cmp(&b.name))
            });
        let exact_len = exact
            .and_then(|route| route.path.as_deref())
            .map_or(0, str::len);
        let folded_len = routes
            .iter()
            .filter(|route| path_matches(route.path.as_deref(), request_path, true))
            .filter_map(|route| route.path.as_deref().map(str::len))
            .max()
            .unwrap_or(0);
        if folded_len > exact_len {
            return Ok(None);
        }
        Ok(exact.cloned())
    }

    /// Return the published canonical hostname for a parsed request host,
    /// without consulting route paths or the database.
    ///
    /// The shared identity authority validates and separates any request port
    /// before this lookup. Route `from` URLs own the redirect hostname;
    /// client-controlled authority bytes never become a `Location` value.
    pub(crate) fn redirect_host(
        &self,
        host: &CanonicalHost,
    ) -> Result<Option<String>, InvalidRouteSnapshot> {
        let hostname = host.to_authority_host();
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        match &*cache {
            RouteCacheState::Unloaded => Ok(None),
            RouteCacheState::Invalid => Err(InvalidRouteSnapshot),
            RouteCacheState::Loaded(map) if map.contains_key(&hostname) => Ok(Some(hostname)),
            RouteCacheState::Loaded(_) => Ok(None),
        }
    }

    #[cfg(test)]
    pub fn is_loaded(&self) -> bool {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        !matches!(*cache, RouteCacheState::Unloaded)
    }

    /// Atomically publish a complete validated enabled-route snapshot.
    /// Validate and publish a snapshot, or mark the cache invalid.
    ///
    /// The build happens before the write lock is taken, so a rebuild — which
    /// parses URLs and compiles regexes — never blocks the request path. On
    /// failure the cache transitions to `Invalid` rather than keeping the
    /// previous snapshot: the operator has changed something the daemon cannot
    /// serve, and continuing to serve the old configuration would hide that
    /// while the two drift apart.
    pub fn load(&self, routes: Vec<Route>) -> Result<(), InvalidRouteSnapshot> {
        let built = build_snapshot(routes);
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        match built {
            Ok(map) => {
                *cache = RouteCacheState::Loaded(map);
                Ok(())
            }
            Err(error) => {
                *cache = RouteCacheState::Invalid;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub fn invalidate(&self) {
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        *cache = RouteCacheState::Unloaded;
    }
}

/// Validate every enabled route and index them by hostname.
///
/// Disabled routes are dropped here rather than filtered at match time, so the
/// request path never sees them and cannot be made to serve one by a bug
/// further down. Everything that could fail at request time — URL parse, path
/// canonicalization, regex compilation — is forced to fail here instead, where
/// it costs one log line rather than a 500 per request.
fn build_snapshot(
    routes: Vec<Route>,
) -> Result<HashMap<String, Vec<Arc<Route>>>, InvalidRouteSnapshot> {
    let mut map: HashMap<String, Vec<Arc<Route>>> = HashMap::new();
    let mut ignored_reserved_headers = false;
    for mut route in routes {
        if !route.enabled {
            continue;
        }
        let url = url::Url::parse(&route.from).map_err(|_| InvalidRouteSnapshot)?;
        let host = url.host_str().ok_or(InvalidRouteSnapshot)?;
        if let Some(path) = route.path.as_deref() {
            route.path = Some(
                crate::request_target::canonicalize_path(path).map_err(|_| InvalidRouteSnapshot)?,
            );
        }
        match (
            route.regex_rewrite_pattern.as_deref(),
            route.regex_rewrite_substitution.as_deref(),
        ) {
            (Some(pattern), Some(_)) => {
                regex::Regex::new(pattern).map_err(|_| InvalidRouteSnapshot)?;
            }
            (None, None) => {}
            _ => return Err(InvalidRouteSnapshot),
        }
        route.headers.add.retain(|name, _| {
            let keep = !crate::proxy::header_boundary::is_reserved_route_header(name);
            ignored_reserved_headers |= !keep;
            keep
        });
        route.headers.remove.retain(|name| {
            let keep = !crate::proxy::header_boundary::is_reserved_route_header(name);
            ignored_reserved_headers |= !keep;
            keep
        });
        map.entry(host.to_owned())
            .or_default()
            .push(Arc::new(route));
    }
    if ignored_reserved_headers {
        tracing::warn!("ignored reserved route header modifications in loaded route snapshot");
    }
    Ok(map)
}

/// Whether `request_path` sits under `prefix`.
///
/// A route with no prefix matches everything; so does `/`. Otherwise the match
/// is on whole segments — `/app` matches `/app` and `/app/x` but not
/// `/application`, because a prefix that could straddle a segment boundary
/// would let one route's policy leak onto a neighbouring path.
///
/// `folded` selects ASCII-case-insensitive comparison, used only to detect the
/// near-miss described in the module docs. Real matching is always the
/// case-sensitive call.
fn path_matches(prefix: Option<&str>, request_path: &str, folded: bool) -> bool {
    let Some(prefix) = prefix else {
        return true;
    };
    if prefix == "/" {
        return true;
    }
    let Some(candidate) = request_path.get(..prefix.len()) else {
        return false;
    };
    let equal = if folded {
        candidate.eq_ignore_ascii_case(prefix)
    } else {
        candidate == prefix
    };
    equal
        && (request_path.len() == prefix.len()
            || prefix.ends_with('/')
            || request_path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

#[cfg(test)]
mod header_boundary_tests {
    use super::RouteCache;
    use crate::identity::CanonicalHost;
    use crate::models::route::{HeaderModifications, LoadBalancing, Route, RouteAccess, TlsMode};
    use uuid::Uuid;

    fn canonical_host(authority: &str) -> CanonicalHost {
        CanonicalHost::from_authority(authority).unwrap().0
    }

    fn legacy_route() -> Route {
        let mut headers = HeaderModifications::default();
        headers.add.insert("Connection".into(), "X-Legacy".into());
        headers.add.insert("X-Custom".into(), "keep".into());
        headers.remove.push("Via".into());
        headers.remove.push("X-Remove".into());
        Route {
            id: Uuid::new_v4(),
            name: "legacy-headers".into(),
            from: "https://app.example.com".into(),
            path: None,
            to: vec!["http://backend:8080".into()],
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
            headers,
            session_cookie_samesite: None,
            response_location_rewrite: true,
            enabled: true,
            concurrency_limit: None,
        }
    }

    #[test]
    fn legacy_reserved_header_operations_are_sanitized_from_snapshot() {
        let cache = RouteCache::new();
        cache
            .load(vec![legacy_route()])
            .expect("legacy snapshot loads");
        let selected = cache.get("app.example.com", "/").unwrap().expect("route");
        assert!(!selected.headers.add.contains_key("Connection"));
        assert_eq!(
            selected.headers.add.get("X-Custom").map(String::as_str),
            Some("keep")
        );
        assert!(!selected.headers.remove.iter().any(|name| name == "Via"));
        assert!(
            selected
                .headers
                .remove
                .iter()
                .any(|name| name == "X-Remove")
        );
    }

    #[test]
    fn redirect_host_uses_the_published_canonical_hostname_and_ignores_request_port() {
        let cache = RouteCache::new();
        let mut dns = legacy_route();
        dns.from = "https://App.Example.COM:8443".into();
        cache.load(vec![dns]).unwrap();

        assert_eq!(
            cache
                .redirect_host(&canonical_host("APP.EXAMPLE.COM:80"))
                .unwrap(),
            Some("app.example.com".into())
        );
        assert_eq!(
            cache
                .redirect_host(&canonical_host("app.example.com:65535"))
                .unwrap(),
            Some("app.example.com".into())
        );
        assert_eq!(
            cache
                .redirect_host(&canonical_host("unknown.example"))
                .unwrap(),
            None
        );
    }

    #[test]
    fn redirect_host_canonicalizes_idna_ipv4_and_ipv6() {
        let cache = RouteCache::new();
        let mut idna = legacy_route();
        idna.name = "idna".into();
        idna.from = "https://b\u{fc}cher.example".into();
        let mut ipv4 = legacy_route();
        ipv4.name = "ipv4".into();
        ipv4.from = "https://127.0.0.1".into();
        let mut ipv6 = legacy_route();
        ipv6.name = "ipv6".into();
        ipv6.from = "https://[2001:db8::1]".into();
        cache.load(vec![idna, ipv4, ipv6]).unwrap();

        assert_eq!(
            cache
                .redirect_host(&canonical_host("XN--BCHER-KVA.EXAMPLE:443"))
                .unwrap(),
            Some("xn--bcher-kva.example".into())
        );
        assert_eq!(
            cache.redirect_host(&canonical_host("127.1:8080")).unwrap(),
            Some("127.0.0.1".into())
        );
        assert_eq!(
            cache
                .redirect_host(&canonical_host("[2001:0db8:0:0:0:0:0:1]:80"))
                .unwrap(),
            Some("[2001:db8::1]".into())
        );
        assert_eq!(
            cache
                .redirect_host(&canonical_host("[2001:db8::2]"))
                .unwrap(),
            None
        );
    }
}
