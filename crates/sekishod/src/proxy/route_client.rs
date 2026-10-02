//! Per-route reqwest client cache for upstreams that need
//! `tls_skip_verify` and/or `host_rewrite`.
//!
//! ## Why per-route
//!
//! The obvious alternative is a single shared `reqwest::Client` with
//! every route's `resolve()` registration pre-loaded. That's more
//! efficient (one connection pool instead of N), but it collides when
//! two routes share a `host_rewrite` value pointing at different
//! backends — reqwest keeps only the last `resolve()` entry per
//! hostname, so one route would silently route to the wrong backend.
//!
//! Per-route isolation also keeps the `danger_accept_invalid_certs`
//! scope narrow: only the routes that explicitly opted in to
//! `tls_skip_verify` get a cert-ignoring client. A shared client
//! would either accept invalid certs for every route (wider blast
//! radius) or require two shared clients (defeating the consolidation).
//!
//! Route counts in IAP deployments run in the dozens, not thousands,
//! so the per-route memory cost (a reqwest::Client is ~few hundred
//! KB including its connection pool) is negligible.
//!
//! ## Why URL authority rewrite instead of Host header rewrite
//!
//! Under HTTP/2 (reqwest picks H2 via ALPN when the upstream offers
//! it), the `:authority` pseudo-header comes from the request URL,
//! not from the `Host` header. If `host_rewrite` only touches the
//! `Host` header and leaves the URL pointing at the backend IP, the
//! upstream sees two divergent authorities and does vhost matching on
//! `:authority` (RFC 9113 §8.3.1-style). On t-pot's bundled nginx
//! this means requests hit the default vhost and route-injected
//! `Authorization: Basic ...` credentials get rejected with 401.
//!
//! The fix: rewrite the URL authority to `host_rewrite`, and use
//! `reqwest::ClientBuilder::resolve()` to pin the TCP connection
//! target to the original backend socket. Result: URL and Host agree
//! (under H1), `:authority` and Host agree (under H2), and vhost
//! matching lands on the right vhost in both cases.
//!
//! ## DNS
//!
//! Backend hostname → SocketAddr resolution happens at client build
//! time via [`hickory-resolver`](https://docs.rs/hickory-resolver), so
//! the record TTL returned by the authoritative resolver drives
//! cache expiry — matching nginx's `resolver`, envoy's
//! `respect_dns_ttl`, and haproxy's `resolvers`. Two triggers force a
//! fresh resolve:
//!
//! 1. **Route generation replacement** — route CRUD withdraws the current
//!    generation, and the replacement owns a fresh cache.
//! 2. **Record TTL expiry** — each cached entry carries
//!    `(resolved_at, ttl)` where `ttl` is the minimum TTL across the
//!    answer's A/AAAA records, clamped to [`MIN_RESOLVE_TTL`] …
//!    [`MAX_RESOLVE_TTL`]. A request that finds the entry expired
//!    drops it and rebuilds. This bounds staleness for backends whose
//!    DNS moves without any route change (cloud LBs, k8s Services,
//!    blue/green cutovers).
//!
//! If DNS fails during a TTL-triggered rebuild we keep the stale
//! entry and serve from it — a flaky resolver must not take the route
//! down. Route-version-triggered rebuilds propagate the error instead,
//! because the operator just changed the route and silently serving
//! the old client would hide the mistake.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};

use crate::models::route::Route;

/// Lower bound on cached-record TTL.
///
/// A misconfigured or malicious authoritative server can return TTL=0
/// or sub-second values; respecting that literally would turn every
/// request into a resolver round-trip and let the DNS layer become a
/// DDoS vector against both us and the resolver. 5 s is short enough
/// to feel "live" during a cutover but long enough that a burst of
/// requests coalesces onto a single lookup.
pub(crate) const MIN_RESOLVE_TTL: Duration = Duration::from_secs(5);

/// Upper bound on cached-record TTL.
///
/// Public DNS operators occasionally publish multi-day TTLs; inside
/// an IAP that would silently defer a blue/green cutover past the
/// point any operator expects. 1 h matches the implicit contract
/// under the old hardcoded design and is the largest window we're
/// willing to trust any third-party DNS setting without operator
/// intervention.
pub(crate) const MAX_RESOLVE_TTL: Duration = Duration::from_secs(3600);

/// Clamp a raw record TTL (as reported by the resolver) into the
/// range we're willing to honour. Exposed `pub(crate)` so the unit
/// tests can assert on the boundaries without pulling in a mock
/// resolver.
pub(crate) fn clamp_ttl(raw: Duration) -> Duration {
    raw.clamp(MIN_RESOLVE_TTL, MAX_RESOLVE_TTL)
}

/// A cached reqwest client + the rewritten URL authority to use when
/// forwarding through it.
#[derive(Clone)]
pub struct RouteClient {
    pub client: reqwest::Client,
    /// Authority portion (`host[:port]`) to use when building the
    /// upstream URL. When `host_rewrite` is set, this is
    /// `host_rewrite[:port_from_backend_url]`; otherwise it's the
    /// backend URL's authority unchanged.
    pub authority: String,
    /// Scheme (`http` or `https`) to use when building the upstream
    /// URL. Taken from the backend URL.
    pub scheme: String,
    /// True iff the URL authority has been rewritten away from the
    /// backend's own authority — either via explicit `host_rewrite`
    /// or via the implicit `preserve_host_header` rewrite to the
    /// route's public hostname. The handler uses this to decide
    /// whether to drop the inbound `Host` header (it would otherwise
    /// duplicate the URL-derived `:authority` under H2 and trip
    /// RFC 9113 §8.3.1 on strict upstreams like nginx).
    pub authority_rewritten: bool,
    /// When the backend address pinned into `client` via `resolve()`
    /// was last looked up. Combined with [`RouteClient::ttl`] to
    /// drive TTL-based re-resolution.
    resolved_at: Instant,
    /// Effective TTL for this entry — the minimum record TTL
    /// returned by the resolver, clamped by [`clamp_ttl`]. For code
    /// paths that bypass the resolver (raw-IP backends, or routes
    /// without host_rewrite where we don't pin a socket) this is
    /// set to [`MAX_RESOLVE_TTL`] — there is no DNS record to
    /// respect, and a no-op rebuild every hour is the same posture
    /// the old hardcoded implementation had.
    ttl: Duration,
}

impl RouteClient {
    /// TTL check based on `Instant::elapsed()`, which reads Rust's
    /// monotonic clock. Wall-clock jumps (NTP steps, DST changes,
    /// manual `date -s`) do not affect this comparison. A switch to
    /// `SystemTime`-based measurement would remove that invariant.
    fn is_expired(&self) -> bool {
        self.resolved_at.elapsed() >= self.ttl
    }
}

/// Wrapper that owns the resolver shared by one `RouteClientCache`.
/// Constructed with that cache so `resolve_socket` calls reuse its
/// resolver configuration and internal cache/pool state.
struct SharedResolver(TokioResolver);

impl SharedResolver {
    fn new() -> Self {
        // Prefer `/etc/resolv.conf` (Linux) / system config (macOS,
        // Windows) — matches what the old `tokio::net::lookup_host`
        // path observed, so host-of-record routing behaviour is
        // unchanged. Fall back to hickory's default (Google Public
        // DNS) if the system config is missing or unreadable: this
        // keeps the proxy functional in stripped-down containers
        // where `/etc/resolv.conf` isn't mounted, at the cost of
        // leaking queries to 8.8.8.8. Operators who don't want that
        // should mount a resolv.conf.
        // Two independent steps can fail here. `builder_tokio()`
        // fails when system DNS config can't be read; the builder's
        // own `.build()` fails during pool/socket setup. Either
        // surfaces the same user-visible story ("no system DNS for
        // us"), so we collapse both into the same fallback branch.
        let resolver = TokioResolver::builder_tokio()
            .and_then(|b| b.build())
            .unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "system DNS config unavailable; falling back to hickory default (Google Public DNS)"
                );
                Resolver::builder_with_config(
                    ResolverConfig::default(),
                    TokioRuntimeProvider::default(),
                )
                .build()
                .expect(
                    "hickory default config must build — no I/O happens until lookup time",
                )
            });
        Self(resolver)
    }
}

pub struct RouteClientCache {
    inner: RwLock<HashMap<(Uuid, String), Arc<RouteClient>>>,
    resolver: Arc<SharedResolver>,
}

impl Default for RouteClientCache {
    fn default() -> Self {
        Self {
            inner: RwLock::default(),
            resolver: Arc::new(SharedResolver::new()),
        }
    }
}

impl RouteClientCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test-only cache reset. Production replaces the whole generation when
    /// route inputs change.
    #[cfg(test)]
    pub async fn invalidate(&self) {
        self.inner.write().await.clear();
    }

    /// Get or build the per-route client for the given upstream
    /// index. `upstream_base` is `route.to[idx]` — the caller picks
    /// which backend in the load-balancing set before calling us so
    /// that different LB targets don't stomp on each other's cache
    /// entry.
    pub async fn get_or_build(
        &self,
        route: &Route,
        upstream_base: &str,
    ) -> Result<Arc<RouteClient>, BuildError> {
        // Fast path — read lock only. Serve a cached entry only if
        // its record TTL hasn't expired; a stale entry falls through
        // to the rebuild path so DNS eventually catches up to
        // backend churn.
        let key = (route.id, upstream_base.to_owned());
        let cached = self.inner.read().await.get(&key).cloned();
        if let Some(c) = cached.as_ref()
            && !c.is_expired()
        {
            return Ok(c.clone());
        }

        // Slow path. Hold the generation-local write lock across the build so
        // concurrent requests cannot construct two clients for the same
        // generation/key. Re-check after acquiring because a prior builder may
        // have filled the entry while this task waited.
        let mut entries = self.inner.write().await;
        let cached = entries.get(&key).cloned();
        if let Some(c) = cached.as_ref()
            && !c.is_expired()
        {
            return Ok(c.clone());
        }
        match build_client(route, upstream_base, &self.resolver.0).await {
            Ok(rc) => {
                let rc = Arc::new(rc);
                entries.insert(key, rc.clone());
                Ok(rc)
            }
            Err(e) => {
                // Graceful TTL fallback: if we had an entry that just
                // aged out and DNS then failed, keep serving the old
                // address. A flaky resolver must not be allowed to
                // take a healthy route down. Cold-miss failures
                // (nothing cached yet) still propagate — there's
                // nothing to fall back to.
                if let Some(stale) = cached {
                    tracing::warn!(
                        route = %route.name,
                        error = %e,
                        "DNS re-resolve failed at TTL expiry; serving previous address"
                    );
                    return Ok(stale);
                }
                Err(e)
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("invalid upstream URL {0}: {1}")]
    InvalidUrl(String, String),
    #[error("upstream URL {0} has no host component")]
    MissingHost(String),
    #[error("failed to resolve {0}: {1}")]
    DnsFailed(String, String),
    #[error("failed to build reqwest client: {0}")]
    ClientBuild(#[from] reqwest::Error),
}

async fn build_client(
    route: &Route,
    upstream_base: &str,
    resolver: &TokioResolver,
) -> Result<RouteClient, BuildError> {
    let parsed = url::Url::parse(upstream_base)
        .map_err(|e| BuildError::InvalidUrl(upstream_base.to_string(), e.to_string()))?;
    let backend_host = parsed
        .host_str()
        .ok_or_else(|| BuildError::MissingHost(upstream_base.to_string()))?
        .to_string();
    let scheme = parsed.scheme().to_string();
    let backend_port = parsed
        .port_or_known_default()
        .ok_or_else(|| BuildError::InvalidUrl(upstream_base.to_string(), "no port".to_string()))?;

    // Rewrite authority applies to the URL the caller builds and to
    // the `resolve()` key. Two paths lead here:
    //
    // 1. Explicit `host_rewrite` — the operator picked a vhost name
    //    they want the upstream to see.
    // 2. Implicit rewrite from `preserve_host_header: true` with no
    //    `host_rewrite` — the inbound Host (== `route.from`'s host)
    //    must reach the upstream verbatim. Under H2, reqwest derives
    //    `:authority` from the URL, so leaving the URL authority as
    //    the backend IP and only emitting the public hostname via the
    //    `Host` header creates an `:authority` / `Host` mismatch that
    //    strict upstreams (nginx after RFC 9113 §8.3.1) reject with
    //    400. Rewriting the URL authority to `route.from`'s host —
    //    same fix shape as path (1), just sourced from `from` instead
    //    of an explicit knob — keeps the two pseudo-headers aligned.
    //
    // When neither path applies (`preserve_host_header: false` and no
    // `host_rewrite`), the authority is the backend's own and we skip
    // the resolve() pin.
    let effective_rewrite: Option<String> = match &route.host_rewrite {
        Some(r) if !r.is_empty() => Some(r.clone()),
        _ if route.preserve_host_header => from_hostname(&route.from),
        _ => None,
    };
    let (authority, rewrite_target): (String, Option<String>) = match &effective_rewrite {
        Some(rewrite) => {
            // URL authority is the rewrite hostname, **without** the
            // backend port. Including the backend port here (e.g.
            // `app-b.example.com:8443` for an upstream on
            // 8443) would leak into the H2 `:authority` and the H1
            // `Host` header — both come from the URL — and trip
            // upstreams that cross-check against the client-visible
            // `Origin` (Django CSRF middleware, in particular,
            // computes `good_origin = "https://" + get_host()` and
            // string-compares it to the request `Origin` header,
            // which the browser writes without the backend port the
            // client never saw).
            //
            // The actual upstream socket comes from the resolve()
            // pin below — `Client::resolve(domain, SocketAddr)`
            // overrides both IP *and* port, so the URL's implicit
            // default port has no effect on which TCP endpoint is
            // contacted. The rewrite hostname plus that resolve()
            // pin are the only two pieces that matter for routing.
            (rewrite.clone(), Some(rewrite.clone()))
        }
        None => {
            let auth = match parsed.port() {
                Some(p) => format!("{backend_host}:{p}"),
                None => backend_host.clone(),
            };
            (auth, None)
        }
    };
    let authority_rewritten = rewrite_target.is_some();

    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(60));

    if route.tls_skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }

    // Pin the rewrite hostname to the backend's actual socket.
    // Without this, reqwest would do a system DNS lookup on the
    // rewrite hostname — which is the public-facing name and likely
    // resolves to *this* proxy, creating a loop.
    //
    // When no rewrite is in effect we skip the resolve pin and take
    // the max-TTL path; reqwest's own DNS cache will handle
    // rediscovery and there is no `:authority`/Host mismatch risk.
    let ttl = if let Some(target) = rewrite_target.as_deref() {
        let (socket, record_ttl) = resolve_socket(resolver, &backend_host, backend_port).await?;
        builder = builder.resolve(target, socket);
        record_ttl
    } else {
        MAX_RESOLVE_TTL
    };

    let client = builder.build()?;
    Ok(RouteClient {
        client,
        authority,
        scheme,
        authority_rewritten,
        resolved_at: Instant::now(),
        ttl,
    })
}

/// Extract just the hostname portion of `route.from` (e.g.
/// `"https://app.example.com/admin"` -> `"app.example.com"`). Used to
/// drive the implicit `preserve_host_header` authority rewrite — the
/// URL `:authority` must match the inbound `Host` (which equals this
/// hostname when the route is reached at all), so we sync the two by
/// rewriting authority to it. Returns `None` if `from` doesn't parse
/// or has no host component; the caller treats that as "no rewrite",
/// which preserves pre-fix behaviour for malformed routes rather than
/// hard-failing client construction.
fn from_hostname(from: &str) -> Option<String> {
    url::Url::parse(from)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

/// Resolve `host` (a DNS name or raw IP literal) to one
/// `SocketAddr` plus the effective (clamped) TTL to cache that
/// answer for.
///
/// The resolver may return several A/AAAA records. We pin to the
/// first one — second has its own LB layer (`upstream::LoadBalancer`)
/// that selects among `route.to`, so fanning out here would double-
/// count. The effective TTL is the *minimum* across all returned
/// records: any one of them expiring means the answer set as a whole
/// is no longer guaranteed fresh, so caching past that point would
/// silently pin us to a retired IP even though the hostname's RRset
/// has moved on.
async fn resolve_socket(
    resolver: &TokioResolver,
    host: &str,
    port: u16,
) -> Result<(SocketAddr, Duration), BuildError> {
    // Raw IP literals short-circuit — hickory would also handle them,
    // but skipping the resolver avoids a pointless query and lets us
    // cache for the full MAX_RESOLVE_TTL (there is no record TTL to
    // respect). Matches the fast-path semantics of the old
    // `tokio::net::lookup_host((ip, port))` code.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok((SocketAddr::new(ip, port), MAX_RESOLVE_TTL));
    }

    let lookup = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| BuildError::DnsFailed(host.to_string(), e.to_string()))?;

    // Take the minimum TTL across the answer RRset. Any one record
    // expiring means the set as a whole is no longer guaranteed
    // fresh, so caching past that point would silently pin us to a
    // retired IP even though the hostname's records have moved on.
    // Fall back to the lookup's own `valid_until` when the answer
    // section is empty for any reason (defensive — shouldn't happen
    // after the `lookup.iter().next()` success below, but we're
    // computing TTL before that check).
    let min_record_ttl_secs = lookup
        .as_lookup()
        .answers()
        .iter()
        .map(|r: &hickory_resolver::proto::rr::Record| r.ttl)
        .min();
    let ttl = match min_record_ttl_secs {
        Some(secs) => clamp_ttl(Duration::from_secs(u64::from(secs))),
        None => {
            let fallback = lookup
                .as_lookup()
                .valid_until()
                .saturating_duration_since(Instant::now());
            clamp_ttl(fallback)
        }
    };

    let ip = lookup.iter().next().ok_or_else(|| {
        BuildError::DnsFailed(host.to_string(), "no addresses returned".to_string())
    })?;
    Ok((SocketAddr::new(ip, port), ttl))
}

/// Build the upstream URL to pass to the route's reqwest client.
/// The authority comes from the cached `RouteClient`; the path +
/// query come from the (already path-transformed) request URI.
pub fn build_rewritten_url(rc: &RouteClient, original: &axum::http::Uri) -> String {
    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    format!("{}://{}{}", rc.scheme, rc.authority, path_and_query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn route_with(host_rewrite: Option<&str>, tls_skip: bool) -> Route {
        let mut r: Route = serde_json::from_value(serde_json::json!({
            "id": Uuid::nil(),
            "name": "r",
            "from": "https://x.example",
            "to": ["https://10.0.0.1:443"],
        }))
        .unwrap();
        r.host_rewrite = host_rewrite.map(String::from);
        r.tls_skip_verify = tls_skip;
        r
    }

    /// Variant for tests that need to disable the
    /// `preserve_host_header` implicit rewrite (i.e. exercise the
    /// truly unrewritten path: backend IP authority on the wire).
    fn route_no_preserve(host_rewrite: Option<&str>, tls_skip: bool) -> Route {
        let mut r = route_with(host_rewrite, tls_skip);
        r.preserve_host_header = false;
        r
    }

    fn test_resolver() -> TokioResolver {
        SharedResolver::new().0
    }

    #[tokio::test]
    async fn authority_omits_backend_port_under_rewrite() {
        // Phantom04 regression: the URL authority must NOT carry the
        // backend port, otherwise the H2 `:authority` and H1 `Host`
        // headers leak `:8443` to upstream — which Django's CSRF
        // middleware then string-compares against the client `Origin`
        // (which the browser writes without that port) and rejects
        // with 403. The backend port reaches the upstream socket via
        // the resolve() pin, not via the URL authority.
        let r = route_with(Some("api.internal"), true);
        let rc = build_client(&r, "https://10.0.0.1:8443", &test_resolver())
            .await
            .expect("build");
        assert_eq!(rc.authority, "api.internal");
        assert_eq!(rc.scheme, "https");
    }

    #[tokio::test]
    async fn authority_drops_default_port_under_rewrite() {
        // Default-port case behaves the same — both backend and
        // client-visible URL omit the port — included only as the
        // sibling assertion to keep the contract obvious.
        let r = route_with(Some("api.internal"), true);
        let rc = build_client(&r, "https://10.0.0.1:443", &test_resolver())
            .await
            .expect("build");
        assert_eq!(rc.authority, "api.internal");
    }

    #[tokio::test]
    async fn no_rewrite_keeps_backend_authority() {
        // No host_rewrite AND preserve_host_header=false → URL
        // authority is the backend's own. This is the
        // appliance-with-Host-derived-redirects path documented in
        // handler.rs.
        let r = route_no_preserve(None, true);
        let rc = build_client(&r, "https://10.0.0.1:8443", &test_resolver())
            .await
            .expect("build");
        assert_eq!(rc.authority, "10.0.0.1:8443");
        assert!(!rc.authority_rewritten);
    }

    #[tokio::test]
    async fn preserve_host_header_implicit_rewrite_to_from_hostname() {
        // Regression: an upstream was running with
        // `preserve_host_header: true` + `host_rewrite: null` against
        // an H2-capable nginx (192.0.2.133:8443). Without the fix,
        // reqwest sent `:authority: 10.0.0.1:8443` (URL-derived) plus
        // `Host: x.example` (preserved), and nginx rejected the H2
        // frame as RFC 9113 §8.3.1 malformed → 400 with empty access
        // log line. The fix rewrites the URL authority to
        // `route.from`'s hostname so `:authority` and the inbound
        // Host agree on the wire. We assert both halves: authority
        // string AND the `authority_rewritten` flag the handler reads
        // to decide whether to drop the duplicate Host header.
        let r = route_with(None, true);
        let rc = build_client(&r, "https://10.0.0.1:8443", &test_resolver())
            .await
            .expect("build");
        assert_eq!(rc.authority, "x.example");
        assert!(rc.authority_rewritten);
    }

    #[tokio::test]
    async fn preserve_host_header_default_port_drops_port() {
        // Same as the explicit-rewrite default-port case: when the
        // backend port is the scheme default we omit it from the URL
        // authority so vhost matching against `from`'s hostname (no
        // port) succeeds.
        let r = route_with(None, true);
        let rc = build_client(&r, "https://10.0.0.1:443", &test_resolver())
            .await
            .expect("build");
        assert_eq!(rc.authority, "x.example");
        assert!(rc.authority_rewritten);
    }

    #[tokio::test]
    async fn explicit_host_rewrite_wins_over_preserve_host_header() {
        // host_rewrite must take precedence over the implicit
        // preserve_host_header rewrite — operators who set
        // host_rewrite explicitly are picking a vhost name that
        // differs from `route.from`, and silently overriding it
        // would defeat the knob. (`preserve_host_header` defaults to
        // true so this exercises the cross-feature interaction.)
        let r = route_with(Some("api.internal"), true);
        let rc = build_client(&r, "https://10.0.0.1:8443", &test_resolver())
            .await
            .expect("build");
        assert_eq!(rc.authority, "api.internal");
        assert!(rc.authority_rewritten);
    }

    #[tokio::test]
    async fn build_rewritten_url_formats_authority_and_path() {
        let r = route_with(Some("api.internal"), true);
        let rc = build_client(&r, "https://10.0.0.1:8443", &test_resolver())
            .await
            .expect("build");
        let uri: axum::http::Uri = "/foo?bar=1".parse().unwrap();
        assert_eq!(
            build_rewritten_url(&rc, &uri),
            "https://api.internal/foo?bar=1"
        );
    }

    #[tokio::test]
    async fn cache_returns_same_client_on_hit() {
        let cache = RouteClientCache::new();
        let r = route_with(Some("api.internal"), true);
        let c1 = cache
            .get_or_build(&r, "https://10.0.0.1:8443")
            .await
            .unwrap();
        let c2 = cache
            .get_or_build(&r, "https://10.0.0.1:8443")
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&c1, &c2));
    }

    /// End-to-end contract for the rewrite fix: the caller supplies
    /// a backend URL pointing at a concrete socket (here, a local
    /// listener on 127.0.0.1) and a `host_rewrite` pointing at a
    /// hostname that deliberately wouldn't resolve (`.invalid.`
    /// under RFC 6761). If the TCP target weren't pinned via
    /// `resolve()`, the request would fail DNS. If it succeeds and
    /// the mock sees `Host: nonexistent.invalid`, both halves of
    /// the fix are proven — rewritten authority on the wire AND
    /// correct TCP target.
    #[tokio::test]
    async fn host_rewrite_pins_tcp_and_propagates_authority() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Capture the first request's raw bytes to inspect Host.
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = socket.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            req
        });

        let mut route = route_with(Some("nonexistent.invalid"), false);
        // Point `to` at an address we know would DNS-fail, so the
        // test fails if resolve() pinning ever breaks. 203.0.113.0/24
        // is TEST-NET-3 (RFC 5737); routing to it would hang rather
        // than reach our listener. Instead we put the actual listener
        // port in the URL and let the rewrite host be fake — the
        // resolve() call pins `nonexistent.invalid` -> 127.0.0.1:port.
        route.to = vec![format!("http://127.0.0.1:{port}")];
        let backend_url = route.to[0].clone();

        let rc = build_client(&route, &backend_url, &test_resolver())
            .await
            .expect("build");
        assert_eq!(rc.authority, "nonexistent.invalid");

        let url = format!("http://nonexistent.invalid:{port}/probe");
        let resp = rc.client.get(&url).send().await.expect("send");
        assert_eq!(resp.status().as_u16(), 200);

        let raw = server.await.unwrap();
        // The mock's raw bytes prove the Host header on the wire is
        // the rewrite value, not the backend IP. Under H1 this is
        // the `Host:` line; under H2 it would be `:authority`, but
        // hyper's H2 over plaintext isn't negotiated without ALPN
        // (which needs TLS), so this test locks the H1 leg. The
        // authority string assertion above plus the reqwest URL
        // construction together cover the H2 leg: `:authority`
        // comes from the URL, which we have just proven carries
        // the rewrite.
        let lower = raw.to_ascii_lowercase();
        assert!(
            lower.contains("host: nonexistent.invalid"),
            "expected rewritten Host in raw request, got: {raw}"
        );
    }

    /// End-to-end contract for the `preserve_host_header` implicit
    /// rewrite (H2 authority regression fix). Mirrors
    /// `host_rewrite_pins_tcp_and_propagates_authority` but with no
    /// explicit `host_rewrite` set: the rewrite target is taken from
    /// `route.from`'s hostname, the URL authority on the wire becomes
    /// that hostname, and the `:authority` / `Host` agreement that
    /// strict H2 upstreams require is therefore reachable.
    ///
    /// We exercise the same H1 wire-capture trick the explicit test
    /// uses (TLS-less listener so no ALPN H2 negotiation), and rely
    /// on the `rc.authority` assertion plus reqwest's URL-to-
    /// `:authority` derivation contract to cover the H2 leg by
    /// construction.
    #[tokio::test]
    async fn preserve_host_header_pins_tcp_and_propagates_authority() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = socket.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            req
        });

        // `preserve_host_header: true` (default) + `host_rewrite: null`
        // — the bug-shaped configuration. We spell `from` to a
        // hostname under RFC 6761's `.invalid.` so that if the
        // resolve() pin ever regresses, the test fails with a DNS
        // error rather than a silent wrong-target connection.
        let mut route = route_with(None, false);
        route.from = "https://phantom-test.invalid".to_string();
        route.to = vec![format!("http://127.0.0.1:{port}")];
        let backend_url = route.to[0].clone();

        let rc = build_client(&route, &backend_url, &test_resolver())
            .await
            .expect("build");
        assert_eq!(
            rc.authority, "phantom-test.invalid",
            "URL authority must be rewritten to route.from's hostname \
             without the backend port so :authority/Host on the wire \
             match the client-visible Origin"
        );
        assert!(
            rc.authority_rewritten,
            "handler relies on this flag to drop the duplicate Host header"
        );

        let url = format!("http://phantom-test.invalid:{port}/probe");
        let resp = rc.client.get(&url).send().await.expect("send");
        assert_eq!(resp.status().as_u16(), 200);

        let raw = server.await.unwrap();
        let lower = raw.to_ascii_lowercase();
        // On the H1 wire, reqwest's `Host:` line is derived from the
        // URL authority — which we just set to `phantom-test.invalid`.
        // Under H2 the same value would land in `:authority`. Either
        // way, the value matches the public hostname the inbound
        // request carried, so an upstream that vhosts on it routes
        // correctly without any RFC 9113 §8.3.1 mismatch.
        assert!(
            lower.contains("host: phantom-test.invalid"),
            "expected from-hostname Host in raw request, got: {raw}"
        );
    }

    /// Test-only: replace a cached entry with a copy whose
    /// `resolved_at` is past its TTL, and return an Arc to the
    /// replacement so callers can assert on its identity. A real
    /// clock is deliberately not used — using a fake time source
    /// would bleed test knowledge into production code.
    async fn age_entry_past_ttl(
        cache: &RouteClientCache,
        route_id: Uuid,
        upstream_base: &str,
    ) -> Arc<RouteClient> {
        let mut w = cache.inner.write().await;
        let key = (route_id, upstream_base.to_owned());
        let rc = w.get(&key).cloned().expect("entry must be present");
        let aged = Arc::new(RouteClient {
            client: rc.client.clone(),
            authority: rc.authority.clone(),
            scheme: rc.scheme.clone(),
            authority_rewritten: rc.authority_rewritten,
            // Shift `resolved_at` back by the entry's own TTL plus
            // slack, so `is_expired()` fires regardless of whether
            // the record TTL got clamped up to MIN or down from
            // MAX. Matching against `rc.ttl` (rather than a fixed
            // constant) keeps this helper honest as the clamp
            // bounds evolve.
            resolved_at: Instant::now() - rc.ttl - Duration::from_secs(1),
            ttl: rc.ttl,
        });
        w.insert(key, aged.clone());
        aged
    }

    #[tokio::test]
    async fn stale_entry_triggers_rebuild() {
        // Cache a good entry, age it past TTL, then demonstrate the
        // next get_or_build returns a freshly built client (different
        // Arc identity from the aged one). Proves the TTL read-lock
        // check evicts.
        let cache = RouteClientCache::new();
        let r = route_with(Some("api.internal"), true);
        cache
            .get_or_build(&r, "https://10.0.0.1:8443")
            .await
            .unwrap();
        let aged = age_entry_past_ttl(&cache, r.id, "https://10.0.0.1:8443").await;
        let rebuilt = cache
            .get_or_build(&r, "https://10.0.0.1:8443")
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&aged, &rebuilt));
    }

    #[tokio::test]
    async fn stale_entry_dns_failure_falls_back_to_previous() {
        // A flaky resolver must not take a healthy route down. If the
        // entry has aged out but the next DNS lookup fails, we serve
        // the stale (but previously-working) client rather than 502.
        let cache = RouteClientCache::new();
        let r = route_with(Some("api.internal"), true);
        cache
            .get_or_build(&r, "https://10.0.0.1:8443")
            .await
            .unwrap();
        let aged = age_entry_past_ttl(&cache, r.id, "https://10.0.0.1:8443").await;

        // Force build_client to fail by pointing at an unresolvable
        // host under RFC 6761's `.invalid`. Cache still holds the
        // aged entry, so we should get *it* back, not an error.
        let error = cache
            .get_or_build(&r, "https://nonexistent.invalid:8443")
            .await;
        assert!(error.is_err());
        let retained = cache
            .inner
            .read()
            .await
            .get(&(r.id, "https://10.0.0.1:8443".to_owned()))
            .cloned()
            .expect("the distinct upstream entry remains cached");
        assert!(Arc::ptr_eq(&aged, &retained));
    }

    #[tokio::test]
    async fn cold_miss_dns_failure_propagates() {
        // No cached entry → DNS failure has no fallback, so the error
        // must surface. Symmetric contract to the stale-fallback case
        // above.
        let cache = RouteClientCache::new();
        let r = route_with(Some("api.internal"), true);
        let err = cache
            .get_or_build(&r, "https://nonexistent.invalid:8443")
            .await;
        assert!(matches!(err, Err(BuildError::DnsFailed(_, _))));
    }

    #[tokio::test]
    async fn invalidate_forces_rebuild() {
        let cache = RouteClientCache::new();
        let r = route_with(Some("api.internal"), true);
        let c1 = cache
            .get_or_build(&r, "https://10.0.0.1:8443")
            .await
            .unwrap();
        cache.invalidate().await;
        let c2 = cache
            .get_or_build(&r, "https://10.0.0.1:8443")
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&c1, &c2));
    }

    #[test]
    fn clamp_ttl_enforces_lower_bound() {
        // TTL=0 from a misconfigured authoritative server would
        // otherwise turn every request into a resolver round-trip.
        assert_eq!(clamp_ttl(Duration::from_secs(0)), MIN_RESOLVE_TTL);
        assert_eq!(clamp_ttl(Duration::from_secs(1)), MIN_RESOLVE_TTL);
        assert_eq!(clamp_ttl(MIN_RESOLVE_TTL), MIN_RESOLVE_TTL);
    }

    #[test]
    fn clamp_ttl_enforces_upper_bound() {
        // Multi-day TTLs from public DNS must not defer a cutover
        // past the 1 h operator-expectation window.
        assert_eq!(clamp_ttl(Duration::from_secs(86_400)), MAX_RESOLVE_TTL);
        assert_eq!(clamp_ttl(MAX_RESOLVE_TTL), MAX_RESOLVE_TTL);
    }

    #[test]
    fn clamp_ttl_passes_through_in_range() {
        let mid = Duration::from_secs(120);
        assert_eq!(clamp_ttl(mid), mid);
    }

    #[tokio::test]
    async fn raw_ip_backend_uses_max_ttl() {
        // A raw IP backend has no DNS record to respect, so we
        // cache for the full upper bound — matches the old
        // hardcoded 1 h behaviour for the IP-literal case.
        let r = route_with(Some("api.internal"), true);
        let rc = build_client(&r, "https://10.0.0.1:8443", &test_resolver())
            .await
            .expect("build");
        assert_eq!(rc.ttl, MAX_RESOLVE_TTL);
    }

    #[tokio::test]
    async fn no_rewrite_uses_max_ttl() {
        // No rewrite path at all (preserve_host_header=false, no
        // host_rewrite). We don't pin a socket, no DNS lookup occurs
        // in build_client, and there's nothing to expire early on.
        let r = route_no_preserve(None, true);
        let rc = build_client(&r, "https://10.0.0.1:8443", &test_resolver())
            .await
            .expect("build");
        assert_eq!(rc.ttl, MAX_RESOLVE_TTL);
    }
}
