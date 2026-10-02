//! The outbound request transform pipeline.
//!
//! Everything sekisho changes about a request before it reaches the upstream
//! happens here, as an ordered list of small [`RequestTransform`]s rather than
//! one procedure. The point of the registry shape is that adding an outbound
//! rule is a new struct plus one line in [`default_pipeline`], with no edit to
//! the request path — and that the order is a list you can read, instead of
//! something you have to reconstruct from control flow.
//!
//! ## The order is the trust boundary
//!
//! `StripInternalHeaders` runs **first**, and everything that injects trusted
//! values runs after it. That sequence is the entire reason an upstream may
//! believe `X-Sekisho-User`: the client's version of every header sekisho owns
//! is deleted before sekisho's own version is written, so no inbound value can
//! survive into the forwarded request. A transform inserted before the strip
//! would silently break that property, which is why `default_pipeline` is a
//! single fixed list and not something assembled per route.
//!
//! `ApplyRouteHeaders` runs **last**, so operator-configured edits win over
//! sekisho's defaults — but only over headers the admission gate already
//! decided a route may touch (see
//! [`crate::proxy::header_boundary::is_reserved_route_header`]). Route config
//! cannot reach the identity or forwarding headers at all, so "last wins"
//! here does not mean "route config can forge identity".
//!
//! ## Transforms are stateless
//!
//! Implementations take everything from the `Route` and the
//! [`TransformContext`], so one pipeline instance is shared by every request
//! in the process. No per-request allocation, and no way for one request's
//! state to influence another's.
//!
//! ## The WebSocket path does not use the pipeline
//!
//! [`crate::proxy::websocket`] applies a hand-picked subset directly. A
//! handshake is not an ordinary forwarded request — the hop-by-hop headers
//! that `sanitize_hop_by_hop` strips are exactly the ones the upgrade needs —
//! so it removes spoofed identity, then pins the new connection's handshake
//! itself. Keep the two in sync when adding a transform that carries identity.

use crate::crypto::IdentityKeyRingSnapshot;
use crate::models::route::Route;
use crate::models::session::Session;
use axum::http::{self, header, uri::Uri};

/// Context passed to each transform (request-scoped, not route-scoped).
pub struct TransformContext<'a> {
    pub tls_enabled: bool,
    pub client_host: &'a str,
    /// Client IP address from the TCP connection (if available).
    pub client_ip: Option<&'a str>,
    pub session: Option<&'a Session>,
    /// Canonical claims prepared at the request boundary before any request
    /// mutation or upstream selection.
    pub prepared_identity_claims: Option<&'a crate::identity::SignedIdentityClaims>,
    /// Atomically published Ed25519 identity-signing snapshot.
    pub identity_key_ring: &'a IdentityKeyRingSnapshot,
    /// Name of the session cookie (`global_config.cookie_name`).
    /// `StripInternalHeaders` removes this entry from the user's
    /// `Cookie:` header before forwarding so a Sekisho-controlled cookie
    /// — which has no purpose for upstream — doesn't bloat the request
    /// past upstream nginx's `large_client_header_buffers` limit.
    pub session_cookie_name: &'a str,
}

/// A request transformation applied before forwarding to the upstream.
/// Implementations must be stateless — all config comes from Route.
pub trait RequestTransform: Send + Sync {
    fn apply(&self, parts: &mut http::request::Parts, route: &Route, ctx: &TransformContext<'_>);
}

/// Ordered pipeline of request transforms. Applied sequentially.
pub struct TransformPipeline {
    transforms: Vec<Box<dyn RequestTransform>>,
}

impl TransformPipeline {
    pub fn new() -> Self {
        Self {
            transforms: Vec::new(),
        }
    }

    /// Register a transform at the end of the pipeline.
    pub fn register<T: RequestTransform + 'static>(mut self, t: T) -> Self {
        self.transforms.push(Box::new(t));
        self
    }

    /// Apply all transforms in order.
    pub fn apply_all(
        &self,
        parts: &mut http::request::Parts,
        route: &Route,
        ctx: &TransformContext<'_>,
    ) {
        for t in &self.transforms {
            t.apply(parts, route, ctx);
        }
    }
}

/// Build the default transform pipeline used by the proxy.
pub fn default_pipeline() -> TransformPipeline {
    TransformPipeline::new()
        .register(StripInternalHeaders)
        .register(RewriteHost)
        .register(AddProxyHeaders)
        .register(AddIdentityHeaders)
        .register(AddSignedIdentityToken)
        .register(ApplyRouteHeaders)
        .register(AddViaHeader)
}

/// Append Sekisho's package-version-free Via field after all prior hop fields.
/// The field still records the received HTTP protocol version.
pub struct AddViaHeader;

impl RequestTransform for AddViaHeader {
    fn apply(&self, parts: &mut http::request::Parts, _route: &Route, _ctx: &TransformContext<'_>) {
        super::header_boundary::append_via(&mut parts.headers, parts.version);
    }
}

/// Public entry point so `proxy::handler::send_upstream` can append
/// the same Via token to upstream responses without duplicating the
/// formatting logic.
pub fn append_via_to_response(headers: &mut http::HeaderMap, received_version: http::Version) {
    super::header_boundary::append_via(headers, received_version);
}

/// Rewrite an absolute `Location` response header whose authority points
/// at one of this route's upstreams (`route.to`) so it points back at
/// the public hostname (`route.from`) instead.
///
/// Why: many network appliances behind the IAP emit
/// `Location: https://<own-IP>/...` after a POST/login. Without
/// this rewrite the browser follows the header to the appliance IP
/// directly, bypassing the proxy entirely and breaking IAP
/// authentication. nginx / Apache / Pomerium / Traefik all do
/// equivalent rewriting by default.
///
/// Behaviour:
/// - relative `Location` (no scheme/authority) → unchanged
/// - authority not in `route.to` (e.g. external SSO redirect) → unchanged
/// - parse failures → unchanged (don't risk corrupting the header)
/// - opt-out per route via `route.response_location_rewrite = false`
pub fn rewrite_response_location(
    headers: &mut http::HeaderMap,
    route: &crate::models::route::Route,
    public_host: &str,
) {
    if !route.response_location_rewrite {
        return;
    }
    let Some(loc_value) = headers.get(http::header::LOCATION) else {
        return;
    };
    let Ok(loc_str) = loc_value.to_str() else {
        return;
    };
    let Ok(loc_uri) = loc_str.parse::<Uri>() else {
        return;
    };
    let Some(loc_authority) = loc_uri.authority() else {
        // Relative Location — already proxy-correct.
        return;
    };
    let loc_scheme = loc_uri.scheme_str();

    // Match against every `to` because load-balanced routes spread
    // requests across multiple upstreams and any of them may be the
    // one that emitted the redirect.
    let matches_upstream = route.to.iter().any(|upstream_url| {
        upstream_url
            .parse::<Uri>()
            .ok()
            .and_then(|u| {
                u.authority().map(|auth| {
                    authorities_match(
                        loc_authority.as_str(),
                        loc_scheme,
                        auth.as_str(),
                        u.scheme_str(),
                    )
                })
            })
            .unwrap_or(false)
    });
    if !matches_upstream {
        return;
    }

    // Compose the new Location: https://<public-host><path?query>.
    // Preserve the path-and-query verbatim — sekisho does not rewrite
    // upstream paths in either direction, so the public side serves
    // the same path the appliance asked the browser to visit.
    let path_and_query = loc_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let new_location = format!("https://{public_host}{path_and_query}");
    if let Ok(v) = http::HeaderValue::from_str(&new_location) {
        headers.insert(http::header::LOCATION, v);
    }
}

/// Compare two URL authorities for the `Location`-rewrite match. Both
/// sides are normalized to include their scheme's default port so that
/// `https://1.2.3.4` and `https://1.2.3.4:443` compare equal — the
/// upstream URL in `route.to` typically omits the port while the
/// appliance's `Location` typically includes it (or vice versa).
fn authorities_match(
    loc_authority: &str,
    loc_scheme: Option<&str>,
    upstream_authority: &str,
    upstream_scheme: Option<&str>,
) -> bool {
    normalize_authority(loc_authority, loc_scheme)
        == normalize_authority(upstream_authority, upstream_scheme)
}

/// Put an authority into a form two URLs can be compared by: lowercased, with
/// the scheme's default port made explicit.
///
/// Needed because `https://host` and `https://host:443` denote the same
/// origin but differ as strings, and an upstream is free to emit either in a
/// `Location` header. Without normalization the comparison in
/// [`authorities_match`] would miss half the redirects it exists to catch.
/// An unknown scheme is left alone rather than guessed at.
fn normalize_authority(authority: &str, scheme: Option<&str>) -> String {
    if authority.contains(':') {
        return authority.to_ascii_lowercase();
    }
    let default_port = match scheme {
        Some("https") => 443,
        Some("http") => 80,
        _ => return authority.to_ascii_lowercase(),
    };
    format!("{}:{}", authority.to_ascii_lowercase(), default_port)
}

// ═══════════════════════ Transforms ═══════════════════════

/// 1. Remove headers that could be spoofed by the client.
///
/// This runs **before** [`AddProxyHeaders`], and the order is the whole point.
/// Anything the proxy is about to assert about the caller — identity, the
/// forwarded chain, the session — has to be removed first, or a client could
/// pre-set it and have the value survive into the upstream request. The strip
/// is by prefix family rather than by a fixed list of names, so a header added
/// to the trusted set in a later release cannot arrive spoofed from a client
/// running against an older build.
pub struct StripInternalHeaders;

impl RequestTransform for StripInternalHeaders {
    fn apply(&self, parts: &mut http::request::Parts, _route: &Route, ctx: &TransformContext<'_>) {
        super::header_boundary::strip_client_proxy_owned_headers(&mut parts.headers);
        strip_session_cookie(&mut parts.headers, ctx.session_cookie_name);
        // RFC 7230 §6.1: a proxy MUST NOT forward hop-by-hop
        // headers across the connection boundary. The response side
        // already does this in `proxy::handler::send_upstream`; this
        // is the symmetric request-side strip. Same set of headers,
        // same justification.
        super::header_boundary::sanitize_hop_by_hop(&mut parts.headers);
    }
}

/// Static set of hop-by-hop headers from RFC 7230 §6.1, plus the
/// `Connection`-token expansion on top.
///
/// **Static set** (always removed): Connection, Keep-Alive,
/// Proxy-Authenticate, Proxy-Authorization, TE, Trailer,
/// Transfer-Encoding, Upgrade.
///
/// **Dynamic set** (RFC 7230 §6.1 connection-options): the
/// `Connection:` header value lists header names that are scoped to
/// the current hop. A client (or upstream) sending `Connection:
/// X-Trace-Id, close` means "X-Trace-Id is hop-by-hop for this
/// connection; also signal close after this response." A proxy must
/// remove every header named in the Connection list before
/// forwarding. Without this, a malicious client can name an
/// arbitrary header (`Connection: X-Audit-Tag`) and have the proxy
/// silently drop it from the upstream view, bypassing whatever
/// upstream-side audit / WAF rules read that header.
/// Remove the Sekisho session cookie from the outbound `Cookie:` header.
///
/// The cookie has no purpose for upstream — Sekisho already validated
/// it on the inbound side — but it's the largest single contributor
/// to the per-request header budget (encrypted session id + signature
/// can run hundreds of bytes). Combined with `X-Sekisho-Jwt` and any
/// route-injected `Authorization`, an unstripped cookie pushes the
/// request past upstream nginx's default `large_client_header_buffers`
/// (8 KB) and produces a confusing "400 Request Header Or Cookie Too
/// Large" instead of the expected upstream response.
///
/// We only drop the *named* cookie — other cookies the user has for
/// the upstream domain (analytics, language pref, app-specific
/// auth) flow through untouched. If the resulting cookie list is
/// empty the header is removed entirely so we don't ship a literal
/// `Cookie:` line with no value.
pub(super) fn strip_session_cookie(headers: &mut http::HeaderMap, session_cookie_name: &str) {
    use http::header::COOKIE;
    let Some(raw) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) else {
        return;
    };
    // RFC 6265 cookie-pair separator is "; ". Tolerate a missing space
    // because some clients/proxies emit ";" only.
    let kept: Vec<String> = raw
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .filter(|p| {
            let name = p.split('=').next().unwrap_or("").trim();
            !name.eq_ignore_ascii_case(session_cookie_name)
        })
        .map(String::from)
        .collect();
    if kept.is_empty() {
        headers.remove(COOKIE);
    } else if let Ok(value) = http::HeaderValue::from_str(&kept.join("; ")) {
        headers.insert(COOKIE, value);
    }
}

/// Apply the route's regex rewrite to the canonical path. Production passes
/// the regex compiled with the published generation; the wrapper below keeps
/// direct unit tests honest without adding a second production cache.
#[cfg(test)]
pub(crate) fn apply_path_rewrite(
    request: &mut http::Request<axum::body::Body>,
    route: &Route,
    canonical_path: &str,
) -> Result<(), http::StatusCode> {
    let compiled = route
        .regex_rewrite_pattern
        .as_deref()
        .map(regex::Regex::new)
        .transpose()
        .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
    apply_path_rewrite_compiled(request, route, canonical_path, compiled.as_ref())
}

/// Apply a route's regex path rewrite, using a regex compiled once per route
/// generation rather than per request.
///
/// Three properties worth knowing:
///
/// - The `compiled` regex is checked against the route's current pattern
///   before use, and a mismatch is a 503 rather than a fallback to compiling
///   here. Rewriting with a stale pattern would send the request somewhere the
///   current configuration does not describe, which is worse than refusing.
/// - Only the matched span is replaced; the text either side of it is copied
///   through verbatim. A pattern anchored mid-path therefore behaves the way
///   an operator expects instead of truncating the rest.
/// - The substitution is decoded via
///   [`crate::request_target::decode_rewrite_template`] *before* capture
///   expansion, and the result is re-validated and re-encoded afterwards. That
///   ordering is what stops a percent-encoded `$` in the template from being
///   read as capture syntax, and stops a rewrite from producing a path that
///   would not have survived inbound canonicalization.
pub(crate) fn apply_path_rewrite_compiled(
    request: &mut http::Request<axum::body::Body>,
    route: &Route,
    canonical_path: &str,
    compiled: Option<&regex::Regex>,
) -> Result<(), http::StatusCode> {
    let (Some(pattern), Some(substitution)) = (
        route.regex_rewrite_pattern.as_deref(),
        route.regex_rewrite_substitution.as_deref(),
    ) else {
        return Ok(());
    };
    let regex = compiled
        .filter(|_| route.regex_rewrite_pattern.as_deref() == Some(pattern))
        .ok_or(http::StatusCode::SERVICE_UNAVAILABLE)?;
    let Some(captures) = regex.captures(canonical_path) else {
        return Ok(());
    };
    let matched = captures
        .get(0)
        .ok_or(http::StatusCode::SERVICE_UNAVAILABLE)?;
    let template = crate::request_target::decode_rewrite_template(substitution)
        .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
    let mut rewritten = String::with_capacity(canonical_path.len() + template.len());
    rewritten.push_str(&canonical_path[..matched.start()]);
    captures.expand(&template, &mut rewritten);
    rewritten.push_str(&canonical_path[matched.end()..]);
    crate::request_target::validate_canonical_path(&rewritten)
        .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
    let rewritten = crate::request_target::encode_canonical_path(&rewritten)
        .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
    let path_and_query = match request.uri().query() {
        Some(query) => format!("{rewritten}?{query}"),
        None => rewritten,
    };
    *request.uri_mut() = path_and_query
        .parse::<Uri>()
        .map_err(|_| http::StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(())
}

/// 3. Rewrite the Host header sent to the upstream.
///
/// Facts about how this transform sees `parts.uri`:
///
/// * On the regular HTTP path, `forward_request` assigns
///   `parts.uri = build_upstream_uri(...)` (an upstream URI with
///   authority) before running the transform pipeline.
/// * A configured path rewrite is applied before the upstream URI is built,
///   so this transform still sees the upstream authority.
/// * The WebSocket path in `handle_websocket` invokes a hand-picked
///   subset of transforms and does not run `RewriteHost`.
pub struct RewriteHost;

impl RequestTransform for RewriteHost {
    fn apply(&self, parts: &mut http::request::Parts, route: &Route, _ctx: &TransformContext<'_>) {
        if let Some(ref rewrite) = route.host_rewrite {
            if let Ok(hv) = header::HeaderValue::from_str(rewrite) {
                parts.headers.insert(header::HOST, hv);
            }
        } else if !route.preserve_host_header {
            // Rewrite Host to the upstream's hostname
            if let Some(host) = parts.uri.host()
                && let Ok(hv) = header::HeaderValue::from_str(host)
            {
                parts.headers.insert(header::HOST, hv);
            }
        }
    }
}

/// 4. Add standard proxy headers.
///
/// Emits both shapes for maximum upstream compatibility:
///
/// - **`X-Forwarded-*`** (de-facto, every reverse proxy ever): the
///   per-component triplet `X-Forwarded-Host` / `X-Forwarded-Proto`
///   / `X-Forwarded-For`. Most legacy backends only know these.
/// - **`Forwarded:`** (RFC 7239, standardised parameterised form):
///   `for=<ip>;host=<host>;proto=<scheme>;by=sekisho`. Modern
///   middleware (caddy, traefik, NIST-tracked code) prefers this
///   single header because it's unambiguous about pairing — an
///   `XFF` chain "1.2.3.4, 5.6.7.8" can't tell you which proxy
///   between you wrote which entry, while `Forwarded` keeps each
///   hop in its own comma-separated entry with all attributes
///   together.
///
/// The two forms are complementary and cheap to emit together; the
/// few extra bytes are dominated by everything else in the request.
pub struct AddProxyHeaders;

impl RequestTransform for AddProxyHeaders {
    fn apply(&self, parts: &mut http::request::Parts, _route: &Route, ctx: &TransformContext<'_>) {
        if let Ok(v) = header::HeaderValue::from_str(ctx.client_host) {
            parts.headers.insert("x-forwarded-host", v);
        }
        let proto = if ctx.tls_enabled { "https" } else { "http" };
        parts
            .headers
            .insert("x-forwarded-proto", header::HeaderValue::from_static(proto));
        if let Some(ip) = ctx.client_ip
            && let Ok(v) = header::HeaderValue::from_str(ip)
        {
            parts.headers.insert("x-forwarded-for", v);
        }

        // RFC 7239: build a single Forwarded entry for this hop and
        // append it to whatever earlier proxies wrote. Each entry's
        // parameters use the spec's `name=value` syntax with `;` as
        // the intra-entry separator and `,` as the inter-entry
        // separator. Quote `host` because it can contain ":<port>",
        // which the grammar requires to be quoted-string.
        let mut entry_parts: Vec<String> = Vec::with_capacity(4);
        if let Some(ip) = ctx.client_ip {
            // RFC 7239 §6: IPv6 needs brackets and the whole value
            // quoted; IPv4 / "unknown" can stay bare.
            let token = if ip.contains(':') && !ip.starts_with('"') {
                format!("for=\"[{ip}]\"")
            } else {
                format!("for={ip}")
            };
            entry_parts.push(token);
        }
        if !ctx.client_host.is_empty() {
            entry_parts.push(format!("host=\"{}\"", ctx.client_host.replace('"', "")));
        }
        entry_parts.push(format!("proto={proto}"));
        entry_parts.push("by=sekisho".to_string());
        let new_entry = entry_parts.join(";");
        let combined = match parts.headers.get("forwarded").and_then(|v| v.to_str().ok()) {
            Some(existing) if !existing.trim().is_empty() => {
                format!("{existing}, {new_entry}")
            }
            _ => new_entry,
        };
        if let Ok(v) = header::HeaderValue::from_str(&combined) {
            parts.headers.insert("forwarded", v);
        }
    }
}

/// 5. Add user identity headers from the session.
///
/// Gated by `route.enable_signed_identity` — same flag as the signed
/// JWT below. If the route doesn't opt in, no `X-Sekisho-User` /
/// `X-Sekisho-Groups` go upstream. The flag therefore means "this
/// route receives Sekisho-injected identity (plain headers + signed
/// JWT)" rather than the narrower "signs a JWT". An upstream that
/// only needs the unsigned hint can still consume the headers; one
/// that wants tamper-evident proof verifies the JWT.
pub struct AddIdentityHeaders;

impl RequestTransform for AddIdentityHeaders {
    fn apply(&self, parts: &mut http::request::Parts, route: &Route, ctx: &TransformContext<'_>) {
        // Gate the plain identity headers behind the same opt-in flag
        // that controls the signed JWT (`enable_signed_identity`). A
        // route either trusts Sekisho to be its identity front (and
        // wants all three headers) or it doesn't — and if it doesn't,
        // the headers are pure bloat. With Entra-style groups that
        // arrive as object IDs, `X-Sekisho-Groups` for a user in 25–50
        // groups runs ~1–2 KB; combined with the user's other
        // cookies and a route-injected `Authorization: Basic ...`,
        // the request can blow past upstream nginx's default
        // `large_client_header_buffers` (8 KB) and surface as
        // "400 Request Header Or Cookie Too Large".
        if !route.enable_signed_identity {
            return;
        }
        if let Some(session) = ctx.session {
            if let Ok(v) = header::HeaderValue::from_str(&session.user_id) {
                parts.headers.insert("x-sekisho-user", v);
            }
            if let Ok(v) = header::HeaderValue::from_str(&session.groups.join(",")) {
                parts.headers.insert("x-sekisho-groups", v);
            }
        }
    }
}

/// 6. Apply route-configured header add/remove modifications.
pub struct ApplyRouteHeaders;

impl RequestTransform for ApplyRouteHeaders {
    fn apply(&self, parts: &mut http::request::Parts, route: &Route, _ctx: &TransformContext<'_>) {
        for (key, value) in &route.headers.add {
            if super::header_boundary::is_reserved_route_header(key) {
                continue;
            }
            if let (Ok(k), Ok(v)) = (
                header::HeaderName::from_bytes(key.as_bytes()),
                header::HeaderValue::from_str(value),
            ) {
                parts.headers.insert(k, v);
            }
        }
        for key in &route.headers.remove {
            if super::header_boundary::is_reserved_route_header(key) {
                continue;
            }
            if let Ok(k) = header::HeaderName::from_bytes(key.as_bytes()) {
                parts.headers.remove(k);
            }
        }
    }
}

/// 7. Add a signed JWT identity assertion for the upstream.
///
/// When `route.enable_signed_identity` is true, mints a short-lived JWT
/// containing the authenticated user's identity and signs it with the
/// current Ed25519 key. The public key is available through JWKS.
pub struct AddSignedIdentityToken;

impl RequestTransform for AddSignedIdentityToken {
    fn apply(&self, parts: &mut http::request::Parts, route: &Route, ctx: &TransformContext<'_>) {
        if !route.enable_signed_identity {
            return;
        }
        let Some(claims) = ctx.prepared_identity_claims else {
            return;
        };

        match ctx.identity_key_ring.sign(claims) {
            Ok(token) => {
                if let Ok(v) = header::HeaderValue::from_str(&token) {
                    parts.headers.insert("x-sekisho-jwt", v);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to sign identity JWT");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::route::Route;

    fn parts_with_header(name: &str, value: &str) -> http::request::Parts {
        let req: http::Request<()> = http::Request::builder()
            .uri("/")
            .header(name, value)
            .body(())
            .unwrap();
        req.into_parts().0
    }

    fn dummy_route() -> Route {
        serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::nil(),
            "name": "r",
            "from": "https://x.example",
            "to": ["http://b:80"],
            "created_at": chrono::Utc::now(),
            "updated_at": chrono::Utc::now(),
        }))
        .unwrap()
    }

    fn ctx<'a>() -> TransformContext<'a> {
        static IDENTITY_KEY_RING: std::sync::LazyLock<std::sync::Arc<IdentityKeyRingSnapshot>> =
            std::sync::LazyLock::new(|| IdentityKeyRingSnapshot::from_test_bytes([0u8; 32]));
        TransformContext {
            tls_enabled: true,
            client_host: "x.example",
            client_ip: None,
            session: None,
            prepared_identity_claims: None,
            identity_key_ring: IDENTITY_KEY_RING.as_ref(),
            session_cookie_name: "_sekisho_session",
        }
    }

    #[test]
    fn strip_internal_removes_x_sekisho_jwt() {
        // A client-supplied identity assertion must not reach the upstream; the
        // proxy is the only party allowed to mint this header.
        let mut parts = parts_with_header("x-sekisho-jwt", "attacker.forged.token");
        StripInternalHeaders.apply(&mut parts, &dummy_route(), &ctx());
        assert!(parts.headers.get("x-sekisho-jwt").is_none());
    }

    #[test]
    fn path_rewrite_uses_canonical_input_and_preserves_query() {
        let mut route = dummy_route();
        route.regex_rewrite_pattern = Some("^/admin/(.*)$".into());
        route.regex_rewrite_substitution = Some("/users/$1".into());
        let mut request = http::Request::builder()
            .uri("/%61dmin/alice?tab=2")
            .body(axum::body::Body::empty())
            .unwrap();

        apply_path_rewrite(&mut request, &route, "/admin/alice").unwrap();
        assert_eq!(request.uri(), "/users/alice?tab=2");

        route.regex_rewrite_pattern = Some("^/admin$".into());
        route.regex_rewrite_substitution = Some("/%61dmin".into());
        let mut encoded_replacement = http::Request::builder()
            .uri("/source?opaque=%252f")
            .body(axum::body::Body::empty())
            .unwrap();
        apply_path_rewrite(&mut encoded_replacement, &route, "/admin").unwrap();
        assert_eq!(encoded_replacement.uri(), "/admin?opaque=%252f");

        route.regex_rewrite_pattern = Some("^/(.*)$".into());
        route.regex_rewrite_substitution = Some("/$1".into());
        for (raw, canonical, expected) in [
            ("/100%25?opaque=%252f", "/100%", "/100%25?opaque=%252f"),
            ("/%E2%98%83", "/☃", "/%E2%98%83"),
            ("/a%20b", "/a b", "/a%20b"),
        ] {
            let mut identity = http::Request::builder()
                .uri(raw)
                .body(axum::body::Body::empty())
                .unwrap();
            apply_path_rewrite(&mut identity, &route, canonical).unwrap();
            assert_eq!(identity.uri(), expected);
        }
    }

    #[test]
    fn absent_rewrite_preserves_raw_path_and_invalid_output_fails_closed() {
        let route = dummy_route();
        let mut request = http::Request::builder()
            .uri("/%61dmin?raw=1")
            .body(axum::body::Body::empty())
            .unwrap();
        apply_path_rewrite(&mut request, &route, "/admin").unwrap();
        assert_eq!(request.uri(), "/%61dmin?raw=1");

        let mut no_match = route.clone();
        no_match.regex_rewrite_pattern = Some("^/other$".into());
        no_match.regex_rewrite_substitution = Some("/changed".into());
        apply_path_rewrite(&mut request, &no_match, "/admin").unwrap();
        assert_eq!(request.uri(), "/%61dmin?raw=1");

        let mut invalid = route;
        invalid.regex_rewrite_pattern = Some("^/admin$".into());
        invalid.regex_rewrite_substitution = Some("/unsafe//path".into());
        assert_eq!(
            apply_path_rewrite(&mut request, &invalid, "/admin"),
            Err(http::StatusCode::SERVICE_UNAVAILABLE)
        );

        for replacement in [
            "/unsafe?part",
            "/unsafe#part",
            "/unsafe%3fpart",
            "/unsafe%23part",
        ] {
            let mut invalid_delimiter = dummy_route();
            invalid_delimiter.regex_rewrite_pattern = Some("^/admin$".into());
            invalid_delimiter.regex_rewrite_substitution = Some(replacement.into());
            assert_eq!(
                apply_path_rewrite(&mut request, &invalid_delimiter, "/admin"),
                Err(http::StatusCode::SERVICE_UNAVAILABLE),
                "accepted rewrite delimiter {replacement}"
            );
        }
    }

    #[test]
    fn ws_safe_strip_removes_identity_and_forwarded_but_keeps_upgrade() {
        // WebSocket upgrade path: same identity / forwarded strip as
        // the non-WS path, but `Connection: upgrade` and
        // `Upgrade: websocket` must survive — without them the
        // upstream sees a plain HTTP/1 request and returns 400.
        let req: http::Request<()> = http::Request::builder()
            .uri("/")
            .header("x-sekisho-jwt", "attacker.forged.token")
            .header("x-sekisho-user", "attacker@example")
            .header("x-sekisho-groups", "admins")
            .header("x-forwarded-for", "203.0.113.1")
            .header("x-forwarded-host", "evil.example")
            .header("x-forwarded-proto", "https")
            .header("forwarded", "for=203.0.113.1;host=evil.example")
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        super::super::header_boundary::strip_client_proxy_owned_headers(&mut parts.headers);
        strip_session_cookie(&mut parts.headers, "_sekisho_session");

        // Identity / forwarded headers must be gone.
        assert!(parts.headers.get("x-sekisho-jwt").is_none());
        assert!(parts.headers.get("x-sekisho-user").is_none());
        assert!(parts.headers.get("x-sekisho-groups").is_none());
        assert!(parts.headers.get("x-forwarded-for").is_none());
        assert!(parts.headers.get("x-forwarded-host").is_none());
        assert!(parts.headers.get("x-forwarded-proto").is_none());
        assert!(parts.headers.get("forwarded").is_none());

        // WebSocket handshake headers must remain.
        assert_eq!(
            parts
                .headers
                .get("connection")
                .and_then(|v| v.to_str().ok()),
            Some("upgrade")
        );
        assert_eq!(
            parts.headers.get("upgrade").and_then(|v| v.to_str().ok()),
            Some("websocket")
        );
        assert!(parts.headers.get("sec-websocket-key").is_some());
        assert!(parts.headers.get("sec-websocket-version").is_some());
    }

    #[test]
    fn ws_safe_strip_drops_session_cookie_only() {
        // The Sekisho session cookie is dropped because it's useless
        // upstream and would inflate the request past upstream
        // header-buffer limits. Other cookies on the same domain
        // (analytics, language pref, app-specific auth) flow through.
        let req: http::Request<()> = http::Request::builder()
            .uri("/")
            .header("cookie", "_sekisho_session=abc123; lang=ja; analytics=xyz")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        super::super::header_boundary::strip_client_proxy_owned_headers(&mut parts.headers);
        strip_session_cookie(&mut parts.headers, "_sekisho_session");

        let cookie = parts
            .headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(!cookie.contains("_sekisho_session"));
        assert!(cookie.contains("lang=ja"));
        assert!(cookie.contains("analytics=xyz"));
    }

    #[test]
    fn route_header_application_skips_reserved_legacy_operations() {
        let mut route = dummy_route();
        route
            .headers
            .add
            .insert("Connection".into(), "X-Legacy".into());
        route.headers.add.insert("X-Custom".into(), "keep".into());
        route.headers.remove.push("Via".into());
        route.headers.remove.push("X-Remove".into());
        let mut parts = parts_with_header("via", "1.0 prior");
        parts
            .headers
            .insert("x-remove", http::HeaderValue::from_static("remove"));

        ApplyRouteHeaders.apply(&mut parts, &route, &ctx());

        assert!(parts.headers.get(http::header::CONNECTION).is_none());
        assert_eq!(parts.headers[http::header::VIA], "1.0 prior");
        assert_eq!(parts.headers["x-custom"], "keep");
        assert!(parts.headers.get("x-remove").is_none());
    }

    #[test]
    fn add_signed_identity_signs_with_eddsa_key_ring() {
        use crate::models::session::Session;
        use jsonwebtoken::{Algorithm, Validation};

        let session = Session {
            id: uuid::Uuid::nil(),
            user_id: "alice@example".into(),
            idp_id: uuid::Uuid::nil(),
            upstream_identity: None,
            claims: std::collections::HashMap::new(),
            groups: vec!["admins".into()],
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            refresh_token_encrypted: None,
            id_token_encrypted: None,
            saml_name_id: None,
            saml_session_index: None,
            last_accessed_at: chrono::Utc::now(),
        };

        let identity_key_ring = IdentityKeyRingSnapshot::from_test_bytes([0xAB; 32]);
        let master_key: [u8; 32] = [0xCD; 32]; // deliberately different
        let now = chrono::Utc::now().timestamp();
        let prepared_claims = crate::identity::SignedIdentityClaims {
            sub: "opaque-subject".into(),
            email: "alice@example.com".into(),
            groups: vec!["admins".into()],
            iss: "https://auth.example.com".into(),
            aud: "https://x.example".into(),
            iat: now,
            nbf: now,
            exp: now + 300,
        };
        let ctx = TransformContext {
            tls_enabled: true,
            client_host: "x.example",
            client_ip: None,
            session: Some(&session),
            prepared_identity_claims: Some(&prepared_claims),
            identity_key_ring: identity_key_ring.as_ref(),
            session_cookie_name: "_sekisho_session",
        };

        // A route that opts into signed identity headers.
        let route: Route = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::nil(),
            "name": "r",
            "from": "https://x.example",
            "to": ["http://b:80"],
            "enable_signed_identity": true,
            "created_at": chrono::Utc::now(),
            "updated_at": chrono::Utc::now(),
        }))
        .unwrap();

        let mut parts = parts_with_header("host", "x.example");
        AddSignedIdentityToken.apply(&mut parts, &route, &ctx);

        let token = parts
            .headers
            .get("x-sekisho-jwt")
            .expect("signed identity token should be inserted")
            .to_str()
            .unwrap()
            .to_string();

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        validation.required_spec_claims.insert("exp".into());
        identity_key_ring
            .verify::<serde_json::Value>(&token, &validation, chrono::Utc::now().timestamp())
            .expect("JWT must verify with the published Ed25519 key");

        // … and must *not* decode with the master key. If this ever
        // starts passing, AddSignedIdentityToken has silently reverted to
        // signing with master_key.
        assert!(
            jsonwebtoken::decode::<serde_json::Value>(
                &token,
                &jsonwebtoken::DecodingKey::from_secret(&master_key),
                &validation,
            )
            .is_err(),
            "JWT must not verify with master_key — it would mean the two keys are being conflated"
        );
    }

    #[test]
    fn strip_internal_removes_identity_and_forwarded_headers() {
        let mut parts = parts_with_header("x-sekisho-user", "alice@example");
        parts
            .headers
            .insert("x-sekisho-groups", "admins".parse().unwrap());
        parts
            .headers
            .insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        StripInternalHeaders.apply(&mut parts, &dummy_route(), &ctx());
        for h in [
            "x-sekisho-user",
            "x-sekisho-groups",
            "x-sekisho-jwt",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-for",
        ] {
            assert!(
                parts.headers.get(h).is_none(),
                "expected header {h} to be stripped"
            );
        }
    }

    /// The ordering invariant, stated as a test: a client that guesses a
    /// header Sekisho does not yet use (`x-sekisho-future-claim`) must not be
    /// able to smuggle it through, and a header the proxy does set
    /// (`x-forwarded-host`) must carry the proxy's value rather than the
    /// client's. `x-safe` is the control — stripping is scoped to the reserved
    /// families and leaves everything else alone.
    #[test]
    fn strip_precedes_trusted_proxy_header_injection_for_whole_prefix_families() {
        let req: http::Request<()> = http::Request::builder()
            .uri("/")
            .header("x-sekisho-future-claim", "forged")
            .header("x-forwarded-future-hop", "forged")
            .header("x-forwarded-host", "evil.example")
            .header("forwarded", "for=attacker;host=evil.example")
            .header("x-safe", "keep")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let ctx = ctx();

        StripInternalHeaders.apply(&mut parts, &dummy_route(), &ctx);
        AddProxyHeaders.apply(&mut parts, &dummy_route(), &ctx);

        assert!(parts.headers.get("x-sekisho-future-claim").is_none());
        assert!(parts.headers.get("x-forwarded-future-hop").is_none());
        assert_eq!(parts.headers["x-forwarded-host"], "x.example");
        assert_eq!(parts.headers["x-forwarded-proto"], "https");
        assert!(
            !parts.headers["forwarded"]
                .to_str()
                .unwrap()
                .contains("attacker")
        );
        assert_eq!(parts.headers["x-safe"], "keep");
    }

    #[test]
    fn strip_session_cookie_drops_only_the_named_entry() {
        // Regression: forwarding the user's `_sekisho_session` cookie
        // to upstream pushes the request past upstream nginx's default
        // `large_client_header_buffers` (8 KB) and surfaces as a
        // confusing "400 Request Header Or Cookie Too Large" instead
        // of the expected upstream response.
        let mut parts = parts_with_header(
            "cookie",
            "lang=ja; _sekisho_session=very-long-base64-encrypted-value-XXXXXXXXXX; ga=GA1.1.x",
        );
        StripInternalHeaders.apply(&mut parts, &dummy_route(), &ctx());
        let remaining = parts
            .headers
            .get("cookie")
            .expect("other cookies must survive")
            .to_str()
            .unwrap();
        assert!(
            !remaining.contains("_sekisho_session"),
            "session cookie must be stripped: {remaining}"
        );
        assert!(remaining.contains("lang=ja"));
        assert!(remaining.contains("ga="));
    }

    #[test]
    fn strip_session_cookie_removes_header_when_only_entry() {
        // If the user only had the session cookie, drop the whole
        // header — don't ship a literal `Cookie:` line with no value.
        let mut parts = parts_with_header("cookie", "_sekisho_session=blob");
        StripInternalHeaders.apply(&mut parts, &dummy_route(), &ctx());
        assert!(parts.headers.get("cookie").is_none());
    }

    #[test]
    fn strip_session_cookie_handles_missing_cookie_header() {
        let mut parts = parts_with_header("x-sekisho-user", "alice");
        // No Cookie header — must not panic.
        StripInternalHeaders.apply(&mut parts, &dummy_route(), &ctx());
        assert!(parts.headers.get("cookie").is_none());
    }

    fn session_with_groups(groups: Vec<&str>) -> Session {
        Session {
            id: uuid::Uuid::nil(),
            user_id: "alice@example.com".into(),
            idp_id: uuid::Uuid::nil(),
            upstream_identity: None,
            claims: Default::default(),
            groups: groups.into_iter().map(String::from).collect(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            refresh_token_encrypted: None,
            id_token_encrypted: None,
            saml_name_id: None,
            saml_session_index: None,
            last_accessed_at: chrono::Utc::now(),
        }
    }

    fn ctx_with_session<'a>(session: &'a Session) -> TransformContext<'a> {
        static IDENTITY_KEY_RING: std::sync::LazyLock<std::sync::Arc<IdentityKeyRingSnapshot>> =
            std::sync::LazyLock::new(|| IdentityKeyRingSnapshot::from_test_bytes([0u8; 32]));
        TransformContext {
            tls_enabled: true,
            client_host: "x.example",
            client_ip: None,
            session: Some(session),
            prepared_identity_claims: None,
            identity_key_ring: IDENTITY_KEY_RING.as_ref(),
            session_cookie_name: "_sekisho_session",
        }
    }

    #[test]
    fn add_identity_headers_skipped_when_route_did_not_opt_in() {
        // Default route (enable_signed_identity = false). The plain
        // identity headers must NOT go to upstream — they're pure
        // bloat for an upstream that ignores them, and risk pushing
        // the request past nginx's header buffers.
        let session = session_with_groups(vec!["g1", "g2"]);
        let mut parts = parts_with_header("x-test", "ignore");
        AddIdentityHeaders.apply(&mut parts, &dummy_route(), &ctx_with_session(&session));
        assert!(
            parts.headers.get("x-sekisho-user").is_none(),
            "X-Sekisho-User must be gated"
        );
        assert!(
            parts.headers.get("x-sekisho-groups").is_none(),
            "X-Sekisho-Groups must be gated"
        );
    }

    #[test]
    fn strip_hop_by_hop_removes_static_set() {
        let mut parts = parts_with_header("transfer-encoding", "chunked");
        parts.headers.insert("te", "trailers".parse().unwrap());
        parts.headers.insert("upgrade", "h2c".parse().unwrap());
        parts.headers.insert("trailer", "expires".parse().unwrap());
        parts
            .headers
            .insert("keep-alive", "timeout=5".parse().unwrap());
        parts
            .headers
            .insert("proxy-authorization", "Basic xx".parse().unwrap());
        parts.headers.insert(
            "connection",
            "keep-alive, transfer-encoding".parse().unwrap(),
        );
        StripInternalHeaders.apply(&mut parts, &dummy_route(), &ctx());
        for h in [
            "transfer-encoding",
            "te",
            "upgrade",
            "trailer",
            "keep-alive",
            "proxy-authorization",
            "connection",
        ] {
            assert!(
                parts.headers.get(h).is_none(),
                "expected hop-by-hop {h} to be stripped"
            );
        }
    }

    #[test]
    fn strip_hop_by_hop_honours_connection_token_list() {
        // RFC 7230 §6.1: the `Connection:` header value names
        // additional headers that are scoped to this hop. A client
        // that sets `Connection: X-Audit-Tag` is asking the proxy to
        // delete `X-Audit-Tag` before forwarding. If we ignored this,
        // a malicious caller could silently strip a header the
        // upstream WAF / audit layer was supposed to read.
        let mut parts = parts_with_header("x-audit-tag", "should-be-dropped");
        parts.headers.insert("x-keep-me", "alive".parse().unwrap());
        parts
            .headers
            .insert("connection", "close, X-Audit-Tag".parse().unwrap());
        StripInternalHeaders.apply(&mut parts, &dummy_route(), &ctx());
        assert!(
            parts.headers.get("x-audit-tag").is_none(),
            "header named in Connection list must be stripped"
        );
        assert_eq!(
            parts.headers.get("x-keep-me").unwrap(),
            "alive",
            "non-listed headers must survive"
        );
        assert!(parts.headers.get("connection").is_none());
    }

    #[test]
    fn add_proxy_headers_emits_rfc7239_forwarded() {
        let mut parts = parts_with_header("x-test", "ignore");
        let session = session_with_groups(vec![]);
        let mut ctx_v4 = ctx_with_session(&session);
        let ip = "203.0.113.7".to_string();
        ctx_v4.client_ip = Some(&ip);
        ctx_v4.client_host = "app.example.com";
        AddProxyHeaders.apply(&mut parts, &dummy_route(), &ctx_v4);
        let fwd = parts
            .headers
            .get("forwarded")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        // RFC 7239 §4 grammar: name=value pairs separated by `;`.
        assert!(fwd.contains("for=203.0.113.7"), "{fwd}");
        assert!(fwd.contains("host=\"app.example.com\""), "{fwd}");
        assert!(fwd.contains("proto=https"), "{fwd}");
        assert!(fwd.contains("by=sekisho"), "{fwd}");
        // X-Forwarded-* must still be emitted alongside for legacy
        // backends — Forwarded augments, doesn't replace.
        assert_eq!(parts.headers.get("x-forwarded-for").unwrap(), "203.0.113.7");
        assert_eq!(parts.headers.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(
            parts.headers.get("x-forwarded-host").unwrap(),
            "app.example.com"
        );
    }

    #[test]
    fn add_proxy_headers_brackets_ipv6() {
        // RFC 7239 §6: IPv6 addresses in `for` must appear bracketed
        // and quoted, e.g. `for="[2001:db8::1]"`. Bare IPv6 would
        // collide with the `;` parameter separator semantics.
        let mut parts = parts_with_header("x-test", "ignore");
        let session = session_with_groups(vec![]);
        let mut ctx_v6 = ctx_with_session(&session);
        let ip = "2001:db8::1".to_string();
        ctx_v6.client_ip = Some(&ip);
        AddProxyHeaders.apply(&mut parts, &dummy_route(), &ctx_v6);
        let fwd = parts
            .headers
            .get("forwarded")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(fwd.contains("for=\"[2001:db8::1]\""), "{fwd}");
    }

    #[test]
    fn strip_internal_drops_client_supplied_forwarded() {
        // Same threat as X-Forwarded-*: a client that pre-fills
        // Forwarded could fake the apparent origin to the upstream.
        let mut parts = parts_with_header("forwarded", "for=1.2.3.4;by=evil-proxy");
        StripInternalHeaders.apply(&mut parts, &dummy_route(), &ctx());
        assert!(parts.headers.get("forwarded").is_none());
    }

    #[test]
    fn add_via_appends_to_existing_chain() {
        // RFC 7230 §5.7.1: each proxy in the chain appends its own
        // pseudonym to whatever the prior hops wrote. A downstream
        // operator reading `Via:` should see the order requests
        // traversed (first proxy → ... → second).
        let mut parts = parts_with_header("via", "1.1 edge-lb");
        AddViaHeader.apply(&mut parts, &dummy_route(), &ctx());
        let values: Vec<_> = parts
            .headers
            .get_all(http::header::VIA)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(values, ["1.1 edge-lb", "1.1 sekisho"]);
    }

    #[test]
    fn add_via_creates_header_when_absent() {
        let mut parts = parts_with_header("x-test", "ignore");
        AddViaHeader.apply(&mut parts, &dummy_route(), &ctx());
        let v = parts
            .headers
            .get(http::header::VIA)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(v, "1.1 sekisho");
    }

    #[test]
    fn append_via_to_response_matches_request_side_format() {
        // The two paths (request transform + response helper) MUST
        // emit the same syntactically valid package-version-free token while
        // preserving each hop's received protocol version.
        let mut req_parts = parts_with_header("x-test", "ignore");
        AddViaHeader.apply(&mut req_parts, &dummy_route(), &ctx());
        let req_via = req_parts.headers.get(http::header::VIA).unwrap().clone();

        let mut resp_headers = http::HeaderMap::new();
        append_via_to_response(&mut resp_headers, http::Version::HTTP_11);
        let resp_via = resp_headers.get(http::header::VIA).unwrap().clone();

        assert_eq!(req_via, resp_via);
    }

    #[test]
    fn via_uses_received_h2_version_for_request_and_response() {
        let mut parts = parts_with_header("x-test", "ignore");
        parts.version = http::Version::HTTP_2;
        AddViaHeader.apply(&mut parts, &dummy_route(), &ctx());
        assert_eq!(parts.headers[http::header::VIA], "2 sekisho");

        let mut response = http::HeaderMap::new();
        append_via_to_response(&mut response, http::Version::HTTP_2);
        assert_eq!(response[http::header::VIA], "2 sekisho");
    }

    #[test]
    fn add_identity_headers_emitted_when_route_opted_in() {
        let session = session_with_groups(vec!["admins", "ops"]);
        let mut route = dummy_route();
        route.enable_signed_identity = true;
        let mut parts = parts_with_header("x-test", "ignore");
        AddIdentityHeaders.apply(&mut parts, &route, &ctx_with_session(&session));
        assert_eq!(
            parts.headers.get("x-sekisho-user").unwrap(),
            "alice@example.com"
        );
        assert_eq!(parts.headers.get("x-sekisho-groups").unwrap(), "admins,ops");
    }

    fn route_with_upstreams(upstreams: Vec<&str>) -> Route {
        let mut r = dummy_route();
        r.to = upstreams.into_iter().map(String::from).collect();
        r
    }

    fn headers_with_location(loc: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::LOCATION,
            http::HeaderValue::from_str(loc).unwrap(),
        );
        h
    }

    #[test]
    fn rewrite_location_replaces_upstream_ip_with_public_host() {
        // Appliance returns Location with its private IP, browser
        // would otherwise jump straight to the IP and bypass the IAP.
        // Public-host substitution keeps every subsequent request on
        // the proxy.
        let route = route_with_upstreams(vec!["https://192.0.2.16"]);
        let mut headers = headers_with_location("https://192.0.2.16/ruletable");
        rewrite_response_location(&mut headers, &route, "appliance.example.com");
        assert_eq!(
            headers.get(http::header::LOCATION).unwrap(),
            "https://appliance.example.com/ruletable"
        );
    }

    #[test]
    fn rewrite_location_normalizes_default_port() {
        // route.to omits the port; appliance Location includes it. The
        // pre-default-port match would fail without normalization, leaving
        // the IP in the response.
        let route = route_with_upstreams(vec!["https://192.0.2.16"]);
        let mut headers = headers_with_location("https://192.0.2.16:443/x?y=z");
        rewrite_response_location(&mut headers, &route, "appliance01.example");
        assert_eq!(
            headers.get(http::header::LOCATION).unwrap(),
            "https://appliance01.example/x?y=z"
        );
    }

    #[test]
    fn rewrite_location_leaves_external_authority_untouched() {
        // Federated-SSO redirect (e.g. login.microsoftonline.com): not
        // ours to rewrite. Touching it would break the OIDC flow.
        let route = route_with_upstreams(vec!["https://192.0.2.16"]);
        let mut headers =
            headers_with_location("https://login.microsoftonline.com/oauth2/authorize?x=1");
        rewrite_response_location(&mut headers, &route, "appliance01.example");
        assert_eq!(
            headers.get(http::header::LOCATION).unwrap(),
            "https://login.microsoftonline.com/oauth2/authorize?x=1"
        );
    }

    #[test]
    fn rewrite_location_leaves_relative_path_untouched() {
        // A relative Location is already proxy-correct — the browser
        // resolves it against the current public URL.
        let route = route_with_upstreams(vec!["https://192.0.2.16"]);
        let mut headers = headers_with_location("/ruletable");
        rewrite_response_location(&mut headers, &route, "appliance01.example");
        assert_eq!(headers.get(http::header::LOCATION).unwrap(), "/ruletable");
    }

    #[test]
    fn rewrite_location_skips_when_route_opted_out() {
        // Operators with a federated-SSO upstream that intentionally
        // bounces the browser to a sibling internal hostname can disable
        // the rewrite per route.
        let mut route = route_with_upstreams(vec!["https://192.0.2.16"]);
        route.response_location_rewrite = false;
        let mut headers = headers_with_location("https://192.0.2.16/ruletable");
        rewrite_response_location(&mut headers, &route, "appliance01.example");
        assert_eq!(
            headers.get(http::header::LOCATION).unwrap(),
            "https://192.0.2.16/ruletable"
        );
    }

    #[test]
    fn rewrite_location_matches_any_upstream_in_load_balanced_route() {
        // Round-robin / random LB across multiple upstreams: any one of
        // them might be the source of the redirect for this request.
        let route = route_with_upstreams(vec!["https://10.0.0.1", "https://10.0.0.2"]);
        let mut headers = headers_with_location("https://10.0.0.2/login");
        rewrite_response_location(&mut headers, &route, "app.example");
        assert_eq!(
            headers.get(http::header::LOCATION).unwrap(),
            "https://app.example/login"
        );
    }

    #[test]
    fn rewrite_location_no_op_when_header_absent() {
        let route = route_with_upstreams(vec!["https://192.0.2.16"]);
        let mut headers = http::HeaderMap::new();
        rewrite_response_location(&mut headers, &route, "appliance01.example");
        assert!(headers.get(http::header::LOCATION).is_none());
    }
}
