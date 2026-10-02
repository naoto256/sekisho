//! Issuer/audience rules for signed identity assertions.
//!
//! Routes that opt into `enable_signed_identity` receive a short-lived JWT
//! signed with the daemon's Ed25519 identity key, so an upstream can trust
//! the caller without trusting the proxy-injected plaintext headers next to
//! it. Minting and key rotation live in [`crate::store::identity_signing`]
//! and the transform that attaches the token lives in
//! [`crate::proxy::transform`]; this module owns the part that has to be
//! exact — what goes into `iss` and `aud`.
//!
//! ## Why origins are canonicalized, and why the two sides differ
//!
//! An upstream compares `aud` byte-for-byte, so a route may declare its
//! audience in exactly one spelling. [`CanonicalOrigin::from_route`] parses
//! `route.from`, re-serializes it as an ASCII origin, and rejects the route
//! unless the result is identical to what the operator wrote. That single
//! round-trip check rules out the whole family of near-misses at once —
//! `https://APP.example.com`, a trailing `/`, an explicit `:443`, userinfo,
//! a query, a fragment — instead of enumerating them one by one.
//!
//! `iss` comes from `auth_domain`, which is operator config rather than
//! anything a request can influence, so [`CanonicalOrigin::from_auth_domain`]
//! normalizes rather than rejects: `AUTH.example.com:443` becomes
//! `https://auth.example.com`. That tolerance is also what makes
//! [`CanonicalOrigin::matches_host`] usable against a parsed inbound `Host`
//! value, which may legitimately carry a different case or a default port.
//!
//! ## Fail closed at boot
//!
//! [`IdentityAuthority::from_boot`] validates every route and refuses to
//! start if any signed-identity route exists without an `auth_domain`. A
//! daemon that cannot name its own issuer must not fall back to serving
//! those routes unsigned.

use crate::models::config::GlobalConfig;
use crate::models::route::{Route, SignedIdentityRouteInput};
use crate::models::session::UpstreamIdentity;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Lifetime of a minted assertion.
///
/// Short on purpose: the token is re-minted per request from live session
/// state, so there is no revocation story to build — a replayed token stops
/// being useful within minutes.
const TOKEN_LIFETIME: Duration = Duration::minutes(5);

/// Operator-facing wording for [`IdentityError::InvalidSignedRoute`], shared
/// with [`crate::validation`] so the admission API and this module cannot
/// drift apart.
pub(crate) const INVALID_SIGNED_ROUTE: &str =
    "signed identity requires a canonical HTTPS origin and a non-redirect route";
/// Operator-facing wording for [`IdentityError::InvalidAuthDomain`].
pub(crate) const INVALID_AUTH_DOMAIN: &str = "auth_domain must be a valid host or host:port";

/// A canonical, typed host component from an HTTP authority.
///
/// Parsing validates the complete authority, including its optional port,
/// while keeping the host separate so callers can deliberately choose
/// whether a port participates in their policy. The returned port follows
/// HTTPS origin rules: an explicit `:443` is normalized to no port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CanonicalHost {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl CanonicalHost {
    pub(crate) fn from_authority(value: &str) -> Option<(Self, Option<u16>)> {
        if value.is_empty() || value.contains('@') {
            return None;
        }
        let authority = value.parse::<axum::http::uri::Authority>().ok()?;
        let host = authority.host();
        let suffix = authority.as_str().strip_prefix(host)?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(authority.port_u16()?)
        }
        .filter(|port| *port != 443);
        let host = match url::Host::parse(host).ok()? {
            url::Host::Domain(host) => Self::Domain(host),
            url::Host::Ipv4(host) => Self::Ipv4(host),
            url::Host::Ipv6(host) => Self::Ipv6(host),
        };
        Some((host, port))
    }

    pub(crate) fn to_authority_host(&self) -> String {
        match self {
            Self::Domain(host) => host.clone(),
            Self::Ipv4(host) => host.to_string(),
            Self::Ipv6(host) => format!("[{host}]"),
        }
    }
}

/// An `https://host[:port]` origin in its one canonical spelling.
///
/// Constructing this type is the validation: once you hold one, `value` is
/// safe to emit as a JWT `iss`/`aud` and `authority` is safe to compare
/// against a `Host` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalOrigin {
    value: String,
    authority: String,
    host: CanonicalHost,
    port: Option<u16>,
}

impl CanonicalOrigin {
    /// Normalize an operator-supplied `host` or `host:port` into an origin.
    ///
    /// The `https://` prefix is implied — `auth_domain` is always HTTPS —
    /// and the explicit field checks reject anything that smuggled a path,
    /// query, fragment or userinfo past the URL parser.
    fn from_auth_domain(value: &str) -> Result<Self, IdentityError> {
        if value.is_empty() {
            return Err(IdentityError::InvalidAuthDomain);
        }
        let parsed = url::Url::parse(&format!("https://{value}"))
            .map_err(|_| IdentityError::InvalidAuthDomain)?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.host().is_none()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(IdentityError::InvalidAuthDomain);
        }
        Self::from_url(parsed).ok_or(IdentityError::InvalidAuthDomain)
    }

    /// Accept a `route.from` value only if it is *already* written as a
    /// canonical origin.
    ///
    /// Same structural checks as [`Self::from_auth_domain`], plus the
    /// round-trip equality test that makes the audience unambiguous: if
    /// re-serializing changed anything, the operator wrote a second spelling
    /// of some origin and we refuse rather than silently picking one.
    fn from_route(value: &str) -> Result<Self, IdentityError> {
        let parsed = url::Url::parse(value).map_err(|_| IdentityError::InvalidSignedRoute)?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.host().is_none()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(IdentityError::InvalidSignedRoute);
        }
        let origin = Self::from_url(parsed).ok_or(IdentityError::InvalidSignedRoute)?;
        if value != origin.value {
            return Err(IdentityError::InvalidSignedRoute);
        }
        Ok(origin)
    }

    /// Split an already-checked URL into its serialized origin and bare
    /// authority. Returns `None` for origins the URL crate serializes as
    /// opaque (`"null"`), which have no `https://` prefix to strip.
    fn from_url(parsed: url::Url) -> Option<Self> {
        let value = parsed.origin().ascii_serialization();
        let authority = value.strip_prefix("https://")?.to_string();
        let (host, port) = CanonicalHost::from_authority(&authority)?;
        Some(Self {
            value,
            authority,
            host,
            port,
        })
    }

    /// The full origin, e.g. `https://app.example.com` — the JWT claim form.
    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    /// The origin without its scheme, e.g. `app.example.com` — the `Host`
    /// header form.
    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }

    /// Build an absolute URL under this origin. `path` must already start
    /// with `/`; the origin never carries one.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.value)
    }

    /// Whether a parsed inbound host and port name this origin.
    pub(crate) fn matches_host(&self, host: &CanonicalHost, port: Option<u16>) -> bool {
        &self.host == host && self.port == port
    }

    /// Whether an inbound `Host` header names this origin.
    pub(crate) fn matches_host_header(&self, value: &str) -> bool {
        CanonicalHost::from_authority(value)
            .is_some_and(|(host, port)| self.matches_host(&host, port))
    }
}

impl fmt::Display for CanonicalOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

/// The process-wide issuer identity, resolved once at startup.
///
/// `issuer` is `None` when no `auth_domain` is configured. That is legal for
/// a deployment with no signed-identity routes, and rejected at boot for any
/// deployment that has one.
#[derive(Debug, Clone)]
pub(crate) struct IdentityAuthority {
    issuer: Option<CanonicalOrigin>,
}

impl IdentityAuthority {
    /// Resolve the issuer and check every route against the signed-identity
    /// rules before any listener binds.
    ///
    /// Routes that have not opted in are not required to have a URL-shaped
    /// `from`, so pre-existing hostname-style routes keep loading.
    pub(crate) fn from_boot(
        config: &GlobalConfig,
        routes: &[Route],
    ) -> Result<Self, IdentityError> {
        let issuer = config
            .auth_domain
            .as_deref()
            .map(CanonicalOrigin::from_auth_domain)
            .transpose()?;
        for route in routes {
            validate_route(route.signed_identity_input())?;
        }
        if routes.iter().any(|route| route.enable_signed_identity) && issuer.is_none() {
            return Err(IdentityError::MissingAuthDomain);
        }
        Ok(Self { issuer })
    }

    /// Admission-time check for a candidate `auth_domain`, so the management
    /// API rejects a value that would only fail at the next boot.
    pub(crate) fn validate_auth_domain(value: &str) -> Result<(), IdentityError> {
        CanonicalOrigin::from_auth_domain(value).map(|_| ())
    }

    /// The configured issuer origin, or [`IdentityError::MissingAuthDomain`].
    pub(crate) fn auth_origin(&self) -> Result<&CanonicalOrigin, IdentityError> {
        self.issuer.as_ref().ok_or(IdentityError::MissingAuthDomain)
    }

    /// Build the claim set for one request.
    ///
    /// `now` is injected rather than read here so the caller pins a single
    /// instant across `iat`/`nbf`/`exp` and tests stay deterministic.
    ///
    /// Two deliberate strictnesses:
    ///
    /// - The subject's email must be one the IdP stated explicitly
    ///   ([`IdentityError::MissingExplicitEmail`]). An opaque `sub` that
    ///   merely looks like an address is not promoted into `email`, because
    ///   upstreams key authorization off that claim.
    /// - `nbf` equals `iat` — no clock-skew grace. Issuer and verifier are
    ///   typically the same host pair inside one deployment, and the 5-minute
    ///   window already absorbs ordinary drift.
    pub(crate) fn prepare_claims(
        &self,
        route: SignedIdentityRouteInput<'_>,
        identity: &UpstreamIdentity,
        groups: &[String],
        now: DateTime<Utc>,
    ) -> Result<SignedIdentityClaims, IdentityError> {
        let audience = validate_route(route)?.ok_or(IdentityError::InvalidSignedRoute)?;
        let email = identity
            .explicit_email
            .as_deref()
            .ok_or(IdentityError::MissingExplicitEmail)?;
        let issuer = self.auth_origin()?;
        let iat = now.timestamp();
        Ok(SignedIdentityClaims {
            sub: identity.subject.clone(),
            email: email.to_string(),
            groups: groups.to_vec(),
            iss: issuer.as_str().to_string(),
            aud: audience.as_str().to_string(),
            iat,
            nbf: iat,
            exp: (now + TOKEN_LIFETIME).timestamp(),
        })
    }

    /// Construct an authority directly from an `auth_domain`, skipping the
    /// route sweep. Tests only — production always goes through
    /// [`Self::from_boot`].
    #[cfg(test)]
    pub(crate) fn for_test(auth_domain: &str) -> Self {
        Self {
            issuer: Some(
                CanonicalOrigin::from_auth_domain(auth_domain)
                    .expect("test auth domain must be canonicalizable"),
            ),
        }
    }
}

/// Validate one route's signed-identity configuration.
///
/// Returns the route's audience origin when the feature is on, `Ok(None)`
/// when it is off, and an error when it is on but the route cannot express a
/// well-defined audience. Redirect routes are rejected outright: they never
/// reach an upstream, so a token minted for them would only ever be a
/// credential handed to a `Location` target.
///
/// Shared by boot ([`IdentityAuthority::from_boot`]) and admission
/// ([`crate::validation`]) so a route that would break startup cannot be
/// written in the first place.
pub(crate) fn validate_route(
    route: SignedIdentityRouteInput<'_>,
) -> Result<Option<CanonicalOrigin>, IdentityError> {
    if !route.enabled {
        return Ok(None);
    }
    if route.redirect {
        return Err(IdentityError::InvalidSignedRoute);
    }
    CanonicalOrigin::from_route(route.from).map(Some)
}

/// The JWT payload handed upstream. Field names are the wire claim names,
/// so renaming one is a breaking change for every relying upstream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SignedIdentityClaims {
    pub(crate) sub: String,
    pub(crate) email: String,
    pub(crate) groups: Vec<String>,
    pub(crate) iss: String,
    pub(crate) aud: String,
    pub(crate) iat: i64,
    pub(crate) nbf: i64,
    pub(crate) exp: i64,
}

/// Why an identity assertion could not be configured or minted.
///
/// Deliberately coarse: the `Display` strings reach operators through the
/// management API, and the proxy maps the variants to status codes without
/// echoing request-derived detail back to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityError {
    InvalidAuthDomain,
    MissingAuthDomain,
    InvalidSignedRoute,
    MissingExplicitEmail,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidAuthDomain => INVALID_AUTH_DOMAIN,
            Self::MissingAuthDomain => "auth_domain is required for signed identity",
            Self::InvalidSignedRoute => INVALID_SIGNED_ROUTE,
            Self::MissingExplicitEmail => "explicit upstream email is required",
        })
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::route::{Route, RouteAccess};
    use crate::models::session::UpstreamIdentityProvenance;

    #[test]
    fn canonical_host_parser_validates_ports_and_normalizes_host_identity() {
        let (dns, port) = CanonicalHost::from_authority("APP.Example:443").unwrap();
        assert_eq!(dns.to_authority_host(), "app.example");
        assert_eq!(port, None);
        let origin = CanonicalOrigin::from_auth_domain("AUTH.Example:443").unwrap();
        let (same_host, same_port) = CanonicalHost::from_authority("auth.example").unwrap();
        assert!(origin.matches_host(&same_host, same_port));
        let (wrong_port_host, wrong_port) =
            CanonicalHost::from_authority("auth.example:80").unwrap();
        assert!(!origin.matches_host(&wrong_port_host, wrong_port));

        let (ipv4, port) = CanonicalHost::from_authority("127.1:8080").unwrap();
        assert_eq!(ipv4.to_authority_host(), "127.0.0.1");
        assert_eq!(port, Some(8080));

        let (ipv6, port) = CanonicalHost::from_authority("[2001:0db8:0:0:0:0:0:1]:80").unwrap();
        assert_eq!(ipv6.to_authority_host(), "[2001:db8::1]");
        assert_eq!(port, Some(80));

        for malformed in [
            "",
            " user@example.com",
            "user@example.com",
            "https://app.example.com",
            "app.example.com/path",
            "2001:db8::1",
            "app.example.com:",
            "app.example.com:not-a-port",
            "app.example.com:65536",
        ] {
            assert!(
                CanonicalHost::from_authority(malformed).is_none(),
                "authority {malformed:?} must fail closed"
            );
        }
    }

    fn route(from: &str) -> Route {
        Route {
            id: uuid::Uuid::new_v4(),
            name: "signed".into(),
            from: from.into(),
            path: None,
            to: vec!["http://upstream.example.com".into()],
            redirect: None,
            idp_id: None,
            access: RouteAccess::default(),
            load_balancing: Default::default(),
            preserve_host_header: true,
            host_rewrite: None,
            timeout_ms: 30_000,
            response_idle_timeout_ms: 180_000,
            enable_websocket: false,
            enable_grpc: false,
            regex_rewrite_pattern: None,
            regex_rewrite_substitution: None,
            enable_signed_identity: true,
            tls_skip_verify: false,
            tls_downstream: Default::default(),
            headers: Default::default(),
            session_cookie_samesite: None,
            response_location_rewrite: true,
            enabled: true,
            concurrency_limit: None,
        }
    }

    #[test]
    fn signed_route_requires_exact_canonical_https_origin() {
        assert!(validate_route(route("https://app.example.com").signed_identity_input()).is_ok());
        assert!(
            validate_route(route("https://app.example.com:8443").signed_identity_input()).is_ok()
        );
        for invalid in [
            "http://app.example.com",
            "https://USER@app.example.com",
            "https://app.example.com/",
            "https://app.example.com/path",
            "https://app.example.com?x=1",
            "https://app.example.com#x",
            "https://APP.example.com",
            "https://app.example.com:443",
        ] {
            assert!(
                validate_route(route(invalid).signed_identity_input()).is_err(),
                "accepted {invalid}"
            );
        }
        let mut redirect = route("https://app.example.com");
        redirect.redirect = Some(crate::models::route::RedirectRule {
            host_redirect: Some("other.example.com".into()),
            path_redirect: None,
            code: 302,
        });
        assert!(validate_route(redirect.signed_identity_input()).is_err());
    }

    #[test]
    fn disabled_route_keeps_legacy_from_unchanged() {
        let mut route = route("not a URL");
        route.enable_signed_identity = false;
        assert_eq!(validate_route(route.signed_identity_input()).unwrap(), None);
    }

    #[test]
    fn claims_use_explicit_upstream_identity_and_fixed_lifetime() {
        let config = GlobalConfig {
            auth_domain: Some("AUTH.example.com:443".into()),
            ..GlobalConfig::default()
        };
        let route = route("https://app.example.com");
        let authority =
            IdentityAuthority::from_boot(&config, std::slice::from_ref(&route)).unwrap();
        let identity = UpstreamIdentity {
            subject: "opaque-subject".into(),
            explicit_email: Some("alice@example.com".into()),
            provenance: UpstreamIdentityProvenance::Oidc,
        };
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let claims = authority
            .prepare_claims(
                route.signed_identity_input(),
                &identity,
                &["ops".into()],
                now,
            )
            .unwrap();
        assert_eq!(claims.sub, "opaque-subject");
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.groups, ["ops"]);
        assert_eq!(claims.iss, "https://auth.example.com");
        assert_eq!(claims.aud, "https://app.example.com");
        assert_eq!(claims.iat, 1_700_000_000);
        assert_eq!(claims.nbf, claims.iat);
        assert_eq!(claims.exp - claims.iat, 300);
    }

    #[test]
    fn missing_explicit_email_is_typed_and_safe() {
        let config = GlobalConfig {
            auth_domain: Some("auth.example.com".into()),
            ..GlobalConfig::default()
        };
        let route = route("https://app.example.com");
        let authority =
            IdentityAuthority::from_boot(&config, std::slice::from_ref(&route)).unwrap();
        let identity = UpstreamIdentity {
            subject: "not-an-email".into(),
            explicit_email: None,
            provenance: UpstreamIdentityProvenance::Oidc,
        };
        assert_eq!(
            authority.prepare_claims(route.signed_identity_input(), &identity, &[], Utc::now()),
            Err(IdentityError::MissingExplicitEmail)
        );
    }
}
