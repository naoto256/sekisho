//! Admission checks for management-plane writes.
//!
//! Every mutation that arrives through the management API passes through this
//! module before it reaches [`crate::store`]. Concentrating the rules here is
//! deliberate: the storage layer applies RFC 7396 merge patches generically
//! over JSON, so a rule expressed there would have to be restated per field,
//! and all three clients (CLI, web UI, anything future) share one gate because
//! they all share the HTTP surface.
//!
//! ## Reject rather than repair
//!
//! Validators return [`Error::BadRequest`] instead of normalizing input. A
//! rejected write tells the operator at the moment they made the mistake; a
//! silently rewritten value is discovered much later, from proxy behaviour
//! that does not match what `show route` prints.
//!
//! ## The same rule at admission and at boot
//!
//! Several checks delegate to the module that enforces the same invariant at
//! runtime — signed identity to [`crate::identity::validate_route`], route
//! paths to [`crate::request_target::canonicalize_path`], header ownership to
//! [`crate::proxy::header_boundary::is_reserved_route_header`], IdP shape to
//! [`crate::auth::strategy`]. Sharing the function rather than restating the
//! rule is what keeps the two answers from drifting, and the goal is blunt: a
//! configuration the daemon would refuse to start with must be impossible to
//! store. [`validate_management_api_binding`] and [`validate_global_config`]
//! are called from both sides for exactly that reason.
//!
//! ## Create and update are validated differently
//!
//! Create bodies carry every field; update bodies are patch-shaped, where
//! `Option<Option<T>>` distinguishes "leave alone" from "clear". The `*_update`
//! validators therefore inspect only the fields a patch actually sets —
//! checking an absent field would reject patches that never touched it. Route
//! cross-field rules are re-checked on the merged row by the backend; the IdP
//! handler builds and validates an effective merged preview before its write.

use crate::error::Error;

/// Validate the effective management-listener pair. An empty listen value is
/// the loopback-only default. Wildcard listeners are never accepted; an
/// explicit non-loopback address requires a canonical, non-empty source ACL.
pub(crate) fn validate_management_api_binding(
    api_listen: &str,
    api_accept_from: &str,
) -> Result<crate::acl::AcceptFrom, Error> {
    let acl = crate::acl::AcceptFrom::parse(api_accept_from)
        .map_err(|error| Error::BadRequest(format!("invalid api_accept_from: {error}")))?;
    if api_accept_from.trim() != acl.to_string_canonical() {
        return Err(Error::BadRequest(
            "api_accept_from must use canonical CIDR notation".into(),
        ));
    }
    let listen = api_listen.trim();
    if listen.is_empty() {
        return Ok(acl);
    }
    let address: std::net::SocketAddr = listen
        .parse()
        .map_err(|_| Error::BadRequest("api_listen must be a concrete IP socket address".into()))?;
    if address.ip().is_unspecified() {
        return Err(Error::BadRequest(
            "api_listen must not use an unspecified address".into(),
        ));
    }
    if !address.ip().is_loopback() && acl.is_any() {
        return Err(Error::BadRequest(
            "non-loopback api_listen requires api_accept_from".into(),
        ));
    }
    Ok(acl)
}

/// Headers that route config can override only when the operator
/// explicitly opts in via `HeaderModifications::allow_credential_overrides`.
///
/// These are user-supplied credentials toward upstream. Mistakenly
/// adding `Authorization: Bearer my-secret` to a public route would
/// leak the secret to every downstream visitor, so the default is to
/// reject. With the opt-in, the canonical IAP pattern works:
///
/// > OIDC authenticates the user → policy decides access → route
/// > injects fixed Basic credentials so upstream sees a single
/// > service-account-style identity.
///
/// Mirrors Pomerium's `set_request_headers: Authorization: Basic ...`.
/// The audit event for `route.create` / `route.update` carries the
/// flag so downstream filters can flag every route that opts in.
const CREDENTIAL_HEADERS: &[&str] = &["authorization", "cookie"];

/// Parse a policy expression with the same syntax and boundary rules used by
/// request-time evaluation. Concrete storage writers call this as a second
/// admission boundary so internal callers cannot bypass the management API.
pub(crate) fn validate_policy_expression(expr: &str) -> Result<(), Error> {
    crate::policy::parse(expr)
        .map_err(|error| Error::BadRequest(format!("invalid expression: {error}")))?;
    Ok(())
}

pub(crate) fn validate_route_policy(
    access: &crate::models::route::RouteAccess,
) -> Result<(), Error> {
    if let Some(expr) = access.policy.as_deref() {
        validate_policy_expression(expr)?;
    }
    Ok(())
}

/// Full validation of a route creation body. Every field is present, so this
/// is the one place a route can be judged without consulting stored state.
pub fn validate_route_create(route: &crate::models::route::CreateRoute) -> Result<(), Error> {
    validate_name(&route.name, "route")?;
    validate_url(&route.from, "from")?;
    if let Some(path) = route.path.as_deref() {
        validate_route_path(path)?;
    }
    if route.to.is_empty() && route.redirect.is_none() {
        return Err(Error::BadRequest(
            "either 'to' (upstream URLs) or 'redirect' must be specified".into(),
        ));
    }
    if !route.to.is_empty() {
        validate_upstreams(&route.to)?;
    }
    if let Some(ref r) = route.redirect {
        validate_redirect(r)?;
    }
    if let Some(t) = route.timeout_ms {
        validate_timeout(t)?;
    }
    if let Some(t) = route.response_idle_timeout_ms {
        validate_response_idle_timeout(t)?;
    }
    validate_regex_rewrite(
        route.regex_rewrite_pattern.as_deref(),
        route.regex_rewrite_substitution.as_deref(),
    )?;
    validate_headers(
        &route.headers.add,
        &route.headers.remove,
        route.headers.allow_credential_overrides,
    )?;
    validate_route_policy(&route.access)?;
    crate::identity::validate_route(route.signed_identity_input())
        .map_err(|_| Error::BadRequest(crate::identity::INVALID_SIGNED_ROUTE.into()))?;
    Ok(())
}

/// Validate only what a route patch explicitly sets.
///
/// Cross-field rules that need the merged result (a `from` that becomes a
/// non-origin URL while signed identity stays on, for instance) cannot be
/// decided here and are re-checked by the backend under its writer lock; see
/// [`crate::models::route::UpdateRoute::explicit_signed_identity_input`].
pub fn validate_route_update(route: &crate::models::route::UpdateRoute) -> Result<(), Error> {
    if let Some(ref n) = route.name {
        validate_name(n, "route")?;
    }
    if let Some(ref f) = route.from {
        validate_url(f, "from")?;
    }
    if let Some(Some(path)) = route.path.as_ref() {
        validate_route_path(path)?;
    }
    if let Some(ref t) = route.to {
        validate_upstreams(t)?;
    }
    if let Some(Some(ref r)) = route.redirect {
        validate_redirect(r)?;
    }
    if let Some(t) = route.timeout_ms {
        validate_timeout(t)?;
    }
    if let Some(t) = route.response_idle_timeout_ms {
        validate_response_idle_timeout(t)?;
    }
    if let Some(ref headers) = route.headers {
        // `headers.add` on the patch type is `HashMap<String, Option<String>>`
        // — Some(s) sets, None instructs RFC 7396 merge to delete the key.
        // Validation only cares about the values that are actually
        // being set, so flatten to `HashMap<String, String>` before
        // calling the shared validator.
        let add_set: std::collections::HashMap<String, String> = headers
            .add
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|val| (k.clone(), val.clone())))
            .collect();
        validate_headers(
            &add_set,
            &headers.remove,
            headers.allow_credential_overrides,
        )?;
    }
    if let Some(access) = &route.access {
        validate_route_policy(access)?;
    }
    // `Option<Option<String>>` distinguishes "clear the field" (Some(None))
    // from "leave it alone" (None). We only validate on an explicit value.
    let pattern = match &route.regex_rewrite_pattern {
        Some(Some(p)) => Some(p.as_str()),
        _ => None,
    };
    let sub = match &route.regex_rewrite_substitution {
        Some(Some(s)) => Some(s.as_str()),
        _ => None,
    };
    validate_regex_rewrite(pattern, sub)?;
    if let Some(input) = route.explicit_signed_identity_input() {
        crate::identity::validate_route(input)
            .map_err(|_| Error::BadRequest(crate::identity::INVALID_SIGNED_ROUTE.into()))?;
    }
    Ok(())
}

/// Validate an IdP creation body by dispatching the protocol-specific half to
/// the strategy for its type, so OIDC and SAML rules stay next to the code
/// that consumes them rather than accumulating here.
pub fn validate_idp_create(
    name: &str,
    idp_type: &crate::models::idp::IdpType,
    oidc_config: &Option<crate::models::idp::OidcConfigInput>,
    saml_config: &Option<crate::models::idp::SamlConfig>,
) -> Result<(), Error> {
    validate_name(name, "identity provider")?;
    crate::auth::strategy::Strategy::for_idp_type(*idp_type)
        .validate_create_config(oidc_config.as_ref(), saml_config.as_ref())
}

/// Type-independent half of IdP patch validation.
///
/// Runs cheap checks on fields that are present before normalization or a
/// database read. Full protocol validation follows on the effective merged
/// row in [`validate_idp_update_for_type`].
pub fn validate_idp_update_syntax(
    update: &crate::models::idp::UpdateIdentityProvider,
) -> Result<(), Error> {
    if let Some(name) = &update.name {
        validate_name(name, "identity provider")?;
    }
    if let Some(Some(issuer_url)) = update
        .oidc_config
        .as_ref()
        .and_then(|config| config.issuer_url.as_ref())
        && url::Url::parse(issuer_url).is_err()
    {
        return Err(Error::BadRequest("issuer_url must be a valid URL".into()));
    }
    if let Some(Some(metadata_url)) = update
        .saml_config
        .as_ref()
        .and_then(|config| config.metadata_url.as_ref())
        && url::Url::parse(metadata_url).is_err()
    {
        return Err(Error::BadRequest("metadata_url must be a valid URL".into()));
    }
    Ok(())
}

/// Validate the effective merged IdP with the strategy selected by its stored
/// immutable `idp_type`. The patch DTO has no type field and cannot switch
/// protocols.
pub fn validate_idp_update_for_type(
    effective: &crate::models::idp::IdentityProvider,
) -> Result<(), Error> {
    crate::auth::strategy::Strategy::for_idp_type(effective.idp_type).validate_update_config(
        effective.oidc_config.as_ref(),
        effective.saml_config.as_ref(),
    )
}

/// Shared OIDC field checks, called from the OIDC strategy on both create and
/// update. The client secret is not checked here: on update an absent secret
/// means "keep the stored one", so emptiness is not an error at this layer.
pub(crate) fn validate_oidc_config_fields(issuer_url: &str, client_id: &str) -> Result<(), Error> {
    validate_url(issuer_url, "issuer_url")?;
    if client_id.trim().is_empty() {
        return Err(Error::BadRequest("client_id must not be empty".into()));
    }
    Ok(())
}

/// Shared SAML field checks. Only the metadata URL is structural — everything
/// else (entity ID, ACS URL) is derived at runtime from `auth_domain`, so
/// there is nothing else here to get wrong.
pub(crate) fn validate_saml_config_fields(metadata_url: &str) -> Result<(), Error> {
    validate_url(metadata_url, "metadata_url")
}

/// Range checks for global config.
///
/// Takes loose arguments rather than the patch struct so
/// [`validate_global_config`] can reuse it to re-check a fully materialized
/// config at boot. The bounds are all "reject values that would be
/// operationally absurd or would starve a shared resource" rather than
/// anything the types could express.
pub fn validate_config_update(
    log_level: Option<&str>,
    session_lifetime_hours: Option<u32>,
    websocket_concurrency_limit: Option<u32>,
    acme_queue_capacity: Option<u32>,
    acme_issuance_concurrency_limit: Option<u32>,
    acme_renewal_scan_interval_hours: Option<u32>,
) -> Result<(), Error> {
    if let Some(level) = log_level {
        const VALID_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];
        if !VALID_LEVELS.contains(&level) {
            return Err(Error::BadRequest(format!(
                "log_level must be one of: {}",
                VALID_LEVELS.join(", ")
            )));
        }
    }
    if let Some(hours) = session_lifetime_hours
        && (hours == 0 || hours > 720)
    {
        return Err(Error::BadRequest(
            "session_lifetime_hours must be between 1 and 720".into(),
        ));
    }
    if let Some(limit) = websocket_concurrency_limit {
        validate_websocket_concurrency_limit(limit)?;
    }
    if let Some(capacity) = acme_queue_capacity
        && !(1..=100_000).contains(&capacity)
    {
        return Err(Error::BadRequest(
            "acme_queue_capacity must be between 1 and 100000".into(),
        ));
    }
    if let Some(limit) = acme_issuance_concurrency_limit
        && !(1..=5).contains(&limit)
    {
        return Err(Error::BadRequest(
            "acme_issuance_concurrency_limit must be between 1 and 5".into(),
        ));
    }
    if let Some(hours) = acme_renewal_scan_interval_hours
        && !(1..=168).contains(&hours)
    {
        return Err(Error::BadRequest(
            "acme_renewal_scan_interval_hours must be between 1 and 168".into(),
        ));
    }
    Ok(())
}

/// Re-run [`validate_config_update`] over a complete config.
///
/// Called at startup: a config row may predate a bound (or have been written
/// directly to the database), and the daemon should fail loudly at boot
/// rather than behave strangely later.
pub fn validate_global_config(config: &crate::models::config::GlobalConfig) -> Result<(), Error> {
    validate_config_update(
        Some(&config.log_level),
        Some(config.session_lifetime_hours),
        Some(config.websocket_concurrency_limit),
        Some(config.acme_queue_capacity),
        Some(config.acme_issuance_concurrency_limit),
        Some(config.acme_renewal_scan_interval_hours),
    )
}

/// Common name rule for every named resource. Length is bounded because names
/// end up in audit events, log fields and CLI tables; content is otherwise
/// unconstrained so operators can use their own conventions.
fn validate_name(name: &str, entity: &str) -> Result<(), Error> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::BadRequest(format!(
            "{entity} name must not be empty"
        )));
    }
    if name.len() > 255 {
        return Err(Error::BadRequest(format!(
            "{entity} name must be at most 255 characters"
        )));
    }
    Ok(())
}

/// Require a parseable URL restricted to `http`/`https`.
///
/// The scheme allowlist is the point: `url::Url` happily parses `file:`,
/// `javascript:` and friends, and these values become outbound fetch targets
/// or redirect destinations.
pub(crate) fn validate_url(url: &str, field: &str) -> Result<(), Error> {
    let parsed = url::Url::parse(url)
        .map_err(|_| Error::BadRequest(format!("{field} must be a valid URL")))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        other => Err(Error::BadRequest(format!(
            "{field} must use http or https scheme, got '{other}'"
        ))),
    }
}

/// Validate each upstream URL, reporting the index so an operator with eight
/// backends is told which one is wrong.
fn validate_upstreams(to: &[String]) -> Result<(), Error> {
    if to.is_empty() {
        return Err(Error::BadRequest(
            "to must contain at least one upstream URL".into(),
        ));
    }
    for (i, url) in to.iter().enumerate() {
        validate_url(url, &format!("to[{i}]"))?;
    }
    Ok(())
}

/// Bound the header-phase timeout. Zero would mean "time out instantly"
/// rather than "no timeout", and the upper bound keeps a typo from parking a
/// connection slot for hours.
fn validate_timeout(ms: u64) -> Result<(), Error> {
    if ms == 0 {
        return Err(Error::BadRequest(
            "timeout_ms must be greater than 0".into(),
        ));
    }
    if ms > 300_000 {
        return Err(Error::BadRequest(
            "timeout_ms must be at most 300000 (5 minutes)".into(),
        ));
    }
    Ok(())
}

/// Only reject zero here. Unlike the header-phase timeout, a long idle
/// allowance is a legitimate configuration — server-sent events and slow
/// streaming upstreams can be quiet for a long time and still be healthy.
fn validate_response_idle_timeout(ms: u64) -> Result<(), Error> {
    if ms == 0 {
        return Err(Error::BadRequest(
            "response_idle_timeout_ms must be greater than 0".into(),
        ));
    }
    Ok(())
}

/// The ceiling is `Semaphore::MAX_PERMITS` because the limit is handed
/// straight to a Tokio semaphore, which panics above it. Deriving the bound
/// from the constant rather than hard-coding a number keeps the two in step
/// across Tokio upgrades.
fn validate_websocket_concurrency_limit(limit: u32) -> Result<(), Error> {
    if limit == 0 || limit as usize > tokio::sync::Semaphore::MAX_PERMITS {
        return Err(Error::BadRequest(format!(
            "websocket_concurrency_limit must be between 1 and {}",
            tokio::sync::Semaphore::MAX_PERMITS
        )));
    }
    Ok(())
}

/// Enforce the two header rules route config must obey.
///
/// Reserved headers are refused outright — they are owned by HTTP framing or
/// by Sekisho itself, and letting route config touch them would let an
/// operator forge the very values the upstream is being asked to trust.
/// Credential headers are refused *unless* the route opted in, because the
/// legitimate use (fixed upstream basic-auth) and the dangerous mistake
/// (pasting a bearer token onto a public route) are the same edit.
///
/// `remove` is checked as strictly as `add`: quietly dropping
/// `X-Sekisho-User` on the way out would be an authentication bypass from
/// the upstream's point of view.
fn validate_headers(
    add: &std::collections::HashMap<String, String>,
    remove: &[String],
    allow_credential_overrides: bool,
) -> Result<(), Error> {
    for key in add.keys() {
        let lower = key.to_lowercase();
        if crate::proxy::header_boundary::is_reserved_route_header(key) {
            return Err(Error::BadRequest(format!(
                "header '{key}' is blocked and cannot be added via route config"
            )));
        }
        if !allow_credential_overrides && CREDENTIAL_HEADERS.contains(&lower.as_str()) {
            return Err(Error::BadRequest(format!(
                "header '{key}' is a credential header; set \
                 headers.allow_credential_overrides=true on the route to opt in \
                 (intended for upstream basic-auth injection)"
            )));
        }
    }
    for key in remove {
        let lower = key.to_lowercase();
        if crate::proxy::header_boundary::is_reserved_route_header(key) {
            return Err(Error::BadRequest(format!(
                "header '{key}' is blocked and cannot be removed via route config"
            )));
        }
        if !allow_credential_overrides && CREDENTIAL_HEADERS.contains(&lower.as_str()) {
            return Err(Error::BadRequest(format!(
                "header '{key}' is a credential header; set \
                 headers.allow_credential_overrides=true on the route to opt in"
            )));
        }
    }
    Ok(())
}

/// Restrict redirect targets to syntactically valid `host[:port]` + absolute
/// path. Without this, a misconfigured route can redirect proxied traffic to
/// an arbitrary URL (open-redirect style). We don't currently enforce a
/// domain allowlist — that belongs in operational policy — but we reject
/// anything that isn't a plain host so a `host_redirect` of `evil.com/path`
/// or `javascript:alert(1)` can't pass through.
fn validate_redirect(r: &crate::models::route::RedirectRule) -> Result<(), Error> {
    if let Some(ref h) = r.host_redirect {
        validate_redirect_host(h)?;
    }
    if let Some(ref p) = r.path_redirect
        && !p.starts_with('/')
    {
        return Err(Error::BadRequest(
            "redirect.path_redirect must start with '/'".into(),
        ));
    }
    // HTTP status must be a 3xx redirect code.
    if !(300..400).contains(&r.code) {
        return Err(Error::BadRequest(format!(
            "redirect.code must be a 3xx status (got {})",
            r.code
        )));
    }
    Ok(())
}

fn validate_redirect_host(host: &str) -> Result<(), Error> {
    if host.is_empty() {
        return Err(Error::BadRequest(
            "redirect.host_redirect must not be empty".into(),
        ));
    }
    // Disallow anything that isn't just host or host:port: no schemes,
    // no paths, no userinfo, no queries or fragments.
    let forbidden: &[char] = &['/', '\\', '?', '#', '@', ' ', '\t', '\n', '\r'];
    if host.contains(forbidden) {
        return Err(Error::BadRequest(
            "redirect.host_redirect must be a bare host[:port], not a URL".into(),
        ));
    }
    // Split off optional :port and validate the host half via url::Host.
    let (name, port_str) = match host.rsplit_once(':') {
        // Bracketed IPv6 like `[::1]:8080` — split only at the last `:`
        // that follows the closing bracket.
        Some((n, p)) if !n.contains(':') || n.ends_with(']') => (n, Some(p)),
        _ => (host, None),
    };
    if let Some(p) = port_str {
        p.parse::<u16>().map_err(|_| {
            Error::BadRequest(format!("redirect.host_redirect: '{p}' is not a valid port"))
        })?;
    }
    url::Host::parse(name.trim_start_matches('[').trim_end_matches(']'))
        .map_err(|_| Error::BadRequest("redirect.host_redirect is not a valid hostname".into()))?;
    Ok(())
}

/// Reject regex rewrite configs that would fail to compile at proxy time.
/// Without this check an invalid pattern would be stored, logged as a warning
/// on first use, and silently skip path rewriting — an easy way for an
/// operator to think rewrites are active when they aren't. Pattern and
/// substitution are a matched pair; rejecting a half-configured rewrite
/// prevents ambiguous state.
fn validate_regex_rewrite(pattern: Option<&str>, substitution: Option<&str>) -> Result<(), Error> {
    match (pattern, substitution) {
        (None, None) => Ok(()),
        (Some(p), Some(_)) => regex::Regex::new(p)
            .map(|_| ())
            .map_err(|e| Error::BadRequest(format!("regex_rewrite_pattern is invalid: {e}"))),
        (Some(_), None) => Err(Error::BadRequest(
            "regex_rewrite_pattern requires regex_rewrite_substitution".into(),
        )),
        (None, Some(_)) => Err(Error::BadRequest(
            "regex_rewrite_substitution requires regex_rewrite_pattern".into(),
        )),
    }
}

/// A route's path prefix must satisfy the same canonical-form rules as an
/// inbound request path. Matching a stored prefix against a canonicalized
/// request path only means anything if both sides were produced by the same
/// function.
fn validate_route_path(path: &str) -> Result<(), Error> {
    crate::request_target::canonicalize_path(path)
        .map(|_| ())
        .map_err(|_| Error::BadRequest("route path is not canonical and safe".into()))
}

/// Require a concrete `ip:port`. Hostnames are rejected on purpose: a bind
/// address that depends on name resolution fails at startup, long after the
/// operator has moved on from the config change that caused it.
pub(crate) fn validate_listen_addr(addr: &str) -> Result<(), Error> {
    use std::net::SocketAddr;
    addr.parse::<SocketAddr>().map_err(|_| {
        Error::BadRequest(format!(
            "'{addr}' is not a valid listen address (expected host:port)"
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::route::{CreateRoute, HeaderModifications};

    fn base_route(name: &str, from: &str, to: Vec<&str>) -> CreateRoute {
        CreateRoute {
            name: name.into(),
            from: from.into(),
            path: None,
            to: to.into_iter().map(String::from).collect(),
            redirect: None,
            idp_id: None,
            access: Default::default(),
            load_balancing: None,
            preserve_host_header: None,
            host_rewrite: None,
            timeout_ms: None,
            response_idle_timeout_ms: None,
            enable_websocket: None,
            enable_grpc: None,
            enable_signed_identity: None,
            regex_rewrite_pattern: None,
            regex_rewrite_substitution: None,
            tls_skip_verify: None,
            tls_downstream: None,
            headers: HeaderModifications::default(),
            session_cookie_samesite: None,
            response_location_rewrite: None,
            enabled: None,
            concurrency_limit: None,
        }
    }

    #[test]
    fn route_create_valid() {
        let r = base_route(
            "my-app",
            "https://app.example.com",
            vec!["http://backend:8080"],
        );
        assert!(validate_route_create(&r).is_ok());
    }

    #[test]
    fn route_path_uses_request_target_validation() {
        let mut route = base_route("r", "https://x.com", vec!["http://b:80"]);
        route.path = Some("/admin/".into());
        assert!(validate_route_create(&route).is_ok());

        for path in [
            "admin",
            "/a//b",
            "/%2f",
            "/%252f",
            "/admin?part",
            "/admin#part",
            "/admin%3fpart",
            "/admin%23part",
            "/a;b",
            "/../a",
        ] {
            route.path = Some(path.into());
            assert!(validate_route_create(&route).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn route_create_empty_name() {
        assert!(
            validate_route_create(&base_route("", "https://x.com", vec!["http://b:80"])).is_err()
        );
    }

    #[test]
    fn route_create_whitespace_only_name() {
        assert!(
            validate_route_create(&base_route("   ", "https://x.com", vec!["http://b:80"]))
                .is_err()
        );
    }

    #[test]
    fn route_create_name_too_long() {
        assert!(
            validate_route_create(&base_route(
                &"a".repeat(256),
                "https://x.com",
                vec!["http://b:80"]
            ))
            .is_err()
        );
    }

    #[test]
    fn route_create_invalid_from_url() {
        assert!(
            validate_route_create(&base_route("app", "not-a-url", vec!["http://b:80"])).is_err()
        );
    }

    #[test]
    fn route_create_empty_to_no_redirect() {
        assert!(validate_route_create(&base_route("app", "https://x.com", vec![])).is_err());
    }

    #[test]
    fn route_create_empty_to_with_redirect() {
        use crate::models::route::RedirectRule;
        let mut r = base_route("app", "https://x.com", vec![]);
        r.redirect = Some(RedirectRule {
            host_redirect: Some("o.com".into()),
            path_redirect: Some("/".into()),
            code: 302,
        });
        assert!(validate_route_create(&r).is_ok());
    }

    #[test]
    fn route_create_invalid_upstream() {
        assert!(
            validate_route_create(&base_route("app", "https://x.com", vec!["not-a-url"])).is_err()
        );
    }

    #[test]
    fn route_create_timeout_zero() {
        let mut r = base_route("app", "https://x.com", vec!["http://b:80"]);
        r.timeout_ms = Some(0);
        assert!(validate_route_create(&r).is_err());
    }

    #[test]
    fn route_create_timeout_too_high() {
        let mut r = base_route("app", "https://x.com", vec!["http://b:80"]);
        r.timeout_ms = Some(300_001);
        assert!(validate_route_create(&r).is_err());
    }

    #[test]
    fn route_create_blocked_header() {
        let mut r = base_route("app", "https://x.com", vec!["http://b:80"]);
        r.headers.add.insert("Host".into(), "evil".into());
        assert!(validate_route_create(&r).is_err());
    }

    #[test]
    fn route_create_custom_header_ok() {
        let mut r = base_route("app", "https://x.com", vec!["http://b:80"]);
        r.headers.add.insert("X-Custom".into(), "v".into());
        assert!(validate_route_create(&r).is_ok());
    }

    #[test]
    fn route_create_rejects_every_reserved_header_namespace() {
        for name in [
            "Keep-Alive",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "Via",
            "Forwarded",
            "X-Forwarded-Other",
            "X-Sekisho-Other",
            "Sec-WebSocket-Protocol",
        ] {
            let mut add = base_route("app", "https://x.com", vec!["http://b:80"]);
            add.headers.add.insert(name.into(), "value".into());
            assert!(validate_route_create(&add).is_err(), "add accepted {name}");

            let mut remove = base_route("app", "https://x.com", vec!["http://b:80"]);
            remove.headers.remove.push(name.into());
            assert!(
                validate_route_create(&remove).is_err(),
                "remove accepted {name}"
            );
        }
    }

    #[test]
    fn route_update_rejects_reserved_header_operations() {
        for update in [
            serde_json::json!({"headers": {"add": {"Via": "1.0 injected"}}}),
            serde_json::json!({"headers": {"remove": ["Sec-WebSocket-Accept"]}}),
        ] {
            let update = serde_json::from_value(update).expect("valid route patch shape");
            assert!(validate_route_update(&update).is_err());
        }
    }

    #[test]
    fn route_create_authorization_header_rejected_by_default() {
        // The most common operator footgun: paste a Pomerium config
        // that injects upstream basic auth, forget to flip the opt-in
        // flag, and have the request silently pass through with no
        // auth header. We want a loud 400 instead.
        let mut r = base_route("app", "https://x.com", vec!["http://b:80"]);
        r.headers
            .add
            .insert("Authorization".into(), "Basic xxx".into());
        let err = validate_route_create(&r).unwrap_err();
        assert!(
            format!("{err:?}").contains("allow_credential_overrides"),
            "error must point operator at the opt-in flag"
        );
    }

    #[test]
    fn route_create_authorization_header_allowed_when_opted_in() {
        let mut r = base_route("app", "https://x.com", vec!["http://b:80"]);
        r.headers
            .add
            .insert("Authorization".into(), "Basic xxx".into());
        r.headers.allow_credential_overrides = true;
        assert!(validate_route_create(&r).is_ok());
    }

    #[test]
    fn route_create_cookie_header_gated_by_same_flag() {
        let mut r = base_route("app", "https://x.com", vec!["http://b:80"]);
        r.headers.add.insert("Cookie".into(), "session=x".into());
        assert!(validate_route_create(&r).is_err());
        r.headers.allow_credential_overrides = true;
        assert!(validate_route_create(&r).is_ok());
    }

    #[test]
    fn route_create_opt_in_does_not_unlock_hard_blocked_headers() {
        // Paranoia: the flag is for credential headers only. Setting
        // it must not let the operator inject Host or X-Forwarded-For
        // — those are still hard-blocked because they break the
        // proxy's invariants regardless of operator intent.
        let mut r = base_route("app", "https://x.com", vec!["http://b:80"]);
        r.headers.allow_credential_overrides = true;
        r.headers
            .add
            .insert("X-Forwarded-For".into(), "1.2.3.4".into());
        assert!(validate_route_create(&r).is_err());
    }

    // ── Redirect validation ──

    fn redirect_route(host: Option<&str>, path: Option<&str>, code: u16) -> CreateRoute {
        use crate::models::route::RedirectRule;
        let mut r = base_route("app", "https://x.com", vec![]);
        r.redirect = Some(RedirectRule {
            host_redirect: host.map(String::from),
            path_redirect: path.map(String::from),
            code,
        });
        r
    }

    #[test]
    fn redirect_host_bare_ok() {
        assert!(validate_route_create(&redirect_route(Some("other.com"), Some("/"), 302)).is_ok());
    }

    #[test]
    fn redirect_host_with_port_ok() {
        assert!(validate_route_create(&redirect_route(Some("other.com:8080"), None, 301)).is_ok());
    }

    #[test]
    fn redirect_host_ipv4_ok() {
        assert!(validate_route_create(&redirect_route(Some("10.0.0.5"), None, 302)).is_ok());
    }

    #[test]
    fn redirect_host_empty_rejected() {
        assert!(validate_route_create(&redirect_route(Some(""), None, 302)).is_err());
    }

    #[test]
    fn redirect_host_with_scheme_rejected() {
        assert!(
            validate_route_create(&redirect_route(Some("http://evil.com"), None, 302)).is_err()
        );
    }

    #[test]
    fn redirect_host_with_path_rejected() {
        assert!(
            validate_route_create(&redirect_route(Some("evil.com/victim"), None, 302)).is_err()
        );
    }

    #[test]
    fn redirect_host_with_userinfo_rejected() {
        assert!(validate_route_create(&redirect_route(Some("user@evil.com"), None, 302)).is_err());
    }

    #[test]
    fn redirect_host_javascript_scheme_rejected() {
        assert!(
            validate_route_create(&redirect_route(Some("javascript:alert(1)"), None, 302)).is_err()
        );
    }

    #[test]
    fn redirect_host_bad_port_rejected() {
        assert!(
            validate_route_create(&redirect_route(Some("other.com:not-a-port"), None, 302))
                .is_err()
        );
    }

    #[test]
    fn redirect_path_must_start_with_slash() {
        assert!(validate_route_create(&redirect_route(None, Some("foo"), 302)).is_err());
    }

    #[test]
    fn redirect_code_non_3xx_rejected() {
        assert!(validate_route_create(&redirect_route(Some("ok.com"), None, 200)).is_err());
        assert!(validate_route_create(&redirect_route(Some("ok.com"), None, 500)).is_err());
    }

    // ── IdP / Config validation (unchanged) ──

    #[test]
    fn idp_create_oidc_valid() {
        use crate::models::idp::{IdpType, OidcConfigInput};
        assert!(
            validate_idp_create(
                "google",
                &IdpType::Oidc,
                &Some(OidcConfigInput {
                    issuer_url: "https://accounts.google.com".into(),
                    client_id: "c".into(),
                    client_secret: Some("plaintext".into()),
                    scopes: vec!["openid".into()],
                    prompt: None,
                }),
                &None
            )
            .is_ok()
        );
    }

    #[test]
    fn idp_create_oidc_missing_secret_rejected() {
        use crate::models::idp::{IdpType, OidcConfigInput};
        assert!(
            validate_idp_create(
                "google",
                &IdpType::Oidc,
                &Some(OidcConfigInput {
                    issuer_url: "https://accounts.google.com".into(),
                    client_id: "c".into(),
                    client_secret: None,
                    scopes: vec!["openid".into()],
                    prompt: None,
                }),
                &None
            )
            .is_err()
        );
    }

    #[test]
    fn idp_create_oidc_missing_config() {
        use crate::models::idp::IdpType;
        assert!(validate_idp_create("g", &IdpType::Oidc, &None, &None).is_err());
    }

    fn oidc_update(issuer_url: &str, client_id: &str) -> crate::models::idp::IdentityProvider {
        crate::models::idp::IdentityProvider {
            id: uuid::Uuid::new_v4(),
            name: "oidc".into(),
            idp_type: crate::models::idp::IdpType::Oidc,
            oidc_config: Some(crate::models::idp::OidcConfig {
                issuer_url: issuer_url.into(),
                client_id: client_id.into(),
                client_secret_encrypted: "encrypted".into(),
                scopes: vec!["openid".into()],
                prompt: None,
            }),
            saml_config: None,
        }
    }

    fn saml_update(metadata_url: &str) -> crate::models::idp::IdentityProvider {
        crate::models::idp::IdentityProvider {
            id: uuid::Uuid::new_v4(),
            name: "saml".into(),
            idp_type: crate::models::idp::IdpType::Saml,
            oidc_config: None,
            saml_config: Some(crate::models::idp::SamlConfig {
                metadata_url: metadata_url.into(),
                slo_url: None,
                name_id_format: None,
                attribute_mapping: Default::default(),
            }),
        }
    }

    #[test]
    fn idp_create_and_update_share_oidc_field_validation() {
        use crate::models::idp::{IdpType, OidcConfigInput};

        for (issuer_url, client_id) in [
            ("not-a-url", "client"),
            ("file:///tmp/issuer", "client"),
            ("https://issuer.example", ""),
            ("https://issuer.example", " \t "),
        ] {
            let create = validate_idp_create(
                "oidc",
                &IdpType::Oidc,
                &Some(OidcConfigInput {
                    issuer_url: issuer_url.into(),
                    client_id: client_id.into(),
                    client_secret: Some("test-secret".into()),
                    scopes: vec!["openid".into()],
                    prompt: None,
                }),
                &None,
            );
            let update = validate_idp_update_for_type(&oidc_update(issuer_url, client_id));
            assert!(
                create.is_err(),
                "create unexpectedly accepted invalid OIDC fields"
            );
            assert!(
                update.is_err(),
                "update unexpectedly accepted invalid OIDC fields"
            );
        }
    }

    #[test]
    fn idp_create_and_update_share_saml_field_validation() {
        use crate::models::idp::{IdpType, SamlConfig};

        for metadata_url in ["not-a-url", "file:///tmp/metadata"] {
            let create = validate_idp_create(
                "saml",
                &IdpType::Saml,
                &None,
                &Some(SamlConfig {
                    metadata_url: metadata_url.into(),
                    slo_url: None,
                    name_id_format: None,
                    attribute_mapping: Default::default(),
                }),
            );
            let update = validate_idp_update_for_type(&saml_update(metadata_url));
            assert!(
                create.is_err(),
                "create unexpectedly accepted invalid SAML fields"
            );
            assert!(
                update.is_err(),
                "update unexpectedly accepted invalid SAML fields"
            );
        }
    }

    #[test]
    fn config_update_invalid_log_level() {
        assert!(validate_config_update(Some("banana"), None, None, None, None, None).is_err());
    }

    #[test]
    fn config_update_session_lifetime_zero() {
        assert!(validate_config_update(None, Some(0), None, None, None, None).is_err());
    }

    #[test]
    fn config_update_valid() {
        assert!(
            validate_config_update(Some("debug"), Some(24), Some(100), None, None, None).is_ok()
        );
    }

    #[test]
    fn config_update_rejects_zero_websocket_limit() {
        assert!(validate_config_update(None, None, Some(0), None, None, None).is_err());
    }

    #[test]
    fn route_response_idle_timeout_must_be_positive() {
        let mut route = base_route("r", "https://x.com", vec!["http://b:80"]);
        route.response_idle_timeout_ms = Some(0);
        assert!(validate_route_create(&route).is_err());
        route.response_idle_timeout_ms = Some(180_000);
        assert!(validate_route_create(&route).is_ok());
    }

    #[test]
    fn route_create_rejects_invalid_regex_rewrite() {
        let mut r = base_route("r", "https://x.com", vec!["http://b:80"]);
        // Lookahead — not supported by the `regex` crate, so must be rejected
        // up front rather than panicking in the proxy transform.
        r.regex_rewrite_pattern = Some("(?!x)x".into());
        r.regex_rewrite_substitution = Some("/y".into());
        assert!(validate_route_create(&r).is_err());
    }

    #[test]
    fn route_create_accepts_valid_regex_rewrite() {
        let mut r = base_route("r", "https://x.com", vec!["http://b:80"]);
        r.regex_rewrite_pattern = Some("^/api/(.*)$".into());
        r.regex_rewrite_substitution = Some("/$1".into());
        assert!(validate_route_create(&r).is_ok());
    }

    #[test]
    fn route_create_rejects_half_configured_regex_rewrite() {
        let mut r = base_route("r", "https://x.com", vec!["http://b:80"]);
        r.regex_rewrite_pattern = Some("^/api/(.*)$".into());
        // No substitution → ambiguous; reject rather than silently ignore.
        r.regex_rewrite_substitution = None;
        assert!(validate_route_create(&r).is_err());
    }
}
#[test]
fn management_api_binding_defaults_to_loopback_only() {
    assert!(validate_management_api_binding("", "").is_ok());
    assert!(validate_management_api_binding("127.0.0.1:9443", "").is_ok());
    assert!(validate_management_api_binding("[::1]:9443", "").is_ok());
}

#[test]
fn management_api_binding_rejects_wildcard_addresses() {
    for address in ["0.0.0.0:9443", "[::]:9443"] {
        let error = validate_management_api_binding(address, "192.0.2.0/24")
            .expect_err("wildcard bind must be rejected");
        assert!(error.to_string().contains("unspecified"));
    }
}

#[test]
fn management_api_binding_requires_acl_for_non_loopback() {
    let error = validate_management_api_binding("192.0.2.10:9443", "")
        .expect_err("non-loopback bind without ACL must be rejected");
    assert!(error.to_string().contains("requires api_accept_from"));
    assert!(validate_management_api_binding("192.0.2.10:9443", "192.0.2.0/24").is_ok());
}

#[test]
fn management_api_binding_requires_canonical_acl() {
    let error = validate_management_api_binding("192.0.2.10:9443", "192.0.2.0/24, 198.51.100.0/24")
        .expect_err("non-canonical separators must not be silently normalized");
    assert!(error.to_string().contains("canonical CIDR"));
}
