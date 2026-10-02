//! Route definitions — the central resource of the proxy.
//!
//! A route binds a public origin (`from`) to one or more upstreams (`to`) and
//! carries everything the data plane needs to serve it: which IdP
//! authenticates it, which policy authorizes it, how the request is rewritten,
//! and how the downstream certificate is obtained.
//!
//! ## Routes are created disabled
//!
//! `enabled` defaults to `false`, including for rows written before the field
//! existed. A route is staged — DNS, policies, IdP binding, certificate — and
//! only then enabled, which is also the moment ACME issuance is triggered. The
//! alternative, create-is-live, makes every half-finished edit briefly
//! serving, and there is no way to stage anything. That the upgrade path drops
//! existing routes back to staged is a deliberate cost of the same rule.
//!
//! ## Fields default to the behaviour that surprises least
//!
//! `preserve_host_header` and `response_location_rewrite` default on, because
//! an upstream that emits its own IP in a `Location` header and thereby routes
//! the browser around the proxy is a far more common failure than an upstream
//! that needed the redirect left alone. `enable_signed_identity` and
//! `enable_websocket` default off, because they add per-request cost or
//! surface area that most routes do not want.
//!
//! ## Create, update and store are three types
//!
//! `CreateRoute` uses `Option<T>` purely to mean "apply the default"; the
//! defaults are then applied once in [`CreateRoute::into_route`].
//! `UpdateRoute` uses `Option<Option<T>>` on every nullable field so a PATCH
//! can say "leave alone", "clear" and "set" distinctly — see
//! [`crate::models::serde_util::deserialize_some`].

use crate::models::serde_util::deserialize_some;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A route as stored and as served by the data plane. Also the shape returned
/// by the management API — routes hold no secrets, so there is no redacted
/// projection the way certificates and IdPs have one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: Uuid,
    pub name: String,
    /// The public-facing URL that this route handles (e.g. "<https://app.example.com>")
    pub from: String,
    /// Optional path prefix for path-based routing (e.g. "/cockpit.html").
    /// If set, only requests matching this prefix are handled by this route.
    #[serde(default)]
    pub path: Option<String>,
    /// Upstream backend URLs to proxy to. Empty if this is a redirect-only route.
    #[serde(default)]
    pub to: Vec<String>,
    /// If set, respond with a redirect instead of proxying.
    #[serde(default)]
    pub redirect: Option<RedirectRule>,
    /// Which IdP to use for authentication on this route.
    /// If None, falls back to config.default_idp_id.
    #[serde(default)]
    pub idp_id: Option<Uuid>,
    #[serde(default)]
    pub access: RouteAccess,
    #[serde(default = "default_load_balancing")]
    pub load_balancing: LoadBalancing,
    #[serde(default = "default_true")]
    pub preserve_host_header: bool,
    /// Override the Host header sent to the upstream with this value.
    /// Takes precedence over preserve_host_header when set.
    #[serde(default)]
    pub host_rewrite: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Maximum idle interval between non-empty upstream response DATA
    /// frames. This is distinct from `timeout_ms`, which ends when
    /// response headers arrive. Does not apply to established WebSocket
    /// tunnels (`101 Switching Protocols`).
    #[serde(default = "default_response_idle_timeout")]
    pub response_idle_timeout_ms: u64,
    #[serde(default)]
    pub enable_websocket: bool,
    #[serde(default)]
    pub enable_grpc: bool,
    /// Regex rewrite: if the request path matches this pattern, replace with substitution.
    /// Example: pattern="^/$", substitution="/WebGoat"
    #[serde(default)]
    pub regex_rewrite_pattern: Option<String>,
    #[serde(default)]
    pub regex_rewrite_substitution: Option<String>,
    /// Inject Sekisho-controlled identity headers toward upstream:
    /// `X-Sekisho-User`, `X-Sekisho-Groups`, and the signed `X-Sekisho-Jwt`
    /// (EdDSA with the current identity-signing key, never the master key).
    /// All three are gated on this single flag — the route either trusts
    /// Sekisho to be its identity front (and wants the full set) or it
    /// doesn't (and they're pure header-budget bloat). Defaults off so
    /// migrating Pomerium-style routes whose upstreams ignore identity
    /// headers don't accidentally push the request past upstream nginx's
    /// `large_client_header_buffers` limit (Entra-style group-OID
    /// claims for a power user run ~1–2 KB of `X-Sekisho-Groups` alone).
    #[serde(default)]
    pub enable_signed_identity: bool,
    /// Skip TLS certificate verification when connecting to upstream (for self-signed certs)
    #[serde(default)]
    pub tls_skip_verify: bool,
    #[serde(default)]
    pub tls_downstream: TlsMode,
    #[serde(default)]
    pub headers: HeaderModifications,
    /// Per-route override for the session cookie's `SameSite`
    /// attribute. `None` (the default) inherits from
    /// `global_config.session_cookie_samesite`. Set to `Some(None)`
    /// (i.e. literally `"none"`) on routes that front an upstream
    /// running its own SAML SP, so the IdP's SAMLResponse POST
    /// (cross-site from the IdP host → upstream host) carries the
    /// IAP's session cookie back. Other routes keep the safer Lax
    /// default; the relaxation is opt-in per route rather than
    /// blanket because every route that opts in widens its CSRF
    /// blast radius.
    #[serde(default)]
    pub session_cookie_samesite: Option<crate::models::config::SameSiteMode>,
    /// Rewrite absolute `Location` response headers whose authority
    /// matches one of `to` so they point at this route's public
    /// `from` instead. On by default — many network appliances and
    /// internal admin UIs emit `Location: https://<own-IP>/...`
    /// after a POST/login, which
    /// would otherwise send the browser to the upstream IP directly,
    /// bypassing the proxy and breaking authentication. Opt out per
    /// route for upstreams that intentionally redirect to a
    /// different host (federated SSO, OAuth callbacks bouncing to
    /// another internal service).
    #[serde(default = "default_true")]
    pub response_location_rewrite: bool,
    /// Whether this route actually serves traffic. A disabled route is
    /// kept in the database — including any certificate issued for its
    /// hostname — but the proxy treats it as if it did not exist (404).
    /// Flipping `enabled` false→true is the trigger point for automatic
    /// ACME certificate acquisition for the route's hostname.
    ///
    /// Default is `false`, including for routes whose stored JSON
    /// predates this field: on upgrade, every route drops back to
    /// staged and must be re-enabled explicitly. The deliberate
    /// activation story (`enable route …` as a single, observable
    /// operation) matters more than a silent carry-forward of the
    /// previous state.
    #[serde(default)]
    pub enabled: bool,
    /// Per-route concurrency limit. `None` means inherit the proxy
    /// global limit (`PROXY_CONCURRENCY_LIMIT`); `Some(n)` caps the
    /// number of in-flight requests against this route specifically.
    /// Once a route hits its cap, new requests get 503 immediately
    /// instead of stacking onto the global pool — a slow upstream
    /// can no longer starve other routes.
    #[serde(default)]
    pub concurrency_limit: Option<u32>,
}

/// Borrowed, rule-free projection consumed by the signed-identity authority.
/// Keeping this in the model layer avoids making Route depend on identity
/// validation while ensuring every caller supplies the same complete inputs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignedIdentityRouteInput<'a> {
    pub(crate) enabled: bool,
    pub(crate) from: &'a str,
    pub(crate) redirect: bool,
}

impl Route {
    /// Project the three fields signed-identity validation needs. Going
    /// through a projection rather than passing `&Route` keeps
    /// [`crate::identity`] from depending on the full model, and keeps the
    /// three call sites (stored route, create body, update body) from each
    /// deciding for themselves what to pass.
    pub(crate) fn signed_identity_input(&self) -> SignedIdentityRouteInput<'_> {
        SignedIdentityRouteInput {
            enabled: self.enable_signed_identity,
            from: &self.from,
            redirect: self.redirect.is_some(),
        }
    }
}

/// Redirect rule — respond with a redirect instead of proxying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectRule {
    /// Redirect to this host (e.g. "admin.example.com")
    pub host_redirect: Option<String>,
    /// Redirect to this path (e.g. "/")
    pub path_redirect: Option<String>,
    /// HTTP status code for the redirect (default 302)
    #[serde(default = "default_redirect_code")]
    pub code: u16,
}

fn default_redirect_code() -> u16 {
    302
}

/// Per-route authorization. `policy` carries a boolean expression in the
/// Policy DSL (see `crate::policy`) evaluated against the session and request.
/// Use `policy.<name>` inside the expression to reference a named `Policy`
/// resource so it can be reused across routes; otherwise just write the
/// expression inline. Combine references and conditions with `and` / `or`.
///
/// Examples:
///   policy: policy.soc-team
///   policy: claim.groups in ["DL_SOC"] and client.ip in ["192.168.0.0/24"]
///   policy: policy.soc and policy.from-office
///
/// `allow_public_unauthenticated_access` bypasses authentication and policy
/// evaluation (health checks, static assets). When `false` and `policy` is
/// `None`, the route denies everyone.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteAccess {
    /// Boolean expression in the Policy DSL. `None`/null = deny.
    #[serde(default)]
    pub policy: Option<String>,
    /// Skip authentication and policy evaluation. Use for health checks,
    /// public assets, etc.
    #[serde(default)]
    pub allow_public_unauthenticated_access: bool,
}

/// Strategy used to choose from a route's upstream list.
///
/// Round-robin keeps a node-local cursor per route and published route
/// generation. Random makes an independent uniform draw with replacement for
/// every request, so consecutive requests may select the same upstream and no
/// cursor or route affinity is involved. Neither strategy performs health
/// checking or cross-node coordination.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancing {
    #[default]
    RoundRobin,
    Random,
}

/// Where this route's downstream certificate comes from. Consulted by the
/// clients' enable-preflight, which is why it must distinguish "the daemon
/// will obtain one" from "the operator must have uploaded one": the second
/// case has to fail with an actionable error before the route goes live rather
/// than after.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Obtained automatically on enable. The default, since an IAP with no
    /// certificate serves nothing.
    #[default]
    Acme,
    /// Operator-uploaded. Enabling fails if no certificate covers the host.
    Custom,
    /// TLS is not terminated here; bytes go to the upstream untouched.
    Passthrough,
    /// Plain HTTP downstream. Only sensible behind a separate terminator.
    None,
}

/// Operator-configured header edits applied to the outbound request, last in
/// the transform pipeline. Headers the proxy is authoritative for are rejected
/// at admission rather than filtered here, so what this struct contains is
/// already known to be safe to apply — see
/// [`crate::proxy::header_boundary::is_reserved_route_header`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderModifications {
    /// Headers to set on the upstream request, overwriting any inbound value.
    #[serde(default)]
    pub add: std::collections::HashMap<String, String>,
    /// Headers to drop before forwarding.
    #[serde(default)]
    pub remove: Vec<String>,
    /// Opt-in to override `Authorization` and `Cookie` from route
    /// config. These are user-supplied credentials toward upstream;
    /// blocking them by default catches accidental "set Authorization
    /// to a secret I want to inject" misconfigurations. The legitimate
    /// IAP pattern (OIDC at the proxy, basic auth toward upstream)
    /// requires this flag because the operator is intentionally
    /// replacing the user's auth identity with a fixed upstream
    /// credential.
    ///
    /// Mirrors Pomerium's `set_request_headers: Authorization: Basic
    /// ...` pattern. The audit event for the route surfaces the flag
    /// state so a `route.create` / `route.update` carrying this is
    /// trivially filterable in Splunk / Sentinel.
    #[serde(default)]
    pub allow_credential_overrides: bool,
}

/// Patch-shaped variant of `HeaderModifications`: `add` accepts
/// `null` per key so the management API can express "delete this
/// entry from the route's add map" as part of an RFC 7396 merge
/// patch. The runtime / storage type stays `HashMap<String, String>`
/// — by the time the merged JSON is deserialized back into `Route`,
/// `json_merge` has dropped every key whose patch value was null,
/// so nulls are never seen on the read side.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderModificationsPatch {
    #[serde(default)]
    pub add: std::collections::HashMap<String, Option<String>>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub allow_credential_overrides: bool,
}

/// Request body for creating a new route
#[derive(Debug, Deserialize)]
pub struct CreateRoute {
    pub name: String,
    pub from: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub redirect: Option<RedirectRule>,
    pub idp_id: Option<Uuid>,
    #[serde(default)]
    pub access: RouteAccess,
    pub load_balancing: Option<LoadBalancing>,
    pub preserve_host_header: Option<bool>,
    pub host_rewrite: Option<String>,
    pub timeout_ms: Option<u64>,
    pub response_idle_timeout_ms: Option<u64>,
    pub enable_websocket: Option<bool>,
    pub enable_grpc: Option<bool>,
    pub enable_signed_identity: Option<bool>,
    pub regex_rewrite_pattern: Option<String>,
    pub regex_rewrite_substitution: Option<String>,
    pub tls_skip_verify: Option<bool>,
    pub tls_downstream: Option<TlsMode>,
    #[serde(default)]
    pub headers: HeaderModifications,
    /// Per-route override for the session cookie's `SameSite`
    /// attribute. See the same field on `Route` — set to `none`
    /// for upstreams running their own SAML SP.
    #[serde(default)]
    pub session_cookie_samesite: Option<crate::models::config::SameSiteMode>,
    pub response_location_rewrite: Option<bool>,
    /// Leave unset to create the route disabled. New routes default to
    /// `false` so that the operator can stage a full configuration —
    /// including policies, IdP bindings, DNS — and only enable once
    /// everything is in place. Enabling is what kicks off ACME.
    pub enabled: Option<bool>,
    /// Optional per-route concurrency cap. See the same field on
    /// `Route` for semantics.
    pub concurrency_limit: Option<u32>,
}

/// Request body for updating a route
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateRoute {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub path: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub redirect: Option<Option<RedirectRule>>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub idp_id: Option<Option<Uuid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<RouteAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_balancing: Option<LoadBalancing>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preserve_host_header: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub host_rewrite: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_idle_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_websocket: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_grpc: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_signed_identity: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub regex_rewrite_pattern: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub regex_rewrite_substitution: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_skip_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_downstream: Option<TlsMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HeaderModificationsPatch>,
    /// Per-route SameSite override. `Option<Option<...>>` so PATCH
    /// can distinguish "leave alone" (None) from "clear back to
    /// default" (Some(None)) and "set to a value" (Some(Some(_))).
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub session_cookie_samesite: Option<Option<crate::models::config::SameSiteMode>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_location_rewrite: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// `Option<Option<u32>>` so PATCH can distinguish "leave alone"
    /// (None) from "clear back to global default" (Some(None)) and
    /// "set to N" (Some(Some(N))).
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub concurrency_limit: Option<Option<u32>>,
}

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    30_000
}

fn default_response_idle_timeout() -> u64 {
    180_000
}

fn default_load_balancing() -> LoadBalancing {
    LoadBalancing::RoundRobin
}

impl CreateRoute {
    pub(crate) fn signed_identity_input(&self) -> SignedIdentityRouteInput<'_> {
        SignedIdentityRouteInput {
            enabled: self.enable_signed_identity.unwrap_or(false),
            from: &self.from,
            redirect: self.redirect.is_some(),
        }
    }

    /// Apply every default and produce the stored form.
    ///
    /// The single place `Option::unwrap_or` is allowed to decide a route's
    /// behaviour. Scattering the same defaults across handlers is how a POST
    /// and a PATCH of the same value end up producing different routes.
    pub fn into_route(self) -> Route {
        Route {
            id: Uuid::new_v4(),
            name: self.name.trim().to_string(),
            from: self.from,
            path: self.path,
            to: self.to,
            redirect: self.redirect,
            idp_id: self.idp_id,
            access: self.access,
            load_balancing: self.load_balancing.unwrap_or_default(),
            preserve_host_header: self.preserve_host_header.unwrap_or(true),
            host_rewrite: self.host_rewrite,
            timeout_ms: self.timeout_ms.unwrap_or(30_000),
            response_idle_timeout_ms: self.response_idle_timeout_ms.unwrap_or(180_000),
            enable_websocket: self.enable_websocket.unwrap_or(false),
            enable_grpc: self.enable_grpc.unwrap_or(false),
            enable_signed_identity: self.enable_signed_identity.unwrap_or(false),
            regex_rewrite_pattern: self.regex_rewrite_pattern,
            regex_rewrite_substitution: self.regex_rewrite_substitution,
            tls_skip_verify: self.tls_skip_verify.unwrap_or(false),
            tls_downstream: self.tls_downstream.unwrap_or_default(),
            headers: self.headers,
            session_cookie_samesite: self.session_cookie_samesite,
            response_location_rewrite: self.response_location_rewrite.unwrap_or(true),
            // Default false: new routes are staged, then explicitly
            // enabled once the operator has verified DNS/IdP/policies.
            enabled: self.enabled.unwrap_or(false),
            concurrency_limit: self.concurrency_limit,
        }
    }
}

impl UpdateRoute {
    /// A patch can be validated before loading the row only when it explicitly
    /// enables signed identity and supplies the public origin. The concrete
    /// backend always validates the fully merged Route under its writer lock.
    pub(crate) fn explicit_signed_identity_input(&self) -> Option<SignedIdentityRouteInput<'_>> {
        if self.enable_signed_identity != Some(true) {
            return None;
        }
        self.from.as_deref().map(|from| SignedIdentityRouteInput {
            enabled: true,
            from,
            redirect: self.redirect.as_ref().is_some_and(Option::is_some),
        })
    }
}

#[cfg(test)]
mod update_route_tests {
    use super::*;

    #[test]
    fn load_balancing_wire_names_and_default_remain_stable() {
        let random: LoadBalancing = serde_json::from_str(r#""random""#).unwrap();
        assert!(matches!(random, LoadBalancing::Random));
        assert_eq!(
            serde_json::to_string(&LoadBalancing::RoundRobin).unwrap(),
            r#""round_robin""#
        );
        assert!(matches!(
            default_load_balancing(),
            LoadBalancing::RoundRobin
        ));
    }

    /// Regression: PATCH `{"concurrency_limit": null}` must round-trip
    /// as Some(None), not None. Pre-fix the default `Option`
    /// deserializer collapsed JSON `null` to outer `None`, so
    /// `skip_serializing_if = "Option::is_none"` then dropped the
    /// field on re-serialize and the merge upstream never saw the
    /// clear → `unset concurrency_limit` from sekisho-cli silently
    /// no-op'd against the route.
    #[test]
    fn explicit_null_preserved_on_double_option_fields() {
        let cases = [
            ("concurrency_limit", r#"{"concurrency_limit": null}"#),
            ("host_rewrite", r#"{"host_rewrite": null}"#),
            ("path", r#"{"path": null}"#),
            ("redirect", r#"{"redirect": null}"#),
            ("idp_id", r#"{"idp_id": null}"#),
            (
                "regex_rewrite_pattern",
                r#"{"regex_rewrite_pattern": null}"#,
            ),
            (
                "regex_rewrite_substitution",
                r#"{"regex_rewrite_substitution": null}"#,
            ),
            (
                "session_cookie_samesite",
                r#"{"session_cookie_samesite": null}"#,
            ),
        ];
        for (field, input) in cases {
            let body: UpdateRoute =
                serde_json::from_str(input).unwrap_or_else(|e| panic!("{field}: parse: {e}"));
            let out =
                serde_json::to_value(&body).unwrap_or_else(|e| panic!("{field}: serialize: {e}"));
            assert!(
                out.get(field).map(|v| v.is_null()).unwrap_or(false),
                "{field}: re-serialized JSON dropped explicit null (got {out})"
            );
        }
    }

    /// Sibling sanity: omitting a field still produces an empty patch
    /// (no spurious nulls), so unrelated fields aren't touched.
    #[test]
    fn omitted_double_option_field_does_not_serialize() {
        let body: UpdateRoute = serde_json::from_str(r#"{"name": "x"}"#).unwrap();
        let out = serde_json::to_value(&body).unwrap();
        assert!(out.get("concurrency_limit").is_none());
        assert!(out.get("host_rewrite").is_none());
        assert!(out.get("path").is_none());
    }
}
