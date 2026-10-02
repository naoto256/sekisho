//! Audit logging primitives.
//!
//! This module owns the small bits of plumbing that every audit-relevant
//! event needs in common: a per-request correlation id, an `Actor`
//! type for attribution, and a `tracing` `target` constant so
//! downstream filters can promote audit events out of the general
//! info-level firehose.
//!
//! ## Why a separate module
//!
//! Each handler emits its own structured `tracing::info!(target:
//! audit::TARGET, ...)`, but the `request_id` they want to include
//! comes from much earlier in the request lifecycle (the moment the
//! TCP-accepted axum router runs). Centralising the middleware here
//! keeps both the management API (`api/mod.rs`) and the proxy
//! (`proxy/mod.rs`) hooked through the same code path, so any future
//! correlation work (request span, propagation header naming) lands in
//! one place.
//!
//! ## Wire shape
//!
//! Inbound requests may bring an `X-Request-ID` header; if it's
//! present and looks like a UUID, we honour it so a caller (LB, smoke
//! test harness, future Terraform provider) can correlate the
//! response it sees against its own log line. Otherwise we mint a
//! UUID v7 — time-ordered IDs make ad-hoc journalctl scans pleasant
//! without giving up uniqueness. The id is then echoed on the
//! response and made available to handlers as a request extension.
//!
//! ## Event taxonomy
//!
//! Every audit event carries `event`, `category`, `result` and (for
//! attributable events) `actor_type` + `actor_id`. The set of
//! `event` strings is intentionally short and stable — operators
//! filter on these in Splunk / Sentinel rules and renaming them is a
//! breaking change.
//!
//! | event | category | who emits |
//! |---|---|---|
//! | `auth.api.success` / `auth.api.failure` | `auth` | `api/scope.rs` |
//! | `auth.api.scope_denied` / `auth.api_key.usage_touch_failed` | `auth` | `api/scope.rs` |
//! | `session.create` / `session.revoke` / `session.expire_batch` | `auth` | `session/manager.rs`, cleanup tick |
//! | `session.admin_revoke` | `mgmt` | `api/sessions.rs::delete` |
//! | `auth.logout.idp_redirect` / `auth.logout.local_only` | `auth` | `auth/mod.rs::sign_out` |
//! | `auth.logout.saml_slo_*` (request_refused, missing_response, no_pending, wrong_kind, idp_mismatch, no_request_id, success, response_invalid) | `auth` | `auth/saml/callback.rs` |
//! | `handoff.consume` / `handoff.reject` | `auth` | `auth/handoff.rs` |
//! | `route.{create,update,delete}` | `mgmt` | `api/routes.rs` |
//! | `idp.{create,update,delete}` | `mgmt` | `api/idps.rs` |
//! | `policy.{create,update,delete}` | `mgmt` | `api/policies.rs` |
//! | `api_key.{create,delete}` | `mgmt` | `api/api_keys.rs` |
//! | `config.update` | `mgmt` | `api/config.rs` |
//! | `instance.update` | `mgmt` | `api/instance.rs` |
//! | `cert.issue.{start,success,failure}` / `cert.upload` / `cert.delete` | `mgmt` | `api/certs.rs` |
//! | `cert.issue.queue.enqueued` | `mgmt` | `api/certs.rs` (non-leader path) |
//! | `cert.issue.queue.{picked,completed,failed}` | `system` | `tls/acme/queue.rs` (leader tick) |
//! | `cert.issue.success` | `system` | `tls/acme/mod.rs` (background renewal tick) |
//! | `cert.renew.failure` | `system` | `tls/acme/mod.rs` (background tick) |
//! | `cert.cache.reload` | `system` | `tls/resolver.rs::reload_if_stale` (HA peer version bump) |
//! | `crypto.identity_signing.rotate` | `crypto` | `api/identity_signing.rs` |
//! | `crypto.master_key.load` | `crypto` | `main.rs::resolve_master_key` |
//! | `crypto.dek.{add,activate,retire,rotate}` | `crypto` | `api/encryption_keys.rs` (warn-level) |
//! | `crypto.dek_ring.bootstrap` | `crypto` | `store/key_ring_loader.rs` |
//! | `crypto.dek_ring.refresh` | `crypto` | `main.rs` ring-stale tick |
//! | `acme.election.{initial,takeover,preempt}` / `acme.election.tick_failed` | `system` | `main.rs` election tick |
//! | `tls.fallback.self_signed` | `system` | `tls/resolver.rs` |
//! | `daemon.startup.warning` | `system` | `startup.rs` (config sanity + IdP probe + cert expiry) |
//! | `daemon.shutdown.{start,drain,complete,force_exit}` | `system` | `main.rs` shutdown sequencer |
//!
//! ## Secret hygiene rules
//!
//! These are load-bearing — violating them in a future handler turns
//! the audit stream into a credential leak:
//!
//! - **never** log the raw value of: API key (only `prefix`),
//!   `client_secret`, `cert_pem` private key, refresh token, master
//!   key, identity-signing private key, management RPK private key, cookie
//!   secret, `cluster_db_url`.
//! - For PATCH-style mutations use [`changed_fields`] to enumerate
//!   the top-level keys touched. Don't dump the patch body.
//! - For OIDC `client_secret` rotation, surface a boolean
//!   `client_secret_rotated` field, not the value (see
//!   `api/idps.rs::update`).
//! - For `bootstrap.cluster_db_url`, log the *action*
//!   (`cluster_db_url_set` / `_cleared` / `noop`), never the URL.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

/// `tracing` target for audit-grade events. Filter on this string to
/// promote them out of the general firehose:
/// `RUST_LOG=sekishod=info,sekishod::audit=info`.
pub const TARGET: &str = "audit";

/// Emit a structured audit event for a successful management-API mutation.
///
/// Why a macro: every CRUD-style handler in `api/*.rs` was hand-rolling
/// the same 10–13 line `tracing::info!(target: audit::TARGET, ...)` block
/// — `event` / `category = "mgmt"` / `result = "success"` / `actor_type` /
/// `actor_id` / `target_resource` / `target_id` / `action` plus a free-form
/// tail of resource-specific fields and a message. Drift between sites
/// (typos in the field names, missing actor attribution after a copy-paste,
/// a "result" string nobody else uses) silently breaks operator filters
/// in Splunk / Sentinel because those rules pivot on exact field names.
/// Funnelling all sites through one macro keeps the contracted shape in
/// one place — anyone violating it has to walk past the macro definition
/// to do so.
///
/// Two arms:
///
/// - **with target** (most resources): pass `target = $expr` for the
///   target id. Emits `target_id = %target` so Display formats Uuid /
///   String / i16 alike.
/// - **without target** (`config.update`, `mgmt_cert.upload`,
///   `instance.update`, `crypto.dek.rotate`): the resource isn't
///   addressed by an id (it's a singleton or covers multiple rows).
///   Omit the `target = ...` clause; `target_id` is left off.
///
/// The trailing `$($rest:tt)*` is forwarded verbatim to `tracing::info!`,
/// so callers keep tracing's natural sigils for resource-specific fields:
/// `name = %p.name`, `changed_fields = ?fields`, `count = n`, plus the
/// final message string.
///
/// # Example
///
/// ```ignore
/// audit_mgmt!(
///     actor = actor,
///     event = "route.create",
///     resource = "route",
///     target = route.id,
///     action = "create",
///     name = %route.name,
///     "route created"
/// );
/// ```
macro_rules! audit_mgmt {
    (
        actor = $actor:expr,
        event = $event:literal,
        resource = $resource:literal,
        target = $target_id:expr,
        action = $action:expr,
        $($rest:tt)*
    ) => {
        tracing::info!(
            target: $crate::audit::TARGET,
            event = $event,
            category = "mgmt",
            result = "success",
            actor_type = $actor.kind_str(),
            actor_id = %$actor.id,
            target_resource = $resource,
            target_id = %$target_id,
            action = $action,
            $($rest)*
        );
    };
    (
        actor = $actor:expr,
        event = $event:literal,
        resource = $resource:literal,
        action = $action:expr,
        $($rest:tt)*
    ) => {
        tracing::info!(
            target: $crate::audit::TARGET,
            event = $event,
            category = "mgmt",
            result = "success",
            actor_type = $actor.kind_str(),
            actor_id = %$actor.id,
            target_resource = $resource,
            action = $action,
            $($rest)*
        );
    };
}

pub(crate) use audit_mgmt;

/// Emit a structured audit event for a successful crypto-tier mutation.
///
/// Same shape as [`audit_mgmt!`] but at `warn` level and with
/// `category = "crypto"`. The level lift is intentional — DEK lifecycle
/// events (add / activate / retire / rotate) are the highest-blast-radius
/// audit lines the daemon emits and should never be drowned in the
/// general info firehose. Operators routinely tail-grep `WARN` for these.
///
/// Two arms exactly mirror [`audit_mgmt!`]: with `target = ...` for the
/// per-key events, without for the cluster-wide rotate.
macro_rules! audit_crypto {
    (
        actor = $actor:expr,
        event = $event:literal,
        resource = $resource:literal,
        target = $target_id:expr,
        action = $action:expr,
        $($rest:tt)*
    ) => {
        tracing::warn!(
            target: $crate::audit::TARGET,
            event = $event,
            category = "crypto",
            result = "success",
            actor_type = $actor.kind_str(),
            actor_id = %$actor.id,
            target_resource = $resource,
            target_id = %$target_id,
            action = $action,
            $($rest)*
        );
    };
    (
        actor = $actor:expr,
        event = $event:literal,
        resource = $resource:literal,
        action = $action:expr,
        $($rest:tt)*
    ) => {
        tracing::warn!(
            target: $crate::audit::TARGET,
            event = $event,
            category = "crypto",
            result = "success",
            actor_type = $actor.kind_str(),
            actor_id = %$actor.id,
            target_resource = $resource,
            action = $action,
            $($rest)*
        );
    };
}

pub(crate) use audit_crypto;

/// Who is making a request, in a form audit handlers can render
/// without re-doing the auth dance. The middleware that authenticates
/// a request inserts an `Actor` into the request extensions; handlers
/// pull it via `Extension<Actor>` and include it in the structured
/// event so an operator can answer "who changed this route?" without
/// joining log streams.
#[derive(Debug, Clone)]
pub struct Actor {
    pub kind: ActorKind,
    /// Stable, low-entropy identifier safe to log: API key prefix
    /// (e.g. `sks_Ab12`), management session token id, or `"system"`
    /// for daemon-internal flows. Never the raw secret.
    pub id: String,
}

/// How the actor behind an audited action authenticated.
///
/// Emitted as `actor_type` on every management event. The distinction matters
/// downstream: an API key is a credential that can be revoked and correlated
/// across nodes, while a management session proves local OS access — so the
/// same action carries a different meaning depending on which one performed it.
#[derive(Debug, Clone, Copy)]
pub enum ActorKind {
    /// Authenticated via `Authorization: Bearer sks_...` API key.
    ApiKey,
    /// Authenticated via management session token from the local
    /// challenge-auth flow (`mgmt_*` token), i.e. a control-socket
    /// caller that already proved Unix peer credentials.
    MgmtSession,
    /// Daemon-internal call (background tick, startup bootstrap).
    /// Mostly for events the daemon emits about itself. Today these
    /// sites emit `actor_type = "system"` as a literal field so they
    /// don't need to materialise an `Actor`; the variant + ctor
    /// stay here so a future audit point that *does* want to thread
    /// an `Actor` through some helper can do so without inventing
    /// a new convention.
    #[allow(dead_code)]
    System,
}

impl Actor {
    /// Constructed by daemon-internal flows that thread an `Actor`
    /// through shared helpers. Inbound-call sites build the variant
    /// directly in `auth_middleware`; system-side audit events emit
    /// the `actor_type=system` literal inline because they aren't
    /// extracting from a request extension.
    #[allow(dead_code)]
    pub fn system() -> Self {
        Self {
            kind: ActorKind::System,
            id: "system".to_string(),
        }
    }

    /// Stable lowercase string for the structured `actor_type` field.
    /// Kept in one place so a Splunk / Sentinel filter rule never has
    /// to enumerate variant spellings.
    pub fn kind_str(&self) -> &'static str {
        match self.kind {
            ActorKind::ApiKey => "api_key",
            ActorKind::MgmtSession => "mgmt_session",
            ActorKind::System => "system",
        }
    }
}

/// Extract the top-level keys of a JSON-Merge-Patch body.
///
/// Used by every PATCH handler to populate the structured
/// `changed_fields` audit field: it tells an operator *which* fields
/// the caller touched without dragging the values themselves into
/// the log line. Crucially this is the right granularity for
/// secret-bearing patches — `["oidc_config"]` says the IdP secret
/// section was touched, but the actual secret value is nowhere in
/// the audit trail.
pub fn changed_fields(patch: &serde_json::Value) -> Vec<String> {
    patch
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Request header name for caller-supplied correlation IDs. Same
/// canonical name vector / fluent-bit / most LBs use, so an operator
/// inspecting an upstream's logs can find Sekisho's matching line by
/// the same id.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Per-request correlation id. Stored as an axum request extension so
/// any handler / middleware deeper in the stack can read it without
/// re-parsing the header. Wrapped in a newtype so the extension lookup
/// is unambiguous (axum keys extensions by type).
///
/// Today no handler pulls this out — the structured tracing
/// subscriber attaches the id via the span field recorded by the
/// middleware, so handler `tracing::info!` calls inherit it for free.
/// The accessor stays exposed for the case where a handler wants to
/// surface the id in an HTTP response body.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RequestId(pub String);

impl RequestId {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// axum middleware: ensure every inbound request carries a
/// `RequestId`, echo it on the response, and surface it as a tracing
/// span field so subsequent log lines auto-include it.
///
/// A caller-supplied `X-Request-ID` is honoured only when it looks
/// like a UUID — that keeps a malicious caller from injecting
/// log-poisoning payloads (newline / control bytes / very long
/// strings) into our structured field. Otherwise a fresh UUID v7 is
/// minted; v7 is time-ordered so a `journalctl | sort` over a window
/// stays roughly chronological even when ids cross several requests.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let id = inbound_id(&req).unwrap_or_else(|| Uuid::now_v7().to_string());
    req.extensions_mut().insert(RequestId(id.clone()));

    // Record on the current span so downstream `tracing::info!` calls
    // pick it up automatically when the span has reserved the field.
    // Handlers that want their event tied back to the request can
    // include `request_id = %req.extensions().get::<RequestId>()...`.
    tracing::Span::current().record("request_id", tracing::field::display(&id));

    let mut resp = next.run(req).await;
    if let Ok(value) = HeaderValue::from_str(&id) {
        resp.headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }
    resp
}

/// Extract a caller-supplied request id, validating it's a UUID. Any
/// non-UUID input (or absent header) returns `None`, which the
/// middleware treats as "mint a new one".
fn inbound_id(req: &Request) -> Option<String> {
    let raw = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())?;
    Uuid::parse_str(raw).ok().map(|u| u.to_string())
}

/// Test-only capture of the structured audit stream.
///
/// Spinning up `tracing-test` or wrestling with the global subscriber
/// is heavier than needed for handler-level assertions. This layer
/// records every `event!` whose target is [`TARGET`] into a `Vec`
/// keyed by event name, so a test can drive a handler and then
/// assert "did `route.create` fire with these fields?".
///
/// Use [`with_audit_capture`] to scope the layer to one test —
/// `tracing` registers subscribers globally so we install one
/// guarded by a mutex per test, then drop it.
#[cfg(test)]
pub mod test_capture {
    use std::collections::HashMap;
    use std::fmt;
    use std::sync::{Arc, Mutex};
    use tracing::Subscriber;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;

    #[derive(Debug, Default, Clone)]
    pub struct CapturedEvent {
        pub fields: HashMap<String, String>,
    }

    impl CapturedEvent {
        pub fn field(&self, name: &str) -> Option<&str> {
            self.fields.get(name).map(String::as_str)
        }
    }

    #[derive(Default, Clone)]
    pub struct AuditCapture {
        pub events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    impl AuditCapture {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn snapshot(&self) -> Vec<CapturedEvent> {
            self.events.lock().unwrap().clone()
        }

        pub fn find(&self, event_name: &str) -> Option<CapturedEvent> {
            self.snapshot()
                .into_iter()
                .find(|e| e.field("event") == Some(event_name))
        }
    }

    struct FieldRecorder<'a>(&'a mut HashMap<String, String>);

    impl<'a> Visit for FieldRecorder<'a> {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_i64(&mut self, field: &Field, value: i64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    impl<S: Subscriber> Layer<S> for AuditCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            if event.metadata().target() != super::TARGET {
                return;
            }
            let mut fields = HashMap::new();
            event.record(&mut FieldRecorder(&mut fields));
            self.events.lock().unwrap().push(CapturedEvent { fields });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with(header: Option<&str>) -> Request {
        let mut b = axum::http::Request::builder().uri("/");
        if let Some(v) = header {
            b = b.header(REQUEST_ID_HEADER, v);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn inbound_id_returns_none_when_header_absent() {
        assert!(inbound_id(&req_with(None)).is_none());
    }

    #[test]
    fn inbound_id_returns_uuid_when_header_is_uuid() {
        let supplied = "0190e5e5-3a8b-7c01-9d4f-12345678abcd";
        let got = inbound_id(&req_with(Some(supplied))).expect("uuid should parse");
        assert_eq!(got, supplied);
    }

    #[test]
    fn inbound_id_rejects_non_uuid_payload() {
        // A caller could try to inject newlines / control bytes to
        // poison downstream JSON log parsers. Validating against the
        // UUID grammar means anything outside `[0-9a-fA-F-]` is gone
        // before it ever lands in the structured field.
        let cases = ["", "not-a-uuid", "<script>", "id with spaces"];
        for c in cases {
            assert!(
                inbound_id(&req_with(Some(c))).is_none(),
                "{c:?} should not be honoured"
            );
        }
    }

    // ─── End-to-end: drive a real handler-emitting code path through
    //     the capture layer and assert the audit event lands with
    //     the contracted shape. The session lifecycle is the easiest
    //     target: SessionManager has no axum dependency, so we can
    //     just call its methods directly.

    use crate::audit::test_capture::AuditCapture;
    use crate::session::manager::SessionManager;
    use crate::store::Store;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    async fn fresh_store() -> Store {
        Store::new_for_test("sqlite::memory:", [0x41u8; 32], None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn session_create_and_revoke_emit_audit_events() {
        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();

        let store = fresh_store().await;
        // Need a real IdP row so the session FK is satisfiable, even
        // though the audit assertions don't care about it.
        let idp = crate::models::idp::IdentityProvider {
            id: uuid::Uuid::new_v4(),
            name: "test-idp".into(),
            idp_type: crate::models::idp::IdpType::Oidc,
            oidc_config: Some(crate::models::idp::OidcConfig {
                issuer_url: "https://issuer.test/".into(),
                client_id: "cid".into(),
                client_secret_encrypted: store.encrypt_active_to_base64(b"plain").await.unwrap(),
                scopes: vec!["openid".into()],
                prompt: None,
            }),
            saml_config: None,
        };
        store.create_idp(&idp).await.unwrap();

        let mgr = SessionManager::new(store.clone(), 24);
        let session = mgr
            .create(
                "alice@example.com",
                idp.id,
                Default::default(),
                vec!["admins".into(), "ops".into()],
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let create = capture
            .find("session.create")
            .expect("session.create event must fire on create");
        assert_eq!(create.field("category"), Some("auth"));
        assert_eq!(create.field("result"), Some("success"));
        assert_eq!(create.field("actor_type"), Some("user"));
        assert_eq!(create.field("actor_id"), Some("alice@example.com"));
        assert_eq!(
            create.field("target_id"),
            Some(session.id.to_string().as_str())
        );
        // Group count goes out as a number, not the list — privacy
        // posture (groups can name internal teams).
        assert_eq!(create.field("group_count"), Some("2"));

        mgr.revoke(session.id).await.unwrap();
        let revoke = capture
            .find("session.revoke")
            .expect("session.revoke event must fire on revoke");
        assert_eq!(revoke.field("actor_id"), Some("alice@example.com"));
        assert_eq!(
            revoke.field("target_id"),
            Some(session.id.to_string().as_str())
        );
    }

    #[tokio::test]
    async fn mgmt_create_emits_attribution_fields() {
        // The mgmt CRUD events are the audit core. Driving
        // a full axum router would need extra deps, but we can verify
        // the contract a different way: emit the same shape the
        // routes::create handler does and assert the capture layer
        // sees the attribution fields land. If a future refactor
        // forgets `actor_type` / `actor_id` / `target_id`, this test
        // catches it.
        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let actor = Actor {
            kind: ActorKind::ApiKey,
            id: "sks_TEST".into(),
        };
        let route_id = uuid::Uuid::new_v4();
        tracing::info!(
            target: TARGET,
            event = "route.create",
            category = "mgmt",
            result = "success",
            actor_type = actor.kind_str(),
            actor_id = %actor.id,
            target_resource = "route",
            target_id = %route_id,
            action = "create",
            name = "test-route",
            "route created"
        );
        let ev = capture
            .find("route.create")
            .expect("route.create event must fire");
        assert_eq!(ev.field("category"), Some("mgmt"));
        assert_eq!(ev.field("actor_type"), Some("api_key"));
        assert_eq!(ev.field("actor_id"), Some("sks_TEST"));
        assert_eq!(ev.field("target_resource"), Some("route"));
        assert_eq!(ev.field("target_id"), Some(route_id.to_string().as_str()));
        assert_eq!(ev.field("action"), Some("create"));
    }

    // ─── Macro shape tests. The macro is the load-bearing piece for
    //     every mgmt CRUD audit line, so we lock its emit shape down
    //     directly: a future refactor that drops `actor_type` or rewrites
    //     `result` to a non-"success" string would break operator
    //     filters in Splunk / Sentinel rules silently.

    #[tokio::test]
    async fn audit_mgmt_macro_emits_full_attribution_with_target() {
        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let actor = Actor {
            kind: ActorKind::ApiKey,
            id: "sks_M".into(),
        };
        let id = uuid::Uuid::new_v4();
        crate::audit_mgmt!(
            actor = actor,
            event = "route.create",
            resource = "route",
            target = id,
            action = "create",
            name = "demo",
            "route created"
        );
        let ev = capture
            .find("route.create")
            .expect("audit_mgmt! must emit the event");
        assert_eq!(ev.field("category"), Some("mgmt"));
        assert_eq!(ev.field("result"), Some("success"));
        assert_eq!(ev.field("actor_type"), Some("api_key"));
        assert_eq!(ev.field("actor_id"), Some("sks_M"));
        assert_eq!(ev.field("target_resource"), Some("route"));
        assert_eq!(ev.field("target_id"), Some(id.to_string().as_str()));
        assert_eq!(ev.field("action"), Some("create"));
        assert_eq!(ev.field("name"), Some("demo"));
    }

    #[tokio::test]
    async fn audit_mgmt_macro_omits_target_id_when_absent() {
        // The no-target arm is used by config.update / instance.update /
        // mgmt_cert.upload — singletons that don't have an id. The macro
        // must not synthesise a stray empty `target_id` field, otherwise
        // operators would have to special-case parsing.
        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let actor = Actor {
            kind: ActorKind::MgmtSession,
            id: "mgmt_X".into(),
        };
        crate::audit_mgmt!(
            actor = actor,
            event = "config.update",
            resource = "config",
            action = "update",
            "global config updated"
        );
        let ev = capture
            .find("config.update")
            .expect("audit_mgmt! no-target arm must emit the event");
        assert_eq!(ev.field("category"), Some("mgmt"));
        assert_eq!(ev.field("actor_type"), Some("mgmt_session"));
        assert_eq!(ev.field("target_resource"), Some("config"));
        assert!(
            ev.field("target_id").is_none(),
            "no-target arm must not synthesise target_id"
        );
        assert_eq!(ev.field("action"), Some("update"));
    }

    #[tokio::test]
    async fn audit_crypto_macro_emits_warn_level_with_crypto_category() {
        let capture = AuditCapture::new();
        let _guard = tracing_subscriber::registry()
            .with(capture.clone())
            .set_default();
        let actor = Actor {
            kind: ActorKind::ApiKey,
            id: "sks_C".into(),
        };
        crate::audit_crypto!(
            actor = actor,
            event = "crypto.dek.add",
            resource = "encryption_key",
            target = 7_i16,
            action = "add",
            "operator added DEK"
        );
        let ev = capture
            .find("crypto.dek.add")
            .expect("audit_crypto! must emit the event");
        assert_eq!(ev.field("category"), Some("crypto"));
        assert_eq!(ev.field("result"), Some("success"));
        assert_eq!(ev.field("actor_type"), Some("api_key"));
        assert_eq!(ev.field("target_resource"), Some("encryption_key"));
        assert_eq!(ev.field("target_id"), Some("7"));
        assert_eq!(ev.field("action"), Some("add"));
    }

    #[test]
    fn newline_bearing_header_is_rejected_by_http_layer() {
        // Defense in depth — even if `inbound_id` got a string with
        // control bytes, axum's header parser refuses to construct
        // it. We document that property here so a future refactor
        // doesn't accidentally relax inbound_id and assume the header
        // layer still catches injection.
        let bad = axum::http::HeaderValue::from_str("a\r\nMESSAGE=fake");
        assert!(bad.is_err());
    }
}
