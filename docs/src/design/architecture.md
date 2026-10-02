# Architecture

This chapter describes the internal structure of Sekisho and the
design decisions that shape it. It is meant for operators who want to
understand what is going on under the hood, and for contributors who
want to extend the proxy without breaking it.

## Crate layout

Sekisho ships three programs, built from one workspace and released
together so they are always on the same version:

```text
sekishod/        The daemon: proxy + management API + ACME client.
sekisho-cli/     Interactive management shell (JunOS-style).
sekisho-webui/   Admin web UI (axum + Maud + HTMX).
```

Those are the three Debian packages. The workspace holds two more
crates that ship inside them rather than on their own —
`sekisho-api-protocol` (the wire types both clients and the daemon
share) and `sekisho-management-rpk-tls` (the pinned-key TLS used on
the management listener).

The three are **version-locked**: every client verifies the server
version on startup. They then diverge on purpose — `sekisho-cli`
exits, `sekisho-webui` degrades to a badge. See
[Version-locked clients](#3-version-locked-clients) below.

Within `crates/sekishod/src`:

```text
main.rs              Entry point, server bootstrap, periodic tasks.
config.rs            CLI args / environment.
error.rs             Common error type to HTTP response.
crypto.rs            ChaCha20-Poly1305 helpers.
validation.rs        Input validation (operates on full Create structs).
observability.rs     Prometheus metrics.

models/              Data model (plain Serialize / Deserialize).
  route.rs           Route, Policy, RedirectRule, HeaderModifications
  idp.rs             IdentityProvider, OidcConfig, SamlConfig
  config.rs          GlobalConfig
  session.rs         Session
  cert.rs            Certificate
  api_key.rs         ApiKey

store/               SQLite storage layer.
  mod.rs             Store init, migrations.
  merge.rs           JSON Merge Patch (RFC 7396), shared by all updates.
  route_cache.rs     In-memory route cache (hostname+path -> Arc<Route>).
  route.rs           Route CRUD.
  idp.rs             IdP CRUD.
  config.rs          GlobalConfig get/update.
  session.rs         Session CRUD + expired-row cleanup.
  cert.rs            Certificate CRUD.
  api_key.rs         API key CRUD + keyed-HMAC verification.
  secrets.rs         Encrypted secret KV store.

api/                 Management REST API (axum).
  mod.rs             Router, auth middleware, SanitizedJson, /version.
  routes.rs          /routes CRUD.
  idps.rs            /idps CRUD (client_secret redacted).
  sessions.rs        /sessions (paginated).
  certs.rs           /certs (durable ACME queue admission on POST).
  api_keys.rs        /api_keys.
  config.rs          /config.

proxy/               Reverse proxy engine.
  mod.rs             ProxyState, Router, ACME challenge dispatch.
  handler.rs         Request handler (route match -> auth -> forward).
  transform.rs       RequestTransform pipeline (registry pattern).
  upstream.rs        Upstream selection: round-robin cursor or uniform random.

auth/                Authentication.
  oidc/              OIDC client (JWKS, JWT verification, PKCE).
  saml/              SAML SP (AuthnRequest, ACS, signature verify).
  handoff.rs         Cross-host session handoff tokens.
  strategy.rs        Auth strategy (OIDC vs SAML by IdP type).
  middleware.rs      AuthStateStore (CSRF state).
  mod.rs             Sign-out, userinfo, safe_redirect helper.

session/             Session management.
  manager.rs         SessionManager (create, validate, revoke).
  cookie_manager.rs  Signed cookie jar.

tls/                 TLS + ACME.
  acme/              ACME client (HTTP-01, auto-renewal).
  resolver.rs        SNI cert resolver (self-signed fallback).
```

## Design principles

The codebase follows a few patterns that exist specifically to make
adding features cheap. They are the reason the project is small
relative to what it does.

### 1. Registry pattern: extending the request pipeline

Every request transformation that happens between matching a route
and forwarding to the upstream is a `RequestTransform` registered on
a pipeline:

```rust
TransformPipeline::new()
    .register(StripInternalHeaders)   // remove x-sekisho-*, x-forwarded-*
    .register(RewriteHost)            // host_rewrite / preserve_host_header
    .register(AddProxyHeaders)        // x-forwarded-host, x-forwarded-proto
    .register(AddIdentityHeaders)     // x-sekisho-user, x-sekisho-groups
    .register(ApplyRouteHeaders)      // headers.add / headers.remove
```

To add a new transformation:

1. Implement `RequestTransform`.
2. Call `.register()` on the pipeline.

`handler.rs` does not need to change.

HTTP connection boundaries are deliberately outside that extensible pipeline.
One crate-private component removes the static hop-by-hop fields and every
field nominated by all `Connection` header values on requests and responses.
It also validates WebSocket handshakes, pins the new connection's
`Connection` and `Upgrade` fields, and appends a `Via` field containing the
received HTTP protocol version and the `sekisho` pseudonym, but no package
version. Route header operations cannot override framing, forwarding, Sekisho,
or WebSocket handshake fields; older persisted operations for those fields are
ignored when a route snapshot is loaded and again when it is applied.

### 2. JSON Merge Patch: extending the data model

Every update operation in the storage layer goes through a single
RFC 7396 JSON Merge Patch implementation:

```rust
// store/route.rs — same pattern regardless of field count
let mut base: Value = serde_json::from_str(&json_str)?;
merge::json_merge(&mut base, &patch);
let route: Route = serde_json::from_value(base)?;
```

Add a field to a model and the storage code does not change.

### 3. Version-locked clients

The daemon exposes only data and integrity: CRUD for every resource,
plus referential / format / uniqueness checks. It does **not** ship a
schema API, a resource registry, or any field metadata. Each client
(`sekisho-cli`, `sekisho-webui`) ships its own compile-time knowledge of
every resource — the forms, the field types, the nav order, the list
columns, everything — and on startup calls
`GET /.sekisho/api/v1/version` to confirm it is talking to a matching
server. Mismatch is a hard startup failure with a clear message.

Why: the earlier scheme served a JSON-Schema tree from the daemon and
had the clients render a generic CRUD UI from it. That sounded
decoupled in theory but leaked UI-only concerns back into the data
model (field visibility flags, nav order, status pills) and still
produced UX that looked generic. In practice the pair was already
shipping from the same source tree — making the version lock
explicit lets each client write the best UX it can for the resources
it knows.

Adding a resource or a field therefore touches three crates. Adding
a non-UI-visible field to an existing resource touches one (just
`crates/sekishod/src/models/*.rs`).

### 4. Authentication strategy: branching on IdP type

```rust
match idp.idp_type {
    IdpType::Oidc => initiate_oidc(...),
    IdpType::Saml => initiate_saml(...),
}
```

Each route can specify `idp_id`. If unset, `config.default_idp_id` is
used. Adding a new IdP type means adding a variant to `IdpType` and a
branch to the strategy.

### 5. Cross-host session handoff

Session cookies are host-only (no `Domain` attribute). When a user
authenticates for, say, `app.example.com` but the IdP callback lands
on the configured `auth_domain` (e.g. `auth.example.com`), the daemon
mints a short-lived encrypted handoff token and redirects the browser
to `https://app.example.com/.sekisho/session-handoff?t=<token>`. The
target host verifies the token, sets its own host-only cookie, and
redirects to the original path. Each host ends up with an independent
cookie for the same server-side session.

See `crates/sekishod/src/auth/handoff.rs`.

### 6. Explicit activation

Routes are created `enabled: false` and only serve traffic after the
operator runs `enable route <name>` (or clicks **Enable** in
sekisho-webui). Enabling is where client-side orchestration decides
whether a certificate needs to be minted: if the route's
`tls_downstream` is `acme` and no cert exists for the hostname, the
client waits for the durable issuance queue before flipping `enabled` to `true`.
The daemon itself does not own this lifecycle — from its perspective
`enabled` is just another boolean field.

## Request lifecycle

### Proxy request

```text
Client
  -> TLS termination (rustls, SNI)
  -> Validate and decode the origin-form request target exactly once
  -> Route matching (RouteCache: hostname + canonical path prefix)
     (disabled routes are skipped -> 404)
  -> Redirect? -> 302
  -> Auth check
       - Public route -> optional session read -> forward
       - Protected route
           - Valid session -> policy evaluation (groups/emails/domains)
               - Allow -> Transform pipeline -> upstream -> response
               - Deny -> 403
           - No session -> auth strategy -> OIDC redirect / SAML AuthnRequest
```

### Authentication callback

```text
IdP
  -> /.sekisho/callback (OIDC) or /.sekisho/saml/acs (SAML)
  -> Code exchange / assertion parse
  -> JWT signature verification (JWKS) or XML signature verification (X.509)
  -> Nonce check
  -> Session create
  -> If the target host matches the callback host: set cookie, redirect
  -> Otherwise: mint handoff token, 302 to the target host's
     /.sekisho/session-handoff so the cookie ends up on the right host
```

## Storage

Two databases. Node-local settings — the bind addresses and the
pointer to the cluster database — live in a per-instance SQLite file
(WAL mode) that every node always has. Everything else lives in the
service database, which is that same SQLite file in the single-node
default and a shared PostgreSQL in HA. Most data is stored as JSON in
a TEXT column:

| Table              | Purpose                       | Indexes                              |
|--------------------|-------------------------------|--------------------------------------|
| routes             | Route definitions             | PK(id), UNIQUE(name)                 |
| identity_providers | IdP configurations            | PK(id), UNIQUE(name)                 |
| global_config      | Global settings (singleton)   | PK(id=1)                             |
| sessions           | User sessions                 | PK(id), idx(user_id), idx(expires_at)|
| certificates       | TLS certificates              | PK(id), UNIQUE(domain), idx(expires_at)|
| api_keys           | Management API keys           | PK(id), UNIQUE(key_hash)             |
| secrets            | Encrypted secret KV           | PK(key)                              |

### In-memory caches

- **Route generation**: one database statement reads the route version and
  ordered route rows from one SQLite statement snapshot or PostgreSQL
  READ COMMITTED statement snapshot. Sekisho validates and builds one
  immutable generation containing the route cache, compiled rewrites,
  upstream-client cache, load-balancing counters, and stable admission-budget
  references, then publishes it as one state transition. Proxy requests read
  that state only; they do not probe the database. The `RouteCache` inside it
  is `hostname -> Vec<Arc<Route>>`, scanned to select the best
  case-sensitive, end-or-slash prefix match, with disabled routes filtered
  out. A separate scan finds the longest ASCII-casefolded prefix; when it is
  longer than the best exact match, it shadows that shorter exact
  match instead of falling through. Invalid route data withdraws publication
  immediately and never partially activates. A coherent database observation
  error marks readiness unavailable but may keep a previously valid generation
  for less than 30 seconds; repeated errors do not extend that interval.

## Security boundaries

- **Master key**: read once from the operator-provisioned credential file
  selected by `SEKISHO_MASTER_KEY_FILE`. Never written to the database or
  accepted as an environment value.
- **Cookie signing key**: encrypted with the master key, stored in
  `secrets`.
- **IdP client secrets**: encrypted at rest. API responses redact
  them as `**REDACTED**`.
- **Certificate private keys**: encrypted at rest.
- **API keys**: stored as `HMAC-SHA256(master_key, raw_key)` and verified
  in constant time, so a database dump alone cannot be attacked
  offline. Used as bearer tokens, and scoped — see
  [API Keys](../configuration/api-keys.md).
- **Session cookies**: signed jar (HMAC), `HttpOnly`, `Secure`,
  host-only, `SameSite` defaulting to `Lax` with a per-route
  override.
- **Handoff tokens**: ChaCha20-Poly1305 sealed with the master key,
  60 s TTL, single-use via a nonce store, bound to the target host.
- **Redirects**: only hostnames that match a registered route are
  accepted (open-redirect protection).
- **Referrer-Policy**: `no-referrer` on every auth redirect so code /
  state / handoff tokens do not leak via `Referer`.

## Cost of adding a field

Adding, for example, `cors_allow_preflight: bool` to `Route`:

| File                          | Change                                               |
|-------------------------------|------------------------------------------------------|
| `crates/sekishod/src/models/route.rs`  | Add the field with `#[serde(default)]`.              |
| `crates/sekishod/src/models/route.rs`  | Add the field to `CreateRoute` / `UpdateRoute` / `into_route()`. |

That is everything on the server. Storage does not change (JSON
Merge Patch is generic), validation operates on `&CreateRoute`, the
proxy handler goes through the transform pipeline.

If the field needs to be editable from the UI, also touch the
clients:

| File                              | Change                                      |
|-----------------------------------|---------------------------------------------|
| `crates/sekisho-cli/src/resources.rs`       | Add a `FieldNode` entry for the field.      |
| `crates/sekisho-webui/src/views/routes.rs`   | Render the field in the create/edit form.   |

Because the clients are version-locked they come along in the same
release. Adding a field the UI does not need to surface skips this
client step entirely.
