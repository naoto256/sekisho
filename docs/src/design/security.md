# Security

This chapter records Sekisho's current security controls, the
regression coverage behind them, the limitations that are true today,
and the trade-offs that were made deliberately. Rotating keys is an
operational task rather than a security review, so it lives in
[Encryption keys](../operating/encryption-keys.md).

## Current controls

- **SQL injection**: every query uses bound parameters.
- **XML external entities (XXE)**: the XML parser rejects DTDs and
  external entities, so SAML payloads cannot exfiltrate data through
  entity expansion.
- **JWT verification**: full chain — `iss`, `aud`, `exp`, `nbf`,
  `nonce`, `kid` matching, no algorithm fallback, JWKS refetch on
  unknown `kid`.
- **SAML signature verification**: unconditional, with a pure-Rust
  Exclusive XML Canonicalization implementation that operates on a
  parsed DOM. There is no code path that bypasses signature
  verification.
- **Daemon session cookies**: `HttpOnly`, `Secure`, signed with HMAC,
  and host-only — no `Domain` attribute, so the cookie never widens to
  a parent domain. `SameSite` defaults to `Lax` and a route may
  override it.
- **Daemon federated-auth correlation**: pending OIDC and SAML
  callback state is stored in the service database. Lookups are
  expiry-aware, and an atomic take ensures each state is consumed at
  most once. The take is the commit point rather than the first step:
  the OIDC callback looks the state up, checks the stored kind and the
  browser nonce, exchanges the authorization code, and only then takes
  it — so a failed exchange does not burn the state. SAML ACS and SLO
  likewise validate the stored kind, IdP and request binding, signature,
  and protocol response first, then take the state. A missing row or a callback that loses the atomic take
  does not create a session.
- **WebUI CSRF protection**: stateless double-submit. Safe requests
  reuse or mint the `_sekisho_csrf` cookie and expose the same token
  in the rendered page's CSRF meta tag. Mutating requests require a
  non-empty, constant-time-equal cookie and `X-CSRF-Token` header.
  The cookie is scoped with `Secure`, `HttpOnly`, and `SameSite=Lax`.
- **WebUI guard and response headers**: when the Basic guard is
  configured, it rejects missing or invalid credentials before
  handlers run. WebUI responses include CSP, HSTS,
  `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`.
  These statements describe the WebUI surface, not daemon proxy or
  management responses.
- **PKCE** on OIDC.
- **Open-redirect protection**: `safe_redirect` allows only hostnames
  that match a registered route.
- **Secret encryption at rest**: current writes use the active DEK
  with XChaCha20-Poly1305. The operator-provisioned KEK wraps the DEK
  ring; it is supplied through an operator-managed credential file and never
  accepted as an environment value.
- **Internal header spoofing**: `X-Sekisho-*` and `X-Forwarded-*` are
  stripped from incoming requests before being added by the proxy.
- **HTTP connection boundaries**: the proxy removes the static hop-by-hop set
  and every field nominated by every `Connection` header value in both
  directions. WebSocket requests and upstream 101 responses must pass strict
  handshake validation before a tunnel opens. Route configuration cannot
  add or remove framing, forwarding, Sekisho, or WebSocket handshake fields.
- **Default-deny policy**: an empty policy denies everything.
- **TLS by default**: requires the explicit `--no-tls` flag to
  disable.
- **Body and admission limits**: request bodies are capped at 1 MiB on
  the management API and 10 MiB on the proxy. Up to 50 ordinary
  management requests, four shared health/readiness probes, and 20
  `POST /auth/challenge` requests may run concurrently. Probe and challenge
  saturation is isolated from the ordinary management budget. The proxy
  has its own in-flight cap of 500 requests.
- **CORS**: `/.sekisho/*` endpoints have an explicit empty allow-list
  (deny). The proxy itself returns no CORS headers by default.
- **Sanitised error responses**: deserialisation and validation errors
  are generalised before being returned, so client input is never
  echoed back.
- **Refusal pages disclose nothing**: when the proxy answers a denial
  with HTML rather than JSON, the page is fixed text chosen by status
  code. It never contains the request path, the hostname asked for, the
  signed-in user, the upstream, or an internal error string — so a page
  that reaches the wrong person still tells them nothing. It loads no
  external asset, which keeps a refusal from becoming a request to a
  third party. It carries a content security policy that forbids every
  source, `nosniff`, `no-referrer`, and `no-store` so that it is not
  cached and the URL that was refused is not leaked onward in a
  referrer.

## Current regression coverage

Security-relevant integration coverage is described by durable
contracts rather than a test count:

- `sekisho-webui`'s actual-binary security contract exercises a
  successful Basic-authenticated page, a rejected CSRF mismatch,
  missing and invalid Basic credentials, the CSRF cookie/meta-token
  relationship, and all six WebUI security headers. Rejected guard
  and CSRF requests are verified not to reach the upstream.
- `sekisho-cli`'s actual-binary version-handshake test verifies that
  a server version mismatch stops the client before authenticated
  configuration or shell work and does not expose the API key.
- `sekishod`'s actual-process smoke test reaches the management TLS
  health endpoint, sends `SIGTERM`, and verifies a successful bounded
  exit, ordered shutdown audit events, control-socket cleanup, and
  master-key redaction.

These process tests do not claim end-to-end coverage of authenticated
public proxy traffic, a live external IdP, or a live upstream
WebSocket. Those remain separate integration boundaries.

## Known limitations

Things that are true today and that could bite you. Each one says what
the effect is, when it applies, and what you can do about it.

### A stalled upstream consumes the route's whole timeout budget

Every proxied request is bounded by the route's `timeout_ms` (default
30 000 ms); exceeding it returns `504`. Underneath that, only some
routes get a separate connect timeout: those that need a dedicated HTTP
client because they set `tls_skip_verify` or `host_rewrite` connect with
a 10-second connect timeout and a 60-second cap. Other routes go through
a shared client with no transport-level timeout of its own.

**Effect.** On those other routes, a TCP connect that hangs is not
failed early — it simply spends the route's `timeout_ms` before the
request is cut off.

**What to do.** Set `timeout_ms` to a value you are willing to wait.
It is the bound that actually holds.

### An established WebSocket tunnel is not time-bounded

`timeout_ms` bounds the WebSocket handshake. Once the tunnel is open it
runs until one side closes it.

**Effect.** A route with `enable_websocket` can hold connections
indefinitely.

**What to do.** This is deliberate — a long-lived socket is the point.
Use `concurrency_limit` on the route if the number of simultaneous
tunnels is the concern.

### Shutdown does not prove every in-flight connection finished

Shutdown signalling stops the listener accept loops and the tracked
periodic and background tasks, with a bounded join and abort. It does
not assert that every already-accepted connection or startup task has
terminated.

**Effect.** A restart can cut an in-flight request.

**What to do.** In HA, drain a node at the load balancer before
restarting it.

### Operational notes

- **API keys** are stored as HMAC-SHA256 values and verified with a
  constant-time comparison. A newly created raw key is returned to
  the operator once; the daemon does not auto-generate an initial API
  key at startup.
- **Master key provisioning** is operator-owned. The daemon requires an exact
  64-hex-character credential file selected by `SEKISHO_MASTER_KEY_FILE` and
  neither generates nor displays the key. A single terminal LF or CRLF is
  accepted; other whitespace is rejected.
- **Sliding-window sessions** are not supported. Sessions have a
  fixed `expires_at` set at creation; `last_accessed_at` is recorded
  but does not extend the lifetime.
- **API key scopes** are enforced. Every management endpoint requires
  one of `management:read`, `management:write` or `management:admin`,
  and the levels are hierarchical. A missing or unknown key is `401`;
  an authenticated key with insufficient scope is `403`. Local-auth
  `mgmt_` session tokens satisfy every level without a scope check,
  because redeeming one already requires running as the daemon's
  service user. See [API Keys](../configuration/api-keys.md).

## Threat model

Sekisho is designed to:

- Stop unauthenticated traffic from reaching protected upstreams.
- Bind every authenticated session to a specific user and a specific
  set of group claims, signed by a trusted IdP.
- Make user identity available to the upstream without giving the
  upstream a way to forge it (the `X-Sekisho-*` headers cannot be
  injected from the public side because they are stripped on
  ingress).
- Encrypt secrets at rest so a compromised SQLite file alone does
  not yield IdP client secrets, certificate keys, or the cookie
  signing key.

It is **not** designed to:

- Inspect or filter request bodies (it is not a WAF).
- Provide its own user database. All identity comes from external
  IdPs.
- Hide the upstream from a user authenticated to it. Once
  authentication succeeds, the user can do whatever the upstream
  allows.
- Defend against a malicious or compromised IdP. Sekisho trusts the
  IdP's signing keys; if those are stolen, anyone holding them can
  mint sessions.

## Reporting issues

For bugs without security implications, open a GitHub issue. For
suspected vulnerabilities, contact the maintainer privately.
