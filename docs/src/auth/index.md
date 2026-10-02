# Authentication

Sekisho supports two authentication protocols out of the box:

- **OIDC (OpenID Connect)** — for Google Workspace, Keycloak,
  Auth0, GitHub OAuth (with caveats), and any other standards-compliant
  OIDC issuer.
- **SAML 2.0** — for Microsoft Entra ID, ADFS, Shibboleth, OneLogin,
  and most enterprise SSO setups that predate OIDC.

A single Sekisho instance can host any number of IdP entries and
target them per route via `idp_id`.

## Common flow

Regardless of protocol, the high-level flow is the same:

1. The user requests a protected route.
2. Sekisho sees no valid session and redirects them to the IdP
   (OIDC `/authorize` or SAML AuthnRequest).
3. The IdP authenticates the user and posts back to Sekisho's
   callback URL (`/.sekisho/callback` for OIDC,
   `/.sekisho/saml/acs` for SAML).
4. Sekisho verifies the response (signature, nonce, audience, etc.)
   and creates the session.
5. Session cookies are host-only, so the cookie set while handling the
   callback on `auth_domain` is not sent to `app.example.com`. Sekisho
   therefore redirects the browser through
   `/.sekisho/session-handoff` on the route's own host with a
   short-lived encrypted token; that host sets its own cookie and
   forwards to the original URL. Each host ends up with an independent
   cookie for the same server-side session. See
   [Cross-host session handoff](../design/architecture.md#5-cross-host-session-handoff).
6. Subsequent requests to that host carry its cookie and bypass the
   IdP roundtrip until the session expires.

## What gets validated

For **OIDC**:

- JWT signature against the issuer's published JWKS (with `kid`
  matching, no algorithm fallback).
- `iss`, `aud`, `exp`, `nbf`, and `nonce` claims.
- Algorithm whitelist: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`.
- PKCE (`code_verifier` / S256) on the authorization code exchange.

For **SAML**:

- XML signature on the response or assertion, RSA-PKCS1 with SHA-256,
  SHA-384 or SHA-512. RSA-SHA1 is refused.
- Exclusive XML Canonicalization (`xml-exc-c14n#`) is applied to a
  parsed DOM, so the bytes that were signed really are the ones being
  verified.
- `Conditions/NotBefore`, `NotOnOrAfter`, `Audience`.
- `InResponseTo` matches the AuthnRequest's `ID`.

For both, IdP authentication state (the `state` parameter for OIDC,
the request `ID` for SAML) is single-use, has a 10-minute lifetime,
and is generated from a cryptographically secure RNG.

## Sessions

A successful authentication creates a session row containing the
user's email, groups, IdP-provided claims, and an expiration. The
session ID is a UUID, signed into a cookie via the
`signed jar` (HMAC). Cookies are `HttpOnly`, `Secure`, and host-only.
`SameSite` is `Lax` unless the route the cookie is being set for
overrides it with `session_cookie_samesite` (`lax`, `strict` or
`none`); on a cross-host handoff the value comes from the route being
handed off to.

Two independent limits apply. The absolute lifetime is
`session_lifetime_hours` (default 8), fixed when the session is created. On
top of that a session expires after **30 minutes of inactivity**, evaluated
against `last_accessed_at` with a 60-second enforcement grace.

The idle check is made by the database rather than by the node serving the
request, so every peer in an HA deployment reaches the same verdict from the
same durable value. Access-time writes are coalesced to at most one per
minute per session, which is why the recorded time can lag a request by up to
that interval.

Idle expiry is not a sliding window in the other direction: activity does not
extend `expires_at`. A session ends at whichever limit it reaches first.

## Authorization

Authentication only proves *who* the session is. *What* that session
is allowed to reach is decided by the route's `access.policy` — a
single boolean expression in the [Policy DSL](../configuration/policies.md).
That expression can reference one or more named
[`Policy`](../configuration/policies.md) objects via `policy.<name>`,
spell the rule inline, or combine both with `and` / `or`.

```text
# Inline expression
claim.groups in ["sre", "ops"]
or (claim.email == "oncall@example.com" and client.ip in ["10.0.0.0/8"])
```

```text
# Reference one named policy
policy.sre-or-ops

# Combine two named policies — replaces the old list-of-names form
policy.sre-or-ops or policy.oncall-bypass
```

The expression language has access to claim values
(`claim.username`, `claim.email`, `claim.groups`, plus any custom
claim the IdP returned), client network details (`client.ip`,
`client.port`), HTTP request fields (`request.method`,
`request.path`, `request.host`, `request.header.*`), and the local
clock (`time.*`, `date.*`). It supports the usual `==` / `!=` /
ordering operators, regex match (`~=` / `!~`), CIDR membership for
IP literals, and `in` / `not in` for list membership. See
[Policies](../configuration/policies.md) for the full grammar,
fields, and evaluation rules.

The single special case is
`access.allow_public_unauthenticated_access`, which bypasses both
authentication and policy evaluation — use it for health endpoints
and other deliberately public routes.

Continue with [OIDC](./oidc.md), [SAML](./saml.md), or
[SAML with Microsoft Entra ID](./saml-entra.md) for the protocol
specifics.
