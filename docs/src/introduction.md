# Introduction

**Sekisho** is a Rust-based identity-aware proxy (IAP) that sits in front of
internal web applications and brokers authentication on their behalf.
Requests are intercepted at TLS termination, authenticated against an
external identity provider (OIDC or SAML), authorized against per-route
policies (groups, emails, domains), and only then forwarded to the
upstream backend.

The name "Sekisho" (関所) refers to the checkpoint stations of
Edo-period Japan, where every traveller had to present credentials
before being allowed to pass. The proxy carries the same posture:
every request must pass through identity and policy checks before
it is relayed to the upstream.

## Why Sekisho?

Most teams running internal web tooling (Grafana, Cockpit, Kibana, internal
dashboards, honeypot consoles) face the same problem:

- The application has weak or no authentication of its own.
- Putting it behind a corporate VPN is heavy-handed for a single dashboard.
- Bolting OIDC into each app individually is repetitive and error-prone.
- Existing IAPs each fit a particular shape — managed SaaS,
  config-file-only, or fronted by a separate TLS terminator — and none of
  them quite matches "drop a single self-contained binary on a host that
  also speaks ACME and SAML natively."

Sekisho was built to be a **single small Rust binary** that you drop on a
host, point at your IdP, and use to gate any number of upstreams behind
SSO — with everything driven by a JSON-over-HTTP management API, an admin
web UI, and an interactive shell.

## What Sekisho can do

- **Identity-aware reverse proxy**: per-route authentication and
  authorization based on user identity, group membership, email, or
  email domain.
- **OIDC and SAML support**: integrate with Google Workspace, Microsoft
  Entra ID, Keycloak, or any standards-compliant IdP.
- **TLS termination with automatic ACME**: certificates are obtained and
  renewed from Let's Encrypt over HTTP-01.
- **Path-based routing**: longest-prefix matching lets multiple apps
  share a hostname.
- **Header injection**: a route that opts in with `enable_signed_identity`
  receives `X-Sekisho-User`, `X-Sekisho-Groups` and a signed
  `X-Sekisho-Jwt`, so the upstream can verify the identity rather than
  re-authenticating. The flag governs all three: a route without it gets
  no `X-Sekisho-*` headers at all.
- **WebSocket and gRPC pass-through**: full-duplex tunnelling, relayed in
  both directions until one side closes.
- **HTTPS redirect and HSTS**: a small HTTP listener handles ACME
  challenges and redirects to HTTPS — but only for hostnames Sekisho
  already publishes; anything else is refused rather than redirected.
- **HA without a coordination sidecar**: two or more `sekishod` peers share
  state (routes, sessions, ACME orders, DEK ring) through the same Postgres.
  Sekisho elects its own ACME leader in that database, so there is no etcd,
  Consul or agent to run for Sekisho itself — the Postgres cluster underneath
  still needs whatever HA mechanism you choose for it.
- **Encrypted secrets at rest**: IdP client secrets, certificate private
  keys, and the cookie signing key are sealed with ChaCha20-Poly1305 using
  per-record DEKs wrapped by a master KEK. The KEK is read from an
  operator-provisioned credential file named by `SEKISHO_MASTER_KEY_FILE`;
  passing the key itself through the environment is refused at startup.

## What Sekisho is not

- It is not a WAF. It does no inspection of request bodies beyond
  forwarding.
- It is not a forward proxy. Clients connect directly to Sekisho by
  hostname (typically via DNS).
- It is not a service mesh. There is no upstream-side agent.
- It does not currently issue its own user accounts; identity always
  comes from an external IdP.

## Three binaries

| Binary           | Role                                                          | Package          |
|------------------|---------------------------------------------------------------|------------------|
| `sekishod`       | The daemon: TLS proxy + management REST API + ACME client.    | `sekishod`       |
| `sekisho-cli`    | A JunOS-style interactive shell for the management API.       | `sekisho-cli`    |
| `sekisho-webui`  | A small admin web UI over that same API.                      | `sekisho-webui`  |

All three ship from the same source tree but as **three separate `.deb`
packages** so you can install only what each host needs (e.g. `sekishod`
alone on a proxy peer, `sekisho-cli` on an admin workstation). They share
an explicit management API version: every client checks the daemon's
`/version` on startup. A product-version difference produces a warning,
while an API-version difference stops both clients before they issue
management operations.
You can still drive Sekisho directly from `curl`, a config-management
tool, or Terraform — the management API is a stable, documented HTTP
contract. The shipped clients can be installed independently and connect
to a remote daemon; their startup version check enforces the management API
compatibility boundary.

## How to read this book

- [Quick Start](./quick-start.md) gets you from a fresh Debian install
  to a working SSO-protected route in about ten minutes.
- [Architecture](./design/architecture.md) explains the internal structure and
  the design principles (registry pattern, JSON Merge Patch,
  API-version-gated clients) that keep the codebase small as features
  are added.
- [Configuration](./configuration/index.md) is the reference for the
  data model and the management API.
- [Authentication](./auth/index.md) covers OIDC and SAML setup,
  including a full walkthrough for Microsoft Entra ID.
- [TLS and ACME](./configuration/tls.md) covers certificate issuance.
- [Operation](./operating/day-to-day.md) and [Security](./design/security.md)
  cover day-to-day running and the current security posture.
