# Sekisho — Identity-Aware Proxy in Rust

A single-binary identity-aware proxy that fronts your internal apps with SSO,
proxy-owned header isolation, verifiable identity assertions, and HA-aware
ACME — written in Rust.

[![CI](https://github.com/naoto256/sekisho/actions/workflows/ci.yml/badge.svg)](https://github.com/naoto256/sekisho/actions/workflows/ci.yml)
[![Release](https://github.com/naoto256/sekisho/actions/workflows/release.yml/badge.svg)](https://github.com/naoto256/sekisho/actions/workflows/release.yml)
[![License: MIT or Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Container](https://img.shields.io/badge/ghcr.io-naoto256%2Fsekisho-blue)](https://github.com/naoto256/sekisho/pkgs/container/sekisho)

**Sekisho** (関所) is the Japanese word for an Edo-period checkpoint
station — every traveller had to present credentials before passing through.
The proxy carries the same posture: every request is authenticated and
authorised before it reaches the upstream.

Concretely, it is for small to mid-sized teams who want a single public
ingress that authenticates every request via OIDC or SAML, terminates TLS
with route-driven ACME, and runs HA without an external coordinator. The IAP
itself is one self-contained Rust binary. Operators can use its management API
directly; the optional CLI and Web UI are companion clients for interactive
day-2 administration.

Design pillars:

- Rust + `rustls`, no OpenSSL on the data path
- KEK / DEK split — per-record DEKs, master key wraps the ring at rest
- Service-DB-backed, single-consume state for federated-auth callbacks;
  stateless double-submit CSRF for the admin Web UI
- Route-driven certificate provisioning (declare a route, ACME just works)
- HA-transparent ACME via an internal service-DB election and queue — no
  external coordinator
- OIDC + SAML (with SLO) in the same binary

## Status

Pre-1.0 (`0.1.x`). Expect breaking changes between minor releases until 1.0.
See [CHANGELOG.md](CHANGELOG.md).

## Quick start

```sh
git clone https://github.com/naoto256/sekisho.git
cd sekisho
cp .env.example .env
# create the credential file named by SEKISHO_MASTER_KEY_FILE in .env,
# then set POSTGRES_PASSWORD=... for the HA compose profile
# bootstrap the local management RPK and copy its single output line to
# SEKISHO_MANAGEMENT_RPK_PIN in .env
docker compose run --rm sekishod --print-management-rpk
docker compose up -d
```

Then:

- TLS proxy on `:443` (and `:80` for ACME HTTP-01 + redirect)
- Management API kept inside the daemon's network namespace on
  `127.0.0.1:9443`
- Admin WebUI on shared loopback at `127.0.0.1:9444`; create an ordinary
  Sekisho HTTPS Route with upstream `http://127.0.0.1:9444` for browser access

Bootstrap that route from inside the daemon container with
`docker compose exec sekishod /usr/bin/sekisho-cli --local-auth
--socket /var/lib/sekisho/control.sock`. The pin is supplied by the Compose
environment. The WebUI
listener and management API are not published directly to the host.

To register your first route and IdP, follow
[`docs/src/quick-start.md`](docs/src/quick-start.md).

## Why Sekisho?

A rough positioning sketch. Cells are best-effort summaries of the upstream
OSS state at the time of writing — see each project's own docs for the
authoritative list.

| Tool             | OIDC | SAML                | TLS / ACME              | HA (self-hosted)         | Admin Web UI         | Admin CLI            |
| ---------------- | ---- | ------------------- | ----------------------- | ------------------------ | -------------------- | -------------------- |
| Sekisho          | yes  | yes (with SLO)      | yes (route-driven ACME) | yes (shared Postgres)    | yes (`sekisho-webui`)| yes (`sekisho-cli`)  |
| oauth2-proxy     | yes  | no                  | no (terminate upstream) | yes (Redis sessions)     | no                   | no (flags / YAML)    |
| Authelia         | yes  | not yet (roadmap)   | no (front with Caddy/…) | yes (Postgres / Redis)   | no (user portal only)| no (YAML)            |
| Pomerium (OSS)   | yes  | via SSO bridge      | yes (autocert)          | yes (Postgres databroker)| Enterprise only      | no (YAML; OSS)       |
| cloudflared      | n/a  | n/a (tunnel client) | n/a (Cloudflare edge)   | n/a (Cloudflare SaaS)    | Cloudflare dashboard | `cloudflared` tunnel |

Notes:

- **oauth2-proxy** is OAuth2/OIDC only; SAML is a long-standing open issue,
  not shipped.
- **Authelia** is an OIDC OP today; SAML 2.0 IdP/SP is an active roadmap
  item (as of v4.39, not yet released).
- **Pomerium OSS** can talk to SAML IdPs through its Authenticate service,
  but the proxy itself is not a native SAML SP — it bridges to SAML
  upstreams via OIDC-style flows. The OSS binary embeds Envoy as a child
  process and runs several internal services (Proxy/Authenticate/Authorize
  /Databroker), all-in-one by default.
- **cloudflared** is a tunnel client; SAML/OIDC and policy live in
  Cloudflare's hosted Access control plane, so it's not really a
  self-hosted IAP and is included only for orientation.
- **Admin UI / CLI**: oauth2-proxy and Authelia are configured via files
  (YAML / flags) with no admin CRUD UI; Pomerium has a Console UI but
  it's an Enterprise product. Sekisho ships an admin web UI and an
  interactive CLI in the same release, with no separate tier.

Differentiators of Sekisho:

- One Rust binary that terminates TLS itself — no fronting nginx/Caddy and
  no embedded Envoy
- OIDC and SAML 2.0 (with SLO) handled natively in-process, statically
  linked, no plugin loader
- ACME provisioning is HA-aware out of the box (peers coordinate through an
  internal service-DB election and queue, with no external coordinator)
- Encryption at rest with per-record DEKs wrapped by a master KEK, not a
  single global key

## Architecture

Sekisho runs in two shapes from the same binary. The storage backend is the
only thing that changes; the auth / proxy / ACME logic is identical.

### Single-node (default — zero external deps)

```text
                    +---------------------+
   Browser  ---->   |      Sekisho        |  ---->  upstream-a (HTTP)
   (TLS)            |   (sekishod, Rust)  |  ---->  upstream-b (HTTP)
                    |  - OIDC / SAML      |  ---->  upstream-c (HTTP)
                    |  - rustls + ACME    |
                    |  - policy / audit   |
                    +----------+----------+
                               |
                               v
                          SQLite file
                  (routes, sessions, DEK ring)

                  + IdP (Entra / Keycloak / SAML)
```

One process, one SQLite file on local disk, plus your IdP. No Postgres, no
Redis, no sidecar — drop the binary on a host and go.

### HA (two or more peers, shared Postgres)

```text
              Browser (TLS)
                    |
        +-----------+-----------+
        |                       |
        v                       v
  +-----------+           +-----------+
  | sekishod  |           | sekishod  |     ---->  upstream-a (HTTP)
  |  peer A   |           |  peer B   |     ---->  upstream-b (HTTP)
  | + local   |           | + local   |     ---->  upstream-c (HTTP)
  |   SQLite  |           |   SQLite  |    (each peer connects directly
  | (instance) |          | (instance) |     to the same upstream pool)
  +-----+-----+           +-----+-----+
        |                       |
        +-----------+-----------+
                    |
               +----v----+         IdP (Entra / Keycloak
               | Postgres|         / SAML)
               | (shared |
               |  service|
               |  state, |
               |  DEK    |
               |  ring)  |
               +---------+
```

Each peer keeps a tiny local SQLite **instance config** file (a pointer
to the cluster DB and instance-local state, sealed with the master KEK).
All authoritative service state — routes, sessions, ACME orders, the DEK
ring — lives in the shared Postgres. Peers coordinate ACME through the
service DB's internal election and queue; no external coordinator or managed
control plane is required.

## What's inside

- `sekishod` — proxy daemon (TLS terminator, policy enforcer, ACME client)
- `sekisho-cli` — interactive client for a local or remote management API
- `sekisho-webui` — read/write browser client for a local or remote management
  API
- `sekisho-api-protocol` — server/CLI/Web UI path contracts and URL
  normalization, API-version negotiation, and certificate-enable orchestration
- `sekisho-management-rpk-tls` — canonical Ed25519 raw-public-key validation
  shared by the management server and clients, plus pinned client TLS setup

## Documentation

- Online mdbook: <https://naoto256.github.io/sekisho/>
- Source: [`docs/src/`](docs/src/) (build with `mdbook build docs`)
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)
- Security policy: [`SECURITY.md`](SECURITY.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
