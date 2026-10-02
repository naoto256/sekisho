# Global Config

`GlobalConfig` is a singleton holding settings that apply to the whole
daemon: auth domain, session lifetime, ACME defaults. It is **shared
across the cluster** in HA, which is why per-node settings — namely
listen addresses — live elsewhere (see
[Per-instance settings](./instance.md)).

## Fields

| Field                     | Type             | Default                                              | Notes                                              |
|---------------------------|------------------|------------------------------------------------------|----------------------------------------------------|
| `auth_domain`             | string or null   | null                                                 | Hostname for `/.sekisho/...` endpoints.             |
| `cookie_name`             | string           | `_sekisho_session`                                   | Session cookie name.                               |
| `session_lifetime_hours`  | u32              | `8`                                                  | Session validity from creation.                    |
| `default_idp_id`          | uuid or null     | null                                                 | IdP for routes without their own `idp_id`. See note. |
| `acme_email`              | string or null   | null                                                 | ACME account contact. Required for issuance.       |
| `acme_directory`          | string           | `https://acme-v02.api.letsencrypt.org/directory`     | ACME directory URL. See note below.                |
| `acme_leader`             | string or null   | null                                                 | Pins ACME issuance to one node by identifier (`SEKISHO_NODE_ID`, else the OS hostname). Null = automatic election; a node with no matching election row is non-leader and fails closed. Restart required. |
| `websocket_concurrency_limit` | u32          | `100`                                                | Per-process cap on established WebSocket tunnels. Over the cap, upgrades get an immediate `503` — they are not queued. Restart required. |
| `acme_queue_capacity`     | u32              | `1000`                                               | Cluster-wide pending + in-progress rows. Live; lowering below active work is drain-only. |
| `acme_issuance_concurrency_limit` | u32       | `5`                                                  | Queue-worker slots (`1..=5`). Restart required.    |
| `acme_renewal_scan_interval_hours` | u32       | `12`                                                 | Renewal admission scan (`1..=168`). Restart required. |
| `log_level`               | string           | `info`                                               | `trace`, `debug`, `info`, `warn`, `error`.         |

## What is not here

Bind addresses and their source-IP allow-lists are **per-node**, so they
are not in `GlobalConfig` — an HA peer has to be able to bind its own
address. They live on the `instance` resource, together with the pointer
to the cluster database. See
[Per-instance settings](./instance.md).

> **Note on `default_idp_id`.** The database column is a `uuid`, and
> the HTTP API accepts / emits only UUIDs. `sekisho-cli` and `sekisho-webui`
> additionally let operators specify the IdP by **name**: `sekisho-webui`
> renders the field as a dropdown labelled with each IdP's name, and
> `sekisho-cli` resolves `set default_idp_id <name>` to the matching
> UUID before sending the PATCH. A pasted UUID still works in both
> UIs. IdP names are unique server-side so the lookup is unambiguous.

> **Note on `acme_directory`.** Let's Encrypt's production directory
> URL is `https://acme-v02.api.letsencrypt.org/directory` (note
> `v02`, not `v2`). The staging directory used for testing without
> rate limits is `https://acme-staging-v02.api.letsencrypt.org/directory`.
> Typos here are a common cause of certificate issuance failures.

## Auth domain

`auth_domain` is the hostname Sekisho uses for its own endpoints —
notably:

- `https://<auth_domain>/.sekisho/callback` (OIDC redirect URI)
- `https://<auth_domain>/.sekisho/saml/acs` (SAML Assertion Consumer
  Service)
- `https://<auth_domain>/.sekisho/sign-out` (RP-initiated logout trigger)
- `https://<auth_domain>/.sekisho/signed-out` (post-logout landing)

It must:

- be reachable by the user's browser,
- resolve via DNS to the Sekisho host,
- have a valid TLS certificate (typically obtained via ACME).

When a user hits a protected route without a session, they are
bounced to `auth_domain` to authenticate; on success they are
redirected back to the original URL.

Session cookies are **host-only** — no `Domain` attribute is set — so
the cookie minted while authenticating belongs to `auth_domain` alone
and is not visible to any other host, sibling or otherwise. A route on
a different hostname does not read that cookie. Instead the browser is
sent to that route's own host with a short-lived, single-use token,
and the route's host mints its own cookie for the same server-side
session. Routes therefore do not have to share a parent domain with
`auth_domain` or with each other.

## Examples

Set the auth domain and ACME contact in `sekisho-cli`:

```text
sekisho@iap# edit sekisho
sekisho@iap edit sekisho> set auth-domain auth.example.com
sekisho@iap edit sekisho> set acme-email ops@example.com
sekisho@iap edit sekisho> commit
```

The web UI edits the same object. To do it from a script instead, see
[Management API](../design/management-api.md).

Use the staging ACME directory while testing:

```text
sekisho@iap edit sekisho> set acme-directory https://acme-staging-v02.api.letsencrypt.org/directory
sekisho@iap edit sekisho> commit
```
