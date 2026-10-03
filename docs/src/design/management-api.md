# Management API

Everything Sekisho stores is a resource behind one HTTPS API.
The `sekisho-cli` shell and the web UI that `sekisho-webui` serves are
both clients of it; they have no private channel and no configuration
of their own. That is what makes
it safe to mix them — see
[Architecture](./architecture.md).

**You do not need this page to run Sekisho.** Install, first route,
IdP, certificates and day-to-day operation are all done from the shell
or the web UI. Read on if you are automating: CI that publishes a
route, a script that rotates a key, a dashboard that reads state.

## Base URL and version

The API is served under `/.sekisho/api/v1/` on the management
listener, which binds `127.0.0.1:9443` by default. Exposing it beyond
loopback is a per-instance setting with rules of its own; see
[Per-instance settings](../configuration/instance.md).

`GET /.sekisho/api/v1/version` needs no credential and is the first
call every client makes. It reports both the product version and
`api_version: 1`. A missing `api_version` is the legacy API v1 shape;
later API versions must report their number. Product-version skew warns,
but an API-version mismatch stops the client rather than guessing.

## Authenticating

Send an API key as a bearer token:

```
Authorization: Bearer sk_...
```

Creating, listing and revoking keys is covered in
[API Keys](../configuration/api-keys.md). A management session token
obtained over the Unix control socket works too, and satisfies every
scope.

## Scopes and endpoints

`management:read`:

| Method | Path                                    |
|--------|-----------------------------------------|
| GET    | `/routes`, `/routes/{id}`               |
| GET    | `/idps`, `/idps/{id}`                   |
| GET    | `/policies`, `/policies/{key}`          |
| GET    | `/certs`, `/certs/{id}`, `/certs/queue/{id}` |
| GET    | `/sessions`, `/sessions/{id}`           |
| GET    | `/acme/leader_election`                 |
| GET    | `/_internal/host`                       |

`management:write`:

| Method          | Path                                       |
|-----------------|--------------------------------------------|
| POST            | `/routes`  ·  PATCH / DELETE `/routes/{id}` |
| POST            | `/idps`  ·  PATCH / DELETE `/idps/{id}`     |
| POST            | `/policies`  ·  PATCH / DELETE `/policies/{key}` |
| POST            | `/certs`, `/certs/upload`  ·  DELETE `/certs/{id}` |
| DELETE          | `/sessions/{id}`                            |

`management:admin`:

| Method       | Path                                                        |
|--------------|-------------------------------------------------------------|
| GET / POST   | `/api_keys`  ·  GET / DELETE `/api_keys/{id}`                |
| GET / POST   | `/encryption_keys`                                           |
| POST         | `/encryption_keys/{key_id}/activate`, `/encryption_keys/{key_id}/retire`, `/encryption_keys/rotate` |
| POST         | `/identity-signing-keys/rotate`                              |
| GET / PATCH  | `/config`                                                    |
| GET / PATCH  | `/instance`                                                  |

Note that several **GET** endpoints require `admin`, not `read`:
`/api_keys`, `/api_keys/{id}`, `/encryption_keys`, `/config` and
`/instance`. Reading them discloses key metadata or the daemon's own
security posture, so they sit with the endpoints that change it. By
contrast `/_internal/host` is a plain `read` endpoint despite the
name.

### Endpoints that need no key at all

These are unauthenticated **within the management plane**. They are
never served on the public proxy port:

| Path                  | Why unauthenticated                                                  |
|-----------------------|-----------------------------------------------------------------------|
| `/version`            | Clients negotiate version compatibility before they have a credential. |
| `/metrics`            | Prometheus exposition; the trust boundary is the host. See [Operation](../operating/day-to-day.md#metrics). |
| `/auth/jwks`          | Upstreams verifying `X-Sekisho-Jwt` need the public key and have no management credential. |
| `/health`, `/healthz` | Liveness probes.                                                      |
| `/ready`, `/readyz`   | Readiness probes.                                                     |
| `/auth/challenge`     | First step of the local-auth flow, which by definition runs before you hold a key. |

## 401 or 403?

The two are distinct and the difference is the fastest way to
diagnose a failing call:

- **401 Unauthorized** — no credential was usable. No `Authorization`
  header, a header that is not `Bearer <key>`, an empty key, or a key
  the daemon does not recognise. The response does not say which.
- **403 Forbidden** — the key is valid and was authenticated, but its
  scopes do not satisfy the endpoint.

So a 403 means the key is real and you need a different scope; a 401
means the key itself is not being accepted. Both outcomes are written
to the audit log with the key's prefix — never the key — under the
events `auth.api.failure` and `auth.api.scope_denied`.

### Local-auth sessions bypass scopes

A management session token obtained through the Unix control socket
(the `mgmt_` prefix) satisfies **every** level, including `admin`,
without a scope check. This is deliberate. Redeeming a challenge on
the control socket requires the connecting process to run as the
daemon's own service user, and that user can already read the
master-key credential and the database directly. A scope restriction
there would restrict nothing while implying otherwise.

## What a PATCH does
- Send only the fields you want to change. Omitting a field leaves it
  alone.
- **An array is replaced whole.** There is no append; send the full
  list you want to end up with.
- A nested object is merged, not replaced. To replace one outright,
  send the parent as a complete new object.
- `null` clears a nullable field. Not every field accepts it — Identity
  Providers reject `null` on required fields, and treat it as "no
  change" on the client secret. See
  [Update semantics](../configuration/idps.md#update-semantics).

Why every resource behaves the same way is in
[Architecture](./architecture.md#2-json-merge-patch-extending-the-data-model).

## Worked examples

Create a policy:

```bash
curl -X POST \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "soc-from-office",
    "expr": "claim.groups == \"soc\"\nand client.ip in [\"192.168.0.0/24\"]\n"
  }' \
  https://sekisho.example.com:9443/.sekisho/api/v1/policies
```

Change only its expression:

```bash
curl -X PATCH \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"expr": "claim.groups in [\"soc\", \"csirt\"]"}' \
  https://sekisho.example.com:9443/.sekisho/api/v1/policies/soc-from-office
```

Point a route at a policy:

```bash
curl -X PATCH \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"access":{"policy":"policy.soc-from-office or policy.executive"}}' \
  https://sekisho.example.com:9443/.sekisho/api/v1/routes/grafana
```

Change two global settings at once:

```bash
curl -X PATCH \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"auth_domain":"auth.example.com","acme_email":"ops@example.com"}' \
  https://sekisho.example.com:9443/.sekisho/api/v1/config
```

`POST` and `PATCH` validate synchronously. A policy expression that
does not parse comes back as `400 Bad Request` naming the line and
column, and nothing is stored. See
[Policies](../configuration/policies.md) for the grammar itself.

### Issuing a certificate directly

Asking Sekisho to obtain a certificate and handing it one you already
have are **not** the same call. They differ in path, in body and in
success status. This section is the first; the next is the second.

`POST /certs` obtains one via ACME, and the body is just the domain.
The shell has no equivalent, so this is the way to pre-mint a
certificate that no route will trigger, the auth-domain certificate
being the usual case.

```bash
curl -X POST \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"auth.example.com"}' \
  https://sekisho.example.com:9443/.sekisho/api/v1/certs
```

Nothing is issued synchronously. The response is `202 Accepted`
carrying a queue id, because issuance is handled by a cluster-wide
queue worker. Poll the id until the row reads `completed` or `failed`.

### Uploading a certificate you already have

`POST /certs/upload` installs a certificate you minted yourself. It is
a **different path** from the one above, and the body carries the PEMs
alongside the domain. This is the endpoint `upload certificate` uses
in the shell.

```bash
curl -X POST \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"app.example.com","cert_pem":"...","key_pem":"..."}' \
  https://sekisho.example.com:9443/.sekisho/api/v1/certs/upload
```

This one completes in the request. The response is `201 Created` with
the stored certificate. Validity dates are read out of the certificate
rather than taken from the request, and the private key is encrypted
before it is written.

Sending PEMs to `/certs` does not upload them — that path only ever
enqueues an ACME order for the domain.

### Managing API keys

Keys are created and revoked over the API too, which is how a
provisioning script issues one per consumer. The raw key comes back
exactly once, in the create response.

```bash
curl -X POST \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-deploy","scopes":["management:write"]}' \
  https://127.0.0.1:9443/.sekisho/api/v1/api_keys

curl -X DELETE \
  -H "Authorization: Bearer $ADMIN_KEY" \
  https://127.0.0.1:9443/.sekisho/api/v1/api_keys/<id>
```

See [API Keys](../configuration/api-keys.md) for scopes, storage and
the first-key bootstrap, which cannot be done over the API.
