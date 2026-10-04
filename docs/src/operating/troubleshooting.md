# Troubleshooting

Sekisho sits between a browser and an application, so when something
breaks the interesting question is usually *which* of the two halves
gave up. Start by reading the daemon's log — every refusal it makes is
recorded there — and work outwards.

```bash
sudo journalctl -u sekishod -f
```

## Tell the status codes apart

Three different refusals look similar from the outside and have nothing
to do with each other. Getting them mixed up sends you looking in the
wrong place.

| Code | Where          | What it means                                                          |
|------|----------------|------------------------------------------------------------------------|
| 401  | Management API | The API key is missing or not valid. Authentication, not permissions.  |
| 403  | Management API | The key authenticated, but its scope does not cover this endpoint.     |
| 403  | Proxy          | The user signed in successfully and the route's policy refused them.   |
| 503  | Management API | Degraded mode — the daemon could not reach the service database.       |

What the refusal looks like depends on who asked for it. A browser
sends an `Accept` header that prefers HTML and gets a small fixed
page. A script, a health check, or anything asking for JSON gets the
JSON body:

```text
HTTP/1.1 403 Forbidden
content-type: application/json
vary: Accept
cache-control: no-store

{"error":"access denied"}
```

HTML is served only when the request asks for it and outranks JSON
outright. No `Accept` header at all, a wildcard-only one, a tie between
the two, or `text/html;q=0` all keep the JSON form, so existing clients
see no change. A malformed entry in the header is discarded on its own
rather than poisoning the whole header, which means a malformed
`Accept` does not automatically produce JSON — the valid entries that
remain still decide.

`Vary: Accept` is set on both forms, so a cache in front of Sekisho
will not hand one client the other's representation.

This covers refusals Sekisho itself generates on the public proxy. An
upstream's own error responses pass through unchanged, and so do the
management API and Sekisho's internal endpoints. A WebSocket upgrade is
unaffected either way.

## A user signs in and then gets 403

The policy refused them. Authentication and authorization are separate
steps, and this is the second one.

**Check.** The daemon logs a warning — message `access denied by
policy`, with the `user` and `route` fields attached. Grep the journal
for that message. There is also a counter,
`sekisho_proxy_policy_denied_total`, labelled by route.

**Fix.** Compare the user's claims against the route's expression with
`show route <name>`. Note that the log records *that* the policy refused
and for whom — it does not record which clause did it. If the expression
has several `and` terms, narrow it until the answer is unambiguous.

## The upstream never sees `X-Sekisho-User`

The route has not opted in. `enable_signed_identity` is the switch for
all three identity headers — `X-Sekisho-User`, `X-Sekisho-Groups` and
`X-Sekisho-Jwt` — not just the JWT. A route without it forwards none of
them.

**Check.** `show route <name>` and look at `enable_signed_identity`.

**Fix.**

```text
sekisho@iap> configure
sekisho@iap# edit route <name>
sekisho@iap edit route/<name>> set enable-signed-identity true
sekisho@iap edit route/<name>> commit
```

## Requests die at a fixed interval

Every proxied request is bounded by the route's `timeout_ms`, which
defaults to 30 000 ms. Exceeding it returns `504` and logs a warning —
message `upstream request timed out`, with the `route` and `timeout_ms`
fields attached.

**Fix.** Raise `timeout_ms` on the route if the upstream is legitimately
slow. There is a separate `response_idle_timeout_ms` (default 180 000
ms) that bounds the gap *between* body frames rather than the whole
request, for streaming responses that are slow but not stalled.

## A WebSocket tunnel stays open forever

That is the design, not a fault. `timeout_ms` bounds the WebSocket
*handshake*. Once the tunnel is established it is not time-bounded —
a long-lived socket is the point of the feature.

## `sekisho-cli --local-auth` is refused

The control socket checks `SO_PEERCRED` and accepts only a peer whose
UID equals the daemon's own effective UID. Root is rejected for the same
reason any other UID is: it does not match.

**Check.** Which user owns the daemon process, and which user you are.

**Fix.** Run as that user explicitly:

```bash
sudo -u sekisho sekisho-cli --local-auth
```

If the socket itself is missing at `/run/sekisho/control.sock`, the
daemon is not running.

## The Web UI gets authentication errors after a daemon restart

With `auth.local_auth`, the Web UI keeps a daemon-issued management credential
in memory. Restarting the daemon invalidates that credential. If the packaged
units are running independently, Web UI requests can therefore receive `401`
until the Web UI restarts or its scheduled credential refresh succeeds.

**Fix.** Refresh the credential immediately:

```bash
sudo systemctl restart sekisho-webui
```

For a co-located local-auth installation, use the optional systemd drop-in in
[Debian and Ubuntu](../install/debian.md) to couple the two unit lifecycles.
The base Web UI unit intentionally remains independent for remote-management
deployments.

## The CLI or Web UI refuses to start at `/version`

Both management clients establish API compatibility before handling a
credential. The CLI reports `compatibility check failed`; the Web UI exits
with `GET /version failed`, `invalid /version response`, or
`management API version mismatch`. This is fail-closed behavior, not an
authentication failure.

**Check.** Confirm that `sekisho_api_url` or the CLI URL reaches the intended
daemon, that the management RPK pin is current, and that
`/.sekisho/api/v1/version` returns JSON. A product-version difference is only
a warning; an API-version difference, malformed response, or unreachable
endpoint stops the client.

**Fix.** Correct the URL or pin, restore the daemon, or install a client with a
compatible management API version. The packaged Web UI retries every five
seconds through `Restart=on-failure`, so it converges after the daemon becomes
reachable.

## Every management API call returns 503

The daemon started but could not reach the service database, so it is in
degraded mode. It stays there until restarted — deliberately, so a
half-working node does not silently serve stale configuration.

**Check.** `/readyz` on the management API will confirm it.

**Fix.** Local auth still works, because it does not depend on the
service database. Correct the connection string and restart:

```text
sekisho@iap> configure
sekisho@iap# edit instance
sekisho@iap edit instance> set cluster-db-url postgres://…
sekisho@iap edit instance> commit
sekisho@iap edit instance> exit
sekisho@iap# exit
```

```bash
sudo systemctl restart sekishod
```

See [Per-instance settings](../configuration/instance.md).

## Turning up the logs

`SEKISHO_LOG_LEVEL` takes `trace`, `debug`, `info`, `warn` or `error`.
`debug` adds protocol-level OIDC and SAML logging, which is what most
authentication problems need. `trace` is very chatty and rarely worth
it.

`SEKISHO_NO_TLS` is the environment form of the `--no-tls` flag. It
disables TLS termination on the proxy listener and is only for local
development — never set it on a host that serves real traffic.

## A SAML signature will not verify

There is no switch that dumps the raw assertion. Earlier releases had
one; it wrote the response and the canonicalized bytes to `/tmp`, and
it was removed rather than renamed.

Raise the log level instead and read the rejection reason:

```bash
SEKISHO_LOG_LEVEL=debug
```

The verifier names the check that actually failed rather than
returning a generic error — a refused algorithm (RSA-SHA1 is rejected
outright), a digest mismatch, a certificate that is not in the IdP's
published metadata, an `InResponseTo` matching no outstanding request,
or an audience mismatch. In practice that identifies the problem
without needing the bytes.

If you do need the raw assertion, capture it at the browser. The SAML
response is a form POST to `/.sekisho/saml/acs` and is visible in the
developer tools before it ever reaches Sekisho — which also avoids
writing user identity attributes to disk on the server.

Note that the daemon's systemd unit gives it a private `/tmp` and
stops it writing outside `/var/lib/sekisho` and `/run/sekisho`, so a
dump left in `/tmp` by some other tool is not where you would expect
it. See [Operation](./day-to-day.md).
