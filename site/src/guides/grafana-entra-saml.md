# Grafana behind Entra ID (SAML)

Grafana ships its own login page and its own user table. Behind Sekisho
you can stop using both: the checkpoint authenticates against Entra and
hands Grafana an identity it can verify.

## What you need first

- A route hostname that resolves to the Sekisho host, with port 80
  reachable so ACME can complete the HTTP-01 challenge.
- `auth_domain` set. It becomes the SAML SP entity ID and the issuer of
  every signed identity token, so pick it before registering with Entra.
- The Entra enterprise application from
  [SAML with Microsoft Entra ID](../docs/auth/saml-entra.html).

## Register the IdP

```text
sekisho@iap# create idp entra
sekisho@iap edit idp/entra> set type saml
sekisho@iap edit idp/entra> set saml-config.metadata-url https://login.microsoftonline.com/<tenant>/federationmetadata/2007-06/federationmetadata.xml
sekisho@iap edit idp/entra> set saml-config.attribute-mapping.email http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
sekisho@iap edit idp/entra> set saml-config.attribute-mapping.groups http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
sekisho@iap edit idp/entra> commit
```

The prompt carries the *server's* hostname, not yours — `sekisho-cli`
asks the daemon on the other end of the socket, so you always know which
checkpoint you are reconfiguring.

The SP entity ID and ACS URL are derived from `auth_domain`; there is
nothing to set for them here, and the Entra side must be registered with
exactly those values.

## Route the traffic

```text
sekisho@iap# create route grafana
sekisho@iap edit route/grafana> set from https://grafana.example.com
sekisho@iap edit route/grafana> set to http://127.0.0.1:3000
sekisho@iap edit route/grafana> set idp-id entra
sekisho@iap edit route/grafana> set access.policy claim.groups in ["platform", "sre"]
sekisho@iap edit route/grafana> set enable-signed-identity true
sekisho@iap edit route/grafana> commit
```

Do not wrap the policy in shell-style quotes. `set` takes the rest of the
line verbatim, so an outer pair of quotes is stored as part of the
expression and the policy stops parsing. Type it exactly as written.

`idp-id` accepts the IdP's name as well as its UUID; the shell resolves
it for you.

Nothing is served yet. Routes are created disabled on purpose, so DNS,
policy and certificate can all be in place before the first request
arrives.

```text
sekisho@iap> enable route grafana
```

Enabling is what triggers certificate issuance. The client enqueues the
ACME order and waits for it before flipping the flag.

## Let Grafana trust the header

With `enable_signed_identity` on, the upstream receives
`X-Sekisho-User`, `X-Sekisho-Groups`, and `X-Sekisho-Jwt`. Grafana's
auth-proxy mode can consume the first of these:

```ini
[auth.proxy]
enabled = true
header_name = X-Sekisho-User
header_property = email
auto_sign_up = true
```

Auth-proxy trusts the header unconditionally, so it is only safe when
Grafana is unreachable except through Sekisho. Bind Grafana to
`127.0.0.1` and let the route be the only path in.

If you would rather verify rather than trust, use `X-Sekisho-Jwt`. It is
signed with the daemon's Ed25519 identity key and the public key is
published as JWKS — but note the endpoint is on the management listener,
not the proxy port, so the upstream needs a route to it and the
management RPK pin. See
[Identity headers](../docs/configuration/routes.html#identity-headers).

## Check it

```text
sekisho@iap> show route grafana
sekisho@iap> show session
```

A browser hitting `https://grafana.example.com` should bounce to Entra,
come back, and land in Grafana already signed in. A user outside the
`platform` and `sre` groups authenticates successfully and is then
refused — authentication and authorization are separate steps, and the
refusal is the policy talking.

What the refused user sees depends on what their client asked for. A
browser prefers HTML and gets a small fixed page; anything asking for
JSON gets the JSON body:

```text
HTTP/1.1 403 Forbidden
content-type: application/json
vary: Accept
cache-control: no-store

{"error":"access denied"}
```

HTML is served only when the request asks for it and outranks JSON
outright. No `Accept` header, a wildcard-only one, a tie, or
`text/html;q=0` all keep the JSON form. A malformed entry is discarded
on its own rather than poisoning the whole header, so a malformed
`Accept` does not automatically produce JSON. [Troubleshooting](../docs/operating/troubleshooting.html#tell-the-status-codes-apart)
has the full picture, including what Sekisho leaves unchanged. The operator-facing half is a warning in the
daemon's log, carrying the user and the route:

```text
WARN access denied by policy user=alice@example.com route=grafana
```

and a counter, `sekisho_proxy_policy_denied_total`, labelled by route so
a sudden change in refusals is visible on a dashboard. Neither records
*which* clause of the policy rejected the request — if you need that, the
expression has to be narrowed until the answer is unambiguous.
