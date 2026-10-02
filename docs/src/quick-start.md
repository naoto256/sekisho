# Quick Start

By the end of this page one of your internal web tools will be behind
a hostname nobody reaches without signing in first, and the tool
itself will receive an identity it can verify. Most of the twenty
minutes goes on registering a client with your identity provider.

It assumes:

- **A host with Docker**, reachable on TCP/80 and TCP/443. Debian and
  Ubuntu packages work just as well — see
  [Debian and Ubuntu](./install/debian.md), then rejoin at step 2.
- **Two hostnames pointing at that host.** One for the tool you are
  protecting (`grafana.example.com` below) and one for Sekisho's own
  login endpoints (`auth.example.com`). Both have to resolve before
  certificates can be issued.
- **An OIDC or SAML identity provider** you can add a redirect URI to —
  Google Workspace, Microsoft Entra ID, Keycloak, Auth0, or anything
  else standards-compliant.
- **Something to protect.** Anything that speaks HTTP. The examples
  use a Grafana on `10.0.0.5:3000`.

## 1. Start the daemon

Sekisho reads its master key from a file you create. Nothing generates
one for you, and the daemon will not start without it:

```bash
openssl rand -hex 32 | sudo install -o root -g 65532 -m 0440 \
  /dev/stdin "$PWD/sekisho-master-key"
```

The container runs as uid/gid 65532, so the file is owned by `root`
and readable only by root and that group. A plain `umask 077` redirect
would leave it readable only by you, and the daemon would fail to
start. Never make it world-readable. On rootless or userns-remapped
Docker the numeric ownership differs — see
[Docker](./install/docker.md) for that case.

> **Back this up now, off this host.** The master key encrypts every
> other secret Sekisho stores — IdP client secrets, TLS private keys,
> the cookie signing key. Lose it and you lose all of them. See
> [Encryption keys](./operating/encryption-keys.md) for what is
> rotated routinely and what is not.

```bash
docker run -d --name sekisho \
  -v "$PWD/sekisho-master-key:/run/secrets/master-key:ro" \
  -e SEKISHO_MASTER_KEY_FILE=/run/secrets/master-key \
  -v sekisho-data:/var/lib/sekisho \
  -p 443:443 -p 80:80 \
  ghcr.io/naoto256/sekisho:latest
```

Port 80 is not optional: it answers the ACME HTTP-01 challenge that
gets you a certificate. [Docker](./install/docker.md) covers the
volume and credential details, and the Compose deployment that adds
PostgreSQL and the web UI.

No API key exists yet and none is printed at startup. The way in is
the local socket, which is the next step.

## 2. Open the shell

`sekisho-cli` can authenticate over a Unix socket instead of an API
key, so no credential has to exist yet. Two things are still required:
the client must run as the **same user as the daemon** — the daemon
checks the peer with `SO_PEERCRED` and rejects every other UID,
including `root` — and it needs the daemon's **management RPK pin**,
which secures the HTTPS round-trip the challenge rides on.

Take the pin from the running daemon and hand it straight to the
client. `docker exec` already runs as the image's `nonroot` user, the
same one the daemon runs as, so the peer check passes:

```bash
PIN="$(docker exec sekisho sekishod --print-management-rpk)"
docker exec -it sekisho sekisho-cli --local-auth \
  --management-rpk-pin "$PIN" \
  --socket /var/lib/sekisho/control.sock
```

On a package install, run both as the `sekisho` service user:

```bash
PIN="$(sudo -u sekisho sekishod --print-management-rpk)"
sudo -u sekisho sekisho-cli --local-auth --management-rpk-pin "$PIN"
```

Pass the pin as an argument rather than exporting it: `sudo` does not
forward the environment by default, so an exported variable does not
reach the client.

```text
Authenticating via local socket /run/sekisho/control.sock ... ok

sekisho@iap>
```

`--socket` is not optional in the container. `/run` is not writable by
`nonroot`, so the image moves the control socket into the state volume
— but that setting belongs to the daemon, and the client does not
inherit it. Left to itself the client looks in `/run/sekisho/` and
reports that no such file exists. On a package install the default is
already right, which is why the second command above does not pass it.

## 3. Tell it where it lives

The auth domain is the hostname Sekisho serves its own `/.sekisho/...`
endpoints on. Browsers are redirected there to log in, and your IdP
sends its callback there:

```text
sekisho@iap> configure
entering configuration mode
sekisho@iap# edit sekisho
sekisho@iap edit sekisho> set auth-domain auth.example.com
sekisho@iap edit sekisho> set acme-email ops@example.com
sekisho@iap edit sekisho> commit
committed:
(daemon restart required for this change to take effect)
sekisho@iap edit sekisho> exit
```

**Restart before going on.** The shell tells you to, and login fails
until you do. The restart also ends your shell session, so reconnect
afterwards — the pin does not change:

```bash
docker restart sekisho
docker exec -it sekisho sekisho-cli --local-auth \
  --management-rpk-pin "$PIN" \
  --socket /var/lib/sekisho/control.sock
```

On a package install:

```bash
sudo systemctl restart sekishod
sudo -u sekisho sekisho-cli --local-auth --management-rpk-pin "$PIN"
```

## 4. Register your identity provider

Back at the prompt of that new session:

```text
sekisho@iap> configure
sekisho@iap# create idp workspace
sekisho@iap edit idp/workspace> set type oidc
sekisho@iap edit idp/workspace> set oidc-config.issuer-url https://accounts.google.com
sekisho@iap edit idp/workspace> set oidc-config.client-id <client-id>.apps.googleusercontent.com
sekisho@iap edit idp/workspace> set oidc-config.client-secret <client-secret>
sekisho@iap edit idp/workspace> commit
```

The redirect URI to register on the IdP side is your auth domain plus
a fixed path:

```text
https://auth.example.com/.sekisho/callback
```

Then make it the default, so routes need not each name one:

```text
sekisho@iap# edit sekisho
sekisho@iap edit sekisho> set default-idp-id workspace
sekisho@iap edit sekisho> commit
sekisho@iap edit sekisho> exit
```

Skip that and any route without its own `idp_id` answers `503`: the
daemon has nowhere to send the user. Using SAML instead?
[SAML with Microsoft Entra ID](./auth/saml-entra.md) is a full
walkthrough.

## 5. Protect something

```text
sekisho@iap# create route grafana
sekisho@iap edit route/grafana> set from https://grafana.example.com
sekisho@iap edit route/grafana> set to http://10.0.0.5:3000
sekisho@iap edit route/grafana> set access.policy claim.domain == "example.com"
sekisho@iap edit route/grafana> set enable-signed-identity true
sekisho@iap edit route/grafana> commit
sekisho@iap# exit
```

Type the policy expression exactly as written. `set` takes everything
after the field name verbatim — it does not unquote or unescape
anything — so the quotes around `"example.com"` are the policy
language's own string syntax and belong there. What must not be added
is an outer pair wrapping the whole expression: those characters would
be stored too, and it would stop parsing.

**Do not skip `access.policy`.** An empty policy denies everyone, so a
route without one lets your users sign in successfully and then
refuses them with `403` — which looks like a broken login but is not.
The example admits anyone whose email domain is `example.com`;
[Policies](./configuration/policies.md) has the grammar and the
named-policy form.

`enable-signed-identity` is what makes Sekisho hand the upstream an
identity at all — see step 7.

New routes land **disabled**. They exist in the database but the proxy
treats them as absent and answers `404`, which is what lets you stage
the policy, the IdP binding and the DNS before any traffic arrives.

## 6. Enable it

```text
sekisho@iap> enable route grafana
```

This is also when the certificate is obtained. With `tls_downstream`
at its `acme` default and no certificate yet for the hostname,
`sekisho-cli` blocks for 30–60 s while one is issued, then flips the
route live. Follow along if you like:

```bash
docker logs -f sekisho
```

You should see Let's Encrypt account creation, an HTTP-01 challenge,
and `certificate issued`. The certificate is stored in the database,
encrypted with the master key.

If ACME fails — DNS not propagated, port 80 unreachable —
`sekisho-cli` prints why and the route stays disabled. Fix it and run
`enable route grafana` again. Later, `disable route grafana` takes a
live route out of service without discarding its configuration or its
certificate.

## 7. Sign in

Open `https://grafana.example.com`. You land at your IdP, sign in, and
come back to Grafana — which, because the route set
`enable-signed-identity`, now sees:

```text
X-Sekisho-User: alice@example.com
X-Sekisho-Groups: ...
X-Sekisho-Jwt: eyJ...
```

That flag governs all three. Without it the upstream gets no
`X-Sekisho-*` headers at all, not merely an unsigned subset. With it,
an upstream that wants proof can verify `X-Sekisho-Jwt` against
Sekisho's published JWKS instead of trusting the network. See
[Identity headers](./configuration/routes.md#identity-headers).

If something is wrong, the status code says where to look. `503` means
no IdP is bound to the route. `403` after a login that appeared to
succeed means the policy refused. `404` means the route is still
disabled. [Troubleshooting](./operating/troubleshooting.md) works
through each of them.

## Where to go next

- [Configuration](./configuration/index.md) — the objects you just
  created, and every field on them.
- [Operation](./operating/day-to-day.md) — logs, backups, upgrades.
- [Per-instance settings](./configuration/instance.md) — the
  management API listens on `127.0.0.1:9443` and stays there until you
  say otherwise. That address is per-instance config rather than an
  environment variable, and a non-loopback one is refused without a
  source ACL.
