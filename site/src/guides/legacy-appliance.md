# An appliance UI that will never support SSO

Some things cannot be fixed at the source: a storage controller, a
hypervisor console, a honeypot dashboard. They have one local account,
no OIDC, no SAML, and no roadmap. The checkpoint can still put them
behind your IdP.

This guide covers the three things that usually break on the first
attempt.

## 1. The upstream speaks plain HTTP on an IP

Terminate TLS at Sekisho and forward to the appliance address. The
public name and the backend address are independent:

```text
sekisho@iap# create route console
sekisho@iap edit route/console> set from https://console.example.com
sekisho@iap edit route/console> set to http://192.0.2.44
sekisho@iap edit route/console> set access.policy claim.groups in ["infra"]
sekisho@iap edit route/console> commit
```

If the appliance serves TLS with a self-signed certificate, keep the
`https://` upstream and set `tls_skip_verify true`. That disables
verification for this route only — it does not weaken any other route,
because each route that opts in gets its own HTTP client.

## 2. It does virtual-host matching, and now sees the wrong host

Many appliances, and anything fronted by nginx, decide which site to
serve from the `Host` header. Forwarding the public name can land you on
the default vhost and a 404, or on a login loop.

```text
sekisho@iap edit route/console> set host-rewrite 192.0.2.44
```

`host_rewrite` rewrites the authority the upstream sees and pins the TCP
target to the original backend, so the URL authority and the `Host`
header agree — which also matters under HTTP/2, where the upstream reads
`:authority` from the URL rather than from a header.

## 3. It redirects to its own IP after login

A POST to the appliance's login form answers with
`Location: https://192.0.2.44/dashboard`. The browser follows it, leaves
the checkpoint entirely, and the session is lost.

This one needs no configuration: `response_location_rewrite` is on by
default. Any absolute `Location` whose authority matches one of the
route's upstreams is rewritten back to the route's public origin.

Turn it off only for an upstream that deliberately redirects somewhere
else, such as a federated login bouncing to another service:

```text
sekisho@iap edit route/console> set response-location-rewrite false
```

## Injecting the appliance's own credential

The appliance still wants its local account. Rather than sharing that
password with everyone, let the route supply it once:

```text
sekisho@iap edit route/console> set headers.allow-credential-overrides true
sekisho@iap edit route/console> set headers.add.Authorization Basic <base64>
sekisho@iap edit route/console> commit
```

The opt-in flag is required because `Authorization` and `Cookie` are
refused by default — pasting a credential onto a route that turns out to
be public is the mistake it guards against. Routes that opt in are
recorded as a discrete field on the audit event, so they can be alerted
on.

The result: your IdP decides who gets in, the policy decides who among
them reaches this box, and the appliance sees one service account it
already understands.

## Before you call it done

```text
sekisho@iap> enable route console
sekisho@iap> show route console
```

Check that the appliance is not reachable except through the
checkpoint. Everything above assumes the route is the only path in; if
the backend address is also routable from user networks, the injected
credential and the identity headers are both bypassable.
