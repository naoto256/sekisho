# Management API TLS

The management API is always served with TLS 1.3 and an Ed25519 raw public
key (RPK). It does not present an X.509 certificate, accept a client
certificate, or offer a plaintext/fallback mode. This is independent of the
proxy listener and its per-route certificate policy.

## Bootstrap the pin

The daemon keeps one encrypted management private key in the local instance
store. It is not stored in the shared service database and is never returned
by an HTTP endpoint. Before starting clients, obtain the public pin locally:

```sh
sudo -u sekisho sekishod --print-management-rpk
```

The command resolves the master key and opens only the instance store. It does
not open the service database, bind a listener, or start background work. Its
single stdout line has this canonical form:

```text
sekisho-rpk-v1:ed25519:<base64url-SPKI-DER>
```

Transfer that line to each client over an authenticated out-of-band channel.
For `sekisho-cli`, pass `--management-rpk-pin` or set
`SEKISHO_MANAGEMENT_RPK_PIN`. For `sekisho-webui`, set
`management_rpk_pin` in YAML or the same environment variable. Missing,
malformed, or mismatched pins fail before a management request; the WebUI also
fails before binding its listener.

Management URLs must use `https://`. Neither client supports an insecure flag,
HTTP fallback, TOFU, or operating-system CA fallback for this connection.

## Listener exposure

The default management listener is loopback-only. Wildcard addresses
(`0.0.0.0` and `::`) are rejected. An explicit non-loopback listener requires
a non-empty canonical `api_accept_from` ACL in the same configuration update;
the effective pair is validated before it is written.

## Rotation

Stop the daemon, then rotate the local key:

```sh
sudo -u sekisho sekishod --rotate-management-rpk
```

Rotation atomically replaces the encrypted local key and prints the new public
pin only after commit. There is no previous-key overlap, staged activation, or
automatic retirement. Distribute the new pin, restart clients, and then start
the daemon. If rotation fails or is cancelled, the old durable key remains.

If rotation is invoked while a daemon is still running, that process keeps its
in-memory key until restart; no hot reload or stop detection is attempted.

## Containers

The reference Compose flow is explicit and has no TOFU step:

```sh
docker compose run --rm sekishod --print-management-rpk
# copy the one-line result into .env as SEKISHO_MANAGEMENT_RPK_PIN
docker compose up -d
```

The environment injects the same pin into the daemon image's CLI healthcheck
and the WebUI. Leaving it empty makes those consumers fail closed.
