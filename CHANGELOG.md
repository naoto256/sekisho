# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

[Unreleased]: https://github.com/naoto256/sekisho/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/naoto256/sekisho/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/naoto256/sekisho/releases/tag/v0.1.0

## [Unreleased]

### Changed

- `PATCH /config` treats `null` for `default_idp_id`, `auth_domain` and
  `acme_email` as "clear this value"; an absent field still means "leave it
  unchanged". The Web UI sends `null` when one of these fields is left empty,
  so clearing the default identity provider under **General** now takes
  effect. A client that sent an explicit `null` for one of them and expected
  no change must omit the field instead.
- The certificate issue and upload requests reject unknown fields with
  `422 Unprocessable Entity` instead of ignoring them.
- The Web UI answers `/healthz` without credentials, so a health probe works
  when basic auth or JWT is configured. The endpoint reports only that the
  Web UI process is serving.
- The Web UI refuses `POST /setup` once an API key is installed. A successful
  submission could previously replace the installed key.
- The Web UI accepts only UUIDs as route, identity-provider and certificate
  ids in its URLs and answers `400 Bad Request` for anything else.
- Fetching SAML metadata no longer follows HTTP redirects. If an identity
  provider's `metadata_url` redirects, configure the final URL.

### Fixed

- Compute `PATCH /config`'s `_restart_required` from stored values before
  and after the update, rather than which fields were sent. Sending an
  unchanged restart-sensitive value no longer triggers the marker.
- Keep the TLS listeners accepting connections after an accept error. A
  single error, such as reaching the file descriptor limit, previously stopped
  the listener until the daemon was restarted. TLS handshakes now have a
  10 second deadline and HTTP/1 request headers a 30 second deadline; an
  HTTP/2 connection that sends nothing is not covered.
- Include the request id in log lines written within the request-handler
  span. In JSON output it appears under `spans`. Log lines written outside
  it, such as connection-acceptance and TLS handshake messages, do not carry
  it, and a `RUST_LOG` filter that turns off the `sekishod::audit` target
  removes it.
- Return a configuration error instead of panicking when an identity
  provider's type and stored configuration disagree.

### Removed

- Remove the `sekisho-cli` `export` and `import` commands from both operational
  and configuration mode immediately, with no deprecation period and no
  replacement command. Import deleted routes and identity providers before
  recreating them, export omitted identity-provider secrets and policies, and
  it continued past per-item failures, so the commands could leave a partial
  configuration.
  Use the database and master-key backups described under
  [Operating → Overview § Backups](https://naoto256.github.io/sekisho/docs/operating/day-to-day.html#backups)
  instead.
  The separately documented YAML policy import never existed.
- Remove `log_level` from the global configuration, the Web UI and
  `sekisho-cli`. The value was stored but never applied. Set the log level
  with `--log-level`, `SEKISHO_LOG_LEVEL` or `RUST_LOG` and restart the daemon.
  A `log_level` field sent to `PATCH /config` is ignored like any other
  unknown field; the request is otherwise processed as usual.
  In an HA deployment, do not change the global configuration while 0.1.1
  and 0.1.2 nodes run side by side: once a 0.1.2 node has written the
  configuration, a 0.1.1 node can no longer read it.

### Security

- Reject identity JWTs in the Web UI guard when `email`, `groups` or `iat`
  is missing, null or has the wrong type. Empty email strings and empty
  group arrays remain accepted.
- Reject login redirect targets that contain a backslash, tab, carriage
  return or line feed.
- Log only the length of ACME HTTP-01 challenge tokens.
- Keep secrets out of the `Debug` output of the pending-login state, the
  Web UI guard configuration and the identity-provider form.

## [0.1.1] - 2026-10-04

### Added

- Add explicit management API version negotiation and report it from
  `show version`.
- Mark the configured default identity provider in the Web UI and link to its
  setting under **General → Sessions**.

### Changed

- Check management API compatibility before either client handles credentials.
  Product-version skew now warns and continues; an incompatible, unreachable,
  or malformed `/version` response stops the client.
- Allow the CLI and Web UI Debian packages to be installed without the daemon
  package for remote administration.
- Keep the packaged Web UI systemd unit independent of a local daemon by
  default, with an optional documented drop-in for co-located `local_auth`.

### Fixed

- Install each systemd unit only once in Debian packages so installation and
  same-version reinstallation work on merged-/usr systems.
- Preserve the Web UI's enabled state across future package upgrades and
  restart it only when it was already active. The 0.1.0 removal script stopped
  and disabled the unit, so existing installations must run
  `sudo systemctl enable --now sekisho-webui` once after upgrading to 0.1.1.
- Protect newly generated `/etc/sekisho-webui/webui.yaml` files as
  `root:sekisho` mode `0640`. Upgrades migrate the exact `root:root` mode
  `0644` metadata generated by 0.1.0 without changing file contents; other
  existing metadata remains operator-managed and unchanged.

## [0.1.0] - 2026-09-30

Initial release.

### Added

- Identity-aware reverse proxy with native OIDC and SAML 2.0 authentication,
  including SAML single logout.
- TLS termination and route-driven ACME certificate management for HTTP,
  HTTP/2, and WebSocket services.
- Route-level access policies using identity claims and request attributes,
  with reusable named policies.
- Host-only sessions, cross-host session handoff, absolute and idle expiry,
  and shared session state for HA deployments.
- Signed identity propagation through proxy-managed headers and EdDSA JWTs,
  with public JWKS rotation.
- Upstream pools with round-robin or random load balancing and per-route
  concurrency limits.
- Single-node operation with SQLite and multi-node HA with shared PostgreSQL,
  including coordinated ACME issuance.
- Version-locked management API, interactive CLI, and Web administration UI,
  with scoped API keys and pinned management TLS.
- KEK/DEK encryption for sensitive stored values, audit logging, Prometheus
  metrics, health checks, and graceful shutdown.
- Linux tarballs, separate amd64 Debian packages for each binary, and a
  multi-arch container image containing `sekishod`, `sekisho-cli`, and
  `sekisho-webui`.
