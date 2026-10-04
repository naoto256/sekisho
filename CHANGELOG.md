# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

[Unreleased]: https://github.com/naoto256/sekisho/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/naoto256/sekisho/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/naoto256/sekisho/releases/tag/v0.1.0

## [Unreleased]

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
  `root:sekisho` mode `0640`; upgrades leave existing operator-managed files
  unchanged.

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
