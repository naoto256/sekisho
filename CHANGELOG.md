# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

[Unreleased]: https://github.com/naoto256/sekisho/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/naoto256/sekisho/releases/tag/v0.1.0

## [Unreleased]

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
