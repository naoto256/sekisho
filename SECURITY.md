# Security Policy

## Reporting a vulnerability

Please use GitHub's private Security Advisory flow:

<https://github.com/naoto256/sekisho/security/advisories/new>

We aim to acknowledge new reports within **5 business days** regardless of
severity.

Please do **not** open a public issue for suspected vulnerabilities.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | yes (active)       |
| < 0.1   | no                 |

While Sekisho is pre-1.0, only the latest minor receives security fixes. On
each new minor release, the previous minor enters a 30-day grace window and is
EOL after that.

## Threat model (high-level)

The security chapter of the documentation carries the current controls,
regression coverage and known limitations:
[`docs/src/design/security.md`](docs/src/design/security.md). The summary below is the
working scope.

In scope:

- Authentication and authorization for **all inbound traffic** that Sekisho
  proxies
- All at-rest secrets (per-record DEKs wrapped by a KEK / master key)
- HA peer consistency through the shared service DB
- Append-only audit log integrity (tamper *detection* with cryptographic
  receipts is out of scope for now — see below)

Out of scope (handled at another layer or deferred):

- DoS / DDoS resistance — assume an upstream CDN or WAF
- Brute-force rate limiting at the IdP — that is the IdP's job
- Supply chain — covered mechanically by `cargo-deny` and `cargo-audit`; SBOM
  is on the roadmap
- Physical and kernel-level attacks against the host
- Actions that an authenticated user performs within the access granted by
  the configured policy. Policy bypasses, session confusion, and forged or
  incorrectly propagated identity headers remain in scope.

## Known limitations and out-of-scope behaviors

- **No supported in-place KEK rotation.** Sekisho cannot re-wrap existing
  data under a new KEK, online or offline. Treat KEK exposure as a
  host-compromise event and perform a clean re-bootstrap; see
  [Encryption keys](docs/src/operating/encryption-keys.md) for the response.
- **No per-route RPS rate limiting yet.** A per-route concurrency limit is
  implemented; token-bucket rate limiting is on the roadmap.
- **HA tested at 2 nodes.** Horizontal scaling is verified for an HA pair.
  Three or more peers should work but are not yet validated.

## Disclosure timeline

1. Report received via GHSA
2. Triage within 5 business days
3. Fix released within 30 days for high-severity issues; lower severities are
   batched into the next minor
4. Public advisory after the fix ships

We will coordinate embargoed disclosure with downstream packagers and
operators when warranted.
