# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-08-14

### Breaking

- `IssuedCertificate.private_key_pem` keeps its field name but now contains an
  `IssuedPrivateKey` capability instead of a plain `String`. Consumers must use
  `expose_secret()` for an explicit borrow, `into_zeroizing()` for ownership
  transfer without copying, or `zeroize()` for an early wipe.
- `IssuedPrivateKey` does not implement implicit `Clone`, `Deref`, `AsRef`,
  `Borrow`, `Display`, `Serialize`, or `PartialEq` access paths.

### Security

- Freshly serialized private-key PEM is moved directly into a zeroizing owned
  buffer. The capability redacts `Debug`, wipes its owned buffer on drop, and
  makes exposure explicit. Consumers remain responsible for copies they create
  and for every buffer outside the capability-owned boundary.

### Changed

- Generalized the package description to cover reusable ACME account
  management, certificate issuance, and renewal primitives.

## [0.2.1] - 2026-08-13

### Fixed

- Credential envelope parsing, format-version validation, and outer and nested
  directory binding now complete before the default HTTP/TLS client or crypto
  provider is constructed. Invalid stored credentials therefore fail with the
  same typed errors even when a host workspace enables multiple rustls crypto
  providers.

### Compatibility

- Valid account restoration, host-owned crypto-provider selection, the public
  API and error variants, credential envelope format version 1, and ARI
  behavior are unchanged. This patch requires no credential migration.

## [0.2.0] - 2026-08-12

### Breaking

- Replaced the free `run_order` and `run_order_with_timeout` functions with a
  durable `AcmeAccount`. Callers now create an account once, persist the
  returned `AcmeAccountCredentials`, and restore it on restart before calling
  `issue` or `issue_with_timeout`.
- `AcmeAccountCredentials` is an opaque, directory-bound, versioned capability.
  It is non-cloneable, redacts `Debug`, and exposes only explicit borrow or
  zero-copy transfer methods. Invalid existing credentials fail closed rather
  than creating a new ACME account.

### Added

- `AcmeAccount::renewal_info` exposes RFC 9773 renewal information as
  `RenewalInformation::Supported` or `Unsupported`. Supported responses carry
  a validated renewal window and a bounded `Retry-After`; typed temporary
  failures carry bounded exponential-retry authority and long-term failures
  carry a six-hour local retry hint.
- `AcmeAccount::issue` and `issue_with_timeout` accept optional predecessor DER.
  ARI-capable directories receive the exact certificate identifier in
  `replaces`, and a mismatched echoed identifier fails closed. Directories that
  do not advertise ARI retain normal-order compatibility.

### Security

- Account credential envelopes are held in canonical-owned zeroizing buffers,
  validate their format version and normalized directory before network I/O,
  and redact diagnostics. Consumers remain responsible for encrypted durable
  persistence and for copies they create across that boundary.
- Private keys in `IssuedCertificate` are redacted from `Debug`, and top-level
  challenge-provider error messages omit provider details.

### Scheduling boundary

- ARI window selection, polling, and fallback scheduling remain consumer
  responsibilities. When ARI is unsupported, a consumer may derive its
  fallback from the certificate's actual validity (for example, renewal after
  two thirds has elapsed); this crate does not impose or execute that policy.

### Dependencies

- Uses `instant-acme` 0.8.5 with an explicit minimal feature set for durable
  credentials, certificate identifiers, replacement orders, and ARI. The
  license policy includes the Mozilla root-data dependency's
  `CDLA-Permissive-2.0` license.

## [0.1.1] - 2026-07-06

### Tooling

- **`publish = false` guard.** Prevents accidental `cargo publish` of
  what is meant to be a private crate. Matches the sister-crate policy.

### Added

- `run_order_with_timeout(directory, email, domain, challenge, timeout)`
  — the timed variant of [`run_order`]. The timeout wraps the protocol
  future after the `set_called` guard is armed, so a timeout that fires
  after the caller's `ChallengeProvider::set` has started still runs the
  same best-effort `cleanup(domain)` path before the timeout error is
  returned. Timeout expiry surfaces as `Error::Transient` (retryable)
  rather than a distinct variant — matches `Error::is_retryable`
  semantics and keeps existing retry loops unchanged.

### Changed — internals

- `run_order` and `run_order_with_timeout` now share a private
  `run_order_with_deadline(..., Option<Duration>)` helper. The public
  `run_order` signature is preserved — consumers do not need to change
  on this bump.

### Added — CI

- First-time CI (`.github/workflows/ci.yml`): `check` job runs
  `cargo fmt --check` / `cargo clippy --all-targets -- -D warnings` /
  `cargo test --all-targets` / `cargo doc --no-deps`
  (`RUSTDOCFLAGS=-Dwarnings`); `supply-chain` job runs
  `cargo-deny check` / `cargo-audit`. Triggers on push to `main` /
  `release/*` and every pull request. All third-party actions pinned
  to a full commit SHA with `# pin-audit:<YYYY-MM-DD> <sha7> (<release>)`
  markers; `permissions: contents: read` declared top-level and
  per-job.

## [0.1.0] - Initial release

### Added

- `run_order` — drive an ACME order to completion against an ACME v2 directory
  and return the issued certificate PEM together with the freshly generated
  private-key PEM. Creates a new ACME account on each call and unconditionally
  agrees to the directory's terms of service. If `ChallengeProvider::set` was
  invoked during the run (regardless of its outcome), a best-effort `cleanup`
  is attempted on every exit path; cleanup errors are logged and do not mask
  the underlying issuance error.
- `ChallengeProvider` trait — caller-supplied abstraction for HTTP-01 token
  storage. Implementation choice (filesystem, in-memory, distributed KV) is
  left to the caller.
- `Error` enum with `Transient` / `Rejected` / `Internal` / `Challenge` variants.
  `Transient` carries network / timeout / 5xx failures that may succeed on
  retry; `Rejected` carries permanent directory rejection (order `Invalid`,
  unexpected authorization status, missing challenge type); `Internal` carries
  local failures (CSR / key generation, unsupported `ChallengeProvider`
  configuration); `Challenge` wraps `ChallengeProvider::set` errors opaquely.
  `Error::is_retryable()` returns `true` iff the variant is `Transient`, so
  callers can gate retry policy without matching variants directly.
- `ProviderError`, `Result` — opaque provider-error box and `Result<T, Error>`
  alias.
- Re-export of `instant_acme::ChallengeType` so callers can name the challenge
  type their provider handles without a direct `instant-acme` dependency.

### Scope

- HTTP-01 only. `run_order` passes the HTTP-01-form key authorization
  (`KeyAuthorization::as_str`) to `ChallengeProvider::set`, and rejects
  providers whose `challenge_type()` returns anything other than
  `Http01` with `Error::Internal`. DNS-01 needs the `dns_value()` form,
  so it requires an API extension and is not yet wired.
- Persistence, encryption at rest, and audit logging are intentionally
  **out of scope** — those belong in the caller.

### Tooling

- `deny.toml` configures `cargo deny` with a permissive license allowlist
  matching the dual `MIT OR Apache-2.0` ship policy.
- `.gitignore` excludes common secret-file patterns (`.env`, `*.pem`,
  `*.key`, `*.p12`, `*.pfx`, `*.db`, `*.sqlite`) in addition to `/target`
  and `Cargo.lock`.
