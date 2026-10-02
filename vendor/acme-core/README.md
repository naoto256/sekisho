# acme-core

[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![rust edition 2024](https://img.shields.io/badge/rust-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![version 0.3.0](https://img.shields.io/badge/version-0.3.0-brightgreen.svg)](CHANGELOG.md)
[![status: private](https://img.shields.io/badge/status-private-lightgrey.svg)](#)
[![not on crates.io](https://img.shields.io/badge/crates.io-unpublished-inactive.svg)](#)

Reusable ACME protocol primitives for account management, certificate issuance, and renewal.

Pure library: no HTTP framework, persistence layer, or database. The caller
supplies a `ChallengeProvider` and an ACME directory URL. The caller persists
an opaque account credential capability, while the crate restores that
account, drives orders, and exposes ACME Renewal Information (ARI) when the
directory supports it.

## Scope

- Durable ACME account creation and restoration through `AcmeAccount` and
  `AcmeAccountCredentials`.
- ACME v2 order lifecycle: authorization → challenge → CSR / finalize →
  certificate download.
- RFC 9773 ARI lookup and predecessor-aware replacement orders.
- Caller-supplied challenge solving via the `ChallengeProvider` trait.
- HTTP-01 only. `AcmeAccount::issue` passes the HTTP-01-form key authorization
  (`instant_acme::KeyAuthorization::as_str`) to `ChallengeProvider::set`.
  DNS-01 support would require an API extension to surface the
  `dns_value()` form to the provider and is not yet wired.

`AcmeAccount::create` creates an account only when credentials are missing and
returns the account together with its directory-bound credential envelope.
Existing credentials must be restored with `AcmeAccount::restore`; malformed,
unknown-version, or wrong-directory credentials fail before the default
HTTP/TLS client and its crypto provider are constructed, instead of silently
creating a replacement account. Valid restores still use the provider selected
by the host binary. Account creation sends
`terms_of_service_agreed: true`, so callers must ensure they accept the
directory's terms before invoking it.

## Out of scope

- Credential persistence, encryption at rest, audit logging, and renewal
  scheduling.
- HTTP server / handler glue. The crate does not embed any web framework.

These belong in the caller.

## Usage

```rust
use std::sync::Arc;
use acme_core::{AcmeAccount, AcmeAccountCredentials, ChallengeProvider};

async fn load_credentials() -> Option<AcmeAccountCredentials> { None }
async fn persist_credentials(_: &[u8]) {}

# async fn run<P: ChallengeProvider>(provider: Arc<P>) -> acme_core::Result<()> {
let directory = "https://acme-v02.api.letsencrypt.org/directory";
let account = if let Some(credentials) = load_credentials().await {
    AcmeAccount::restore(directory, credentials).await?
} else {
    let (account, credentials) = AcmeAccount::create(
        directory,
        Some("admin@example.com"),
    ).await?;
    persist_credentials(credentials.as_bytes()).await;
    account
};

let issued = account.issue("example.com", &provider, None).await?;
# let _ = (issued.certificate_pem, issued.private_key_pem);
# Ok(()) }
```

`AcmeAccountCredentials` is non-cloneable and redacts `Debug`. Its envelope is
held in a zeroizing buffer, but the library's wipe guarantee is limited to
buffers it owns. The caller owns durable encryption, atomic missing-winner
creation, and any copies made while persisting `as_bytes()`. Use
`into_zeroizing()` when transferring ownership without copying.

For a replacement order, pass the predecessor certificate's DER bytes:

```rust,ignore
let issued = account.issue(
    "example.com",
    &provider,
    Some(&predecessor_der),
).await?;
```

When the directory supports ARI, the predecessor identifier is included as
`replaces` and the server's echoed identifier must match. A directory that does
not advertise ARI uses a normal order; malformed predecessors and other ARI or
order failures do not silently take that fallback.

`renewal_info(certificate_der)` returns `RenewalInformation::Supported` with a
validated window and bounded refetch interval, or
`RenewalInformation::Unsupported`. Temporary ARI failures carry bounded
exponential-retry authority, while long-term failures carry a six-hour local
retry hint. The caller remains the scheduler: when ARI is unsupported it can,
for example, enqueue renewal after two thirds of the certificate's actual
`not_before`/`not_after` validity has elapsed.

For a hard upper bound around one order, use `issue_with_timeout`:

```rust,ignore
let issued = account.issue_with_timeout(
    "example.com",
    &provider,
    None,
    std::time::Duration::from_secs(120),
).await?;
```

Timeout expiry is retryable. Once challenge setup has started, timeout and
other exits retain the same best-effort `cleanup(domain)` contract.

## Migrating from 0.2.x

Version 0.3.0 keeps the public `IssuedCertificate.private_key_pem` field name but
changes its type from `String` to the dedicated `IssuedPrivateKey` capability.
Borrow the PEM explicitly with `expose_secret()` while encrypting or persisting
it, or use `into_zeroizing()` to transfer its owned zeroizing buffer without a
copy. `zeroize()` is available when the caller can wipe it before its normal
drop point.

`IssuedPrivateKey` does not implicitly clone, dereference, display, compare, or
serialize its contents. Its best-effort wipe guarantee covers only the buffer
owned by the capability. The caller owns any copy it creates, including copies
made across an encryption or persistence boundary.

## Migrating from 0.1.x

Version 0.2.0 intentionally removes the free `run_order` and
`run_order_with_timeout` functions. Create or restore one durable
`AcmeAccount`, then call `issue` or `issue_with_timeout` on it. Persist the
opaque `AcmeAccountCredentials` bytes in the consumer's existing protected
storage; do not interpret the versioned envelope or automatically replace an
invalid stored value.

Callers that renew certificates may pass the predecessor DER to `issue` and
use `renewal_info` for ARI scheduling. `Supported` supplies the CA window;
`Unsupported` leaves fallback timing to the consumer. The library does not
persist credentials, choose a two-thirds fallback date, or run a scheduler.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
