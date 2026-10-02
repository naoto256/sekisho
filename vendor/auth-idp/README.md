# auth-idp

[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![rust edition 2024](https://img.shields.io/badge/rust-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![version 0.4.1](https://img.shields.io/badge/version-0.4.1-brightgreen.svg)](CHANGELOG.md)
[![status: private](https://img.shields.io/badge/status-private-lightgrey.svg)](#)
[![not on crates.io](https://img.shields.io/badge/crates.io-unpublished-inactive.svg)](#)

IdP-side authentication protocol primitives.

Protocol-layer SAML and OIDC code. Pure library — no HTTP handlers,
no application state, no Store / DB dependency. Callers supply a
constructed `reqwest::Client` and pre-decrypted secrets. Envelope
encryption of at-rest secrets is out of scope — use the sister
[`envelope-aead`](https://github.com/naoto256/envelope-aead) crate.

## Scope

- **OIDC client** — `OidcClient::new(http, idp, client, decrypted_client_secret)`,
  Discovery + JWKS fetch / cache, ID-token verification, authorize / token
  exchange / end-session URL composition.
- **SAML SP** — `SamlClient` covering metadata parsing, AuthnRequest /
  LogoutRequest emission, XML signature verification, exclusive XML
  Canonicalization (W3C exc-c14n#), semantic validation, signed Redirect
  AuthnRequests, and signed encrypted Assertions. Credentialed clients use
  `SamlSpCredentials` with one matching X.509 certificate and unencrypted RSA
  PKCS#8 private key; metadata advertises the signing/encryption key and the
  RSA-OAEP-SHA256 + AES-256-GCM encryption suite.
- **HTTP helpers** — narrow wrappers used by the above.
- **Error type** — `Error` / `Result` carrying the protocol-layer failure
  modes.

## Out of scope

- HTTP framework glue (axum / hyper handlers).
- Application state, session DB, cookie store, audit logging.
- Secret-at-rest decryption — callers pass pre-decrypted secrets in.
- Mechanism-registry wiring — that pairs with the sister `auth-core` crate.
- Outbound URL policy on the `reqwest::Client` the caller supplies (HTTPS
  enforcement, private / link-local / loopback address rejection, redirect
  policy). If `OidcIdpConfig::issuer_url` or `SamlIdpConfig::metadata_url`
  can be influenced by untrusted input, the caller MUST validate them
  before construction. See the `OidcClient::new` rustdoc for the concrete
  attack vector — a malicious OIDC discovery response can redirect the
  server-side token exchange (leaking `client_secret`) or drive the
  user's browser through an attacker-supplied authorization URL.

These belong in the caller.

## Migrating from 0.3.0

0.4.0 is additive. Existing callers can continue using `SamlClient::new` and
retain unsigned AuthnRequests and plaintext signed Assertion processing.

To sign Redirect-binding AuthnRequests, advertise SP signing/encryption keys,
and accept signed encrypted Assertions, construct validated credentials and
use the credentialed constructor:

```rust,ignore
use auth_idp::saml::{SamlClient, SamlSpCredentials};

let credentials = SamlSpCredentials::try_new(
    std::fs::read("sp-certificate.pem")?,
    std::fs::read("sp-private-key.pk8.pem")?,
)?;
let client = SamlClient::new_with_credentials(
    &http,
    &idp_config,
    &sp_config,
    credentials,
).await?;
```

The private key must be an unencrypted RSA PKCS#8 PEM matching the certificate,
with a modulus of at least 2048 bits. Credential and encrypted-response errors
are intentionally fixed and redacted.

## Migrating from 0.2.0

`OidcUserInfo::refresh_token` and `OidcUserInfo::id_token` now have type
`Option<OidcToken>` instead of `Option<String>`. Borrow token text explicitly
with `expose_secret()`, or transfer the owned `Zeroizing<String>` without a
copy by calling `into_zeroizing()`.

If a caller creates a separate `String` copy from the borrowed token text,
that copy belongs to the caller and must be protected and cleared according
to the caller's own secret-handling policy.

## Migrating from 0.1.0

### Envelope encryption moved to `envelope-aead`

The `auth_idp::crypto` module is removed. Envelope encryption (KEK,
DEK ring, versioned XChaCha20-Poly1305 blob formats, per-blob rewrap)
now lives in the standalone [`envelope-aead`](https://github.com/naoto256/envelope-aead)
crate. Wire formats are byte-compatible, so stored blobs round-trip
through the new crate unchanged; switch imports and drop `chacha20poly1305`
/ `zeroize` from your own `Cargo.toml` if you only pulled them for the
crypto surface. `Error::Crypto` is likewise gone.

### `process_logout_response` signature

`SamlClient::process_logout_response` has a new signature. The
`is_redirect_binding: bool` parameter is gone; callers now pick a
[`LogoutResponseBinding`] variant that carries every input the matching
signature check needs.

```rust,ignore
// 0.1.0
client.process_logout_response(&payload, &expected_id, is_redirect_binding)?;

// 0.2.0
use auth_idp::saml::LogoutResponseBinding;

// POST binding: the embedded XML ds:Signature is verified.
client.process_logout_response(&payload, &expected_id, LogoutResponseBinding::Post)?;

// HTTP-Redirect binding: the detached query-string signature is verified
// against the pinned IdP certificates. Pass the raw query string as
// delivered by the browser — re-encoding the parameters upstream will
// break verification.
client.process_logout_response(
    &payload,
    &expected_id,
    LogoutResponseBinding::Redirect { raw_query: request_url.query().unwrap_or("") },
)?;
```

0.1.0 documented that Redirect-binding signature verification was left
to the caller; 0.2.0 performs it in-crate for symmetry with the POST
binding and with the login-side `process_response`. See the `[0.2.0]`
entry in [CHANGELOG.md](CHANGELOG.md) for the full rationale.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
