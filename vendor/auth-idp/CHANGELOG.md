# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-08-28

### Security

- OIDC ID tokens now require issuer, audience, expiry, and subject claims and
  enforce the authorized-party claim when an ID token names multiple
  audiences or supplies `azp` explicitly.
- Unencrypted SAML login and logout processing now rejects protocol,
  assertion, and XMLDSig elements in foreign or missing namespaces.
- Removed the debug-build environment knob that wrote raw SAML responses and
  canonicalized signature material to predictable shared temporary paths.

### Tooling / CI

- CI requires both `xmllint` and `xmlsec1` independent canonicalization
  oracles, so unavailable external tools cannot silently skip those checks.

## [0.4.0] - 2026-08-27

### Added

- **Validated SAML SP credentials.** `SamlSpCredentials::try_new` accepts one
  X.509 certificate and one matching unencrypted RSA PKCS#8 private key,
  rejects malformed, mismatched, oversized, or sub-2048-bit credentials, and
  retains private key material in zeroizing storage with redacted diagnostics.
- **Credentialed SAML client construction.** `SamlClient::new_with_credentials`
  is additive; the existing `SamlClient::new` constructor and unsigned behavior
  remain available.
- **Signed Redirect-binding AuthnRequests and key-bearing SP metadata.** A
  credentialed client signs the exact encoded Redirect query with RSA-SHA256.
  Its metadata sets `AuthnRequestsSigned=true`, publishes signing and encryption
  `KeyDescriptor` entries, and advertises RSA-OAEP-SHA256 with AES-256-GCM.
- **Encrypted SAML Assertions.** Credentialed clients accept exactly one signed
  encrypted Assertion using RSA-OAEP SHA-256 / MGF1 SHA-256 key transport and
  AES-256-GCM content encryption. Plaintext signed Assertions remain supported.

### Security

- Encrypted-response parsing is namespace-aware, bounded, and fail-closed for
  duplicate, mixed plaintext/encrypted, nested, malformed, or unsupported
  algorithm shapes.
- Decrypted XML is passed through the existing signature and semantic
  validation pipeline before claims are returned. Public decryption failures
  use a fixed redacted error, and temporary private-key/content-key/plaintext
  buffers use zeroizing ownership where available.
- Public-path E2E and negative tests cover exact Redirect signature bytes,
  certificate/key policy, encrypted Assertion round trips, algorithm and XML
  shape confusion, ciphertext bounds, tampering, and fixed error behavior.

## [0.3.0] - 2026-08-11

### Breaking

- **OIDC token fields use an explicit secret capability.**
  `OidcUserInfo::refresh_token` and `OidcUserInfo::id_token` now have type
  `Option<OidcToken>` instead of `Option<String>`. `OidcToken` does not
  implement `Clone`, `Deref`, `Display`, or `Serialize`; borrow token text
  explicitly with `expose_secret()`, or transfer the owned
  `Zeroizing<String>` without a copy with `into_zeroizing()`. Any separate
  string copy a caller creates is owned by that caller and falls outside this
  crate's zeroizing guarantees.

### Security

- **SAML identity extraction is bound to the verified signed target.** Login
  responses accept exactly one direct-child Assertion, and HTTP-POST logout
  responses validate semantics on the same root `LogoutResponse` whose
  signature was verified. Duplicate IDs, misplaced or unrelated signatures,
  and ambiguous signature shapes fail closed.
- **Decoded SAML XML has common resource bounds.** Login POST, Logout POST,
  and Logout Redirect inputs are capped at 1 MiB of decoded XML before
  signature and semantic processing. Redirect DEFLATE output uses the same
  bound, and XML nesting is limited to 64 elements with the document root at
  depth 1.
- **OIDC secrets owned by this crate use zeroizing storage.** This covers the
  client secret, raw token-response bytes, intermediate access/ID/refresh
  tokens, and returned `OidcToken` values. It does not claim that temporary
  buffers inside dependencies or copies created by callers are wiped.

### Tooling / CI

- CI requires `xmllint` as the independent canonicalization oracle and runs
  the differential exclusive-C14N property test with 10,000 cases.
- CI checkout uses an audited Node 24 action release pinned by full commit
  hash.

## [0.2.0] - 2026-07-06

### Breaking

- **`crypto` module removed.** Envelope encryption (KEK / DEK ring,
  versioned XChaCha20-Poly1305 blob formats, per-blob rewrap) now
  lives in the standalone `envelope-aead` crate. Depend on
  `envelope-aead` (v0.1.x) directly instead of `auth_idp::crypto::*`;
  wire formats and semantics are byte-compatible, so stored blobs
  round-trip through the new crate unchanged. `Error::Crypto` is
  removed and the `chacha20poly1305` / `zeroize` dependencies drop
  out of this crate.
- **SAML: `SamlClient::process_logout_response` signature changed.**
  The `is_redirect_binding: bool` parameter is replaced by
  [`LogoutResponseBinding`], a new enum whose `Redirect` variant carries
  the raw query string alongside it:
  ```diff
  -pub fn process_logout_response(
  -    &self, payload: &str, expected_in_response_to: &str, is_redirect_binding: bool,
  -) -> Result<()>
  +pub fn process_logout_response(
  +    &self, payload: &str, expected_in_response_to: &str,
  +    binding: LogoutResponseBinding<'_>,
  +) -> Result<()>
  ```
  The `(true, no raw_query)` foot-gun is now impossible to spell; the
  variant that declares Redirect binding is also the variant that
  supplies the raw query the signature check needs.

### Security

- **SAML: HTTP-Redirect binding `LogoutResponse` signatures are now
  verified.** v0.1.0 documented that Redirect signatures were left to
  the caller because they live on the URL query string. That created
  an asymmetric contract with the POST binding (which already ran
  XML-DSig verification here) and let a forged Redirect-bound
  `LogoutResponse` reach `process_logout_response` unchallenged.
  v0.2.0 verifies the detached query-string signature against the
  pinned IdP certificates, and refuses when the caller-processed
  payload does not match the `SAMLResponse` parameter the IdP signed.
- **SAML: XML `GeneralRef` events are fail-closed in the c14n parser.**
  Only the built-in numeric / named references from XML 1.0 are
  expanded; any DTD-defined entity name is refused rather than resolved
  through `quick_xml::escape::unescape`. Closes an XXE-shaped input
  vector where a caller-controlled entity name would otherwise flow
  into text nodes.
- **SAML: attribute values are XML-spec normalized on parse
  (`XmlVersion::Implicit1_0`).** Whitespace / CR / LF folding now
  matches what canonicalisation expects, so the octets fed into the
  signature verifier reflect the same value the IdP signed.
- **SAML: metadata extraction is scoped to the first
  `<EntityDescriptor>`.** The signing certificate walker
  (`extract_all_idp_certs`), the SSO URL picker (`extract_sso_url`),
  and the SLO URL picker (`extract_slo_url`) now all ignore any
  `<EntityDescriptor>` siblings that appear after the first one.
  In v0.1.0 the certificate walker traversed the entire document,
  and the URL pickers still returned the first document-wide match;
  in an
  `<EntitiesDescriptor>` bundle that combination could construct a
  `SamlClient` whose entity ID / signing certs came from entity A
  and SSO/SLO endpoints came from entity B. Certificate scoping
  additionally excludes `use="encryption"` KeyDescriptors and every
  KeyDescriptor outside the `<IDPSSODescriptor>` — SAML §2.4.1.1
  treats an unset `use` as "either role", so those keys are still
  accepted.
- **SAML: `SamlClient::process_logout_response` checks Issuer and
  Destination.** Issuer must equal the IdP entity ID extracted from
  metadata; `Destination` (when present) must equal `sp_slo_url`
  (when advertised). Symmetric with the AuthnResponse path.
- **SAML: AuthnResponse must carry `<samlp:Status>` with a Success
  `<StatusCode>`.** v0.1.0 accepted a signed Response with an
  Assertion regardless of the top-level status, so a `Responder` or
  `AuthnFailed` envelope with a leftover Assertion could pass as a
  successful login.
- **SAML: `SignedInfo/CanonicalizationMethod` is validated.** Only
  exclusive c14n without comments is accepted; anything else is
  refused with a specific error instead of a downstream
  "verification failed".
- **SAML: exc-c14n `#WithComments` Reference `Transform` is refused.**
  The canonicalizer drops comments; accepting the WithComments
  variant would hash a subtly different octet stream than the IdP
  declared.
- **SAML: `enveloped-signature` transform strips only the target
  Signature.** The XMLDSIG transform semantically removes the
  ancestor `<ds:Signature>` containing the transform, not every
  `<ds:Signature>` descendant of the referenced element. v0.2.0
  identifies the target Signature by its **structural path from the
  referenced element** (pointer identity in the original parse tree),
  applied against the cloned subtree used for digest computation.
  Content-based identification (SignatureValue text, ID attribute,
  etc.) is unsafe because those values are public within the document
  and an attacker can copy them into a second `<ds:Signature>` node
  they insert inside the referenced subtree, silently deleting
  attacker-controlled bytes from the digest input. When the enclosing
  Signature lies outside the referenced subtree (a legitimate SAML
  shape — Assertion-scoped signature whose Signature sits as a Response
  child), the transform is a no-op per spec; an inner injected
  Signature keeps its bytes in the digest and forces a mismatch.
  Structural XSW defences (unique-Assertion count, `covers_assertion`)
  remain unchanged.
- **SAML: Reference `Transforms` order is enforced.** The chain is
  accepted only as `[exc-c14n]` or `[enveloped-signature, exc-c14n]`
  in document order. Reversed order (`[exc-c14n,
  enveloped-signature]`) and any other shape are refused with a
  specific error rather than silently applying the crate's preferred
  order — a hostile or misconfigured IdP declaring the reverse would
  otherwise compute the digest over a different octet stream than we
  do.
- **SAML: `authn_request_url` XML-escapes template values and joins
  the SSO URL with `?` or `&` depending on whether it already carries
  a query.** v0.1.0 injected the raw SSO URL, so an IdP whose
  Destination URL contained `&` produced malformed XML the IdP
  refused; the same code path also corrupted SSO endpoints that
  already carried a query string.
- **OIDC: discovery `issuer` is validated against the configured
  issuer URL at fetch time.** `OidcClient::new` refuses a discovery
  document whose `issuer` disagrees with the configured `issuer_url`
  (OIDC Discovery §4.3). Trailing-slash tolerance is applied
  consistently: the value stored on the client is the
  canonicalised (trimmed) form, and the JWT `iss` check accepts both
  the canonical and slash-suffixed forms so that a configured
  `"https://idp.example.com/"` does not reject ID tokens whose `iss`
  omits the trailing slash (or vice versa). ID-token verification
  pins the operator-configured `issuer_url` as the trust anchor
  rather than echoing whatever the discovery document advertised.
- **`publish = false` guard.** Prevents accidental `cargo publish` of
  what is meant to be a private crate.

### Documented

- **Trust-boundary note for OIDC outbound URLs.** `OidcClient::new`
  rustdoc and the README "Out of scope" section now spell out that
  `idp.issuer_url` (and `SamlIdpConfig::metadata_url`) must be
  operator-controlled: a malicious discovery response can redirect the
  server-side token exchange (leaking `client_secret`) or steer the
  browser through an attacker-supplied authorization URL. HTTPS
  enforcement / private-range rejection / redirect policy are caller
  responsibilities — the crate does not override the `reqwest::Client`
  policy the caller supplies.

### Added

- `LogoutResponseBinding<'a>` enum with `Post` and
  `Redirect { raw_query: &'a str }` variants.
- Public `saml::verify_redirect_binding_signature(raw_query, message_param,
  expected_message_value, cert_ders)` — re-exported so callers can
  verify IdP-initiated `LogoutRequest` messages (same detached
  signature format) without going through `SamlClient`.

### Fixed

- **SAML: IdP metadata attribute values are XML-decoded.** Producers
  frequently emit URLs containing `&` as `&amp;`. v0.1.0 returned the
  raw byte slice, so `extract_idp_entity_id` / `extract_slo_url` /
  `extract_sso_url` surfaced literal `&amp;` sequences and broke
  downstream URL comparisons and redirects. Attribute values now go
  through `decoded_and_normalized_value` (`XmlVersion::Implicit1_0`).

### Changed — dependencies

- `quick-xml` bumped from `0.37` to `0.41` for the
  `normalized_value` / `decoded_and_normalized_value` APIs that back
  the XML-spec-compliant attribute value handling above, and for the
  new `Event::GeneralRef` variant the c14n parser now fails-closed on.

## [0.1.0] - Initial release

### Added — OIDC

- `OidcClient` covering OIDC Discovery (`/.well-known/openid-configuration`),
  JWKS fetch + cache, authorize URL composition (`authorize_url`), token
  exchange (`exchange_code`), end-session URL composition
  (`end_session_url`), and post-logout redirect handling.
- `OidcIdpConfig` (issuer URL) + `OidcClientConfig` (client_id, redirect_url,
  scopes); the `decrypted_client_secret` flows in via the constructor.
- ID-token verification: issuer / audience / nonce / exp checks plus JWKS
  key selection via `jsonwebtoken`.

### Added — SAML

- `SamlClient` Service Provider with XML signature verification.
  Public surface: `new`, `authn_request_url`, `process_response`,
  `slo_redirect_url`, `logout_request_redirect_url`,
  `process_logout_response`, `sp_metadata`.
- IdP metadata parsing for SSO / SLO endpoints (XML namespace prefix
  agnostic — local-name comparison), x509 certificate extraction,
  attribute-mapping passthrough.
- `SamlSpConfig::sp_slo_url: Option<String>` — explicit SP-side SLO
  endpoint. `None` omits the `<md:SingleLogoutService>` element from
  the metadata generated by `sp_metadata`. Replaces the earlier
  `acs_url.replace("/saml/acs", "/saml/slo")` derivation.
- **Exclusive XML Canonicalization** (W3C `xml-exc-c14n#`) implemented in
  `saml::c14n`. Includes ancestor-namespace propagation, attribute
  sorting, and prefix-list handling. Backed by:
  - Oracle-based unit tests (`c14n_test.rs`, `c14n_oracle_test.rs`,
    `c14n_subtree_oracle_test.rs`) cross-checking the implementation
    against `xmlsec1` on representative documents.
  - Property-based fuzz tests (`c14n_fuzz_test.rs`).
- XML signature verification (`saml::signature`) against multiple IdP
  certs (rolling-key IdPs like Entra ID are supported by trying each).
- Semantic validation (`saml::validate`): Response Issuer + Assertion
  Issuer match (both must equal the caller-supplied
  `expected_issuer`, typically the IdP entity ID extracted from
  metadata), Destination, audience match, `InResponseTo` correlation,
  NotBefore / NotOnOrAfter time windows. One-time replay prevention
  itself is out of scope — callers track their own pending-request /
  nonce state and consume the `InResponseTo` ID on match.
- Configurable `request_id_prefix` so callers tag their AuthnRequest /
  LogoutRequest IDs (`<prefix>_<uuid>` / `<prefix>_lo_<uuid>`).

### Added — crypto

- XChaCha20-Poly1305 helpers wrapping the `chacha20poly1305` crate with
  `zeroize`-protected key handling. Two on-the-wire blob shapes:
  - **v2** `0x02 || nonce(24) || ciphertext+tag` — KEK-direct. APIs:
    `encrypt`, `decrypt`, `encrypt_to_base64`, `decrypt_from_base64`.
  - **v3** `0x03 || key_id(1) || nonce(24) || ciphertext+tag` —
    DEK-routed via [`MasterKeyRing`]. APIs: `encrypt_v3`,
    `decrypt_v3_with`, plus the ring methods (`encrypt_active`,
    `encrypt_with`, `decrypt_any`, `encrypt_active_to_base64`,
    `decrypt_any_from_base64`, `active_key_id`, `version`,
    `known_key_ids`).
- `peek_key_id` / `peek_key_id_from_base64` — extract the v3 `key_id`
  byte without decrypting (rotation tooling).
- `MasterKeyRing::new` / `MasterKeyRing::placeholder_single` —
  construct a ring from caller-decrypted DEKs.
- `CryptoError` enum surfacing the AEAD / format / key-lookup
  failure modes; `Debug` for `MasterKeyRing` redacts DEK bytes.

### Added — http

- Narrow `reqwest` helpers used by the OIDC / SAML clients (header
  shaping, decoding small protocol responses).

### Added — error

- `Error` enum with `AuthenticationFailed`, `ConfigurationError`,
  `ExternalServiceError`, `Internal`, `KidNotFound(Option<String>)`,
  and `Crypto(#[from] crate::crypto::CryptoError)` variants.
  `Result<T>` alias.

### Scope

- Pure protocol library. No HTTP framework glue, no application state,
  no Store / DB, no audit / logging surfaces beyond `tracing::warn`.
- Callers pass in a constructed `reqwest::Client` and pre-decrypted
  secrets.

### Tooling

- `deny.toml` configures `cargo deny` with a permissive license
  allowlist matching the dual `MIT OR Apache-2.0` ship policy.
- `.gitignore` excludes common secret-file patterns (`.env`, `*.pem`,
  `*.key`, `*.p12`, `*.pfx`, `*.db`, `*.sqlite`) in addition to
  `/target` and `Cargo.lock`.
- Debug knob: `AUTH_IDP_DEBUG_SAML=1` (debug builds only) dumps raw
  SAML response XML and canonicalised signature bytes under
  `/tmp/auth-idp-saml-*` with mode `0600`. Never enable in production.
