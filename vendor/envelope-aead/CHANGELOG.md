# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-26

### Fixed

- Authenticate active-key ciphertext before returning
  `RewrapOutcome::AlreadyActive`, so a spoofed active key ID or a
  tampered nonce/tag fails decryption instead of bypassing AEAD
  verification.

## [0.1.0] - Initial release

### Added

- `Kek` — 32-byte root key with `from_bytes` / `from_hex` constructors,
  `Zeroizing` storage, redacted `Debug`. Exposes `seal` / `open` (v2
  envelope) and `seal_to_base64` / `open_from_base64` for text
  columns. Deliberately narrow — intended for bootstrap secrets and
  short-lived tokens, not general at-rest secrets.
- `DekPlaintext` — 32-byte data encryption key with `generate` (OS
  RNG), redacted `Debug`, `Zeroizing` storage. Constructor from raw
  bytes is crate-private so every DEK in circulation has a known
  provenance. `seal_under(kek)` produces an `EncryptedDekBlob`.
- `DekKeyId` — one-byte identifier with range-checked `new(u16)`
  constructor.
- `EncryptedDekBlob` — v2 blob whose plaintext is required to be
  exactly a 32-byte DEK. Rejects wrong-length / wrong-version input
  at `from_bytes`. Provides `open(kek)` -> `DekPlaintext`.
- `DekRing` — immutable in-memory snapshot of the DEK ring.
  `Clone`-cheap, `Send + Sync + 'static`, no interior mutability.
  Methods: `active_key_id`, `version`, `known_key_ids`, `contains`,
  `encrypt_active`, `encrypt_with`, `decrypt`, plus base64 helpers
  and `placeholder_single` for tests / bootstrap.
- `EncryptedDekRecord<B>` — generic-over-container storage-row shape
  consumed by `DekRing::from_encrypted_records(kek, records, version)`.
- `bootstrap_initial_dek(kek)` — one-shot generator returning an
  `InitialDekBootstrap { key_id, encrypted_blob, ring }` a daemon
  can persist + install without a reload round-trip.
- `peek_key_id` / `peek_key_id_from_base64` — read the v3 `key_id`
  byte without decrypting. Returns `Ok(None)` for v2 blobs.
- `rewrap_if_not_active(ring, blob)` — per-blob rotation primitive.
  Returns `RewrapOutcome::AlreadyActive` when the blob matches the
  ring's active key, `RewrapOutcome::Rewrapped(bytes)` otherwise.
  Refuses v2 blobs explicitly.
- `Error` enum with `CiphertextTooShort`, `UnknownVersion`,
  `VersionMismatch`, `UnknownKeyId`, `DecryptionFailed`,
  `KekHexDecode`, `Base64Decode`, `KeyIdOutOfRange`,
  `DekPlaintextLength`, `InvalidDekBlobLength`, `NoActiveKey`,
  `DuplicateKeyId`, `MultipleActiveKeys`, `ActiveKeyMarkedRetired`,
  `Rng`. `Result<T>` alias.

### Wire formats

- **v2** `0x02 || nonce(24) || ciphertext+tag` (XChaCha20-Poly1305,
  AAD empty). KEK-sealed; carries a DEK when consumed via
  `EncryptedDekBlob`, or arbitrary caller plaintext when consumed via
  `Kek::seal` / `Kek::open`.
- **v3** `0x03 || key_id(1) || nonce(24) || ciphertext+tag`
  (XChaCha20-Poly1305, AAD empty). DEK-routed via `DekRing`; the
  `key_id` byte is not authenticated as AAD but selects the DEK, so
  header tampering surfaces as AEAD rejection.

Byte-for-byte compatible with existing at-rest blobs written by the
daemons this crate was extracted from — no migration needed.

### Scope

- Pure primitives crate. No storage layer, no polling / refresh loops,
  no HA leader fencing, no CLI / management API, no KEK source
  policy. Those responsibilities stay with the consuming daemon.

### Tooling

- `deny.toml` configures `cargo deny` with a permissive license
  allowlist matching the dual `MIT OR Apache-2.0` ship policy.
- `.gitignore` excludes common secret-file patterns (`.env`, `*.pem`,
  `*.key`, `*.p12`, `*.pfx`, `*.db`, `*.sqlite`) in addition to
  `/target` and `Cargo.lock`.
- `publish = false` in `Cargo.toml` — this is a private crate.
