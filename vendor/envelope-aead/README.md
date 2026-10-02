# envelope-aead

[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![rust edition 2024](https://img.shields.io/badge/rust-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![version 0.1.1](https://img.shields.io/badge/version-0.1.1-brightgreen.svg)](CHANGELOG.md)
[![status: private](https://img.shields.io/badge/status-private-lightgrey.svg)](#)
[![not on crates.io](https://img.shields.io/badge/crates.io-unpublished-inactive.svg)](#)

Envelope encryption primitives — a long-lived **KEK** wraps a rotatable
**DEK ring**, and application secrets are XChaCha20-Poly1305 blobs
routed through the ring. Intended for at-rest secret storage in
daemons (session tokens, TLS private keys, OIDC client secrets, ACME
account keys, etc.), where rotating the DEK should re-encrypt
everything without touching the KEK.

## Design

- **Typed AEAD boundary.** Raw `encrypt_v2` / `decrypt_v2` /
  `encrypt_v3` / `decrypt_v3_with` entry points are `pub(crate)` — no
  caller can spell an envelope operation without going through the
  typed surface. Raw KEK material has one public ingress
  (`Kek::from_bytes`, alongside `Kek::from_hex`) so callers can hand
  in bytes loaded from a KMS or file; there is no public accessor to
  read the KEK back out.
- **Zeroizing everywhere.** Every secret type (`Kek`, `DekPlaintext`,
  `DekRing`, decrypted DEK plaintext buffers) holds its bytes in
  `Zeroizing` and redacts them in `Debug`. Intermediate copies during
  hex decode / RNG fill / AEAD decrypt are wrapped in `Zeroizing` too,
  so panics and `tracing` output do not leak key material.
- **Wire-format stable.** v2 (`0x02 || nonce || ct+tag`) and v3
  (`0x03 || key_id || nonce || ct+tag`) match the byte-level layout
  already in use by the daemons this crate was extracted from, so
  existing stored blobs decrypt unchanged.
- **Empty AAD.** By design; matches the existing consumers. Callers
  who need header integrity can compose their own AAD scheme above
  this layer.

### Public surface

Types:

- `Kek`, `DekPlaintext`, `DekKeyId`, `EncryptedDekBlob`
- `DekRing`, `EncryptedDekRecord<B>`, `RewrapOutcome`
- `InitialDekBootstrap`, `Error`, `Result<T>`

Free functions:

- `bootstrap_initial_dek(kek)` — one-shot first-boot generator
- `peek_key_id(blob)` / `peek_key_id_from_base64(str)` — inspect a v3
  blob's `key_id` without decrypting
- `rewrap_if_not_active(ring, blob)` — per-blob rewrap primitive

Constants:

- `CIPHER_V2`, `CIPHER_V3`, `NONCE_LEN`, `TAG_LEN`

## Scope

In scope:

- Envelope AEAD format (v2 and v3, both XChaCha20-Poly1305)
- Typed `Kek` / `DekPlaintext` / `DekKeyId` / `EncryptedDekBlob` / `DekRing`
- `DekRing::from_encrypted_records` — build a snapshot from storage rows
- `bootstrap_initial_dek(kek)` — one-shot generator for first-boot
- `peek_key_id` and `rewrap_if_not_active` — per-blob rotation primitives

Out of scope (kept in the caller / daemon):

- Storage schemas, SQL migrations, transactional semantics
- Ring version polling / refresh loops / HA leader fencing
- Bulk table walking (encrypted-column inventory across daemon tables)
- Management API endpoints, CLI verbs, audit events
- KEK source policy (env variable names, file paths, KMS integration)
- Format migration timing (when to rewrap legacy v2 → v3)
- KEK rotation itself — the KEK is treated as a fixed root here

## Usage

```rust
use envelope_aead::{Kek, DekRing, EncryptedDekRecord, bootstrap_initial_dek};

# fn example() -> envelope_aead::Result<()> {
// Root KEK — obtain from your secret source (env, KMS, file, ...).
let kek = Kek::from_hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")?;

// First boot: generate an initial DEK, persist the encrypted blob,
// install the returned ring.
let boot = bootstrap_initial_dek(&kek)?;
// daemon persists `boot.encrypted_blob.as_bytes()` alongside key_id=boot.key_id
let mut ring = boot.ring;

// Subsequent boots: read encrypted DEK rows and rebuild the ring.
let records = vec![EncryptedDekRecord {
    key_id: 0,
    encrypted_blob: boot.encrypted_blob.as_bytes().to_vec(),
    active: true,
    retired: false,
}];
ring = DekRing::from_encrypted_records(&kek, records, 0)?;

// At-rest secrets flow through the DEK ring — v3 blobs carry key_id.
// `decrypt` returns `Zeroizing<Vec<u8>>` so the plaintext wipes on drop.
let sealed = ring.encrypt_active(b"session-token")?;
assert_eq!(&*ring.decrypt(&sealed)?, b"session-token");
# Ok(()) }
```

For **bootstrap secrets** (config that must decrypt before the ring
is loadable) and **short-lived tokens** (in-flight handoff cookies),
seal directly under the KEK — these are v2 blobs and never touch the
ring:

```rust
# use envelope_aead::Kek;
# fn example(kek: &Kek) -> envelope_aead::Result<()> {
let blob = kek.seal(b"instance-config-value")?;
let opened = kek.open(&blob)?;
assert_eq!(&*opened, b"instance-config-value");
# Ok(()) }
```

**Do not** use `Kek::seal` for general at-rest secrets — those go
through the DEK ring so rotation actually rotates them. `seal` is a
deliberately narrow escape hatch.

## Rotation

Per-blob rewrap is a pure function of the ring and the blob bytes:

```rust
# use envelope_aead::{DekRing, RewrapOutcome, rewrap_if_not_active};
# fn example(ring: &DekRing, blob: &[u8]) -> envelope_aead::Result<()> {
match rewrap_if_not_active(ring, blob)? {
    RewrapOutcome::AlreadyActive => {
        // leave the stored row untouched
    }
    RewrapOutcome::Rewrapped(new_bytes) => {
        // replace the stored row with new_bytes
        let _ = new_bytes;
    }
}
# Ok(()) }
```

The daemon owns the outer loop — which table, which row set, which
transaction, which audit event. That layer is deliberately not
generalised here because each daemon's storage inventory differs.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
