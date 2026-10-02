//! Envelope encryption primitives — KEK-wrapped DEK ring + versioned
//! XChaCha20-Poly1305 blobs for at-rest secret storage.
//!
//! # Threat model in one paragraph
//!
//! A daemon holds a long-lived 32-byte **KEK** (root secret). Data is
//! encrypted under a **DEK** (rotatable 32-byte data-encryption key)
//! that is itself KEK-sealed on disk. Rotating the DEK re-encrypts
//! all data without touching the KEK; the KEK is bootstrapped from
//! whatever secure source the daemon can arrange (env var, KMS, HSM,
//! sealed file) and only handled at process start.
//!
//! # Wire formats
//!
//! Both formats are XChaCha20-Poly1305 with a 24-byte random nonce
//! and 16-byte Poly1305 tag; AAD is empty.
//!
//! ```text
//! v2: 0x02 || nonce(24) || ciphertext+tag       -- KEK-sealed
//! v3: 0x03 || key_id(1) || nonce(24) || ciphertext+tag -- DEK-routed
//! ```
//!
//! v2 blobs are read/written through [`Kek::seal`] / [`Kek::open`] and
//! are appropriate only for a narrow class of ring-independent
//! secrets (bootstrap config that must decrypt before the ring loads;
//! short-lived tokens that gain nothing from rotation). Everything
//! else is v3 through the [`DekRing`].
//!
//! # Typed AEAD boundary
//!
//! The **AEAD write / read entry points are private**: raw
//! `encrypt_v2` / `decrypt_v2` / `encrypt_v3` / `decrypt_v3_with`
//! functions are `pub(crate)` only, and callers cannot spell an
//! envelope operation without going through the typed API. Encryption
//! happens exclusively through [`Kek::seal`] (v2, narrow use) and
//! [`DekRing::encrypt_active`] / [`DekRing::encrypt_with`] (v3).
//!
//! Raw `[u8; 32]` **KEK material** does have one public ingress —
//! [`Kek::from_bytes`] — because callers loading a KEK from a KMS
//! blob or a sealed file need a way to hand it over. `from_hex` is
//! the second, string-shaped, ingress. Both immediately copy into
//! [`zeroize::Zeroizing`] storage, and there is no public accessor to read the
//! bytes back out. Every downstream use goes through the typed
//! surface.
//!
//! All secret types ([`Kek`], [`DekPlaintext`], [`DekRing`]) hold
//! their key material in [`zeroize::Zeroizing`] and redact `Debug`, so key
//! bytes never leak into `tracing` output or panic backtraces.
//!
//! # Scope
//!
//! In scope:
//!
//! - Envelope AEAD format (v2 / v3)
//! - Typed KEK / DEK / key-id / ring primitives
//! - Loading a ring from encrypted storage records
//! - Bootstrap of the initial DEK
//! - Per-blob rewrap (`rewrap_if_not_active`) and key-id peek
//!
//! Out of scope (kept in the caller / daemon):
//!
//! - Storage schemas, SQL migrations, transactional semantics
//! - Ring version polling / refresh loops / HA leader fencing
//! - Bulk table walking / encrypted-column inventory
//! - Management API, CLI verbs, audit events
//! - KEK source policy (env variable names, file paths, KMS integration)
//! - Format migration timing (when to rewrap v2 → v3 etc.)
//! - KEK rotation itself (the KEK is treated as a fixed root)

pub mod bootstrap;
pub mod dek;
pub mod error;
pub mod kek;
pub mod ring;
pub mod rotation;

mod format;

pub use bootstrap::{InitialDekBootstrap, bootstrap_initial_dek};
pub use dek::{DekKeyId, DekPlaintext, EncryptedDekBlob};
pub use error::{Error, Result};
pub use kek::Kek;
pub use ring::{DekRing, EncryptedDekRecord, RewrapOutcome};
pub use rotation::{peek_key_id, peek_key_id_from_base64, rewrap_if_not_active};

/// Version byte prefixing every v2 blob.
pub const CIPHER_V2: u8 = format::V2;
/// Version byte prefixing every v3 blob.
pub const CIPHER_V3: u8 = format::V3;
/// XChaCha20 nonce length, in bytes.
pub const NONCE_LEN: usize = format::NONCE_LEN;
/// Poly1305 tag length, in bytes.
pub const TAG_LEN: usize = format::TAG_LEN;
