//! Serde data model for everything the daemon persists or exposes.
//!
//! These types are the contract the whole system is organized around: the
//! management API stores JSON, the store layer merges patches against that
//! JSON generically, and the clients compile in their own knowledge of the
//! same shapes. Adding a field here is therefore usually enough — the storage
//! layer never has to learn about it.
//!
//! Two conventions recur across the submodules and are worth knowing once:
//!
//! - **Three types per resource.** `Xxx` is the stored/serving form,
//!   `CreateXxx` the POST body, `UpdateXxx` the PATCH body. They are separate
//!   types rather than one type with optional fields because each has
//!   different required fields and different defaults, and collapsing them
//!   would make "required on create, immutable on update" unexpressible.
//! - **`Option<Option<T>>` on patch types.** RFC 7396 merge patch gives `null`
//!   and "absent" different meanings — clear the field versus leave it alone —
//!   and plain `Option<T>` collapses both to `None`. See
//!   [`serde_util::deserialize_some`].
//!
//! Secrets stored inside these structs are encrypted before they get here, and
//! the types that can still hold plaintext carry hand-written `Debug` impls
//! that redact. Those impls are load-bearing, not cosmetic: the structs are
//! logged on the error paths.

pub mod acme_queue;
pub mod api_key;
pub mod cert;
pub mod config;
pub mod idp;
pub mod policy;
pub mod route;
pub mod serde_util;
pub mod session;
