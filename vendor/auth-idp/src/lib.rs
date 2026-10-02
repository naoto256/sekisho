//! Authentication protocol primitives.
//!
//! Protocol-layer SAML and OIDC code. Pure library — no HTTP handlers,
//! no application state, no Store / DB dependency. Callers pass in a
//! constructed `reqwest::Client` and pre-decrypted secrets. Envelope
//! encryption of at-rest secrets lives in the separate `envelope-aead`
//! crate; this crate concerns itself only with the IdP protocol layer.

pub mod error;
pub mod http;
pub mod oidc;
pub mod saml;

pub use error::{Error, Result};
