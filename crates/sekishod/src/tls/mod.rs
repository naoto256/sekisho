//! Downstream and management-plane TLS.
//!
//! Three concerns that share nothing but the name: [`acme`] obtains
//! certificates, [`resolver`] picks one per SNI at handshake time, and [`api`]
//! builds the management listener's config — which is raw-public-key pinned
//! rather than certificate-based, because its clients are the operator's own
//! tools and a pin is a stronger and simpler statement than a PKI chain.

pub mod acme;
pub mod api;
pub mod resolver;
