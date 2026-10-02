//! Management API path constants shared by the daemon and its clients.
//!
//! The daemon mounts these under `/.sekisho/api/v1` and the clients append
//! them to their configured base URL. Sharing the literals rather than
//! repeating them is what keeps a path rename from becoming a runtime 404 in
//! one of three crates that all ship together — the compiler catches it
//! instead.
//!
//! Paths only. This crate deliberately does not re-export the server's data
//! model: clients own their own presentation types, and a shared model would
//! put the daemon back in the business of knowing about its UIs.

pub const ROUTES: &str = "/routes";
pub const IDPS: &str = "/idps";
pub const POLICIES: &str = "/policies";
pub const CERTS: &str = "/certs";
pub const CERTS_UPLOAD: &str = "/certs/upload";
pub const CERTS_QUEUE: &str = "/certs/queue";
pub const API_KEYS: &str = "/api_keys";
pub const SESSIONS: &str = "/sessions";
pub const CONFIG: &str = "/config";
pub const INSTANCE: &str = "/instance";
pub const VERSION: &str = "/version";
pub const HEALTH: &str = "/health";
pub const ACME_LEADER_ELECTION: &str = "/acme/leader_election";
pub const ENCRYPTION_KEYS: &str = "/encryption_keys";
pub const READY: &str = "/ready";
pub const HEALTHZ: &str = "/healthz";
pub const READYZ: &str = "/readyz";
pub const METRICS: &str = "/metrics";
