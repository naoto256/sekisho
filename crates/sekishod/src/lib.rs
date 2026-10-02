//! `sekishod` — the sekisho daemon.
//!
//! A single process serves three concurrent surfaces over one shared
//! `state::AppState`:
//!
//! 1. **TLS reverse proxy** (`proxy`) — SNI-resolved rustls listener, route
//!    match, authentication, policy evaluation, then an outbound transform
//!    pipeline into the upstream.
//! 2. **Management REST API** (`api`) — CRUD over routes, IdPs, policies,
//!    certificates, sessions, API keys and global config, nested under
//!    `/.sekisho/api/v1` on its own RPK-pinned TLS 1.3 listener.
//! 3. **ACME client** (`tls::acme`) — HTTP-01 issuance and renewal for the
//!    downstream certificates the proxy listener serves.
//!
//! ## Why a library crate with a near-empty binary
//!
//! The daemon lives here rather than in `main.rs` so that integration tests
//! can drive the same startup path the binary does. Nothing outside this
//! workspace is meant to depend on `sekishod`, so the module tree below is
//! private and the handful of `pub` re-exports at the bottom are exactly the
//! binary's contract — the management clients talk HTTP, not Rust.
//!
//! ## Where the invariants live
//!
//! - `validation` is the single admission gate for management writes; the
//!   store layer assumes its input is already validated.
//! - `identity` owns the canonical-origin rules behind signed identity
//!   tokens, and is consulted from both the admission path and the proxy.
//! - `startup` runs the boot-time consistency checks that must pass before
//!   any listener binds.

mod acl;
mod api;
mod audit;
mod auth;
mod config;
#[allow(unused_imports)]
mod crypto;
mod error;
mod identity;
mod models;
mod observability;
mod policy;
mod proxy;
mod request_target;
mod route_generation;
mod runtime;
mod session;
mod shutdown;
mod startup;
mod state;
mod store;
mod tls;
mod validation;

pub(crate) use audit::{audit_crypto, audit_mgmt};
pub use config::CliConfig;
pub use runtime::{ManagementRpkCommand, management_rpk_one_shot, run};
