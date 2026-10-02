//! Session lifetime and the cookie that carries its identifier.
//!
//! Two halves that are deliberately separate: [`manager`] owns server-side
//! state (create, validate, expire) and [`cookie_manager`] owns the browser
//! side (signing, attributes, clearing). The cookie never carries claims, only
//! a signed identifier, so the two only meet at that id — which is what makes
//! revocation immediate and keeps the browser from holding anything the daemon
//! can no longer vouch for.

pub mod cookie_manager;
pub mod manager;

#[cfg(test)]
#[path = "cookie_test.rs"]
mod cookie_test;
