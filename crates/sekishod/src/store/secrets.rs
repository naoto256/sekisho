//! Encrypted key-value secrets.
//!
//! Every method here is a one-line `dispatch!` into the active
//! [`crate::store::backend::Backend`]. The indirection is the point: callers
//! name the operation, the enum decides whether SQLite or Postgres serves it,
//! and a backend that forgot to implement one is a compile error rather than a
//! runtime surprise. The degraded `Unavailable` arm turns every call here into
//! a clean 503.

use crate::error::Result;

use super::Store;
use super::dispatch;

impl Store {
    pub async fn get_secret(&self, key: &str) -> Result<Option<String>> {
        dispatch!(self, get_secret, key)
    }

    pub async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        dispatch!(self, set_secret, key, value)
    }
}
