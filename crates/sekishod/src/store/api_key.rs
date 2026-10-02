//! API key persistence.
//!
//! Every method here is a one-line `dispatch!` into the active
//! [`crate::store::backend::Backend`]. The indirection is the point: callers
//! name the operation, the enum decides whether SQLite or Postgres serves it,
//! and a backend that forgot to implement one is a compile error rather than a
//! runtime surprise. The degraded `Unavailable` arm turns every call here into
//! a clean 503.
//!
//! The hash never leaves this layer in either direction: [`Store::create_api_key`]
//! generates the key and returns the plaintext exactly once, and
//! [`Store::lookup_api_key`] takes the raw key and does the comparison
//! backend-side. A caller therefore has no way to hold a hash, and no way to
//! authenticate with one.

use crate::error::Result;
use crate::models::api_key::{ApiKey, ApiKeyScopeSet, ApiKeyWithSecret};
use uuid::Uuid;

use super::Store;
use super::dispatch;

impl Store {
    pub async fn create_api_key(
        &self,
        name: &str,
        scopes: &ApiKeyScopeSet,
    ) -> Result<ApiKeyWithSecret> {
        dispatch!(self, create_api_key, name, scopes)
    }

    pub async fn get_api_key(&self, id: Uuid) -> Result<ApiKey> {
        dispatch!(self, get_api_key, id)
    }

    /// Resolve a presented key to its record, or `NotFound`.
    ///
    /// Takes the raw key rather than a hash so hashing stays in one place and
    /// the comparison can be done the way the backend requires. The error
    /// deliberately does not distinguish "no such key" from "malformed key".
    pub async fn lookup_api_key(&self, raw_key: &str) -> Result<ApiKey> {
        dispatch!(self, lookup_api_key, raw_key)
    }

    /// Record that a key was just used. Best-effort at the call site: an
    /// authorization decision has already been made, and failing the request
    /// over a bookkeeping write would turn a degraded database into a lockout.
    pub async fn touch_api_key_usage(&self, id: Uuid) -> Result<()> {
        dispatch!(self, touch_api_key_usage, id)
    }

    #[allow(dead_code)] // Retained as the unbounded internal operation.
    pub async fn list_api_keys(&self) -> Result<Vec<ApiKey>> {
        dispatch!(self, list_api_keys)
    }

    pub(crate) async fn list_api_keys_page(&self, limit: i64, offset: i64) -> Result<Vec<ApiKey>> {
        dispatch!(self, list_api_keys_page, limit, offset)
    }

    pub async fn delete_api_key(&self, id: Uuid) -> Result<()> {
        dispatch!(self, delete_api_key, id)
    }

    #[allow(dead_code)] // exercised by store_test; kept for future ops/admin use
    pub async fn api_key_count(&self) -> Result<i64> {
        dispatch!(self, api_key_count)
    }
}
