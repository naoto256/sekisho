//! Identity provider persistence.
//!
//! Every method here is a one-line `dispatch!` into the active
//! [`crate::store::backend::Backend`]. The indirection is the point: callers
//! name the operation, the enum decides whether SQLite or Postgres serves it,
//! and a backend that forgot to implement one is a compile error rather than a
//! runtime surprise. The degraded `Unavailable` arm turns every call here into
//! a clean 503.
//!
//! Rows here hold the *sealed* OIDC client secret; sealing happens in
//! [`crate::api::idps`] before anything reaches this layer, so nothing in this
//! module needs the master key.

use crate::error::Result;
use crate::models::idp::IdentityProvider;
use uuid::Uuid;

use super::Store;
use super::dispatch;

impl Store {
    pub async fn list_idps(&self) -> Result<Vec<IdentityProvider>> {
        dispatch!(self, list_idps)
    }

    pub(crate) async fn list_idps_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<IdentityProvider>> {
        dispatch!(self, list_idps_page, limit, offset)
    }

    pub async fn get_idp(&self, id: Uuid) -> Result<IdentityProvider> {
        dispatch!(self, get_idp, id)
    }

    pub async fn create_idp(&self, idp: &IdentityProvider) -> Result<()> {
        dispatch!(self, create_idp, idp)
    }

    pub async fn update_idp(
        &self,
        id: Uuid,
        update: serde_json::Value,
    ) -> Result<IdentityProvider> {
        dispatch!(self, update_idp, id, update)
    }

    pub async fn delete_idp(&self, id: Uuid) -> Result<()> {
        dispatch!(self, delete_idp, id)
    }
}
