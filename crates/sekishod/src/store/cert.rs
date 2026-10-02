//! Certificate persistence.
//!
//! Every method here is a one-line `dispatch!` into the active
//! [`crate::store::backend::Backend`]. The indirection is the point: callers
//! name the operation, the enum decides whether SQLite or Postgres serves it,
//! and a backend that forgot to implement one is a compile error rather than a
//! runtime surprise. The degraded `Unavailable` arm turns every call here into
//! a clean 503.
//!
//! `upsert_cert` rather than separate insert and update: both ACME renewal and
//! operator upload mean "this domain should now be served by this
//! certificate", and making the caller first ask whether a row exists would
//! add a race for no benefit.

use crate::error::Result;
use crate::models::cert::Certificate;
use uuid::Uuid;

use super::Store;
use super::dispatch;

impl Store {
    pub async fn list_certs(&self) -> Result<Vec<Certificate>> {
        dispatch!(self, list_certs)
    }

    pub(crate) async fn list_certs_page(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Certificate>> {
        dispatch!(self, list_certs_page, limit, offset)
    }

    pub async fn get_cert(&self, id: Uuid) -> Result<Certificate> {
        dispatch!(self, get_cert, id)
    }

    pub async fn upsert_cert(&self, cert: &Certificate) -> Result<()> {
        dispatch!(self, upsert_cert, cert)
    }

    pub async fn delete_cert(&self, id: Uuid) -> Result<()> {
        dispatch!(self, delete_cert, id)
    }

    /// Certificates expiring within `days_before` days. Drives the renewal
    /// scan; the window is a parameter rather than a constant so the scan
    /// interval and the renewal lead time can be tuned independently.
    pub async fn get_expiring_certs(&self, days_before: i64) -> Result<Vec<Certificate>> {
        dispatch!(self, get_expiring_certs, days_before)
    }
}
