//! Route persistence.
//!
//! Every method here is a one-line `dispatch!` into the active
//! [`crate::store::backend::Backend`]. The indirection is the point: callers
//! name the operation, the enum decides whether SQLite or Postgres serves it,
//! and a backend that forgot to implement one is a compile error rather than a
//! runtime surprise. The degraded `Unavailable` arm turns every call here into
//! a clean 503.
//!
//! Note the two list shapes. `list_routes` is unbounded and used internally
//! where the caller genuinely needs every route (cache rebuild, reference
//! checks); `list_routes_page` is what the API uses, so an operator with a
//! large route table cannot be served an unbounded response.

use crate::error::Result;
use crate::models::route::Route;
use uuid::Uuid;

/// One coherent database observation of the route version and all route rows.
///
/// The version and the rows must come from the same read, or a cache rebuild
/// can stamp a generation with a version number that does not describe the
/// rows it contains — after which the next change looks like a no-op and the
/// data plane serves stale routes indefinitely.
#[derive(Debug)]
pub(crate) struct RouteObservation {
    pub(crate) version: u64,
    pub(crate) routes: Vec<Route>,
}

use super::Store;
use super::dispatch;

impl Store {
    /// Read the route table and its version atomically. The only correct
    /// input for a cache rebuild; see [`RouteObservation`].
    pub(crate) async fn observe_routes(&self) -> Result<RouteObservation> {
        dispatch!(self, observe_routes)
    }

    pub async fn list_routes(&self) -> Result<Vec<Route>> {
        dispatch!(self, list_routes)
    }

    pub(crate) async fn list_routes_page(&self, limit: i64, offset: i64) -> Result<Vec<Route>> {
        dispatch!(self, list_routes_page, limit, offset)
    }

    pub async fn get_route(&self, id: Uuid) -> Result<Route> {
        dispatch!(self, get_route, id)
    }

    pub async fn create_route(&self, route: &Route) -> Result<()> {
        dispatch!(self, create_route, route)
    }

    /// Apply an RFC 7396 merge patch under the backend's writer lock and
    /// return the merged row. Takes raw JSON rather than `UpdateRoute` because
    /// merge semantics are defined over the document, not over the Rust type —
    /// which is also how "set this field to null" survives the trip.
    pub async fn update_route(&self, id: Uuid, update: serde_json::Value) -> Result<Route> {
        dispatch!(self, update_route, id, update)
    }

    pub async fn delete_route(&self, id: Uuid) -> Result<()> {
        dispatch!(self, delete_route, id)
    }
}
