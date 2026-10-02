//! Session persistence.
//!
//! Every method here is a one-line `dispatch!` into the active
//! [`crate::store::backend::Backend`]. The indirection is the point: callers
//! name the operation, the enum decides whether SQLite or Postgres serves it,
//! and a backend that forgot to implement one is a compile error rather than a
//! runtime surprise. The degraded `Unavailable` arm turns every call here into
//! a clean 503.
//!
//! ## Two read paths, on purpose
//!
//! [`Store::get_session`] returns the row for management listing.
//! [`Store::get_session_for_validation`] answers the proxy's different
//! question — "is this session usable right now?" — and returns a
//! [`SessionValidation`] that already encodes expiry and idleness. Letting the
//! request path load a row and judge it itself would put the same rule in two
//! places, and the judgement has to be made against the database's clock in HA
//! rather than whichever node happens to be serving.
//!
//! ## Touching is a conditional write
//!
//! [`Store::touch_session_if_due`] carries the caller's observed
//! `last_accessed_at` so the backend can decide, in one statement, whether the
//! throttle interval has elapsed. That compare-and-set shape is what keeps
//! concurrent requests for the same session from each issuing a write, and
//! keeps the decision on the database's clock.

use crate::error::Result;
use crate::models::session::Session;
use crate::store::backend::{SessionTouchOutcome, SessionValidation};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::Store;
use super::dispatch;

impl Store {
    pub async fn create_session(&self, session: &Session) -> Result<()> {
        dispatch!(self, create_session, session)
    }

    pub async fn get_session(&self, id: Uuid) -> Result<Session> {
        dispatch!(self, get_session, id)
    }

    pub(crate) async fn get_session_for_validation(&self, id: Uuid) -> Result<SessionValidation> {
        dispatch!(self, get_session_for_validation, id)
    }

    pub(crate) async fn touch_session_if_due(
        &self,
        id: Uuid,
        expected_last_accessed_at: DateTime<Utc>,
    ) -> Result<SessionTouchOutcome> {
        dispatch!(self, touch_session_if_due, id, expected_last_accessed_at)
    }

    pub async fn list_sessions(
        &self,
        user_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Session>> {
        dispatch!(self, list_sessions, user_filter, limit, offset)
    }

    pub async fn delete_session(&self, id: Uuid) -> Result<()> {
        dispatch!(self, delete_session, id)
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<u64> {
        dispatch!(self, cleanup_expired_sessions)
    }
}
