//! Policy storage facade. Same dispatch pattern as the other resources;
//! the backend handles the JSON-blob DB operations.
//!
//! Note `get_policy_by_name` alongside the id lookup: policies are the one
//! resource referenced by name from inside another resource's data — a route's
//! expression says `policy.<name>` — so the name is a lookup key on the
//! evaluation path, not just a label.

use crate::error::Result;
use crate::models::policy::Policy;
use uuid::Uuid;

use super::Store;
use super::dispatch;

impl Store {
    #[allow(dead_code)] // Retained as the unbounded internal operation.
    pub async fn list_policies(&self) -> Result<Vec<Policy>> {
        dispatch!(self, list_policies)
    }

    pub(crate) async fn list_policies_page(&self, limit: i64, offset: i64) -> Result<Vec<Policy>> {
        dispatch!(self, list_policies_page, limit, offset)
    }

    pub async fn get_policy(&self, id: Uuid) -> Result<Policy> {
        dispatch!(self, get_policy, id)
    }

    pub async fn get_policy_by_name(&self, name: &str) -> Result<Policy> {
        dispatch!(self, get_policy_by_name, name)
    }

    pub async fn create_policy(&self, p: &Policy) -> Result<()> {
        dispatch!(self, create_policy, p)
    }

    pub async fn update_policy(&self, id: Uuid, update: serde_json::Value) -> Result<Policy> {
        dispatch!(self, update_policy, id, update)
    }

    pub async fn delete_policy(&self, id: Uuid) -> Result<()> {
        dispatch!(self, delete_policy, id)
    }
}
