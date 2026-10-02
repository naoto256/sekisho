//! `Policy` — a named, reusable boolean expression evaluated against the
//! session and request context. The expression is stored verbatim as a string;
//! see `crate::policy` for the grammar and evaluator.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    /// Unique within the sekisho instance. Routes reference policies by name.
    pub name: String,
    /// The policy expression source (verbatim, comments and whitespace
    /// preserved). Parsed on every request — keep parser fast.
    pub expr: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreatePolicy {
    pub name: String,
    pub expr: String,
}

impl CreatePolicy {
    pub fn into_policy(self) -> Policy {
        Policy {
            id: Uuid::new_v4(),
            name: self.name.trim().to_string(),
            expr: self.expr,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdatePolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expr: Option<String>,
}
