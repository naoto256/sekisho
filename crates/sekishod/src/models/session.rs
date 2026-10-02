//! Server-side session state.
//!
//! Sessions live in the database, not in the cookie — the cookie carries only
//! a signed identifier. That is what makes immediate revocation possible and
//! keeps the browser from holding claims the daemon can no longer vouch for.
//!
//! ## Two views of identity, kept apart
//!
//! [`Session::user_id`] and `claims` are the compatibility view, populated
//! with fallbacks so older routes keep working. [`UpstreamIdentity`] is the
//! strict view: only what the IdP actually asserted, with no fallback anywhere
//! in its construction. Signed identity assertions read exclusively from the
//! strict view, because an inferred email that an upstream then authorizes on
//! is the failure mode the whole feature exists to avoid.
//!
//! ## Idle expiry is computed, not stored
//!
//! The constants below define an idle window instead of a stored deadline, so
//! the rule can change without migrating rows, and so every HA node reaches
//! the same verdict from the same `last_accessed_at`. Touches are throttled
//! and compared inside the database precisely so that "same verdict on every
//! node" survives clock skew between them.

use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Sessions are touched at most once per minute. The comparison is made by
/// the database so every HA node observes the same clock and durable value.
pub const SESSION_TOUCH_INTERVAL_SECS: i64 = 60;
/// A session may be idle for thirty minutes before the enforcement grace.
pub const SESSION_IDLE_TIMEOUT_SECS: i64 = 30 * 60;
/// Allows an in-flight request one touch interval to persist its access time.
pub const SESSION_ENFORCEMENT_GRACE_SECS: i64 = 60;
/// The value enforcement actually compares against: the idle timeout plus the
/// grace, so a request that arrives just before the deadline is not killed by
/// the touch it is itself about to perform.
pub const SESSION_IDLE_EXPIRY_SECS: i64 =
    SESSION_IDLE_TIMEOUT_SECS + SESSION_ENFORCEMENT_GRACE_SECS;

/// Which protocol asserted the identity. Retained because the two carry
/// different guarantees about what a subject means, and because sign-out has
/// to take a different path for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamIdentityProvenance {
    Oidc,
    Saml,
}

/// Identity exactly as the IdP asserted it, with no inference.
///
/// Deliberately narrow. Anything that had to be guessed, defaulted or derived
/// belongs in the session's `claims` map instead, so that a consumer asking
/// for this type gets a guarantee rather than a best effort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamIdentity {
    /// Protocol-native stable subject (`sub` for OIDC, NameID for SAML).
    pub subject: String,
    /// Email asserted explicitly by the upstream IdP. Never populated from
    /// Sekisho's compatibility fallback to subject / NameID.
    pub explicit_email: Option<String>,
    pub provenance: UpstreamIdentityProvenance,
}

/// One authenticated browser session.
///
/// Serialized as JSON into a single column, which is why nearly every field
/// carries `#[serde(default)]` or an explicit skip: rows written by older
/// builds must keep decoding, and fields that hold sealed material must never
/// be serialized into an API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    /// Display/compatibility subject. May have been derived by fallback; see
    /// `upstream_identity` for the version that never was.
    pub user_id: String,
    pub idp_id: Uuid,
    pub claims: HashMap<String, serde_json::Value>,
    pub groups: Vec<String>,
    /// Protocol identity retained separately from the compatibility
    /// `user_id`/claims view. Rows written before this field existed decode as
    /// `None` and remain usable for ordinary sessions, but cannot mint a
    /// signed identity assertion.
    #[serde(default)]
    pub upstream_identity: Option<UpstreamIdentity>,
    #[serde(with = "ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub expires_at: DateTime<Utc>,
    /// Encrypted refresh token (if available). Never serialized to API responses.
    /// Read via serde Deserialize when loading from DB.
    #[serde(skip_serializing)]
    #[allow(dead_code)]
    pub refresh_token_encrypted: Option<String>,
    /// Encrypted OIDC ID token (JWT), kept so sign-out can replay it
    /// as `id_token_hint` at the IdP's RP-Initiated Logout endpoint.
    /// SAML sessions never populate this.
    #[serde(skip_serializing)]
    pub id_token_encrypted: Option<String>,
    /// SAML NameID captured at login. Needed to build a SAML
    /// `LogoutRequest` at sign-out: the IdP identifies the session
    /// by NameID + Format, and without it SLO degrades to the
    /// local-only terminal page. OIDC sessions never populate this.
    pub saml_name_id: Option<String>,
    /// SAML `AuthnStatement/@SessionIndex` captured at login. Entra's
    /// SLO requires this value in the `LogoutRequest` so the IdP can
    /// correlate the request to the authenticated session; without it
    /// the tenant returns `AADSTS50068 "not a participant in the
    /// current session"`. OIDC sessions never populate this; SAML
    /// sessions from IdPs that omit `SessionIndex` also leave it
    /// `None`, in which case the LogoutRequest omits the element (the
    /// IdP falls back to matching by NameID alone).
    pub saml_session_index: Option<String>,
    #[serde(with = "ts_seconds")]
    pub last_accessed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_json_without_upstream_identity_decodes_as_none() {
        let now = Utc::now().timestamp();
        let value = serde_json::json!({
            "id": Uuid::new_v4(),
            "user_id": "legacy-subject",
            "idp_id": Uuid::new_v4(),
            "claims": {},
            "groups": [],
            "created_at": now,
            "expires_at": now + 3600,
            "refresh_token_encrypted": null,
            "id_token_encrypted": null,
            "saml_name_id": null,
            "saml_session_index": null,
            "last_accessed_at": now
        });
        let session: Session = serde_json::from_value(value).unwrap();
        assert!(session.upstream_identity.is_none());
    }
}
