//! Management API keys and their scopes.
//!
//! A key is never stored: only a keyed digest and an 8-character prefix are.
//! The prefix exists so an operator can recognize a key in a list and in audit
//! events without the daemon retaining anything that could authenticate.
//!
//! The digest is `HMAC-SHA256(master_key, raw_key)`, not a bare hash — see
//! [`crate::store::backend::api_key_hash`] for the stored form and the
//! constant-time verify. Keying it on the master key, which never leaves the
//! process, means a database dump on its own cannot be attacked offline at
//! all. A password KDF would be the wrong tool in the other direction: the
//! input is a 256-bit CSPRNG value, so there is no dictionary to stretch
//! against, and the cost would land on every management request.
//!
//! Both [`ApiKey`] and [`ApiKeyWithSecret`] carry hand-written `Debug` impls.
//! That is a security control, not formatting: these structs reach `tracing`
//! on error paths, and a derived `Debug` would put the hash — or, once, the
//! key itself — into the journal.

use chrono::serde::{ts_seconds, ts_seconds_option};
use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use uuid::Uuid;

/// A management privilege level.
///
/// **Variant order is the privilege lattice.** The derived `Ord` is what
/// [`ApiKeyScopeSet::allows`] compares, so declaring these least- to
/// most-privileged is load-bearing: reordering them silently changes
/// authorization everywhere, with nothing failing to compile. New levels must
/// be inserted at their correct rank, not appended.
///
/// The wire strings are pinned with `#[serde(rename)]` and the enum is closed,
/// so an unrecognized scope in a stored row fails to deserialize rather than
/// being ignored — a key whose scopes cannot be read must not be usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ApiKeyScope {
    #[serde(rename = "management:read")]
    Read,
    #[serde(rename = "management:write")]
    Write,
    #[serde(rename = "management:admin")]
    Admin,
}

impl ApiKeyScope {
    /// The canonical wire string. Duplicated from the `#[serde(rename)]`
    /// attributes because audit events and error messages need the name
    /// without going through serde.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "management:read",
            Self::Write => "management:write",
            Self::Admin => "management:admin",
        }
    }
}

impl std::fmt::Display for ApiKeyScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Non-empty, duplicate-free canonical API-key scopes.
///
/// The enum closes the accepted strings and `BTreeSet` gives a stable wire and
/// storage order (`read`, `write`, `admin`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyScopeSet(BTreeSet<ApiKeyScope>);

impl ApiKeyScopeSet {
    /// Whether this key satisfies `required`.
    ///
    /// Hierarchical, not exact-match: any held scope at or above `required`
    /// grants it, so a write key does not also have to be issued a read scope.
    /// A consequence worth knowing is that the set collapses — holding
    /// `admin` makes every other member redundant.
    pub fn allows(&self, required: ApiKeyScope) -> bool {
        self.0.iter().any(|scope| *scope >= required)
    }

    /// Tests only. Production scope sets always arrive by deserializing
    /// operator input, so they pass through the non-empty and duplicate-free
    /// checks in [`Deserialize`].
    #[cfg(test)]
    pub fn admin() -> Self {
        Self(BTreeSet::from([ApiKeyScope::Admin]))
    }

    /// Storage and wire use the same JSON encoding on purpose: one
    /// representation means a round-trip through the database cannot change
    /// what a key is allowed to do.
    pub fn to_storage(&self) -> std::result::Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Inverse of [`Self::to_storage`]. Fails closed on anything unparseable
    /// — the caller has no valid scope set, so the request cannot be
    /// authorized.
    pub fn from_storage(value: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(value)
    }
}

impl Serialize for ApiKeyScopeSet {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// Hand-written so the two invariants the type promises — non-empty, and free
/// of duplicates — are enforced at the parse boundary rather than checked by
/// each caller. A duplicate is rejected instead of silently deduplicated
/// because it means the operator's intent was unclear, and `BTreeSet` would
/// otherwise swallow the mistake.
impl<'de> Deserialize<'de> for ApiKeyScopeSet {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<ApiKeyScope>::deserialize(deserializer)?;
        if values.is_empty() {
            return Err(D::Error::custom("at least one API key scope is required"));
        }
        let len = values.len();
        let scopes = values.into_iter().collect::<BTreeSet<_>>();
        if scopes.len() != len {
            return Err(D::Error::custom("duplicate API key scope"));
        }
        Ok(Self(scopes))
    }
}

/// A key as stored and as listed through the API. Holds no material that can
/// authenticate a request.
#[derive(Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub name: String,
    /// The key prefix (first 8 chars) for identification. The full key is only
    /// returned once at creation time.
    pub prefix: String,
    /// Keyed digest of the full key (`$hmac$<hex>`), used for verification.
    /// Not a bare SHA-256 — see the module docs.
    #[serde(skip_serializing)]
    #[allow(dead_code)]
    pub key_hash: String,
    pub scopes: ApiKeyScopeSet,
    #[serde(with = "ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(default, with = "ts_seconds_option")]
    pub last_used_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for ApiKey {
    // Redact `key_hash`. The HMAC keying already means a leaked digest is not
    // offline-attackable without the master key, but a log line is a much
    // easier thing to exfiltrate than the master key is, so the two should
    // not be allowed to meet.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("prefix", &self.prefix)
            .field("key_hash", &"<redacted>")
            .field("scopes", &self.scopes)
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

/// Creation body. Scopes are required — there is no default, because the
/// safe default and the useful default are not the same and guessing either
/// one for the operator would be wrong.
#[derive(Debug, Deserialize)]
pub struct CreateApiKey {
    pub name: String,
    pub scopes: ApiKeyScopeSet,
}

/// Returned only once when an API key is created.
///
/// The one place a plaintext key exists in a response. Kept as a distinct
/// type so that "this value is secret" is visible in every signature that
/// touches it, rather than being a property of one particular handler.
#[derive(Serialize)]
pub struct ApiKeyWithSecret {
    #[serde(flatten)]
    pub api_key: ApiKey,
    pub key: String,
}

impl std::fmt::Debug for ApiKeyWithSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyWithSecret")
            .field("api_key", &self.api_key)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ApiKey {
        ApiKey {
            id: Uuid::nil(),
            name: "n".into(),
            prefix: "sk_abcd1".into(),
            key_hash: "deadbeefcafef00d".into(),
            scopes: ApiKeyScopeSet::admin(),
            created_at: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            last_used_at: None,
        }
    }

    #[test]
    fn debug_does_not_leak_api_key_hash() {
        let s = format!("{:?}", sample());
        assert!(!s.contains("deadbeefcafef00d"), "leak: {s}");
        assert!(s.contains("redacted"), "should mark: {s}");
    }

    #[test]
    fn debug_does_not_leak_api_key_secret() {
        let k = ApiKeyWithSecret {
            api_key: sample(),
            key: "sk_super_secret_value_42".into(),
        };
        let s = format!("{k:?}");
        assert!(!s.contains("super_secret_value"), "leak: {s}");
        assert!(s.contains("redacted"), "should mark: {s}");
    }

    #[test]
    fn scopes_are_closed_nonempty_duplicate_free_and_canonical() {
        let scopes: ApiKeyScopeSet =
            serde_json::from_str(r#"["management:admin","management:read","management:write"]"#)
                .unwrap();
        assert_eq!(
            serde_json::to_string(&scopes).unwrap(),
            r#"["management:read","management:write","management:admin"]"#
        );
        assert!(scopes.allows(ApiKeyScope::Read));
        assert!(scopes.allows(ApiKeyScope::Write));
        assert!(scopes.allows(ApiKeyScope::Admin));

        for invalid in [
            r#"[]"#,
            r#"["management:read","management:read"]"#,
            r#"["management:Read"]"#,
            r#"[" management:read"]"#,
            r#"["unknown"]"#,
        ] {
            assert!(serde_json::from_str::<ApiKeyScopeSet>(invalid).is_err());
        }
    }

    #[test]
    fn scope_hierarchy_is_monotonic() {
        let read: ApiKeyScopeSet = serde_json::from_str(r#"["management:read"]"#).unwrap();
        let write: ApiKeyScopeSet = serde_json::from_str(r#"["management:write"]"#).unwrap();
        let admin = ApiKeyScopeSet::admin();

        assert!(read.allows(ApiKeyScope::Read));
        assert!(!read.allows(ApiKeyScope::Write));
        assert!(!read.allows(ApiKeyScope::Admin));
        assert!(write.allows(ApiKeyScope::Read));
        assert!(write.allows(ApiKeyScope::Write));
        assert!(!write.allows(ApiKeyScope::Admin));
        assert!(admin.allows(ApiKeyScope::Read));
        assert!(admin.allows(ApiKeyScope::Write));
        assert!(admin.allows(ApiKeyScope::Admin));
    }
}
