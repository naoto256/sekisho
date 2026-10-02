//! Cluster-wide global configuration.
//!
//! Exactly one row of this exists per service database, and every node in an
//! HA deployment reads the same one. That is the dividing line against the
//! per-instance config: anything a peer must be able to set differently
//! (bind addresses, most obviously) lives there, and anything that must be
//! identical fleet-wide lives here. Getting that split wrong is how two nodes
//! end up disagreeing about who may issue a certificate.
//!
//! ## Every field must survive a row written by an older build
//!
//! New fields carry `#[serde(default = ...)]` and the default lives in a named
//! `const fn` rather than inline, so the same value backs both deserialization
//! and [`GlobalConfig::default`]. Two literals would drift, and the drift
//! would show up as a limit that changes when a config row happens to be
//! rewritten.
//!
//! ## Which changes need a restart
//!
//! Some limits are read once at startup and some are read per operation. The
//! per-field docs say which, because there is no way to tell from the type and
//! it is the first thing an operator asks after a `set`.

use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

/// Stable lowercase representation of the `Set-Cookie` `SameSite`
/// attribute. Persisted as a string so a `sekisho-cli set
/// session_cookie_samesite none` reads naturally; clamped at the API
/// layer so unknown values can't slip through to `cookie::SameSite`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SameSiteMode {
    /// Browser sends the cookie on same-site requests and on top-
    /// level cross-site GETs. Blocks cross-site POST. Default — the
    /// modern browser default and the right CSRF posture for an
    /// IAP that doesn't sit in front of legacy SAML SP routes.
    #[default]
    Lax,
    /// Strictly same-site only. Cross-site GET is also blocked. Too
    /// strict for any IAP that needs OIDC/SAML callbacks to work,
    /// included for completeness.
    Strict,
    /// Browser sends the cookie on every request regardless of
    /// initiator, including cross-site POSTs. Required when an
    /// upstream behind the IAP runs its own SAML SP and the
    /// SAMLResponse POST from the IdP needs to carry the IAP's
    /// session cookie back. Trades CSRF blast radius for SP
    /// compatibility — `Secure` is always also set, so the cookie
    /// at least never traverses a cleartext channel.
    None,
}

impl SameSiteMode {
    /// Map to the `cookie` crate's `SameSite` enum so the cookie
    /// builder can consume it directly without re-parsing.
    pub fn as_cookie(&self) -> cookie::SameSite {
        match self {
            Self::Lax => cookie::SameSite::Lax,
            Self::Strict => cookie::SameSite::Strict,
            Self::None => cookie::SameSite::None,
        }
    }
}

/// `Option<Option<T>>` fields need this helper to tell "JSON null" from
/// "field omitted". Without it, serde's default Option deserializer
/// collapses both into `None`, which is the opposite of what a merge-patch
/// API wants — null means "clear this", missing means "leave it alone".
///
/// Identical in behaviour to [`crate::models::serde_util::deserialize_some`],
/// which is what the other model modules use.
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// The singleton config row. Read at startup and, for the fields marked as
/// such below, again per operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    // NOTE: `proxy_listen`, `api_listen`, `http_listen` used to live
    // here. They moved to the per-instance bootstrap SQLite (the
    // `instance_config` table, with `encrypted = 0`) because bind addresses are
    // node-local — in HA every peer needs its own — and putting them
    // in the cluster-wide service DB forced every node to share an
    // address. They're now read/written through `InstanceStore` and
    // the `/instance` management endpoint.
    pub auth_domain: Option<String>,
    pub cookie_name: String,
    pub session_lifetime_hours: u32,
    pub default_idp_id: Option<Uuid>,
    pub acme_email: Option<String>,
    pub acme_directory: String,
    /// In an HA deployment, only the effective leader calls Let's
    /// Encrypt on behalf of the cluster — otherwise every node races
    /// to issue the same cert and burns through ACME rate limits.
    /// This field pins the leader by node identifier (matching
    /// `SEKISHO_NODE_ID` or the host's OS hostname). When it's `None`
    /// the effective leader is chosen by automatic election against
    /// `acme_leader_election`; a node without a matching election row
    /// is non-leader and fails closed on issuance. Each node with its
    /// HTTP listener enabled can answer HTTP-01 challenges; the
    /// effective leader owns issuance.
    #[serde(default)]
    pub acme_leader: Option<String>,
    /// Per-process cap for established WebSocket tunnels. Loaded at
    /// startup; changing it requires a daemon restart. Requests that
    /// arrive while the cap is full are rejected immediately with
    /// `503 Service Unavailable`; they are not queued and no upstream
    /// connection is opened.
    #[serde(default = "default_websocket_concurrency_limit")]
    pub websocket_concurrency_limit: u32,
    /// Cluster-wide cap for active ACME queue rows (`pending` plus
    /// `in_progress`). Read transactionally by the service-DB admission
    /// path, so updates take effect without restarting the daemon.
    #[serde(default = "default_acme_queue_capacity")]
    pub acme_queue_capacity: u32,
    /// Maximum number of ACME orders started concurrently by the elected
    /// queue worker. Loaded at startup; changing it requires a restart.
    #[serde(default = "default_acme_issuance_concurrency_limit")]
    pub acme_issuance_concurrency_limit: u32,
    /// Interval between scans that enqueue certificates due for renewal.
    /// Loaded at startup; changing it requires a restart.
    #[serde(default = "default_acme_renewal_scan_interval_hours")]
    pub acme_renewal_scan_interval_hours: u32,
    pub log_level: String,
}

/// Sized for the tunnel-heavy case an IAP actually sees (terminal and
/// remote-desktop front-ends), not for general HTTP traffic: each permit
/// holds a socket and a task for as long as the tunnel lives.
pub const fn default_websocket_concurrency_limit() -> u32 {
    100
}

/// A backlog bound, not a throughput target. Large enough that a bulk enable
/// of an entire fleet of routes is not rejected, small enough that a runaway
/// enqueue loop is visible as a failure instead of unbounded growth.
pub const fn default_acme_queue_capacity() -> u32 {
    1_000
}

/// Kept deliberately small: the bottleneck is the ACME directory's own rate
/// limits, and more parallel orders buy nothing while making a rate-limit
/// lockout easier to trigger.
pub const fn default_acme_issuance_concurrency_limit() -> u32 {
    5
}

/// Twice a day. The renewal window is measured in weeks, so the scan only has
/// to be frequent enough that a node being down for a maintenance window
/// cannot cause a miss.
pub const fn default_acme_renewal_scan_interval_hours() -> u32 {
    12
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            auth_domain: None,
            cookie_name: "_sekisho_session".to_string(),
            session_lifetime_hours: 8,
            default_idp_id: None,
            acme_email: None,
            acme_directory: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            acme_leader: None,
            websocket_concurrency_limit: default_websocket_concurrency_limit(),
            acme_queue_capacity: default_acme_queue_capacity(),
            acme_issuance_concurrency_limit: default_acme_issuance_concurrency_limit(),
            acme_renewal_scan_interval_hours: default_acme_renewal_scan_interval_hours(),
            log_level: "info".to_string(),
        }
    }
}

/// Patch body for [`GlobalConfig`]. Plain `Option<T>` on fields that are
/// non-nullable in the stored form (there is nothing to clear them to) and
/// `Option<Option<T>>` only where `null` is a meaningful value.
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateGlobalConfig {
    // proxy_listen / api_listen are no longer here — they live in the
    // per-instance bootstrap config now. PATCH them via `/instance`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_lifetime_hours: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_idp_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme_directory: Option<String>,
    /// Same null-vs-missing story as `api_listen`. `Some(None)` clears
    /// the static pin and returns to automatic election; a node without
    /// a matching election row is non-leader and fails closed.
    /// `Some(Some("node-a"))` pins issuance to a specific node.
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub acme_leader: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket_concurrency_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme_queue_capacity: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme_issuance_concurrency_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme_renewal_scan_interval_hours: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_default_for_new_and_legacy_config() {
        assert_eq!(GlobalConfig::default().websocket_concurrency_limit, 100);
        assert_eq!(GlobalConfig::default().acme_queue_capacity, 1_000);
        assert_eq!(GlobalConfig::default().acme_issuance_concurrency_limit, 5);
        assert_eq!(GlobalConfig::default().acme_renewal_scan_interval_hours, 12);
        let legacy = serde_json::json!({
            "auth_domain": null,
            "cookie_name": "_sekisho_session",
            "session_lifetime_hours": 8,
            "default_idp_id": null,
            "acme_email": null,
            "acme_directory": "https://acme.invalid/directory",
            "acme_leader": null,
            "log_level": "info"
        });
        let parsed: GlobalConfig = serde_json::from_value(legacy).expect("legacy config");
        assert_eq!(parsed.websocket_concurrency_limit, 100);
        assert_eq!(parsed.acme_queue_capacity, 1_000);
        assert_eq!(parsed.acme_issuance_concurrency_limit, 5);
        assert_eq!(parsed.acme_renewal_scan_interval_hours, 12);
    }
}
