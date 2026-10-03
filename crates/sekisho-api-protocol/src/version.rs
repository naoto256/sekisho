//! Management API version negotiation shared by the daemon and both clients.
//!
//! API v1 predates the `api_version` response field. A missing field therefore
//! means v1; once a server moves to a later API version it must report that
//! version explicitly.

use serde_json::Value;

/// Management API version implemented by this workspace.
pub const API_VERSION: u64 = 1;

/// API version spoken by daemons that predate the `api_version` field.
const LEGACY_API_VERSION: u64 = 1;

/// Compatibility of one daemon `/version` response with this client build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionCompatibility {
    Match,
    ProductMismatch {
        server_version: String,
    },
    ApiMismatch {
        server_version: String,
        server_api_version: u64,
    },
    InvalidResponse {
        reason: String,
    },
}

/// Classify a decoded daemon `/version` response.
///
/// Product versions are diagnostic only. API versions are the compatibility
/// boundary, and an explicit malformed value fails closed. The absent-field
/// fallback is intentionally limited to v1 compatibility.
pub fn classify_version_response(
    value: &Value,
    client_product_version: &str,
) -> VersionCompatibility {
    let Some(server_version) = value.get("version").and_then(Value::as_str) else {
        return VersionCompatibility::InvalidResponse {
            reason: "missing string `version` field".to_string(),
        };
    };

    let server_api_version = match value.get("api_version") {
        None => LEGACY_API_VERSION,
        Some(value) => match value.as_u64() {
            Some(version) => version,
            None => {
                return VersionCompatibility::InvalidResponse {
                    reason: "`api_version` must be a non-negative integer".to_string(),
                };
            }
        },
    };

    if server_api_version != API_VERSION {
        return VersionCompatibility::ApiMismatch {
            server_version: server_version.to_string(),
            server_api_version,
        };
    }

    if server_version != client_product_version {
        return VersionCompatibility::ProductMismatch {
            server_version: server_version.to_string(),
        };
    }

    VersionCompatibility::Match
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_api_version_is_legacy_v1() {
        let response = serde_json::json!({ "version": "0.1.0" });
        assert_eq!(LEGACY_API_VERSION, 1);
        assert_eq!(
            classify_version_response(&response, "0.1.0"),
            VersionCompatibility::Match
        );
    }

    #[test]
    fn legacy_v1_with_product_skew_remains_compatible() {
        let response = serde_json::json!({ "version": "0.1.0" });
        assert_eq!(
            classify_version_response(&response, "0.1.1"),
            VersionCompatibility::ProductMismatch {
                server_version: "0.1.0".to_string(),
            }
        );
    }

    #[test]
    fn explicit_v1_is_accepted() {
        let response = serde_json::json!({
            "version": "0.1.0",
            "api_version": API_VERSION,
        });
        assert_eq!(
            classify_version_response(&response, "0.1.0"),
            VersionCompatibility::Match
        );
    }

    #[test]
    fn product_mismatch_remains_compatible() {
        let response = serde_json::json!({
            "version": "0.1.1",
            "api_version": API_VERSION,
        });
        assert_eq!(
            classify_version_response(&response, "0.1.0"),
            VersionCompatibility::ProductMismatch {
                server_version: "0.1.1".to_string(),
            }
        );
    }

    #[test]
    fn api_mismatch_takes_precedence_over_product_mismatch() {
        let response = serde_json::json!({
            "version": "9.9.9",
            "api_version": API_VERSION + 1,
        });
        assert_eq!(
            classify_version_response(&response, "0.1.0"),
            VersionCompatibility::ApiMismatch {
                server_version: "9.9.9".to_string(),
                server_api_version: API_VERSION + 1,
            }
        );
    }

    #[test]
    fn explicit_malformed_api_version_is_invalid() {
        let response = serde_json::json!({
            "version": "0.1.0",
            "api_version": "1",
        });
        assert!(matches!(
            classify_version_response(&response, "0.1.0"),
            VersionCompatibility::InvalidResponse { .. }
        ));
    }
}
