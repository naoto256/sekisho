//! Identity provider configuration.
//!
//! One `IdentityProvider` row carries the config for whichever protocol its
//! `idp_type` names; the other protocol's field is `None`. A flat struct with
//! two optionals rather than an enum with payloads, because the row is stored
//! as JSON and merge-patched field by field — an enum would make "patch the
//! issuer URL" require re-sending the whole variant.
//!
//! ## Wire input and stored form are different types
//!
//! [`OidcConfigInput`] carries a creation secret in plaintext; [`OidcConfig`]
//! carries it sealed. [`OidcConfigPatch`] is separate again so nested fields
//! retain their three states: missing means unchanged, null can clear a
//! nullable value, and a concrete value replaces it.
//!
//! A missing, null, empty or redacted update secret means "keep the stored
//! one". That convention lets the management UI round-trip a record without
//! re-sending a secret it was never shown or wiping the stored value. A null
//! SAML mapping entry, by contrast, deletes that one key through RFC 7396.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::serde_util::deserialize_some;

/// A configured IdP. Exactly one of `oidc_config` / `saml_config` is
/// populated, selected by `idp_type`; the pairing is enforced by
/// [`crate::validation`] rather than by the type, for the merge-patch reason
/// in the module docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub id: Uuid,
    pub name: String,
    #[serde(rename = "type")]
    pub idp_type: IdpType,
    pub oidc_config: Option<OidcConfig>,
    pub saml_config: Option<SamlConfig>,
}

/// Which protocol an IdP speaks. Immutable after creation: the two protocols
/// have disjoint config, so a type change would be a delete and a create
/// wearing the same id.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IdpType {
    Oidc,
    Saml,
}

/// Internal storage representation. `client_secret_encrypted` holds the
/// base64-encoded AEAD blob produced by `crypto::encrypt_to_base64` and
/// is never the plaintext secret. The wire-input counterpart is
/// [`OidcConfigInput`] (plaintext `client_secret`); the API handler
/// encrypts on the way in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    /// Stored encrypted at rest.
    pub client_secret_encrypted: String,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    pub prompt: Option<String>,
}

/// Wire input for OIDC config on POST/PATCH /idps. Carries `client_secret`
/// as **plaintext**; the handler encrypts it with the daemon's master key
/// before persisting. On update, an absent or empty `client_secret` means
/// "leave the stored secret alone" — the same convention cert upload and
/// bootstrap follow.
#[derive(Clone, Deserialize, Serialize)]
pub struct OidcConfigInput {
    pub issuer_url: String,
    pub client_id: String,
    /// Plaintext OIDC client secret. Empty / absent on PATCH = no change.
    /// Required on POST (validated separately).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
}

impl std::fmt::Debug for OidcConfigInput {
    // `client_secret` is the IdP's plaintext OAuth client secret. Containers
    // that derive `Debug` and recurse here (CreateIdentityProvider,
    // UpdateIdentityProvider) pick up the redaction automatically.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfigInput")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("scopes", &self.scopes)
            .field("prompt", &self.prompt)
            .finish()
    }
}

/// PATCH-shaped OIDC config. The outer option records whether a field was
/// present; the inner option records an explicit JSON `null` so the handler
/// can reject null for required fields and clear nullable fields.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct OidcConfigPatch {
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub issuer_url: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_id: Option<Option<String>>,
    /// Plaintext secret. Missing/null/empty/redacted preserve the stored
    /// secret; only a non-empty real value requests rotation.
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_secret: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub scopes: Option<Option<Vec<String>>>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub prompt: Option<Option<String>>,
}

impl std::fmt::Debug for OidcConfigPatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfigPatch")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self
                    .client_secret
                    .as_ref()
                    .map(|value| value.as_ref().map(|_| "<redacted>")),
            )
            .field("scopes", &self.scopes)
            .field("prompt", &self.prompt)
            .finish()
    }
}

/// SAML SP config. `entity_id` and the ACS URL are NOT stored here —
/// they're derived at runtime from the daemon's `auth_domain` global
/// config (`https://{auth_domain}` and `https://{auth_domain}/.sekisho/saml/acs`
/// respectively). Letting users override them caused stale values to drift
/// from the listening endpoint and confused operators reading `show idp`,
/// so the fields were removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    pub metadata_url: String,
    pub slo_url: Option<String>,
    pub name_id_format: Option<String>,
    #[serde(default)]
    pub attribute_mapping: std::collections::HashMap<String, String>,
}

/// Patch-shaped variant of `SamlConfig`: `attribute_mapping` accepts
/// `null` per key so the management API can express "delete this
/// entry from the mapping" as part of an RFC 7396 merge patch. The
/// runtime / storage type stays `HashMap<String, String>` — by the
/// time the merged JSON is deserialized back into `SamlConfig`,
/// `json_merge` has dropped every key whose patch value was null,
/// so nulls are never seen on the read side.
///
/// Mirrors `route::HeaderModificationsPatch`; same RFC 7396 caveat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfigPatch {
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata_url: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub slo_url: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub name_id_format: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_some",
        skip_serializing_if = "Option::is_none"
    )]
    pub attribute_mapping: Option<Option<std::collections::HashMap<String, Option<String>>>>,
}

/// `openid` is mandatory for an OIDC flow; `email` and `profile` are what the
/// session and policy layers expect to find claims in. Defaulted rather than
/// required so a minimal IdP definition works out of the box.
fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "email".to_string(),
        "profile".to_string(),
    ]
}

/// Creation body. Takes [`SamlConfig`] directly, unlike the update body:
/// there is no stored map to merge against on create, so the patch-shaped
/// variant would only add a layer of `Option` with nothing to express.
#[derive(Debug, Deserialize)]
pub struct CreateIdentityProvider {
    pub name: String,
    #[serde(rename = "type")]
    pub idp_type: IdpType,
    pub oidc_config: Option<OidcConfigInput>,
    pub saml_config: Option<SamlConfig>,
}

/// Patch body. `idp_type` is absent by design — see [`IdpType`].
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateIdentityProvider {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_config: Option<OidcConfigPatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_config: Option<SamlConfigPatch>,
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_oidc_client_secret() {
        let input = OidcConfigInput {
            issuer_url: "https://issuer.example".into(),
            client_id: "client".into(),
            client_secret: Some("super_secret_value_42".into()),
            scopes: vec!["openid".into()],
            prompt: None,
        };
        let s = format!("{input:?}");
        assert!(!s.contains("super_secret_value"), "leak: {s}");
        assert!(s.contains("redacted"), "should mark: {s}");
        assert!(s.contains("client"), "non-secret preserved: {s}");
    }

    #[test]
    fn debug_redaction_propagates_through_update_wrapper() {
        let upd = UpdateIdentityProvider {
            name: None,
            oidc_config: Some(OidcConfigPatch {
                issuer_url: Some(Some("https://issuer.example".into())),
                client_id: Some(Some("client".into())),
                client_secret: Some(Some("super_secret_value_42".into())),
                scopes: Some(Some(vec![])),
                prompt: None,
            }),
            saml_config: None,
        };
        let s = format!("{upd:?}");
        assert!(!s.contains("super_secret_value"), "leak: {s}");
    }

    #[test]
    fn nested_patch_distinguishes_missing_null_and_value() {
        let update: UpdateIdentityProvider = serde_json::from_value(serde_json::json!({
            "oidc_config": {
                "issuer_url": null,
                "prompt": "login",
                "unknown": "ignored"
            },
            "unknown": true
        }))
        .unwrap();
        let oidc = update.oidc_config.unwrap();
        assert_eq!(oidc.issuer_url, Some(None));
        assert_eq!(oidc.client_id, None);
        assert_eq!(oidc.prompt, Some(Some("login".into())));
    }

    #[test]
    fn top_level_config_null_remains_compat_noop() {
        let update: UpdateIdentityProvider = serde_json::from_value(serde_json::json!({
            "oidc_config": null,
            "saml_config": null
        }))
        .unwrap();
        assert!(update.oidc_config.is_none());
        assert!(update.saml_config.is_none());
    }
}
