//! sekisho SAML — HTTP-level handlers + `IdentityProvider` config bridge.
//!
//! Protocol implementation lives in `auth_idp::saml`. Call sites import
//! from there directly.

pub mod callback;

use crate::models::idp::IdentityProvider;
use auth_idp::saml::SamlIdpConfig;

/// Fallible because an IdP's `type` and its config are independent fields: a
/// provider that is not SAML, or one with no `saml_config`, is a
/// configuration error for the request that reached it rather than a panic.
impl TryFrom<&IdentityProvider> for SamlIdpConfig {
    type Error = crate::error::Error;

    fn try_from(idp: &IdentityProvider) -> crate::error::Result<Self> {
        if idp.idp_type != crate::models::idp::IdpType::Saml {
            return Err(crate::error::Error::ConfigurationError(
                "expected SAML IdP".into(),
            ));
        }
        let cfg = idp
            .saml_config
            .as_ref()
            .ok_or_else(|| crate::error::Error::ConfigurationError("missing saml_config".into()))?;
        Ok(SamlIdpConfig {
            metadata_url: cfg.metadata_url.clone(),
            slo_url: cfg.slo_url.clone(),
            attribute_mapping: cfg.attribute_mapping.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_saml_bridge_rejects_wrong_type_and_missing_config() {
        let valid: IdentityProvider = serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::nil(), "name": "test", "type": "saml", "oidc_config": null,
            "saml_config": {"metadata_url": "https://idp.example/metadata",
                "slo_url": "https://idp.example/logout", "attribute_mapping": {"email": "mail"}}
        }))
        .unwrap();
        let converted = SamlIdpConfig::try_from(&valid).unwrap();
        assert_eq!(converted.metadata_url, "https://idp.example/metadata");
        assert_eq!(
            converted.slo_url.as_deref(),
            Some("https://idp.example/logout")
        );
        assert_eq!(
            converted.attribute_mapping.get("email").map(String::as_str),
            Some("mail")
        );
        let mut wrong_type = valid.clone();
        wrong_type.idp_type = crate::models::idp::IdpType::Oidc;
        let mut missing = valid.clone();
        missing.saml_config = None;
        let errors = [wrong_type, missing].map(|idp| {
            std::panic::catch_unwind(|| SamlIdpConfig::try_from(&idp)).is_ok_and(|result| {
                matches!(result, Err(crate::error::Error::ConfigurationError(_)))
            })
        });
        assert_eq!(
            errors,
            [true, true],
            "wrong type and missing config must return errors, not panic"
        );
    }
}
