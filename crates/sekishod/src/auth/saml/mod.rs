//! sekisho SAML — HTTP-level handlers + `IdentityProvider` config bridge.
//!
//! Protocol implementation lives in `auth_idp::saml`. Call sites import
//! from there directly.

pub mod callback;

use crate::models::idp::IdentityProvider;
use auth_idp::saml::SamlIdpConfig;

impl From<&IdentityProvider> for SamlIdpConfig {
    fn from(idp: &IdentityProvider) -> Self {
        let cfg = idp.saml_config.as_ref().expect("expected SAML IdP");
        SamlIdpConfig {
            metadata_url: cfg.metadata_url.clone(),
            slo_url: cfg.slo_url.clone(),
            attribute_mapping: cfg.attribute_mapping.clone(),
        }
    }
}
