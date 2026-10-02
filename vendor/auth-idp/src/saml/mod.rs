//! SAML Service Provider implementation.
//!
//! - `mod.rs` — SamlClient (protocol facade, metadata parsing, response processing)
//! - `signature.rs` — XML signature verification (SignatureValue extraction + ring)
//! - `c14n.rs` — Exclusive XML Canonicalization (W3C exc-c14n#)

pub mod c14n;
mod signature;
mod validate;

/// Verify the detached signature that the SAML HTTP-Redirect binding
/// carries on the URL query string. Re-exported so callers can validate
/// IdP-initiated LogoutRequests (same detached-signature format) without
/// going through [`SamlClient::process_logout_response`].
pub use signature::verify_redirect_binding_signature;

/// SAML 2.0 HTTP-Redirect binding URN. Used both to pick the right
/// `SingleLogoutService` endpoint out of IdP metadata and as the
/// binding advertised in our SP metadata.
pub const SAML_BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
/// SAML 2.0 HTTP-POST binding URN. Present for the POST-binding branch
/// of the SLO callback and for the SP-metadata advertisement; the
/// extractor in `extract_slo_url` takes this URN as the lookup key.
pub const SAML_BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// Which SAML binding delivered a [`SamlClient::process_logout_response`]
/// payload. The variant carries every input the corresponding signature
/// check needs, so the "verify against something the caller must
/// remember to also pass in" foot-gun does not exist.
///
/// - [`LogoutResponseBinding::Post`] — HTTP-POST binding. The response
///   is a base64-encoded XML document whose embedded `ds:Signature`
///   element is verified against the pinned IdP certificates.
/// - [`LogoutResponseBinding::Redirect`] — HTTP-Redirect binding. The
///   response is DEFLATE-then-base64 XML, and the signature lives on
///   the URL query string rather than in the payload. The caller must
///   supply the exact `raw_query` octets as delivered by the browser
///   so byte-equivalent verification is possible.
#[derive(Debug, Clone, Copy)]
pub enum LogoutResponseBinding<'a> {
    /// HTTP-POST binding. Embedded XML `ds:Signature` is verified.
    Post,
    /// HTTP-Redirect binding. The detached query-string signature is
    /// verified over the raw query bytes.
    Redirect {
        /// Exact raw query string as delivered by the browser (no
        /// re-encoding). Percent-encoded octets must match what the
        /// IdP signed.
        raw_query: &'a str,
    },
}

#[cfg(test)]
#[path = "c14n_test.rs"]
mod c14n_test;

#[cfg(test)]
#[path = "c14n_oracle_test.rs"]
mod c14n_oracle_test;

#[cfg(test)]
#[path = "c14n_fuzz_test.rs"]
mod c14n_fuzz_test;

#[cfg(test)]
#[path = "c14n_subtree_oracle_test.rs"]
mod c14n_subtree_oracle_test;

use crate::error::{Error, Result};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::rsa::{OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey};
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use uuid::Uuid;
use x509_parser::oid_registry::OID_PKCS1_RSAENCRYPTION;
use x509_parser::prelude::parse_x509_certificate;
use x509_parser::public_key::PublicKey;
use zeroize::Zeroizing;

const MAX_ENCRYPTED_ASSERTION_BYTES: usize = 1024 * 1024;
const MAX_ENCRYPTED_CIPHERTEXT_BYTES: usize = 512 * 1024;
const XMLENC_RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
const XMLENC_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const XMLENC_MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
const XMLENC_AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const NS_XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// IdP-side SAML config. Caller assembles this from whatever storage
/// it uses.
#[derive(Debug, Clone)]
pub struct SamlIdpConfig {
    pub metadata_url: String,
    pub slo_url: Option<String>,
    pub attribute_mapping: HashMap<String, String>,
}

/// SP-side SAML config. `request_id_prefix` is caller-chosen
/// (e.g. `"_myapp"`) — used as the leading token of
/// `<prefix>_<uuid>` AuthnRequest IDs and `<prefix>_lo_<uuid>`
/// LogoutRequest IDs.
///
/// `sp_slo_url` is the SP-side SLO endpoint that [`SamlClient::sp_metadata`]
/// advertises. `None` omits the `<md:SingleLogoutService>` element from
/// the metadata — i.e. the SP publishes no SLO endpoint for incoming
/// LogoutResponse routing. Outgoing SP-initiated LogoutRequests are
/// independent of this setting and remain possible whenever the IdP's
/// own SLO endpoint is known (see `slo_redirect_url`).
#[derive(Debug, Clone)]
pub struct SamlSpConfig {
    pub entity_id: String,
    pub acs_url: String,
    pub sp_slo_url: Option<String>,
    pub request_id_prefix: String,
}

const INVALID_SP_CREDENTIALS: &str = "invalid SAML SP credentials";
const MAX_SP_CREDENTIAL_BYTES: usize = 128 * 1024;

/// Validated SP signing and encrypted-assertion decryption material. The
/// certificate is public metadata; the PKCS#8 key remains in a zeroizing
/// buffer for its entire ownership span and is the private decryption custody.
pub struct SamlSpCredentials {
    certificate_der: Vec<u8>,
    private_key_der: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SamlSpCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SamlSpCredentials")
            .field("certificate_present", &(!self.certificate_der.is_empty()))
            .field("private_key_present", &(!self.private_key_der.is_empty()))
            .finish()
    }
}

impl SamlSpCredentials {
    /// Validate one X.509 certificate PEM and one unencrypted RSA PKCS#8 PEM.
    /// Both are mandatory and must describe the same RSA key (2048 bits or
    /// larger). Error text is fixed and contains no source material.
    pub fn try_new(certificate_pem: Vec<u8>, private_key_pem: Vec<u8>) -> Result<Self> {
        let certificate_pem = Zeroizing::new(certificate_pem);
        let private_key_pem = Zeroizing::new(private_key_pem);
        let certificate_der = decode_pem(&certificate_pem, "CERTIFICATE")?;
        let private_key_der = decode_pem(&private_key_pem, "PRIVATE KEY")?;
        let (remainder, certificate) = match parse_x509_certificate(&certificate_der) {
            Ok(value) => value,
            Err(_) => return Err(invalid_sp_credentials()),
        };
        if !remainder.is_empty()
            || certificate.tbs_certificate.subject_pki.algorithm.algorithm
                != OID_PKCS1_RSAENCRYPTION
            || certificate
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .unused_bits
                != 0
        {
            return Err(invalid_sp_credentials());
        }
        let certificate_key = certificate
            .tbs_certificate
            .subject_pki
            .parsed()
            .map_err(|_| invalid_sp_credentials())?;
        if !matches!(&certificate_key, PublicKey::RSA(_)) || certificate_key.key_size() < 2048 {
            return Err(invalid_sp_credentials());
        }
        let key_pair = match RsaKeyPair::from_pkcs8(&private_key_der) {
            Ok(value) => value,
            Err(_) => return Err(invalid_sp_credentials()),
        };
        if key_pair.public().modulus_len() < 256
            || certificate
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data
                != key_pair.public().as_ref()
        {
            return Err(invalid_sp_credentials());
        }
        Ok(Self {
            certificate_der: certificate_der.to_vec(),
            private_key_der,
        })
    }

    fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    fn sign_redirect_query(&self, input: &[u8]) -> Result<Vec<u8>> {
        let key_pair =
            RsaKeyPair::from_pkcs8(&self.private_key_der).map_err(|_| invalid_sp_credentials())?;
        let mut signature = vec![0; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input,
                &mut signature,
            )
            .map_err(|_| invalid_sp_credentials())?;
        Ok(signature)
    }
}

fn invalid_sp_credentials() -> Error {
    Error::ConfigurationError(INVALID_SP_CREDENTIALS.to_owned())
}

fn decode_pem(input: &[u8], label: &str) -> Result<Zeroizing<Vec<u8>>> {
    if input.len() > MAX_SP_CREDENTIAL_BYTES {
        return Err(invalid_sp_credentials());
    }
    let text = std::str::from_utf8(input)
        .map_err(|_| invalid_sp_credentials())?
        .trim();
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = text
        .strip_prefix(&begin)
        .and_then(|rest| rest.strip_suffix(&end))
        .ok_or_else(invalid_sp_credentials)?;
    if body.contains("ENCRYPTED") || body.contains("-----BEGIN") || body.contains("-----END") {
        return Err(invalid_sp_credentials());
    }
    let compact = Zeroizing::new(
        body.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    );
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .map_err(|_| invalid_sp_credentials())?,
    );
    if decoded.is_empty() || decoded.len() > MAX_SP_CREDENTIAL_BYTES {
        return Err(invalid_sp_credentials());
    }
    Ok(decoded)
}

/// A SAML Service Provider with XML signature verification.
pub struct SamlClient {
    entity_id: String,
    acs_url: String,
    /// SP-side SLO endpoint, copied from `SamlSpConfig::sp_slo_url`.
    /// `None` means no SP SLO endpoint is advertised in the metadata
    /// generated by `sp_metadata`. Outgoing SP-initiated LogoutRequests
    /// are still possible whenever `slo_redirect_url` (the IdP-side
    /// endpoint) is known.
    sp_slo_url: Option<String>,
    /// IdP entity ID extracted from the metadata `EntityDescriptor`.
    /// Used as the expected SAML Response / Assertion Issuer during
    /// semantic validation.
    idp_entity_id: String,
    sso_url: String,
    /// SLO endpoint advertised in IdP metadata for HTTP-Redirect binding.
    /// Preferred for outgoing LogoutRequest because (a) the spec allows
    /// SP-initiated SLO via Redirect without signing and (b) a 302 keeps
    /// the request out of intermediary proxies' request bodies.
    /// `None` → SLO is unsupported on the IdP side; sign_out falls back
    /// to local-only.
    slo_redirect_url: Option<String>,
    attribute_mapping: HashMap<String, String>,
    /// IdP's X.509 certificates (DER) for signature verification.
    /// Multiple are common (rolling-key IdPs); the verifier tries each.
    idp_certs_der: Vec<Vec<u8>>,
    request_id_prefix: String,
    sp_credentials: Option<SamlSpCredentials>,
}

impl SamlClient {
    pub async fn new(
        http: &reqwest::Client,
        idp: &SamlIdpConfig,
        sp: &SamlSpConfig,
    ) -> Result<Self> {
        let metadata_resp =
            http.get(&idp.metadata_url).send().await.map_err(|e| {
                Error::ExternalServiceError(format!("SAML metadata fetch failed: {e}"))
            })?;
        let metadata_bytes = crate::http::limited_response(metadata_resp, 1024 * 1024)
            .await
            .map_err(|e| Error::ExternalServiceError(format!("SAML metadata: {e}")))?;
        let metadata_xml = String::from_utf8(metadata_bytes.to_vec())
            .map_err(|e| Error::ExternalServiceError(format!("SAML metadata UTF-8: {e}")))?;

        let sso_url = extract_sso_url(&metadata_xml).ok_or_else(|| {
            Error::ExternalServiceError("SSO URL not found in IdP metadata".into())
        })?;

        let idp_entity_id = extract_idp_entity_id(&metadata_xml).ok_or_else(|| {
            Error::ExternalServiceError(
                "IdP entity ID (EntityDescriptor/@entityID) not found in metadata".into(),
            )
        })?;

        // SLO is optional — an IdP that omits `SingleLogoutService`
        // cannot participate in SP-initiated logout. Callers learn this
        // by reading `slo_redirect_url()` and degrade to local-only
        // sign-out. Live metadata advertisement takes priority over the
        // caller-supplied `SamlIdpConfig::slo_url` because metadata
        // reflects what the IdP currently supports; the config is the
        // caller's last-known value and may have drifted.
        let slo_redirect_url =
            extract_slo_url(&metadata_xml, SAML_BINDING_REDIRECT).or_else(|| idp.slo_url.clone());

        let idp_certs_der = extract_all_idp_certs(&metadata_xml);
        if idp_certs_der.is_empty() {
            return Err(Error::ExternalServiceError(
                "no X.509 certificate found in IdP SAML metadata; cannot verify signatures".into(),
            ));
        }
        tracing::info!(
            count = idp_certs_der.len(),
            "loaded IdP signing certificates from SAML metadata"
        );

        Ok(Self {
            entity_id: sp.entity_id.clone(),
            acs_url: sp.acs_url.clone(),
            sp_slo_url: sp.sp_slo_url.clone(),
            idp_entity_id,
            sso_url,
            slo_redirect_url,
            attribute_mapping: idp.attribute_mapping.clone(),
            idp_certs_der,
            request_id_prefix: sp.request_id_prefix.clone(),
            sp_credentials: None,
        })
    }

    /// Build a client with validated SP credentials while preserving the
    /// existing unsigned [`SamlClient::new`] constructor for older callers.
    pub async fn new_with_credentials(
        http: &reqwest::Client,
        idp: &SamlIdpConfig,
        sp: &SamlSpConfig,
        credentials: SamlSpCredentials,
    ) -> Result<Self> {
        let mut client = Self::new(http, idp, sp).await?;
        client.sp_credentials = Some(credentials);
        Ok(client)
    }

    /// IdP SLO endpoint for HTTP-Redirect binding, if advertised.
    /// Used by the sign-out path to decide between SP-initiated SLO
    /// and the local-only terminal page.
    pub fn slo_redirect_url(&self) -> Option<&str> {
        self.slo_redirect_url.as_deref()
    }

    /// Build a SAML `LogoutRequest` and the URL to redirect the browser
    /// to. Returns `(redirect_url, logout_request_id)`; the caller is
    /// expected to remember the ID alongside the pending logout so the
    /// incoming `LogoutResponse` can be correlated via `InResponseTo`.
    ///
    /// The request is unsigned. With the legacy [`SamlClient::new`] constructor
    /// this mirrors the unsigned AuthnRequest path. A client created with
    /// [`SamlClient::new_with_credentials`] signs AuthnRequests, but this API's
    /// LogoutRequest remains unsigned: SP LogoutRequest signing is a separate
    /// capability not enabled by `SamlSpCredentials`.
    pub fn logout_request_redirect_url(
        &self,
        name_id: &str,
        session_index: Option<&str>,
        relay_state: &str,
    ) -> Result<(String, String)> {
        let slo_url = self
            .slo_redirect_url
            .as_deref()
            .ok_or_else(|| Error::ConfigurationError("IdP has no SLO endpoint".into()))?;

        let id = format!("{}_lo_{}", self.request_id_prefix, Uuid::new_v4());
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // Per SAML Core §3.7.1 `<samlp:SessionIndex>` follows the
        // `<saml:NameID>` (and any `<saml:BaseID>`/`<saml:EncryptedID>`)
        // inside LogoutRequest. We only emit it when we captured one
        // at login — IdPs that don't include `AuthnStatement/@SessionIndex`
        // in their assertion leave the field empty and the IdP matches
        // on NameID alone.
        let session_index_element = match session_index {
            Some(idx) if !idx.is_empty() => {
                format!(
                    "<samlp:SessionIndex>{}</samlp:SessionIndex>",
                    xml_escape(idx)
                )
            }
            _ => String::new(),
        };

        // Minimal LogoutRequest. NameID is echoed as-is with no Format
        // attribute; this signature does not expose an optional NameID
        // Format input, and `session_index` is the only optional input.
        // IdP behavior with the resulting message is IdP-dependent.
        let logout_request = format!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{now}" Destination="{dest}"><saml:Issuer>{issuer}</saml:Issuer><saml:NameID>{name_id}</saml:NameID>{session_index_element}</samlp:LogoutRequest>"#,
            dest = xml_escape(slo_url),
            issuer = xml_escape(&self.entity_id),
            name_id = xml_escape(name_id),
        );

        let encoded = deflate_base64_encode(&logout_request)?;
        let sep = if slo_url.contains('?') { '&' } else { '?' };
        let url = format!(
            "{slo_url}{sep}SAMLRequest={}&RelayState={}",
            urlencoding::encode(&encoded),
            urlencoding::encode(relay_state),
        );
        Ok((url, id))
    }

    /// Process an incoming SAML `LogoutResponse` (base64-encoded, as
    /// delivered by either the HTTP-Redirect or HTTP-POST binding).
    ///
    /// Returns `Ok(())` on a Success-status response whose
    /// `InResponseTo` matches the expected LogoutRequest ID.
    ///
    /// Signature verification is unconditional and depends on the
    /// binding the caller declares via [`LogoutResponseBinding`]:
    ///
    /// - [`LogoutResponseBinding::Post`] — the embedded XML `ds:Signature`
    ///   is verified against the pinned IdP certificates.
    /// - [`LogoutResponseBinding::Redirect { raw_query }`] — the detached
    ///   query-string signature is verified over the exact `raw_query`
    ///   bytes the browser delivered. Any re-encoding of the query
    ///   parameters upstream of this call will break verification.
    ///
    /// Decoded XML is capped at 1 MiB before signature or semantic
    /// processing. This protocol limit does not replace the raw HTTP form or
    /// query request-size limit owned by the caller.
    ///
    /// Symmetric with `process_response` (login), covering both POST
    /// and Redirect bindings. See the type-level docs on
    /// [`LogoutResponseBinding`] for the shape of each variant.
    ///
    /// Everything else surfaces as `Err(Error::AuthenticationFailed(_))`
    /// with a specific error message. Handling and any audit or user
    /// consequences are owned by the caller.
    pub fn process_logout_response(
        &self,
        saml_response_b64_or_deflated: &str,
        expected_in_response_to: &str,
        binding: LogoutResponseBinding<'_>,
    ) -> Result<()> {
        // Redirect binding carries DEFLATE-then-base64; POST binding
        // carries plain base64 of the XML.
        let xml_bytes = match binding {
            LogoutResponseBinding::Redirect { .. } => {
                decode_deflate_base64(saml_response_b64_or_deflated)?
            }
            LogoutResponseBinding::Post => decode_base64_saml_xml(
                saml_response_b64_or_deflated,
                "SAML LogoutResponse base64 decode failed",
            )?,
        };
        let xml = String::from_utf8(xml_bytes).map_err(|e| {
            Error::AuthenticationFailed(format!("SAML LogoutResponse UTF-8 error: {e}"))
        })?;

        let root = match binding {
            LogoutResponseBinding::Post => {
                signature::verify_logout_response(&xml, &self.idp_certs_der)?.into_root()
            }
            LogoutResponseBinding::Redirect { raw_query } => {
                signature::verify_redirect_binding_signature(
                    raw_query,
                    "SAMLResponse",
                    saml_response_b64_or_deflated,
                    &self.idp_certs_der,
                )?;
                c14n::parse_xml_tree(&xml)?
            }
        };
        let namespaces = NamespaceIndex::new(&root);
        if root.local_name != "LogoutResponse" || !namespaces.matches(&root, NS_PROTOCOL) {
            return Err(Error::AuthenticationFailed(format!(
                "SAML response root is {}, expected LogoutResponse",
                root.local_name
            )));
        }

        // Issuer, if present, must match the IdP we trust. Missing
        // Issuer is tolerated because the signature layer already binds
        // the response to a trusted key, but a mismatched Issuer is a
        // hard signal that the response is meant for someone else.
        let issuer_element = root.children.iter().find_map(|c| match c {
            c14n::XmlNode::Element(e)
                if e.local_name == "Issuer" && namespaces.matches(e, NS_ASSERTION) =>
            {
                Some(e)
            }
            _ => None,
        });
        let issuer = issuer_element.map(text_of).unwrap_or_default();
        if !issuer.is_empty() && issuer != self.idp_entity_id {
            return Err(Error::AuthenticationFailed(format!(
                "SAML LogoutResponse Issuer {issuer:?} does not match expected IdP {:?}",
                self.idp_entity_id
            )));
        }

        // Destination, if present, must match the SP-side SLO endpoint
        // we published. Skip when the SP does not advertise SLO (a
        // signed LogoutResponse with Destination is spec-compliant but
        // uncommon in that setup).
        let destination = root
            .attributes
            .iter()
            .find(|(_, local, _)| local == "Destination")
            .map(|(_, _, v)| v.as_str());
        if let (Some(dest), Some(expected)) = (destination, self.sp_slo_url.as_deref())
            && dest != expected
        {
            return Err(Error::AuthenticationFailed(format!(
                "SAML LogoutResponse Destination {dest:?} does not match SP SLO endpoint {expected:?}"
            )));
        }

        // InResponseTo must match the LogoutRequest ID we issued.
        let in_response_to = root
            .attributes
            .iter()
            .find(|(_, local, _)| local == "InResponseTo")
            .map(|(_, _, v)| v.as_str());
        match in_response_to {
            Some(got) if got == expected_in_response_to => {}
            Some(got) => {
                return Err(Error::AuthenticationFailed(format!(
                    "SAML LogoutResponse InResponseTo {got:?} does not match expected"
                )));
            }
            None => {
                return Err(Error::AuthenticationFailed(
                    "SAML LogoutResponse missing InResponseTo".into(),
                ));
            }
        }

        // Status must be Success. PartialLogout is allowed by spec but
        // this crate surfaces it as an `Err(AuthenticationFailed)`; how
        // the caller records it is out of scope.
        let status_code = find_status_code(&root, &namespaces);
        match status_code.as_deref() {
            Some("urn:oasis:names:tc:SAML:2.0:status:Success") => Ok(()),
            Some(other) => Err(Error::AuthenticationFailed(format!(
                "SAML LogoutResponse Status {other}"
            ))),
            None => Err(Error::AuthenticationFailed(
                "SAML LogoutResponse missing Status/StatusCode".into(),
            )),
        }
    }

    /// Generate the SAML AuthnRequest redirect URL and the AuthnRequest ID.
    ///
    /// The ID is returned so the caller can hold it in pending-request
    /// state alongside the browser session and later require the SAML
    /// Response's `InResponseTo` attribute to match. Without that check
    /// an attacker who obtains a valid signed assertion for any user
    /// could replay it against the ACS and trigger login.
    #[allow(dead_code)]
    pub fn authn_request_url(&self, relay_state: &str) -> Result<(String, String)> {
        let id = format!("{}_{}", self.request_id_prefix, Uuid::new_v4());
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // Escape SP-controlled and metadata-derived values before
        // embedding them in the XML template. Metadata values reach us
        // XML-decoded (see `metadata_attr_value`), so an IdP-declared
        // Destination containing `&` would otherwise produce malformed
        // XML the IdP refuses. The other three fields carry
        // caller-configured strings and get the same treatment for
        // symmetry.
        let authn_request = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{now}" Destination="{sso}" AssertionConsumerServiceURL="{acs}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>{entity_id}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>"#,
            id = xml_escape(&id),
            sso = xml_escape(&self.sso_url),
            acs = xml_escape(&self.acs_url),
            entity_id = xml_escape(&self.entity_id),
        );

        let encoded = deflate_base64_encode(&authn_request)?;

        // SSO endpoints frequently already carry a query (e.g.
        // `?tenant=acme`); appending `?SAMLRequest=...` would corrupt
        // the URL. Mirror the SLO path's separator decision.
        let sep = if self.sso_url.contains('?') { '&' } else { '?' };
        let encoded_request = urlencoding::encode(&encoded);
        let encoded_relay = urlencoding::encode(relay_state);
        let url = if let Some(credentials) = &self.sp_credentials {
            let sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            let signing_input = format!(
                "SAMLRequest={encoded_request}&RelayState={encoded_relay}&SigAlg={}",
                urlencoding::encode(sig_alg),
            );
            let signature = credentials.sign_redirect_query(signing_input.as_bytes())?;
            format!(
                "{}{sep}{signing_input}&Signature={}",
                self.sso_url,
                urlencoding::encode(&base64::engine::general_purpose::STANDARD.encode(signature)),
            )
        } else {
            format!(
                "{}{sep}SAMLRequest={encoded_request}&RelayState={encoded_relay}",
                self.sso_url,
            )
        };
        Ok((url, id))
    }

    /// Process a SAML Response (POST binding, base64-encoded).
    ///
    /// `expected_in_response_to` is the AuthnRequest ID we generated for the
    /// SP-initiated flow. When provided, the Response's `InResponseTo` MUST
    /// match; when `None` (IdP-initiated flow, not currently exposed), the
    /// check is skipped. See `SamlClient::authn_request_url` for how the ID
    /// is produced.
    ///
    /// Decoded XML is capped at 1 MiB before signature or semantic
    /// processing. This protocol limit does not replace the raw HTTP form
    /// request-size limit owned by the caller.
    pub fn process_response(
        &self,
        saml_response_b64: &str,
        expected_in_response_to: Option<&str>,
    ) -> Result<SamlUserInfo> {
        let response_bytes =
            decode_base64_saml_xml(saml_response_b64, "SAML response base64 decode failed")?;

        let response_xml = String::from_utf8(response_bytes)
            .map_err(|e| Error::AuthenticationFailed(format!("SAML response UTF-8 error: {e}")))?;
        let parsed_response = c14n::parse_xml_tree(&response_xml)?;
        if response_has_encrypted_assertion(&parsed_response) {
            let result = (|| {
                let credentials = self.sp_credentials.as_ref().ok_or_else(|| {
                    Error::AuthenticationFailed("encrypted SAML assertion is not configured".into())
                })?;
                let decrypted = decrypt_encrypted_assertion_tree(
                    parsed_response,
                    &credentials.private_key_der,
                )?;
                self.process_validated_response(&decrypted, expected_in_response_to)
            })();
            return result.map_err(|_| {
                Error::AuthenticationFailed("encrypted SAML assertion is invalid".into())
            });
        }
        self.process_validated_response(&response_xml, expected_in_response_to)
    }

    fn process_validated_response(
        &self,
        response_xml: &str,
        expected_in_response_to: Option<&str>,
    ) -> Result<SamlUserInfo> {
        // XML signature proves the bytes were authored by the IdP and binds
        // validation to the exact direct-child Assertion covered by it.
        let verified = signature::verify_login_response(response_xml, &self.idp_certs_der)?;

        // 2. Semantic validation — proves the assertion targets *us*, is
        //    currently valid, and is a reply to an AuthnRequest we issued.
        //    Must run after signature; running before would let a forged
        //    unsigned Response surface confusing error messages.
        let ctx = validate::AssertionValidationContext {
            expected_issuer: &self.idp_entity_id,
            expected_audience: &self.entity_id,
            expected_destination: &self.acs_url,
            expected_recipient: &self.acs_url,
            expected_in_response_to,
            now: chrono::Utc::now(),
        };
        let validated = validate::validate_response(&verified, &ctx)?;

        let mut claims = HashMap::new();
        let mut explicit_email = None;
        let mut groups = Vec::new();

        for (key, values) in &validated.attributes {
            if self.attribute_mapping.get("email").map(|s| s.as_str()) == Some(key.as_str())
                && let Some(v) = values.first()
            {
                explicit_email = Some(v.clone());
            }
            if self.attribute_mapping.get("groups").map(|s| s.as_str()) == Some(key.as_str()) {
                groups = values.clone();
            }
            if let Some(v) = values.first() {
                claims.insert(key.clone(), serde_json::Value::String(v.clone()));
            }
        }

        let email = explicit_email
            .clone()
            .unwrap_or_else(|| validated.name_id.clone());
        claims.insert(
            "email".to_string(),
            serde_json::Value::String(email.clone()),
        );

        Ok(SamlUserInfo {
            explicit_email,
            email,
            groups,
            claims,
            name_id: validated.name_id,
            session_index: validated.session_index,
        })
    }

    /// Generate SP metadata XML. Declares the ACS endpoint for login;
    /// the legacy unsigned constructor advertises no signing or encryption
    /// key descriptors, while a credentialed client advertises signed
    /// AuthnRequests plus RSA-OAEP-SHA256/MGF1-SHA256 and AES-256-GCM
    /// encryption methods;
    /// if `sp_slo_url` is set, also declares the SLO endpoint under
    /// both Redirect and POST bindings. Omitting `sp_slo_url`
    /// publishes metadata that advertises no SP SLO endpoint at all.
    pub fn sp_metadata(&self) -> String {
        let slo_block = match self.sp_slo_url.as_deref() {
            Some(slo) => format!(
                r#"    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{slo}"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{slo}"/>
"#,
                slo = xml_escape(slo),
            ),
            None => String::new(),
        };
        let key_descriptors = self
            .sp_credentials
            .as_ref()
            .map(|credentials| {
                let certificate = base64::engine::general_purpose::STANDARD
                    .encode(credentials.certificate_der());
                format!(
                    "    <md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>\n    <md:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo><md:EncryptionMethod Algorithm=\"{XMLENC_RSA_OAEP}\"/><md:EncryptionMethod Algorithm=\"{XMLENC_AES256_GCM}\"/></md:KeyDescriptor>\n"
                )
            })
            .unwrap_or_default();
        let authn_requests_signed = if self.sp_credentials.is_some() {
            "true"
        } else {
            "false"
        };
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <md:SPSSODescriptor AuthnRequestsSigned="{authn_requests_signed}" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
{key_descriptors}{slo_block}    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#,
            entity_id = xml_escape(&self.entity_id),
            acs = xml_escape(&self.acs_url),
        )
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub struct SamlUserInfo {
    /// Email exactly as supplied by the configured SAML attribute. `None`
    /// means `email` below fell back to NameID for login compatibility.
    pub explicit_email: Option<String>,
    pub email: String,
    pub groups: Vec<String>,
    pub claims: HashMap<String, serde_json::Value>,
    /// The raw `<saml:NameID>` from the Assertion Subject. Persisted on
    /// the Session so SP-initiated Single Logout can echo it back in a
    /// `LogoutRequest`. Kept verbatim (no normalization) because the IdP
    /// matches on exact value.
    pub name_id: String,
    /// `AuthnStatement/@SessionIndex` from the assertion, if present.
    /// Persisted on the Session so the outgoing `LogoutRequest` can
    /// include `<samlp:SessionIndex>` — Entra requires it to correlate
    /// the logout to the authenticated session.
    pub session_index: Option<String>,
}

#[allow(dead_code)]
fn deflate_base64_encode(data: &str) -> Result<String> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data.as_bytes())
        .map_err(|e| Error::Internal(format!("deflate write failed: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| Error::Internal(format!("deflate finish failed: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&compressed))
}

/// Extract X.509 signing certificates from SAML IdP metadata (DER bytes).
///
/// Restricted to `<KeyDescriptor>` elements sitting inside the
/// **IDPSSODescriptor** of the FIRST `<EntityDescriptor>` in the
/// document, whose `use` attribute is either `"signing"` or absent
/// (SAML metadata §2.4.1.1 treats an unset `use` as "either role").
/// Anything else — `use="encryption"`, keys belonging to the SP-side
/// descriptor, and keys belonging to a different EntityDescriptor in
/// an `<EntitiesDescriptor>` bundle — is deliberately ignored.
/// Trusting those would let a non-signing key or a key belonging to a
/// different entity authenticate AuthnResponses / LogoutResponses.
///
/// This scoping matches [`extract_idp_entity_id`]: both settle on the
/// first `<EntityDescriptor>`, so the entity ID we present to the
/// Issuer validator and the certificate set the signature verifier
/// trusts are guaranteed to describe the same entity.
fn extract_all_idp_certs(metadata_xml: &str) -> Vec<Vec<u8>> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(metadata_xml);
    let mut in_cert = false;
    let mut cert_b64 = String::new();
    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();

    // Tracks how deep we are inside the FIRST `<EntityDescriptor>` and,
    // deeper, inside its `<IDPSSODescriptor>` and a signing-use
    // `<KeyDescriptor>`. SAML metadata does not allow
    // `<EntityDescriptor>` nested inside another, so a plain boolean is
    // sufficient to gate on "still inside the selected entity".
    let mut selected_entity_seen = false;
    let mut in_selected_entity = false;
    let mut in_idp_sso: i32 = 0;
    let mut in_signing_key: i32 = 0;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let local = name.split(':').next_back().unwrap_or(&name);
                match local {
                    "EntityDescriptor" if !selected_entity_seen => {
                        selected_entity_seen = true;
                        in_selected_entity = true;
                    }
                    "IDPSSODescriptor" if in_selected_entity => in_idp_sso += 1,
                    "KeyDescriptor" if in_selected_entity && in_idp_sso > 0 => {
                        let use_attr = e
                            .attributes()
                            .flatten()
                            .find(|a| a.key.as_ref() == b"use")
                            .and_then(|a| String::from_utf8(a.value.to_vec()).ok());
                        if use_attr.as_deref().is_none_or(|u| u == "signing") {
                            in_signing_key += 1;
                        }
                    }
                    "X509Certificate" if in_signing_key > 0 => {
                        in_cert = true;
                        cert_b64.clear();
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) if in_cert => {
                if let Ok(decoded) = e.decode()
                    && let Ok(text) = quick_xml::escape::unescape(&decoded)
                {
                    cert_b64.push_str(&text);
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let local = name.split(':').next_back().unwrap_or(&name);
                match local {
                    "X509Certificate" if in_cert => {
                        let clean: String =
                            cert_b64.chars().filter(|c| !c.is_whitespace()).collect();
                        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&clean)
                            && seen.insert(der.clone())
                        {
                            certs.push(der);
                        }
                        in_cert = false;
                    }
                    "KeyDescriptor" if in_signing_key > 0 => {
                        in_signing_key -= 1;
                    }
                    "IDPSSODescriptor" if in_idp_sso > 0 => {
                        in_idp_sso -= 1;
                    }
                    "EntityDescriptor" if in_selected_entity => {
                        // Closing the first EntityDescriptor. Later
                        // `<EntityDescriptor>` siblings in an
                        // `<EntitiesDescriptor>` bundle belong to
                        // different entities and MUST NOT contribute
                        // signing certs to the set we return.
                        in_selected_entity = false;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    certs
}

/// Common cap on decoded SAML XML accepted from POST and Redirect bindings.
/// Binding decoders enforce it before signature or semantic processing. Raw
/// HTTP form and query limits remain the caller's responsibility upstream.
const MAX_SAML_XML_BYTES: usize = 1024 * 1024;
const SAML_XML_LIMIT_ERROR: &str = "SAML XML exceeds 1048576-byte decoded limit";

/// Decode base64 SAML XML into a fixed-capacity buffer. `decode_slice` never
/// allocates from the attacker-controlled decoded size; `MAX + 1` preserves
/// an exact boundary distinction before the bytes reach XML processing.
fn decode_base64_saml_xml(s: &str, decode_error_prefix: &str) -> Result<Vec<u8>> {
    let mut out = vec![0; MAX_SAML_XML_BYTES + 1];
    let decoded_len = match base64::engine::general_purpose::STANDARD.decode_slice(s, &mut out) {
        Ok(len) => len,
        Err(base64::DecodeSliceError::OutputSliceTooSmall) => {
            return Err(Error::AuthenticationFailed(SAML_XML_LIMIT_ERROR.into()));
        }
        Err(base64::DecodeSliceError::DecodeError(error)) => {
            return Err(Error::AuthenticationFailed(format!(
                "{decode_error_prefix}: {error}"
            )));
        }
    };
    if decoded_len > MAX_SAML_XML_BYTES {
        return Err(Error::AuthenticationFailed(SAML_XML_LIMIT_ERROR.into()));
    }
    out.truncate(decoded_len);
    Ok(out)
}

fn response_has_encrypted_assertion(root: &c14n::XmlElement) -> bool {
    contains_element(root, "EncryptedAssertion")
}

fn decrypt_encrypted_assertion_tree(
    root: c14n::XmlElement,
    private_key_der: &[u8],
) -> Result<Zeroizing<String>> {
    if element_namespace(&root, &HashMap::new()).as_deref() != Some(NS_PROTOCOL)
        || root.local_name != "Response"
    {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML response shape is invalid".into(),
        ));
    }
    let root_ns = namespace_context(&root, &HashMap::new());
    let mut encrypted = None;
    let mut plaintext_count = 0usize;
    for child in &root.children {
        let c14n::XmlNode::Element(child) = child else {
            continue;
        };
        match (
            element_namespace(child, &root_ns).as_deref(),
            child.local_name.as_str(),
        ) {
            (Some(NS_ASSERTION), "EncryptedAssertion") if encrypted.is_none() => {
                encrypted = Some(child.clone())
            }
            (Some(NS_ASSERTION), "EncryptedAssertion") => {
                return Err(Error::AuthenticationFailed(
                    "encrypted SAML response shape is invalid".into(),
                ));
            }
            (Some(NS_ASSERTION), "Assertion") => plaintext_count += 1,
            _ => {}
        }
    }
    if root.children.iter().any(|child| {
        let c14n::XmlNode::Element(child) = child else {
            return false;
        };
        root_has_nested_assertion(child, &root_ns)
    }) {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML response shape is invalid".into(),
        ));
    }
    if encrypted.is_none() || plaintext_count != 0 {
        return Err(Error::AuthenticationFailed(
            "SAML response must contain exactly one encrypted Assertion".into(),
        ));
    }
    let encrypted = encrypted.expect("checked above");
    let assertion = decrypt_assertion_element(&encrypted, private_key_der, &root_ns)?;
    if assertion.local_name != "Assertion"
        || element_namespace(&assertion, &HashMap::new()).as_deref() != Some(NS_ASSERTION)
    {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML response assertion namespace is invalid".into(),
        ));
    }
    let mut replacement = Some(assertion);
    let mut replaced = root;
    for child in &mut replaced.children {
        if let c14n::XmlNode::Element(child) = child
            && child.local_name == "EncryptedAssertion"
            && element_namespace(child, &root_ns).as_deref() == Some(NS_ASSERTION)
        {
            *child = replacement.take().expect("single encrypted assertion");
        }
    }
    let canonical = c14n::exclusive_c14n(&replaced, &HashMap::new());
    let text = String::from_utf8(canonical)
        .map_err(|_| Error::AuthenticationFailed("decrypted SAML assertion is not UTF-8".into()))?;
    Ok(Zeroizing::new(text))
}

fn namespace_context(
    elem: &c14n::XmlElement,
    inherited: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut context = inherited.clone();
    for (prefix, uri) in &elem.ns_decls {
        context.insert(prefix.clone(), uri.clone());
    }
    context
}

fn element_namespace(
    elem: &c14n::XmlElement,
    inherited: &HashMap<String, String>,
) -> Option<String> {
    let context = namespace_context(elem, inherited);
    context.get(&elem.prefix).cloned()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NamespaceAuthority {
    Protocol,
    Assertion,
    XmlDsig,
    ExclusiveC14n,
    Other,
}

impl NamespaceAuthority {
    fn from_uri(uri: &str) -> Self {
        match uri {
            NS_PROTOCOL => Self::Protocol,
            NS_ASSERTION => Self::Assertion,
            NS_DS => Self::XmlDsig,
            "http://www.w3.org/2001/10/xml-exc-c14n#" => Self::ExclusiveC14n,
            _ => Self::Other,
        }
    }

    #[cfg(test)]
    fn retained_uri_bytes(self) -> usize {
        match self {
            Self::Protocol => 0,
            Self::Assertion => 0,
            Self::XmlDsig => 0,
            Self::ExclusiveC14n => 0,
            Self::Other => 0,
        }
    }
}

pub(super) struct NamespaceIndex {
    namespaces: HashMap<usize, NamespaceAuthority>,
}

impl NamespaceIndex {
    pub(super) fn new(root: &c14n::XmlElement) -> Self {
        let mut namespaces = HashMap::new();
        let mut context = HashMap::new();
        Self::walk(root, &mut context, &mut namespaces);
        Self { namespaces }
    }

    pub(super) fn matches(&self, elem: &c14n::XmlElement, expected: &str) -> bool {
        let expected = NamespaceAuthority::from_uri(expected);
        expected != NamespaceAuthority::Other
            && self
                .namespaces
                .get(&(elem as *const c14n::XmlElement as usize))
                == Some(&expected)
    }

    fn walk<'a>(
        elem: &'a c14n::XmlElement,
        context: &mut HashMap<&'a str, &'a str>,
        namespaces: &mut HashMap<usize, NamespaceAuthority>,
    ) {
        #[cfg(test)]
        NAMESPACE_TRAVERSAL_VISITS.with(|visits| {
            if let Some(current) = visits.get() {
                visits.set(Some(current + 1));
            }
        });
        let mut replaced = Vec::with_capacity(elem.ns_decls.len());
        for (prefix, uri) in &elem.ns_decls {
            replaced.push((
                prefix.as_str(),
                context.insert(prefix.as_str(), uri.as_str()),
            ));
        }
        if let Some(namespace) = context.get(elem.prefix.as_str()) {
            namespaces.insert(
                elem as *const c14n::XmlElement as usize,
                NamespaceAuthority::from_uri(namespace),
            );
        }
        for child in &elem.children {
            if let c14n::XmlNode::Element(child) = child {
                Self::walk(child, context, namespaces);
            }
        }
        for (prefix, previous) in replaced.into_iter().rev() {
            if let Some(previous) = previous {
                context.insert(prefix, previous);
            } else {
                context.remove(&prefix);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn retained_namespace_storage(&self) -> (usize, usize) {
        let owned_uri_bytes = self
            .namespaces
            .values()
            .copied()
            .map(NamespaceAuthority::retained_uri_bytes)
            .sum();
        (self.namespaces.len(), owned_uri_bytes)
    }
}

#[cfg(test)]
std::thread_local! {
    static NAMESPACE_TRAVERSAL_VISITS: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
struct NamespaceTraversalMeasurement {
    previous: Option<usize>,
}

#[cfg(test)]
impl NamespaceTraversalMeasurement {
    fn new() -> Self {
        let previous = NAMESPACE_TRAVERSAL_VISITS.with(|visits| visits.replace(Some(0)));
        Self { previous }
    }

    fn visits(&self) -> usize {
        NAMESPACE_TRAVERSAL_VISITS.with(|visits| {
            visits
                .get()
                .expect("namespace traversal measurement is active")
        })
    }
}

#[cfg(test)]
impl Drop for NamespaceTraversalMeasurement {
    fn drop(&mut self) {
        NAMESPACE_TRAVERSAL_VISITS.with(|visits| visits.set(self.previous));
    }
}

#[cfg(test)]
pub(super) fn measure_namespace_traversals<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let measurement = NamespaceTraversalMeasurement::new();
    let result = f();
    let visits = measurement.visits();
    (result, visits)
}

fn root_has_nested_assertion(elem: &c14n::XmlElement, inherited: &HashMap<String, String>) -> bool {
    let context = namespace_context(elem, inherited);
    elem.children.iter().any(|child| {
        let c14n::XmlNode::Element(child) = child else {
            return false;
        };
        let child_context = namespace_context(child, &context);
        let ns = child_context.get(&child.prefix).map(String::as_str);
        if ns == Some(NS_ASSERTION)
            && (child.local_name == "Assertion" || child.local_name == "EncryptedAssertion")
        {
            return true;
        }
        root_has_nested_assertion(child, &context)
    })
}

fn decrypt_assertion_element(
    encrypted_assertion: &c14n::XmlElement,
    private_key_der: &[u8],
    inherited: &HashMap<String, String>,
) -> Result<c14n::XmlElement> {
    let encrypted_assertion_context = namespace_context(encrypted_assertion, inherited);
    require_exact_children(
        encrypted_assertion,
        &[("EncryptedData", NS_XENC)],
        &encrypted_assertion_context,
    )?;
    let encrypted_data = direct_element_ns(
        encrypted_assertion,
        "EncryptedData",
        NS_XENC,
        &encrypted_assertion_context,
    )
    .ok_or_else(|| {
        Error::AuthenticationFailed("encrypted SAML assertion is missing EncryptedData".into())
    })?;
    let data_context = namespace_context(encrypted_data, &encrypted_assertion_context);
    require_exact_children(
        encrypted_data,
        &[
            ("EncryptionMethod", NS_XENC),
            ("KeyInfo", NS_DS),
            ("CipherData", NS_XENC),
        ],
        &data_context,
    )?;
    let data_method = direct_element_ns(encrypted_data, "EncryptionMethod", NS_XENC, &data_context)
        .and_then(|method| exact_unqualified_attr(method, "Algorithm"))
        .ok_or_else(|| Error::AuthenticationFailed("encrypted SAML algorithm is missing".into()))?;
    if data_method != XMLENC_AES256_GCM {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML assertion uses an unsupported content algorithm".into(),
        ));
    }
    let key_info = direct_element_ns(encrypted_data, "KeyInfo", NS_DS, &data_context)
        .ok_or_else(|| Error::AuthenticationFailed("encrypted SAML key is missing".into()))?;
    let key_info_context = namespace_context(key_info, &data_context);
    let encrypted_key = direct_element_ns(key_info, "EncryptedKey", NS_XENC, &key_info_context)
        .ok_or_else(|| Error::AuthenticationFailed("encrypted SAML key is missing".into()))?;
    require_exact_children(key_info, &[("EncryptedKey", NS_XENC)], &data_context)?;
    let key_context = namespace_context(encrypted_key, &key_info_context);
    require_exact_children(
        encrypted_key,
        &[("EncryptionMethod", NS_XENC), ("CipherData", NS_XENC)],
        &key_context,
    )?;
    let key_method = direct_element_ns(encrypted_key, "EncryptionMethod", NS_XENC, &key_context)
        .ok_or_else(|| {
            Error::AuthenticationFailed("encrypted SAML key algorithm is missing".into())
        })?;
    require_text_leaf(
        direct_element_ns(encrypted_data, "EncryptionMethod", NS_XENC, &data_context)
            .expect("data method exists"),
    )?;
    let method_context = namespace_context(key_method, &key_context);
    require_key_method_children(key_method, &method_context)?;
    let key_algorithm = exact_unqualified_attr(key_method, "Algorithm").unwrap_or_default();
    if key_algorithm != XMLENC_RSA_OAEP {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML key uses an unsupported algorithm".into(),
        ));
    }
    if direct_element_ns(key_method, "DigestMethod", NS_DS, &method_context)
        .and_then(|digest| exact_unqualified_attr(digest, "Algorithm"))
        != Some(XMLENC_SHA256)
    {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML key must use SHA-256".into(),
        ));
    }
    require_text_leaf(
        direct_element_ns(key_method, "DigestMethod", NS_DS, &method_context)
            .expect("digest exists"),
    )?;
    require_text_leaf(
        direct_element_ns(key_method, "MGF", NS_XENC11, &method_context).expect("mgf exists"),
    )?;
    if direct_element_ns(key_method, "MGF", NS_XENC11, &method_context)
        .and_then(|mgf| exact_unqualified_attr(mgf, "Algorithm"))
        != Some(XMLENC_MGF1_SHA256)
    {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML key must use SHA-256 MGF1".into(),
        ));
    }
    let key_cipher_data = direct_element_ns(encrypted_key, "CipherData", NS_XENC, &key_context)
        .expect("checked above");
    let data_cipher_data = direct_element_ns(encrypted_data, "CipherData", NS_XENC, &data_context)
        .expect("checked above");
    require_exact_children(key_cipher_data, &[("CipherValue", NS_XENC)], &key_context)?;
    require_exact_children(data_cipher_data, &[("CipherValue", NS_XENC)], &data_context)?;
    let key_cipher = cipher_value(encrypted_key, &key_context)?;
    let data_cipher = cipher_value(encrypted_data, &data_context)?;
    let private = PrivateDecryptingKey::from_pkcs8(private_key_der)
        .map_err(|_| Error::AuthenticationFailed("encrypted SAML key cannot be opened".into()))?;
    let oaep = OaepPrivateDecryptingKey::new(private)
        .map_err(|_| Error::AuthenticationFailed("encrypted SAML key cannot be opened".into()))?;
    if key_cipher.len() != oaep.key_size_bytes() {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML key has an invalid size".into(),
        ));
    }
    let mut wrapped_key = Zeroizing::new(vec![0u8; oaep.min_output_size()]);
    let wrapped_plaintext = oaep
        .decrypt(&OAEP_SHA256_MGF1SHA256, &key_cipher, &mut wrapped_key, None)
        .map_err(|_| Error::AuthenticationFailed("encrypted SAML key cannot be opened".into()))?;
    if wrapped_plaintext.len() != 32 {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML content key has an invalid size".into(),
        ));
    }
    let mut content = Zeroizing::new(data_cipher);
    if content.len() < 12 + 16 {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML content is too short".into(),
        ));
    }
    let nonce = Nonce::try_assume_unique_for_key(&content[..12])
        .map_err(|_| Error::AuthenticationFailed("encrypted SAML nonce is invalid".into()))?;
    let key = UnboundKey::new(&AES_256_GCM, wrapped_plaintext)
        .map_err(|_| Error::AuthenticationFailed("encrypted SAML content key is invalid".into()))?;
    let plaintext = LessSafeKey::new(key)
        .open_in_place(nonce, Aad::empty(), &mut content[12..])
        .map_err(|_| {
            Error::AuthenticationFailed("encrypted SAML content cannot be opened".into())
        })?;
    if plaintext.len() > MAX_ENCRYPTED_ASSERTION_BYTES {
        return Err(Error::AuthenticationFailed(
            "decrypted SAML assertion exceeds the size limit".into(),
        ));
    }
    let plaintext = std::str::from_utf8(plaintext)
        .map_err(|_| Error::AuthenticationFailed("decrypted SAML assertion is not UTF-8".into()))?;
    let assertion = c14n::parse_xml_tree(plaintext)?;
    if assertion.local_name != "Assertion" || contains_element(&assertion, "EncryptedAssertion") {
        return Err(Error::AuthenticationFailed(
            "decrypted SAML content is not a plaintext Assertion".into(),
        ));
    }
    Ok(assertion)
}

fn contains_element(elem: &c14n::XmlElement, local_name: &str) -> bool {
    elem.children.iter().any(|child| match child {
        c14n::XmlNode::Element(element) => {
            element.local_name == local_name || contains_element(element, local_name)
        }
        _ => false,
    })
}

fn direct_element_ns<'a>(
    elem: &'a c14n::XmlElement,
    local_name: &str,
    namespace: &str,
    inherited: &HashMap<String, String>,
) -> Option<&'a c14n::XmlElement> {
    let context = namespace_context(elem, inherited);
    elem.children.iter().find_map(|child| match child {
        c14n::XmlNode::Element(element) if element.local_name == local_name => {
            let child_context = namespace_context(element, &context);
            let resolved = child_context.get(&element.prefix).map(String::as_str);
            if resolved == Some(namespace) {
                Some(element)
            } else {
                None
            }
        }
        c14n::XmlNode::Element(_) => None,
        _ => None,
    })
}

fn namespace_matches(namespace: Option<&str>, expected: &str) -> bool {
    namespace == Some(expected)
}

fn require_exact_children(
    elem: &c14n::XmlElement,
    expected: &[(&str, &str)],
    inherited: &HashMap<String, String>,
) -> Result<()> {
    let context = namespace_context(elem, inherited);
    let mut counts = vec![0usize; expected.len()];
    for child in &elem.children {
        let c14n::XmlNode::Element(child) = child else {
            continue;
        };
        let child_context = namespace_context(child, &context);
        let namespace = child_context.get(&child.prefix).map(String::as_str);
        let Some(index) = expected
            .iter()
            .position(|(name, ns)| child.local_name == *name && namespace_matches(namespace, ns))
        else {
            return Err(Error::AuthenticationFailed(
                "encrypted SAML response shape is invalid".into(),
            ));
        };
        counts[index] += 1;
    }
    if counts.iter().any(|count| *count != 1) {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML response shape is invalid".into(),
        ));
    }
    Ok(())
}

fn optional_empty_oaep_params(
    elem: &c14n::XmlElement,
    inherited: &HashMap<String, String>,
) -> Result<()> {
    let context = namespace_context(elem, inherited);
    let mut seen = false;
    for child in &elem.children {
        let c14n::XmlNode::Element(child) = child else {
            continue;
        };
        let child_context = namespace_context(child, &context);
        let namespace = child_context.get(&child.prefix).map(String::as_str);
        if child.local_name != "OAEPparams" || namespace != Some(NS_XENC) {
            continue;
        }
        if seen || require_text_leaf(child).is_err() || !text_content(child).trim().is_empty() {
            return Err(Error::AuthenticationFailed(
                "encrypted SAML response shape is invalid".into(),
            ));
        }
        seen = true;
    }
    Ok(())
}

fn require_key_method_children(
    elem: &c14n::XmlElement,
    inherited: &HashMap<String, String>,
) -> Result<()> {
    let context = namespace_context(elem, inherited);
    let mut counts = [0usize; 2];
    let mut oaep_params = 0usize;
    for child in &elem.children {
        let c14n::XmlNode::Element(child) = child else {
            continue;
        };
        let child_context = namespace_context(child, &context);
        let namespace = child_context.get(&child.prefix).map(String::as_str);
        if child.local_name == "DigestMethod" && namespace == Some(NS_DS) {
            counts[0] += 1;
        } else if child.local_name == "MGF" && namespace == Some(NS_XENC11) {
            counts[1] += 1;
        } else if child.local_name == "OAEPparams" && namespace == Some(NS_XENC) {
            oaep_params += 1;
        } else {
            return Err(Error::AuthenticationFailed(
                "encrypted SAML response shape is invalid".into(),
            ));
        }
    }
    if counts != [1, 1] || oaep_params > 1 {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML response shape is invalid".into(),
        ));
    }
    optional_empty_oaep_params(elem, inherited)
}

fn exact_unqualified_attr<'a>(elem: &'a c14n::XmlElement, local_name: &str) -> Option<&'a str> {
    let mut matches = elem
        .attributes
        .iter()
        .filter(|(prefix, name, _)| prefix.is_empty() && name == local_name);
    let first = matches.next()?.2.as_str();
    if matches.next().is_some() {
        None
    } else {
        Some(first)
    }
}

fn require_text_leaf(elem: &c14n::XmlElement) -> Result<()> {
    if elem.children.iter().any(|child| {
        matches!(
            child,
            c14n::XmlNode::Element(_) | c14n::XmlNode::ProcessingInstruction { .. }
        )
    }) {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML response shape is invalid".into(),
        ));
    }
    Ok(())
}

fn cipher_value(elem: &c14n::XmlElement, inherited: &HashMap<String, String>) -> Result<Vec<u8>> {
    let value = direct_element_ns(elem, "CipherData", NS_XENC, inherited)
        .and_then(|data| direct_element_ns(data, "CipherValue", NS_XENC, inherited))
        .map(text_content)
        .ok_or_else(|| Error::AuthenticationFailed("encrypted SAML cipher is missing".into()))?;
    require_text_leaf(
        direct_element_ns(elem, "CipherData", NS_XENC, inherited)
            .and_then(|data| direct_element_ns(data, "CipherValue", NS_XENC, inherited))
            .expect("cipher value exists"),
    )?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|_| Error::AuthenticationFailed("encrypted SAML cipher is invalid".into()))?;
    if decoded.is_empty() || decoded.len() > MAX_ENCRYPTED_CIPHERTEXT_BYTES {
        return Err(Error::AuthenticationFailed(
            "encrypted SAML cipher exceeds the size limit".into(),
        ));
    }
    Ok(decoded)
}

fn text_content(elem: &c14n::XmlElement) -> Zeroizing<String> {
    elem.children
        .iter()
        .fold(Zeroizing::new(String::new()), |mut output, child| {
            match child {
                c14n::XmlNode::Text(text) => output.push_str(text),
                c14n::XmlNode::Element(element) => output.push_str(&text_content(element)),
                c14n::XmlNode::ProcessingInstruction { .. } => {}
            }
            output
        })
}

/// Decode a SAML Redirect-binding payload: DEFLATE-then-base64.
/// Matches `deflate_base64_encode` on the outgoing side, so this
/// is the function every Redirect-bound `SAMLRequest` /
/// `SAMLResponse` (logout flow) must go through. Decoded payloads
/// are capped before signature or semantic processing.
fn decode_deflate_base64(s: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| Error::AuthenticationFailed(format!("base64 decode failed: {e}")))?;
    let decoder = flate2::read::DeflateDecoder::new(&compressed[..]);
    let mut limited = decoder.take((MAX_SAML_XML_BYTES + 1) as u64);
    let mut out = Vec::with_capacity(
        compressed
            .len()
            .saturating_mul(3)
            .min(MAX_SAML_XML_BYTES + 1),
    );
    limited
        .read_to_end(&mut out)
        .map_err(|e| Error::AuthenticationFailed(format!("inflate failed: {e}")))?;
    if out.len() > MAX_SAML_XML_BYTES {
        return Err(Error::AuthenticationFailed(SAML_XML_LIMIT_ERROR.into()));
    }
    Ok(out)
}

/// Walk a parsed LogoutResponse for `<samlp:Status><samlp:StatusCode Value="...">`
/// and return the `Value`. Returns `None` if either element is absent.
/// Concatenate every immediate text child of an XML element into a
/// single `String`. SAML `<Issuer>`, `<NameID>`, and similar leaves are
/// modelled as one or more text nodes; this helper matches the
/// canonicalisation the signature layer performs.
fn text_of(elem: &c14n::XmlElement) -> String {
    let mut out = String::new();
    for child in &elem.children {
        if let c14n::XmlNode::Text(t) = child {
            out.push_str(t);
        }
    }
    out
}

fn find_status_code(root: &c14n::XmlElement, namespaces: &NamespaceIndex) -> Option<String> {
    use c14n::XmlNode;
    for child in &root.children {
        if let XmlNode::Element(e) = child
            && e.local_name == "Status"
            && namespaces.matches(e, NS_PROTOCOL)
        {
            for sub in &e.children {
                if let XmlNode::Element(sc) = sub
                    && sc.local_name == "StatusCode"
                    && namespaces.matches(sc, NS_PROTOCOL)
                {
                    return sc
                        .attributes
                        .iter()
                        .find(|(_, local, _)| local == "Value")
                        .map(|(_, _, v)| v.clone());
                }
            }
        }
    }
    None
}

/// Return the local part of an XML element name (`prefix:local` →
/// `local`; bare `name` → `name`). XML namespace prefixes are arbitrary
/// — a producer is free to pick `md:`, `samlmd:`, or none at all as
/// long as the URI binding matches — so the streaming metadata extractors
/// dispatch on local-names. Parsed SAML response and logout validation
/// use exact `NamespaceIndex` URI checks instead.
fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().position(|&b| b == b':') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

/// Decode + XML-unescape a metadata attribute value. XML producers may
/// (and do) percent-encode `&` inside a `Location` URL as `&amp;`; taking
/// the raw byte slice would surface that as a literal `&amp;` sequence
/// and break URL comparisons / redirects downstream. Also normalizes
/// attribute-value whitespace per the XML spec.
fn metadata_attr_value(
    attr: &quick_xml::events::attributes::Attribute<'_>,
    decoder: quick_xml::encoding::Decoder,
) -> Option<String> {
    attr.decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, decoder)
        .ok()
        .map(|value| value.into_owned())
}

/// Pull the IdP entity ID from the root `<EntityDescriptor entityID=...>`
/// of an SAML metadata document. Used as the expected SAML Response /
/// Assertion Issuer during validation.
fn extract_idp_entity_id(metadata_xml: &str) -> Option<String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(metadata_xml);
    loop {
        match reader.read_event() {
            Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e))
                if local_name(e.name().as_ref()) == b"EntityDescriptor" =>
            {
                for attr in e.attributes().flatten() {
                    if attr.key.as_ref() == b"entityID" {
                        return metadata_attr_value(&attr, reader.decoder());
                    }
                }
                return None;
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    None
}

/// Walk IdP metadata for a `SingleLogoutService` advertising the
/// requested binding, restricted to the FIRST `<EntityDescriptor>` in
/// the document. Returns its `Location` if found.
///
/// The scoping matches [`extract_idp_entity_id`] and
/// [`extract_all_idp_certs`]: in an `<EntitiesDescriptor>` bundle,
/// only the entity we've settled on as the trust anchor contributes
/// URLs, otherwise a `SamlClient` could end up with entity ID and
/// signing certs from entity A but SLO URL from entity B.
fn extract_slo_url(metadata_xml: &str, binding_uri: &str) -> Option<String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(metadata_xml);
    let mut selected_entity_seen = false;
    let mut in_selected_entity = false;
    loop {
        match reader.read_event() {
            Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => {
                let name = e.name();
                let local = local_name(name.as_ref());
                if local == b"EntityDescriptor" && !selected_entity_seen {
                    selected_entity_seen = true;
                    in_selected_entity = true;
                    continue;
                }
                if in_selected_entity && local == b"SingleLogoutService" {
                    let mut location = None;
                    let mut matched_binding = false;
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"Location" => {
                                location = metadata_attr_value(&attr, reader.decoder());
                            }
                            b"Binding" => {
                                matched_binding = metadata_attr_value(&attr, reader.decoder())
                                    .is_some_and(|binding| binding == binding_uri);
                            }
                            _ => {}
                        }
                    }
                    if matched_binding && location.is_some() {
                        return location;
                    }
                }
            }
            Ok(Event::End(ref e))
                if local_name(e.name().as_ref()) == b"EntityDescriptor" && in_selected_entity =>
            {
                // Selected entity closed; ignore any siblings that
                // belong to different entities.
                return None;
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    None
}

/// Walk IdP metadata for a Redirect-binding `SingleSignOnService`,
/// restricted to the FIRST `<EntityDescriptor>` (same scoping as
/// [`extract_slo_url`] / [`extract_idp_entity_id`]).
fn extract_sso_url(metadata_xml: &str) -> Option<String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(metadata_xml);
    let mut selected_entity_seen = false;
    let mut in_selected_entity = false;
    loop {
        match reader.read_event() {
            Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => {
                let name = e.name();
                let local = local_name(name.as_ref());
                if local == b"EntityDescriptor" && !selected_entity_seen {
                    selected_entity_seen = true;
                    in_selected_entity = true;
                    continue;
                }
                if in_selected_entity && local == b"SingleSignOnService" {
                    let mut location = None;
                    let mut is_redirect = false;
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"Location" => {
                                location = metadata_attr_value(&attr, reader.decoder());
                            }
                            b"Binding" => {
                                is_redirect = metadata_attr_value(&attr, reader.decoder())
                                    .is_some_and(|binding| {
                                        binding
                                            == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                    });
                            }
                            _ => {}
                        }
                    }
                    if is_redirect {
                        return location;
                    }
                }
            }
            Ok(Event::End(ref e))
                if local_name(e.name().as_ref()) == b"EntityDescriptor" && in_selected_entity =>
            {
                return None;
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod slo_tests {
    //! Builder-side unit tests for SAML Single Logout.
    //!
    //! These exercise the pure functions — URL extraction from metadata,
    //! LogoutResponse parsing — without a running IdP or network fetch.
    //! The `SamlClient::new` HTTP path is out of scope for this module.

    use super::*;

    const METADATA_WITH_BOTH: &str = r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>Zm9v</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/slo"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/slo-post"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;

    const METADATA_WITHOUT_SLO: &str = r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;

    #[test]
    fn extract_slo_url_prefers_requested_binding() {
        let redirect = extract_slo_url(METADATA_WITH_BOTH, SAML_BINDING_REDIRECT);
        assert_eq!(redirect.as_deref(), Some("https://idp.example.com/slo"));
        let post = extract_slo_url(METADATA_WITH_BOTH, SAML_BINDING_POST);
        assert_eq!(post.as_deref(), Some("https://idp.example.com/slo-post"));
    }

    #[test]
    fn extract_slo_url_returns_none_when_absent() {
        assert!(extract_slo_url(METADATA_WITHOUT_SLO, SAML_BINDING_REDIRECT).is_none());
        assert!(extract_slo_url(METADATA_WITHOUT_SLO, SAML_BINDING_POST).is_none());
    }

    #[test]
    fn metadata_extractors_unescape_attribute_values() {
        // Extractors must unescape XML attribute values so IdP metadata
        // URLs containing `&` (encoded in XML as `&amp;`) surface as
        // literal `&` and do not break downstream URL comparisons or
        // redirects.
        let metadata = r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/entity?a=1&amp;b=2">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso?a=1&amp;b=2"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/slo?a=1&amp;b=2"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;

        assert_eq!(
            extract_idp_entity_id(metadata).as_deref(),
            Some("https://idp.example.com/entity?a=1&b=2")
        );
        assert_eq!(
            extract_sso_url(metadata).as_deref(),
            Some("https://idp.example.com/sso?a=1&b=2")
        );
        assert_eq!(
            extract_slo_url(metadata, SAML_BINDING_REDIRECT).as_deref(),
            Some("https://idp.example.com/slo?a=1&b=2")
        );
    }

    #[test]
    fn extract_all_idp_certs_excludes_encryption_key() {
        // KeyDescriptor `use="encryption"` must never end up in the set
        // the signature verifier trusts, even when it sits inside the
        // IDPSSODescriptor.
        let signing_cert_b64 = base64::engine::general_purpose::STANDARD.encode(b"SIGNING_CERT");
        let encryption_cert_b64 =
            base64::engine::general_purpose::STANDARD.encode(b"ENCRYPTION_CERT");
        let metadata = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{signing_cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{encryption_cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#
        );
        let certs = extract_all_idp_certs(&metadata);
        let signing_bytes = b"SIGNING_CERT".to_vec();
        let encryption_bytes = b"ENCRYPTION_CERT".to_vec();
        assert_eq!(certs.len(), 1, "encryption cert must not be trusted");
        assert_eq!(certs[0], signing_bytes);
        assert!(!certs.iter().any(|c| c == &encryption_bytes));
    }

    #[test]
    fn extract_all_idp_certs_excludes_sp_side_descriptor() {
        // SPSSODescriptor / AuthnAuthorityDescriptor / other roles
        // publish their own keys. Signing an AuthnResponse with an
        // SP-side key must not be accepted, so those descriptors are
        // out of scope even when they sit in the same metadata
        // document.
        let idp_cert_b64 = base64::engine::general_purpose::STANDARD.encode(b"IDP_CERT");
        let sp_cert_b64 = base64::engine::general_purpose::STANDARD.encode(b"SP_CERT");
        let metadata = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{idp_cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{sp_cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#
        );
        let certs = extract_all_idp_certs(&metadata);
        let idp_bytes = b"IDP_CERT".to_vec();
        let sp_bytes = b"SP_CERT".to_vec();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], idp_bytes);
        assert!(!certs.iter().any(|c| c == &sp_bytes));
    }

    #[test]
    fn extract_all_idp_certs_excludes_other_entity_in_bundle() {
        // A `<EntitiesDescriptor>` bundle can carry multiple IdP
        // `<EntityDescriptor>` children. `extract_idp_entity_id` picks
        // the first one; `extract_all_idp_certs` must scope to the
        // same entity, otherwise the client would trust the second
        // entity's signing key to authenticate the first entity's
        // AuthnResponses.
        let selected_cert_b64 =
            base64::engine::general_purpose::STANDARD.encode(b"SELECTED_ENTITY_CERT");
        let other_cert_b64 = base64::engine::general_purpose::STANDARD.encode(b"OTHER_ENTITY_CERT");
        let metadata = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <md:EntityDescriptor entityID="https://idp.example.com/entity">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="signing">
        <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{selected_cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      </md:KeyDescriptor>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://other-idp.example.com/entity">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="signing">
        <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{other_cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      </md:KeyDescriptor>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>"#
        );
        assert_eq!(
            extract_idp_entity_id(&metadata).as_deref(),
            Some("https://idp.example.com/entity"),
            "extract_idp_entity_id must pick the first entity",
        );
        let certs = extract_all_idp_certs(&metadata);
        let selected_bytes = b"SELECTED_ENTITY_CERT".to_vec();
        let other_bytes = b"OTHER_ENTITY_CERT".to_vec();
        assert_eq!(certs, vec![selected_bytes]);
        assert!(
            !certs.iter().any(|c| c == &other_bytes),
            "other entity's signing cert must not be trusted"
        );
    }

    #[test]
    fn extract_sso_and_slo_urls_are_scoped_to_selected_entity() {
        // First `<EntityDescriptor>` carries entityID + signing cert
        // but NO SSO/SLO service. Second entity carries only SSO/SLO.
        // The extractors must not adopt the second entity's URLs — a
        // mixed client would send AuthnRequests / LogoutRequests to
        // an entity whose signing key we do not trust.
        let selected_cert_b64 =
            base64::engine::general_purpose::STANDARD.encode(b"SELECTED_ENTITY_CERT");
        let metadata = format!(
            r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <md:EntityDescriptor entityID="https://idp.example.com/entity">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="signing">
        <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{selected_cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      </md:KeyDescriptor>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://other-idp.example.com/entity">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://other-idp.example.com/sso"/>
      <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://other-idp.example.com/slo"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>"#
        );
        assert_eq!(
            extract_idp_entity_id(&metadata).as_deref(),
            Some("https://idp.example.com/entity"),
            "sanity: entity ID picker settles on the first entity",
        );
        assert!(
            extract_sso_url(&metadata).is_none(),
            "SSO URL from a different entity must not be adopted"
        );
        assert!(
            extract_slo_url(&metadata, SAML_BINDING_REDIRECT).is_none(),
            "SLO URL from a different entity must not be adopted"
        );
    }

    #[test]
    fn extract_all_idp_certs_accepts_key_descriptor_without_use_attribute() {
        // SAML metadata §2.4.1.1: an omitted `use` means the key covers
        // both signing and encryption. The signing role must therefore
        // accept it.
        let cert_b64 = base64::engine::general_purpose::STANDARD.encode(b"DEFAULT");
        let metadata = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor>
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#
        );
        let certs = extract_all_idp_certs(&metadata);
        let expected = b"DEFAULT".to_vec();
        assert_eq!(certs, vec![expected]);
    }

    #[test]
    fn authn_request_url_appends_ampersand_when_sso_url_has_query() {
        let mut client = mk_client(None);
        client.sso_url = "https://idp.example.com/sso?tenant=acme".into();
        let (url, _id) = client.authn_request_url("rs").expect("build url");
        assert!(
            url.starts_with("https://idp.example.com/sso?tenant=acme&SAMLRequest="),
            "expected ampersand separator, got: {url}"
        );
        assert!(url.contains("&RelayState=rs"));
    }

    #[test]
    fn authn_request_url_xml_escapes_ampersand_in_sso_destination() {
        // A metadata SSO URL containing `&` (e.g. multi-tenant IdPs
        // that carry a query on the endpoint) must be XML-escaped in
        // the AuthnRequest's Destination attribute so the emitted
        // message stays well-formed.
        let mut client = mk_client(None);
        client.sso_url = "https://idp.example.com/sso?a=1&b=2".into();
        let (url, _id) = client.authn_request_url("rs").expect("build url");
        let payload = url
            .split("SAMLRequest=")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .expect("SAMLRequest param");
        let encoded = urlencoding::decode(payload).expect("decode");
        let xml = String::from_utf8(decode_deflate_base64(&encoded).unwrap()).unwrap();
        assert!(
            xml.contains(r#"Destination="https://idp.example.com/sso?a=1&amp;b=2""#),
            "Destination attribute must XML-escape `&`, got: {xml}"
        );
        assert!(!xml.contains("a=1&b=2\""), "raw `&` must not leak: {xml}");
    }

    #[test]
    fn extract_slo_url_skips_sso_service_with_matching_binding() {
        // Defence against a metadata parser bug that accepts any
        // `*Service` element with the right Binding — a buggy impl
        // could return the SSO URL here, which would land a
        // LogoutRequest on the login endpoint and produce a confusing
        // failure instead of "SLO unsupported".
        assert!(extract_slo_url(METADATA_WITHOUT_SLO, SAML_BINDING_REDIRECT).is_none());
    }

    /// Build a `SamlClient` by hand for tests that don't need a running
    /// IdP — the public `new()` does a metadata fetch we can't stub cleanly.
    fn mk_client(slo: Option<&str>) -> SamlClient {
        SamlClient {
            entity_id: "https://sp.example.com".into(),
            acs_url: "https://sp.example.com/saml/acs".into(),
            sp_slo_url: None,
            idp_entity_id: "https://idp.example.com".into(),
            sso_url: "https://idp.example.com/sso".into(),
            slo_redirect_url: slo.map(str::to_string),
            attribute_mapping: HashMap::new(),
            idp_certs_der: vec![TEST_CERT_DER.to_vec()],
            request_id_prefix: "_test".into(),
            sp_credentials: None,
        }
    }

    fn nested_saml_document(root: &str, depth: usize) -> String {
        assert!(depth > 0);
        let mut xml = format!("<{root}>");
        xml.push_str(&"<n>".repeat(depth - 1));
        xml.push_str(&"</n>".repeat(depth - 1));
        xml.push_str(&format!("</{root}>"));
        xml
    }

    // Baked-in RSA test key + matching certificate, shared with signature
    // tests. `TEST_KEY_PKCS8_DER` signs the redirect query the tests hand
    // to `process_logout_response`; `TEST_CERT_DER` (populated on
    // `mk_client().idp_certs_der`) provides the matching public key.
    const TEST_KEY_PKCS8_DER: &[u8] = include_bytes!("testdata/saml_test.p8.der");
    const TEST_CERT_DER: &[u8] = include_bytes!("testdata/saml_test.crt.der");

    fn encrypted_public_fixture() -> (SamlClient, String, String, String) {
        use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
        use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey};
        let (signed, _) = signature::tests::process_response_identity_fixtures();
        let start = signed.find("<saml:Assertion").expect("assertion start");
        let end = signed[start..]
            .find("</saml:Assertion>")
            .map(|i| start + i + "</saml:Assertion>".len())
            .expect("assertion end");
        let content_key = [7u8; 32];
        let nonce_bytes = [3u8; 12];
        let plaintext = signed[start..end].to_owned();
        let mut encrypted_content = plaintext.as_bytes().to_vec();
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &content_key).expect("AES key"))
            .seal_in_place_append_tag(
                Nonce::try_assume_unique_for_key(&nonce_bytes).expect("nonce"),
                Aad::empty(),
                &mut encrypted_content,
            )
            .expect("seal");
        let private = PrivateDecryptingKey::from_pkcs8(TEST_KEY_PKCS8_DER).expect("RSA key");
        let public_der =
            AsDer::<PublicKeyX509Der>::as_der(&private.public_key()).expect("public key DER");
        let public = OaepPublicEncryptingKey::new(
            PublicEncryptingKey::from_der(public_der.as_ref()).expect("public key"),
        )
        .expect("OAEP key");
        let mut wrapped = vec![0; public.ciphertext_size()];
        let wrapped = public
            .encrypt(&OAEP_SHA256_MGF1SHA256, &content_key, &mut wrapped, None)
            .expect("wrap");
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(wrapped);
        let mut data = nonce_bytes.to_vec();
        data.extend_from_slice(&encrypted_content);
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let encrypted = format!(
            r#"<saml:EncryptedAssertion ID="_a1"><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="{XMLENC_AES256_GCM}"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="{XMLENC_RSA_OAEP}"><ds:DigestMethod Algorithm="{XMLENC_SHA256}"/><xenc11:MGF Algorithm="{XMLENC_MGF1_SHA256}"/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>{key_b64}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{data_b64}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>"#
        );
        let prefix = signed[..start].replacen("<samlp:Response", "<samlp:Response xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"", 1);
        let response = prefix + &encrypted + &signed[end..];
        let credentials = SamlSpCredentials::try_new(
            pem("CERTIFICATE", TEST_CERT_DER),
            pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
        )
        .expect("credentials");
        let mut client = mk_client(None);
        client.sp_credentials = Some(credentials);
        (client, response, data_b64, plaintext)
    }

    fn reencrypt_fixture_plaintext(response: &str, plaintext: &[u8]) -> String {
        let content_key = [7u8; 32];
        let nonce_bytes = [3u8; 12];
        let mut encrypted = plaintext.to_vec();
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &content_key).expect("AES key"))
            .seal_in_place_append_tag(
                Nonce::try_assume_unique_for_key(&nonce_bytes).expect("nonce"),
                Aad::empty(),
                &mut encrypted,
            )
            .expect("seal");
        let mut data = nonce_bytes.to_vec();
        data.extend_from_slice(&encrypted);
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        let start =
            response.find("<xenc:CipherValue>").expect("cipher start") + "<xenc:CipherValue>".len();
        let end = response[start..]
            .find("</xenc:CipherValue>")
            .map(|i| start + i)
            .expect("cipher end");
        let second_start = response[end..]
            .find("<xenc:CipherValue>")
            .map(|i| end + i + "<xenc:CipherValue>".len())
            .expect("data cipher start");
        let second_end = response[second_start..]
            .find("</xenc:CipherValue>")
            .map(|i| second_start + i)
            .expect("data cipher end");
        let mut out = response.to_owned();
        out.replace_range(second_start..second_end, &encoded);
        out
    }

    fn replace_first_cipher_value(response: &str, value: &str) -> String {
        let start = response
            .find("<xenc:CipherValue>")
            .expect("key cipher start")
            + "<xenc:CipherValue>".len();
        let end = response[start..]
            .find("</xenc:CipherValue>")
            .map(|i| start + i)
            .expect("key cipher end");
        let mut out = response.to_owned();
        out.replace_range(start..end, value);
        out
    }

    fn replace_data_cipher_value(response: &str, value: &str) -> String {
        let first_end = response
            .find("</xenc:CipherValue>")
            .expect("key cipher end");
        let start = response[first_end..]
            .find("<xenc:CipherValue>")
            .map(|i| first_end + i + "<xenc:CipherValue>".len())
            .expect("data cipher start");
        let end = response[start..]
            .find("</xenc:CipherValue>")
            .map(|i| start + i)
            .expect("data cipher end");
        let mut out = response.to_owned();
        out.replace_range(start..end, value);
        out
    }

    #[test]
    fn process_response_consumes_only_the_verified_direct_assertion() {
        let client = mk_client(None);
        let (valid, wrapped) = signature::tests::process_response_identity_fixtures();
        let valid = base64::engine::general_purpose::STANDARD.encode(valid);
        let wrapped = base64::engine::general_purpose::STANDARD.encode(wrapped);

        let user = client
            .process_response(&valid, Some("_req1"))
            .expect("valid signed login response");
        assert_eq!(user.email, "alice@example.com");
        assert!(
            client.process_response(&wrapped, Some("_req1")).is_err(),
            "wrapped signed identity must be rejected"
        );
    }

    #[test]
    fn post_base64_decode_enforces_common_xml_limit() {
        let exact = vec![b'x'; MAX_SAML_XML_BYTES];
        let exact_payload = base64::engine::general_purpose::STANDARD.encode(&exact);
        let decoded = decode_base64_saml_xml(&exact_payload, "login decode")
            .expect("exact decoded boundary must be accepted");
        assert_eq!(decoded.len(), MAX_SAML_XML_BYTES);

        let oversized = vec![b'x'; MAX_SAML_XML_BYTES + 1];
        let oversized_payload = base64::engine::general_purpose::STANDARD.encode(&oversized);
        let error = decode_base64_saml_xml(&oversized_payload, "login decode")
            .expect_err("decoded limit plus one must be rejected");
        assert!(
            matches!(
                error,
                Error::AuthenticationFailed(ref message)
                    if message == SAML_XML_LIMIT_ERROR
            ),
            "oversized POST payload must return the fixed safe error"
        );

        let login_error =
            decode_base64_saml_xml("%%%invalid-base64%%%", "SAML response base64 decode failed")
                .expect_err("invalid login base64 must fail");
        assert!(
            matches!(
                login_error,
                Error::AuthenticationFailed(ref message)
                    if message.starts_with("SAML response base64 decode failed:")
            ),
            "login invalid-base64 classification must be preserved"
        );

        let logout_error = decode_base64_saml_xml(
            "%%%invalid-base64%%%",
            "SAML LogoutResponse base64 decode failed",
        )
        .expect_err("invalid logout base64 must fail");
        assert!(
            matches!(
                logout_error,
                Error::AuthenticationFailed(ref message)
                    if message.starts_with("SAML LogoutResponse base64 decode failed:")
            ),
            "logout invalid-base64 classification must be preserved"
        );
    }

    #[test]
    fn login_and_logout_post_reject_oversize_before_verification() {
        let client = mk_client(None);
        let payload =
            base64::engine::general_purpose::STANDARD.encode(vec![b'x'; MAX_SAML_XML_BYTES + 1]);

        let login_error = client
            .process_response(&payload, Some("_req"))
            .err()
            .expect("oversized login POST must fail before signature processing");
        assert!(
            matches!(
                login_error,
                Error::AuthenticationFailed(ref message)
                    if message == SAML_XML_LIMIT_ERROR
            ),
            "login POST must use the common fixed limit error"
        );

        let logout_error = client
            .process_logout_response(&payload, "_req", LogoutResponseBinding::Post)
            .expect_err("oversized logout POST must fail before signature processing");
        assert!(
            matches!(
                logout_error,
                Error::AuthenticationFailed(ref message)
                    if message == SAML_XML_LIMIT_ERROR
            ),
            "logout POST must use the common fixed limit error"
        );
    }

    #[test]
    fn login_and_logout_post_preserve_utf8_error_classification() {
        let client = mk_client(None);
        let payload = base64::engine::general_purpose::STANDARD.encode([0xff]);

        let login_error = client
            .process_response(&payload, Some("_req"))
            .err()
            .expect("invalid login UTF-8 must fail");
        assert!(
            matches!(
                login_error,
                Error::AuthenticationFailed(ref message)
                    if message.starts_with("SAML response UTF-8 error:")
            ),
            "login UTF-8 classification must be preserved"
        );

        let logout_error = client
            .process_logout_response(&payload, "_req", LogoutResponseBinding::Post)
            .expect_err("invalid logout UTF-8 must fail");
        assert!(
            matches!(
                logout_error,
                Error::AuthenticationFailed(ref message)
                    if message.starts_with("SAML LogoutResponse UTF-8 error:")
            ),
            "logout UTF-8 classification must be preserved"
        );
    }

    #[test]
    fn login_and_logout_post_inherit_parser_depth_limit() {
        let client = mk_client(None);
        let depth = c14n::MAX_XML_ELEMENT_DEPTH + 1;

        let login_payload = base64::engine::general_purpose::STANDARD
            .encode(nested_saml_document("Response", depth));
        let login_error = client
            .process_response(&login_payload, Some("_req"))
            .err()
            .expect("deep login XML must fail during parsing");
        assert!(
            matches!(
                login_error,
                Error::AuthenticationFailed(ref message)
                    if message == c14n::XML_DEPTH_LIMIT_ERROR
            ),
            "login path must inherit the fixed parser depth error"
        );

        let logout_payload = base64::engine::general_purpose::STANDARD
            .encode(nested_saml_document("LogoutResponse", depth));
        let logout_error = client
            .process_logout_response(&logout_payload, "_req", LogoutResponseBinding::Post)
            .expect_err("deep logout XML must fail during parsing");
        assert!(
            matches!(
                logout_error,
                Error::AuthenticationFailed(ref message)
                    if message == c14n::XML_DEPTH_LIMIT_ERROR
            ),
            "logout path must inherit the fixed parser depth error"
        );
    }

    #[test]
    fn logout_request_redirect_url_fails_when_slo_absent() {
        let client = mk_client(None);
        let err = client
            .logout_request_redirect_url("alice@example.com", None, "rs")
            .unwrap_err();
        assert!(format!("{err}").contains("no SLO endpoint"), "got: {err}");
    }

    #[test]
    fn logout_request_redirect_url_encodes_samlrequest_and_relaystate() {
        let client = mk_client(Some("https://idp.example.com/slo"));
        let (url, id) = client
            .logout_request_redirect_url("alice@example.com", None, "state 1?x=2")
            .expect("build url");

        assert!(id.starts_with("_test_lo_"));
        assert!(url.starts_with("https://idp.example.com/slo?SAMLRequest="));
        // RelayState with a space + query char must survive URL encoding.
        assert!(url.contains("&RelayState=state%201%3Fx%3D2"));
        // SAMLRequest is DEFLATE+base64 of our LogoutRequest — round-trip
        // it through the decoder and check the XML carries the NameID and ID.
        let qs: std::collections::HashMap<_, _> = url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        let payload = qs.get("SAMLRequest").unwrap();
        let xml_bytes = decode_deflate_base64(payload).expect("decode payload");
        let xml = String::from_utf8(xml_bytes).expect("utf8");
        assert!(xml.contains("alice@example.com"));
        assert!(xml.contains(&format!(r#"ID="{id}""#)));
        assert!(xml.contains(r#"Destination="https://idp.example.com/slo""#));
    }

    #[test]
    fn logout_request_redirect_url_appends_ampersand_when_endpoint_has_query() {
        let client = mk_client(Some("https://idp.example.com/slo?tenant=acme"));
        let (url, _id) = client
            .logout_request_redirect_url("bob@example.com", None, "xyz")
            .unwrap();
        assert!(url.starts_with("https://idp.example.com/slo?tenant=acme&SAMLRequest="));
        assert!(url.contains("&RelayState=xyz"));
    }

    #[test]
    fn logout_request_escapes_xml_metacharacters_in_name_id() {
        // If the IdP ever emits a NameID containing XML metacharacters
        // (unusual but legal — NameID is just xs:string), we must not
        // inject them raw and produce malformed XML.
        let client = mk_client(Some("https://idp.example.com/slo"));
        let (url, _id) = client
            .logout_request_redirect_url("a&b<c>@example.com", None, "")
            .unwrap();
        let qs: std::collections::HashMap<_, _> = url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        let payload = qs.get("SAMLRequest").unwrap();
        let xml = String::from_utf8(decode_deflate_base64(payload).unwrap()).unwrap();
        assert!(xml.contains("a&amp;b&lt;c&gt;@example.com"));
        assert!(!xml.contains("a&b<c>@example.com"));
    }

    /// Minimal success LogoutResponse. Redirect binding signs the query
    /// string, so the XML itself intentionally has no embedded ds:Signature.
    fn logout_response_xml(in_response_to: &str, status: &str) -> String {
        format!(
            r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z" InResponseTo="{in_response_to}"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status></samlp:LogoutResponse>"#
        )
    }

    fn logout_response_xml_full(
        in_response_to: &str,
        issuer: &str,
        destination: Option<&str>,
        status: &str,
    ) -> String {
        let dest_attr = match destination {
            Some(d) => format!(r#" Destination="{d}""#),
            None => String::new(),
        };
        format!(
            r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z"{dest_attr} InResponseTo="{in_response_to}"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status></samlp:LogoutResponse>"#
        )
    }

    /// DEFLATE+base64 a LogoutResponse, mimicking how the IdP returns
    /// it via the HTTP-Redirect binding's `SAMLResponse` query parameter.
    fn deflate_bytes_b64(bytes: &[u8]) -> String {
        use std::io::Write;
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes).unwrap();
        let bytes = enc.finish().unwrap();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn deflate_b64(xml: &str) -> String {
        deflate_bytes_b64(xml.as_bytes())
    }

    /// Build a signed HTTP-Redirect binding query for `SAMLResponse=payload`.
    /// Uses the baked-in RSA test key so the signature can be verified with
    /// the matching `TEST_CERT_DER` populated on `mk_client()`.
    fn signed_logout_response_query(payload: &str, relay_state: Option<&str>) -> String {
        use ring::rand::SystemRandom;
        use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

        let sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        let mut signed_input = format!("SAMLResponse={}", urlencoding::encode(payload));
        if let Some(relay_state) = relay_state {
            signed_input.push_str("&RelayState=");
            signed_input.push_str(&urlencoding::encode(relay_state));
        }
        signed_input.push_str("&SigAlg=");
        signed_input.push_str(&urlencoding::encode(sig_alg));

        let key = RsaKeyPair::from_pkcs8(TEST_KEY_PKCS8_DER).expect("test RSA key");
        let rng = SystemRandom::new();
        let mut signature = vec![0; key.public().modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &rng,
            signed_input.as_bytes(),
            &mut signature,
        )
        .expect("sign redirect query");

        format!(
            "{signed_input}&Signature={}",
            urlencoding::encode(&base64::engine::general_purpose::STANDARD.encode(signature))
        )
    }

    #[test]
    fn process_logout_response_accepts_success() {
        let client = mk_client(Some("https://idp.example.com/slo"));
        let xml = logout_response_xml(
            "_test_lo_req1",
            "urn:oasis:names:tc:SAML:2.0:status:Success",
        );
        let payload = deflate_b64(&xml);
        let query = signed_logout_response_query(&payload, None);
        client
            .process_logout_response(
                &payload,
                "_test_lo_req1",
                LogoutResponseBinding::Redirect { raw_query: &query },
            )
            .expect("success");
    }

    #[test]
    fn process_logout_response_ignores_signed_foreign_issuer_collision() {
        let client = mk_client(Some("https://idp.example.com/slo"));
        let xml = logout_response_xml(
            "_test_lo_req1",
            "urn:oasis:names:tc:SAML:2.0:status:Success",
        )
        .replacen(
            "<saml:Issuer>",
            "<evil:Issuer xmlns:evil=\"urn:attacker:assertion\">evil</evil:Issuer><saml:Issuer>",
            1,
        );
        let payload = deflate_b64(&xml);
        let query = signed_logout_response_query(&payload, None);
        client
            .process_logout_response(
                &payload,
                "_test_lo_req1",
                LogoutResponseBinding::Redirect { raw_query: &query },
            )
            .expect("foreign Issuer collision must not hide the genuine SAML Issuer");
    }

    #[test]
    fn redirect_decode_enforces_decoded_size_limit() {
        let exact = vec![b'x'; MAX_SAML_XML_BYTES];
        let exact_payload = deflate_bytes_b64(&exact);
        let decoded = decode_deflate_base64(&exact_payload).expect("exact boundary must decode");
        assert_eq!(
            decoded.len(),
            MAX_SAML_XML_BYTES,
            "exact decoded boundary must be preserved"
        );

        let oversized = vec![b'x'; MAX_SAML_XML_BYTES + 1];
        let oversized_payload = deflate_bytes_b64(&oversized);
        assert!(
            oversized_payload.len() < 8 * 1024,
            "fixture must remain a high-ratio compressed payload"
        );
        let err = decode_deflate_base64(&oversized_payload)
            .expect_err("decoded limit plus one must be rejected");
        assert!(
            matches!(
                err,
                Error::AuthenticationFailed(ref message)
                    if message == SAML_XML_LIMIT_ERROR
            ),
            "oversized decoded payload must return the fixed limit error"
        );
    }

    #[test]
    fn redirect_decode_preserves_invalid_input_error_class() {
        assert!(
            matches!(
                decode_deflate_base64("%%%invalid-base64%%%"),
                Err(Error::AuthenticationFailed(_))
            ),
            "invalid base64 must remain an authentication failure"
        );

        let invalid_deflate = base64::engine::general_purpose::STANDARD.encode([0xff; 16]);
        assert!(
            matches!(
                decode_deflate_base64(&invalid_deflate),
                Err(Error::AuthenticationFailed(_))
            ),
            "invalid DEFLATE must remain an authentication failure"
        );
    }

    #[test]
    fn oversized_redirect_fails_before_signature_processing() {
        let client = mk_client(Some("https://idp.example.com/slo"));
        let oversized = vec![b'x'; MAX_SAML_XML_BYTES + 1];
        let payload = deflate_bytes_b64(&oversized);
        let err = client
            .process_logout_response(
                &payload,
                "_req",
                LogoutResponseBinding::Redirect {
                    raw_query: "not-a-signed-query",
                },
            )
            .expect_err("oversized Redirect payload must fail closed");
        assert!(
            matches!(
                err,
                Error::AuthenticationFailed(ref message)
                    if message == SAML_XML_LIMIT_ERROR
            ),
            "decoded-size rejection must precede signature and semantic processing"
        );
    }

    #[test]
    fn post_logout_response_consumes_only_the_verified_root() {
        let client = mk_client(Some("https://idp.example.com/slo"));
        let (valid, attacks) = signature::tests::logout_response_identity_fixtures();
        let valid = base64::engine::general_purpose::STANDARD.encode(valid);
        client
            .process_logout_response(&valid, "_test_lo_req1", LogoutResponseBinding::Post)
            .expect("valid root-signed POST LogoutResponse");

        for attack in attacks {
            let encoded = base64::engine::general_purpose::STANDARD.encode(attack);
            assert!(
                client
                    .process_logout_response(
                        &encoded,
                        "_test_lo_req1",
                        LogoutResponseBinding::Post,
                    )
                    .is_err(),
                "ambiguous signed POST LogoutResponse must be rejected"
            );
        }
    }

    #[test]
    fn process_logout_response_rejects_wrong_in_response_to() {
        let client = mk_client(Some("https://idp.example.com/slo"));
        let xml = logout_response_xml("_other", "urn:oasis:names:tc:SAML:2.0:status:Success");
        let payload = deflate_b64(&xml);
        let query = signed_logout_response_query(&payload, None);
        let err = client
            .process_logout_response(
                &payload,
                "_expected",
                LogoutResponseBinding::Redirect { raw_query: &query },
            )
            .unwrap_err();
        assert!(format!("{err}").contains("InResponseTo"), "got: {err}");
    }

    #[test]
    fn process_logout_response_rejects_missing_in_response_to() {
        let client = mk_client(Some("https://idp.example.com/slo"));
        // Same minimal shape but without the InResponseTo attribute.
        let xml = r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#;
        let payload = deflate_b64(xml);
        let query = signed_logout_response_query(&payload, None);
        let err = client
            .process_logout_response(
                &payload,
                "_expected",
                LogoutResponseBinding::Redirect { raw_query: &query },
            )
            .unwrap_err();
        assert!(format!("{err}").contains("InResponseTo"), "got: {err}");
    }

    #[test]
    fn process_logout_response_surfaces_non_success_status() {
        let client = mk_client(Some("https://idp.example.com/slo"));
        let xml = logout_response_xml("_req", "urn:oasis:names:tc:SAML:2.0:status:PartialLogout");
        let payload = deflate_b64(&xml);
        let query = signed_logout_response_query(&payload, None);
        let err = client
            .process_logout_response(
                &payload,
                "_req",
                LogoutResponseBinding::Redirect { raw_query: &query },
            )
            .unwrap_err();
        assert!(format!("{err}").contains("PartialLogout"), "got: {err}");
    }

    #[test]
    fn process_logout_response_rejects_wrong_root_element() {
        let client = mk_client(Some("https://idp.example.com/slo"));
        // An IdP that replies with a LogoutRequest (i.e. starts its own
        // IdP-initiated logout) must not be mistaken for a reply to ours.
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z"><saml:NameID>a@x</saml:NameID></samlp:LogoutRequest>"#;
        let payload = deflate_b64(xml);
        let query = signed_logout_response_query(&payload, None);
        let err = client
            .process_logout_response(
                &payload,
                "_req",
                LogoutResponseBinding::Redirect { raw_query: &query },
            )
            .unwrap_err();
        assert!(format!("{err}").contains("LogoutResponse"), "got: {err}");
    }

    #[test]
    fn process_logout_response_rejects_forged_redirect_signature() {
        // Attacker-controlled query string signed with a key we don't
        // recognise. The client's `idp_certs_der` cannot verify the
        // Signature, so the whole thing must be rejected before any
        // InResponseTo / status inspection happens.
        let client = mk_client(Some("https://idp.example.com/slo"));
        let xml = logout_response_xml("_req", "urn:oasis:names:tc:SAML:2.0:status:Success");
        let payload = deflate_b64(&xml);
        // A syntactically-valid-looking query with a bogus Signature.
        let bogus_query = format!(
            "SAMLResponse={}&SigAlg={}&Signature={}",
            urlencoding::encode(&payload),
            urlencoding::encode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            urlencoding::encode(&base64::engine::general_purpose::STANDARD.encode([0u8; 256])),
        );
        let err = client
            .process_logout_response(
                &payload,
                "_req",
                LogoutResponseBinding::Redirect {
                    raw_query: &bogus_query,
                },
            )
            .unwrap_err();
        assert!(
            format!("{err}").contains("verification failed"),
            "got: {err}"
        );
    }

    #[test]
    fn process_logout_response_rejects_wrong_issuer() {
        // The XML-DSig layer bound the response to a trusted key, but a
        // rogue tenant sharing the same signing infrastructure could
        // still emit a response whose Issuer names a different IdP.
        // Refuse.
        let client = mk_client(Some("https://idp.example.com/slo"));
        let xml = logout_response_xml_full(
            "_req",
            "https://other-idp.example.com",
            None,
            "urn:oasis:names:tc:SAML:2.0:status:Success",
        );
        let payload = deflate_b64(&xml);
        let query = signed_logout_response_query(&payload, None);
        let err = client
            .process_logout_response(
                &payload,
                "_req",
                LogoutResponseBinding::Redirect { raw_query: &query },
            )
            .unwrap_err();
        assert!(format!("{err}").contains("Issuer"), "got: {err}");
    }

    #[test]
    fn process_logout_response_rejects_wrong_destination() {
        // Destination pinning defends against a signed LogoutResponse
        // being replayed against a peer SP that trusts the same IdP:
        // the browser landing at our /saml/slo endpoint with someone
        // else's Destination attribute must be refused.
        let mut client = mk_client(Some("https://idp.example.com/slo"));
        client.sp_slo_url = Some("https://sp.example.com/saml/slo".into());
        let xml = logout_response_xml_full(
            "_req",
            "https://idp.example.com",
            Some("https://other-sp.example.com/saml/slo"),
            "urn:oasis:names:tc:SAML:2.0:status:Success",
        );
        let payload = deflate_b64(&xml);
        let query = signed_logout_response_query(&payload, None);
        let err = client
            .process_logout_response(
                &payload,
                "_req",
                LogoutResponseBinding::Redirect { raw_query: &query },
            )
            .unwrap_err();
        assert!(format!("{err}").contains("Destination"), "got: {err}");
    }

    #[test]
    fn logout_request_includes_session_index_when_provided() {
        let client = mk_client(Some("https://idp.example.com/slo"));
        let (url, _id) = client
            .logout_request_redirect_url("alice@example.com", Some("_abc12345-session-index"), "rs")
            .expect("build url");
        let qs: std::collections::HashMap<_, _> = url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        let payload = qs.get("SAMLRequest").unwrap();
        let xml = String::from_utf8(decode_deflate_base64(payload).unwrap()).unwrap();
        // SessionIndex element must be present and ordered after NameID
        // (spec §3.7.1). Position check guards against a regression
        // that puts SessionIndex before NameID — ADFS rejects that
        // ordering.
        let name_id_pos = xml.find("</saml:NameID>").expect("NameID present");
        let si_pos = xml
            .find("<samlp:SessionIndex>_abc12345-session-index</samlp:SessionIndex>")
            .expect("SessionIndex present");
        assert!(si_pos > name_id_pos, "SessionIndex must follow NameID");
    }

    #[test]
    fn logout_request_omits_session_index_when_none() {
        // Sessions where the IdP didn't return an AuthnStatement with
        // SessionIndex must still produce a valid LogoutRequest;
        // IdP-side matching with only NameID is IdP-dependent.
        let client = mk_client(Some("https://idp.example.com/slo"));
        let (url, _id) = client
            .logout_request_redirect_url("alice@example.com", None, "rs")
            .expect("build url");
        let qs: std::collections::HashMap<_, _> = url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        let payload = qs.get("SAMLRequest").unwrap();
        let xml = String::from_utf8(decode_deflate_base64(payload).unwrap()).unwrap();
        assert!(
            !xml.contains("SessionIndex"),
            "session without IdP-supplied SessionIndex must not emit element, got: {xml}"
        );
    }

    #[test]
    fn logout_request_omits_session_index_when_empty_string() {
        // Defensive: an empty-string SessionIndex would serialize to
        // `<samlp:SessionIndex></samlp:SessionIndex>`, which the IdP
        // would either reject or treat as a global logout. Treat empty
        // as absent.
        let client = mk_client(Some("https://idp.example.com/slo"));
        let (url, _id) = client
            .logout_request_redirect_url("alice@example.com", Some(""), "rs")
            .expect("build url");
        let qs: std::collections::HashMap<_, _> = url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        let payload = qs.get("SAMLRequest").unwrap();
        let xml = String::from_utf8(decode_deflate_base64(payload).unwrap()).unwrap();
        assert!(!xml.contains("SessionIndex"), "got: {xml}");
    }

    #[test]
    fn logout_request_escapes_xml_metacharacters_in_session_index() {
        // SessionIndex values are opaque IdP-issued strings. Entra
        // emits UUID-like values, but the spec only requires xs:string,
        // so escape metacharacters defensively — same policy as NameID.
        let client = mk_client(Some("https://idp.example.com/slo"));
        let (url, _id) = client
            .logout_request_redirect_url("alice@example.com", Some("a&b<c>\"d'"), "rs")
            .expect("build url");
        let qs: std::collections::HashMap<_, _> = url::Url::parse(&url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        let payload = qs.get("SAMLRequest").unwrap();
        let xml = String::from_utf8(decode_deflate_base64(payload).unwrap()).unwrap();
        assert!(
            xml.contains("<samlp:SessionIndex>a&amp;b&lt;c&gt;&quot;d&apos;</samlp:SessionIndex>")
        );
        assert!(!xml.contains("a&b<c>"));
    }

    #[test]
    fn sp_metadata_includes_slo_when_configured() {
        let mut client = mk_client(None);
        client.sp_slo_url = Some("https://sp.example.com/saml/slo".into());
        let metadata = client.sp_metadata();
        assert!(metadata.contains("SingleLogoutService"));
        assert!(metadata.contains("Location=\"https://sp.example.com/saml/slo\""));
        assert!(metadata.contains(SAML_BINDING_REDIRECT));
        assert!(metadata.contains(SAML_BINDING_POST));
    }

    #[test]
    fn sp_metadata_omits_slo_when_unset() {
        let client = mk_client(None);
        let metadata = client.sp_metadata();
        assert!(!metadata.contains("SingleLogoutService"));
    }

    fn pem(label: &str, der: &[u8]) -> Vec<u8> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN {label}-----\n{encoded}\n-----END {label}-----\n").into_bytes()
    }

    #[test]
    fn sp_credentials_validate_match_and_redact_debug() {
        let credentials = SamlSpCredentials::try_new(
            pem("CERTIFICATE", TEST_CERT_DER),
            pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
        )
        .expect("test certificate and key match");
        let debug = format!("{credentials:?}");
        assert!(debug.contains("certificate_present: true"));
        assert!(debug.contains("private_key_present: true"));
        assert!(!debug.contains("BEGIN"));
        assert!(
            SamlSpCredentials::try_new(
                pem("CERTIFICATE", TEST_CERT_DER),
                pem("PRIVATE KEY", b"not-a-key"),
            )
            .is_err()
        );
        let mut trailing_cert = TEST_CERT_DER.to_vec();
        trailing_cert.push(0);
        assert!(
            SamlSpCredentials::try_new(
                pem("CERTIFICATE", &trailing_cert),
                pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
            )
            .is_err()
        );
        assert!(
            SamlSpCredentials::try_new(
                vec![b' '; MAX_SP_CREDENTIAL_BYTES + 1],
                pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
            )
            .is_err()
        );
    }

    #[test]
    fn sp_credentials_reject_nonzero_subject_public_key_unused_bits() {
        let (_, certificate) = parse_x509_certificate(TEST_CERT_DER).expect("certificate");
        let subject_key = certificate
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;
        let subject_key = subject_key.as_ref();
        let data_offset = TEST_CERT_DER
            .windows(subject_key.len())
            .position(|window| window == subject_key)
            .expect("subject public key bytes")
            .checked_sub(1)
            .expect("unused-bits byte");
        let mut malformed = TEST_CERT_DER.to_vec();
        malformed[data_offset] = 1;
        assert!(
            SamlSpCredentials::try_new(
                pem("CERTIFICATE", &malformed),
                pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
            )
            .is_err()
        );
    }

    #[test]
    fn credential_authn_request_is_redirect_signed_and_metadata_advertises_keys() {
        let credentials = SamlSpCredentials::try_new(
            pem("CERTIFICATE", TEST_CERT_DER),
            pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
        )
        .expect("test certificate and key match");
        let mut client = mk_client(None);
        client.sp_credentials = Some(credentials);
        let (url, _) = client
            .authn_request_url("relay")
            .expect("signed authn request");
        let parsed = url::Url::parse(&url).expect("url");
        assert!(parsed.query_pairs().any(|(key, _)| key == "Signature"));
        assert!(parsed.query_pairs().any(|(key, value)| {
            key == "SigAlg" && value == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        }));
        let metadata = client.sp_metadata();
        assert!(metadata.contains("AuthnRequestsSigned=\"true\""));
        assert!(metadata.contains("KeyDescriptor use=\"signing\""));
        assert!(metadata.contains("KeyDescriptor use=\"encryption\""));
        assert!(metadata.contains(XMLENC_RSA_OAEP));
        assert!(metadata.contains(XMLENC_AES256_GCM));
    }

    #[test]
    fn credential_redirect_signature_covers_exact_encoded_query_octets() {
        use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

        let credentials = SamlSpCredentials::try_new(
            pem("CERTIFICATE", TEST_CERT_DER),
            pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
        )
        .expect("test certificate and key match");
        let mut client = mk_client(None);
        client.sp_credentials = Some(credentials);
        client.sso_url = "https://idp.example.com/sso?existing=1".into();
        let public_key = parse_x509_certificate(TEST_CERT_DER)
            .expect("certificate")
            .1
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;
        let verifier = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key);
        for (relay, expected_keys) in [
            ("", vec!["SAMLRequest", "RelayState", "SigAlg"]),
            ("space value", vec!["SAMLRequest", "RelayState", "SigAlg"]),
            ("a&b+c/%", vec!["SAMLRequest", "RelayState", "SigAlg"]),
            ("日本語/é", vec!["SAMLRequest", "RelayState", "SigAlg"]),
        ] {
            let (url, _) = client.authn_request_url(relay).expect("signed request");
            let query = url.split_once('?').expect("query").1;
            let signed_query = format!(
                "SAMLRequest={}",
                query.split_once("SAMLRequest=").expect("SAMLRequest").1
            );
            let parts: Vec<&str> = signed_query.split('&').collect();
            let signed_keys = parts
                .iter()
                .filter_map(|part| part.split_once('=').map(|(key, _)| key))
                .filter(|key| *key != "Signature")
                .collect::<Vec<_>>();
            assert_eq!(signed_keys, expected_keys);
            assert!(!signed_keys.contains(&"existing"));
            let parsed = url::Url::parse(&url).expect("url");
            assert_eq!(
                parsed
                    .query_pairs()
                    .filter(|(key, _)| key == "existing")
                    .count(),
                1
            );
            let relay_values = parsed
                .query_pairs()
                .filter_map(|(key, value)| (key == "RelayState").then_some(value.into_owned()))
                .collect::<Vec<_>>();
            assert_eq!(relay_values, vec![relay.to_string()]);
            let signature = parts
                .iter()
                .find_map(|part| part.strip_prefix("Signature="))
                .expect("signature");
            let signed = parts
                .iter()
                .filter(|part| !part.starts_with("Signature="))
                .copied()
                .collect::<Vec<_>>()
                .join("&");
            let signature = base64::engine::general_purpose::STANDARD
                .decode(
                    urlencoding::decode(signature)
                        .expect("signature encoding")
                        .as_bytes(),
                )
                .expect("signature base64");
            verifier
                .verify(signed.as_bytes(), &signature)
                .expect("signature verifies");
        }
    }

    #[test]
    fn signed_encrypted_process_response_round_trips_claims() {
        use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
        use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey};

        let content_key = [7u8; 32];
        let nonce_bytes = [3u8; 12];
        let (signed, _) = signature::tests::process_response_identity_fixtures();
        let start = signed.find("<saml:Assertion").expect("assertion start");
        let end = signed[start..]
            .find("</saml:Assertion>")
            .map(|i| start + i + "</saml:Assertion>".len())
            .expect("assertion end");
        let mut encrypted_content = signed.as_bytes()[start..end].to_vec();
        let aes_key = UnboundKey::new(&AES_256_GCM, &content_key).expect("AES key");
        LessSafeKey::new(aes_key)
            .seal_in_place_append_tag(
                Nonce::try_assume_unique_for_key(&nonce_bytes).expect("nonce"),
                Aad::empty(),
                &mut encrypted_content,
            )
            .expect("seal");
        let private = PrivateDecryptingKey::from_pkcs8(TEST_KEY_PKCS8_DER).expect("RSA key");
        let public_der =
            AsDer::<PublicKeyX509Der>::as_der(&private.public_key()).expect("public key DER");
        let public = PublicEncryptingKey::from_der(public_der.as_ref()).expect("public key");
        let public = OaepPublicEncryptingKey::new(public).expect("OAEP key");
        let mut wrapped = vec![0; public.ciphertext_size()];
        let wrapped = public
            .encrypt(&OAEP_SHA256_MGF1SHA256, &content_key, &mut wrapped, None)
            .expect("wrap");
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(wrapped);
        let mut data = nonce_bytes.to_vec();
        data.extend_from_slice(&encrypted_content);
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let encrypted = format!(
            r#"<saml:EncryptedAssertion ID="_a1"><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="{XMLENC_AES256_GCM}"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="{XMLENC_RSA_OAEP}"><ds:DigestMethod Algorithm="{XMLENC_SHA256}"/><xenc11:MGF Algorithm="{XMLENC_MGF1_SHA256}"/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>{key_b64}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{data_b64}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>"#
        );
        let prefix = signed[..start].replacen(
            "<samlp:Response",
            "<samlp:Response xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
            1,
        );
        let response = prefix + &encrypted + &signed[end..];
        let credentials = SamlSpCredentials::try_new(
            pem("CERTIFICATE", TEST_CERT_DER),
            pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
        )
        .expect("credentials");
        let mut client = mk_client(None);
        client.sp_credentials = Some(credentials);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&response);
        let user = client
            .process_response(&encoded, Some("_req1"))
            .expect("public encrypted response");
        assert_eq!(user.email, "alice@example.com");
    }

    #[test]
    fn encrypted_structure_rejects_validly_formed_duplicates_and_mixed_shapes() {
        let (client, response, _, _) = encrypted_public_fixture();
        let reject_public = |variant: String| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(variant);
            let error = match client.process_response(&encoded, Some("_req1")) {
                Ok(_) => panic!("ambiguous encrypted structure must reject"),
                Err(error) => error,
            };
            assert_eq!(
                error.to_string(),
                "authentication failed: encrypted SAML assertion is invalid"
            );
            assert!(std::error::Error::source(&error).is_none());
        };
        let duplicate_public = response.replacen(
            "</xenc:EncryptedData>",
            "</xenc:EncryptedData><xenc:EncryptedData><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/></xenc:EncryptedData>",
            1,
        );
        reject_public(duplicate_public);
        let assertion_end = response
            .find("</saml:EncryptedAssertion>")
            .expect("encrypted assertion end")
            + "</saml:EncryptedAssertion>".len();
        reject_public(format!(
            "{}{}{}",
            &response[..assertion_end],
            &response[response
                .find("<saml:EncryptedAssertion")
                .expect("encrypted start")..assertion_end],
            &response[assertion_end..]
        ));
        reject_public(response.replacen(
            "<saml:EncryptedAssertion",
            "<saml:Assertion ID=\"_plain\"/><saml:EncryptedAssertion",
            1,
        ));
        reject_public(response.replacen(
            "</saml:EncryptedAssertion>",
            "<evil:EncryptedAssertion xmlns:evil=\"urn:evil\"/></saml:EncryptedAssertion>",
            1,
        ));
    }

    #[test]
    fn encrypted_bounds_reach_size_boundary() {
        let exact_b64 = base64::engine::general_purpose::STANDARD
            .encode(vec![0x5a; MAX_ENCRYPTED_CIPHERTEXT_BYTES]);
        let exact_xml = format!(
            r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:CipherData><xenc:CipherValue>{exact_b64}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#
        );
        let exact = c14n::parse_xml_tree(&exact_xml).expect("exact boundary XML shape");
        let exact_context = namespace_context(&exact, &HashMap::new());
        let exact_value = cipher_value(&exact, &exact_context).expect("exact limit accepted");
        assert_eq!(exact_value.len(), MAX_ENCRYPTED_CIPHERTEXT_BYTES);

        let oversized = format!(
            r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"#,
            "A".repeat(MAX_ENCRYPTED_CIPHERTEXT_BYTES * 2)
        );
        let oversized = c14n::parse_xml_tree(&oversized).expect("oversized XML shape");
        let oversized_context = namespace_context(&oversized, &HashMap::new());
        assert!(cipher_value(&oversized, &oversized_context).is_err());

        let (client, response, _, _) = encrypted_public_fixture();
        let too_large = base64::engine::general_purpose::STANDARD.encode(vec![
            0x5a;
            MAX_ENCRYPTED_CIPHERTEXT_BYTES
                + 1
        ]);
        let end = response
            .rfind("</xenc:CipherValue>")
            .expect("data cipher end");
        let start = response[..end]
            .rfind("<xenc:CipherValue>")
            .expect("data cipher start")
            + "<xenc:CipherValue>".len();
        let mut public_oversized = response;
        public_oversized.replace_range(start..end, &too_large);
        let encoded = base64::engine::general_purpose::STANDARD.encode(public_oversized);
        let error = match client.process_response(&encoded, Some("_req1")) {
            Ok(_) => panic!("ciphertext above the limit must reject"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "authentication failed: encrypted SAML assertion is invalid"
        );
        assert!(std::error::Error::source(&error).is_none());

        let nested = c14n::parse_xml_tree(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:EncryptedAssertion/></saml:Subject></saml:Assertion>"#,
        )
        .expect("nested assertion shape");
        assert!(contains_element(&nested, "EncryptedAssertion"));
    }

    #[test]
    fn encrypted_response_public_errors_are_fixed_and_redacted() {
        let credentials = SamlSpCredentials::try_new(
            pem("CERTIFICATE", TEST_CERT_DER),
            pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
        )
        .expect("test credentials");
        let mut client = mk_client(None);
        client.sp_credentials = Some(credentials);
        let response = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><evil:EncryptedAssertion xmlns:evil="urn:evil"/></samlp:Response>"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(response);
        let error = match client.process_response(&encoded, Some("_req1")) {
            Ok(_) => panic!("reject shape"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "authentication failed: encrypted SAML assertion is invalid"
        );
        assert!(std::error::Error::source(&error).is_none());
        assert!(!format!("{error:?}").contains("urn:evil"));
    }

    #[test]
    fn encrypted_failures_share_one_public_error_across_all_stages() {
        use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
        use aws_lc_rs::rsa::{KeySize, OaepPublicEncryptingKey, PublicEncryptingKey};
        let (client, response, data_b64, plaintext) = encrypted_public_fixture();
        let mut tampered_data = base64::engine::general_purpose::STANDARD
            .decode(&data_b64)
            .expect("valid data cipher");
        let last = tampered_data.len() - 1;
        tampered_data[last] ^= 1;
        let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(tampered_data);
        let tampered = replace_data_cipher_value(&response, &tampered_b64);
        let malformed = reencrypt_fixture_plaintext(&response, b"<saml:Assertion");
        let signature_bad = reencrypt_fixture_plaintext(
            &response,
            plaintext
                .replacen("<ds:SignatureValue>", "<ds:SignatureValue>A", 1)
                .as_bytes(),
        );
        let digest_bad = reencrypt_fixture_plaintext(
            &response,
            plaintext
                .replacen("<ds:DigestValue>", "<ds:DigestValue>A", 1)
                .as_bytes(),
        );
        let second = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("second RSA key");
        let second_der =
            AsDer::<PublicKeyX509Der>::as_der(&second.public_key()).expect("second public key");
        let second_public = OaepPublicEncryptingKey::new(
            PublicEncryptingKey::from_der(second_der.as_ref()).expect("second public"),
        )
        .expect("second OAEP");
        let mut wrong_wrapped = vec![0; second_public.ciphertext_size()];
        let wrong_wrapped = second_public
            .encrypt(
                &OAEP_SHA256_MGF1SHA256,
                &[7u8; 32],
                &mut wrong_wrapped,
                None,
            )
            .expect("second wrap");
        let wrong_key = replace_first_cipher_value(
            &response,
            &base64::engine::general_purpose::STANDARD.encode(wrong_wrapped),
        );
        for response in [
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"><samlp:EncryptedAssertion/></samlp:Response>",
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"><evil:EncryptedAssertion xmlns:evil=\"urn:evil\"/></samlp:Response>",
            tampered.as_str(),
            malformed.as_str(),
            signature_bad.as_str(),
            digest_bad.as_str(),
            wrong_key.as_str(),
        ] {
            let encoded = base64::engine::general_purpose::STANDARD.encode(response);
            let error = match client.process_response(&encoded, Some("_req1")) {
                Ok(_) => panic!("reject"),
                Err(error) => error,
            };
            assert_eq!(
                error.to_string(),
                "authentication failed: encrypted SAML assertion is invalid"
            );
            assert!(std::error::Error::source(&error).is_none());
            assert_eq!(
                format!("{error:?}"),
                "AuthenticationFailed(\"encrypted SAML assertion is invalid\")"
            );
        }
        let mut semantic_client = client;
        semantic_client.acs_url = "https://other.example/saml/acs".into();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&response);
        let error = match semantic_client.process_response(&encoded, Some("_req1")) {
            Ok(_) => panic!("semantic mismatch must reject"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "authentication failed: encrypted SAML assertion is invalid"
        );
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(
            format!("{error:?}"),
            "AuthenticationFailed(\"encrypted SAML assertion is invalid\")"
        );
    }

    #[test]
    fn credentialed_plaintext_literal_encrypted_assertion_remains_valid() {
        let valid = signature::tests::process_response_identity_fixture_with_literal();
        let credentials = SamlSpCredentials::try_new(
            pem("CERTIFICATE", TEST_CERT_DER),
            pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
        )
        .expect("validated credentials");
        let mut client = mk_client(None);
        client.sp_credentials = Some(credentials);
        let encoded = base64::engine::general_purpose::STANDARD.encode(valid);
        let user = client
            .process_response(&encoded, Some("_req1"))
            .expect("plaintext response");
        assert_eq!(user.email, "literal EncryptedAssertion text");
        assert!(
            user.claims
                .values()
                .any(|value| value == "literal EncryptedAssertion text")
        );
    }

    #[test]
    fn encryption_namespaces_are_exact_and_child_local_declarations_work() {
        let (client, response, _, _) = encrypted_public_fixture();
        let local = response
            .replace(" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"", "")
            .replace(" xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\"", "")
            .replace(
                "<xenc:EncryptedData>",
                "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">",
            )
            .replace(
                "<ds:KeyInfo>",
                "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">",
            )
            .replace(
                "<xenc:EncryptedKey>",
                "<xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">",
            )
            .replace(
                "<ds:DigestMethod",
                "<ds:DigestMethod xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
            )
            .replace(
                "<xenc11:MGF",
                "<xenc11:MGF xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\"",
            );
        let encoded = base64::engine::general_purpose::STANDARD.encode(&local);
        client
            .process_response(&encoded, Some("_req1"))
            .expect("child-local declarations");
        let ancestor = response
            .replace(" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"", "")
            .replace(" xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\"", "")
            .replace(
                "<saml:EncryptedAssertion ID=\"_a1\">",
                "<saml:EncryptedAssertion ID=\"_a1\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\">",
            );
        let encoded = base64::engine::general_purpose::STANDARD.encode(&ancestor);
        client
            .process_response(&encoded, Some("_req1"))
            .expect("ancestor declarations");
        let spoof = local.replacen(
            "xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"",
            "xmlns:xenc=\"urn:spoof\"",
            1,
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(spoof);
        let error = match client.process_response(&encoded, Some("_req1")) {
            Ok(_) => panic!("spoof namespace"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "authentication failed: encrypted SAML assertion is invalid"
        );
        let correct_signed =
            signature::tests::process_response_identity_fixture_with_assertion_namespace(
                NS_ASSERTION,
            );
        let correct_start = correct_signed
            .find("<saml:Assertion")
            .expect("correct assertion start");
        let correct_end = correct_signed[correct_start..]
            .find("</saml:Assertion>")
            .map(|i| correct_start + i + "</saml:Assertion>".len())
            .expect("correct assertion end");
        let correct_response = reencrypt_fixture_plaintext(
            &response,
            &correct_signed.as_bytes()[correct_start..correct_end],
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(correct_response);
        let user = client
            .process_response(&encoded, Some("_req1"))
            .expect("correct Assertion namespace");
        assert_eq!(user.email, "alice@example.com");

        let wrong_signed =
            signature::tests::process_response_identity_fixture_with_assertion_namespace(
                "urn:wrong-assertion",
            );
        let wrong_start = wrong_signed
            .find("<saml:Assertion")
            .expect("wrong assertion start");
        let wrong_end = wrong_signed[wrong_start..]
            .find("</saml:Assertion>")
            .map(|i| wrong_start + i + "</saml:Assertion>".len())
            .expect("wrong assertion end");
        let wrong_response = reencrypt_fixture_plaintext(
            &response,
            &wrong_signed.as_bytes()[wrong_start..wrong_end],
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(wrong_response);
        let error = match client.process_response(&encoded, Some("_req1")) {
            Ok(_) => panic!("wrong decrypted Assertion namespace"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "authentication failed: encrypted SAML assertion is invalid"
        );
    }

    #[test]
    fn oaep_params_accepts_absent_or_whitespace_empty_only_in_key_method() {
        let (client, response, _, _) = encrypted_public_fixture();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&response);
        client
            .process_response(&encoded, Some("_req1"))
            .expect("absent OAEPparams");
        let whitespace = response.replacen(
            "</xenc:EncryptionMethod><xenc:CipherData>",
            "<xenc:OAEPparams> \t</xenc:OAEPparams></xenc:EncryptionMethod><xenc:CipherData>",
            1,
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(whitespace);
        client
            .process_response(&encoded, Some("_req1"))
            .expect("whitespace OAEPparams");
        let reject_public = |label: &str, variant: String| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(variant);
            let error = match client.process_response(&encoded, Some("_req1")) {
                Ok(_) => panic!("invalid OAEPparams must reject: {label}"),
                Err(error) => error,
            };
            assert_eq!(
                error.to_string(),
                "authentication failed: encrypted SAML assertion is invalid"
            );
            assert!(std::error::Error::source(&error).is_none());
        };
        reject_public("misplaced", response.replacen(
            "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/>",
            "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"><xenc:OAEPparams> </xenc:OAEPparams></xenc:EncryptionMethod>",
            1,
        ));
        let duplicate = response.replacen(
            "<xenc11:MGF Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/>",
            "<xenc11:MGF Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/><xenc:OAEPparams></xenc:OAEPparams><xenc:OAEPparams></xenc:OAEPparams>",
            1,
        );
        reject_public("duplicate", duplicate);
        reject_public("nested", response.replacen(
            "<xenc11:MGF Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/>",
            "<xenc11:MGF Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/><xenc:OAEPparams><xenc:Nested/></xenc:OAEPparams>",
            1,
        ));
        reject_public("pi", response.replacen(
            "<xenc11:MGF Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/>",
            "<xenc11:MGF Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/><xenc:OAEPparams><?pi?></xenc:OAEPparams>",
            1,
        ));
        let method = c14n::parse_xml_tree(
            r#"<xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><xenc11:MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/><xenc:OAEPparams>  </xenc:OAEPparams></xenc:EncryptionMethod>"#,
        ).expect("OAEPparams fixture");
        require_key_method_children(&method, &HashMap::new()).expect("empty OAEPparams allowed");
        let nonempty = c14n::parse_xml_tree(
            r#"<xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><xenc11:MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/><xenc:OAEPparams>x</xenc:OAEPparams></xenc:EncryptionMethod>"#,
        ).expect("nonempty OAEPparams fixture");
        assert!(require_key_method_children(&nonempty, &HashMap::new()).is_err());
    }

    #[test]
    fn metadata_advertises_exact_encryption_suite_structure() {
        let credentials = SamlSpCredentials::try_new(
            pem("CERTIFICATE", TEST_CERT_DER),
            pem("PRIVATE KEY", TEST_KEY_PKCS8_DER),
        )
        .expect("credentials");
        let mut client = mk_client(None);
        client.sp_credentials = Some(credentials);
        let metadata = client.sp_metadata();
        assert!(metadata.contains("xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\""));
        let parsed = c14n::parse_xml_tree(&metadata).expect("metadata XML");
        assert!(contains_element(&parsed, "EncryptionMethod"));
        assert_eq!(metadata.matches(XMLENC_RSA_OAEP).count(), 1);
        assert_eq!(metadata.matches(XMLENC_AES256_GCM).count(), 1);
        fn find_encryption(node: &c14n::XmlElement) -> Option<&c14n::XmlElement> {
            node.children.iter().find_map(|child| match child {
                c14n::XmlNode::Element(element)
                    if element.local_name == "KeyDescriptor"
                        && element
                            .attributes
                            .iter()
                            .any(|(_, name, value)| name == "use" && value == "encryption") =>
                {
                    Some(element)
                }
                c14n::XmlNode::Element(element) => find_encryption(element),
                _ => None,
            })
        }
        let encryption = find_encryption(&parsed).expect("encryption descriptor");
        let names = encryption
            .children
            .iter()
            .filter_map(|child| match child {
                c14n::XmlNode::Element(element) => Some((
                    element.local_name.as_str(),
                    element.prefix.as_str(),
                    element
                        .attributes
                        .iter()
                        .find(|(prefix, name, _)| prefix.is_empty() && name == "Algorithm")
                        .map(|(_, _, value)| value.as_str()),
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                ("KeyInfo", "ds", None),
                ("EncryptionMethod", "md", Some(XMLENC_RSA_OAEP)),
                ("EncryptionMethod", "md", Some(XMLENC_AES256_GCM)),
            ]
        );
    }
}
