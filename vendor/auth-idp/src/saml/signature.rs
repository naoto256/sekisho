//! SAML XML signature verification.
//!
//! Two independent cryptographic checks, both mandatory:
//!
//! 1. **SignedInfo signature** — `exc-c14n(ds:SignedInfo)` is verified against
//!    `ds:SignatureValue` using the IdP's public key. Proves *someone* with
//!    the private key authored the `<SignedInfo>` element.
//!
//! 2. **Reference digests** — for each `<ds:Reference URI="#id">` inside
//!    `<SignedInfo>`, resolve the referenced element by `@ID`, apply the
//!    declared transform chain (we accept only `enveloped-signature` +
//!    `exc-c14n`), compute the SHA-256 digest, and compare constant-time
//!    against `<ds:DigestValue>`. Proves the *content* of the referenced
//!    element matches what was signed.
//!
//! Skipping the second check would let an attacker keep a legitimate
//! `<SignedInfo>` intact while swapping the actual Assertion for one
//! they control — the classic XML Signature Wrapping (XSW) attack.
//! Defence-in-depth: we also reject Responses with more than one
//! Reference or more than one Assertion.

use super::c14n::{XmlElement, XmlNode, exclusive_c14n, parse_xml_tree};
use crate::error::{Error, Result};
use base64::Engine;
use std::collections::{HashMap, HashSet};

/// URIs we accept for each XML-DSig slot. SHA-1 is refused everywhere.
const SUPPORTED_DIGEST_METHOD: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const C14N_EXC_NO_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const C14N_EXC_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const TRANSFORM_ENVELOPED_SIG: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const NS_EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

fn require_namespace(
    namespaces: &super::NamespaceIndex,
    elem: &XmlElement,
    expected: &str,
    label: &str,
) -> Result<()> {
    if !namespaces.matches(elem, expected) {
        return Err(Error::AuthenticationFailed(format!(
            "SAML {label} namespace is invalid"
        )));
    }
    Ok(())
}

/// Proof that a login Response was parsed once and that its verified signature
/// is bound to the exact Assertion consumed by semantic validation.
pub(super) struct VerifiedLoginResponse {
    root: XmlElement,
    assertion_child_index: usize,
}

/// Proof that a POST-bound LogoutResponse was parsed once and that its
/// verified signature targets the exact root consumed by semantic validation.
pub(super) struct VerifiedLogoutResponse {
    root: XmlElement,
}

impl VerifiedLogoutResponse {
    pub(super) fn into_root(self) -> XmlElement {
        self.root
    }
}

impl VerifiedLoginResponse {
    pub(super) fn root(&self) -> &XmlElement {
        &self.root
    }

    pub(super) fn assertion(&self) -> &XmlElement {
        match &self.root.children[self.assertion_child_index] {
            XmlNode::Element(assertion) => assertion,
            _ => {
                unreachable!("verified Assertion child changed after construction")
            }
        }
    }

    #[cfg(test)]
    pub(super) fn assume_verified_for_test(root: XmlElement) -> Result<Self> {
        let namespaces = super::NamespaceIndex::new(&root);
        let assertion_child_index = login_assertion_child_index(&root, &namespaces)?;
        Ok(Self {
            root,
            assertion_child_index,
        })
    }
}

/// Parse and verify a login Response while binding the signature target to the
/// exact direct-child Assertion returned to semantic validation.
pub(super) fn verify_login_response(
    xml: &str,
    cert_ders: &[Vec<u8>],
) -> Result<VerifiedLoginResponse> {
    if cert_ders.is_empty() {
        return Err(Error::AuthenticationFailed(
            "no IdP certificates available for signature verification".into(),
        ));
    }

    let root = parse_xml_tree(xml)?;
    let namespaces = super::NamespaceIndex::new(&root);
    if root.local_name != "Response" || !namespaces.matches(&root, super::NS_PROTOCOL) {
        return Err(Error::AuthenticationFailed(format!(
            "SAML response root is {}, expected Response",
            root.local_name
        )));
    }

    let assertion_child_index = login_assertion_child_index(&root, &namespaces)?;
    let assertion = match &root.children[assertion_child_index] {
        XmlNode::Element(assertion) => assertion,
        _ => unreachable!("Assertion index was validated above"),
    };
    let id_map = build_unique_id_map(&root)?;
    let signatures = find_descendants_in_namespace(&root, "Signature", super::NS_DS, &namespaces);
    let signature = match signatures.as_slice() {
        [single] => *single,
        [] => {
            return Err(Error::AuthenticationFailed(
                "SAML response missing ds:Signature element".into(),
            ));
        }
        _ => {
            return Err(Error::AuthenticationFailed(
                "SAML response contains ambiguous ds:Signature elements".into(),
            ));
        }
    };

    let signed_info =
        find_direct_child_in_namespace(signature, "SignedInfo", super::NS_DS, &namespaces)
            .ok_or_else(|| {
                Error::AuthenticationFailed("SAML response missing ds:SignedInfo element".into())
            })?;
    let references =
        find_direct_children_in_namespace(signed_info, "Reference", super::NS_DS, &namespaces);
    let reference = match references.as_slice() {
        [single] => *single,
        [] => {
            return Err(Error::AuthenticationFailed(
                "SAML SignedInfo has no Reference".into(),
            ));
        }
        _ => {
            return Err(Error::AuthenticationFailed(
                "SAML SignedInfo has multiple References; only one is supported".into(),
            ));
        }
    };
    let reference_uri = get_attr(reference, "URI")
        .and_then(|uri| uri.strip_prefix('#'))
        .ok_or_else(|| {
            Error::AuthenticationFailed(
                "SAML Reference must be a same-document ID reference".into(),
            )
        })?;
    let signed_target = id_map.get(reference_uri).copied().ok_or_else(|| {
        Error::AuthenticationFailed(
            "SAML Reference does not resolve to an ID in the document".into(),
        )
    })?;
    if !std::ptr::eq(signed_target, &root) && !std::ptr::eq(signed_target, assertion) {
        return Err(Error::AuthenticationFailed(
            "SAML signature does not target the Response or consumed Assertion".into(),
        ));
    }

    let target_signatures =
        find_direct_children_in_namespace(signed_target, "Signature", super::NS_DS, &namespaces);
    if target_signatures.len() != 1 || !std::ptr::eq(target_signatures[0], signature) {
        return Err(Error::AuthenticationFailed(
            "SAML enveloped Signature must be the sole direct child of its signed target".into(),
        ));
    }

    verify_parsed_saml_signature(&root, &namespaces, cert_ders, signature, &id_map)?;
    Ok(VerifiedLoginResponse {
        root,
        assertion_child_index,
    })
}

/// Parse and verify a POST-bound LogoutResponse while binding its embedded
/// signature to the exact root returned to semantic validation.
pub(super) fn verify_logout_response(
    xml: &str,
    cert_ders: &[Vec<u8>],
) -> Result<VerifiedLogoutResponse> {
    if cert_ders.is_empty() {
        return Err(Error::AuthenticationFailed(
            "no IdP certificates available for signature verification".into(),
        ));
    }

    let root = parse_xml_tree(xml)?;
    verify_logout_response_root(root, cert_ders)
}

/// Shared body of LogoutResponse verification. Called on the
/// production path by `verify_logout_response` and on the test-only
/// compatibility path by `verify_saml_signature`.
fn verify_logout_response_root(
    root: XmlElement,
    cert_ders: &[Vec<u8>],
) -> Result<VerifiedLogoutResponse> {
    let namespaces = super::NamespaceIndex::new(&root);
    if root.local_name != "LogoutResponse" || !namespaces.matches(&root, super::NS_PROTOCOL) {
        return Err(Error::AuthenticationFailed(format!(
            "SAML response root is {}, expected LogoutResponse",
            root.local_name
        )));
    }

    let root_id = get_attr(&root, "ID")
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            Error::AuthenticationFailed("SAML LogoutResponse root is missing ID".into())
        })?;
    let id_map = build_unique_id_map(&root)?;
    let signatures = find_descendants_in_namespace(&root, "Signature", super::NS_DS, &namespaces);
    let signature = match signatures.as_slice() {
        [single] => *single,
        [] => {
            return Err(Error::AuthenticationFailed(
                "SAML LogoutResponse missing ds:Signature element".into(),
            ));
        }
        _ => {
            return Err(Error::AuthenticationFailed(
                "SAML LogoutResponse contains ambiguous ds:Signature elements".into(),
            ));
        }
    };

    let signed_info =
        find_direct_child_in_namespace(signature, "SignedInfo", super::NS_DS, &namespaces)
            .ok_or_else(|| {
                Error::AuthenticationFailed("SAML response missing ds:SignedInfo element".into())
            })?;
    let references =
        find_direct_children_in_namespace(signed_info, "Reference", super::NS_DS, &namespaces);
    let reference = match references.as_slice() {
        [single] => *single,
        [] => {
            return Err(Error::AuthenticationFailed(
                "SAML SignedInfo has no Reference".into(),
            ));
        }
        _ => {
            return Err(Error::AuthenticationFailed(
                "SAML SignedInfo has multiple References; only one is supported".into(),
            ));
        }
    };
    let reference_id = get_attr(reference, "URI")
        .and_then(|uri| uri.strip_prefix('#'))
        .ok_or_else(|| {
            Error::AuthenticationFailed(
                "SAML Reference must be a same-document ID reference".into(),
            )
        })?;
    if reference_id != root_id {
        return Err(Error::AuthenticationFailed(
            "SAML LogoutResponse signature does not target the response root".into(),
        ));
    }
    let signed_target = id_map.get(reference_id).copied().ok_or_else(|| {
        Error::AuthenticationFailed(
            "SAML Reference does not resolve to an ID in the document".into(),
        )
    })?;
    if !std::ptr::eq(signed_target, &root) {
        return Err(Error::AuthenticationFailed(
            "SAML LogoutResponse signature does not target the response root".into(),
        ));
    }

    let target_signatures =
        find_direct_children_in_namespace(&root, "Signature", super::NS_DS, &namespaces);
    if target_signatures.len() != 1 || !std::ptr::eq(target_signatures[0], signature) {
        return Err(Error::AuthenticationFailed(
            "SAML LogoutResponse Signature must be the sole direct Signature child".into(),
        ));
    }

    verify_parsed_saml_signature(&root, &namespaces, cert_ders, signature, &id_map)?;
    Ok(VerifiedLogoutResponse { root })
}

/// Test-only compatibility verifier retained for the legacy SAML
/// fixture corpus. Production callers use `verify_login_response` /
/// `verify_logout_response`, which return proof types that bind the
/// signature target to the exact element consumed by semantic
/// validation. This docstring is the group boundary marker for the
/// related test-only helpers (`build_id_map`, `walk_ids`,
/// `verify_legacy_assertion_coverage`); those helpers do not carry
/// individual docs.
///
/// Verify the SAML Response XML signature.
///
/// Fails (with a specific error message) if any of the following are wrong:
///
///   - SignedInfo is missing or malformed.
///   - SignatureMethod is SHA-1 or otherwise unsupported.
///   - SignatureValue does not verify under any IdP cert.
///   - There is more than one `<ds:Reference>` (rare in SAML and hides XSW).
///   - The Reference URI cannot be resolved to an `@ID`-identified element.
///   - The Transform chain contains an algorithm other than
///     enveloped-signature / exc-c14n.
///   - The computed digest differs from `<ds:DigestValue>`.
///   - There is more than one `<saml:Assertion>` in the document.
#[cfg(test)]
pub fn verify_saml_signature(xml: &str, cert_ders: &[Vec<u8>]) -> Result<()> {
    if cert_ders.is_empty() {
        return Err(Error::AuthenticationFailed(
            "no IdP certificates available for signature verification".into(),
        ));
    }

    let doc = parse_xml_tree(xml)?;
    if doc.local_name == "LogoutResponse" {
        return verify_logout_response_root(doc, cert_ders).map(drop);
    }

    let namespaces = super::NamespaceIndex::new(&doc);
    let signature = find_descendant_in_namespace(&doc, "Signature", super::NS_DS, &namespaces)
        .ok_or_else(|| {
            Error::AuthenticationFailed("SAML response missing ds:Signature element".into())
        })?;
    let assertion_count =
        count_descendants_in_namespace(&doc, "Assertion", super::NS_ASSERTION, &namespaces);
    if assertion_count > 1 {
        return Err(Error::AuthenticationFailed(format!(
            "SAML response contains {assertion_count} Assertion elements; only one is allowed"
        )));
    }

    let id_map = build_id_map(&doc);
    verify_parsed_saml_signature(&doc, &namespaces, cert_ders, signature, &id_map)?;
    verify_legacy_assertion_coverage(signature, &id_map, &namespaces)
}

#[cfg(test)]
fn verify_legacy_assertion_coverage(
    signature: &XmlElement,
    id_map: &HashMap<String, &XmlElement>,
    namespaces: &super::NamespaceIndex,
) -> Result<()> {
    let signed_info =
        find_direct_child_in_namespace(signature, "SignedInfo", super::NS_DS, namespaces)
            .ok_or_else(|| {
                Error::AuthenticationFailed("SAML response missing ds:SignedInfo element".into())
            })?;
    let references =
        find_direct_children_in_namespace(signed_info, "Reference", super::NS_DS, namespaces);
    let reference = references
        .first()
        .ok_or_else(|| Error::AuthenticationFailed("SAML SignedInfo has no Reference".into()))?;
    let ref_uri = get_attr(reference, "URI").unwrap_or("");
    let signed_id = ref_uri.strip_prefix('#').unwrap_or("");
    let signed_elem = id_map.get(signed_id).copied().ok_or_else(|| {
        Error::AuthenticationFailed(format!(
            "SAML Reference URI {ref_uri:?} does not resolve to an ID in the document"
        ))
    })?;
    let covers_assertion = signed_elem.local_name == "Response"
        || signed_elem.local_name == "Assertion"
        || find_descendant_in_namespace(signed_elem, "Assertion", super::NS_ASSERTION, namespaces)
            .is_some();
    if !covers_assertion {
        return Err(Error::AuthenticationFailed(format!(
            "SAML signature covers {:?} which does not contain an Assertion",
            signed_elem.local_name
        )));
    }
    Ok(())
}

fn verify_parsed_saml_signature(
    doc: &XmlElement,
    namespaces: &super::NamespaceIndex,
    cert_ders: &[Vec<u8>],
    signature: &XmlElement,
    id_map: &HashMap<String, &XmlElement>,
) -> Result<()> {
    require_namespace(namespaces, signature, super::NS_DS, "Signature")?;
    // Locate <ds:SignedInfo>, <ds:SignatureValue>, and gather all
    // <ds:Reference> entries that live inside that particular SignedInfo.
    let signed_info =
        find_direct_child_in_namespace(signature, "SignedInfo", super::NS_DS, namespaces)
            .ok_or_else(|| {
                Error::AuthenticationFailed("SAML response missing ds:SignedInfo element".into())
            })?;
    let sig_value_elem =
        find_direct_child_in_namespace(signature, "SignatureValue", super::NS_DS, namespaces)
            .ok_or_else(|| {
                Error::AuthenticationFailed(
                    "SAML response missing ds:SignatureValue element".into(),
                )
            })?;

    // --- Reference digest checks ---
    let references =
        find_direct_children_in_namespace(signed_info, "Reference", super::NS_DS, namespaces);
    match references.len() {
        0 => {
            return Err(Error::AuthenticationFailed(
                "SAML SignedInfo has no Reference".into(),
            ));
        }
        1 => {}
        n => {
            // Multiple References are legal in XML-DSig but vanishingly rare
            // in SAML; accepting them widens the attack surface for little
            // real-world gain, so we refuse.
            return Err(Error::AuthenticationFailed(format!(
                "SAML SignedInfo has {n} References; only one is supported"
            )));
        }
    }
    let reference = references[0];

    verify_reference(doc, namespaces, reference, signature, id_map)?;

    // --- CanonicalizationMethod ---
    // We canonicalize SignedInfo with exclusive c14n (no comments) below.
    // If the IdP declared a different method, the bytes we hash will not
    // match what the IdP signed and verification would silently fail —
    // but the actual mismatch is a policy question, not an
    // arithmetic one. Refuse anything we do not implement so the caller
    // gets a clear error instead of a generic "verification failed".
    let c14n_method = find_direct_child_in_namespace(
        signed_info,
        "CanonicalizationMethod",
        super::NS_DS,
        namespaces,
    )
    .ok_or_else(|| {
        Error::AuthenticationFailed("SAML SignedInfo missing CanonicalizationMethod".into())
    })?;
    let c14n_alg = Some(c14n_method)
        .and_then(|e| get_attr(e, "Algorithm").map(|s| s.to_string()))
        .ok_or_else(|| {
            Error::AuthenticationFailed("SAML SignedInfo missing CanonicalizationMethod".into())
        })?;
    if c14n_alg != C14N_EXC_NO_COMMENTS {
        return Err(Error::AuthenticationFailed(format!(
            "SAML SignedInfo declares unsupported CanonicalizationMethod {c14n_alg:?}; \
             only {C14N_EXC_NO_COMMENTS} is implemented"
        )));
    }

    // --- SignedInfo signature ---
    let signature_method =
        find_direct_child_in_namespace(signed_info, "SignatureMethod", super::NS_DS, namespaces)
            .ok_or_else(|| {
                Error::AuthenticationFailed("SAML SignedInfo missing SignatureMethod".into())
            })?;
    let sig_alg = Some(signature_method)
        .and_then(|e| get_attr(e, "Algorithm").map(|s| s.to_string()))
        .ok_or_else(|| {
            Error::AuthenticationFailed("SAML SignedInfo missing SignatureMethod".into())
        })?;
    let algorithm = ring_algorithm_for(&sig_alg)?;

    let sig_value_b64 = text_content(sig_value_elem);
    let clean_sig: String = sig_value_b64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&clean_sig)
        .map_err(|e| {
            Error::AuthenticationFailed(format!("SignatureValue base64 decode failed: {e}"))
        })?;

    // Build the ancestor-namespace context for SignedInfo — c14n requires it.
    let ancestor_ns = ancestor_namespaces(doc, signed_info);
    let canonical = exclusive_c14n(signed_info, &ancestor_ns);

    verify_signature_bytes(
        &canonical,
        &signature_bytes,
        &sig_alg,
        algorithm,
        cert_ders,
        "SAML signature",
    )
}

/// Verify the detached signature used by the SAML HTTP-Redirect binding.
///
/// The HTTP-Redirect binding signs the URL-encoded query string rather
/// than an XML sub-tree: the IdP builds the string
/// `<message_param>=<value>&RelayState=<value>&SigAlg=<uri>` (RelayState
/// omitted when absent), signs it, and appends `&Signature=<base64>`.
/// The signed bytes are exactly the octets the IdP produced, so the
/// caller MUST pass the raw query string as delivered by the browser —
/// re-encoding the parameters changes the bytes and breaks verification.
///
/// - `raw_query` — the exact raw query string of the request URL.
/// - `message_param` — `"SAMLRequest"` or `"SAMLResponse"` depending on
///   the direction of the message being verified.
/// - `expected_message_value` — the decoded payload the caller has
///   already processed. Refusing to verify when the two disagree closes
///   the "sign one payload, deliver another" attack.
/// - `cert_ders` — the pinned IdP public certificates.
pub fn verify_redirect_binding_signature(
    raw_query: &str,
    message_param: &str,
    expected_message_value: &str,
    cert_ders: &[Vec<u8>],
) -> Result<()> {
    if cert_ders.is_empty() {
        return Err(Error::AuthenticationFailed(
            "no IdP certificates available for signature verification".into(),
        ));
    }

    if !matches!(message_param, "SAMLRequest" | "SAMLResponse") {
        return Err(Error::AuthenticationFailed(format!(
            "unsupported SAML Redirect binding message parameter {message_param:?}"
        )));
    }

    let params = RedirectBindingParams::parse(raw_query)?;

    let message = params.protected(message_param)?;
    let sig_alg = params.protected("SigAlg")?;
    let signature = params.protected("Signature")?;
    let relay_state = params.get("RelayState");

    let message_value = decode_query_value(message)?;
    if message_value != expected_message_value {
        return Err(Error::AuthenticationFailed(format!(
            "SAML Redirect binding {message_param} does not match the processed payload"
        )));
    }

    let signed_input = match relay_state {
        Some(relay_state) => format!("{message}&{relay_state}&{sig_alg}"),
        None => format!("{message}&{sig_alg}"),
    };
    let sig_alg_value = decode_query_value(sig_alg)?;
    let algorithm = ring_algorithm_for(&sig_alg_value)?;
    let signature_value = decode_query_value(signature)?;
    let clean_sig: String = signature_value
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&clean_sig)
        .map_err(|e| {
            Error::AuthenticationFailed(format!("Redirect-binding Signature decode failed: {e}"))
        })?;

    verify_signature_bytes(
        signed_input.as_bytes(),
        &signature_bytes,
        &sig_alg_value,
        algorithm,
        cert_ders,
        "SAML Redirect-binding signature",
    )
}

fn verify_signature_bytes(
    signed_input: &[u8],
    signature_bytes: &[u8],
    sig_alg: &str,
    algorithm: &'static dyn ring::signature::VerificationAlgorithm,
    cert_ders: &[Vec<u8>],
    context: &str,
) -> Result<()> {
    use ring::signature as ring_sig;
    let mut last_err: Option<ring::error::Unspecified> = None;
    for (idx, cert_der) in cert_ders.iter().enumerate() {
        let Some(spki) = extract_spki_from_x509(cert_der) else {
            tracing::debug!(cert_index = idx, "skipping cert: SPKI extraction failed");
            continue;
        };
        let public_key = ring_sig::UnparsedPublicKey::new(algorithm, spki);
        match public_key.verify(signed_input, signature_bytes) {
            Ok(()) => {
                tracing::debug!(cert_index = idx, algorithm = sig_alg, "{context} verified");
                return Ok(());
            }
            Err(e) => {
                tracing::trace!(cert_index = idx, error = %e, "cert did not verify, trying next");
                last_err = Some(e);
            }
        }
    }

    tracing::warn!(
        certs_tried = cert_ders.len(),
        algorithm = sig_alg,
        last_error = ?last_err,
        "{context} verification failed against all IdP certificates"
    );
    Err(Error::AuthenticationFailed(format!(
        "{context} verification failed: tried {} certificate(s) with {sig_alg}",
        cert_ders.len()
    )))
}

/// SAML Redirect binding query parameters we canonicalize into the
/// signed input. Every other name is silently ignored by the parser
/// (callers may hang extra parameters off the URL without invalidating
/// the signature), but every parameter that DECODES to one of these
/// names must appear in canonical raw form — otherwise we refuse the
/// query. See [`RedirectBindingParams::parse`].
const PROTECTED_PARAMS: &[&str] = &[
    "SAMLRequest",
    "SAMLResponse",
    "RelayState",
    "SigAlg",
    "Signature",
];

/// Parsed Redirect-binding query parameters, restricted to the five
/// protected names. Storing raw `&str` segments (not decoded values)
/// preserves the exact octets the IdP signed; decoding happens later
/// only for values that need semantic checks.
#[derive(Debug)]
struct RedirectBindingParams<'a> {
    /// (canonical name, raw `name=value` segment) for every protected
    /// parameter that appeared in the query.
    entries: Vec<(&'static str, &'a str)>,
}

impl<'a> RedirectBindingParams<'a> {
    /// Walk `raw_query` once, applying fail-closed name canonicalisation:
    ///
    /// - A segment whose raw name is one of [`PROTECTED_PARAMS`] is
    ///   stored under that canonical name.
    /// - A segment whose raw name percent-decodes to a protected name
    ///   but is not itself equal to it (e.g. `Relay%53tate`,
    ///   `SAMLResp%6Fnse`) is refused. Any downstream caller-side parser
    ///   would treat it as a legitimate parameter and get a different
    ///   view of the query than the signature verifier had — closing
    ///   that gap is the whole point.
    /// - A protected name appearing more than once (in any form) is
    ///   refused for the same reason.
    /// - Non-protected names, and segments without an `=`, are ignored.
    fn parse(raw_query: &str) -> Result<RedirectBindingParams<'_>> {
        let mut entries: Vec<(&'static str, &str)> = Vec::new();
        for segment in raw_query.split('&') {
            let Some((raw_name, _)) = segment.split_once('=') else {
                continue;
            };
            let decoded_name = urlencoding::decode(raw_name).map_err(|e| {
                Error::AuthenticationFailed(format!(
                    "SAML Redirect binding query parameter name decode failed: {e}"
                ))
            })?;
            let Some(&canonical) = PROTECTED_PARAMS
                .iter()
                .find(|name| decoded_name.as_ref() == **name)
            else {
                continue;
            };
            if raw_name != canonical {
                return Err(Error::AuthenticationFailed(format!(
                    "SAML Redirect binding parameter {canonical:?} appears under \
                     non-canonical name {raw_name:?}; a downstream parser would \
                     see a different query than the signature verifier"
                )));
            }
            if entries.iter().any(|(name, _)| *name == canonical) {
                return Err(Error::AuthenticationFailed(format!(
                    "SAML Redirect binding contains duplicate {canonical} query parameters"
                )));
            }
            entries.push((canonical, segment));
        }
        Ok(RedirectBindingParams { entries })
    }

    /// Return the raw `name=value` segment for a protected parameter,
    /// or `None` if the query did not carry it. `name` MUST be one of
    /// [`PROTECTED_PARAMS`]; other names always return `None`.
    fn get(&self, name: &str) -> Option<&'a str> {
        self.entries
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, seg)| *seg)
    }

    /// Same as [`RedirectBindingParams::get`], but returns
    /// `AuthenticationFailed` when the query does not carry `name`. Used
    /// for parameters the SAML Redirect binding requires.
    fn protected(&self, name: &str) -> Result<&'a str> {
        self.get(name).ok_or_else(|| {
            Error::AuthenticationFailed(format!(
                "SAML Redirect binding missing {name} query parameter"
            ))
        })
    }
}

fn decode_query_value(segment: &str) -> Result<String> {
    let (_, encoded) = segment.split_once('=').ok_or_else(|| {
        Error::AuthenticationFailed("SAML Redirect binding query parameter has no value".into())
    })?;
    urlencoding::decode(encoded)
        .map(|value| value.into_owned())
        .map_err(|e| {
            Error::AuthenticationFailed(format!("SAML Redirect binding query decode failed: {e}"))
        })
}

fn ring_algorithm_for(uri: &str) -> Result<&'static dyn ring::signature::VerificationAlgorithm> {
    use ring::signature as ring_sig;
    match uri {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => {
            Ok(&ring_sig::RSA_PKCS1_2048_8192_SHA256)
        }
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => {
            Ok(&ring_sig::RSA_PKCS1_2048_8192_SHA384)
        }
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => {
            Ok(&ring_sig::RSA_PKCS1_2048_8192_SHA512)
        }
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Err(Error::AuthenticationFailed(
            "SAML response signed with insecure RSA-SHA1; refusing".into(),
        )),
        other => Err(Error::AuthenticationFailed(format!(
            "unsupported SAML SignatureMethod algorithm: {other}"
        ))),
    }
}

/// Verify a single `<ds:Reference>` against the element it points at.
/// Applies the declared transform chain and compares SHA-256 digests
/// constant-time.
fn verify_reference(
    doc: &XmlElement,
    namespaces: &super::NamespaceIndex,
    reference: &XmlElement,
    enclosing_signature: &XmlElement,
    id_map: &HashMap<String, &XmlElement>,
) -> Result<()> {
    require_namespace(namespaces, reference, super::NS_DS, "Reference")?;

    // --- DigestMethod ---
    let digest_method_elem =
        find_direct_child_in_namespace(reference, "DigestMethod", super::NS_DS, namespaces)
            .ok_or_else(|| Error::AuthenticationFailed("Reference missing DigestMethod".into()))?;
    let digest_method = Some(digest_method_elem)
        .and_then(|e| get_attr(e, "Algorithm").map(|s| s.to_string()))
        .ok_or_else(|| Error::AuthenticationFailed("Reference missing DigestMethod".into()))?;
    if digest_method != SUPPORTED_DIGEST_METHOD {
        return Err(Error::AuthenticationFailed(format!(
            "unsupported or insecure DigestMethod: {digest_method}"
        )));
    }

    // --- DigestValue ---
    let digest_value_elem =
        find_direct_child_in_namespace(reference, "DigestValue", super::NS_DS, namespaces)
            .ok_or_else(|| Error::AuthenticationFailed("Reference missing DigestValue".into()))?;
    let digest_value_b64 = text_content(digest_value_elem);
    let expected_digest: Vec<u8> = base64::engine::general_purpose::STANDARD
        .decode(
            digest_value_b64
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        )
        .map_err(|e| {
            Error::AuthenticationFailed(format!("DigestValue base64 decode failed: {e}"))
        })?;

    // --- Resolve URI -> element by ID ---
    // Only same-document references (`#id`) are supported. External URIs
    // would require a fetch, and neither the SAML profile nor our threat
    // model permits that.
    let uri = get_attr(reference, "URI")
        .ok_or_else(|| Error::AuthenticationFailed("Reference missing URI attribute".into()))?;
    let id = uri.strip_prefix('#').ok_or_else(|| {
        Error::AuthenticationFailed(format!(
            "Reference URI {uri:?} is not a same-document ID reference"
        ))
    })?;
    let referenced = id_map.get(id).copied().ok_or_else(|| {
        Error::AuthenticationFailed(format!(
            "Reference URI {uri:?} does not resolve to any @ID in the document"
        ))
    })?;

    // --- Transform chain ---
    // XMLDSIG requires transforms to run in document order and the final
    // stage to be a c14n producing the octets we hash. We accept exactly
    // two shapes:
    //
    //   [exc-c14n]                              -- reference points at a
    //                                              subtree that does not
    //                                              enclose the Signature
    //   [enveloped-signature, exc-c14n]         -- reference points at a
    //                                              subtree that encloses
    //                                              this Signature; strip
    //                                              it before c14n
    //
    // Anything else (reversed order, extra transforms, unknown algorithm,
    // exc-c14n#WithComments, no c14n at all) is refused. Silent reordering
    // would let a hostile IdP declare a chain that computes over a different
    // octet stream than we do — better to fail closed at parse time.
    let transforms =
        find_direct_child_in_namespace(reference, "Transforms", super::NS_DS, namespaces);
    let transform_list: Vec<&XmlElement> = match transforms {
        Some(t) => find_direct_children_in_namespace(t, "Transform", super::NS_DS, namespaces),
        None => Vec::new(),
    };

    let algs: Vec<&str> = transform_list
        .iter()
        .map(|tr| {
            get_attr(tr, "Algorithm")
                .ok_or_else(|| Error::AuthenticationFailed("Transform missing Algorithm".into()))
        })
        .collect::<Result<Vec<_>>>()?;

    let (enveloped, c14n_transform_idx) = match algs.as_slice() {
        [C14N_EXC_NO_COMMENTS] => (false, 0),
        [TRANSFORM_ENVELOPED_SIG, C14N_EXC_NO_COMMENTS] => (true, 1),
        // Explicit rejection for the WithComments variant so callers get
        // a specific error instead of the generic "unsupported chain".
        // Our canonicalizer drops comments; accepting the transform here
        // would hash a subtly different octet stream than the IdP declared.
        [.., C14N_EXC_WITH_COMMENTS] | [C14N_EXC_WITH_COMMENTS, ..] => {
            return Err(Error::AuthenticationFailed(
                "SAML Reference Transform declares exc-c14n#WithComments; \
                 only the no-comments variant is implemented"
                    .into(),
            ));
        }
        // exc-c14n before enveloped-signature is defined by the spec but
        // reverses the octet stream we would hash; refuse loudly rather
        // than silently canonicalize the pre-strip form.
        [C14N_EXC_NO_COMMENTS, TRANSFORM_ENVELOPED_SIG] => {
            return Err(Error::AuthenticationFailed(
                "SAML Reference Transforms declare c14n before enveloped-signature; \
                 only [enveloped-signature, exc-c14n] is accepted"
                    .into(),
            ));
        }
        [] => {
            return Err(Error::AuthenticationFailed(
                "SAML Reference does not declare an exclusive c14n transform".into(),
            ));
        }
        _ => {
            return Err(Error::AuthenticationFailed(format!(
                "unsupported SAML Reference Transform chain: {algs:?}"
            )));
        }
    };

    // Only the accepted c14n transform can carry <ec:InclusiveNamespaces>.
    let mut inclusive_prefixes: HashSet<String> = HashSet::new();
    if let Some(incl) = find_descendant_in_namespace(
        transform_list[c14n_transform_idx],
        "InclusiveNamespaces",
        NS_EXCLUSIVE_C14N,
        namespaces,
    ) && let Some(list) = get_attr(incl, "PrefixList")
    {
        for p in list.split_whitespace() {
            inclusive_prefixes.insert(p.to_string());
        }
    }

    // --- Apply transforms: clone the referenced element, optionally strip
    //     *this specific* Signature (identified by structural path from the
    //     referenced element, not by any forgeable text content), then c14n. ---
    let mut working = referenced.clone();
    if enveloped {
        // XMLDSIG defines the enveloped-signature transform as removing
        // "the Signature element containing the Transform" from the digest
        // input. Locate that specific element by pointer identity in the
        // *original* tree — that is the ground truth for "which Signature
        // declared this transform".
        //
        // Content-based matching (SignatureValue text, ID attribute, etc.)
        // is unsafe: those values are public within the document, so an
        // attacker can copy them into a second `<ds:Signature>` and cause
        // both to be stripped together, silently deleting attacker-injected
        // bytes from the digest input.
        match find_child_path(referenced, enclosing_signature) {
            Some(path) if !path.is_empty() && !remove_element_at_path(&mut working, &path) => {
                return Err(Error::AuthenticationFailed(
                    "enveloped-signature transform failed to locate target \
                     Signature in cloned working tree (internal consistency)"
                        .into(),
                ));
            }
            Some(path) if !path.is_empty() => {}
            Some(_) => {
                // referenced *is* the enclosing Signature — nonsensical: the
                // transform would remove the entire reference target.
                return Err(Error::AuthenticationFailed(
                    "enveloped-signature transform declared but the referenced \
                     element is the enclosing Signature itself"
                        .into(),
                ));
            }
            None => {
                // Enclosing Signature is outside the referenced subtree — a
                // common shape when the Reference URI resolves to an inner
                // element (e.g. a signed Assertion whose sibling Signature
                // lives on the Response). The transform is a no-op per spec
                // because there is nothing to remove from the digest input,
                // and no attack surface is opened: any Signature an attacker
                // injects inside the referenced subtree keeps its bytes in
                // the digest and forces a mismatch.
            }
        }
    }
    let ancestor_ns = ancestor_namespaces(doc, referenced);
    let canonical =
        super::c14n::exclusive_c14n_with_prefix_list(&working, &ancestor_ns, &inclusive_prefixes);

    // --- SHA-256 + constant-time compare. ---
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&canonical);
    let computed: [u8; 32] = h.finalize().into();

    if expected_digest.len() != computed.len() {
        return Err(Error::AuthenticationFailed(
            "SAML Reference DigestValue length mismatch".into(),
        ));
    }
    if !constant_time_eq(&expected_digest, &computed) {
        return Err(Error::AuthenticationFailed(
            "SAML Reference DigestValue does not match computed digest (possible XSW)".into(),
        ));
    }

    Ok(())
}

/// Byte-wise constant-time comparison. We avoid the `subtle` crate to keep
/// the dependency footprint small — 32 bytes of XOR-accumulate is trivially
/// constant-time without it.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Locate `target` inside `root`'s element subtree by pointer identity and
/// return the child-index path from `root` to `target` (empty path means
/// `root == target`). `None` means `target` is not in `root`'s subtree.
///
/// The tree is borrowed from the original parse so identity comparison is
/// meaningful — we resolve the path here, then apply it against a clone.
///
/// This is deliberately structural, not content-based, because the
/// enveloped-signature transform must remove the exact ancestor Signature
/// that owns the Reference. Content-based lookup (SignatureValue text, ID
/// attribute, etc.) is unsafe: those values are public within the document
/// and an attacker can copy them into a sibling `<ds:Signature>` to trick
/// content-based logic into stripping the sibling too — silently deleting
/// attacker-injected bytes from the digest input.
fn find_child_path(root: &XmlElement, target: &XmlElement) -> Option<Vec<usize>> {
    if std::ptr::eq(root, target) {
        return Some(Vec::new());
    }
    for (idx, child) in root.children.iter().enumerate() {
        if let XmlNode::Element(e) = child
            && let Some(mut sub) = find_child_path(e, target)
        {
            sub.insert(0, idx);
            return Some(sub);
        }
    }
    None
}

/// Remove the element at `path` (child indices from `root`). Non-empty
/// `path` is required; removing the root itself is refused. Returns `false`
/// if the path does not resolve to an element node — treat as a caller bug
/// / tampering signal.
fn remove_element_at_path(root: &mut XmlElement, path: &[usize]) -> bool {
    match path {
        [] => false,
        [idx] => {
            if root
                .children
                .get(*idx)
                .is_some_and(|c| matches!(c, XmlNode::Element(_)))
            {
                root.children.remove(*idx);
                true
            } else {
                false
            }
        }
        [head, rest @ ..] => match root.children.get_mut(*head) {
            Some(XmlNode::Element(child)) => remove_element_at_path(child, rest),
            _ => false,
        },
    }
}

// --- Tree helpers ---

fn get_attr<'a>(elem: &'a XmlElement, name: &str) -> Option<&'a str> {
    elem.attributes
        .iter()
        .find(|(_, local, _)| local == name)
        .map(|(_, _, value)| value.as_str())
}

#[cfg(test)]
fn find_direct_child<'a>(elem: &'a XmlElement, local: &str) -> Option<&'a XmlElement> {
    for child in &elem.children {
        if let XmlNode::Element(e) = child
            && e.local_name == local
        {
            return Some(e);
        }
    }
    None
}

#[cfg(test)]
fn find_direct_children<'a>(elem: &'a XmlElement, local: &str) -> Vec<&'a XmlElement> {
    elem.children
        .iter()
        .filter_map(|c| match c {
            XmlNode::Element(e) if e.local_name == local => Some(e),
            _ => None,
        })
        .collect()
}

fn find_direct_child_in_namespace<'a>(
    elem: &'a XmlElement,
    local: &str,
    namespace: &str,
    namespaces: &super::NamespaceIndex,
) -> Option<&'a XmlElement> {
    elem.children.iter().find_map(|child| match child {
        XmlNode::Element(child)
            if child.local_name == local && namespaces.matches(child, namespace) =>
        {
            Some(child)
        }
        _ => None,
    })
}

fn find_direct_children_in_namespace<'a>(
    elem: &'a XmlElement,
    local: &str,
    namespace: &str,
    namespaces: &super::NamespaceIndex,
) -> Vec<&'a XmlElement> {
    elem.children
        .iter()
        .filter_map(|child| match child {
            XmlNode::Element(child)
                if child.local_name == local && namespaces.matches(child, namespace) =>
            {
                Some(child)
            }
            _ => None,
        })
        .collect()
}

fn find_descendant_in_namespace<'a>(
    elem: &'a XmlElement,
    local: &str,
    namespace: &str,
    namespaces: &super::NamespaceIndex,
) -> Option<&'a XmlElement> {
    if elem.local_name == local && namespaces.matches(elem, namespace) {
        return Some(elem);
    }
    elem.children.iter().find_map(|child| match child {
        XmlNode::Element(child) => {
            find_descendant_in_namespace(child, local, namespace, namespaces)
        }
        _ => None,
    })
}

fn find_descendants_in_namespace<'a>(
    elem: &'a XmlElement,
    local: &str,
    namespace: &str,
    namespaces: &super::NamespaceIndex,
) -> Vec<&'a XmlElement> {
    let mut matches = Vec::new();
    collect_descendants_in_namespace(elem, local, namespace, namespaces, &mut matches);
    matches
}

fn collect_descendants_in_namespace<'a>(
    elem: &'a XmlElement,
    local: &str,
    namespace: &str,
    namespaces: &super::NamespaceIndex,
    matches: &mut Vec<&'a XmlElement>,
) {
    if elem.local_name == local && namespaces.matches(elem, namespace) {
        matches.push(elem);
    }
    for child in &elem.children {
        if let XmlNode::Element(child) = child {
            collect_descendants_in_namespace(child, local, namespace, namespaces, matches);
        }
    }
}

fn count_descendants_in_namespace(
    elem: &XmlElement,
    local: &str,
    namespace: &str,
    namespaces: &super::NamespaceIndex,
) -> usize {
    let mut count = usize::from(elem.local_name == local && namespaces.matches(elem, namespace));
    for child in &elem.children {
        if let XmlNode::Element(child) = child {
            count += count_descendants_in_namespace(child, local, namespace, namespaces);
        }
    }
    count
}

#[cfg(test)]
fn find_by_local_name<'a>(elem: &'a XmlElement, local: &str) -> Option<&'a XmlElement> {
    if elem.local_name == local {
        return Some(elem);
    }
    for child in &elem.children {
        if let XmlNode::Element(e) = child
            && let Some(found) = find_by_local_name(e, local)
        {
            return Some(found);
        }
    }
    None
}

fn text_content(elem: &XmlElement) -> String {
    let mut out = String::new();
    for child in &elem.children {
        if let XmlNode::Text(t) = child {
            out.push_str(t);
        }
    }
    out
}

/// Build an `@ID -> element` map over the whole document. Only the `ID`
/// attribute (spec-defined for SAML) is recorded; `Id`/`id` are ignored.
#[cfg(test)]
fn build_id_map(root: &XmlElement) -> HashMap<String, &XmlElement> {
    let mut map = HashMap::new();
    walk_ids(root, &mut map);
    map
}

/// ID map that fails on any duplicate `ID` attribute. Used by the
/// login and logout verifiers so that a `Reference` URI resolves to
/// at most one element; a document with multiple elements sharing
/// an ID is rejected outright.
fn build_unique_id_map(root: &XmlElement) -> Result<HashMap<String, &XmlElement>> {
    let mut map = HashMap::new();
    walk_unique_ids(root, &mut map)?;
    Ok(map)
}

fn walk_unique_ids<'a>(
    elem: &'a XmlElement,
    out: &mut HashMap<String, &'a XmlElement>,
) -> Result<()> {
    if let Some(id) = get_attr(elem, "ID")
        && out.insert(id.to_string(), elem).is_some()
    {
        return Err(Error::AuthenticationFailed(
            "SAML response contains duplicate ID attributes".into(),
        ));
    }
    for child in &elem.children {
        if let XmlNode::Element(child) = child {
            walk_unique_ids(child, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn walk_ids<'a>(elem: &'a XmlElement, out: &mut HashMap<String, &'a XmlElement>) {
    if let Some(id) = get_attr(elem, "ID") {
        out.insert(id.to_string(), elem);
    }
    for child in &elem.children {
        if let XmlNode::Element(e) = child {
            walk_ids(e, out);
        }
    }
}

/// Enforce two invariants relied on by the login capability
/// binding: exactly one direct-child `Assertion` under the
/// Response, and no additional `Assertion` descendants anywhere
/// else in the document. Rejects XSW-family payloads that add
/// sibling or nested Assertion elements.
fn login_assertion_child_index(
    root: &XmlElement,
    namespaces: &super::NamespaceIndex,
) -> Result<usize> {
    let mut assertion_index = None;
    for (index, child) in root.children.iter().enumerate() {
        let XmlNode::Element(child) = child else {
            continue;
        };
        if child.local_name != "Assertion" || !namespaces.matches(child, super::NS_ASSERTION) {
            continue;
        }
        if assertion_index.is_some() {
            return Err(Error::AuthenticationFailed(
                "SAML Response must contain exactly one direct-child Assertion".into(),
            ));
        }
        assertion_index = Some(index);
    }
    let assertion_child_index = assertion_index.ok_or_else(|| {
        Error::AuthenticationFailed(
            "SAML Response must contain exactly one direct-child Assertion".into(),
        )
    })?;
    if count_descendants_in_namespace(root, "Assertion", super::NS_ASSERTION, namespaces) != 1 {
        return Err(Error::AuthenticationFailed(
            "SAML response must contain exactly one Assertion element".into(),
        ));
    }
    Ok(assertion_child_index)
}

/// Return the namespace declarations visible from `target`'s parent chain
/// (i.e. everything inherited, not `target`'s own declarations).
fn ancestor_namespaces<'a>(
    root: &'a XmlElement,
    target: &'a XmlElement,
) -> HashMap<String, String> {
    let mut context = HashMap::new();
    let mut found = None;
    collect_ancestor_ns(root, target, &mut context, &mut found);
    found.unwrap_or_default()
}

/// Walk the tree, accumulating namespace declarations on the way down
/// until we hit `target`. On hit, `out` already contains ancestors-only.
fn collect_ancestor_ns(
    elem: &XmlElement,
    target: &XmlElement,
    context: &mut HashMap<String, String>,
    found: &mut Option<HashMap<String, String>>,
) -> bool {
    if std::ptr::eq(elem, target) {
        *found = Some(context.clone());
        return true;
    }
    let mut replaced = Vec::with_capacity(elem.ns_decls.len());
    for (prefix, uri) in &elem.ns_decls {
        replaced.push((prefix.clone(), context.insert(prefix.clone(), uri.clone())));
    }
    for child in &elem.children {
        if let XmlNode::Element(e) = child
            && collect_ancestor_ns(e, target, context, found)
        {
            return true;
        }
    }
    // Revert this element's ns decls (pop on the way back up).
    for (prefix, previous) in replaced.into_iter().rev() {
        if let Some(previous) = previous {
            context.insert(prefix, previous);
        } else {
            context.remove(&prefix);
        }
    }
    false
}

/// Extract the RSA public key bytes from a DER-encoded X.509 certificate, in the
/// format ring expects: the inner `RSAPublicKey` ASN.1 structure
/// (`SEQUENCE { modulus INTEGER, publicExponent INTEGER }`), i.e. the contents
/// of the `subjectPublicKey` BIT STRING — *not* the full `SubjectPublicKeyInfo`
/// envelope. Passing the SPKI envelope to `ring::signature::UnparsedPublicKey`
/// silently fails verification (ring masks parse errors as `Unspecified` to
/// avoid timing attacks).
fn extract_spki_from_x509(cert_der: &[u8]) -> Option<Vec<u8>> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    Some(
        cert.tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec(),
    )
}

#[cfg(test)]
pub(super) mod tests {
    //! Unit tests built around synthetic, self-signed SAML Responses.
    //!
    //! We generate a 2048-bit RSA key at test time, craft a Response, sign it
    //! the same way an IdP would, then poke at the bytes to check each negative
    //! path. That way we exercise both the crypto and the XSW-related
    //! structural checks without depending on a live IdP.
    use super::*;
    use crate::saml::c14n::{exclusive_c14n, parse_xml_tree};
    use ring::rand::SystemRandom;
    use ring::signature::RsaKeyPair;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    struct Fixture {
        cert_der: Vec<u8>,
        key: RsaKeyPair,
        rng: SystemRandom,
    }

    // Pre-generated RSA keypair + self-signed cert for the signing tests.
    // ring/rcgen cannot generate RSA keys at runtime (no RSA keygen backend),
    // so we ship a throwaway key as embedded bytes. These are safe to commit:
    // the cert is a CN=saml-test self-signed throwaway used only by tests.
    const TEST_KEY_PKCS8_DER: &[u8] = include_bytes!("testdata/saml_test.p8.der");
    const TEST_CERT_DER: &[u8] = include_bytes!("testdata/saml_test.crt.der");
    const TEST_CERT2_DER: &[u8] = include_bytes!("testdata/saml_test2.crt.der");

    impl Fixture {
        /// Load the baked-in RSA keypair + cert.
        fn new() -> Self {
            let key = RsaKeyPair::from_pkcs8(TEST_KEY_PKCS8_DER).expect("load pkcs8");
            Fixture {
                cert_der: TEST_CERT_DER.to_vec(),
                key,
                rng: SystemRandom::new(),
            }
        }
    }

    /// Re-emit a fresh SignedInfo element without relying on the string
    /// manipulation above. Matches the shape of the one inside `sign_response`.
    fn signed_info_block(digest_b64: &str, assertion_id: &str) -> String {
        format!(
            r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
        )
    }

    /// End-to-end valid signed response: sign + verify round-trips.
    #[test]
    fn accepts_valid_signed_response() {
        let fx = Fixture::new();
        let xml = sign_fresh(&fx, "_a1", "");
        verify_saml_signature(&xml, std::slice::from_ref(&fx.cert_der)).expect("valid signature");
    }

    /// XSW: inject a second unsigned Assertion as a sibling. Must reject
    /// outright (>1 Assertion guard), not just silently ignore.
    #[test]
    fn rejects_xsw_assertion_injected_as_sibling() {
        let fx = Fixture::new();
        let evil = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil" Version="2.0" IssueInstant="2026-04-19T00:00:00Z"><saml:Issuer>evil</saml:Issuer><saml:Subject><saml:NameID>evil@example.com</saml:NameID></saml:Subject></saml:Assertion>"#;
        let xml = sign_fresh(&fx, "_a1", evil);
        let err = verify_saml_signature(&xml, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(format!("{err}").contains("Assertion"), "got: {err}");
    }

    /// Tamper with the DigestValue after signing — SignedInfo signature still
    /// verifies against the *tampered* SignedInfo (because the signer would
    /// have signed these bytes), but the digest-vs-content check must catch
    /// the mismatch. To simulate, we leave SignedInfo alone and instead
    /// mutate the Assertion content: digest in SignedInfo no longer matches
    /// the re-canonicalized Assertion, so Reference verification fails.
    #[test]
    fn rejects_reference_digest_mismatch() {
        let fx = Fixture::new();
        let xml = sign_fresh(&fx, "_a1", "");
        // Flip one byte inside the Assertion (the email), leaving Signature intact.
        let tampered = xml.replace("alice@example.com", "mallory@example.com");
        let err = verify_saml_signature(&tampered, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(
            format!("{err}").contains("Digest") || format!("{err}").contains("digest"),
            "got: {err}"
        );
    }

    /// The Reference declares SHA-1 — must refuse. We rebuild a Response
    /// with an altered DigestMethod URI.
    #[test]
    fn rejects_sha1_digest_method() {
        let fx = Fixture::new();
        let xml = sign_fresh(&fx, "_a1", "");
        let bad = xml.replace(
            "http://www.w3.org/2001/04/xmlenc#sha256",
            "http://www.w3.org/2000/09/xmldsig#sha1",
        );
        let err = verify_saml_signature(&bad, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(
            format!("{err}").contains("DigestMethod") || format!("{err}").contains("Signature"),
            "got: {err}"
        );
    }

    /// The Reference declares RSA-SHA1 — must refuse.
    #[test]
    fn rejects_rsa_sha1_signature_method() {
        let fx = Fixture::new();
        let xml = sign_fresh(&fx, "_a1", "");
        let bad = xml.replace(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        );
        let err = verify_saml_signature(&bad, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(
            format!("{err}").contains("SHA1") || format!("{err}").contains("SHA-1"),
            "got: {err}"
        );
    }

    /// SignedInfo declares an unsupported CanonicalizationMethod. The
    /// bytes we hash are exclusive c14n regardless, so accepting the
    /// declaration would either "verify" against a stream the IdP did
    /// not intend (if the two algorithms coincidentally produce the
    /// same octets for this doc) or fail with a generic
    /// "verification failed" that hides the real reason. Refuse
    /// declared / implemented mismatches explicitly.
    #[test]
    fn rejects_unsupported_canonicalization_method() {
        let fx = Fixture::new();
        let xml = sign_fresh(&fx, "_a1", "");
        let bad = xml.replace(
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">",
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\">",
        );
        let err = verify_saml_signature(&bad, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(
            format!("{err}").contains("CanonicalizationMethod"),
            "got: {err}"
        );
    }

    /// The Reference Transform declares exc-c14n#WithComments. Our
    /// canonicalizer strips comments, so accepting the declaration
    /// would digest a subtly different octet stream than the IdP
    /// signed. Refuse the WithComments variant explicitly.
    #[test]
    fn rejects_reference_transform_with_comments_variant() {
        let fx = Fixture::new();
        let xml = sign_fresh(&fx, "_a1", "");
        // Only the Reference's exc-c14n transform is on the payload; the
        // SignedInfo's own CanonicalizationMethod stays no-comments.
        let bad = xml.replacen(
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">",
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\">",
            1,
        );
        let err = verify_saml_signature(&bad, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(format!("{err}").contains("WithComments"), "got: {err}");
    }

    /// Sign the entire `<samlp:Response ID="_r1">` (URI="#_r1"), producing a
    /// Response-scoped signature where the enclosing Signature IS a child of
    /// the referenced element. Only used by the copied-SignatureValue
    /// regression below — that shape needs `find_child_path` to return
    /// `Some(non-empty)` so path-based strip actually fires, which
    /// Assertion-scoped signing (the standard `sign_fresh` layout) doesn't
    /// exercise.
    fn sign_fresh_response_scoped(fx: &Fixture) -> String {
        let assertion = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.example.com/saml/acs" NotOnOrAfter="2099-01-01T00:00:00Z" InResponseTo="_req1"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>"#;
        // Build the Response WITHOUT the Signature — that is exactly what
        // the verifier reconstructs after the enveloped-signature transform
        // strips the target Signature from a clone of the referenced element.
        let response_stripped = format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z" Destination="https://sp.example.com/saml/acs" InResponseTo="_req1"><saml:Issuer>https://idp.example.com</saml:Issuer>{assertion}</samlp:Response>"##
        );
        let stripped_tree = parse_xml_tree(&response_stripped).unwrap();
        let digest_bytes = exclusive_c14n(&stripped_tree, &HashMap::new());
        let digest = Sha256::digest(&digest_bytes);
        let digest_b64 = base64::engine::general_purpose::STANDARD.encode(digest);

        let si = signed_info_block(&digest_b64, "_r1");
        let si_tree = parse_xml_tree(&si).unwrap();
        let si_canonical = exclusive_c14n(&si_tree, &HashMap::new());
        let mut sig = vec![0u8; fx.key.public().modulus_len()];
        fx.key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &fx.rng,
                &si_canonical,
                &mut sig,
            )
            .unwrap();
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

        // Real Signature goes as the FIRST Response child so a DFS
        // `find_by_local_name` in `verify_saml_signature` picks it — not any
        // pseudo-`<ds:Signature>` a test buries deeper. This isolates the
        // digest-mismatch path from the "first Signature is malformed"
        // early-refuse path.
        format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z" Destination="https://sp.example.com/saml/acs" InResponseTo="_req1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{si}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature><saml:Issuer>https://idp.example.com</saml:Issuer>{assertion}</samlp:Response>"##
        )
    }

    fn sign_root_element(fx: &Fixture, unsigned: &str, root_id: &str) -> String {
        let root = parse_xml_tree(unsigned).expect("parse unsigned root");
        let digest_bytes = exclusive_c14n(&root, &HashMap::new());
        let digest_b64 =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&digest_bytes));
        let signed_info = signed_info_block(&digest_b64, root_id);
        let signed_info_tree = parse_xml_tree(&signed_info).expect("parse SignedInfo");
        let signed_info_bytes = exclusive_c14n(&signed_info_tree, &HashMap::new());
        let mut signature_bytes = vec![0u8; fx.key.public().modulus_len()];
        fx.key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &fx.rng,
                &signed_info_bytes,
                &mut signature_bytes,
            )
            .expect("sign root");
        let signature_value = base64::engine::general_purpose::STANDARD.encode(signature_bytes);
        let signature = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{signature_value}</ds:SignatureValue></ds:Signature>"#
        );
        let insertion = unsigned.find('>').expect("root opening tag") + 1;
        let mut signed = unsigned.to_string();
        signed.insert_str(insertion, &signature);
        signed
    }

    /// Sanity: the Response-scoped signer verifies clean when no injection is
    /// present. Guards against the helper drifting from spec semantics.
    #[test]
    fn accepts_valid_response_scoped_signature() {
        let fx = Fixture::new();
        let xml = sign_fresh_response_scoped(&fx);
        verify_saml_signature(&xml, std::slice::from_ref(&fx.cert_der))
            .expect("Response-scoped signature must verify clean");
    }

    /// Copied-`SignatureValue` regression, pinned to the digest-mismatch
    /// rejection path.
    ///
    /// The document is Response-scoped (URI="#_r1"), so the enclosing
    /// Signature is inside the referenced subtree and path-based strip
    /// actually fires. The attacker inserts a second `<ds:Signature>` — with
    /// the outer signature's `SignatureValue` text copied verbatim — as
    /// another Response child. Both are inside the referenced Response.
    ///
    /// Old content-based strip would have removed both by SignatureValue
    /// match, silently deleting `<evil/>` from the digest input and letting
    /// the outer digest still verify. Path-based strip removes only the
    /// exact target node from the clone; the injected node stays in the
    /// canonicalised octet stream and the reference digest mismatches.
    ///
    /// The real Signature is placed as the FIRST Response child by the
    /// helper, so DFS `find_by_local_name` in `verify_saml_signature`
    /// selects it and reaches the digest step — pinning the rejection to
    /// the digest-mismatch banner rather than an early structural refuse.
    #[test]
    fn rejects_injected_signature_with_copied_signature_value() {
        let fx = Fixture::new();
        let clean = sign_fresh_response_scoped(&fx);
        let sv_open = "<ds:SignatureValue>";
        let sv_close = "</ds:SignatureValue>";
        let sv_start = clean.find(sv_open).expect("SignatureValue present") + sv_open.len();
        let sv_end = clean[sv_start..]
            .find(sv_close)
            .expect("SignatureValue closes")
            + sv_start;
        let real_sig_value = &clean[sv_start..sv_end];
        let injected = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>{real_sig_value}</ds:SignatureValue><evil>attacker-controlled</evil></ds:Signature>"#
        );
        // Post-hoc injection: attacker splices the fake Signature into the
        // already-signed document. It was NOT part of the digest at signing
        // time, so it must NOT be stripped at verify time — otherwise the
        // digest would match and the attack would succeed.
        let bad = clean.replacen(
            "</samlp:Response>",
            &format!("{injected}</samlp:Response>"),
            1,
        );
        assert_ne!(bad, clean, "injection substitution did not fire");
        let err = verify_saml_signature(&bad, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(
            format!("{err}").contains("DigestValue"),
            "expected digest mismatch, got: {err}"
        );
    }

    /// The transform chain must be [enveloped-signature, exc-c14n] in that
    /// order. A hostile IdP swapping the order would compute the digest over
    /// a different octet stream than we do; refuse loudly instead of
    /// silently applying our own preferred order.
    #[test]
    fn rejects_reference_transforms_in_reverse_order() {
        let fx = Fixture::new();
        let xml = sign_fresh(&fx, "_a1", "");
        let bad = xml.replacen(
            "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">",
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\">",
            1,
        );
        assert_ne!(bad, xml, "reverse-order substitution did not fire");
        let err = verify_saml_signature(&bad, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(
            format!("{err}").contains("enveloped-signature"),
            "got: {err}"
        );
    }

    /// Sign with Fixture A, verify with a completely unrelated cert → fail
    /// cleanly. Both certs are baked-in fixtures (no runtime RSA generation).
    #[test]
    fn rejects_wrong_signing_key() {
        let a = Fixture::new();
        let xml = sign_fresh(&a, "_a1", "");
        let err = verify_saml_signature(&xml, &[TEST_CERT2_DER.to_vec()]).unwrap_err();
        assert!(
            format!("{err}").contains("verification failed"),
            "got: {err}"
        );
    }

    #[test]
    fn find_child_path_locates_element_by_identity() {
        // Two structurally-identical <ds:Signature> siblings; pointer identity
        // must pick the exact node passed in, not "any Signature that looks
        // like it".
        let xml = r#"<Root xmlns="urn:x"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>SAME</ds:SignatureValue></ds:Signature><Mid/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>SAME</ds:SignatureValue></ds:Signature></Root>"#;
        let tree = parse_xml_tree(xml).unwrap();
        let sigs = find_direct_children(&tree, "Signature");
        assert_eq!(sigs.len(), 2);
        let path_first = find_child_path(&tree, sigs[0]).unwrap();
        let path_second = find_child_path(&tree, sigs[1]).unwrap();
        assert_ne!(
            path_first, path_second,
            "identical-looking siblings must resolve to different paths"
        );
    }

    #[test]
    fn remove_element_at_path_removes_only_that_node() {
        // Nested target reached via a multi-step path. Only the addressed
        // node disappears; siblings and unrelated Signatures survive.
        let xml = r#"<Root xmlns="urn:x"><Inner><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>TARGET</ds:SignatureValue></ds:Signature></Inner><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>OTHER</ds:SignatureValue></ds:Signature><Keep/></Root>"#;
        let mut tree = parse_xml_tree(xml).unwrap();
        // Path to <Inner>/<ds:Signature>: [0, 0].
        assert!(remove_element_at_path(&mut tree, &[0, 0]));
        let out = String::from_utf8(exclusive_c14n(&tree, &HashMap::new())).unwrap();
        assert!(!out.contains("TARGET"), "target not removed: {out}");
        assert!(
            out.contains("OTHER"),
            "non-target Signature must be preserved: {out}"
        );
        assert!(out.contains("Keep"), "siblings must remain: {out}");
    }

    #[test]
    fn remove_element_at_path_refuses_empty_and_out_of_range() {
        let xml = r#"<Root xmlns="urn:x"><Child/></Root>"#;
        let mut tree = parse_xml_tree(xml).unwrap();
        assert!(
            !remove_element_at_path(&mut tree, &[]),
            "empty path must not remove the root"
        );
        assert!(
            !remove_element_at_path(&mut tree, &[99]),
            "out-of-range index must not remove anything"
        );
    }

    fn sign_fresh(fx: &Fixture, assertion_id: &str, extra: &str) -> String {
        // Newer, cleaner version of Fixture::sign_response that composes the
        // Response as a single template — keeps SignedInfo bytes stable for
        // canonicalisation.
        let assertion = format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="2026-04-19T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.example.com/saml/acs" NotOnOrAfter="2099-01-01T00:00:00Z" InResponseTo="_req1"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>"#
        );
        sign_fresh_assertion(fx, assertion_id, extra, &assertion)
    }

    fn element_count(elem: &XmlElement) -> usize {
        1 + elem
            .children
            .iter()
            .filter_map(|child| match child {
                XmlNode::Element(child) => Some(element_count(child)),
                _ => None,
            })
            .sum::<usize>()
    }

    #[test]
    fn namespace_resolution_work_is_bounded_for_wide_signature_collisions() {
        let fx = Fixture::new();
        let collisions = (0..128)
            .map(|_| r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#)
            .collect::<String>();
        let xml = sign_fresh(&fx, "_a1", &collisions);
        let tree = parse_xml_tree(&xml).expect("parse wide collision response");
        let elements = element_count(&tree);

        let (result, visits) = super::super::measure_namespace_traversals(|| {
            verify_login_response(&xml, std::slice::from_ref(&fx.cert_der))
        });
        assert!(
            result.is_err(),
            "multiple genuine signatures remain ambiguous"
        );
        assert!(
            visits <= elements * 4,
            "namespace resolution rescanned the tree: visits={visits}, elements={elements}"
        );
    }

    #[test]
    fn namespace_index_does_not_duplicate_inherited_uri_storage() {
        let foreign_uri = format!("urn:foreign:{}", "x".repeat(4096));
        let children = (0..512).map(|_| "<f:x/>").collect::<String>();
        let xml = format!(r#"<f:Response xmlns:f="{foreign_uri}">{children}</f:Response>"#);
        assert!(xml.len() < 1024 * 1024);
        let tree = parse_xml_tree(&xml).expect("parse inherited foreign namespace tree");
        let elements = element_count(&tree);
        let index = super::super::NamespaceIndex::new(&tree);
        let (node_entries, owned_uri_bytes) = index.retained_namespace_storage();
        assert_eq!(node_entries, elements);
        assert!(owned_uri_bytes <= foreign_uri.len());
        assert!(verify_login_response(&xml, &[vec![0]]).is_err());
    }

    #[test]
    fn namespace_traversal_measurement_is_isolated() {
        let local_xml = r#"<root xmlns="urn:local"><child/></root>"#;
        let local_tree = parse_xml_tree(local_xml).expect("parse local tree");
        let local_elements = element_count(&local_tree);
        let foreign_children = "<child/>".repeat(128);
        let foreign_xml = format!(r#"<root xmlns="urn:foreign">{foreign_children}</root>"#);

        let ((), visits) = super::super::measure_namespace_traversals(|| {
            let foreign = std::thread::spawn(move || {
                let foreign_tree = parse_xml_tree(&foreign_xml).expect("parse foreign tree");
                let _ = super::super::NamespaceIndex::new(&foreign_tree);
            });
            let _ = super::super::NamespaceIndex::new(&local_tree);
            foreign.join().expect("foreign traversal thread");
        });
        assert_eq!(visits, local_elements);

        let ((inner_visits, ()), outer_visits) = super::super::measure_namespace_traversals(|| {
            let _ = super::super::NamespaceIndex::new(&local_tree);
            let ((), inner_visits) = super::super::measure_namespace_traversals(|| {
                let _ = super::super::NamespaceIndex::new(&local_tree);
            });
            let _ = super::super::NamespaceIndex::new(&local_tree);
            (inner_visits, ())
        });
        assert_eq!(inner_visits, local_elements);
        assert_eq!(outer_visits, local_elements * 2);

        let ((), sequential_visits) = super::super::measure_namespace_traversals(|| {
            let _ = super::super::NamespaceIndex::new(&local_tree);
        });
        assert_eq!(sequential_visits, local_elements);
    }

    #[test]
    fn signed_login_ignores_foreign_extension_name_collisions() {
        let fx = Fixture::new();
        let extensions = r#"<ext:Signature xmlns:ext="urn:example:extension"/><ext:Assertion xmlns:ext="urn:example:extension"/>"#;
        let xml = sign_fresh_assertion_scoped(&fx).replacen(
            "</samlp:Response>",
            &format!("{extensions}</samlp:Response>"),
            1,
        );
        verify_login_response(&xml, std::slice::from_ref(&fx.cert_der))
            .expect("foreign extension local-name collisions must be ignored");
    }

    fn sign_fresh_assertion(
        fx: &Fixture,
        assertion_id: &str,
        extra: &str,
        assertion: &str,
    ) -> String {
        sign_fresh_assertion_with_signature_ns(
            fx,
            assertion_id,
            extra,
            assertion,
            "http://www.w3.org/2000/09/xmldsig#",
        )
    }

    fn sign_fresh_assertion_with_signature_ns(
        fx: &Fixture,
        assertion_id: &str,
        extra: &str,
        assertion: &str,
        signature_ns: &str,
    ) -> String {
        let assertion_tree = parse_xml_tree(assertion).unwrap();
        let digest_bytes = exclusive_c14n(&assertion_tree, &HashMap::new());
        let digest = Sha256::digest(&digest_bytes);
        let digest_b64 = base64::engine::general_purpose::STANDARD.encode(digest);

        let si = signed_info_block(&digest_b64, assertion_id)
            .replace("http://www.w3.org/2000/09/xmldsig#", signature_ns);
        let si_tree = parse_xml_tree(&si).unwrap();
        let si_canonical = exclusive_c14n(&si_tree, &HashMap::new());
        let mut sig = vec![0u8; fx.key.public().modulus_len()];
        fx.key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &fx.rng,
                &si_canonical,
                &mut sig,
            )
            .unwrap();
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

        // Embed the exact SignedInfo bytes we just signed — not a rebuilt
        // string — so canonicalization on the verify side produces the same
        // octets.
        format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z" Destination="https://sp.example.com/saml/acs" InResponseTo="_req1"><saml:Issuer>https://idp.example.com</saml:Issuer>{assertion}<ds:Signature xmlns:ds="{signature_ns}">{si}<ds:SignatureValue>{sig_b64}</ds:SignatureValue></ds:Signature>{extra}</samlp:Response>"##
        )
    }

    fn sign_fresh_assertion_scoped(fx: &Fixture) -> String {
        let signed = sign_fresh(fx, "_a1", "");
        move_signature(&signed, "</saml:Assertion>")
    }

    #[test]
    fn login_rejects_cryptographically_valid_wrong_and_mixed_namespaces() {
        let fx = Fixture::new();
        let valid = sign_fresh_assertion_scoped(&fx);
        verify_login_response(&valid, std::slice::from_ref(&fx.cert_der))
            .expect("valid assertion-scoped response");

        let wrong_protocol = valid.replacen(
            "urn:oasis:names:tc:SAML:2.0:protocol",
            "urn:attacker:protocol",
            1,
        );
        assert_crypto_valid_without_bound_shape(&wrong_protocol, &fx);
        assert!(
            verify_login_response(&wrong_protocol, std::slice::from_ref(&fx.cert_der)).is_err(),
            "foreign Response namespace must be rejected"
        );

        let missing_protocol = valid
            .replacen(
                "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"",
                "<Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"",
                1,
            )
            .replacen("</samlp:Response>", "</Response>", 1);
        assert_crypto_valid_without_bound_shape(&missing_protocol, &fx);
        assert!(
            verify_login_response(&missing_protocol, std::slice::from_ref(&fx.cert_der)).is_err(),
            "missing Response namespace must be rejected"
        );

        let assertion = r#"<saml:Assertion xmlns:saml="urn:attacker:assertion" ID="_foreign_a" Version="2.0" IssueInstant="2026-04-19T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.example.com/saml/acs" NotOnOrAfter="2099-01-01T00:00:00Z" InResponseTo="_req1"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>"#;
        let wrong_assertion = move_signature(
            &sign_fresh_assertion(&fx, "_foreign_a", "", assertion),
            "</saml:Assertion>",
        );
        assert!(
            verify_login_response(&wrong_assertion, std::slice::from_ref(&fx.cert_der)).is_err(),
            "foreign Assertion namespace must be rejected even when signed"
        );

        let mixed_assertion = assertion
            .replace(
                "urn:attacker:assertion",
                "urn:oasis:names:tc:SAML:2.0:assertion",
            )
            .replacen(
                "<saml:Issuer>",
                "<evil:Issuer xmlns:evil=\"urn:attacker:assertion\">",
                1,
            )
            .replacen("</saml:Issuer>", "</evil:Issuer>", 1);
        let mixed = move_signature(
            &sign_fresh_assertion(&fx, "_foreign_a", "", &mixed_assertion),
            "</saml:Assertion>",
        );
        let verified = verify_login_response(&mixed, std::slice::from_ref(&fx.cert_der))
            .expect("mixed-namespace response remains cryptographically valid");
        let ctx = super::super::validate::AssertionValidationContext {
            expected_issuer: "https://idp.example.com",
            expected_audience: "https://sp.example.com",
            expected_destination: "https://sp.example.com/saml/acs",
            expected_recipient: "https://sp.example.com/saml/acs",
            expected_in_response_to: Some("_req1"),
            now: chrono::DateTime::parse_from_rfc3339("2026-04-19T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        };
        assert!(
            super::super::validate::validate_response(&verified, &ctx).is_err(),
            "foreign consumed Issuer namespace must be rejected after signature verification"
        );

        let wrong_dsig = move_signature(
            &sign_fresh_assertion_with_signature_ns(
                &fx,
                "_foreign_a",
                "",
                &mixed_assertion.replace(
                    "urn:attacker:assertion",
                    "urn:oasis:names:tc:SAML:2.0:assertion",
                ),
                "urn:attacker:xmldsig",
            ),
            "</saml:Assertion>",
        );
        assert!(
            verify_login_response(&wrong_dsig, std::slice::from_ref(&fx.cert_der)).is_err(),
            "foreign XMLDSig namespace must be rejected even when signed"
        );
    }

    fn move_signature(signed: &str, before: &str) -> String {
        let signature_start = signed.find("<ds:Signature").expect("Signature start");
        let signature_end = signed[signature_start..]
            .find("</ds:Signature>")
            .map(|offset| signature_start + offset + "</ds:Signature>".len())
            .expect("Signature end");
        let signature = signed[signature_start..signature_end].to_string();
        let mut without = signed.to_string();
        without.replace_range(signature_start..signature_end, "");
        let insertion = without.find(before).expect("insertion point");
        without.insert_str(insertion, &signature);
        without
    }

    fn strip_signature(signed: &str) -> String {
        let signature_start = signed.find("<ds:Signature").expect("Signature start");
        let signature_end = signed[signature_start..]
            .find("</ds:Signature>")
            .map(|offset| signature_start + offset + "</ds:Signature>".len())
            .expect("Signature end");
        let mut without = signed.to_string();
        without.replace_range(signature_start..signature_end, "");
        without
    }

    fn assert_crypto_valid_without_bound_shape(xml: &str, fx: &Fixture) {
        let root = parse_xml_tree(xml).expect("parse signed fixture");
        let signature = find_by_local_name(&root, "Signature").expect("Signature");
        let id_map = build_id_map(&root);
        let namespaces = super::super::NamespaceIndex::new(&root);
        verify_parsed_saml_signature(
            &root,
            &namespaces,
            std::slice::from_ref(&fx.cert_der),
            signature,
            &id_map,
        )
        .expect("fixture signature must remain cryptographically valid");
    }

    fn resign_embedded_assertion(xml: &str, fx: &Fixture) -> String {
        let root = parse_xml_tree(xml).expect("parse attack fixture");
        let signature = find_by_local_name(&root, "Signature").expect("Signature");
        let signed_info = find_direct_child(signature, "SignedInfo").expect("SignedInfo");
        let reference = find_direct_child(signed_info, "Reference").expect("Reference");
        let referenced_id = get_attr(reference, "URI")
            .and_then(|uri| uri.strip_prefix('#'))
            .expect("same-document Reference");
        let id_map = build_id_map(&root);
        let referenced = id_map
            .get(referenced_id)
            .copied()
            .expect("referenced element");
        let signature_path =
            find_child_path(referenced, signature).expect("Signature inside signed Assertion");
        let mut digest_target = referenced.clone();
        assert!(remove_element_at_path(&mut digest_target, &signature_path));
        let digest_bytes = exclusive_c14n(&digest_target, &ancestor_namespaces(&root, referenced));
        let digest_b64 =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&digest_bytes));
        let replacement_signed_info = signed_info_block(&digest_b64, referenced_id);
        let signed_info_tree =
            parse_xml_tree(&replacement_signed_info).expect("parse replacement SignedInfo");
        let signed_info_bytes = exclusive_c14n(&signed_info_tree, &HashMap::new());
        let mut signature_bytes = vec![0u8; fx.key.public().modulus_len()];
        fx.key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &fx.rng,
                &signed_info_bytes,
                &mut signature_bytes,
            )
            .expect("sign attack fixture");
        let replacement_signature_value =
            base64::engine::general_purpose::STANDARD.encode(signature_bytes);

        let signed_info_start = xml.find("<ds:SignedInfo").expect("SignedInfo start");
        let signed_info_end = xml[signed_info_start..]
            .find("</ds:SignedInfo>")
            .map(|offset| signed_info_start + offset + "</ds:SignedInfo>".len())
            .expect("SignedInfo end");
        let mut resigned = xml.to_string();
        resigned.replace_range(signed_info_start..signed_info_end, &replacement_signed_info);
        let value_start = resigned
            .find("<ds:SignatureValue>")
            .map(|offset| offset + "<ds:SignatureValue>".len())
            .expect("SignatureValue start");
        let value_end = resigned[value_start..]
            .find("</ds:SignatureValue>")
            .map(|offset| value_start + offset)
            .expect("SignatureValue end");
        resigned.replace_range(value_start..value_end, &replacement_signature_value);
        resigned
    }

    pub(in crate::saml) fn process_response_identity_fixtures() -> (String, String) {
        let fx = Fixture::new();
        let valid = sign_fresh_assertion_scoped(&fx).replacen(
            "</saml:Issuer>",
            concat!(
                "</saml:Issuer>",
                "<samlp:Status><samlp:StatusCode ",
                "Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>",
                "</samlp:Status>"
            ),
            1,
        );
        let (legit, _, _) = extract_assertion(&valid);
        let evil = strip_signature(&make_evil(&legit));
        let attack = resign_embedded_assertion(
            &valid.replace(
                &legit,
                &format!("{evil}<samlp:Extensions>{legit}</samlp:Extensions>"),
            ),
            &fx,
        );
        (valid, attack)
    }

    pub(in crate::saml) fn process_response_identity_fixture_with_literal() -> String {
        let fx = Fixture::new();
        let valid = sign_fresh_assertion_scoped(&fx).replacen(
            "</saml:Issuer>",
            "</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>",
            1,
        );
        let (legit, _, _) = extract_assertion(&valid);
        let modified = legit.replace("alice@example.com", "literal EncryptedAssertion text");
        resign_embedded_assertion(&valid.replace(&legit, &modified), &fx)
    }

    pub(in crate::saml) fn process_response_identity_fixture_with_assertion_namespace(
        namespace: &str,
    ) -> String {
        let fx = Fixture::new();
        let (valid, _) = process_response_identity_fixtures();
        let (legit, _, _) = extract_assertion(&valid);
        let modified = legit.replacen(
            "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"",
            &format!("xmlns:saml=\"{namespace}\""),
            1,
        );
        resign_embedded_assertion(&valid.replace(&legit, &modified), &fx)
    }

    #[test]
    fn login_verifier_accepts_root_and_assertion_scoped_signatures() {
        let fx = Fixture::new();
        verify_login_response(
            &sign_fresh_response_scoped(&fx),
            std::slice::from_ref(&fx.cert_der),
        )
        .expect("root-scoped login signature");
        verify_login_response(
            &sign_fresh_assertion_scoped(&fx),
            std::slice::from_ref(&fx.cert_der),
        )
        .expect("assertion-scoped login signature");
    }

    #[test]
    fn login_verifier_rejects_cryptographically_valid_xsw2_nested_response() {
        let fx = Fixture::new();
        let signed = sign_fresh_assertion_scoped(&fx);
        let (_, legit_start, legit_end) = extract_assertion(&signed);
        let evil = strip_signature(&make_evil(&signed[legit_start..legit_end]));
        let attack = resign_embedded_assertion(
            &format!(
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_outer">{evil}{signed}</samlp:Response>"#
            ),
            &fx,
        );
        assert_crypto_valid_without_bound_shape(&attack, &fx);
        assert!(
            verify_login_response(&attack, std::slice::from_ref(&fx.cert_der)).is_err(),
            "XSW-2 nested Response must be rejected"
        );
    }

    #[test]
    fn login_verifier_rejects_cryptographically_valid_xsw3_extensions_wrap() {
        let fx = Fixture::new();
        let signed = sign_fresh_assertion_scoped(&fx);
        let (legit, _, _) = extract_assertion(&signed);
        let evil = strip_signature(&make_evil(&legit));
        let attack = resign_embedded_assertion(
            &signed.replace(
                &legit,
                &format!("{evil}<samlp:Extensions>{legit}</samlp:Extensions>"),
            ),
            &fx,
        );
        assert_crypto_valid_without_bound_shape(&attack, &fx);
        assert!(
            verify_login_response(&attack, std::slice::from_ref(&fx.cert_der)).is_err(),
            "XSW-3 Extensions wrap must be rejected"
        );
    }

    #[test]
    fn login_verifier_rejects_cryptographically_valid_xsw4_assertion_wrap() {
        let fx = Fixture::new();
        let signed = sign_fresh_assertion_scoped(&fx);
        let (legit, _, _) = extract_assertion(&signed);
        let evil = strip_signature(&make_evil(&legit));
        let wrapped_evil =
            evil.replacen("</saml:Assertion>", &format!("{legit}</saml:Assertion>"), 1);
        let attack = resign_embedded_assertion(&signed.replace(&legit, &wrapped_evil), &fx);
        assert_crypto_valid_without_bound_shape(&attack, &fx);
        assert!(
            verify_login_response(&attack, std::slice::from_ref(&fx.cert_der)).is_err(),
            "XSW-4 Assertion wrap must be rejected"
        );
    }

    #[test]
    fn login_verifier_rejects_duplicate_ids_in_both_document_orders() {
        let fx = Fixture::new();
        let signed = sign_fresh_assertion_scoped(&fx);
        let duplicate = r#"<samlp:Extensions ID="_a1"/>"#;
        let before = signed.replacen("<saml:Assertion", &format!("{duplicate}<saml:Assertion"), 1);
        let after = signed.replacen(
            "</saml:Assertion>",
            &format!("</saml:Assertion>{duplicate}"),
            1,
        );
        for attack in [before, after] {
            assert!(
                verify_login_response(&attack, std::slice::from_ref(&fx.cert_der)).is_err(),
                "duplicate ID must be rejected regardless of document order"
            );
        }
    }

    #[test]
    fn login_verifier_rejects_misplaced_unrelated_and_extra_signatures() {
        let fx = Fixture::new();
        let valid = sign_fresh_assertion_scoped(&fx);

        let misplaced = move_signature(&valid, "</samlp:Response>");
        assert_crypto_valid_without_bound_shape(&misplaced, &fx);
        assert!(
            verify_login_response(&misplaced, std::slice::from_ref(&fx.cert_der)).is_err(),
            "misplaced Signature must be rejected"
        );

        let with_extensions = valid.replacen(
            "</saml:Assertion>",
            "</saml:Assertion><samlp:Extensions></samlp:Extensions>",
            1,
        );
        let unrelated = move_signature(&with_extensions, "</samlp:Extensions>");
        assert_crypto_valid_without_bound_shape(&unrelated, &fx);
        assert!(
            verify_login_response(&unrelated, std::slice::from_ref(&fx.cert_der)).is_err(),
            "unrelated Signature must be rejected"
        );

        let extra = valid.replacen(
            "</samlp:Response>",
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></samlp:Response>"#,
            1,
        );
        assert_crypto_valid_without_bound_shape(&extra, &fx);
        assert!(
            verify_login_response(&extra, std::slice::from_ref(&fx.cert_der)).is_err(),
            "extra Signature must be rejected as ambiguous"
        );
    }

    fn unsigned_logout_response(id: &str, extra: &str) -> String {
        format!(
            r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="2026-04-19T00:00:00Z" InResponseTo="_test_lo_req1"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{extra}</samlp:LogoutResponse>"#
        )
    }

    pub(in crate::saml) fn logout_response_identity_fixtures() -> (String, Vec<String>) {
        let fx = Fixture::new();
        let valid_unsigned = unsigned_logout_response("_logout", "");
        let valid = sign_root_element(&fx, &valid_unsigned, "_logout");

        let nested_unsigned = unsigned_logout_response("_nested", "");
        let nested_signed = sign_root_element(&fx, &nested_unsigned, "_nested");
        let nested = unsigned_logout_response("_outer", &nested_signed);

        let unrelated_unsigned = r#"<samlp:Extensions xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_unrelated"><samlp:Status/></samlp:Extensions>"#;
        let unrelated_signed = sign_root_element(&fx, unrelated_unsigned, "_unrelated");
        let unrelated = unsigned_logout_response("_outer_unrelated", &unrelated_signed);

        let misplaced_unsigned =
            unsigned_logout_response("_misplaced", "<samlp:Extensions></samlp:Extensions>");
        let misplaced = move_signature(
            &sign_root_element(&fx, &misplaced_unsigned, "_misplaced"),
            "</samlp:Extensions>",
        );

        let duplicate_a_unsigned = unsigned_logout_response(
            "_duplicate_a",
            r#"<samlp:Extensions ID="_duplicate"/><saml:Attribute ID="_duplicate"/>"#,
        );
        let duplicate_a = sign_root_element(&fx, &duplicate_a_unsigned, "_duplicate_a");
        let duplicate_b_unsigned = unsigned_logout_response(
            "_duplicate_b",
            r#"<saml:Attribute ID="_duplicate"/><samlp:Extensions ID="_duplicate"/>"#,
        );
        let duplicate_b = sign_root_element(&fx, &duplicate_b_unsigned, "_duplicate_b");

        let extra_unsigned = unsigned_logout_response(
            "_extra",
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#,
        );
        let extra = sign_root_element(&fx, &extra_unsigned, "_extra");

        (
            valid,
            vec![
                nested,
                unrelated,
                misplaced,
                duplicate_a,
                duplicate_b,
                extra,
            ],
        )
    }

    #[test]
    fn logout_verifier_accepts_only_the_signed_root_identity() {
        let fx = Fixture::new();
        let (valid, attacks) = logout_response_identity_fixtures();
        verify_logout_response(&valid, std::slice::from_ref(&fx.cert_der))
            .expect("valid root-signed LogoutResponse");
        verify_saml_signature(&valid, std::slice::from_ref(&fx.cert_der))
            .expect("compatibility verifier accepts LogoutResponse");
        let missing_root_id = valid.replacen(r#" ID="_logout""#, "", 1);
        assert!(
            verify_logout_response(&missing_root_id, std::slice::from_ref(&fx.cert_der)).is_err(),
            "LogoutResponse root ID is mandatory"
        );

        for attack in attacks {
            assert_crypto_valid_without_bound_shape(&attack, &fx);
            assert!(
                verify_logout_response(&attack, std::slice::from_ref(&fx.cert_der)).is_err(),
                "ambiguous LogoutResponse identity must be rejected"
            );
        }
    }

    #[test]
    fn logout_rejects_cryptographically_valid_wrong_and_mixed_namespaces() {
        let fx = Fixture::new();
        let wrong_protocol = unsigned_logout_response("_wrong_protocol", "").replacen(
            "urn:oasis:names:tc:SAML:2.0:protocol",
            "urn:attacker:protocol",
            1,
        );
        let wrong_protocol = sign_root_element(&fx, &wrong_protocol, "_wrong_protocol");
        assert!(
            verify_logout_response(&wrong_protocol, std::slice::from_ref(&fx.cert_der)).is_err(),
            "foreign LogoutResponse namespace must be rejected even when signed"
        );

        let missing_protocol = unsigned_logout_response("_missing_protocol", "")
            .replacen(
                "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"",
                "<LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"",
                1,
            )
            .replacen("</samlp:LogoutResponse>", "</LogoutResponse>", 1);
        let missing_protocol = sign_root_element(&fx, &missing_protocol, "_missing_protocol");
        assert!(
            verify_logout_response(&missing_protocol, std::slice::from_ref(&fx.cert_der)).is_err(),
            "missing LogoutResponse namespace must be rejected even when signed"
        );

        let mixed = unsigned_logout_response("_mixed", "")
            .replacen(
                "<saml:Issuer>",
                "<evil:Issuer xmlns:evil=\"urn:attacker:assertion\">",
                1,
            )
            .replacen("</saml:Issuer>", "</evil:Issuer>", 1);
        let mixed = sign_root_element(&fx, &mixed, "_mixed");
        verify_logout_response(&mixed, std::slice::from_ref(&fx.cert_der))
            .expect("mixed-namespace LogoutResponse remains cryptographically valid");
    }

    #[test]
    fn signed_logout_ignores_foreign_extension_name_collisions() {
        let fx = Fixture::new();
        let extensions = r#"<ext:Signature xmlns:ext="urn:example:extension"/><ext:Assertion xmlns:ext="urn:example:extension"/>"#;
        let unsigned = unsigned_logout_response("_foreign_collisions", extensions);
        let xml = sign_root_element(&fx, &unsigned, "_foreign_collisions");
        verify_logout_response(&xml, std::slice::from_ref(&fx.cert_der))
            .expect("foreign extension local-name collisions must be ignored");
    }

    // -----------------------------------------------------------------------
    // XML Signature Wrapping (XSW) corpus — Somorovsky et al., USENIX
    // Security 2012, "On Breaking SAML: Be Whoever You Want to Be".
    //
    // XSW-1 (evil Assertion injected as sibling of Signature) is covered by
    // `rejects_xsw_assertion_injected_as_sibling` above. The four shapes
    // below preserve the signed original Assertion intact somewhere in the
    // document so the cryptographic checks would pass, while hiding the
    // payload an attacker controls at a location the consumer scans first.
    // Each must be rejected — primarily by the `count_descendants
    // ("Assertion") > 1` guard, with `covers_assertion` as the backstop
    // when the count happens to be 1 (it never is here, but the layered
    // defence is the point).
    //
    // We construct each PoC by post-processing a freshly-signed Response
    // from `sign_fresh`, so the signature itself remains cryptographically
    // valid against the buried original.
    // -----------------------------------------------------------------------

    /// Extract the signed `<saml:Assertion ID="_a1">...</saml:Assertion>` from
    /// a sign_fresh output as a substring, returning (assertion, start, end).
    fn extract_assertion(signed: &str) -> (String, usize, usize) {
        let s = signed
            .find("<saml:Assertion")
            .expect("Assertion in signed XML");
        let e =
            signed.find("</saml:Assertion>").expect("Assertion end") + "</saml:Assertion>".len();
        (signed[s..e].to_string(), s, e)
    }

    /// Build an attacker-controlled Assertion: different ID, different
    /// subject. The structure mirrors the legit one so consumers that scan
    /// by tag name would happily extract from it.
    fn make_evil(legit: &str) -> String {
        legit
            .replace("ID=\"_a1\"", "ID=\"_evil\"")
            .replace("alice@example.com", "mallory@example.com")
    }

    /// XSW-5: original Assertion is preserved inside a `<ds:Object>` that
    /// becomes a child of `<ds:Signature>`. An evil Assertion is left at the
    /// top level. The signature still verifies against the buried original;
    /// a naive consumer reads the evil Assertion.
    #[test]
    fn rejects_xsw5_original_buried_inside_signature_object() {
        let fx = Fixture::new();
        let signed = sign_fresh(&fx, "_a1", "");
        let (legit, _, _) = extract_assertion(&signed);
        let evil = make_evil(&legit);
        let attack = signed.replace(&legit, &evil).replace(
            "</ds:Signature>",
            &format!("<ds:Object>{legit}</ds:Object></ds:Signature>"),
        );
        let err = verify_saml_signature(&attack, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(
            format!("{err}").contains("only one is allowed"),
            "XSW-5 not rejected by Assertion-count guard: {err}"
        );
    }

    /// XSW-6: original Assertion is wrapped in a `<ds:Object>` placed as a
    /// sibling of (not inside) the Signature element. Evil Assertion replaces
    /// the original at the top level.
    #[test]
    fn rejects_xsw6_original_buried_in_sibling_object() {
        let fx = Fixture::new();
        let signed = sign_fresh(&fx, "_a1", "");
        let (legit, _, _) = extract_assertion(&signed);
        let evil = make_evil(&legit);
        let attack = signed.replace(
            &legit,
            &format!(
                "{evil}<ds:Object xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{legit}</ds:Object>"
            ),
        );
        let err = verify_saml_signature(&attack, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(
            format!("{err}").contains("only one is allowed"),
            "XSW-6 not rejected by Assertion-count guard: {err}"
        );
    }

    /// XSW-7: original Assertion is buried inside `<samlp:Extensions>`. The
    /// Extensions element is a legitimate SAML protocol slot for arbitrary
    /// nested content, so a parser that did not enforce a single-Assertion
    /// rule could be fooled into trusting the evil one.
    #[test]
    fn rejects_xsw7_original_buried_in_samlp_extensions() {
        let fx = Fixture::new();
        let signed = sign_fresh(&fx, "_a1", "");
        let (legit, _, _) = extract_assertion(&signed);
        let evil = make_evil(&legit);
        let attack = signed.replace(
            &legit,
            &format!("{evil}<samlp:Extensions>{legit}</samlp:Extensions>"),
        );
        let err = verify_saml_signature(&attack, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(
            format!("{err}").contains("only one is allowed"),
            "XSW-7 not rejected by Assertion-count guard: {err}"
        );
    }

    /// XSW-8: original Assertion *wraps* the Signature element (Signature
    /// becomes a child of the original Assertion). Evil Assertion is left
    /// as a sibling at the top level. The enveloped-signature transform
    /// strips the embedded Signature before digesting, so crypto still
    /// works on the buried original.
    #[test]
    fn rejects_xsw8_original_wraps_signature_with_evil_sibling() {
        let fx = Fixture::new();
        let signed = sign_fresh(&fx, "_a1", "");
        let (legit, _, _) = extract_assertion(&signed);
        let evil = make_evil(&legit);

        let sig_start = signed.find("<ds:Signature").expect("Signature start");
        let sig_end =
            signed.find("</ds:Signature>").expect("Signature end") + "</ds:Signature>".len();
        let sig_elem = signed[sig_start..sig_end].to_string();

        // Remove Signature from its sibling position.
        let without_sig = format!("{}{}", &signed[..sig_start], &signed[sig_end..]);
        // Splice Signature inside the original Assertion (before its close).
        let legit_with_sig_inside =
            legit.replace("</saml:Assertion>", &format!("{sig_elem}</saml:Assertion>"));
        // Replace the original-at-top with [evil-at-top, original-wrapping-sig].
        let attack = without_sig.replace(&legit, &format!("{evil}{legit_with_sig_inside}"));

        let err = verify_saml_signature(&attack, std::slice::from_ref(&fx.cert_der)).unwrap_err();
        assert!(
            format!("{err}").contains("only one is allowed"),
            "XSW-8 not rejected by Assertion-count guard: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // CVE corpus — regression tests for published SAML library
    // vulnerabilities. Each test names the CVE and the design property of
    // *this* implementation that makes the corresponding attack infeasible.
    // -----------------------------------------------------------------------

    /// CVE-2024-45409 (Sept 2024, ruby-saml / GitLab SSO): the verifier
    /// trusted the X.509 certificate embedded in the response's `<KeyInfo>`
    /// rather than the configured IdP certificate. An attacker could forge
    /// a response, sign it with their own key, embed their own cert in
    /// KeyInfo, and authenticate as anyone.
    ///
    /// Our defense: `verify_saml_signature` accepts pinned IdP certificates
    /// as a `&[Vec<u8>]` parameter from the caller and never reads
    /// `<ds:KeyInfo>`. To prove that, we sign a response with attacker key A
    /// and embed an X509Data block carrying cert A in KeyInfo, then verify
    /// against the legitimate IdP cert B (the attacker does not hold B's
    /// private key). Verification must fail.
    #[test]
    fn cve_2024_45409_keyinfo_cert_must_not_be_trusted() {
        let attacker = Fixture::new();
        let signed_by_attacker = sign_fresh(&attacker, "_a1", "");
        // Embed the attacker's own cert in KeyInfo. A vulnerable verifier
        // would use this cert to check the signature, see a match, and
        // accept the response.
        let attacker_cert_b64 =
            base64::engine::general_purpose::STANDARD.encode(&attacker.cert_der);
        let with_keyinfo = signed_by_attacker.replace(
            "</ds:Signature>",
            &format!(
                "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{attacker_cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"
            ),
        );
        // Verify with the *real* IdP cert (TEST_CERT2_DER) — a separate
        // self-signed cert whose private key the attacker does not have.
        let err = verify_saml_signature(&with_keyinfo, &[TEST_CERT2_DER.to_vec()])
            .expect_err("KeyInfo cert must not be trusted");
        assert!(
            format!("{err}").contains("verification failed"),
            "CVE-2024-45409 regression: verifier appears to trust KeyInfo cert. err={err}"
        );
    }

    /// CVE-2019-3878 (mod_auth_mellon): under certain configurations the
    /// module accepted SAML responses with no signature at all, allowing
    /// trivial authentication bypass.
    ///
    /// Our defense: `verify_saml_signature` unconditionally requires a
    /// `<ds:Signature>` element and errors out otherwise; the SAML client
    /// pipeline has no "skip verification" branch. This test strips the
    /// entire Signature element from an otherwise valid response and
    /// confirms rejection.
    #[test]
    fn cve_2019_3878_unsigned_response_must_be_rejected() {
        let fx = Fixture::new();
        let xml_signed = sign_fresh(&fx, "_a1", "");
        let sig_start = xml_signed
            .find("<ds:Signature")
            .expect("Signature in sign_fresh output");
        let sig_end =
            xml_signed.find("</ds:Signature>").expect("Signature close") + "</ds:Signature>".len();
        let unsigned = format!("{}{}", &xml_signed[..sig_start], &xml_signed[sig_end..]);
        let err = verify_saml_signature(&unsigned, std::slice::from_ref(&fx.cert_der))
            .expect_err("unsigned response must be rejected");
        assert!(
            format!("{err}").contains("ds:Signature"),
            "CVE-2019-3878 regression: missing Signature must be a hard error. err={err}"
        );
    }

    /// CVE-2017-11428 (OneLogin python-saml / ruby-saml comment truncation):
    /// `<NameID>admin@admin.com<!---->.evil@evil.com</NameID>` was
    /// canonicalized to the full concatenated text (comments stripped) for
    /// signature purposes, but some SP libraries used an XPath / DOM helper
    /// that returned only the first text node, yielding `admin@admin.com`.
    /// IdP signs the full string; SP reads the truncated one; account
    /// takeover.
    ///
    /// Our defense: `text_content` walks `XmlNode::Text` children and
    /// concatenates them in order, with comments already absent from the
    /// parsed tree (they are discarded at parse time, matching the
    /// without-comments exc-c14n variant we use). The text the SP extracts
    /// is therefore byte-identical to what was signed. This test parses a
    /// comment-truncation payload and asserts the extracted value is the
    /// full concatenation rather than the prefix.
    #[test]
    fn cve_2017_11428_comment_truncation_in_text_extraction() {
        use crate::saml::c14n::parse_xml_tree;
        let xml = "<NameID>admin@admin.com<!--cut-->.evil@evil.com</NameID>";
        let root = parse_xml_tree(xml).expect("parse_xml_tree");
        let extracted = text_content(&root);
        assert_eq!(
            extracted, "admin@admin.com.evil@evil.com",
            "CVE-2017-11428 regression: text extraction must concatenate all \
             text nodes around comments rather than truncate at the first."
        );
    }

    // -----------------------------------------------------------------------
    // Redirect-binding query parameter canonicalisation.
    //
    // The verifier and any caller-side query parser must agree on which
    // segments are protected. If we accept `Relay%53tate` and a downstream
    // web framework decodes it to `RelayState`, the framework sees a
    // relay-state the IdP never signed. Refuse the whole query instead.
    // -----------------------------------------------------------------------

    #[test]
    fn redirect_params_reject_encoded_alias_of_protected_name() {
        // `Relay%53tate` decodes to `RelayState`. Downstream parsers would
        // treat that as a legit RelayState; the signature verifier does not
        // include it in the signed input. Refuse the query.
        let err =
            RedirectBindingParams::parse("SAMLResponse=abc&SigAlg=x&Signature=y&Relay%53tate=zzz")
                .unwrap_err();
        assert!(
            format!("{err}").contains("non-canonical name"),
            "got: {err}"
        );
    }

    #[test]
    fn redirect_params_reject_duplicate_protected_name() {
        // Duplicates in raw form: both segments have the canonical spelling.
        let err = RedirectBindingParams::parse(
            "SAMLResponse=first&SAMLResponse=second&SigAlg=x&Signature=y",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("duplicate"), "got: {err}");
    }

    #[test]
    fn redirect_params_reject_duplicate_across_raw_and_encoded() {
        // Second copy would decode to a protected name but is not spelled
        // canonically — `Relay%53tate=` is refused as an encoded alias
        // before the duplicate check runs. Either way, the query is
        // fail-closed.
        let err = RedirectBindingParams::parse(
            "SAMLResponse=x&SigAlg=y&Signature=z&RelayState=one&Relay%53tate=two",
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("non-canonical name") || msg.contains("duplicate"),
            "got: {msg}"
        );
    }

    #[test]
    fn redirect_params_ignore_unrelated_extra_segments() {
        // Extra caller-added parameters (e.g. `tenant=acme`) must not
        // affect signature verification and must not be rejected.
        let params = RedirectBindingParams::parse(
            "SAMLResponse=abc&SigAlg=x&Signature=y&RelayState=z&tenant=acme",
        )
        .expect("parse");
        assert_eq!(params.get("RelayState"), Some("RelayState=z"));
        assert_eq!(params.get("SAMLResponse"), Some("SAMLResponse=abc"));
        assert_eq!(params.get("SigAlg"), Some("SigAlg=x"));
        assert_eq!(params.get("Signature"), Some("Signature=y"));
    }

    #[test]
    fn redirect_params_optional_relay_state() {
        let params =
            RedirectBindingParams::parse("SAMLResponse=abc&SigAlg=x&Signature=y").expect("parse");
        assert_eq!(params.get("RelayState"), None);
    }

    /// The entry point accepts only `SAMLRequest` and `SAMLResponse`
    /// as the signed-payload parameter. Anything else is refused
    /// before touching the query, so `RelayState` and other query
    /// params cannot be used as the "signed payload" slot.
    #[test]
    fn verify_redirect_binding_signature_rejects_unknown_message_param() {
        let fx = Fixture::new();
        let err = verify_redirect_binding_signature(
            "SAMLResponse=abc&SigAlg=x&Signature=y",
            "RelayState",
            "abc",
            std::slice::from_ref(&fx.cert_der),
        )
        .expect_err("must refuse non-message parameter names");
        assert!(
            format!("{err}").contains("unsupported SAML Redirect binding message parameter"),
            "got: {err}"
        );
    }
}
