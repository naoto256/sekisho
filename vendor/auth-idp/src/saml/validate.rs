//! Post-signature SAML Response semantic validation.
//!
//! XML signature verification (see `signature.rs`) tells us *who* signed the
//! document, but not *what it means*. A signed assertion can be replayed,
//! used against the wrong SP, or accepted before/after its lifetime unless
//! we check the conditions the IdP set:
//!
//! - `samlp:Response/saml:Issuer` and `saml:Assertion/saml:Issuer` must
//!   both equal the IdP entity ID the caller expects — under the trusted-key
//!   assumption this binds the signed text to the configured identifier;
//!   possession of that key can sign the expected Issuer, so the check
//!   presupposes an uncompromised signer.
//! - `samlp:Response/@Destination` must equal our ACS URL (defeats
//!   cross-SP replay: stolen assertion meant for tenant X posted to our
//!   ACS).
//! - `samlp:Response/@InResponseTo` must equal the AuthnRequest ID we
//!   generated for this browser session (defeats replay across sessions
//!   and binds the assertion to *our* initiation).
//! - `saml:Conditions/@NotBefore` / `@NotOnOrAfter` bound the assertion's
//!   validity in time — a 60 s clock-skew leeway is permitted.
//! - `saml:AudienceRestriction/saml:Audience` must contain our entity ID
//!   (defeats cross-tenant replay within the same IdP).
//! - `saml:SubjectConfirmationData/@Recipient` must equal our ACS URL,
//!   and its `@NotOnOrAfter` must be in the future.
//!
//! This module does **not** verify XML signatures — that must happen first
//! in the caller. These checks run on the already-signature-verified
//! Response element.

use super::c14n::{XmlElement, XmlNode};
use super::signature::VerifiedLoginResponse;
use crate::error::{Error, Result};

/// Maximum tolerated clock skew between this SP and the IdP, in seconds.
/// Mirrors the default used by most SAML stacks (pysaml2, Shibboleth SP).
const CLOCK_SKEW_SECS: i64 = 60;

/// Data extracted from a signed SAML Response and its Assertion, ready for
/// claim mapping after validation has passed.
#[derive(Debug)]
pub struct ValidatedAssertion {
    pub name_id: String,
    pub attributes: std::collections::HashMap<String, Vec<String>>,
    /// `AuthnStatement/@SessionIndex` from the first AuthnStatement, if
    /// the IdP issued one. Required by Entra on a later `LogoutRequest`
    /// to correlate the request to the authenticated session.
    /// `None` when the IdP omits AuthnStatement or its SessionIndex
    /// attribute — the LogoutRequest then omits the element and the
    /// IdP falls back to NameID matching.
    pub session_index: Option<String>,
}

/// Validation inputs supplied by the SP.
pub struct AssertionValidationContext<'a> {
    /// IdP entity ID the caller expects to see in both
    /// `samlp:Response/saml:Issuer` and `saml:Assertion/saml:Issuer`.
    /// Typically extracted from the IdP metadata's `EntityDescriptor`
    /// at startup.
    pub expected_issuer: &'a str,
    pub expected_audience: &'a str,
    pub expected_destination: &'a str,
    pub expected_recipient: &'a str,
    /// The AuthnRequest ID we generated when starting the SP-initiated
    /// flow. `None` accepts IdP-initiated flow as well.
    pub expected_in_response_to: Option<&'a str>,
    pub now: chrono::DateTime<chrono::Utc>,
}

/// Walk a signature-verified SAML Response, run every validation listed in
/// the module doc, and return the Assertion's claim inputs on success.
pub(super) fn validate_response(
    verified: &VerifiedLoginResponse,
    ctx: &AssertionValidationContext<'_>,
) -> Result<ValidatedAssertion> {
    let root = verified.root();
    let namespaces = super::NamespaceIndex::new(root);
    if root.local_name != "Response" || !namespaces.matches(root, super::NS_PROTOCOL) {
        return Err(Error::AuthenticationFailed(format!(
            "SAML response root is {}, expected Response",
            root.local_name
        )));
    }

    // --- Response Status ---
    // SAML Core §3.2.2 requires every Response to carry a Status. Even
    // when the signature verifies and an Assertion is present, a
    // non-Success StatusCode means the IdP is reporting failure — an
    // `AuthnFailed` or `Responder` response with a leftover Assertion
    // must not be treated as a successful authentication.
    let status_code = find_status_code(root, &namespaces);
    match status_code.as_deref() {
        Some("urn:oasis:names:tc:SAML:2.0:status:Success") => {}
        Some(other) => {
            return Err(Error::AuthenticationFailed(format!(
                "SAML Response StatusCode {other:?} is not Success"
            )));
        }
        None => {
            return Err(Error::AuthenticationFailed(
                "SAML Response missing Status/StatusCode".into(),
            ));
        }
    }

    // --- Response Issuer ---
    // SAML Core makes Issuer optional on Response but mandatory on a
    // signed Response (§5.4). Absence prevents the required issuer
    // check; refuse to proceed.
    let response_issuer =
        find_first_child_in_namespace(&namespaces, root, "Issuer", super::NS_ASSERTION)
            .map(text_content)
            .ok_or_else(|| {
                Error::AuthenticationFailed("SAML Response missing Issuer element".into())
            })?;
    if response_issuer != ctx.expected_issuer {
        return Err(Error::AuthenticationFailed(format!(
            "SAML Response Issuer {response_issuer:?} does not match expected IdP {:?}",
            ctx.expected_issuer
        )));
    }

    // --- Response-level attributes ---
    let destination = get_attr(root, "Destination");
    let in_response_to = get_attr(root, "InResponseTo");

    if let Some(dest) = destination {
        if dest != ctx.expected_destination {
            return Err(Error::AuthenticationFailed(format!(
                "SAML Response Destination {dest:?} does not match ACS URL {:?}",
                ctx.expected_destination
            )));
        }
    } else {
        // Destination is OPTIONAL in the schema but REQUIRED when the
        // Response is signed (SAML Core §5.4.1). Absence prevents the
        // required destination check, leaving cross-SP replay unblocked
        // — refuse.
        return Err(Error::AuthenticationFailed(
            "SAML Response missing required Destination attribute".into(),
        ));
    }

    if let Some(expected) = ctx.expected_in_response_to {
        match in_response_to {
            Some(got) if got == expected => {}
            Some(got) => {
                return Err(Error::AuthenticationFailed(format!(
                    "SAML Response InResponseTo {got:?} does not match AuthnRequest ID"
                )));
            }
            None => {
                return Err(Error::AuthenticationFailed(
                    "SAML Response missing InResponseTo (expected SP-initiated flow)".into(),
                ));
            }
        }
    }

    // The capability binds this exact direct-child Assertion to the verified
    // signature target; semantic validation cannot select a different node.
    let assertion = verified.assertion();
    if !namespaces.matches(assertion, super::NS_ASSERTION) {
        return Err(Error::AuthenticationFailed(
            "SAML Assertion namespace is invalid".into(),
        ));
    }

    // --- Assertion Issuer ---
    // Mandatory on every Assertion (SAML Core §2.5). Must also match
    // the expected IdP — Response Issuer alone is insufficient because
    // a Response can carry an Assertion authored by a different entity.
    let assertion_issuer =
        find_first_child_in_namespace(&namespaces, assertion, "Issuer", super::NS_ASSERTION)
            .map(text_content)
            .ok_or_else(|| {
                Error::AuthenticationFailed("SAML Assertion missing Issuer element".into())
            })?;
    if assertion_issuer != ctx.expected_issuer {
        return Err(Error::AuthenticationFailed(format!(
            "SAML Assertion Issuer {assertion_issuer:?} does not match expected IdP {:?}",
            ctx.expected_issuer
        )));
    }

    // --- Conditions ---
    if let Some(conditions) =
        find_first_child_in_namespace(&namespaces, assertion, "Conditions", super::NS_ASSERTION)
    {
        if let Some(nb) = get_attr(conditions, "NotBefore") {
            let nb = parse_saml_time(nb)?;
            if ctx.now + chrono::Duration::seconds(CLOCK_SKEW_SECS) < nb {
                return Err(Error::AuthenticationFailed(format!(
                    "SAML Assertion Conditions/@NotBefore {nb} is in the future"
                )));
            }
        }
        if let Some(noa) = get_attr(conditions, "NotOnOrAfter") {
            let noa = parse_saml_time(noa)?;
            if ctx.now - chrono::Duration::seconds(CLOCK_SKEW_SECS) >= noa {
                return Err(Error::AuthenticationFailed(format!(
                    "SAML Assertion Conditions/@NotOnOrAfter {noa} has passed"
                )));
            }
        }

        // AudienceRestriction — Audience must contain our entity ID.
        // A single Assertion may carry multiple AudienceRestriction
        // elements; the IdP's intent is the INTERSECTION, so we require
        // every restriction to list us.
        let ars = find_all_children_in_namespace(
            &namespaces,
            conditions,
            "AudienceRestriction",
            super::NS_ASSERTION,
        );
        let mut has_any = false;
        for ar in ars {
            has_any = true;
            let audiences: Vec<String> =
                find_all_children_in_namespace(&namespaces, ar, "Audience", super::NS_ASSERTION)
                    .into_iter()
                    .map(text_content)
                    .collect();
            if !audiences.iter().any(|a| a == ctx.expected_audience) {
                return Err(Error::AuthenticationFailed(format!(
                    "SAML Assertion AudienceRestriction does not include {:?} (got {:?})",
                    ctx.expected_audience, audiences
                )));
            }
        }
        if !has_any {
            return Err(Error::AuthenticationFailed(
                "SAML Assertion Conditions missing AudienceRestriction".into(),
            ));
        }
    } else {
        // A Conditions element is OPTIONAL in the SAML schema. Absence
        // means no audience check and no time-bound — refuse.
        return Err(Error::AuthenticationFailed(
            "SAML Assertion missing Conditions element".into(),
        ));
    }

    // --- Subject / SubjectConfirmation / SubjectConfirmationData ---
    let subject =
        find_first_child_in_namespace(&namespaces, assertion, "Subject", super::NS_ASSERTION)
            .ok_or_else(|| {
                Error::AuthenticationFailed("SAML Assertion missing Subject element".into())
            })?;

    let name_id_elem =
        find_first_child_in_namespace(&namespaces, subject, "NameID", super::NS_ASSERTION)
            .ok_or_else(|| {
                Error::AuthenticationFailed("SAML Assertion Subject missing NameID".into())
            })?;
    let name_id = text_content(name_id_elem);
    if name_id.is_empty() {
        return Err(Error::AuthenticationFailed(
            "SAML Assertion NameID is empty".into(),
        ));
    }

    // At least one SubjectConfirmation with method bearer must point at us.
    let confirmations = find_all_children_in_namespace(
        &namespaces,
        subject,
        "SubjectConfirmation",
        super::NS_ASSERTION,
    );
    if confirmations.is_empty() {
        return Err(Error::AuthenticationFailed(
            "SAML Assertion Subject missing SubjectConfirmation".into(),
        ));
    }
    let mut any_valid_confirmation = false;
    for sc in confirmations {
        // Only Method="urn:oasis:names:tc:SAML:2.0:cm:bearer" is in scope
        // for web-SSO; anything else (holder-of-key, sender-vouches) would
        // require extra proof we don't carry — treat as unsupported and skip.
        let method = get_attr(sc, "Method").unwrap_or("");
        if method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
            continue;
        }
        let Some(scd) = find_first_child_in_namespace(
            &namespaces,
            sc,
            "SubjectConfirmationData",
            super::NS_ASSERTION,
        ) else {
            continue;
        };

        // Recipient MUST match our ACS URL — mandatory for bearer.
        let recipient = get_attr(scd, "Recipient").ok_or_else(|| {
            Error::AuthenticationFailed("SAML SubjectConfirmationData missing Recipient".into())
        })?;
        if recipient != ctx.expected_recipient {
            return Err(Error::AuthenticationFailed(format!(
                "SAML SubjectConfirmationData Recipient {recipient:?} does not match ACS URL"
            )));
        }

        // NotOnOrAfter MUST be in the future (bearer expiry).
        let noa = get_attr(scd, "NotOnOrAfter").ok_or_else(|| {
            Error::AuthenticationFailed("SAML SubjectConfirmationData missing NotOnOrAfter".into())
        })?;
        let noa = parse_saml_time(noa)?;
        if ctx.now - chrono::Duration::seconds(CLOCK_SKEW_SECS) >= noa {
            return Err(Error::AuthenticationFailed(format!(
                "SAML SubjectConfirmationData NotOnOrAfter {noa} has passed"
            )));
        }

        // NotBefore is OPTIONAL in SubjectConfirmationData; if present, validate.
        if let Some(nb) = get_attr(scd, "NotBefore") {
            let nb = parse_saml_time(nb)?;
            if ctx.now + chrono::Duration::seconds(CLOCK_SKEW_SECS) < nb {
                return Err(Error::AuthenticationFailed(format!(
                    "SAML SubjectConfirmationData NotBefore {nb} is in the future"
                )));
            }
        }

        // If the IdP echoes InResponseTo in SCD, it must match our AuthnRequest
        // ID (Entra does this; enforcing adds a second line of defence).
        if let (Some(expected), Some(got)) =
            (ctx.expected_in_response_to, get_attr(scd, "InResponseTo"))
            && got != expected
        {
            return Err(Error::AuthenticationFailed(format!(
                "SAML SubjectConfirmationData InResponseTo {got:?} does not match AuthnRequest ID"
            )));
        }

        any_valid_confirmation = true;
        break;
    }
    if !any_valid_confirmation {
        return Err(Error::AuthenticationFailed(
            "SAML Assertion has no bearer SubjectConfirmation matching the ACS".into(),
        ));
    }

    // --- AttributeStatement -> attributes map ---
    let mut attributes: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for attr_stmt in find_all_children_in_namespace(
        &namespaces,
        assertion,
        "AttributeStatement",
        super::NS_ASSERTION,
    ) {
        for attr in
            find_all_children_in_namespace(&namespaces, attr_stmt, "Attribute", super::NS_ASSERTION)
        {
            let Some(name) = get_attr(attr, "Name") else {
                continue;
            };
            let values: Vec<String> = find_all_children_in_namespace(
                &namespaces,
                attr,
                "AttributeValue",
                super::NS_ASSERTION,
            )
            .into_iter()
            .map(text_content)
            .collect();
            attributes
                .entry(name.to_string())
                .or_default()
                .extend(values);
        }
    }

    // --- AuthnStatement/@SessionIndex (optional) ---
    // Captured for SP-initiated Single Logout: the IdP needs the
    // SessionIndex value in our LogoutRequest to identify which of a
    // user's concurrent sessions to terminate. If the IdP omits both
    // AuthnStatement and the SessionIndex attribute, we record `None`
    // and later build a LogoutRequest without the element.
    let session_index = find_first_child_in_namespace(
        &namespaces,
        assertion,
        "AuthnStatement",
        super::NS_ASSERTION,
    )
    .and_then(|stmt| get_attr(stmt, "SessionIndex"))
    .map(|s| s.to_string())
    .filter(|s| !s.is_empty());

    Ok(ValidatedAssertion {
        name_id,
        attributes,
        session_index,
    })
}

// --- XML tree helpers. c14n::XmlElement does not expose these itself, and
// keeping them private to this module avoids tempting unrelated callers into
// using the internal tree representation. ---

fn get_attr<'a>(elem: &'a XmlElement, name: &str) -> Option<&'a str> {
    elem.attributes
        .iter()
        .find(|(_, local, _)| local == name)
        .map(|(_, _, value)| value.as_str())
}

fn find_first_child_in_namespace<'a>(
    namespaces: &super::NamespaceIndex,
    elem: &'a XmlElement,
    local: &str,
    namespace: &str,
) -> Option<&'a XmlElement> {
    for child in &elem.children {
        if let XmlNode::Element(e) = child
            && e.local_name == local
            && namespaces.matches(e, namespace)
        {
            return Some(e);
        }
    }
    None
}

fn find_all_children_in_namespace<'a>(
    namespaces: &super::NamespaceIndex,
    elem: &'a XmlElement,
    local: &str,
    namespace: &str,
) -> Vec<&'a XmlElement> {
    elem.children
        .iter()
        .filter_map(|c| match c {
            XmlNode::Element(e) if e.local_name == local && namespaces.matches(e, namespace) => {
                Some(e)
            }
            _ => None,
        })
        .collect()
}

fn text_content(elem: &XmlElement) -> String {
    // SAML attribute values and NameIDs are single text children in practice;
    // concatenate just in case the IdP emits multiple text nodes split by
    // entities or CDATA sections.
    let mut out = String::new();
    for child in &elem.children {
        if let XmlNode::Text(t) = child {
            out.push_str(t);
        }
    }
    out
}

/// Extract the `Value` attribute of the top-level `<Status><StatusCode>`
/// pair on a SAML Response root. Nested `<StatusCode>` chains carry the
/// detail (e.g. `RequestDenied`), but the top-level value is what
/// determines Success / non-Success and is what §3.2.2 mandates.
fn find_status_code(root: &XmlElement, namespaces: &super::NamespaceIndex) -> Option<String> {
    let status = find_first_child_in_namespace(namespaces, root, "Status", super::NS_PROTOCOL)?;
    let status_code =
        find_first_child_in_namespace(namespaces, status, "StatusCode", super::NS_PROTOCOL)?;
    get_attr(status_code, "Value").map(|s| s.to_string())
}

/// Parse a SAML timestamp (`xsd:dateTime`) — RFC 3339 in practice.
fn parse_saml_time(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::AuthenticationFailed(format!("invalid SAML timestamp {s:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::c14n::parse_xml_tree;

    /// Minimal SAML Response skeleton — fill in attrs via `{...}` placeholders
    /// so tests can mutate individual fields. NOT signed; signature
    /// verification happens at a layer we deliberately mock out for these
    /// unit tests.
    struct ResponseParts<'a> {
        destination: &'a str,
        in_response_to: &'a str,
        audience: &'a str,
        recipient: &'a str,
        scd_not_on_or_after: &'a str,
        conditions_not_before: &'a str,
        conditions_not_on_or_after: &'a str,
        extra_assertion: &'a str,
    }

    fn build_response(p: ResponseParts<'_>) -> String {
        let ResponseParts {
            destination,
            in_response_to,
            audience,
            recipient,
            scd_not_on_or_after,
            conditions_not_before,
            conditions_not_on_or_after,
            extra_assertion,
        } = p;
        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z" Destination="{destination}" InResponseTo="{in_response_to}">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="{recipient}" NotOnOrAfter="{scd_not_on_or_after}" InResponseTo="{in_response_to}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{conditions_not_before}" NotOnOrAfter="{conditions_not_on_or_after}">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
        <saml:AttributeValue>alice@example.com</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>{extra_assertion}
</samlp:Response>"#
        )
    }

    fn default_parts() -> ResponseParts<'static> {
        ResponseParts {
            destination: "https://sp.example.com/saml/acs",
            in_response_to: "_req123",
            audience: "https://sp.example.com",
            recipient: "https://sp.example.com/saml/acs",
            scd_not_on_or_after: "2099-01-01T00:00:00Z",
            conditions_not_before: "2000-01-01T00:00:00Z",
            conditions_not_on_or_after: "2099-01-01T00:00:00Z",
            extra_assertion: "",
        }
    }

    fn default_response() -> String {
        build_response(default_parts())
    }

    fn default_ctx() -> AssertionValidationContext<'static> {
        AssertionValidationContext {
            expected_issuer: "https://idp.example.com",
            expected_audience: "https://sp.example.com",
            expected_destination: "https://sp.example.com/saml/acs",
            expected_recipient: "https://sp.example.com/saml/acs",
            expected_in_response_to: Some("_req123"),
            now: chrono::DateTime::parse_from_rfc3339("2026-04-19T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        }
    }

    fn validate(xml: &str, ctx: &AssertionValidationContext<'_>) -> Result<ValidatedAssertion> {
        let root = parse_xml_tree(xml).expect("parse");
        let verified = VerifiedLoginResponse::assume_verified_for_test(root)?;
        validate_response(&verified, ctx)
    }

    #[test]
    fn accepts_valid_assertion() {
        let v = validate(&default_response(), &default_ctx()).expect("valid");
        assert_eq!(v.name_id, "alice@example.com");
        assert_eq!(
            v.attributes
                .get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
                .unwrap(),
            &vec!["alice@example.com".to_string()]
        );
    }

    #[test]
    fn rejects_expired_assertion() {
        let xml = build_response(ResponseParts {
            conditions_not_on_or_after: "2020-01-01T00:00:00Z", // past
            ..default_parts()
        });
        let err = validate(&xml, &default_ctx()).unwrap_err();
        assert!(
            format!("{err}").contains("NotOnOrAfter"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_future_assertion() {
        let xml = build_response(ResponseParts {
            conditions_not_before: "2099-01-01T00:00:00Z",
            conditions_not_on_or_after: "2100-01-01T00:00:00Z",
            ..default_parts()
        });
        let err = validate(&xml, &default_ctx()).unwrap_err();
        assert!(format!("{err}").contains("NotBefore"), "unexpected: {err}");
    }

    #[test]
    fn rejects_non_success_status_code() {
        // A signed Response can carry a valid Assertion while
        // simultaneously reporting Responder / AuthnFailed at the
        // top-level StatusCode. Treating that as success would let a
        // partial-failure envelope authenticate the user.
        let xml = build_response(default_parts()).replace(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:oasis:names:tc:SAML:2.0:status:Responder",
        );
        let err = validate(&xml, &default_ctx()).unwrap_err();
        assert!(
            format!("{err}").contains("StatusCode") && format!("{err}").contains("Responder"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_missing_status() {
        // Drop the whole `<samlp:Status>` element. Signature-verified or
        // not, a Response with no StatusCode does not indicate an
        // authentication outcome and must be refused.
        let xml = build_response(default_parts()).replace(
            "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>",
            "",
        );
        let err = validate(&xml, &default_ctx()).unwrap_err();
        assert!(format!("{err}").contains("Status"), "unexpected: {err}");
    }

    #[test]
    fn foreign_status_collision_does_not_satisfy_required_slot() {
        let foreign = r#"<ext:Status xmlns:ext="urn:example:extension"><ext:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></ext:Status>"#;
        let without_genuine = build_response(default_parts()).replace(
            "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>",
            foreign,
        );
        let err = validate(&without_genuine, &default_ctx()).unwrap_err();
        assert!(format!("{err}").contains("Status"), "unexpected: {err}");

        let with_genuine = build_response(default_parts()).replacen(
            "<samlp:Status>",
            &format!("{foreign}<samlp:Status>"),
            1,
        );
        validate(&with_genuine, &default_ctx())
            .expect("foreign Status collision must not hide the genuine SAML Status");
    }

    #[test]
    fn rejects_wrong_response_issuer() {
        let ctx = AssertionValidationContext {
            expected_issuer: "https://other-idp.example.com",
            ..default_ctx()
        };
        let err = validate(&default_response(), &ctx).unwrap_err();
        assert!(
            format!("{err}").contains("Response Issuer"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_wrong_assertion_issuer() {
        // Response Issuer matches expected, but Assertion Issuer does
        // not — must still reject.
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z" Destination="https://sp.example.com/saml/acs" InResponseTo="_req123">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z">
    <saml:Issuer>https://evil.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>alice@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="https://sp.example.com/saml/acs" NotOnOrAfter="2099-01-01T00:00:00Z" InResponseTo="_req123"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#;
        let err = validate(xml, &default_ctx()).unwrap_err();
        assert!(
            format!("{err}").contains("Assertion Issuer"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_wrong_audience() {
        let xml = build_response(ResponseParts {
            audience: "https://evil.example.com",
            ..default_parts()
        });
        let err = validate(&xml, &default_ctx()).unwrap_err();
        assert!(format!("{err}").contains("Audience"), "unexpected: {err}");
    }

    #[test]
    fn rejects_wrong_destination() {
        let xml = build_response(ResponseParts {
            destination: "https://other.example.com/acs",
            ..default_parts()
        });
        let err = validate(&xml, &default_ctx()).unwrap_err();
        assert!(
            format!("{err}").contains("Destination"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_wrong_recipient() {
        let xml = build_response(ResponseParts {
            recipient: "https://other.example.com/acs",
            ..default_parts()
        });
        let err = validate(&xml, &default_ctx()).unwrap_err();
        assert!(format!("{err}").contains("Recipient"), "unexpected: {err}");
    }

    #[test]
    fn rejects_wrong_in_response_to() {
        let xml = build_response(ResponseParts {
            in_response_to: "_other_req",
            ..default_parts()
        });
        let err = validate(&xml, &default_ctx()).unwrap_err();
        assert!(
            format!("{err}").contains("InResponseTo"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_multiple_assertions() {
        // Inject a second sibling Assertion — classic XSW wrapping attempt
        // (the extraction logic should not even look at it).
        let extra = r#"
  <saml:Assertion ID="_a2" Version="2.0" IssueInstant="2026-04-19T00:00:00Z">
    <saml:Issuer>https://evil.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>evil@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>"#;
        let xml = build_response(ResponseParts {
            extra_assertion: extra,
            ..default_parts()
        });
        let err = validate(&xml, &default_ctx()).unwrap_err();
        assert!(
            format!("{err}").contains("exactly one direct-child Assertion"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_missing_scd() {
        // Strip the SubjectConfirmationData entirely — not a valid bearer
        // confirmation without it.
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z" Destination="https://sp.example.com/saml/acs" InResponseTo="_req123">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>alice@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#;
        let err = validate(xml, &default_ctx()).unwrap_err();
        assert!(
            format!("{err}").contains("SubjectConfirmation"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn captures_session_index_from_authn_statement() {
        // Entra-shaped assertion: AuthnStatement with a SessionIndex
        // attribute. Must land in ValidatedAssertion.session_index so
        // the outgoing LogoutRequest can echo it back.
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z" Destination="https://sp.example.com/saml/acs" InResponseTo="_req123">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>alice@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="https://sp.example.com/saml/acs" NotOnOrAfter="2099-01-01T00:00:00Z" InResponseTo="_req123"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-04-19T00:00:00Z" SessionIndex="_abcd1234-entra-session">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>"#;
        let v = validate(xml, &default_ctx()).expect("valid");
        assert_eq!(v.session_index.as_deref(), Some("_abcd1234-entra-session"));
    }

    #[test]
    fn session_index_none_when_authn_statement_absent() {
        // Baseline: the default test builder omits AuthnStatement, so
        // ValidatedAssertion.session_index must be None. Covers the
        // IdP-omitted-AuthnStatement path where no SessionIndex is
        // available.
        let v = validate(&default_response(), &default_ctx()).expect("valid");
        assert!(v.session_index.is_none());
    }

    #[test]
    fn session_index_none_when_attribute_missing() {
        // AuthnStatement present but no SessionIndex attribute.
        // Treat as absent rather than reading an empty string.
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z" Destination="https://sp.example.com/saml/acs" InResponseTo="_req123">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-04-19T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>alice@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="https://sp.example.com/saml/acs" NotOnOrAfter="2099-01-01T00:00:00Z" InResponseTo="_req123"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-04-19T00:00:00Z"/>
  </saml:Assertion>
</samlp:Response>"#;
        let v = validate(xml, &default_ctx()).expect("valid");
        assert!(v.session_index.is_none());
    }

    #[test]
    fn leeway_allows_small_clock_skew() {
        // Conditions NotBefore is 30s ahead of `now` — should still pass
        // given the 60s leeway.
        let xml = build_response(ResponseParts {
            conditions_not_before: "2026-04-19T00:00:30Z",
            ..default_parts()
        });
        validate(&xml, &default_ctx()).expect("within leeway");
    }
}
