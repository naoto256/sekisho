//! Tests for Exclusive XML Canonicalization (W3C exc-c14n#, without comments).
//!
//! Vectors are borrowed from goxmldsig's `canonicalize_test.go`, which derives
//! them from W3C XML Signature interop tests. They cover: simple subtree,
//! default-namespace pruning, default-namespace re-declaration, attribute
//! sort order on a real SAML AuthnRequest, and the InclusiveNamespaces
//! PrefixList extension.

use super::c14n::{exclusive_c14n, exclusive_c14n_with_prefix_list, parse_xml_tree};
use std::collections::{HashMap, HashSet};

fn c14n(xml: &str) -> String {
    let root = parse_xml_tree(xml).expect("parse failed");
    let bytes = exclusive_c14n(&root, &HashMap::new());
    String::from_utf8(bytes).expect("output is not UTF-8")
}

fn c14n_with_prefix_list(xml: &str, prefixes: &[&str]) -> String {
    let root = parse_xml_tree(xml).expect("parse failed");
    let set: HashSet<String> = prefixes.iter().map(|s| s.to_string()).collect();
    let bytes = exclusive_c14n_with_prefix_list(&root, &HashMap::new(), &set);
    String::from_utf8(bytes).expect("output is not UTF-8")
}

#[test]
fn default_ns_is_pruned_when_unused() {
    // Default namespace `xmlns="urn:baz"` is in scope but no element/attribute
    // visibly uses it, so exc-c14n must drop it.
    let input = r#"<foo:Foo xmlns="urn:baz" xmlns:foo="urn:foo"><foo:Bar></foo:Bar></foo:Foo>"#;
    let expected = r#"<foo:Foo xmlns:foo="urn:foo"><foo:Bar></foo:Bar></foo:Foo>"#;
    assert_eq!(c14n(input), expected);
}

#[test]
fn default_ns_redeclared_on_child_kept() {
    // Each level redeclares the default namespace; both must survive.
    let input = r#"<Foo xmlns="urn:foo"><Bar xmlns="uri:bar"></Bar></Foo>"#;
    let expected = r#"<Foo xmlns="urn:foo"><Bar xmlns="uri:bar"></Bar></Foo>"#;
    assert_eq!(c14n(input), expected);
}

#[test]
fn xmldoc_attribute_order() {
    // Attribute ordering: namespace decls (default first, then prefixed) come
    // before regular attributes, sorted by key.
    let input = r#"<Foo ID="id1619705532971228558789260" xmlns:bar="urn:bar" xmlns="urn:foo"><bar:Baz></bar:Baz></Foo>"#;
    let expected = r#"<Foo xmlns="urn:foo" ID="id1619705532971228558789260"><bar:Baz xmlns:bar="urn:bar"></bar:Baz></Foo>"#;
    assert_eq!(c14n(input), expected);
}

#[test]
fn saml_authn_request_full() {
    // Real-world SAML AuthnRequest: many attributes (must be sorted), comment
    // (stripped in without-comments variant), nested namespace propagation
    // (saml: only re-declared on elements that actually use it).
    let input = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_88a93ebe-abdf-48cd-9ed0-b0dd1b252909" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://saml2.test.astuart.co/sso/saml2" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0" IssueInstant="2016-04-28T15:37:17" Destination="http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO"><!-- Some Comment --><saml:Issuer>https://saml2.test.astuart.co/sso/saml2</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format=""/><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"#;
    let expected = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceIndex="0" AssertionConsumerServiceURL="https://saml2.test.astuart.co/sso/saml2" AttributeConsumingServiceIndex="0" Destination="http://idp.astuart.co/idp/profile/SAML2/Redirect/SSO" ID="_88a93ebe-abdf-48cd-9ed0-b0dd1b252909" IssueInstant="2016-04-28T15:37:17" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://saml2.test.astuart.co/sso/saml2</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format=""></samlp:NameIDPolicy><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"#;
    assert_eq!(c14n(input), expected);
}

#[test]
fn prefix_list_keeps_unused_xs_at_root() {
    // PrefixList = "xs": the xs prefix must be treated as visibly utilized at
    // the root even though no element/attribute uses it. The redundant
    // re-declaration on the child must therefore be pruned.
    let input = r#"<foo:Foo xmlns:foo="urn:foo" xmlns:xs="http://www.w3.org/2001/XMLSchema"><foo:Bar xmlns:xs="http://www.w3.org/2001/XMLSchema"></foo:Bar></foo:Foo>"#;
    let expected = r#"<foo:Foo xmlns:foo="urn:foo" xmlns:xs="http://www.w3.org/2001/XMLSchema"><foo:Bar></foo:Bar></foo:Foo>"#;
    assert_eq!(c14n_with_prefix_list(input, &["xs"]), expected);
}

#[test]
fn empty_element_uses_explicit_close_tag() {
    // exc-c14n forbids self-closing tags; `<Bar/>` must become `<Bar></Bar>`.
    let input = r#"<Foo xmlns="urn:foo"><Bar/></Foo>"#;
    let expected = r#"<Foo xmlns="urn:foo"><Bar></Bar></Foo>"#;
    assert_eq!(c14n(input), expected);
}

#[test]
fn comments_are_stripped() {
    let input = r#"<Foo xmlns="urn:foo"><!-- hi --><Bar/></Foo>"#;
    let expected = r#"<Foo xmlns="urn:foo"><Bar></Bar></Foo>"#;
    assert_eq!(c14n(input), expected);
}
