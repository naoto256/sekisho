//! Exclusive XML Canonicalization (W3C exc-c14n#, without comments).
//!
//! Implements the subset of C14N needed for SAML signature verification:
//! namespace normalization, attribute sorting, and proper escaping.

use crate::error::{Error, Result};
use std::collections::{BTreeSet, HashMap, HashSet};
use zeroize::Zeroize;

pub(super) const MAX_XML_ELEMENT_DEPTH: usize = 64;
pub(super) const XML_DEPTH_LIMIT_ERROR: &str = "SAML XML exceeds the maximum element depth of 64";

#[derive(Debug, Clone)]
pub struct XmlElement {
    pub prefix: String,
    pub local_name: String,
    /// Namespace declarations on this element: (prefix, uri).
    /// prefix="" means default namespace (xmlns="...").
    pub ns_decls: Vec<(String, String)>,
    /// Non-namespace attributes: (prefix, local_name, value).
    pub attributes: Vec<(String, String, String)>,
    pub children: Vec<XmlNode>,
}

#[derive(Debug, Clone)]
pub enum XmlNode {
    Element(XmlElement),
    Text(String),
    /// XML processing instruction. `target` is the PI name (e.g. `xml-stylesheet`),
    /// `data` is the remainder after the first whitespace (may be empty).
    /// Canonicalized as `<?target data?>` (or `<?target?>` when data is empty).
    ProcessingInstruction {
        target: String,
        data: String,
    },
}

impl Drop for XmlElement {
    fn drop(&mut self) {
        self.prefix.zeroize();
        self.local_name.zeroize();
        for (prefix, uri) in &mut self.ns_decls {
            prefix.zeroize();
            uri.zeroize();
        }
        for (prefix, name, value) in &mut self.attributes {
            prefix.zeroize();
            name.zeroize();
            value.zeroize();
        }
        for child in &mut self.children {
            match child {
                XmlNode::Element(_) => {}
                XmlNode::Text(text) => text.zeroize(),
                XmlNode::ProcessingInstruction { target, data } => {
                    target.zeroize();
                    data.zeroize();
                }
            }
        }
    }
}

/// Parse an XML string into a tree.
///
/// Element depth is capped at 64, counting the document root as depth 1.
/// The caller remains responsible for bounding the raw HTTP or form input
/// before passing decoded XML to this parser.
pub fn parse_xml_tree(xml: &str) -> Result<XmlElement> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_str(xml);
    let mut stack: Vec<XmlElement> = Vec::new();
    let mut root: Option<XmlElement> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                ensure_element_depth(stack.len() + 1)?;
                stack.push(parse_start_element(e)?);
            }
            Ok(Event::Empty(ref e)) => {
                ensure_element_depth(stack.len() + 1)?;
                let elem = parse_start_element(e)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlNode::Element(elem));
                } else {
                    root = Some(elem);
                }
            }
            Ok(Event::Text(ref e)) => {
                let decoded = e.decode().map_err(|err| {
                    Error::AuthenticationFailed(format!("XML decode error: {err}"))
                })?;
                let text = quick_xml::escape::unescape(&decoded)
                    .map_err(|err| {
                        Error::AuthenticationFailed(format!("XML unescape error: {err}"))
                    })?
                    .to_string();
                if !text.is_empty()
                    && let Some(parent) = stack.last_mut()
                {
                    parent.children.push(XmlNode::Text(text));
                }
            }
            Ok(Event::GeneralRef(ref e)) => {
                let decoded = e.decode().map_err(|err| {
                    Error::AuthenticationFailed(format!("XML reference decode error: {err}"))
                })?;
                // SAML forbids DTD-defined entities; accepting only XML's
                // built-ins and numeric references keeps XXE-shaped inputs
                // fail-closed instead of expanding caller-controlled names.
                let escaped = format!("&{decoded};");
                let text = quick_xml::escape::unescape(&escaped)
                    .map_err(|err| {
                        Error::AuthenticationFailed(format!("XML reference error: {err}"))
                    })?
                    .to_string();
                if !text.is_empty()
                    && let Some(parent) = stack.last_mut()
                {
                    parent.children.push(XmlNode::Text(text));
                }
            }
            Ok(Event::CData(ref e)) => {
                // CDATA section content is appended as raw text. The canonicalizer's
                // escape_text re-escapes <, &, etc. on output, so the CDATA wrapper
                // collapses to the equivalent entity-escaped form per exc-c14n.
                let text = String::from_utf8_lossy(e.as_ref()).into_owned();
                if !text.is_empty()
                    && let Some(parent) = stack.last_mut()
                {
                    parent.children.push(XmlNode::Text(text));
                }
            }
            Ok(Event::PI(ref e)) => {
                // quick-xml exposes the PI body (everything between `<?` and `?>`)
                // as a single byte slice. Per XML 1.0 §2.6, target is the leading
                // Name and data is whatever follows the first whitespace run.
                let body = String::from_utf8_lossy(e.as_ref()).into_owned();
                let (target, data) = match body.find(|c: char| c.is_ascii_whitespace()) {
                    Some(idx) => {
                        let (t, rest) = body.split_at(idx);
                        (t.to_string(), rest.trim_start().to_string())
                    }
                    None => (body, String::new()),
                };
                if let Some(parent) = stack.last_mut() {
                    parent
                        .children
                        .push(XmlNode::ProcessingInstruction { target, data });
                }
            }
            Ok(Event::End(_)) => {
                let elem = stack
                    .pop()
                    .ok_or_else(|| Error::AuthenticationFailed("unbalanced XML tags".into()))?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlNode::Element(elem));
                } else {
                    root = Some(elem);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {} // skip comments and events we do not model (DTDs, decls, etc.)
            Err(e) => return Err(Error::AuthenticationFailed(format!("XML parse error: {e}"))),
        }
    }

    root.ok_or_else(|| Error::AuthenticationFailed("empty XML document".into()))
}

fn ensure_element_depth(depth: usize) -> Result<()> {
    if depth > MAX_XML_ELEMENT_DEPTH {
        return Err(Error::AuthenticationFailed(XML_DEPTH_LIMIT_ERROR.into()));
    }
    Ok(())
}

fn parse_start_element(e: &quick_xml::events::BytesStart) -> Result<XmlElement> {
    let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
    let (prefix, local_name) = match full_name.split_once(':') {
        Some((p, l)) => (p.to_string(), l.to_string()),
        None => (String::new(), full_name),
    };

    let mut ns_decls = Vec::new();
    let mut attributes = Vec::new();

    for attr_result in e.attributes() {
        let attr = attr_result
            .map_err(|err| Error::AuthenticationFailed(format!("XML attribute error: {err}")))?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|err| Error::AuthenticationFailed(format!("XML attr value error: {err}")))?
            .to_string();

        if key == "xmlns" {
            ns_decls.push((String::new(), value));
        } else if let Some(ns_prefix) = key.strip_prefix("xmlns:") {
            ns_decls.push((ns_prefix.to_string(), value));
        } else {
            let (ap, al) = match key.split_once(':') {
                Some((p, l)) => (p.to_string(), l.to_string()),
                None => (String::new(), key),
            };
            attributes.push((ap, al, value));
        }
    }

    Ok(XmlElement {
        prefix,
        local_name,
        ns_decls,
        attributes,
        children: Vec::new(),
    })
}

/// Find an element by local name, collecting namespace declarations from ancestors.
/// Returns the element and the accumulated namespace context (prefix -> URI) from all
/// ancestor elements (not including the target element's own declarations).
#[allow(dead_code)]
pub fn find_element_with_ancestor_ns<'a>(
    elem: &'a XmlElement,
    target_local: &str,
    ancestor_ns: &HashMap<String, String>,
) -> Option<(&'a XmlElement, HashMap<String, String>)> {
    if elem.local_name == target_local {
        return Some((elem, ancestor_ns.clone()));
    }

    let mut child_ns = ancestor_ns.clone();
    for (prefix, uri) in &elem.ns_decls {
        child_ns.insert(prefix.clone(), uri.clone());
    }

    for child in &elem.children {
        if let XmlNode::Element(child_elem) = child
            && let Some(result) = find_element_with_ancestor_ns(child_elem, target_local, &child_ns)
        {
            return Some(result);
        }
    }

    None
}

/// Apply Exclusive C14N (without comments) to an element subtree.
/// `ancestor_ns` contains namespace declarations in scope from ancestors in the
/// original document. The canonicalized output starts with no rendered namespaces.
pub fn exclusive_c14n(elem: &XmlElement, ancestor_ns: &HashMap<String, String>) -> Vec<u8> {
    exclusive_c14n_with_prefix_list(elem, ancestor_ns, &HashSet::new())
}

/// Apply Exclusive C14N (without comments) with an InclusiveNamespaces PrefixList.
/// Prefixes in `prefix_list` are treated as visibly utilized everywhere in the
/// subtree, so namespace declarations for them survive even when no
/// element/attribute in the canonicalized form references the prefix. This is the
/// `<ec:InclusiveNamespaces PrefixList="..."/>` extension defined by the
/// xml-exc-c14n spec for IdPs that depend on inherited namespaces
/// inside signed content.
pub fn exclusive_c14n_with_prefix_list(
    elem: &XmlElement,
    ancestor_ns: &HashMap<String, String>,
    prefix_list: &HashSet<String>,
) -> Vec<u8> {
    let mut output = Vec::new();
    let rendered = HashMap::new();
    exc_c14n_element(elem, ancestor_ns, &rendered, prefix_list, &mut output);
    output
}

fn exc_c14n_element(
    elem: &XmlElement,
    available_ns: &HashMap<String, String>,
    parent_rendered: &HashMap<String, String>,
    prefix_list: &HashSet<String>,
    output: &mut Vec<u8>,
) {
    // Available namespaces = ancestors + this element's own declarations
    let mut elem_available = available_ns.clone();
    for (prefix, uri) in &elem.ns_decls {
        elem_available.insert(prefix.clone(), uri.clone());
    }

    // Collect visibly utilized prefixes: self prefix, attribute prefixes,
    // plus any prefix forced inclusive by the InclusiveNamespaces PrefixList.
    let mut utilized: BTreeSet<&str> = BTreeSet::new();
    utilized.insert(&elem.prefix);
    for (attr_prefix, _, _) in &elem.attributes {
        if !attr_prefix.is_empty() {
            utilized.insert(attr_prefix);
        }
    }
    for prefix in prefix_list {
        utilized.insert(prefix.as_str());
    }

    // Determine which namespace declarations need to be rendered.
    // Special case for the default namespace (empty prefix): exc-c14n requires
    // emitting `xmlns=""` to "undeclare" it when an ancestor had a default ns
    // and this element does not visibly use one.
    let mut ns_to_render: Vec<(&str, &str)> = Vec::new();
    for prefix in &utilized {
        if let Some(uri) = elem_available.get(*prefix) {
            let already = parent_rendered.get(*prefix);
            if already != Some(uri) {
                ns_to_render.push((prefix, uri));
            }
        } else if prefix.is_empty() {
            // No default ns in scope but parent rendered one — emit xmlns="" to undeclare.
            if let Some(prev) = parent_rendered.get("")
                && !prev.is_empty()
            {
                ns_to_render.push(("", ""));
            }
        }
    }

    // Sort namespace declarations:
    //   1. default ns declaration (xmlns="...") first
    //   2. then xmlns:prefix declarations sorted by prefix
    ns_to_render.sort_by(|a, b| match (a.0.is_empty(), b.0.is_empty()) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.0.cmp(b.0),
    });

    // Updated rendered context for children
    let mut new_rendered = parent_rendered.clone();
    for (prefix, uri) in &ns_to_render {
        new_rendered.insert(prefix.to_string(), uri.to_string());
    }

    // --- Output opening tag ---
    output.extend_from_slice(b"<");
    write_qname(output, &elem.prefix, &elem.local_name);

    // Namespace declarations
    for (prefix, uri) in &ns_to_render {
        if prefix.is_empty() {
            output.extend_from_slice(b" xmlns=\"");
        } else {
            output.extend_from_slice(b" xmlns:");
            output.extend_from_slice(prefix.as_bytes());
            output.extend_from_slice(b"=\"");
        }
        output.extend_from_slice(escape_attr_value(uri).as_bytes());
        output.push(b'"');
    }

    // Attribute sort order per W3C XML C14N spec (and goxmldsig's SortedAttrs):
    //   1. Unprefixed attributes (no namespace) come before any prefixed ones,
    //      sorted lexicographically by local name.
    //   2. Prefixed attributes are then sorted by their resolved namespace URI,
    //      and ties are broken by local name.
    // Namespace declarations themselves are emitted separately above and are
    // not included here.
    let mut sorted_attrs: Vec<&(String, String, String)> = elem.attributes.iter().collect();
    sorted_attrs.sort_by(|a, b| {
        let (a_unprefixed, a_ns) = if a.0.is_empty() {
            (true, "")
        } else {
            (
                false,
                elem_available.get(&a.0).map(|s| s.as_str()).unwrap_or(""),
            )
        };
        let (b_unprefixed, b_ns) = if b.0.is_empty() {
            (true, "")
        } else {
            (
                false,
                elem_available.get(&b.0).map(|s| s.as_str()).unwrap_or(""),
            )
        };
        // Unprefixed attributes sort before prefixed ones.
        match (a_unprefixed, b_unprefixed) {
            (true, false) => return std::cmp::Ordering::Less,
            (false, true) => return std::cmp::Ordering::Greater,
            _ => {}
        }
        // Same class: compare by namespace URI, then local name.
        a_ns.cmp(b_ns).then_with(|| a.1.cmp(&b.1))
    });

    for (ap, al, av) in sorted_attrs {
        output.push(b' ');
        write_qname(output, ap, al);
        output.extend_from_slice(b"=\"");
        output.extend_from_slice(escape_attr_value(av).as_bytes());
        output.push(b'"');
    }

    output.push(b'>');

    // --- Children ---
    for child in &elem.children {
        match child {
            XmlNode::Element(child_elem) => {
                exc_c14n_element(
                    child_elem,
                    &elem_available,
                    &new_rendered,
                    prefix_list,
                    output,
                );
            }
            XmlNode::Text(text) => {
                output.extend_from_slice(escape_text(text).as_bytes());
            }
            XmlNode::ProcessingInstruction { target, data } => {
                // Per exc-c14n: `<?target?>` if data is empty, else
                // `<?target<space>data?>` with exactly one space between the
                // two parts. Inside an element subtree no surrounding line
                // feeds are emitted.
                output.extend_from_slice(b"<?");
                output.extend_from_slice(target.as_bytes());
                if !data.is_empty() {
                    output.push(b' ');
                    output.extend_from_slice(data.as_bytes());
                }
                output.extend_from_slice(b"?>");
            }
        }
    }

    // --- Closing tag (always present, even for empty elements) ---
    output.extend_from_slice(b"</");
    write_qname(output, &elem.prefix, &elem.local_name);
    output.push(b'>');
}

fn write_qname(output: &mut Vec<u8>, prefix: &str, local_name: &str) {
    if !prefix.is_empty() {
        output.extend_from_slice(prefix.as_bytes());
        output.push(b':');
    }
    output.extend_from_slice(local_name.as_bytes());
}

/// C14N text node escaping.
fn escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#xD;")
}

/// C14N attribute value escaping.
fn escape_attr_value(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

#[cfg(test)]
mod resource_bound_tests {
    use super::*;

    fn nested_start_document(depth: usize) -> String {
        assert!(depth > 0);
        let mut xml = "<n>".repeat(depth);
        xml.push_str(&"</n>".repeat(depth));
        xml
    }

    fn nested_empty_document(depth: usize) -> String {
        assert!(depth > 0);
        let parent_depth = depth - 1;
        let mut xml = "<n>".repeat(parent_depth);
        xml.push_str("<leaf/>");
        xml.push_str(&"</n>".repeat(parent_depth));
        xml
    }

    fn assert_depth_limit(error: Error) {
        assert!(
            matches!(
                error,
                Error::AuthenticationFailed(ref message)
                    if message == XML_DEPTH_LIMIT_ERROR
            ),
            "depth overflow must return the fixed safe error"
        );
    }

    #[test]
    fn start_elements_enforce_root_one_depth_boundary() {
        parse_xml_tree(&nested_start_document(MAX_XML_ELEMENT_DEPTH))
            .expect("depth 64 Start elements must be accepted");
        let error = parse_xml_tree(&nested_start_document(MAX_XML_ELEMENT_DEPTH + 1))
            .expect_err("depth 65 Start element must be rejected");
        assert_depth_limit(error);
    }

    #[test]
    fn empty_elements_enforce_root_one_depth_boundary() {
        parse_xml_tree(&nested_empty_document(MAX_XML_ELEMENT_DEPTH))
            .expect("depth 64 Empty element must be accepted");
        let error = parse_xml_tree(&nested_empty_document(MAX_XML_ELEMENT_DEPTH + 1))
            .expect_err("depth 65 Empty element must be rejected");
        assert_depth_limit(error);
    }
}
