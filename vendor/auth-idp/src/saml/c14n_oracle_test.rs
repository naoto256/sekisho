//! Oracle-based differential tests for Exclusive XML Canonicalization.
//!
//! Runs each corpus input through both `xmllint --exc-c14n` (libxml2, the
//! reference implementation) and our `exclusive_c14n`, then asserts the two
//! byte sequences are identical. This catches divergences that hand-written
//! `assert_eq!` tests cannot foresee — particularly around attribute escaping,
//! namespace inheritance/undeclaration, and whitespace/line-ending handling.
//!
//! If `xmllint` is not available on the host, every test in this module is a
//! no-op (passes with a one-shot stderr warning). macOS ships it at
//! `/usr/bin/xmllint`; on Debian/Ubuntu install `libxml2-utils`.
//!
//! Corpus scope intentionally complements `c14n_test.rs`:
//! - attribute value escaping (CR/LF/TAB, quote/amp/lt, mixed runs)
//! - text node escaping (literal CR vs LF, lt/gt/amp, char refs)
//! - default-namespace inheritance and explicit `xmlns=""` undeclaration
//! - prefix re-mapping across nesting levels
//! - attribute sort across mixed prefixed/unprefixed
//! - the special `xml:` prefix (lang/space/base)
//! - empty element expansion, whitespace between attributes

use super::c14n::{exclusive_c14n, parse_xml_tree};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Lazily resolves the xmllint binary path. `None` means "not installed";
/// callers should skip rather than fail. Cached so we only stat once.
fn xmllint_path() -> Option<&'static str> {
    static PATH: OnceLock<Option<&'static str>> = OnceLock::new();
    *PATH.get_or_init(|| {
        for candidate in ["/usr/bin/xmllint", "/opt/homebrew/bin/xmllint"] {
            if std::path::Path::new(candidate).exists() {
                return Some(candidate);
            }
        }
        // Fall back to PATH lookup.
        let out = Command::new("sh")
            .args(["-c", "command -v xmllint"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let path = String::from_utf8(out.stdout).ok()?;
        let path = path.trim();
        if path.is_empty() {
            None
        } else {
            // Leak intentionally — this is process-lifetime.
            Some(Box::leak(path.to_string().into_boxed_str()) as &'static str)
        }
    })
}

/// Pipe `input` into `xmllint --exc-c14n` and return stdout, with comments
/// stripped to match our without-comments variant. Returns `None` only when
/// xmllint is unavailable (so the caller can skip).
///
/// xmllint's CLI only exposes the with-comments variant of exclusive C14N
/// (there is no `--exc-c14n-without-comments` flag). Our implementation is
/// without-comments, which is the variant SAML SignedInfo references via
/// `http://www.w3.org/2001/10/xml-exc-c14n#`. The two variants only differ in
/// whether `<!-- ... -->` survives, so we post-process xmllint's output to
/// remove comment markers. Comment substrings are well-defined in canonical
/// XML and never overlap with attribute/text content, so a non-greedy regex
/// is safe.
///
/// Processing instructions are *not* stripped — our impl drops them, xmllint
/// preserves them, and the divergence is tracked separately by an ignored
/// test below. xmllint errors (invalid XML, etc.) panic, because such inputs
/// should never reach the oracle in this curated corpus.
fn xmllint_c14n(input: &str) -> Option<Vec<u8>> {
    let path = xmllint_path()?;
    let mut child = Command::new(path)
        .args(["--exc-c14n", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xmllint");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write to xmllint stdin");
    let out = child.wait_with_output().expect("wait xmllint");
    assert!(
        out.status.success(),
        "xmllint failed on corpus input. stderr:\n{}\ninput:\n{}",
        String::from_utf8_lossy(&out.stderr),
        input,
    );
    Some(strip_comments(&out.stdout))
}

/// Remove every `<!-- ... -->` substring (non-greedy). Operates on raw bytes
/// because XML canonical output is byte-defined.
fn strip_comments(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"<!--")
            && let Some(end) = find_subslice(&bytes[i + 4..], b"-->")
        {
            i += 4 + end + 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Render bytes as a human-readable string for diff output, escaping the few
/// whitespace bytes that would otherwise be invisible in a terminal.
fn show(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\n' => s.push_str("\\n\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{:02x}", b)),
        }
    }
    s
}

/// Core oracle check. Skips silently if xmllint is unavailable.
fn assert_c14n_matches_oracle(name: &str, input: &str) {
    let Some(expected) = xmllint_c14n(input) else {
        static WARNED: OnceLock<()> = OnceLock::new();
        WARNED.get_or_init(|| {
            eprintln!(
                "[c14n_oracle_test] xmllint not found; skipping oracle checks. \
                 Install libxml2-utils (Debian/Ubuntu) or rely on macOS's /usr/bin/xmllint."
            );
        });
        return;
    };

    let root = parse_xml_tree(input)
        .unwrap_or_else(|e| panic!("[{name}] our parser rejected input: {e:?}\ninput: {input}"));
    let actual = exclusive_c14n(&root, &HashMap::new());

    if actual != expected {
        panic!(
            "[{name}] c14n divergence from xmllint oracle\n\
             input:\n{input}\n\n\
             expected ({} bytes):\n{}\n\n\
             actual   ({} bytes):\n{}\n",
            expected.len(),
            show(&expected),
            actual.len(),
            show(&actual),
        );
    }
}

// ---------------------------------------------------------------------------
// Curated corpus. Each test is one XML input.
// ---------------------------------------------------------------------------

#[test]
fn attr_value_escapes_lt_amp_quote() {
    assert_c14n_matches_oracle(
        "attr_value_escapes_lt_amp_quote",
        r#"<r a="&lt;&amp;&quot;v" b="plain"/>"#,
    );
}

#[test]
fn attr_value_escapes_whitespace_chars() {
    // libxml2 expands &#9; / &#10; / &#13; during parsing; exc-c14n must then
    // re-encode them in attribute context as &#x9; / &#xA; / &#xD;.
    assert_c14n_matches_oracle(
        "attr_value_escapes_whitespace_chars",
        r#"<r a="tab&#9;lf&#10;cr&#13;end"/>"#,
    );
}

#[test]
fn text_lt_amp_escaped_but_quote_left_alone() {
    assert_c14n_matches_oracle(
        "text_lt_amp_escaped_but_quote_left_alone",
        r#"<r>&lt;tag&gt;&amp;ent "quoted"</r>"#,
    );
}

#[test]
fn text_literal_cr_becomes_xd_entity() {
    // &#13; in text content is preserved as &#xD; (CR is the only whitespace
    // that survives parse/normalize round-trip in text nodes).
    assert_c14n_matches_oracle("text_literal_cr_becomes_xd_entity", r#"<r>a&#13;b</r>"#);
}

#[test]
fn text_numeric_charrefs_expand_to_literals() {
    // &#9; / &#10; in text round-trip to literal tab/newline (NOT entities)
    // in the canonicalized form.
    assert_c14n_matches_oracle(
        "text_numeric_charrefs_expand_to_literals",
        r#"<r>a&#9;b&#10;c</r>"#,
    );
}

#[test]
fn empty_element_expands_to_open_close_pair() {
    assert_c14n_matches_oracle(
        "empty_element_expands_to_open_close_pair",
        r#"<r><a/><b></b></r>"#,
    );
}

#[test]
fn default_ns_undeclared_when_child_has_no_default_ns() {
    // Ancestor declares default ns; child element is unprefixed but resets
    // the default ns. exc-c14n must emit xmlns="" on the child to undeclare.
    assert_c14n_matches_oracle(
        "default_ns_undeclared_when_child_has_no_default_ns",
        r#"<r xmlns="urn:r"><a xmlns=""><b/></a></r>"#,
    );
}

#[test]
fn default_ns_redeclared_to_different_uri_on_child() {
    assert_c14n_matches_oracle(
        "default_ns_redeclared_to_different_uri_on_child",
        r#"<r xmlns="urn:r"><a xmlns="urn:a"><b/></a></r>"#,
    );
}

#[test]
fn prefix_only_visibly_used_inside_subtree_moves_down() {
    // xmlns:p is declared on root but only used by a grandchild — exc-c14n
    // must move the declaration down to where it is first visible.
    assert_c14n_matches_oracle(
        "prefix_only_visibly_used_inside_subtree_moves_down",
        r#"<r xmlns:p="urn:p"><a><p:b/></a></r>"#,
    );
}

#[test]
fn unused_prefix_decl_is_dropped() {
    // xmlns:unused is never referenced anywhere — exc-c14n must drop it.
    assert_c14n_matches_oracle(
        "unused_prefix_decl_is_dropped",
        r#"<r xmlns:unused="urn:nope"><a/></r>"#,
    );
}

#[test]
fn prefix_remapped_to_different_uri_at_deeper_level() {
    // p maps to urn:1 at root, then is rebound to urn:2 inside <a>. Both
    // declarations must survive in the canonicalized form because both are
    // visibly used at their own level.
    assert_c14n_matches_oracle(
        "prefix_remapped_to_different_uri_at_deeper_level",
        r#"<p:r xmlns:p="urn:1"><p:a xmlns:p="urn:2"><p:b/></p:a></p:r>"#,
    );
}

#[test]
fn attr_sort_mixes_unprefixed_and_prefixed() {
    // Per W3C C14N: unprefixed attributes first (lex by local name), then
    // prefixed (lex by namespace URI, ties broken by local name).
    assert_c14n_matches_oracle(
        "attr_sort_mixes_unprefixed_and_prefixed",
        r#"<r xmlns:a="urn:a" xmlns:b="urn:b" b:y="1" zz="2" a:x="3" aa="4"/>"#,
    );
}

#[test]
fn attr_sort_same_prefix_uri_ties_broken_by_local_name() {
    assert_c14n_matches_oracle(
        "attr_sort_same_prefix_uri_ties_broken_by_local_name",
        r#"<r xmlns:p="urn:p" p:c="3" p:a="1" p:b="2"/>"#,
    );
}

#[test]
fn xml_lang_and_xml_space_are_treated_as_xml_namespace() {
    // The xml: prefix is bound by spec to http://www.w3.org/XML/1998/namespace.
    // It is never declared explicitly, never emitted in xmlns:xml="...", and
    // attributes carrying it sort after unprefixed attributes.
    assert_c14n_matches_oracle(
        "xml_lang_and_xml_space_are_treated_as_xml_namespace",
        r#"<r xml:lang="en" b="1" xml:space="preserve"/>"#,
    );
}

#[test]
fn extra_whitespace_between_attributes_is_normalized() {
    assert_c14n_matches_oracle(
        "extra_whitespace_between_attributes_is_normalized",
        r#"<r   a="1"    b="2"   />"#,
    );
}

#[test]
fn xml_declaration_is_stripped() {
    assert_c14n_matches_oracle(
        "xml_declaration_is_stripped",
        r#"<?xml version="1.0" encoding="UTF-8"?><r><a/></r>"#,
    );
}

#[test]
fn comments_are_stripped_without_comments_variant() {
    assert_c14n_matches_oracle(
        "comments_are_stripped_without_comments_variant",
        r#"<r><!-- header --><a/><!-- mid --><b/><!-- trailer --></r>"#,
    );
}

#[test]
fn nested_text_with_mixed_content() {
    assert_c14n_matches_oracle(
        "nested_text_with_mixed_content",
        r#"<r>head<a>inner</a>mid<b/>tail</r>"#,
    );
}

#[test]
fn saml_assertion_shaped_input() {
    // Smaller-than-full but SAML-shaped — exercises attribute sort + nested
    // re-declaration of saml: prefix on children that actually use it.
    assert_c14n_matches_oracle(
        "saml_assertion_shaped_input",
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a" IssueInstant="2024-01-01T00:00:00Z" Version="2.0"><saml:Issuer>idp</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">u@e</saml:NameID></saml:Subject></saml:Assertion>"#,
    );
}

// ---------------------------------------------------------------------------
// CDATA and processing instructions: now first-class in parse_xml_tree.
// These were divergences against xmllint before parse_xml_tree learned the
// two corresponding quick-xml events.
// ---------------------------------------------------------------------------

#[test]
fn cdata_section_text_is_escaped_in_canonical_form() {
    // CDATA wraps `<x>&y</x>` raw; canonical form must escape it as if it
    // were entity-encoded text.
    assert_c14n_matches_oracle(
        "cdata_section_text_is_escaped_in_canonical_form",
        r#"<r><![CDATA[<x>&y</x>]]></r>"#,
    );
}

#[test]
fn cdata_concatenates_with_adjacent_text_nodes() {
    assert_c14n_matches_oracle(
        "cdata_concatenates_with_adjacent_text_nodes",
        r#"<r>before<![CDATA[<mid>]]>after</r>"#,
    );
}

#[test]
fn processing_instruction_with_data_is_preserved() {
    assert_c14n_matches_oracle(
        "processing_instruction_with_data_is_preserved",
        r#"<r><?target data?><a/></r>"#,
    );
}

#[test]
fn processing_instruction_without_data_is_preserved() {
    assert_c14n_matches_oracle(
        "processing_instruction_without_data_is_preserved",
        r#"<r><?target?><a/></r>"#,
    );
}

#[test]
fn processing_instruction_data_with_embedded_whitespace_kept() {
    // Multi-token data: `<?stylesheet href="x" type="y"?>` — exactly one
    // space between target and data, internal whitespace preserved verbatim.
    assert_c14n_matches_oracle(
        "processing_instruction_data_with_embedded_whitespace_kept",
        r#"<r><?stylesheet href="x" type="y"?></r>"#,
    );
}
