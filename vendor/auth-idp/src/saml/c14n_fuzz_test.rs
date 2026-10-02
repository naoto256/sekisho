//! Generation-based differential fuzzing for Exclusive XML Canonicalization.
//!
//! Builds a randomly-shaped `NodeSpec` tree from small fixed pools of name
//! tokens, prefixes, namespace URIs, attribute values, text fragments,
//! CDATA bodies, PI bodies, and comments, then renders it to XML source and
//! checks that `xmllint --exc-c14n` and our `exclusive_c14n` produce the
//! same bytes. Complements the curated corpus in `c14n_oracle_test.rs`:
//! the corpus is hand-aimed at known traps, the fuzzer explores the shape
//! space the corpus cannot anticipate.
//!
//! Design choices for keeping the generator well-formed:
//! - The root element implicitly declares `xmlns:p1`, `xmlns:p2`, `xmlns:p3`
//!   (to fixed URIs) and a default namespace. Any prefix is therefore
//!   always in scope; descendants may shadow via their own ns_decls.
//! - At every element, attributes are deduped by (resolved namespace URI,
//!   local name) — the well-formedness rule XML namespaces imposes.
//! - At every element, ns_decls are deduped by target (Default or Prefix(p))
//!   so the source XML never repeats `xmlns:p1=...` twice on one tag.
//! - All pool entries for text / attr values / CDATA / PI / comments are
//!   chosen to be valid in their respective XML production. xmllint's
//!   parser is the final arbiter; if it rejects the rendered source the
//!   test panics with the offending input so the pools can be tightened.

use super::c14n::{exclusive_c14n, parse_xml_tree};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Pools. Small on purpose — collisions across the same prefix/local-name
// surface attribute-sort and namespace-shadowing edge cases more reliably.
// ---------------------------------------------------------------------------

const NCNAMES: &[&str] = &["a", "b", "x", "yz"];
const PREFIXES: &[&str] = &["p1", "p2", "p3"];
const NS_URIS: &[&str] = &["urn:1", "urn:2", "urn:3"];

/// Default-namespace URI implicitly declared at the root. Choosing a
/// recognisable token makes oracle failures easier to read.
const ROOT_DEFAULT_NS: &str = "urn:root";

/// Source-form attribute values. Each entry is exactly what gets inserted
/// between the quotes in the rendered XML, so character references like
/// `&#9;` survive into the parser before attribute-value normalisation.
const ATTR_VALUES: &[&str] = &[
    "",
    "x",
    "x&amp;y",
    "x&lt;y",
    "x&quot;y",
    "x&#9;y",
    "x&#10;y",
    "x&#13;y",
    "with space",
    "&amp;&amp;&amp;",
];

/// Source-form text node contents. Same rule as ATTR_VALUES — these go into
/// the document raw, so escape sequences must already be expressed.
const TEXTS: &[&str] = &[
    "hello",
    "&amp;&lt;&gt;",
    "&#9;tab",
    "&#10;lf",
    "&#13;cr",
    "  spaces  ",
    "mixed text",
];

/// CDATA bodies — verbatim character data, must not contain `]]>`.
const CDATA_BODIES: &[&str] = &["plain", "with <angle> & amp", "line1\nline2", ""];

const PI_TARGETS: &[&str] = &["pi", "stylesheet", "tgt"];

/// PI data — must not contain `?>`.
const PI_DATAS: &[&str] = &["", "data", "k=\"v\"", "multi  word"];

/// Comment bodies. Must not contain `--` and must not end with `-`.
const COMMENT_BODIES: &[&str] = &["", " c ", " a b ", "x"];

// ---------------------------------------------------------------------------
// Spec types (deterministic representation of generated XML)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum NodeSpec {
    Element(ElementSpec),
    Text(usize),
    CData(usize),
    Pi(usize, usize),
    Comment(usize),
}

#[derive(Debug, Clone)]
struct ElementSpec {
    /// `None` = unprefixed (bound to default namespace in scope).
    prefix: Option<usize>,
    local: usize,
    ns_decls: Vec<NsDecl>,
    attrs: Vec<AttrSpec>,
    children: Vec<NodeSpec>,
}

#[derive(Debug, Clone, Copy)]
struct NsDecl {
    target: NsTarget,
    uri: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NsTarget {
    Default,
    Prefix(usize),
}

#[derive(Debug, Clone, Copy)]
struct AttrSpec {
    prefix: Option<usize>,
    local: usize,
    value: usize,
}

// ---------------------------------------------------------------------------
// proptest strategies
// ---------------------------------------------------------------------------

fn ns_decl_strategy() -> impl Strategy<Value = NsDecl> {
    prop_oneof![
        (0usize..NS_URIS.len()).prop_map(|u| NsDecl {
            target: NsTarget::Default,
            uri: u
        }),
        (0usize..PREFIXES.len(), 0usize..NS_URIS.len()).prop_map(|(p, u)| NsDecl {
            target: NsTarget::Prefix(p),
            uri: u,
        }),
    ]
}

fn attr_strategy() -> impl Strategy<Value = AttrSpec> {
    (
        prop::option::of(0usize..PREFIXES.len()),
        0usize..NCNAMES.len(),
        0usize..ATTR_VALUES.len(),
    )
        .prop_map(|(prefix, local, value)| AttrSpec {
            prefix,
            local,
            value,
        })
}

fn node_spec_strategy() -> BoxedStrategy<NodeSpec> {
    let leaf = prop_oneof![
        1 => (0usize..TEXTS.len()).prop_map(NodeSpec::Text),
        1 => (0usize..CDATA_BODIES.len()).prop_map(NodeSpec::CData),
        1 => (0usize..PI_TARGETS.len(), 0usize..PI_DATAS.len())
            .prop_map(|(t, d)| NodeSpec::Pi(t, d)),
        1 => (0usize..COMMENT_BODIES.len()).prop_map(NodeSpec::Comment),
        2 => (
            prop::option::of(0usize..PREFIXES.len()),
            0usize..NCNAMES.len(),
            prop::collection::vec(ns_decl_strategy(), 0..3),
            prop::collection::vec(attr_strategy(), 0..3),
        ).prop_map(|(p, l, ns, a)| NodeSpec::Element(ElementSpec {
            prefix: p,
            local: l,
            ns_decls: ns,
            attrs: a,
            children: vec![],
        })),
    ];
    leaf.prop_recursive(3, 48, 4, |inner| {
        (
            prop::option::of(0usize..PREFIXES.len()),
            0usize..NCNAMES.len(),
            prop::collection::vec(ns_decl_strategy(), 0..3),
            prop::collection::vec(attr_strategy(), 0..3),
            prop::collection::vec(inner, 0..4),
        )
            .prop_map(|(p, l, ns, a, c)| {
                NodeSpec::Element(ElementSpec {
                    prefix: p,
                    local: l,
                    ns_decls: ns,
                    attrs: a,
                    children: c,
                })
            })
    })
    .boxed()
}

fn root_strategy() -> BoxedStrategy<ElementSpec> {
    (
        prop::option::of(0usize..PREFIXES.len()),
        0usize..NCNAMES.len(),
        prop::collection::vec(ns_decl_strategy(), 0..3),
        prop::collection::vec(attr_strategy(), 0..3),
        prop::collection::vec(node_spec_strategy(), 0..4),
    )
        .prop_map(|(p, l, ns, a, c)| ElementSpec {
            prefix: p,
            local: l,
            ns_decls: ns,
            attrs: a,
            children: c,
        })
        .boxed()
}

// ---------------------------------------------------------------------------
// Renderer: NodeSpec tree -> XML source string.
//
// Implicitly declares all pool prefixes (and a default namespace) on the
// root so any prefix in any descendant is in scope. Inside each element:
//   - dedupe ns_decls by target (last wins)
//   - resolve attribute prefixes against the current scope, dedupe by
//     (resolved namespace URI, local name) so the rendered source is XML-
//     namespaces-well-formed.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Scope {
    /// `None` key = default namespace; `Some(prefix)` = a prefixed namespace.
    bindings: HashMap<Option<&'static str>, &'static str>,
}

impl Scope {
    fn root() -> Self {
        let mut bindings = HashMap::new();
        bindings.insert(None, ROOT_DEFAULT_NS);
        for (i, &p) in PREFIXES.iter().enumerate() {
            bindings.insert(Some(p), NS_URIS[i]);
        }
        Self { bindings }
    }

    fn with(&self, decls: &[NsDecl]) -> Self {
        let mut child = self.clone();
        // Dedupe by target: last decl in source order wins.
        let mut seen = HashSet::new();
        for d in decls.iter().rev() {
            if !seen.insert(d.target) {
                continue;
            }
            let uri = NS_URIS[d.uri];
            match d.target {
                NsTarget::Default => {
                    child.bindings.insert(None, uri);
                }
                NsTarget::Prefix(pi) => {
                    child.bindings.insert(Some(PREFIXES[pi]), uri);
                }
            }
        }
        child
    }

    fn resolve_attr(&self, prefix: Option<usize>, local: usize) -> (&'static str, &'static str) {
        let local_str = NCNAMES[local];
        match prefix {
            None => ("", local_str),
            Some(pi) => {
                let prefix_str = PREFIXES[pi];
                let uri = self.bindings.get(&Some(prefix_str)).copied().unwrap_or("");
                (uri, local_str)
            }
        }
    }
}

fn render_root(spec: &ElementSpec) -> String {
    let mut buf = String::new();
    render_element(&mut buf, spec, &Scope::root(), /*is_root=*/ true);
    buf
}

fn render_element(buf: &mut String, spec: &ElementSpec, parent_scope: &Scope, is_root: bool) {
    // Compute the scope visible inside this element. For the root we
    // include the implicit pool decls; descendants only see the parent's
    // scope plus this element's spec.ns_decls.
    let child_scope = parent_scope.with(&spec.ns_decls);

    let prefix_str = spec.prefix.map(|p| PREFIXES[p]);
    let local_str = NCNAMES[spec.local];

    buf.push('<');
    if let Some(p) = prefix_str {
        buf.push_str(p);
        buf.push(':');
    }
    buf.push_str(local_str);

    // Spec ns_decls take precedence; whichever pool prefixes (and default
    // ns) the spec did not redeclare get the implicit binding at the root.
    // Children only emit what the spec says — implicit decls live at the
    // root only.
    let mut emitted_targets: HashSet<NsTarget> = HashSet::new();
    let mut ordered: Vec<NsDecl> = Vec::new();
    for d in spec.ns_decls.iter().rev() {
        if emitted_targets.insert(d.target) {
            ordered.push(*d);
        }
    }
    ordered.reverse();

    if is_root {
        // Implicit decls for any target the spec did not cover.
        let mut implicit: Vec<(NsTarget, &'static str)> = Vec::new();
        if !emitted_targets.contains(&NsTarget::Default) {
            implicit.push((NsTarget::Default, ROOT_DEFAULT_NS));
        }
        for (i, _) in PREFIXES.iter().enumerate() {
            if !emitted_targets.contains(&NsTarget::Prefix(i)) {
                implicit.push((NsTarget::Prefix(i), NS_URIS[i]));
            }
        }
        for (target, uri) in implicit {
            match target {
                NsTarget::Default => buf.push_str(&format!(" xmlns=\"{}\"", uri)),
                NsTarget::Prefix(pi) => {
                    buf.push_str(&format!(" xmlns:{}=\"{}\"", PREFIXES[pi], uri));
                }
            }
        }
    }

    for d in &ordered {
        let uri = NS_URIS[d.uri];
        match d.target {
            NsTarget::Default => buf.push_str(&format!(" xmlns=\"{}\"", uri)),
            NsTarget::Prefix(pi) => {
                buf.push_str(&format!(" xmlns:{}=\"{}\"", PREFIXES[pi], uri));
            }
        }
    }

    // Dedupe attributes by resolved (namespace URI, local name).
    let mut emitted_attrs: HashSet<(&str, &str)> = HashSet::new();
    let mut ordered_attrs: Vec<&AttrSpec> = Vec::new();
    for a in spec.attrs.iter().rev() {
        let key = child_scope.resolve_attr(a.prefix, a.local);
        if emitted_attrs.insert(key) {
            ordered_attrs.push(a);
        }
    }
    ordered_attrs.reverse();
    for a in ordered_attrs {
        buf.push(' ');
        if let Some(pi) = a.prefix {
            buf.push_str(PREFIXES[pi]);
            buf.push(':');
        }
        buf.push_str(NCNAMES[a.local]);
        buf.push_str("=\"");
        buf.push_str(ATTR_VALUES[a.value]);
        buf.push('"');
    }

    if spec.children.is_empty() {
        buf.push_str("/>");
        return;
    }
    buf.push('>');

    for child in &spec.children {
        match child {
            NodeSpec::Element(e) => render_element(buf, e, &child_scope, false),
            NodeSpec::Text(idx) => buf.push_str(TEXTS[*idx]),
            NodeSpec::CData(idx) => {
                buf.push_str("<![CDATA[");
                buf.push_str(CDATA_BODIES[*idx]);
                buf.push_str("]]>");
            }
            NodeSpec::Pi(t, d) => {
                buf.push_str("<?");
                buf.push_str(PI_TARGETS[*t]);
                let data = PI_DATAS[*d];
                if !data.is_empty() {
                    buf.push(' ');
                    buf.push_str(data);
                }
                buf.push_str("?>");
            }
            NodeSpec::Comment(idx) => {
                buf.push_str("<!--");
                buf.push_str(COMMENT_BODIES[*idx]);
                buf.push_str("-->");
            }
        }
    }

    buf.push_str("</");
    if let Some(p) = prefix_str {
        buf.push_str(p);
        buf.push(':');
    }
    buf.push_str(local_str);
    buf.push('>');
}

// ---------------------------------------------------------------------------
// Oracle plumbing (shares xmllint detection with c14n_oracle_test, but lives
// here standalone to avoid cross-module test wiring).
// ---------------------------------------------------------------------------

fn xmllint_path() -> Option<&'static str> {
    static PATH: OnceLock<Option<&'static str>> = OnceLock::new();
    *PATH.get_or_init(|| {
        for candidate in ["/usr/bin/xmllint", "/opt/homebrew/bin/xmllint"] {
            if std::path::Path::new(candidate).exists() {
                return Some(candidate);
            }
        }
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
            Some(Box::leak(path.to_string().into_boxed_str()) as &'static str)
        }
    })
}

fn xmllint_c14n_or_skip(input: &str) -> Option<Vec<u8>> {
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
        "xmllint rejected generated XML — pool entry is malformed.\nstderr:\n{}\ninput:\n{}",
        String::from_utf8_lossy(&out.stderr),
        input,
    );
    Some(strip_comments(&out.stdout))
}

fn strip_comments(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"<!--")
            && let Some(end) = bytes[i + 4..].windows(3).position(|w| w == b"-->")
        {
            i += 4 + end + 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

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

// ---------------------------------------------------------------------------
// The fuzz test itself.
// ---------------------------------------------------------------------------

proptest! {
    // 256 default cases is enough to surface most attribute-sort and ns-
    // pruning bugs within a few seconds; bump via PROPTEST_CASES if hunting.
    #![proptest_config(ProptestConfig {
        cases: 256,
        // Don't burn time shrinking — pool indices shrink trivially anyway.
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn fuzz_exclusive_c14n_matches_xmllint(spec in root_strategy()) {
        let xml = render_root(&spec);

        let Some(expected) = xmllint_c14n_or_skip(&xml) else {
            // xmllint unavailable — skip silently. Use the curated oracle
            // module's warning machinery? Not worth the cross-module
            // coupling for a one-time stderr line.
            return Ok(());
        };

        let root = parse_xml_tree(&xml)
            .map_err(|e| TestCaseError::fail(format!("our parser rejected generated XML: {e:?}\ninput:\n{xml}")))?;
        let actual = exclusive_c14n(&root, &HashMap::new());

        prop_assert_eq!(
            &actual,
            &expected,
            "c14n divergence from xmllint oracle\n\
             input:\n{}\n\n\
             expected ({} bytes):\n{}\n\n\
             actual   ({} bytes):\n{}\n",
            xml,
            expected.len(),
            show(&expected),
            actual.len(),
            show(&actual),
        );
    }
}
