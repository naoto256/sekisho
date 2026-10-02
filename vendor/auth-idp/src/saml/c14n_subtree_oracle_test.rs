//! Subtree-canonicalization oracle backed by xmlsec1.
//!
//! Complements `c14n_oracle_test.rs` (xmllint, whole-document, no PrefixList,
//! no ancestor inheritance) by exercising the two paths xmllint's CLI cannot:
//!
//! 1. **`ancestor_ns` parameter to `exclusive_c14n`.** SAML signature
//!    verification canonicalizes a *subtree* (the signed Assertion/Response)
//!    while inheriting namespace bindings from ancestors of that subtree.
//!    The whole-doc oracle never exercises this path.
//! 2. **`exclusive_c14n_with_prefix_list`.** SAML IdPs that follow the
//!    Shibboleth / xmldsig-filter convention add an
//!    `<ec:InclusiveNamespaces PrefixList="..."/>` element to force certain
//!    ancestor-scope prefixes to be rendered even when not visibly used.
//!    `xmllint --exc-c14n` has no CLI knob for this; xmlsec1 does.
//!
//! Oracle technique: xmlsec1 signs a template containing the target subtree
//! and a `<Signature>` element with `Reference URI="#<id>"`, an exc-c14n
//! transform, optional `<InclusiveNamespaces PrefixList="..."/>`, and SHA-256
//! digest method. We parse `DigestValue` out of xmlsec1's stdout — this is
//! `base64(SHA256(xmlsec1's c14n output))`. We then compute the same digest
//! over OUR canonicalization of the same subtree (finding it by ID, walking
//! ancestors to collect their namespace declarations, calling
//! `exclusive_c14n_with_prefix_list`). Equal digests = identical c14n bytes
//! modulo SHA-256 collision.
//!
//! The byte-level information is lost on failure — we only learn "your c14n
//! differs". For finer-grained diagnosis, fall back to the c14n_oracle_test
//! (xmllint) or c14n_fuzz_test (xmllint).
//!
//! Test setup requires:
//! - `xmlsec1` on PATH (or in `/opt/homebrew/bin/`)
//! - `openssl` CLI (for ephemeral key generation)
//!
//! Missing either: all tests skip silently with a one-shot stderr warning.

use super::c14n::{XmlElement, XmlNode, exclusive_c14n_with_prefix_list, parse_xml_tree};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// Locate xmlsec1, preferring known paths to avoid an `sh -c` for the common
/// case.
fn xmlsec1_path() -> Option<&'static str> {
    static P: OnceLock<Option<&'static str>> = OnceLock::new();
    *P.get_or_init(|| {
        [
            "/opt/homebrew/bin/xmlsec1",
            "/usr/local/bin/xmlsec1",
            "/usr/bin/xmlsec1",
        ]
        .into_iter()
        .find(|c| std::path::Path::new(c).exists())
    })
}

/// Locate openssl CLI.
fn openssl_path() -> Option<&'static str> {
    static P: OnceLock<Option<&'static str>> = OnceLock::new();
    *P.get_or_init(|| {
        [
            "/opt/homebrew/bin/openssl",
            "/usr/bin/openssl",
            "/usr/local/bin/openssl",
        ]
        .into_iter()
        .find(|c| std::path::Path::new(c).exists())
    })
}

/// Generate (once per test process) a 2048-bit RSA key under /tmp for
/// xmlsec1 signing. Returns `None` if either tool is missing or key gen
/// fails.
fn test_key_path() -> Option<&'static PathBuf> {
    static KEY: OnceLock<Option<PathBuf>> = OnceLock::new();
    KEY.get_or_init(|| {
        let openssl = openssl_path()?;
        xmlsec1_path()?;
        let path = std::env::temp_dir().join("auth-idp-c14n-subtree-oracle-key.pem");
        if path.exists() {
            return Some(path);
        }
        let status = Command::new(openssl)
            .args(["genrsa", "-out", path.to_str()?, "2048"])
            .status()
            .ok()?;
        if status.success() { Some(path) } else { None }
    })
    .as_ref()
}

/// Wrap `inner_xml` in a `<doc>` + Signature template where the Reference
/// points at `target_id` and the Transform optionally carries an
/// `InclusiveNamespaces PrefixList`. Returns the template string ready for
/// `xmlsec1 --sign`.
fn build_sign_template(inner_xml: &str, target_id: &str, prefix_list: Option<&str>) -> String {
    let inclusive = match prefix_list {
        Some(pl) => format!(
            "<InclusiveNamespaces xmlns=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"{}\"/>",
            pl
        ),
        None => String::new(),
    };
    format!(
        r##"<doc>
{inner}
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <Reference URI="#{tid}">
      <Transforms>
        <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">{incl}</Transform>
      </Transforms>
      <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <DigestValue/>
    </Reference>
  </SignedInfo>
  <SignatureValue/>
  <KeyInfo><KeyName>idp</KeyName></KeyInfo>
</Signature>
</doc>"##,
        inner = inner_xml,
        tid = target_id,
        incl = inclusive,
    )
}

/// Sign `template` with the ephemeral key and return the `DigestValue` from
/// xmlsec1's stdout. Returns `None` only if the test setup is unavailable.
fn xmlsec1_reference_digest(template: &str) -> Option<String> {
    let key = test_key_path()?;
    let xmlsec1 = xmlsec1_path()?;

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let tmp = std::env::temp_dir().join(format!(
        "auth-idp-c14n-subtree-{}-{}.xml",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::write(&tmp, template).expect("write template");

    // Use named-key + KeyInfo/KeyName matching instead of --lax-key-search.
    // The latter only exists in xmlsec1 1.3+; Ubuntu 24.04 ships 1.2.x which
    // matches the loaded key against <ds:KeyName> in the template. The
    // template above declares <KeyName>idp</KeyName>, so we load the key
    // under the same name with `--privkey-pem:idp`.
    let out = Command::new(xmlsec1)
        .args([
            "--sign",
            "--privkey-pem:idp",
            key.to_str().unwrap(),
            "--id-attr:ID",
            "target",
            tmp.to_str().unwrap(),
        ])
        .output()
        .expect("spawn xmlsec1");
    let _ = std::fs::remove_file(&tmp);

    assert!(
        out.status.success(),
        "xmlsec1 --sign failed.\nstderr:\n{}\nstdout:\n{}\ntemplate:\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
        template,
    );
    let stdout = String::from_utf8(out.stdout).expect("xmlsec1 output is utf-8");
    Some(
        extract_digest_value(&stdout)
            .unwrap_or_else(|| panic!("no <DigestValue> in xmlsec1 stdout:\n{}", stdout)),
    )
}

fn extract_digest_value(signed: &str) -> Option<String> {
    let s = signed.find("<DigestValue>")? + "<DigestValue>".len();
    let e = signed[s..].find("</DigestValue>")?;
    Some(signed[s..s + e].trim().to_string())
}

/// Walk `root` to find the element whose unprefixed `ID` attribute equals
/// `target_id`. Returns the element together with the namespace map in
/// scope at that element (ancestors' decls only — the target's own decls
/// remain on `elem.ns_decls` for the canonicalizer to handle).
fn find_by_id_with_ancestor_ns<'a>(
    elem: &'a XmlElement,
    target_id: &str,
    scope: &HashMap<String, String>,
) -> Option<(&'a XmlElement, HashMap<String, String>)> {
    for (ap, al, av) in &elem.attributes {
        if ap.is_empty() && al == "ID" && av == target_id {
            return Some((elem, scope.clone()));
        }
    }
    let mut child_scope = scope.clone();
    for (p, u) in &elem.ns_decls {
        child_scope.insert(p.clone(), u.clone());
    }
    for child in &elem.children {
        if let XmlNode::Element(e) = child
            && let Some(found) = find_by_id_with_ancestor_ns(e, target_id, &child_scope)
        {
            return Some(found);
        }
    }
    None
}

fn our_subtree_digest(doc_xml: &str, target_id: &str, prefix_list: &[&str]) -> String {
    let root = parse_xml_tree(doc_xml).expect("our parser accepted doc");
    let (target, ancestor_ns) = find_by_id_with_ancestor_ns(&root, target_id, &HashMap::new())
        .unwrap_or_else(|| panic!("ID '{target_id}' not found in:\n{doc_xml}"));
    let pl: HashSet<String> = prefix_list.iter().map(|s| s.to_string()).collect();
    let bytes = exclusive_c14n_with_prefix_list(target, &ancestor_ns, &pl);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    B64.encode(hasher.finalize())
}

/// Core oracle check. If xmlsec1 + openssl are unavailable, returns
/// without running (one-shot stderr warning). Otherwise asserts digest
/// equality.
fn assert_subtree_digest_matches(name: &str, doc_xml: &str, target_id: &str, prefix_list: &[&str]) {
    let pl_attr = if prefix_list.is_empty() {
        None
    } else {
        Some(prefix_list.join(" "))
    };
    let template = build_sign_template(doc_xml, target_id, pl_attr.as_deref());

    let Some(expected) = xmlsec1_reference_digest(&template) else {
        static WARNED: OnceLock<()> = OnceLock::new();
        WARNED.get_or_init(|| {
            eprintln!(
                "[c14n_subtree_oracle_test] xmlsec1 or openssl not found; \
                 skipping subtree oracle checks. brew install xmlsec1 to enable."
            );
        });
        return;
    };

    let actual = our_subtree_digest(doc_xml, target_id, prefix_list);

    assert_eq!(
        actual, expected,
        "[{}] subtree c14n digest divergence from xmlsec1\ntarget_id: {}\nprefix_list: {:?}\ndoc:\n{}\n\nexpected (xmlsec1): {}\nactual   (auth-idp): {}",
        name, target_id, prefix_list, doc_xml, expected, actual,
    );
}

// ---------------------------------------------------------------------------
// ancestor_ns cases — target subtree wrapped in ancestors that declare
// namespaces. The c14n of the target must inherit those declarations.
// ---------------------------------------------------------------------------

#[test]
fn ancestor_default_ns_used_by_target() {
    // <doc> declares default ns; <target> is unprefixed so it visibly uses
    // the default. xmlsec1's c14n must emit xmlns="urn:default" on <target>.
    assert_subtree_digest_matches(
        "ancestor_default_ns_used_by_target",
        r#"<wrap xmlns="urn:default"><target ID="t1"><x/></target></wrap>"#,
        "t1",
        &[],
    );
}

#[test]
fn ancestor_default_ns_unused_by_target_is_pruned() {
    // <doc> declares default ns; <target> uses a prefixed element and
    // does NOT visibly use the default ns. exc-c14n must prune it.
    assert_subtree_digest_matches(
        "ancestor_default_ns_unused_by_target_is_pruned",
        r#"<wrap xmlns="urn:wrap" xmlns:p="urn:p"><target ID="t1"><p:x/></target></wrap>"#,
        "t1",
        &[],
    );
}

#[test]
fn ancestor_prefix_visibly_used_inside_target() {
    // p: is declared by ancestor and used by an attribute inside target.
    assert_subtree_digest_matches(
        "ancestor_prefix_visibly_used_inside_target",
        r#"<wrap xmlns:p="urn:p"><target ID="t1"><x p:k="v"/></target></wrap>"#,
        "t1",
        &[],
    );
}

#[test]
fn ancestor_prefix_shadowed_by_target_local_decl() {
    // p is bound to urn:1 by ancestor; target redeclares p to urn:2 and
    // uses it. exc-c14n on target must emit xmlns:p="urn:2" (the local
    // binding wins for everything in the subtree).
    assert_subtree_digest_matches(
        "ancestor_prefix_shadowed_by_target_local_decl",
        r#"<wrap xmlns:p="urn:1"><target ID="t1" xmlns:p="urn:2"><p:x/></target></wrap>"#,
        "t1",
        &[],
    );
}

#[test]
fn deep_ancestor_chain_collects_all_decls() {
    // 3 levels of ancestors each declaring one prefix; only one is used
    // inside target. Only the used one survives.
    assert_subtree_digest_matches(
        "deep_ancestor_chain_collects_all_decls",
        r#"<a xmlns:p1="urn:1"><b xmlns:p2="urn:2"><c xmlns:p3="urn:3"><target ID="t1"><x p2:k="v"/></target></c></b></a>"#,
        "t1",
        &[],
    );
}

// ---------------------------------------------------------------------------
// PrefixList cases — InclusiveNamespaces forces ancestor-scope prefixes to
// be rendered on the canonicalized subtree even when not visibly used.
// ---------------------------------------------------------------------------

#[test]
fn prefix_list_forces_unused_ancestor_prefix_to_be_rendered() {
    // p is in scope from ancestor but unused inside target. PrefixList="p"
    // forces it to be emitted on the canonicalized subtree.
    assert_subtree_digest_matches(
        "prefix_list_forces_unused_ancestor_prefix_to_be_rendered",
        r#"<wrap xmlns:p="urn:p"><target ID="t1"><x/></target></wrap>"#,
        "t1",
        &["p"],
    );
}

#[test]
fn prefix_list_with_multiple_prefixes() {
    assert_subtree_digest_matches(
        "prefix_list_with_multiple_prefixes",
        r#"<wrap xmlns:p="urn:p" xmlns:q="urn:q" xmlns:r="urn:r"><target ID="t1"><x p:k="v"/></target></wrap>"#,
        "t1",
        &["p", "q", "r"],
    );
}

#[test]
fn prefix_list_with_already_visible_prefix_is_idempotent() {
    // p is both visibly used (attribute prefix) AND listed in PrefixList.
    // Should render exactly once.
    assert_subtree_digest_matches(
        "prefix_list_with_already_visible_prefix_is_idempotent",
        r#"<wrap xmlns:p="urn:p"><target ID="t1"><x p:k="v"/></target></wrap>"#,
        "t1",
        &["p"],
    );
}

#[test]
fn prefix_list_does_not_render_undefined_prefix() {
    // PrefixList names a prefix that is not actually declared in any
    // ancestor. exc-c14n: nothing to render for it (no URI to bind).
    assert_subtree_digest_matches(
        "prefix_list_does_not_render_undefined_prefix",
        r#"<wrap xmlns:p="urn:p"><target ID="t1"><x/></target></wrap>"#,
        "t1",
        &["nope"],
    );
}

#[test]
fn prefix_list_with_shadowed_prefix_uses_local_binding() {
    // p in scope as urn:1 from ancestor; target redeclares p=urn:2 locally;
    // PrefixList="p" — the local binding (urn:2) wins on the target tag.
    assert_subtree_digest_matches(
        "prefix_list_with_shadowed_prefix_uses_local_binding",
        r#"<wrap xmlns:p="urn:1"><target ID="t1" xmlns:p="urn:2"><x/></target></wrap>"#,
        "t1",
        &["p"],
    );
}
