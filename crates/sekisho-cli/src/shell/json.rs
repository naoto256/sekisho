//! Pure JSON shape helpers shared across the shell module.
//!
//! Nothing here touches the API client or the names cache — these
//! are value-only transformations the edit / ops / completion paths
//! all compose. Kept separate so the rest of the shell stays
//! testable without standing up serde_json fixtures inline.

use serde_json::{Map, Value};

/// Split a dotted, kebab-cased field reference into snake_case JSON keys.
/// Used by `set access.policy x`-style shortcuts so users don't have to
/// `edit access` just to touch one leaf.
pub(super) fn field_to_json_key(field: &str) -> Vec<String> {
    field
        .split('.')
        .map(|part| part.replace('-', "_"))
        .collect()
}

/// Local RFC 7396 JSON Merge Patch implementation, used by `show` in edit mode
/// to preview what the resource will look like after `commit` without sending
/// the changes to the server.
pub(super) fn json_merge_patch(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, pv) in p {
                if pv.is_null() {
                    b.remove(k);
                } else {
                    let bv = b.entry(k.clone()).or_insert(Value::Null);
                    json_merge_patch(bv, pv);
                }
            }
        }
        (b, p) => *b = p.clone(),
    }
}

pub(super) fn parse_value(s: &str) -> Value {
    match s {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "null" => Value::Null,
        _ => {
            if let Ok(n) = s.parse::<i64>() {
                Value::Number(n.into())
            } else {
                Value::String(s.to_string())
            }
        }
    }
}

/// Walk `path` into `value`, returning the sub-tree or None if it doesn't
/// exist. Used by `show` inside nested edit scopes.
pub(super) fn narrow_to_path<'a>(value: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut v = value;
    for key in path {
        v = v.get(key)?;
    }
    Some(v)
}

pub(super) fn set_nested(map: &mut Map<String, Value>, keys: &[String], value: Value) {
    if keys.len() == 1 {
        map.insert(keys[0].clone(), value);
    } else {
        let entry = map
            .entry(keys[0].clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(inner) = entry {
            set_nested(inner, &keys[1..], value);
        }
    }
}

pub(super) fn print_json(v: &Value) {
    if let Ok(s) = serde_json::to_string_pretty(v) {
        println!("{s}");
    }
}

/// Loose UUID shape check: 8-4-4-4-12 hex. Good enough to tell a
/// pasted UUID from an IdP name without pulling in the `uuid` crate
/// for one predicate.
pub(super) fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        let expect_dash = matches!(i, 8 | 13 | 18 | 23);
        if expect_dash {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn field_to_json_key_converts_dashes_to_underscores() {
        assert_eq!(field_to_json_key("auth-domain"), vec!["auth_domain"]);
        assert_eq!(
            field_to_json_key("access.allow-public-unauthenticated-access"),
            vec!["access", "allow_public_unauthenticated_access"]
        );
    }

    #[test]
    fn is_uuid_accepts_canonical_form() {
        assert!(is_uuid("11111111-2222-3333-4444-555555555555"));
        assert!(is_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
    }

    #[test]
    fn is_uuid_rejects_everything_else() {
        // Wrong length.
        assert!(!is_uuid("1234"));
        // Human-readable name.
        assert!(!is_uuid("corp-okta"));
        // Dashes in wrong spots.
        assert!(!is_uuid("111111112-222-3333-4444-555555555555"));
        // Non-hex char.
        assert!(!is_uuid("gggggggg-bbbb-cccc-dddd-eeeeeeeeeeee"));
    }

    #[test]
    fn parse_value_recognises_primitives() {
        assert_eq!(parse_value("true"), json!(true));
        assert_eq!(parse_value("false"), json!(false));
        assert_eq!(parse_value("null"), Value::Null);
        assert_eq!(parse_value("42"), json!(42));
        assert_eq!(parse_value("hello"), json!("hello"));
        // Leading zeros / non-int-looking tokens remain as strings.
        assert_eq!(parse_value("1.5"), json!("1.5"));
    }

    #[test]
    fn set_nested_inserts_top_level() {
        let mut m = Map::new();
        set_nested(&mut m, &["name".into()], json!("app"));
        assert_eq!(Value::Object(m), json!({ "name": "app" }));
    }

    #[test]
    fn set_nested_creates_intermediate_objects() {
        let mut m = Map::new();
        set_nested(
            &mut m,
            &["access".into(), "policy".into()],
            json!("policy.soc"),
        );
        assert_eq!(
            Value::Object(m),
            json!({ "access": { "policy": "policy.soc" } })
        );
    }

    #[test]
    fn set_nested_with_path_prefix() {
        let mut m = Map::new();
        let mut keys = vec!["access".to_string()];
        keys.extend(field_to_json_key("policy"));
        set_nested(&mut m, &keys, json!("policy.soc"));
        assert_eq!(
            Value::Object(m),
            json!({ "access": { "policy": "policy.soc" } })
        );
    }

    #[test]
    fn json_merge_patch_overwrites_scalars() {
        let mut base = json!({ "a": 1, "b": 2 });
        json_merge_patch(&mut base, &json!({ "b": 99 }));
        assert_eq!(base, json!({ "a": 1, "b": 99 }));
    }

    #[test]
    fn json_merge_patch_null_removes_field() {
        let mut base = json!({ "host": "a", "port": 80 });
        json_merge_patch(&mut base, &json!({ "host": null }));
        assert_eq!(base, json!({ "port": 80 }));
    }

    #[test]
    fn json_merge_patch_deep_merge() {
        let mut base = json!({ "access": { "policy": "a", "public": false } });
        json_merge_patch(&mut base, &json!({ "access": { "policy": "b" } }));
        assert_eq!(
            base,
            json!({ "access": { "policy": "b", "public": false } })
        );
    }

    #[test]
    fn narrow_to_path_follows_nesting() {
        let v = json!({ "a": { "b": { "c": 42 } } });
        assert_eq!(
            narrow_to_path(&v, &["a".into(), "b".into()]).unwrap(),
            &json!({ "c": 42 })
        );
    }

    #[test]
    fn narrow_to_path_empty_returns_root() {
        let v = json!({ "a": 1 });
        assert_eq!(narrow_to_path(&v, &[]).unwrap(), &v);
    }

    #[test]
    fn narrow_to_path_missing_returns_none() {
        let v = json!({ "a": 1 });
        assert!(narrow_to_path(&v, &["nope".into()]).is_none());
    }
}
