//! RFC 7396 JSON Merge Patch.
//!
//! The single update mechanism for every stored resource. Because rows are
//! JSON documents and patching is defined over the document rather than over a
//! Rust type, adding a field to a model requires no change to the storage
//! layer at all — which is the property the whole model/store split is built
//! on.
//!
//! The rule to keep in mind is that `null` *deletes*. That is what lets a
//! PATCH clear an optional field, and it is why the patch-shaped model types
//! use `Option<Option<T>>`: serde must be able to tell an omitted field from an
//! explicit null before the document ever reaches this function. See
//! [`crate::models::serde_util::deserialize_some`].
//!
//! Note the consequence for collections: a JSON array is a scalar to merge
//! patch, so patching `to` replaces the whole list rather than appending. That
//! is RFC behaviour, not an oversight — there is no way to express "add one
//! upstream" in this format, and clients send the full list.

use serde_json::Value;

/// Apply RFC 7396 JSON Merge Patch semantics to `base`.
///
/// An object patch treats a non-object target as an empty object, removes
/// members whose patch value is null, and recursively merges every other
/// member. A non-object patch replaces the target as a whole.
pub fn json_merge(base: &mut Value, patch: &Value) {
    if let Value::Object(patch_map) = patch {
        if !base.is_object() {
            *base = Value::Object(serde_json::Map::new());
        }
        let Value::Object(base_map) = base else {
            unreachable!("base was replaced with an object");
        };
        for (key, patch_val) in patch_map {
            if patch_val.is_null() {
                base_map.remove(key);
            } else {
                let base_val = base_map.entry(key.clone()).or_insert(Value::Null);
                json_merge(base_val, patch_val);
            }
        }
    } else {
        *base = patch.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_overwrites_scalar() {
        let mut base = json!({"name": "old", "from": "https://a.com"});
        let patch = json!({"name": "new"});
        json_merge(&mut base, &patch);
        assert_eq!(base["name"], "new");
        assert_eq!(base["from"], "https://a.com"); // unchanged
    }

    #[test]
    fn merge_deep_object() {
        let mut base =
            json!({"access": {"policies": ["soc"], "allow_public_unauthenticated_access": false}});
        let patch = json!({"access": {"policies": ["soc", "ops"]}});
        json_merge(&mut base, &patch);
        assert_eq!(base["access"]["policies"], json!(["soc", "ops"]));
        assert_eq!(base["access"]["allow_public_unauthenticated_access"], false);
    }

    #[test]
    fn merge_null_removes_field() {
        let mut base = json!({"host_rewrite": "old.com", "name": "app"});
        let patch = json!({"host_rewrite": null});
        json_merge(&mut base, &patch);
        assert!(base.get("host_rewrite").is_none());
        assert_eq!(base["name"], "app");
    }

    #[test]
    fn merge_adds_new_field() {
        let mut base = json!({"name": "app"});
        let patch = json!({"tls_skip_verify": true});
        json_merge(&mut base, &patch);
        assert_eq!(base["tls_skip_verify"], true);
    }

    #[test]
    fn rfc_7396_object_over_non_object_and_replacement_vectors() {
        let vectors = [
            (
                "object over scalar removes null member",
                json!("scalar"),
                json!({"keep": 1, "drop": null}),
                json!({"keep": 1}),
            ),
            (
                "object over null removes null member",
                Value::Null,
                json!({"keep": 1, "drop": null}),
                json!({"keep": 1}),
            ),
            (
                "object over array removes null member",
                json!([1, 2]),
                json!({"a": "b", "c": null}),
                json!({"a": "b"}),
            ),
            (
                "nested scalar becomes object before null deletion",
                json!({"outer": "scalar"}),
                json!({"outer": {"keep": true, "drop": null}}),
                json!({"outer": {"keep": true}}),
            ),
            (
                "inserted object recursively drops null",
                json!({}),
                json!({"a": {"bb": {"ccc": null}}}),
                json!({"a": {"bb": {}}}),
            ),
            (
                "empty object replaces scalar",
                json!("scalar"),
                json!({}),
                json!({}),
            ),
            (
                "array patch replaces object",
                json!({"a": "b"}),
                json!(["c", "d"]),
                json!(["c", "d"]),
            ),
            (
                "scalar patch replaces object",
                json!({"a": "b"}),
                json!("replacement"),
                json!("replacement"),
            ),
            (
                "null patch replaces object",
                json!({"a": "b"}),
                Value::Null,
                Value::Null,
            ),
        ];

        for (name, mut base, patch, expected) in vectors {
            json_merge(&mut base, &patch);
            assert_eq!(base, expected, "{name}");
        }
    }
}
