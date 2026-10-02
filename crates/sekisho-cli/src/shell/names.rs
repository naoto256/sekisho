//! Resource registry helpers + cache of instance labels for tab completion.
//!
//! The resource list itself is compile-time (`crate::resources`). What
//! we add here is a cache of *what's on the server right now* — the
//! rustyline `Completer` runs synchronously and cannot block on an API
//! call, so we refresh this cache out-of-band after every mutation and
//! the completer reads from it.

use serde_json::Value;

use crate::api::ApiClient;
use crate::resources::{
    descriptor, is_config_resource, is_singleton, resource_api_path, resources,
};

use super::ShellMode;

/// Resource names (plus the synthetic `config` and `version` aliases used
/// only by `show`: `config` dumps every config resource, `version` reports
/// the local CLI / daemon build tags).
pub(super) fn all_resource_names() -> Vec<&'static str> {
    ["config", "version"]
        .into_iter()
        .chain(resources().iter().map(|r| r.name))
        .collect()
}

pub(super) fn config_resource_names() -> Vec<&'static str> {
    resources()
        .iter()
        .filter(|r| is_config_resource(r.name))
        .map(|r| r.name)
        .collect()
}

pub(super) fn creatable_config_resource_names() -> Vec<&'static str> {
    resources()
        .iter()
        .filter(|r| r.config && r.creatable)
        .map(|r| r.name)
        .collect()
}

/// Resource types accepted by a shell mode/verb pair.
///
/// This is the shell grammar's single capability authority. Resource metadata
/// still describes data shape and broad visibility, but does not imply that
/// every operational resource supports every mutation verb.
pub(super) fn resource_names_for(mode: ShellMode, verb: &str) -> Vec<&'static str> {
    match (mode, verb) {
        (ShellMode::Operational, "show") => all_resource_names(),
        (ShellMode::Operational, "create") => operational_capabilities(&["api-key"]),
        (ShellMode::Operational, "delete") => {
            operational_capabilities(&["route", "idp", "certificate", "api-key", "session"])
        }
        (ShellMode::Operational, "enable" | "disable") => operational_capabilities(&["route"]),
        (ShellMode::Operational, "upload") => operational_capabilities(&["certificate"]),
        (ShellMode::Operational, "add" | "activate" | "retire" | "rotate") => {
            operational_capabilities(&["encryption-key"])
        }
        (ShellMode::Config, "show") => ["config"]
            .into_iter()
            .chain(config_resource_names())
            .collect(),
        (ShellMode::Config, "edit") => config_resource_names(),
        (ShellMode::Config, "create" | "delete") => creatable_config_resource_names(),
        _ => Vec::new(),
    }
}

/// Pass a hand-written operational list through, asserting in debug builds
/// that every name in it is actually an operational resource.
///
/// The lists here are written out rather than derived because operational verbs
/// apply to different subsets and the subsets are not a property of the
/// resource table. The `debug_assert!` is the guard against that hand-written
/// list drifting away from the table: a name that stops being operational
/// fails the shell's own tests rather than silently offering a verb the daemon
/// will refuse.
fn operational_capabilities(names: &[&'static str]) -> Vec<&'static str> {
    debug_assert!(names.iter().all(|name| {
        resources()
            .iter()
            .find(|resource| resource.name == *name)
            .is_some_and(|resource| resource.operational)
    }));
    names.to_vec()
}

/// Whether this (mode, verb, resource) combination exists at all.
///
/// The single authority for what the shell will accept, so that dispatch,
/// completion and help cannot disagree about the command surface. Completion
/// narrows further — see [`resource_is_visible_in_completion`] — but nothing
/// widens past this.
pub(super) fn resource_is_allowed(mode: ShellMode, verb: &str, resource: &str) -> bool {
    resource_names_for(mode, verb).contains(&resource)
}

/// Whether a statically supported resource type is useful to offer right now.
///
/// The capability set remains owned by [`resource_names_for`]. This predicate
/// only layers the synchronous instance-name cache over commands that require
/// an existing target.
pub(super) fn resource_is_visible_in_completion(
    mode: ShellMode,
    verb: &str,
    resource: &str,
) -> bool {
    if !resource_is_allowed(mode, verb, resource) {
        return false;
    }
    match (mode, verb) {
        (ShellMode::Config, "edit") => descriptor(resource).is_some_and(|definition| {
            definition.directly_editable || !cached_resource_names(resource).is_empty()
        }),
        (ShellMode::Config | ShellMode::Operational, "delete") => {
            !cached_resource_names(resource).is_empty()
        }
        _ => true,
    }
}

/// Cached resource instance labels (name / domain / id) for tab completion.
/// Filled at startup and refreshed after every mutation. The completer is a
/// synchronous trait so we cannot call the API from `complete()` — this cache
/// is the bridge.
static NAMES_CACHE: std::sync::OnceLock<
    std::sync::RwLock<std::collections::HashMap<String, Vec<String>>>,
> = std::sync::OnceLock::new();

fn names_cache() -> &'static std::sync::RwLock<std::collections::HashMap<String, Vec<String>>> {
    NAMES_CACHE.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Best label to identify an instance: prefer `name`, then `domain` (certs),
/// then fall back to `id` (sessions).
pub(super) fn instance_label(item: &Value) -> Option<String> {
    for key in ["name", "domain", "id"] {
        if let Some(s) = item.get(key).and_then(|v| v.as_str())
            && !s.is_empty()
        {
            return Some(s.to_string());
        }
    }
    None
}

pub(super) fn cached_resource_names(resource: &str) -> Vec<String> {
    names_cache()
        .read()
        .map(|c| c.get(resource).cloned().unwrap_or_default())
        .unwrap_or_default()
}

/// Write labels into the cache.
pub(super) fn store_resource_names(resource: &str, names: Vec<String>) {
    if let Ok(mut c) = names_cache().write() {
        c.insert(resource.to_string(), names);
    }
}

/// Fetch the list for `resource` from the API and refresh the names cache.
/// Silently ignores errors (cache simply stays stale).
pub(super) async fn refresh_names(client: &ApiClient, resource: &str) {
    let path = resource_api_path(resource);
    if path.is_empty() || resource == "config" || is_singleton(resource) {
        return;
    }
    if let Ok(items) = client.get_list(path).await {
        let labels: Vec<String> = items.iter().filter_map(instance_label).collect();
        store_resource_names(resource, labels);
    }
}

/// Prefetch all listable resources at startup.
pub(super) async fn prefetch_all_names(client: &ApiClient) {
    for r in resources() {
        refresh_names(client, r.name).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mode_verb_resource_capabilities_are_exact() {
        assert_eq!(
            resource_names_for(ShellMode::Operational, "show"),
            [
                "config",
                "version",
                "route",
                "idp",
                "policy",
                "certificate",
                "api-key",
                "session",
                "sekisho",
                "instance",
                "acme-state",
                "encryption-key",
            ]
        );
        assert_eq!(
            resource_names_for(ShellMode::Operational, "create"),
            ["api-key"]
        );
        assert_eq!(
            resource_names_for(ShellMode::Operational, "delete"),
            ["route", "idp", "certificate", "api-key", "session"]
        );
        assert_eq!(
            resource_names_for(ShellMode::Config, "create"),
            ["route", "idp", "policy"]
        );
        assert_eq!(
            resource_names_for(ShellMode::Config, "show"),
            ["config", "route", "idp", "policy", "sekisho", "instance"]
        );
        assert_eq!(
            resource_names_for(ShellMode::Config, "edit"),
            ["route", "idp", "policy", "sekisho", "instance"]
        );
        assert_eq!(
            resource_names_for(ShellMode::Config, "delete"),
            ["route", "idp", "policy"]
        );
        assert_eq!(
            resource_names_for(ShellMode::Operational, "upload"),
            ["certificate"]
        );
        for verb in ["enable", "disable"] {
            assert_eq!(resource_names_for(ShellMode::Operational, verb), ["route"]);
        }
        for verb in ["add", "activate", "retire", "rotate"] {
            assert_eq!(
                resource_names_for(ShellMode::Operational, verb),
                ["encryption-key"]
            );
        }
    }

    #[test]
    fn unsupported_create_and_delete_resources_are_rejected() {
        for resource in ["route", "idp", "acme-state", "encryption-key"] {
            assert!(!resource_is_allowed(
                ShellMode::Operational,
                "create",
                resource
            ));
        }
        for resource in ["acme-state", "encryption-key", "policy"] {
            assert!(!resource_is_allowed(
                ShellMode::Operational,
                "delete",
                resource
            ));
        }
    }

    #[test]
    fn instance_label_prefers_name_over_domain_over_id() {
        assert_eq!(
            instance_label(&json!({ "name": "n", "domain": "d", "id": "i" })),
            Some("n".into())
        );
        assert_eq!(
            instance_label(&json!({ "domain": "d", "id": "i" })),
            Some("d".into())
        );
        assert_eq!(instance_label(&json!({ "id": "i" })), Some("i".into()));
        assert_eq!(instance_label(&json!({})), None);
    }

    #[test]
    fn instance_label_skips_empty_strings() {
        assert_eq!(
            instance_label(&json!({ "name": "", "id": "fallback" })),
            Some("fallback".into())
        );
    }
}
