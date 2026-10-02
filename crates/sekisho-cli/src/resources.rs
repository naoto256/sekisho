//! The compile-time resource and field tree the shell renders from.
//!
//! This is the client half of the version-locked split: the daemon serves data
//! and knows nothing about presentation, and everything about *how* a resource
//! looks — which fields exist, their types, their order, what completes — lives
//! here. The tradeoff is explicit. A UI-visible field change touches this file
//! as well as the server, which is acceptable because the two ship together,
//! and in exchange the shell gets completion and validation that a
//! schema-driven client could not produce.
//!
//! Field paths are kebab-case at the shell surface and translated to the
//! JSON names on the way out, so the command language reads like a CLI rather
//! than like the wire format.

//! Resource registry — the shell's version-locked knowledge of what
//! lives on the server.
//!
//! Previously this was fetched at startup from `GET /_internal/resources`
//! and `GET /schema/{resource}`; the server ran a full schemars tree walk
//! and the client mirrored it. That scheme failed in practice — UI-only
//! concerns (read-only flags, enum hints, label derivation) leaked back
//! into the server and the split stopped paying for itself. Now the
//! shell ships with its own version-matched description of every
//! resource it knows about, and the server's sole job is CRUD plus
//! referential integrity.
//!
//! Adding a new resource or field: edit the `RESOURCES` table here,
//! then make sure the server accepts the shape. No `schemars` dance,
//! no schema fetch, no indirection.
//!
//! All lookups are compiled down to a static `Vec<ResourceDef>`
//! through `std::sync::OnceLock` so the hot paths (tab completion,
//! `edit` scope walks) pay zero per-call allocation.

use sekisho_api_protocol::api_paths;
use std::sync::OnceLock;

/// Everything the shell needs to know to interact with one kind of
/// server-managed object. Field tree plus enough bits to drive the
/// show / edit / create / delete verbs.
#[derive(Debug, Clone)]
/// One manageable resource: its shell name, its API path, and its field tree.
pub struct ResourceDef {
    pub name: &'static str,
    pub api_path: &'static str,
    /// Singleton resources (currently just `config`) occupy the full
    /// API path on their own — no `/{id}` segment.
    pub directly_editable: bool,
    /// Appears in `show config` dumps and config-mode create/delete.
    pub config: bool,
    /// Appears in operational verbs (`show`, `delete <operational
    /// resource>`). Not mutually exclusive with `config` — `idp`
    /// straddles both.
    pub operational: bool,
    /// `create <resource> <name>` is accepted (excludes server-managed
    /// resources like sessions and certificates).
    pub creatable: bool,
    /// Top-level field tree for the resource. Nested objects descend
    /// through `FieldNode.children`.
    pub fields: Vec<FieldNode>,
}

#[derive(Debug, Clone)]
/// A node in a resource's field tree. Nested objects and arrays are
/// represented structurally rather than flattened, so `edit` can walk into a
/// sub-object and completion knows where it is.
pub struct FieldNode {
    pub name: &'static str,
    /// Short type tag (`"string"`, `"bool"`, `"number"`, `"uuid"`,
    /// `"idp_ref"`, `"string[]"`, `"object"`). Drives `set` value
    /// parsing and the `is_array_field` / `is_object_field` /
    /// `is_idp_ref_field` helpers. `idp_ref` is a UUID on the wire but
    /// the shell accepts an IdP name on input and resolves it via the
    /// API before PATCH.
    pub ty: &'static str,
    pub children: Vec<FieldNode>,
    /// This node is a scalar leaf the user can `set`. Object-typed
    /// nodes are `editable: false` themselves — the user descends
    /// into them via `edit <field>`. Server-managed values (`id`,
    /// `created_at`, `enabled`, ...) are also `editable: false`;
    /// they only appear here if `show` should render them.
    pub editable: bool,
}

impl FieldNode {
    /// `true` if this node or any descendant is editable. Used by
    /// `edit` tab completion to hide dead-end subtrees.
    pub fn has_editable_descendant(&self) -> bool {
        self.editable || self.children.iter().any(|c| c.has_editable_descendant())
    }
}

fn leaf(name: &'static str, ty: &'static str) -> FieldNode {
    FieldNode {
        name,
        ty,
        children: Vec::new(),
        editable: true,
    }
}

fn readonly(name: &'static str, ty: &'static str) -> FieldNode {
    FieldNode {
        name,
        ty,
        children: Vec::new(),
        editable: false,
    }
}

fn object(name: &'static str, children: Vec<FieldNode>) -> FieldNode {
    FieldNode {
        name,
        ty: "object",
        children,
        editable: false,
    }
}

/// Every resource, in navigation order. The order is presentation, not data —
/// it decides what `show ?` lists first.
pub fn resources() -> &'static [ResourceDef] {
    static R: OnceLock<Vec<ResourceDef>> = OnceLock::new();
    R.get_or_init(build_resources).as_slice()
}

/// Look up a resource by its shell name, or `None` if the operator typed
/// something that is not a resource.
pub fn descriptor(name: &str) -> Option<&'static ResourceDef> {
    resources().iter().find(|r| r.name == name)
}

/// Map a shell resource name to its management API path.
pub fn resource_api_path(name: &str) -> &'static str {
    descriptor(name).map(|r| r.api_path).unwrap_or("")
}

/// Whether a resource is a singleton config object rather than a collection.
/// Singletons have no id, so `show`/`set` address them directly and the shell
/// must not offer list or delete verbs for them.
pub fn is_config_resource(name: &str) -> bool {
    descriptor(name).map(|r| r.config).unwrap_or(false)
}

/// Singleton resources have no `/{id}` segment: the verb operates on a
/// fixed row. `sekisho` and `bootstrap` are singletons today.
pub fn is_singleton(name: &str) -> bool {
    descriptor(name)
        .map(|r| r.directly_editable)
        .unwrap_or(false)
}

fn build_resources() -> Vec<ResourceDef> {
    vec![
        ResourceDef {
            name: "route",
            api_path: api_paths::ROUTES,
            directly_editable: false,
            config: true,
            operational: true,
            creatable: true,
            fields: vec![
                leaf("name", "string"),
                leaf("from", "string"),
                leaf("path", "string"),
                leaf("to", "string[]"),
                object(
                    "redirect",
                    vec![
                        leaf("host_redirect", "string"),
                        leaf("path_redirect", "string"),
                        leaf("code", "number"),
                    ],
                ),
                leaf("idp_id", "uuid"),
                object(
                    "access",
                    vec![
                        leaf("policy", "string"),
                        leaf("allow_public_unauthenticated_access", "bool"),
                    ],
                ),
                leaf("load_balancing", "string"),
                leaf("preserve_host_header", "bool"),
                leaf("host_rewrite", "string"),
                leaf("timeout_ms", "number"),
                leaf("response_idle_timeout_ms", "number"),
                leaf("enable_websocket", "bool"),
                leaf("enable_grpc", "bool"),
                leaf("regex_rewrite_pattern", "string"),
                leaf("regex_rewrite_substitution", "string"),
                leaf("enable_signed_identity", "bool"),
                leaf("tls_skip_verify", "bool"),
                leaf("tls_downstream", "string"),
                object(
                    "headers",
                    vec![
                        leaf("add", "object"),
                        leaf("remove", "string[]"),
                        // Opt-in to add/remove `Authorization` /
                        // `Cookie` from route config. Default false;
                        // flip true when wiring the IAP-classic
                        // pattern (OIDC at the proxy + basic auth
                        // toward upstream).
                        leaf("allow_credential_overrides", "bool"),
                    ],
                ),
                // SameSite override for the session cookie minted on
                // this host. Empty / unset = inherit Lax default.
                // Set to "none" for upstreams that run their own
                // SAML SP — the IdP's SAMLResponse POST is cross-
                // site and would otherwise drop the IAP cookie.
                // "strict" included for completeness; breaks proxy-
                // level OIDC/SAML callbacks.
                leaf("session_cookie_samesite", "string"),
                leaf("response_location_rewrite", "bool"),
                // `enabled` is settable only via `enable route`/`disable
                // route` — the edit flow should render it (so `show`
                // users can see it) but refuse `set enabled`.
                readonly("enabled", "bool"),
                // Empty / unset inherits the global proxy budget. Zero is a
                // valid explicit cap and rejects every request to the route.
                leaf("concurrency_limit", "number"),
            ],
        },
        ResourceDef {
            name: "idp",
            api_path: api_paths::IDPS,
            directly_editable: false,
            config: true,
            operational: true,
            creatable: true,
            fields: vec![
                leaf("name", "string"),
                leaf("type", "string"),
                // OIDC: `client_secret` is plaintext on the wire. The
                // server encrypts with the master key and returns
                // `**REDACTED**` on GET; an empty value on PATCH means
                // "leave the stored secret alone".
                object(
                    "oidc_config",
                    vec![
                        leaf("issuer_url", "string"),
                        leaf("client_id", "string"),
                        leaf("client_secret", "string"),
                        leaf("scopes", "string[]"),
                        leaf("prompt", "string"),
                    ],
                ),
                // SAML: field names match `sekishod::models::idp::SamlConfig`
                // directly. `attribute_mapping` is a free-form string→string
                // map but the server only consults the `email` and
                // `groups` keys — `set attribute_mapping.email "mail"`
                // is the typical form.
                object(
                    "saml_config",
                    vec![
                        leaf("metadata_url", "string"),
                        leaf("slo_url", "string"),
                        leaf("name_id_format", "string"),
                        object(
                            "attribute_mapping",
                            vec![leaf("email", "string"), leaf("groups", "string")],
                        ),
                    ],
                ),
            ],
        },
        ResourceDef {
            name: "policy",
            api_path: api_paths::POLICIES,
            directly_editable: false,
            config: true,
            operational: false,
            creatable: true,
            // Server's `Policy` struct has just `name` and `expr`; there
            // is no `description` column. `edit-expr` writes to `expr`
            // too (shell.rs), so keep them in step.
            fields: vec![leaf("name", "string"), leaf("expr", "string")],
        },
        ResourceDef {
            name: "certificate",
            api_path: api_paths::CERTS,
            directly_editable: false,
            config: false,
            operational: true,
            creatable: false,
            fields: vec![
                readonly("id", "uuid"),
                readonly("domain", "string"),
                readonly("source", "string"),
                readonly("issued_at", "string"),
                readonly("expires_at", "string"),
            ],
        },
        ResourceDef {
            // Kebab-case on the CLI side (`delete api-key <name>`); the
            // server routes the collection at `/api_keys` though.
            name: "api-key",
            api_path: api_paths::API_KEYS,
            directly_editable: false,
            config: false,
            operational: true,
            creatable: true,
            fields: vec![
                leaf("name", "string"),
                readonly("scopes", "array"),
                readonly("prefix", "string"),
                readonly("created_at", "string"),
                readonly("last_used_at", "string"),
            ],
        },
        ResourceDef {
            name: "session",
            api_path: api_paths::SESSIONS,
            directly_editable: false,
            config: false,
            operational: true,
            creatable: false,
            fields: vec![
                readonly("id", "uuid"),
                readonly("user_id", "string"),
                readonly("idp_id", "uuid"),
                readonly("created_at", "string"),
                readonly("expires_at", "string"),
                readonly("last_accessed_at", "string"),
            ],
        },
        // The singleton `config` resource — no instances, edited in
        // place. Named `sekisho` in the edit prompt for the "sekisho
        // itself" intuition (analogous to JunOS `system` being the
        // device root).
        ResourceDef {
            name: "sekisho",
            api_path: api_paths::CONFIG,
            directly_editable: true,
            config: true,
            operational: false,
            creatable: false,
            fields: vec![
                // proxy_listen / api_listen / http_listen used to be
                // here. They moved to the per-instance bootstrap
                // (`set instance proxy_listen ...`) because bind
                // addresses are node-local — every HA peer listens on
                // its own NIC and a cluster-wide GlobalConfig field
                // would force every peer to share an address.
                leaf("auth_domain", "string"),
                leaf("cookie_name", "string"),
                leaf("session_lifetime_hours", "number"),
                // `idp_ref`: accepts either an IdP UUID or an IdP
                // name; name → UUID resolution happens client-side in
                // `cmd_set` so the server API stays UUID-only.
                leaf("default_idp_id", "idp_ref"),
                leaf("acme_email", "string"),
                leaf("acme_directory", "string"),
                // HA: pin the ACME-renewal leader to a specific instance.
                // Empty / unset = automatic election (recommended).
                leaf("acme_leader", "string"),
                leaf("websocket_concurrency_limit", "number"),
                leaf("acme_queue_capacity", "number"),
                leaf("acme_issuance_concurrency_limit", "number"),
                leaf("acme_renewal_scan_interval_hours", "number"),
                leaf("log_level", "string"),
            ],
        },
        // Singleton instance resource — instance-local
        // configuration. Carries both the encrypted `cluster_db_url`
        // (returned as `**REDACTED**`) and the plaintext per-node
        // listen addresses. The server response distinguishes the
        // two: `cluster_db_url` is redacted, the listen fields are
        // round-tripped verbatim because they're not secrets. All
        // mutations require a daemon restart to take effect; the
        // shell surfaces that hint when rendering the API response.
        ResourceDef {
            name: "instance",
            api_path: api_paths::INSTANCE,
            directly_editable: true,
            config: true,
            operational: false,
            creatable: false,
            fields: vec![
                leaf("cluster_db_url", "string"),
                leaf("proxy_listen", "string"),
                leaf("proxy_accept_from", "string"),
                leaf("api_listen", "string"),
                leaf("api_accept_from", "string"),
                leaf("http_listen", "string"),
                leaf("http_accept_from", "string"),
            ],
        },
        // Singleton read-only view into the ACME leader election. No
        // editable fields (operator pins via `set acme_leader` on the
        // `sekisho` config); this is purely operational debugging — who
        // currently owns issuance, when did their heartbeat last
        // refresh, do they match the pinned override.
        ResourceDef {
            name: "acme-state",
            api_path: api_paths::ACME_LEADER_ELECTION,
            directly_editable: true,
            config: false,
            operational: true,
            creatable: false,
            fields: vec![
                readonly("my_node_id", "string"),
                readonly("current_leader_node_id", "string"),
                readonly("current_leader_updated_at", "string"),
                readonly("i_am_leader", "bool"),
                readonly("pinned_acme_leader", "string"),
            ],
        },
        // DEK ring rows. Read-only from the resource-registry POV: the
        // mutating verbs (add / activate / retire / rotate) live as
        // top-level operational commands in shell.rs because their UX
        // ("here's the new key, save it offline") doesn't fit the
        // generic create / edit / delete vocabulary.
        ResourceDef {
            name: "encryption-key",
            api_path: api_paths::ENCRYPTION_KEYS,
            directly_editable: false,
            config: false,
            operational: true,
            creatable: false,
            fields: vec![
                readonly("key_id", "number"),
                readonly("status", "string"),
                readonly("active", "bool"),
                readonly("retired", "bool"),
            ],
        },
    ]
}

/// Fields reachable at a given nested scope. `path` is the staged
/// edit position (each segment is a snake_case field name); an empty
/// path returns the resource's top-level fields. Returns an empty
/// slice if the path descends through a non-object or an unknown
/// resource.
pub fn scope_fields(resource: &str, path: &[String]) -> Vec<FieldNode> {
    let Some(def) = descriptor(resource) else {
        return Vec::new();
    };
    let mut cursor: &[FieldNode] = &def.fields;
    for seg in path {
        match cursor.iter().find(|f| f.name == seg.as_str()) {
            Some(f) if !f.children.is_empty() => cursor = &f.children,
            _ => return Vec::new(),
        }
    }
    cursor.to_vec()
}

/// Whether a field holds an array. Drives the shell's set/append handling:
/// an array field takes repeated values, a scalar one does not.
pub fn is_array_field(resource: &str, path: &[String], field_kebab: &str) -> bool {
    let field_snake = field_kebab.replace('-', "_");
    scope_fields(resource, path)
        .iter()
        .any(|f| f.name == field_snake && f.ty == "string[]")
}

/// Whether a field is a nested object, i.e. whether `edit` can descend into
/// it rather than treating it as a value.
pub fn is_object_field(resource: &str, path: &[String], field_kebab: &str) -> bool {
    let field_snake = field_kebab.replace('-', "_");
    scope_fields(resource, path)
        .iter()
        .any(|f| f.name == field_snake && !f.children.is_empty())
}

/// `true` if the field at (resource, path, field) is tagged `idp_ref`.
/// `cmd_set` uses this to decide whether a non-UUID value should be
/// looked up in the IdP list before being sent to the server.
pub fn is_idp_ref_field(resource: &str, path: &[String], field_kebab: &str) -> bool {
    let field_snake = field_kebab.replace('-', "_");
    scope_fields(resource, path)
        .iter()
        .any(|f| f.name == field_snake && f.ty == "idp_ref")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_resources_are_present() {
        for name in [
            "route",
            "idp",
            "policy",
            "certificate",
            "api-key",
            "session",
            "sekisho",
            "instance",
        ] {
            assert!(descriptor(name).is_some(), "missing resource: {name}");
        }
    }

    #[test]
    fn instance_is_singleton_with_cluster_db_url() {
        let b = descriptor("instance").expect("instance resource");
        assert!(b.directly_editable, "instance is a singleton");
        assert!(!b.creatable, "instance has no create verb");
        assert!(
            b.fields
                .iter()
                .any(|f| f.name == "cluster_db_url" && f.editable),
            "cluster_db_url must be settable",
        );
    }

    #[test]
    fn route_has_access_policy_at_two_levels_deep() {
        let fields = scope_fields("route", &["access".into()]);
        assert!(
            fields
                .iter()
                .any(|f| f.name == "policy" && f.ty == "string"),
            "access.policy should be reachable",
        );
    }

    #[test]
    fn route_enabled_is_read_only() {
        let fields = scope_fields("route", &[]);
        let enabled = fields
            .iter()
            .find(|f| f.name == "enabled")
            .expect("enabled field");
        assert!(!enabled.editable, "enabled must not be settable via `set`");
    }

    /// The shell's compile-time field map matches the server's route model
    /// shape. That is what the version handshake relies on to detect skew — it
    /// does not establish that the server will accept any particular payload,
    /// which only the server's own validation decides.
    #[test]
    fn route_field_tree_covers_the_mutable_server_shape() {
        let route = descriptor("route").expect("route resource");
        let names: Vec<_> = route.fields.iter().map(|field| field.name).collect();
        assert_eq!(
            names,
            [
                "name",
                "from",
                "path",
                "to",
                "redirect",
                "idp_id",
                "access",
                "load_balancing",
                "preserve_host_header",
                "host_rewrite",
                "timeout_ms",
                "response_idle_timeout_ms",
                "enable_websocket",
                "enable_grpc",
                "regex_rewrite_pattern",
                "regex_rewrite_substitution",
                "enable_signed_identity",
                "tls_skip_verify",
                "tls_downstream",
                "headers",
                "session_cookie_samesite",
                "response_location_rewrite",
                "enabled",
                "concurrency_limit",
            ]
        );
        for (name, ty) in [
            ("response_location_rewrite", "bool"),
            ("concurrency_limit", "number"),
        ] {
            let field = route
                .fields
                .iter()
                .find(|field| field.name == name)
                .unwrap_or_else(|| panic!("missing route field {name}"));
            assert_eq!(field.ty, ty);
            assert!(field.editable, "{name} must be editable");
        }
    }

    #[test]
    fn array_detection() {
        assert!(is_array_field("route", &[], "to"));
        assert!(!is_array_field("route", &[], "from"));
    }

    #[test]
    fn object_detection() {
        assert!(is_object_field("route", &[], "access"));
        assert!(!is_object_field("route", &[], "name"));
    }

    #[test]
    fn default_idp_id_is_an_idp_ref() {
        assert!(is_idp_ref_field("sekisho", &[], "default_idp_id"));
        assert!(is_idp_ref_field("sekisho", &[], "default-idp-id"));
        // A plain UUID leaf (route.idp_id stays a raw UUID) is not an
        // idp_ref.
        assert!(!is_idp_ref_field("route", &[], "idp_id"));
        // Unknown fields are never idp_refs.
        assert!(!is_idp_ref_field("sekisho", &[], "auth_domain"));
    }
}
