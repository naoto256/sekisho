//! Version-locked resource registry.
//!
//! sekisho-webui's UI knowledge of every Sekisho resource is compiled in.
//! That matches sekisho-cli's approach and completes the "server is
//! data-plus-integrity only, clients ship with matching domain
//! knowledge" architecture. There is no runtime fetch of schemas or
//! descriptors; a sekisho-webui binary is married to the server version
//! it was built against.
//!
//! Adding a resource server-side therefore *does* require rebuilding
//! sekisho-webui. The previous dynamic-discovery scheme sounded nice in
//! theory but leaked UI concerns back into the server — the split was
//! a fiction. With `GET /version` gating startup, version drift now
//! surfaces as a clear refusal rather than a subtly broken form.

/// One entry in the navigation bar. Every field is `&'static str` — this
/// whole table is a compile-time constant.
#[derive(Debug, Clone, Copy)]
pub struct Resource {
    /// Path segment in the sekisho-webui URL (`/<mount>`).
    pub mount: &'static str,
    /// Page title / nav label (human, title-cased).
    pub title: &'static str,
    /// Nav ordering — lower comes first.
    pub nav_order: u8,
}

pub const RESOURCES: &[Resource] = &[
    Resource {
        mount: "routes",
        title: "Routes",
        nav_order: 10,
    },
    Resource {
        mount: "policies",
        title: "Policies",
        nav_order: 20,
    },
    Resource {
        mount: "certificates",
        title: "Certificates",
        nav_order: 30,
    },
    Resource {
        mount: "sessions",
        title: "Sessions",
        nav_order: 40,
    },
    Resource {
        mount: "idps",
        title: "Identity Providers",
        nav_order: 50,
    },
    Resource {
        mount: "api_keys",
        title: "API Keys",
        nav_order: 60,
    },
    // Consolidated "General" page — the daemon's global config plus
    // rare-but-dangerous instance and encryption-key operations grouped
    // under a single nav entry.
    Resource {
        mount: "general",
        title: "General",
        nav_order: 70,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounts_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for r in RESOURCES {
            assert!(seen.insert(r.mount), "duplicate mount: {}", r.mount);
        }
    }
}
