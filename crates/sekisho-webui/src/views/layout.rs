//! Page chrome shared by every full-page view.
//!
//! ## No inline script or style, anywhere
//!
//! Everything is served from `/_assets/…` on the same origin. That is what
//! lets the CSP stay a flat `script-src 'self'; style-src 'self'` with no
//! nonces and no hashes — a policy with no per-request machinery is one that
//! cannot be weakened by a handler forgetting to thread a nonce through.
//! Adding a single inline `<script>` would force the whole scheme open, so the
//! rule is absolute rather than case-by-case.
//!
//! ## Everything goes through `Page`
//!
//! A builder rather than a free function with six arguments, so a view that
//! omits the CSRF token or the user simply renders without them instead of
//! silently passing them in the wrong positional slot. It is also the single
//! place the version badge is decided, which is why a matching version renders
//! no markup at all rather than an "ok" indicator.

use maud::{DOCTYPE, Markup, html};

use crate::ServerVersion;
use crate::assets::{
    htmx_path, logo_path, pico_path, sekisho_webui_css_path, sekisho_webui_js_path, wordmark_path,
};
use crate::auth::guard::AuthenticatedUser;

/// Compile-time client version, mirrored here so the layout doesn't
/// need to import `main.rs`'s constant. `env!` is evaluated when the
/// crate is built, so this stays in lock-step with the binary.
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Page chrome: doctype, navigation, container. Every full-page view goes
/// through `Page::render`.
///
/// All scripts and stylesheets are served from the same origin under
/// `/_assets/…`; there are no inline `<script>` or `<style>` elements, which
/// lets the CSP stay a strict `script-src 'self'; style-src 'self'` without
/// per-request nonce plumbing.
pub struct Page<'a> {
    pub title: &'a str,
    pub user: Option<&'a AuthenticatedUser>,
    pub show_nav: bool,
    pub csrf_token: Option<&'a str>,
    pub server_version: Option<&'a ServerVersion>,
}

impl<'a> Page<'a> {
    /// Start from the default chrome: navigation shown, no user, no CSRF
    /// token, no version badge. Callers add what they need.
    pub fn new(title: &'a str) -> Self {
        Self {
            title,
            user: None,
            show_nav: true,
            csrf_token: None,
            server_version: None,
        }
    }

    pub fn with_user(mut self, user: Option<&'a AuthenticatedUser>) -> Self {
        self.user = user;
        self
    }

    pub fn with_csrf(mut self, token: &'a str) -> Self {
        self.csrf_token = Some(token);
        self
    }

    pub fn with_server_version(mut self, v: &'a ServerVersion) -> Self {
        self.server_version = Some(v);
        self
    }

    pub fn hide_nav(mut self) -> Self {
        self.show_nav = false;
        self
    }

    pub fn render(self, body: Markup) -> Markup {
        html! {
            (DOCTYPE)
            html lang="en" data-theme="light" {
                head {
                    meta charset="utf-8";
                    meta name="viewport" content="width=device-width, initial-scale=1";
                    @if let Some(t) = self.csrf_token {
                        meta name="csrf-token" content=(t);
                    }
                    title { (self.title) " — Sekisho IAP" }
                    link rel="icon" type="image/svg+xml" href=(logo_path());
                    link rel="stylesheet" href=(pico_path());
                    link rel="stylesheet" href=(sekisho_webui_css_path());
                    script src=(htmx_path()) defer {}
                    // sekisho-webui.js hardens htmx config and wires the CSRF
                    // header; must load after htmx, so `defer` keeps execution
                    // order while not blocking HTML parsing.
                    script src=(sekisho_webui_js_path()) defer {}
                }
                body hx-boost="true" {
                    main class="container" {
                        @if self.show_nav {
                            (nav(self.user, self.server_version))
                        }
                        (body)
                    }
                }
            }
        }
    }
}

fn nav(user: Option<&AuthenticatedUser>, version: Option<&ServerVersion>) -> Markup {
    use crate::registry::RESOURCES;

    // Every nav entry is a compile-time constant now — the registry
    // is API-version-gated, so nav is too.
    let mut entries: Vec<(u8, &'static str, &'static str)> = Vec::new();
    for r in RESOURCES {
        entries.push((r.nav_order, r.mount, r.title));
    }
    entries.sort_by_key(|(o, _, _)| *o);

    html! {
        nav {
            ul {
                li {
                    strong {
                        a href="/" class="brand" {
                            img src=(wordmark_path()) alt="sekisho" class="brand-mark";
                        }
                    }
                }
            }
            ul {
                @for (_, mount, label) in &entries {
                    li { a href=(format!("/{mount}")) { (label) } }
                }
            }
            ul {
                @if let Some(v) = version {
                    @let badge = version_badge(v);
                    @if !badge.0.is_empty() {
                        li class="version-badge" { (badge) }
                    }
                }
                @if let Some(u) = user {
                    li class="signed-in-as" {
                        small class="muted" {
                            span { "signed in as" } br;
                            strong { (u.user) }
                        }
                    }
                }
            }
        }
    }
}

/// Render the version-state badge.
///
/// Always renders something — the post-General-consolidation nav has
/// the room — so the operator gets a positive "yes, the binaries
/// agree" signal alongside the warning states.
///
/// * `Match` — compact green `v<VER>`, tooltip carries the full pair.
/// * `Mismatch` — red `⚠ vCLI↔SERVER` for compatible product-version skew,
///   with the full sentence in the `title` attribute.
/// * `Unreachable` — yellow `⚠ vCLI↔?`. Distinct from Mismatch so the
///   operator knows it's a connectivity issue, not a drift.
pub fn version_badge(state: &ServerVersion) -> Markup {
    match state {
        ServerVersion::Match => {
            let label = format!("v{CLIENT_VERSION}");
            let tip = format!("sekisho-webui and sekisho daemon both report {CLIENT_VERSION}.");
            html! {
                small class="version-warning ok" title=(tip) { (label) }
            }
        }
        ServerVersion::Mismatch(server) => {
            let label = format!("⚠ v{CLIENT_VERSION}↔{server}");
            let tip = format!(
                "Product version differs: sekisho-webui is {CLIENT_VERSION}, sekisho daemon is \
                 {server}. Their management API version is compatible."
            );
            html! {
                small class="version-warning mismatch" title=(tip) { (label) }
            }
        }
        ServerVersion::Unreachable => {
            let label = format!("⚠ v{CLIENT_VERSION}↔?");
            let tip = format!(
                "Could not reach the sekisho daemon's /version endpoint at startup. \
                 sekisho-webui is {CLIENT_VERSION}; the daemon's version is unknown."
            );
            html! {
                small class="version-warning unreachable" title=(tip) { (label) }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_renders_compact_green_badge() {
        let m = version_badge(&ServerVersion::Match).into_string();
        assert!(m.contains(CLIENT_VERSION), "expected version label: {m}");
        assert!(
            m.contains("class=\"version-warning ok\""),
            "expected ok class: {m}"
        );
        assert!(m.contains("title="), "expected hover tooltip: {m}");
        assert!(!m.contains("⚠"), "match must not carry warning sigil: {m}");
    }

    #[test]
    fn mismatch_renders_compact_with_tooltip() {
        let m = version_badge(&ServerVersion::Mismatch("9.9.9".into())).into_string();
        assert!(m.contains("⚠"), "expected warning sigil: {m}");
        assert!(m.contains("9.9.9"), "expected server version: {m}");
        assert!(m.contains(CLIENT_VERSION), "expected client version: {m}");
        assert!(m.contains("title="), "expected hover tooltip: {m}");
        assert!(
            m.contains("class=\"version-warning mismatch\""),
            "expected mismatch class: {m}"
        );
    }

    #[test]
    fn unreachable_renders_compact_with_question_mark() {
        let m = version_badge(&ServerVersion::Unreachable).into_string();
        assert!(m.contains("⚠"), "expected warning sigil");
        assert!(m.contains("↔?"), "expected unknown-server marker");
        assert!(m.contains(CLIENT_VERSION));
        assert!(
            m.contains("class=\"version-warning unreachable\""),
            "expected unreachable class: {m}"
        );
    }

    #[test]
    fn nav_omits_instance_from_top_level() {
        // Render nav with no user / no version state — instance is
        // consolidated under General rather than exposed at top level.
        let html = nav(None, None).into_string();
        assert!(html.contains(">General<"), "General entry expected");
        assert!(
            !html.contains("href=\"/instance\""),
            "Instance should not be a top-level nav entry: {html}"
        );
    }

    #[test]
    fn nav_lists_seven_top_level_entries() {
        // Routes / Policies / Certificates / Sessions / Identity Providers
        // / API Keys / General — exactly seven.
        use crate::registry::RESOURCES;
        assert_eq!(RESOURCES.len(), 7, "expected 7 nav resources");
    }
}
