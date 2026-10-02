//! Dashboard body.
//!
//! Deliberately static: a card per resource and nothing else. The landing page
//! is reached before the operator has said what they want, so it costs nothing
//! to render and cannot fail — any live counts here would mean a fan-out of
//! management API calls on the one page that must always come up, including
//! when the daemon is the thing that is broken.

use maud::{Markup, html};

use crate::auth::guard::AuthenticatedUser;

/// Dashboard body. Wrapped in the standard page chrome by the handler.
pub fn index(_user: Option<&AuthenticatedUser>) -> Markup {
    html! {
        hgroup {
            h1 { "Sekisho admin" }
            p { "Browse and edit configuration for the Sekisho identity-aware proxy." }
        }
        section {
            div class="grid" {
                article {
                    h4 { "Routes" }
                    p { "Upstream bindings, TLS, access policies." }
                    a href="/routes" role="button" { "Open" }
                }
                article {
                    h4 { "Identity providers" }
                    p { "OIDC or SAML sources used to authenticate end users." }
                    a href="/idps" role="button" { "Open" }
                }
                article {
                    h4 { "Certificates" }
                    p { "Issued and uploaded certificates for TLS termination." }
                    a href="/certificates" role="button" { "Open" }
                }
            }
            div class="grid" {
                article {
                    h4 { "API keys" }
                    p { "Credentials for this management API." }
                    a href="/api_keys" role="button" { "Open" }
                }
                article {
                    h4 { "Sessions" }
                    p { "Currently active end-user sessions." }
                    a href="/sessions" role="button" { "Open" }
                }
                article {
                    h4 { "General" }
                    p { "Daemon-wide config, instance config, and encryption keys." }
                    a href="/general" role="button" { "Open" }
                }
            }
        }
    }
}
