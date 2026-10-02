//! API key entry screen body. The handler wraps this in `render_setup_page`
//! so the CSRF token lands in the surrounding layout.

use maud::{Markup, html};

pub fn form_body(error: Option<&str>) -> Markup {
    html! {
        article {
            hgroup {
                h2 { "Enter a Sekisho API key" }
                p { "sekisho-webui needs a management API key to talk to Sekisho. "
                    "The key is held only in process memory; restarting sekisho-webui "
                    "means re-entering it." }
            }
            @if let Some(err) = error {
                div class="flash error" { (err) }
            }
            form method="post" action="/setup" {
                label {
                    "API key"
                    input type="password" name="api_key" autofocus required placeholder="sk_...";
                }
                button type="submit" { "Use this key" }
            }
            footer {
                small {
                    "Prefer passwordless? Restart sekisho-webui with "
                    code { "--local-auth" }
                    " to use the Unix control socket."
                }
            }
        }
    }
}
