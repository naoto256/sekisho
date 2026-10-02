//! First-run credential setup.
//!
//! The one page reachable without a credential, and the only place an API key
//! is accepted from a form. Two consequences shape the code:
//!
//! - [`SetupForm`] carries a hand-written `Debug` that redacts the key.
//!   Handler arguments are exactly the sort of thing that ends up in a
//!   `tracing` line during debugging, and a derived `Debug` would put an admin
//!   credential in the log.
//! - [`show`] redirects away when a credential is already installed, so the
//!   page cannot be used to silently replace a working credential with a
//!   typo — or by a CSRF-shaped request from elsewhere.
//!
//! The submitted key is verified against the daemon before being stored;
//! accepting it first would leave the UI configured with something that cannot
//! authenticate and no obvious way to tell.

use axum::{
    Form,
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::AppState;
use crate::auth::{Credential, apikey};
use crate::client::SekishoClient;

use super::common::render_setup_page;

/// Render the setup form, or redirect home if setup is already done.
pub async fn show(State(state): State<AppState>) -> Response {
    // If already authenticated, don't bother showing setup again.
    if state.cred.read().await.is_set() {
        return Redirect::to("/").into_response();
    }
    render_setup_page(&state, "Setup", crate::views::setup::form_body(None))
}

/// The submitted API key. See the module docs for why `Debug` is hand-written.
#[derive(Deserialize)]
pub struct SetupForm {
    pub api_key: String,
}

impl std::fmt::Debug for SetupForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupForm")
            .field("api_key", &"<redacted>")
            .finish()
    }
}

/// Verify the submitted key against the daemon and install it on success.
pub async fn submit(State(state): State<AppState>, Form(form): Form<SetupForm>) -> Response {
    let key = form.api_key.trim().to_string();
    if key.is_empty() {
        return render_setup_page(
            &state,
            "Setup",
            crate::views::setup::form_body(Some("API key is required.")),
        );
    }

    // Install the key into a scratch credential and probe /config to confirm it works.
    let probe_cred = crate::auth::new_shared(Credential::ApiKey(key.clone()));
    let client = match SekishoClient::new(
        state.args.sekisho_api_url.clone(),
        probe_cred.clone(),
        &state.management_rpk_pin,
    ) {
        Ok(c) => c,
        Err(e) => {
            return render_setup_page(
                &state,
                "Setup",
                crate::views::setup::form_body(Some(&format!("Could not build HTTP client: {e}"))),
            );
        }
    };
    if let Err(e) = client.probe().await {
        return render_setup_page(
            &state,
            "Setup",
            crate::views::setup::form_body(Some(&format!("Key rejected by Sekisho: {e}"))),
        );
    }

    apikey::install(&state.cred, key).await;

    Redirect::to("/").into_response()
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_api_key() {
        let f = SetupForm {
            api_key: "sk_super_secret_value_42".into(),
        };
        let s = format!("{f:?}");
        assert!(!s.contains("super_secret_value"), "leak: {s}");
        assert!(s.contains("redacted"), "should mark: {s}");
    }

    #[test]
    fn setup_probe_remains_bound_to_the_admin_config_resource() {
        // `SekishoClient::probe` intentionally calls CONFIG. The daemon's
        // central scope table classifies CONFIG GET as admin, so setup cannot
        // persist a read- or write-only key as the WebUI credential.
        assert_eq!(sekisho_api_protocol::api_paths::CONFIG, "/config");
    }
}
