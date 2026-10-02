//! DEK ring management sub-handlers.
//!
//! The visible UI lives in the `/general` Danger Zone (see
//! `views::general::encryption_keys_section`); this module
//! owns the four POST endpoints that mutate the daemon's DEK ring:
//!
//! * `POST /general/encryption_keys` — generate + insert (inactive)
//! * `POST /general/encryption_keys/{id}/activate`
//! * `POST /general/encryption_keys/{id}/retire`
//! * `POST /general/encryption_keys/rotate` — bulk re-encrypt
//!
//! Every handler re-renders the consolidated General page through
//! [`super::general::render_with_dek_state`] so success banners (the
//! one-shot `key_hex` after add, or the `examined/reencrypted/skipped`
//! counters after rotate) and error banners (the leader-fence hint
//! after a 503, or the safety-check refusal after a premature retire)
//! stay anchored at the encryption-keys section the operator just
//! submitted from.
//!
//! The daemon-side API already enforces the leader fence and the
//! "refuse retire while rows still encrypt with this key" check, so
//! the webui doesn't try to second-guess either policy — it just
//! surfaces the error message verbatim.

use axum::{
    Extension,
    extract::{Path, State},
    response::Response,
};
use sekisho_api_protocol::api_paths;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::guard::AuthenticatedUser;

use super::general::{DekFlash, render_with_dek_state};

pub async fn add(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let u = user.as_deref();
    match s
        .client
        .post_json::<Value>(api_paths::ENCRYPTION_KEYS, &json!({}))
        .await
    {
        Ok(v) => render_with_dek_state(&s, u, DekFlash::Added(v)).await,
        Err(e) => render_with_dek_state(&s, u, DekFlash::Error(humanise(&e))).await,
    }
}

pub async fn activate(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(key_id): Path<i16>,
) -> Response {
    let u = user.as_deref();
    let path = format!("{}/{}/activate", api_paths::ENCRYPTION_KEYS, key_id);
    match s.client.post_json::<Value>(&path, &json!({})).await {
        Ok(_) => render_with_dek_state(&s, u, DekFlash::None).await,
        Err(e) => render_with_dek_state(&s, u, DekFlash::Error(humanise(&e))).await,
    }
}

pub async fn retire(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
    Path(key_id): Path<i16>,
) -> Response {
    let u = user.as_deref();
    let path = format!("{}/{}/retire", api_paths::ENCRYPTION_KEYS, key_id);
    match s.client.post_json::<Value>(&path, &json!({})).await {
        Ok(_) => render_with_dek_state(&s, u, DekFlash::None).await,
        Err(e) => render_with_dek_state(&s, u, DekFlash::Error(humanise(&e))).await,
    }
}

pub async fn rotate(
    State(s): State<AppState>,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let u = user.as_deref();
    let path = format!("{}/rotate", api_paths::ENCRYPTION_KEYS);
    match s.client.post_json::<Value>(&path, &json!({})).await {
        Ok(v) => render_with_dek_state(&s, u, DekFlash::Rotated(v)).await,
        Err(e) => render_with_dek_state(&s, u, DekFlash::Error(humanise(&e))).await,
    }
}

/// Strip the boilerplate that [`crate::client::SekishoClient`] wraps
/// around upstream errors (`"/encryption_keys/0/activate -> 503: ..."`)
/// down to the daemon's actual message, and tack on a leader-fence
/// retry hint when the upstream status was 503. The hint is purely
/// additive so a 503 unrelated to the leader (theoretically possible
/// if the daemon is unhealthy) still reads sensibly.
fn humanise(e: &anyhow::Error) -> String {
    let raw = e.to_string();
    let is_503 = raw.contains("-> 503");
    // The daemon's `Error` variants serialise into a JSON envelope.
    // Try to peel out the human-readable `message` field; fall back to
    // the raw string if anything goes sideways.
    // Client wrapper format: `"<path> -> <status>: <body>"`. Split at
    // the first `": "` after `-> ` so a body that itself contains `: `
    // (the daemon's safety-check message does, e.g. `"refusing to
    // retire key_id 3: 17 row(s) ..."`) survives intact.
    let inner: &str = raw
        .find("-> ")
        .and_then(|i| raw[i..].find(": ").map(|j| &raw[i + j + 2..]))
        .unwrap_or(&raw);
    // Daemon error envelope is `{"error":{"code":..,"message":..}}`;
    // older or non-JSON paths fall back to the raw string.
    let msg = serde_json::from_str::<Value>(inner)
        .ok()
        .as_ref()
        .and_then(|v| {
            v.get("error")
                .and_then(|x| x.get("message"))
                .and_then(|m| m.as_str())
                .or_else(|| v.get("message").and_then(|m| m.as_str()))
                .map(str::to_string)
        })
        .unwrap_or_else(|| inner.to_string());
    if is_503 && !msg.contains("leader") {
        format!("{msg} (retry from the cluster leader)")
    } else {
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanise_extracts_daemon_message_from_envelope() {
        let raw = anyhow::anyhow!(
            "/encryption_keys/0/activate -> 503: {{\"error\":{{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"this node is not the cluster leader; retry against node-2\"}}}}"
        );
        let h = humanise(&raw);
        assert!(h.contains("not the cluster leader"));
        assert!(h.contains("node-2"));
        // Already mentions "leader" — no double hint appended.
        assert_eq!(h.matches("leader").count(), 1);
    }

    #[test]
    fn humanise_appends_leader_hint_on_bare_503() {
        let raw = anyhow::anyhow!(
            "/encryption_keys/0/activate -> 503: {{\"error\":{{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"upstream lost contact\"}}}}"
        );
        let h = humanise(&raw);
        assert!(h.contains("retry from the cluster leader"));
    }

    #[test]
    fn humanise_falls_back_to_raw_on_non_json_body() {
        let raw = anyhow::anyhow!("/encryption_keys -> 400: bad request");
        let h = humanise(&raw);
        assert!(h.contains("bad request"));
    }

    #[test]
    fn humanise_passes_through_safety_check_message() {
        let raw = anyhow::anyhow!(
            "/encryption_keys/3/retire -> 400: {{\"error\":{{\"code\":\"BAD_REQUEST\",\"message\":\"refusing to retire key_id 3: 17 row(s) still encrypted with it (run 'rotate encryption-key' first)\"}}}}"
        );
        let h = humanise(&raw);
        assert!(h.contains("refusing to retire"));
        assert!(h.contains("17 row(s)"));
        // No 503 -> no leader hint appended.
        assert!(!h.contains("retry from the cluster leader"));
    }
}
