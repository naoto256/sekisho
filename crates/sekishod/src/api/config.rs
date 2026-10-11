//! Global configuration read and patch.
//!
//! ## `_restart_required` is advisory, and computed per request
//!
//! Several fields are only read at startup, so patching them changes the
//! stored value without changing the running daemon. Rather than reject those
//! patches — an operator staging config before a planned restart is a
//! legitimate thing to do — the response carries a `_restart_required` list
//! naming which of the restart-sensitive fields [`update`] tracks have
//! changed, and the same list goes into the audit event.
//!
//! The list comes from comparing the stored config before and after the
//! update, value against value as stored, so a patch that leaves the tracked
//! fields as they were — including one that sends a value already stored —
//! says nothing. Which fields are tracked is written out in [`update`];
//! keeping that in step with the fields that are actually read at startup is
//! a manual obligation, and the per-field docs on
//! [`crate::models::config::GlobalConfig`] are the other half of it.

use axum::Json;
use axum::extract::{Extension, State};
use axum::response::IntoResponse;

use super::SanitizedJson;
use crate::audit::{self, Actor};
use crate::error::Result;
use crate::models::config::UpdateGlobalConfig;
use crate::validation;

/// Return the global config. No redaction: nothing in
/// [`crate::models::config::GlobalConfig`] is secret — secrets live in the
/// encrypted KV, not here.
pub async fn get(State(store): State<crate::store::Store>) -> Result<impl IntoResponse> {
    let config = store.get_config().await?;
    Ok(Json(config))
}

/// Merge-patch the global config.
///
/// `auth_domain` is checked against the canonical-origin rules before anything
/// else, because it becomes the `iss` of every signed identity assertion — a
/// value that only fails at the next boot would take signed-identity routes
/// down with it.
pub async fn update(
    State(store): State<crate::store::Store>,
    Extension(actor): Extension<Actor>,
    SanitizedJson(body): SanitizedJson<UpdateGlobalConfig>,
) -> Result<impl IntoResponse> {
    // Only a new value needs validating. `null` clears the domain.
    if let Some(Some(auth_domain)) = &body.auth_domain {
        crate::identity::IdentityAuthority::validate_auth_domain(auth_domain).map_err(|_| {
            crate::error::Error::BadRequest(crate::identity::INVALID_AUTH_DOMAIN.into())
        })?;
    }
    validation::validate_config_update(
        body.session_lifetime_hours,
        body.websocket_concurrency_limit,
        body.acme_queue_capacity,
        body.acme_issuance_concurrency_limit,
        body.acme_renewal_scan_interval_hours,
    )?;
    let patch = serde_json::to_value(&body)
        .map_err(|e| crate::error::Error::Internal(format!("serialize error: {e}")))?;
    let fields = audit::changed_fields(&patch);
    // The read and the update are separate operations, not one transaction.
    // If another PATCH lands between them, the list below can name a field
    // this request did not change, or leave out one it did. That affects the
    // list only: what is validated and what is stored do not depend on it.
    let before = store.get_config().await?;
    let config = store.update_config(patch).await?;
    let mut restart_required = Vec::new();
    if before.auth_domain != config.auth_domain {
        restart_required.push("auth_domain");
    }
    if before.session_lifetime_hours != config.session_lifetime_hours {
        restart_required.push("session_lifetime_hours");
    }
    if before.websocket_concurrency_limit != config.websocket_concurrency_limit {
        restart_required.push("websocket_concurrency_limit");
    }
    if before.acme_issuance_concurrency_limit != config.acme_issuance_concurrency_limit {
        restart_required.push("acme_issuance_concurrency_limit");
    }
    if before.acme_renewal_scan_interval_hours != config.acme_renewal_scan_interval_hours {
        restart_required.push("acme_renewal_scan_interval_hours");
    }

    crate::audit_mgmt!(
        actor = actor,
        event = "config.update",
        resource = "config",
        action = "update",
        changed_fields = ?fields,
        restart_required = ?restart_required,
        "global config updated"
    );

    let mut response = serde_json::to_value(&config)
        .map_err(|e| crate::error::Error::Internal(format!("serialize error: {e}")))?;
    if !restart_required.is_empty() {
        response["_restart_required"] = serde_json::json!(restart_required);
    }
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn patch_response(
        store: &crate::store::Store,
        patch: serde_json::Value,
    ) -> serde_json::Value {
        let response = update(
            State(store.clone()),
            Extension(Actor::system()),
            SanitizedJson(serde_json::from_value(patch).unwrap()),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn hardening_restart_marker_requires_a_saved_value_change() {
        for (field, changed) in [
            ("auth_domain", serde_json::json!("auth.example")),
            ("session_lifetime_hours", serde_json::json!(12)),
            ("websocket_concurrency_limit", serde_json::json!(64)),
            ("acme_issuance_concurrency_limit", serde_json::json!(2)),
            ("acme_renewal_scan_interval_hours", serde_json::json!(6)),
        ] {
            let store = crate::store::Store::new_for_test("sqlite::memory:", [0x77; 32], None)
                .await
                .unwrap();
            let initial = serde_json::to_value(store.get_config().await.unwrap()).unwrap();
            assert_ne!(initial[field], changed);
            let omitted = patch_response(&store, serde_json::json!({})).await;
            assert!(
                omitted.get("_restart_required").is_none(),
                "{field}: omitted"
            );
            let same = patch_response(&store, serde_json::json!({field: initial[field]})).await;
            assert!(
                same.get("_restart_required").is_none(),
                "{field}: same value"
            );
            let updated = patch_response(&store, serde_json::json!({field: changed})).await;
            assert_eq!(updated["_restart_required"], serde_json::json!([field]));
            assert_eq!(updated[field], changed);
            let repeated = patch_response(&store, serde_json::json!({field: changed})).await;
            assert!(
                repeated.get("_restart_required").is_none(),
                "{field}: repeated"
            );
            let omitted = patch_response(&store, serde_json::json!({})).await;
            assert!(
                omitted.get("_restart_required").is_none(),
                "{field}: omit after change"
            );
            assert_eq!(omitted[field], changed);
        }
    }

    #[tokio::test]
    async fn hardening_restart_marker_tracks_auth_clear_and_mixed_changes() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [0x78; 32], None)
            .await
            .unwrap();
        let response = patch_response(&store, serde_json::json!({"auth_domain": null})).await;
        assert!(response.get("_restart_required").is_none());
        let set = patch_response(
            &store,
            serde_json::json!({"auth_domain": "AUTH.example:443"}),
        )
        .await;
        assert_eq!(set["_restart_required"], serde_json::json!(["auth_domain"]));
        let same = patch_response(
            &store,
            serde_json::json!({"auth_domain": "AUTH.example:443"}),
        )
        .await;
        assert!(same.get("_restart_required").is_none());
        let case_change = patch_response(
            &store,
            serde_json::json!({"auth_domain": "auth.example:443"}),
        )
        .await;
        assert_eq!(
            case_change["_restart_required"],
            serde_json::json!(["auth_domain"])
        );
        let clear = patch_response(&store, serde_json::json!({"auth_domain": null})).await;
        assert_eq!(
            clear["_restart_required"],
            serde_json::json!(["auth_domain"])
        );
        assert!(clear["auth_domain"].is_null());
        let again = patch_response(&store, serde_json::json!({"auth_domain": null})).await;
        assert!(again.get("_restart_required").is_none());

        let before = store.get_config().await.unwrap();
        let mixed = patch_response(
            &store,
            serde_json::json!({
                "auth_domain": null,
                "session_lifetime_hours": before.session_lifetime_hours,
                "websocket_concurrency_limit": 64,
                "acme_issuance_concurrency_limit": before.acme_issuance_concurrency_limit,
                "acme_renewal_scan_interval_hours": 6,
                "acme_email": "operator@example.com"
            }),
        )
        .await;
        assert_eq!(
            mixed["_restart_required"],
            serde_json::json!([
                "websocket_concurrency_limit",
                "acme_renewal_scan_interval_hours"
            ])
        );
        assert_eq!(mixed["acme_email"], "operator@example.com");
    }

    #[tokio::test]
    async fn hardening_removed_log_level_patch_is_ignored_and_get_omits_it() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [0x75; 32], None)
            .await
            .unwrap();
        for value in [
            serde_json::json!("debug"),
            serde_json::json!("banana"),
            serde_json::Value::Null,
            serde_json::json!({"ignored": true}),
        ] {
            let patch: UpdateGlobalConfig =
                serde_json::from_value(serde_json::json!({"log_level": value})).unwrap();
            let response = update(
                State(store.clone()),
                Extension(Actor::system()),
                SanitizedJson(patch),
            )
            .await
            .unwrap()
            .into_response();
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(body.get("log_level").is_none());
            assert!(body.get("_restart_required").is_none());
            assert_eq!(body["session_lifetime_hours"], 8);
        }
        let response = get(State(store)).await.unwrap().into_response();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(body.get("log_level").is_none());
    }

    #[tokio::test]
    async fn hardening_nullable_config_api_clears_sqlite_and_marks_auth_restart() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [0x75; 32], None)
            .await
            .unwrap();
        let values = serde_json::json!({"default_idp_id": uuid::Uuid::nil(),
            "auth_domain": "auth.example", "acme_email": "operator@example.com"});
        let config = store.update_config(values).await.unwrap();
        assert!(config.default_idp_id.is_some());
        let missing: UpdateGlobalConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        update(
            State(store.clone()),
            Extension(Actor::system()),
            SanitizedJson(missing),
        )
        .await
        .unwrap();
        assert_eq!(
            store.get_config().await.unwrap().auth_domain.as_deref(),
            Some("auth.example")
        );
        let clear: UpdateGlobalConfig = serde_json::from_value(serde_json::json!({
            "default_idp_id": null, "auth_domain": null, "acme_email": null
        }))
        .unwrap();
        let response = update(
            State(store.clone()),
            Extension(Actor::system()),
            SanitizedJson(clear),
        )
        .await
        .unwrap()
        .into_response();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["_restart_required"],
            serde_json::json!(["auth_domain"])
        );
        let config = store.get_config().await.unwrap();
        assert!(config.default_idp_id.is_none());
        assert!(config.auth_domain.is_none());
        assert!(config.acme_email.is_none());
    }

    #[tokio::test]
    async fn auth_domain_update_is_validated_and_declared_restart_required() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [0x75; 32], None)
            .await
            .unwrap();
        let invalid: UpdateGlobalConfig =
            serde_json::from_value(serde_json::json!({"auth_domain": "host/path"})).unwrap();
        let error = match update(
            State(store.clone()),
            Extension(Actor::system()),
            SanitizedJson(invalid),
        )
        .await
        {
            Ok(_) => panic!("invalid auth_domain was accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, crate::error::Error::BadRequest(_)));
        assert!(store.get_config().await.unwrap().auth_domain.is_none());

        let valid: UpdateGlobalConfig =
            serde_json::from_value(serde_json::json!({"auth_domain": "AUTH.example.com:443"}))
                .unwrap();
        let response = update(
            State(store.clone()),
            Extension(Actor::system()),
            SanitizedJson(valid),
        )
        .await
        .unwrap()
        .into_response();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["_restart_required"],
            serde_json::json!(["auth_domain"])
        );
        assert_eq!(
            store.get_config().await.unwrap().auth_domain.as_deref(),
            Some("AUTH.example.com:443")
        );
    }

    #[tokio::test]
    async fn session_lifetime_update_is_declared_restart_required() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [0x76; 32], None)
            .await
            .unwrap();
        let patch: UpdateGlobalConfig =
            serde_json::from_value(serde_json::json!({"session_lifetime_hours": 12})).unwrap();

        let response = update(
            State(store.clone()),
            Extension(Actor::system()),
            SanitizedJson(patch),
        )
        .await
        .unwrap()
        .into_response();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            value["_restart_required"],
            serde_json::json!(["session_lifetime_hours"])
        );
        assert_eq!(store.get_config().await.unwrap().session_lifetime_hours, 12);
    }
}
