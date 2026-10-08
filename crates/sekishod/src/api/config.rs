//! Global configuration read and patch.
//!
//! ## `_restart_required` is advisory, and computed per request
//!
//! Several fields are only read at startup, so patching them changes the
//! stored value without changing the running daemon. Rather than reject those
//! patches — an operator staging config before a planned restart is a
//! legitimate thing to do — the response carries a `_restart_required` list
//! naming which of the fields *in this patch* need one, and the same list goes
//! into the audit event.
//!
//! The list is built from what the patch touched rather than from a static
//! table of field names, so a patch that changes nothing restart-sensitive
//! says nothing. Keeping it in step with the fields that are actually read at
//! startup is a manual obligation; the per-field docs on
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
    // Only a new value needs validating. `null` clears the domain; it is
    // still listed as restart-required below.
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
    let mut restart_required = Vec::new();
    if body.auth_domain.is_some() {
        restart_required.push("auth_domain");
    }
    if body.session_lifetime_hours.is_some() {
        restart_required.push("session_lifetime_hours");
    }
    if body.websocket_concurrency_limit.is_some() {
        restart_required.push("websocket_concurrency_limit");
    }
    if body.acme_issuance_concurrency_limit.is_some() {
        restart_required.push("acme_issuance_concurrency_limit");
    }
    if body.acme_renewal_scan_interval_hours.is_some() {
        restart_required.push("acme_renewal_scan_interval_hours");
    }

    let config = store.update_config(patch).await?;

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
