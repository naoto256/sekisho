//! Identity provider CRUD.
//!
//! The module has two boundary jobs: turn a typed partial update into one RFC
//! 7396 patch, and keep the OIDC client secret readable by the daemon without
//! ever making it readable through the API.
//!
//! ## The `**REDACTED**` round trip
//!
//! Reads replace the secret with [`REDACTED`]. A management UI that fetches a
//! record, lets an operator edit an unrelated field and PATCHes it back would
//! otherwise send that sentinel as the new secret. [`normalized_update_patch`]
//! removes missing, null, empty and redacted secret spellings before any
//! encryption or store write. That makes a naive read-modify-write preserve
//! the stored secret.
//!
//! The corollary is that a genuine rotation cannot be distinguished from an
//! accidental resubmit by looking at the stored result, which is why
//! [`update`] computes `client_secret_rotated` *before* the transform runs and
//! audits it as its own field. `changed_fields = ["oidc_config"]` would not
//! tell an operator whether a credential moved.
//!
//! ## Encryption happens on the way in, once
//!
//! Creation crosses the boundary in [`encrypt_oidc_input`]; rotation crosses
//! it in [`transform_oidc_secret_in_patch`]. Both seal the plaintext before
//! the backend sees it. The normalized patch is also merged into the stored
//! row for validation, so nested partial updates are checked as the effective
//! configuration rather than as an incomplete object.

use super::pagination::{PageQuery, normalize, remove_probe, wrap};
use super::{AppState, SanitizedJson};
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::error::{Error, Result};
use crate::models::idp::{
    CreateIdentityProvider, IdentityProvider, OidcConfig, OidcConfigInput, UpdateIdentityProvider,
};
use crate::validation;

/// Sentinel value written in place of secret fields on GET responses.
/// Kept in sync with the same literal in `api::bootstrap` — a separate
/// copy per module avoids cross-module coupling and both tests lock the
/// exact bytes down.
pub(super) const REDACTED: &str = "**REDACTED**";

fn insert_required_patch_value<T: serde::Serialize>(
    target: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    field: &str,
    value: &Option<Option<T>>,
) -> Result<()> {
    match value {
        None => Ok(()),
        Some(None) => Err(Error::BadRequest(format!("{field} must not be null"))),
        Some(Some(value)) => {
            target.insert(
                key.into(),
                serde_json::to_value(value)
                    .map_err(|e| Error::Internal(format!("serialize error: {e}")))?,
            );
            Ok(())
        }
    }
}

fn insert_nullable_patch_value<T: serde::Serialize>(
    target: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &Option<Option<T>>,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    target.insert(
        key.into(),
        serde_json::to_value(value)
            .map_err(|e| Error::Internal(format!("serialize error: {e}")))?,
    );
    Ok(())
}

/// Convert the typed PATCH DTO to the single RFC 7396 document sent to the
/// backend. Empty nested objects and secret-preservation spellings disappear,
/// making a semantic no-op observable before any encryption or store write.
fn normalized_update_patch(body: &UpdateIdentityProvider) -> Result<serde_json::Value> {
    let mut root = serde_json::Map::new();
    if let Some(name) = &body.name {
        root.insert("name".into(), serde_json::Value::String(name.clone()));
    }

    if let Some(oidc) = &body.oidc_config {
        let mut config = serde_json::Map::new();
        insert_required_patch_value(
            &mut config,
            "issuer_url",
            "oidc_config.issuer_url",
            &oidc.issuer_url,
        )?;
        insert_required_patch_value(
            &mut config,
            "client_id",
            "oidc_config.client_id",
            &oidc.client_id,
        )?;
        if let Some(Some(secret)) = &oidc.client_secret
            && !secret.is_empty()
            && secret != REDACTED
        {
            config.insert(
                "client_secret".into(),
                serde_json::Value::String(secret.clone()),
            );
        }
        insert_required_patch_value(&mut config, "scopes", "oidc_config.scopes", &oidc.scopes)?;
        insert_nullable_patch_value(&mut config, "prompt", &oidc.prompt)?;
        if !config.is_empty() {
            root.insert("oidc_config".into(), serde_json::Value::Object(config));
        }
    }

    if let Some(saml) = &body.saml_config {
        let mut config = serde_json::Map::new();
        insert_required_patch_value(
            &mut config,
            "metadata_url",
            "saml_config.metadata_url",
            &saml.metadata_url,
        )?;
        insert_nullable_patch_value(&mut config, "slo_url", &saml.slo_url)?;
        insert_nullable_patch_value(&mut config, "name_id_format", &saml.name_id_format)?;
        insert_required_patch_value(
            &mut config,
            "attribute_mapping",
            "saml_config.attribute_mapping",
            &saml.attribute_mapping,
        )?;
        if !config.is_empty() {
            root.insert("saml_config".into(), serde_json::Value::Object(config));
        }
    }

    Ok(serde_json::Value::Object(root))
}

fn client_secret_rotation_requested(body: &UpdateIdentityProvider) -> bool {
    body.oidc_config
        .as_ref()
        .and_then(|config| config.client_secret.as_ref())
        .and_then(Option::as_deref)
        .is_some_and(|secret| !secret.is_empty() && secret != REDACTED)
}

fn effective_idp(stored: &IdentityProvider, patch: &serde_json::Value) -> Result<IdentityProvider> {
    let mut validation_patch = patch.clone();
    if let Some(oidc) = validation_patch
        .get_mut("oidc_config")
        .and_then(serde_json::Value::as_object_mut)
    {
        // Plaintext is a wire-only rotation signal, not part of the stored
        // model used to validate the effective merged configuration.
        oidc.remove("client_secret");
    }
    let mut merged = serde_json::to_value(stored)
        .map_err(|e| Error::Internal(format!("serialize error: {e}")))?;
    crate::store::merge::json_merge(&mut merged, &validation_patch);
    serde_json::from_value(merged).map_err(|_| {
        Error::BadRequest("identity provider update would produce invalid configuration".into())
    })
}

/// Redact sensitive fields from IdP before returning in API response.
///
/// The wire shape exposes the secret as `client_secret` (plaintext on
/// input, REDACTED on output) so clients never see the at-rest field
/// name `client_secret_encrypted` and can't accidentally round-trip an
/// already-encrypted blob back as if it were plaintext.
fn redact_idp(idp: IdentityProvider) -> Result<serde_json::Value> {
    let mut v = serde_json::to_value(idp).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize IdentityProvider for redact");
        Error::Internal("internal serialization error".into())
    })?;
    if let Some(oidc) = v.get_mut("oidc_config").and_then(|c| c.as_object_mut()) {
        oidc.remove("client_secret_encrypted");
        oidc.insert(
            "client_secret".into(),
            serde_json::Value::String(REDACTED.into()),
        );
    }
    Ok(v)
}

/// Translate the wire-side `oidc_config.client_secret` (plaintext or
/// REDACTED) into the at-rest `client_secret_encrypted` for the merge
/// patch. Three cases:
///
/// - `client_secret` is REDACTED → drop it (a GET → edit → PATCH
///   round-trip must preserve the stored secret, not overwrite it).
/// - `client_secret` is a non-empty string → encrypt with the master
///   key and emit `client_secret_encrypted` in the patch.
/// - `client_secret` is null/empty/missing → drop it (PATCH means "no
///   change to the secret").
///
/// Same posture as cert upload (`api::certs::upload`) and bootstrap
/// (`api::bootstrap::update`): wire is plaintext, server is the only
/// thing that ever touches the master key.
async fn transform_oidc_secret_in_patch(
    patch: &mut serde_json::Value,
    store: &crate::store::Store,
) -> Result<()> {
    let Some(oidc) = patch.get_mut("oidc_config").and_then(|v| v.as_object_mut()) else {
        return Ok(());
    };
    // Always strip the input-side field; we'll re-add the encrypted
    // form below if there's a real value to encrypt.
    let raw = oidc.remove("client_secret");
    // A naive client (or an old one) could send `client_secret_encrypted`
    // directly. Drop it unconditionally — the only legal way to rotate
    // is via plaintext `client_secret`, otherwise the daemon would have
    // to trust caller-supplied ciphertext that it can't verify.
    oidc.remove("client_secret_encrypted");
    let Some(value) = raw else {
        return Ok(());
    };
    let plaintext = match value {
        serde_json::Value::String(s) if s == REDACTED || s.is_empty() => return Ok(()),
        serde_json::Value::String(s) => s,
        serde_json::Value::Null => return Ok(()),
        other => {
            return Err(Error::BadRequest(format!(
                "oidc_config.client_secret must be a string, got {other}"
            )));
        }
    };
    let encrypted = store
        .encrypt_active_to_base64(plaintext.as_bytes())
        .await
        .map_err(|e| match e {
            Error::Crypto(inner) => {
                Error::Internal(format!("failed to encrypt OIDC client secret: {inner}"))
            }
            other => other,
        })?;
    oidc.insert(
        "client_secret_encrypted".into(),
        serde_json::Value::String(encrypted),
    );
    Ok(())
}

/// Build a storage `IdentityProvider` from the wire-side
/// `CreateIdentityProvider`. For OIDC this encrypts the supplied
/// plaintext `client_secret` with the master key; SAML is a direct copy.
async fn build_idp_from_create(
    body: CreateIdentityProvider,
    store: &crate::store::Store,
) -> Result<IdentityProvider> {
    let oidc_storage = match body.oidc_config {
        Some(input) => Some(encrypt_oidc_input(input, store).await?),
        None => None,
    };
    Ok(IdentityProvider {
        id: Uuid::new_v4(),
        name: body.name.trim().to_string(),
        idp_type: body.idp_type,
        oidc_config: oidc_storage,
        saml_config: body.saml_config,
    })
}

/// Seal the plaintext client secret and produce the stored form.
///
/// The crypto error is remapped to [`Error::Internal`] rather than propagated
/// as [`Error::Crypto`]: from the caller's point of view the request was
/// valid, and the failure is the daemon's key state, not their input.
async fn encrypt_oidc_input(
    input: OidcConfigInput,
    store: &crate::store::Store,
) -> Result<OidcConfig> {
    let secret_plain = input.client_secret.unwrap_or_default();
    if secret_plain.is_empty() {
        // Defence in depth — `validate_idp_create` already rejects this.
        return Err(Error::BadRequest(
            "oidc_config.client_secret must not be empty".into(),
        ));
    }
    let encrypted = store
        .encrypt_active_to_base64(secret_plain.as_bytes())
        .await
        .map_err(|e| match e {
            Error::Crypto(inner) => {
                Error::Internal(format!("failed to encrypt OIDC client secret: {inner}"))
            }
            other => other,
        })?;
    Ok(OidcConfig {
        issuer_url: input.issuer_url,
        client_id: input.client_id,
        client_secret_encrypted: encrypted,
        scopes: input.scopes,
        prompt: input.prompt,
    })
}

/// Paginated IdP list, redacted.
pub async fn list(
    State(store): State<crate::store::Store>,
    Query(q): Query<PageQuery>,
) -> Result<impl IntoResponse> {
    let (limit, offset) = normalize(q);
    let mut idps = store.list_idps_page(limit + 1, offset).await?;
    let has_more = remove_probe(&mut idps, limit);
    let redacted: Vec<serde_json::Value> =
        idps.into_iter().map(redact_idp).collect::<Result<_>>()?;
    Ok(Json(wrap(&redacted, limit, offset, has_more)))
}

/// Fetch one IdP, redacted.
pub async fn get(
    State(store): State<crate::store::Store>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let idp = store.get_idp(id).await?;
    Ok(Json(redact_idp(idp)?))
}

/// Create an IdP, sealing the client secret on the way in.
pub async fn create(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    SanitizedJson(body): SanitizedJson<CreateIdentityProvider>,
) -> Result<impl IntoResponse> {
    validation::validate_idp_create(
        &body.name,
        &body.idp_type,
        &body.oidc_config,
        &body.saml_config,
    )?;
    let idp_type = crate::auth::strategy::Strategy::for_idp_type(body.idp_type).display_kind();
    let idp = build_idp_from_create(body, &state.store).await?;
    state.store.create_idp(&idp).await?;
    crate::audit_mgmt!(
        actor = actor,
        event = "idp.create",
        resource = "idp",
        target = idp.id,
        action = "create",
        idp_type = idp_type,
        name = %idp.name,
        "identity provider created"
    );
    Ok((StatusCode::CREATED, Json(redact_idp(idp)?)))
}

/// Merge-patch an IdP.
///
/// The typed body is normalized once, then merged with the stored row for
/// protocol validation. An effective no-op returns before encryption, store
/// mutation, version change or audit; only a real plaintext secret requests a
/// rotation. `idp_type` is absent from the patch because the protocol is
/// immutable.
pub async fn update(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<Uuid>,
    SanitizedJson(body): SanitizedJson<UpdateIdentityProvider>,
) -> Result<impl IntoResponse> {
    validation::validate_idp_update_syntax(&body)?;
    let mut patch = normalized_update_patch(&body)?;
    let stored = state.store.get_idp(id).await?;
    let effective = effective_idp(&stored, &patch)?;
    validation::validate_idp_update_for_type(&effective)?;
    // Capture the secret-rotation signal *before* the transform
    // strips `client_secret` from the patch. Operators care
    // specifically about "did this PATCH rotate an OIDC secret"
    // because that's the highest-blast-radius mutation on an IdP;
    // bundling it in the changed_fields = ["oidc_config"] catch-all
    // would lose that signal.
    let client_secret_rotated = client_secret_rotation_requested(&body);
    if !client_secret_rotated
        && serde_json::to_value(&effective)
            .map_err(|e| Error::Internal(format!("serialize error: {e}")))?
            == serde_json::to_value(&stored)
                .map_err(|e| Error::Internal(format!("serialize error: {e}")))?
    {
        return Ok(Json(redact_idp(stored)?));
    }
    let fields = audit::changed_fields(&patch);
    transform_oidc_secret_in_patch(&mut patch, &state.store).await?;
    let idp = state.store.update_idp(id, patch).await?;
    crate::audit_mgmt!(
        actor = actor,
        event = "idp.update",
        resource = "idp",
        target = id,
        action = "update",
        changed_fields = ?fields,
        client_secret_rotated,
        "identity provider updated"
    );
    Ok(Json(redact_idp(idp)?))
}

/// Delete an IdP.
///
/// Refuses with 409 while anything still points at it — the global
/// `default_idp_id`, or any route's `idp_id`. Both checks exist because a
/// dangling reference does not fail loudly: the route would keep serving and
/// only break at the next authentication, far from the change that caused it.
pub async fn delete(
    State(store): State<crate::store::Store>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    // Check if this IdP is referenced as the default
    let config = store.get_config().await?;
    if config.default_idp_id == Some(id) {
        return Err(Error::Conflict(
            "cannot delete IdP that is set as default_idp_id in config".into(),
        ));
    }

    // Check if any route references this IdP
    let routes = store.list_routes().await?;
    if routes.iter().any(|r| r.idp_id == Some(id)) {
        return Err(Error::Conflict(
            "cannot delete IdP that is referenced by one or more routes".into(),
        ));
    }

    store.delete_idp(id).await?;
    crate::audit_mgmt!(
        actor = actor,
        event = "idp.delete",
        resource = "idp",
        target = id,
        action = "delete",
        "identity provider deleted"
    );
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::idp::{IdpType, OidcConfig};
    use axum::response::IntoResponse;
    use serde_json::json;
    use uuid::Uuid;

    fn oidc_idp(secret: &str) -> IdentityProvider {
        IdentityProvider {
            id: Uuid::new_v4(),
            name: "google".into(),
            idp_type: IdpType::Oidc,
            oidc_config: Some(OidcConfig {
                issuer_url: "https://accounts.google.example".into(),
                client_id: "client-abc".into(),
                client_secret_encrypted: secret.into(),
                scopes: vec!["openid".into(), "email".into()],
                prompt: None,
            }),
            saml_config: None,
        }
    }

    #[test]
    fn redact_replaces_oidc_client_secret() {
        let v = redact_idp(oidc_idp("super-secret")).unwrap();
        // GET exposes the wire field `client_secret` (REDACTED), not
        // the at-rest column name.
        assert_eq!(v["oidc_config"]["client_secret"], REDACTED);
        assert!(
            v["oidc_config"].get("client_secret_encrypted").is_none(),
            "at-rest field must never appear on the wire"
        );
        assert_eq!(v["oidc_config"]["client_id"], "client-abc");
    }

    #[tokio::test]
    async fn transform_drops_sentinel_but_keeps_other_fields() {
        let key = [0x42u8; 32];
        let store = crate::store::Store::new_for_test("sqlite::memory:", key, None)
            .await
            .unwrap();
        let mut patch = json!({
            "name": "google-renamed",
            "oidc_config": {
                "issuer_url": "https://accounts.google.example",
                "client_id": "client-abc",
                "client_secret": REDACTED,
                "scopes": ["openid", "email"]
            }
        });
        transform_oidc_secret_in_patch(&mut patch, &store)
            .await
            .unwrap();
        assert_eq!(patch["name"], "google-renamed");
        assert!(
            patch["oidc_config"].get("client_secret").is_none(),
            "sentinel must be removed from the merge patch"
        );
        assert!(
            patch["oidc_config"]
                .get("client_secret_encrypted")
                .is_none(),
            "no at-rest field should be synthesised when there's no new secret"
        );
        assert_eq!(patch["oidc_config"]["client_id"], "client-abc");
        assert_eq!(patch["oidc_config"]["scopes"], json!(["openid", "email"]));
    }

    #[tokio::test]
    async fn degraded_secret_encryption_preserves_service_unavailable_response() {
        let store = crate::store::Store::new_for_test_degraded("service DB offline")
            .await
            .unwrap();
        let mut patch = json!({
            "oidc_config": {
                "client_secret": "must-not-encrypt"
            }
        });

        let err = transform_oidc_secret_in_patch(&mut patch, &store)
            .await
            .expect_err("degraded encryption must fail");
        assert!(matches!(err, Error::ServiceUnavailable(_)));
        assert_eq!(
            err.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn transform_encrypts_real_secret() {
        // A genuine rotation sends plaintext; the transform encrypts it
        // through the DEK ring and emits the at-rest field name.
        let key = [0x33u8; 32];
        let store = crate::store::Store::new_for_test("sqlite::memory:", key, None)
            .await
            .unwrap();
        let mut patch = json!({
            "oidc_config": {
                "client_secret": "rotated-plaintext"
            }
        });
        transform_oidc_secret_in_patch(&mut patch, &store)
            .await
            .unwrap();
        assert!(
            patch["oidc_config"].get("client_secret").is_none(),
            "plaintext must be stripped after encryption"
        );
        let encrypted = patch["oidc_config"]["client_secret_encrypted"]
            .as_str()
            .expect("client_secret_encrypted must be a string");
        let decrypted = store.decrypt_any_from_base64(encrypted).await.unwrap();
        assert_eq!(decrypted, b"rotated-plaintext");
    }

    #[tokio::test]
    async fn transform_drops_caller_supplied_encrypted_blob() {
        // A naive client sending `client_secret_encrypted` directly must
        // not be able to bypass encryption by handing us ciphertext the
        // server can't verify. Drop it unconditionally.
        let key = [0x44u8; 32];
        let store = crate::store::Store::new_for_test("sqlite::memory:", key, None)
            .await
            .unwrap();
        let mut patch = json!({
            "oidc_config": {
                "client_secret_encrypted": "caller-supplied-garbage"
            }
        });
        transform_oidc_secret_in_patch(&mut patch, &store)
            .await
            .unwrap();
        assert!(
            patch["oidc_config"]
                .get("client_secret_encrypted")
                .is_none()
        );
    }

    // ═══════════════════════ roundtrip through Store ═══════════════════════
    //
    // Mirrors the bootstrap module's testing style: drive the handler's
    // inner operations through Store directly rather than spin up an
    // axum::Router, which is not how the rest of this crate is tested.

    #[tokio::test]
    async fn patch_with_redacted_sentinel_preserves_secret() {
        // Regression for the GET → edit → PATCH round-trip: if a caller
        // re-sends the sentinel we surfaced on GET, the stored secret
        // must survive untouched. Otherwise a benign "rename this IdP"
        // flow in the admin UI silently clobbers the real client secret.
        let master_key = [0x55u8; 32];
        let store = crate::store::Store::new_for_test("sqlite::memory:", master_key, None)
            .await
            .unwrap();

        let idp = oidc_idp("real-secret");
        let idp_id = idp.id;
        store.create_idp(&idp).await.unwrap();

        // Simulate a naive client: GET (which returns the sentinel) and
        // round-trip the whole body back as a PATCH with a changed name.
        let getted = redact_idp(store.get_idp(idp_id).await.unwrap()).unwrap();
        assert_eq!(getted["oidc_config"]["client_secret"], REDACTED);

        // Patch body = the redacted view but with a new name.
        let mut patch = getted.clone();
        patch["name"] = json!("google-renamed");
        // Drop fields the updater doesn't understand (id/type) to match
        // what a client-side form submit would actually send; those are
        // not part of UpdateIdentityProvider.
        if let Some(obj) = patch.as_object_mut() {
            obj.remove("id");
            obj.remove("type");
            obj.remove("saml_config");
        }

        transform_oidc_secret_in_patch(&mut patch, &store)
            .await
            .unwrap();
        store.update_idp(idp_id, patch).await.unwrap();

        let after = store.get_idp(idp_id).await.unwrap();
        assert_eq!(after.name, "google-renamed");
        assert_eq!(
            after.oidc_config.as_ref().unwrap().client_secret_encrypted,
            "real-secret",
            "stored secret must survive the sentinel round-trip"
        );
    }

    #[tokio::test]
    async fn patch_with_plaintext_secret_rotates_encrypted() {
        let master_key = [0x66u8; 32];
        let store = crate::store::Store::new_for_test("sqlite::memory:", master_key, None)
            .await
            .unwrap();

        // Seed the IdP with a properly-encrypted secret so the OIDC
        // decrypt path would succeed before and after the rotation.
        let original_encrypted = store
            .encrypt_active_to_base64(b"original-plaintext")
            .await
            .unwrap();
        let idp = oidc_idp(&original_encrypted);
        let idp_id = idp.id;
        store.create_idp(&idp).await.unwrap();

        let mut patch = json!({
            "oidc_config": {
                "issuer_url": "https://accounts.google.example",
                "client_id": "client-abc",
                "client_secret": "rotated-plaintext",
                "scopes": ["openid", "email"]
            }
        });
        transform_oidc_secret_in_patch(&mut patch, &store)
            .await
            .unwrap();
        store.update_idp(idp_id, patch).await.unwrap();

        let after = store.get_idp(idp_id).await.unwrap();
        let stored = &after.oidc_config.as_ref().unwrap().client_secret_encrypted;
        let decrypted = store.decrypt_any_from_base64(stored).await.unwrap();
        assert_eq!(decrypted, b"rotated-plaintext");
    }
}
