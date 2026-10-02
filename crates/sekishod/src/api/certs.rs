//! Certificate endpoints: listing, ACME issuance, and manual upload.
//!
//! ## Issuance is queued, never synchronous
//!
//! `POST /certs` inserts a cluster-wide queue row and returns `202` with an
//! id to poll. An ACME order takes tens of seconds and can fail in ways worth
//! retrying, which makes it the wrong shape for a request/response call: the
//! client would be holding a connection open across a rate-limited external
//! dependency with no way to resume after a disconnect.
//!
//! Queueing also solves the HA problem. Any node accepts the request, but only
//! the elected leader runs orders — so a request that landed on a follower
//! still gets served, and two nodes cannot race to issue the same certificate
//! and burn a rate limit doing it.
//!
//! ## Upload is a separate endpoint, not a mode
//!
//! Operator-supplied certificates go to `/certs/upload` rather than reusing
//! `POST /certs` with different fields. Same request shape for two different
//! flows means a typo silently switches mode; separate endpoints make it a
//! parse error. The server also reads validity dates out of the certificate
//! itself rather than trusting the body, so an uploaded cert cannot claim an
//! expiry it does not have and thereby dodge renewal.
//!
//! Private keys are sealed with the active DEK before storage, and responses
//! carry [`CertificateInfo`] — never the PEM bodies.

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::error::{Error, Result};
use crate::models::acme_queue::{AcmeQueueAdmission, AcmeQueueRow, AcmeQueueStatus};
use crate::models::cert::{CertSource, Certificate, CertificateInfo};
use crate::store::Store;

use super::AppState;
use super::pagination::{PageQuery, normalize, remove_probe, wrap};

/// Paginated certificate list, metadata only.
pub async fn list(
    State(store): State<Store>,
    Query(q): Query<PageQuery>,
) -> Result<impl IntoResponse> {
    let (limit, offset) = normalize(q);
    let mut certs = store.list_certs_page(limit + 1, offset).await?;
    let has_more = remove_probe(&mut certs, limit);
    let infos: Vec<CertificateInfo> = certs.iter().map(CertificateInfo::from).collect();
    Ok(Json(wrap(&infos, limit, offset, has_more)))
}

/// Delete a certificate. Does not touch routes that referenced its hostname:
/// a route left without a certificate fails its next enable preflight, which
/// is a clearer signal than having the delete refused.
pub async fn delete(
    State(store): State<Store>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    store.delete_cert(id).await?;
    crate::audit_mgmt!(
        actor = actor,
        event = "cert.delete",
        resource = "cert",
        target = id,
        action = "delete",
        "certificate deleted"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Fetch one certificate's metadata.
pub async fn get(State(store): State<Store>, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    let cert = store.get_cert(id).await?;
    Ok(Json(CertificateInfo::from(&cert)))
}

/// Body of `POST /certs`. One field, so a request carrying anything else is
/// almost certainly meant for `/certs/upload`.
#[derive(Deserialize)]
pub struct IssueCertRequest {
    pub domain: String,
}

/// Validate that `domain` is a syntactically valid DNS hostname.
/// Does NOT verify the name resolves — ACME will fail if it doesn't.
fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(Error::BadRequest("invalid domain length".into()));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::BadRequest("invalid domain label length".into()));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::BadRequest(
                "domain label cannot start/end with '-'".into(),
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::BadRequest(
                "domain may only contain ASCII letters, digits, '-', and '.'".into(),
            ));
        }
    }
    Ok(())
}

/// Shape of the `202 Accepted` body returned after queue admission.
#[derive(Debug, Serialize)]
pub struct QueuedIssuance {
    pub queue_id: Uuid,
    pub domain: String,
    pub status: AcmeQueueStatus,
}

impl From<&AcmeQueueRow> for QueuedIssuance {
    fn from(row: &AcmeQueueRow) -> Self {
        Self {
            queue_id: row.id,
            domain: row.domain.clone(),
            status: row.status,
        }
    }
}

/// `POST /certs` — ACME issuance for the given domain.
///
/// Every node inserts or reuses a queue row and returns `202 Accepted`
/// with `{queue_id, domain, status}`. The client polls
/// `GET /certs/queue/{id}` until `status` is `completed` or `failed`.
/// The leader's background tick picks the row, runs the order, and
/// writes the result back.
pub async fn issue(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    crate::api::SanitizedJson(body): crate::api::SanitizedJson<IssueCertRequest>,
) -> Result<axum::response::Response> {
    // Manual requests deliberately enqueue instead of invoking the manager.
    // AppState retains it for the independently spawned queue worker.
    let _ = &state.acme;
    // Lowercase before validate / persist so downstream matching —
    // DB `certificates.domain` lookups, ACME identifier comparison,
    // and `CertResolver`'s SNI key — all see the same case.
    let domain = body.domain.trim().to_ascii_lowercase();
    validate_domain(&domain)?;

    match state
        .store
        .acme_queue_enqueue(&domain, &crate::tls::acme::node_id())
        .await?
    {
        AcmeQueueAdmission::Inserted(row) | AcmeQueueAdmission::Existing(row) => {
            tracing::info!(
                target: audit::TARGET,
                event = "cert.issue.queue.accepted",
                category = "mgmt",
                result = "accepted",
                actor_type = actor.kind_str(),
                actor_id = %actor.id,
                target_resource = "cert_queue",
                target_id = %row.id,
                domain = %domain,
                action = "enqueue",
                "ACME issuance accepted by the cluster queue"
            );
            Ok((StatusCode::ACCEPTED, Json(QueuedIssuance::from(&row))).into_response())
        }
        AcmeQueueAdmission::Full => {
            tracing::warn!(
                target: audit::TARGET,
                event = "cert.issue.queue.rejected",
                category = "mgmt",
                result = "rejected",
                actor_type = actor.kind_str(),
                actor_id = %actor.id,
                target_resource = "cert_queue",
                domain = %domain,
                action = "enqueue",
                reason = "capacity",
                "ACME issuance queue is full"
            );
            Err(Error::ServiceUnavailable(
                "ACME issuance queue is full".into(),
            ))
        }
    }
}

/// `GET /certs/queue/{id}` — poll a queued issuance's status.
///
/// Returns the queue row — `status`, `error_msg`, `result_cert_id`
/// and timestamps. Clients poll until the status is `completed` (fetch
/// the cert from `/certs/{result_cert_id}` if they want the details)
/// or `failed` (surface `error_msg` to the user).
///
/// Authenticated by the standard management API middleware. No
/// separate authz is needed: anyone who can call `POST /certs` to
/// create the queue row can read its status.
pub async fn queue_status(
    State(store): State<Store>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let row = store.acme_queue_get(id).await?.ok_or(Error::NotFound)?;
    Ok(Json(row))
}

/// Body of `POST /certs/upload`. Validity dates are deliberately absent —
/// the server parses them out of `cert_pem` instead of trusting the caller.
#[derive(Deserialize)]
pub struct UploadCertRequest {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// `POST /certs/upload` — install a hand-minted certificate for
/// `domain`. The server extracts `not_before` / `not_after` from the
/// cert itself (so clients don't get to lie about expiry), encrypts
/// the private key with the active DEK, and writes through the same
/// upsert path ACME issuance uses. It then attempts a resolver reload;
/// a top-level reload error propagates, and later handshakes use the
/// new cert only if that row was loaded.
///
/// Separate from the ACME `POST /certs` endpoint so the two flows
/// don't share a request shape — a missing / extra field should be
/// a parse error, not a silent mode switch.
pub async fn upload(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    crate::api::SanitizedJson(body): crate::api::SanitizedJson<UploadCertRequest>,
) -> Result<impl IntoResponse> {
    let domain = body.domain.trim().to_ascii_lowercase();
    validate_domain(&domain)?;

    let validated = crate::tls::resolver::validate_proxy_certificate(
        &domain,
        &body.cert_pem,
        &body.key_pem,
        Utc::now(),
    )
    .map_err(Error::BadRequest)?;
    let not_before = validated.not_before;
    let not_after = validated.not_after;

    let key_encrypted = state
        .store
        .encrypt_active_to_base64(body.key_pem.as_bytes())
        .await
        .map_err(|e| match e {
            Error::Crypto(inner) => {
                Error::Internal(format!("failed to encrypt private key: {inner}"))
            }
            other => other,
        })?;

    let cert = Certificate {
        id: Uuid::new_v4(),
        domain: domain.clone(),
        cert_pem: body.cert_pem,
        key_pem_encrypted: key_encrypted,
        source: CertSource::Upload,
        issued_at: not_before,
        expires_at: not_after,
    };

    state.store.upsert_cert(&cert).await?;
    state
        .cert_resolver
        .reload()
        .await
        .map_err(|e| Error::Internal(format!("cert resolver reload failed: {e}")))?;
    crate::audit_mgmt!(
        actor = actor,
        event = "cert.upload",
        resource = "cert",
        target = cert.id,
        action = "upload",
        domain = %domain,
        expires_at = %not_after,
        "custom certificate uploaded"
    );

    Ok((StatusCode::CREATED, Json(CertificateInfo::from(&cert))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{IdentityKeyRingSnapshot, MasterKey};
    use crate::tls::acme::AcmeManager;
    use crate::tls::acme::challenge::Http01Provider;
    use crate::tls::resolver::CertResolver;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn queue_full_router_returns_standard_service_unavailable_without_order() {
        let store = Store::new_for_test("sqlite::memory:", [0x31; 32], None)
            .await
            .unwrap();
        store
            .update_config(serde_json::json!({"acme_queue_capacity": 1}))
            .await
            .unwrap();
        store
            .acme_queue_enqueue("occupied.example", "node-a")
            .await
            .unwrap();

        // An accidental order attempt would connect here and then block waiting
        // for a directory response. The router must reject from queue admission
        // without touching this listener.
        let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let directory = format!("http://{}/directory", upstream.local_addr().unwrap());
        let acme = Arc::new(AcmeManager::new(
            store.clone(),
            Arc::new(Http01Provider::new(store.clone())),
            &directory,
            None,
        ));
        let state = AppState {
            store: store.clone(),
            acme,
            cert_resolver: Arc::new(CertResolver::new(store)),
            master_key: MasterKey::from_test_bytes([0x32; 32]),
            identity_authority: Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example.com",
            )),
            jwt_signing_key: IdentityKeyRingSnapshot::from_test_bytes([0x33; 32]),
        };
        let app = axum::Router::new()
            .route(
                sekisho_api_protocol::api_paths::CERTS,
                axum::routing::post(issue),
            )
            .with_state(state)
            .layer(Extension(Actor::system()));
        let request = Request::builder()
            .method("POST")
            .uri("/certs")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"domain":"new.example"}"#))
            .unwrap();
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(1), app.oneshot(request))
                .await
                .expect("queue-full response must not wait on ACME")
                .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get("retry-after").is_none());
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "error": {
                    "code": "SERVICE_UNAVAILABLE",
                    "message": "service unavailable"
                }
            })
        );
        assert!(matches!(
            upstream.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}
