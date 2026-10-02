//! DEK ring management endpoints.
//!
//! Five verbs:
//!
//! * `GET /encryption_keys` — list every non-retired row plus retired
//!   rows for audit visibility.
//! * `POST /encryption_keys` — generate a new 32-byte DEK on this node,
//!   KEK-encrypt it, INSERT inactive at the smallest free key_id.
//!   Returns the hex-encoded plaintext exactly once so the operator can
//!   archive it offline.
//! * `POST /encryption_keys/{key_id}/activate` — flip active. Refuses
//!   on non-leader nodes (HA fence — the acme_leader_election row picks
//!   the writer for any management mutation that has to land in DB
//!   order). Bumps `key_ring_version` so peers refresh on next poll.
//! * `POST /encryption_keys/{key_id}/retire` — mark retired. Leader-only.
//!   Refuses if any encrypted column still holds rows on the key being
//!   retired (the bulk re-encrypt runs separately and must complete
//!   first).
//! * `POST /encryption_keys/rotate` — bulk re-encrypt every at-rest
//!   blob onto the active DEK. Leader-only. Idempotent: rows already
//!   on the active key are skipped via the v3 `peek_key_id` cheap path.
//!
//! All verbs other than GET log a structured audit event. The returned
//! body shape stays minimal (`{key_id, status, ...}`) and never echoes
//! key material on read.

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use super::AppState;
use crate::audit::Actor;
use crate::error::{Error, Result};

/// Status string returned by GET. Stable contract for the CLI table.
fn status_for(active: bool, retired: bool) -> &'static str {
    if retired {
        "retired"
    } else if active {
        "active"
    } else {
        "inactive"
    }
}

pub async fn list(State(state): State<AppState>) -> Result<impl IntoResponse> {
    // Pull every row including retired ones — the CLI shows them in a
    // separate column for audit visibility.
    let rows = state.store.master_keys_load_active_set().await?;
    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "key_id": r.key_id,
                "status": status_for(r.active, r.retired),
                // `created_at` / `retired_at` aren't in MasterKeyRow yet;
                // the CLI table has placeholder columns until the loader
                // is widened.  Keep the shape future-proof.
                "active": r.active,
                "retired": r.retired,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

pub async fn add(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
) -> Result<impl IntoResponse> {
    use rand::Rng;
    let dek: [u8; 32] = rand::rng().random();
    let next_id = state
        .store
        .master_keys_allocate_inactive_plaintext(&dek, &state.master_key)
        .await?;

    crate::audit_crypto!(
        actor = actor,
        event = "crypto.dek.add",
        resource = "encryption_key",
        target = next_id,
        action = "add",
        "operator added DEK"
    );

    // Refresh the local ring so this node can already decrypt blobs
    // from the new key. Peers will pick it up on their next poll.
    if let Ok(ring) = crate::store::key_ring_loader::refresh(&state.store, &state.master_key).await
    {
        state.store.replace_key_ring(ring).await;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "key_id": next_id,
            "status": "inactive",
            // One-shot disclosure — the operator must archive this.
            // Subsequent GETs never include the plaintext again.
            "key_hex": hex::encode(dek),
            "next_steps": "Save the key_hex offline as recovery, verify with \
                'show encryption-keys' on each peer, then \
                'activate encryption-key <key_id>'.",
        })),
    ))
}

pub async fn activate(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse> {
    let key_id = parse_dek_key_id(&key_id)?;
    leader_only(&state).await?;
    state.store.master_keys_activate(i16::from(key_id)).await?;

    crate::audit_crypto!(
        actor = actor,
        event = "crypto.dek.activate",
        resource = "encryption_key",
        target = key_id,
        action = "activate",
        "operator activated DEK"
    );

    if let Ok(ring) = crate::store::key_ring_loader::refresh(&state.store, &state.master_key).await
    {
        state.store.replace_key_ring(ring).await;
    }

    Ok(Json(json!({
        "key_id": key_id,
        "status": "active",
        "next_steps": "Run 'rotate encryption-key' to re-encrypt existing data.",
    })))
}

pub async fn retire(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
    Path(key_id): Path<String>,
) -> Result<impl IntoResponse> {
    let key_id = parse_dek_key_id(&key_id)?;
    leader_only(&state).await?;

    // Pre-check: count rows that still encrypt with this key. The
    // bulk re-encrypt verb is what gets that count to zero; refusing
    // here is what stops a footgun where retire silently bricks any
    // row the operator hadn't migrated yet.
    let scan = crate::store::dek_rotation::scan_key_id_usage(&state.store, key_id).await?;
    if scan.total > 0 {
        return Err(Error::ConfigurationError(format!(
            "refusing to retire key_id {key_id}: {} row(s) still encrypted with it (run 'rotate encryption-key' first)",
            scan.total
        )));
    }

    state.store.master_keys_retire(i16::from(key_id)).await?;

    crate::audit_crypto!(
        actor = actor,
        event = "crypto.dek.retire",
        resource = "encryption_key",
        target = key_id,
        action = "retire",
        "operator retired DEK"
    );

    if let Ok(ring) = crate::store::key_ring_loader::refresh(&state.store, &state.master_key).await
    {
        state.store.replace_key_ring(ring).await;
    }

    Ok(Json(json!({
        "key_id": key_id,
        "status": "retired",
    })))
}

fn parse_dek_key_id(value: &str) -> Result<u8> {
    value
        .parse()
        .map_err(|_| Error::BadRequest("key_id must be between 0 and 255".into()))
}

pub async fn rotate(
    State(state): State<AppState>,
    Extension(actor): Extension<Actor>,
) -> Result<impl IntoResponse> {
    leader_only(&state).await?;
    let report = crate::store::dek_rotation::reencrypt_all(&state.store).await?;

    crate::audit_crypto!(
        actor = actor,
        event = "crypto.dek.rotate",
        resource = "encryption_key",
        action = "rotate",
        rows_examined = report.examined,
        rows_reencrypted = report.reencrypted,
        rows_skipped = report.skipped,
        "operator triggered bulk DEK rotation"
    );

    Ok(Json(json!({
        "examined": report.examined,
        "reencrypted": report.reencrypted,
        "skipped": report.skipped,
        "active_key_id": state.store.key_ring_snapshot().await.active_key_id().get(),
    })))
}

/// HA fence: the activate / retire / rotate verbs must run on whichever
/// node the cluster considers the ACME leader. The leader is already
/// the singleton with the write lock for elective management mutations
/// (cert renewals); piggy-backing on that machinery avoids inventing a
/// second election.
///
/// Single-node deployments (no Postgres, no acme_leader_election row)
/// are always permitted — the read returns `None` and we treat that as
/// "I am the only node, of course I'm the leader". This matches the
/// behaviour the operator expects from `sekisho-cli show encryption-keys`
/// on a single-node `cargo run` setup.
async fn leader_only(state: &AppState) -> Result<()> {
    let row = state.store.acme_election_read().await?;
    let my_node = crate::tls::acme::node_id();
    match row {
        None => Ok(()), // single-node / pre-first-tick — always allow
        Some(r) if r.node_id == my_node => Ok(()),
        Some(r) => Err(Error::NotClusterLeader(r.node_id)),
    }
}
