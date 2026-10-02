//! Bulk re-encryption of every at-rest column onto the active DEK.
//!
//! Driven by the CLI verb `rotate encryption-key` (and its mgmt API
//! sibling `POST /encryption_keys/rotate`). For each at-rest column we
//! support, the routine:
//!
//! 1. Loads the supported table's rows and visits them in
//!    [`CHUNK_SIZE`]-sized iteration slices. No transaction surrounds a
//!    slice.
//! 2. Inspects each encrypted blob via [`crate::crypto::peek_key_id`] —
//!    rows already on the active key are skipped without paying the
//!    decrypt round-trip.
//! 3. For v3 rows with an older key_id, decrypts via the ring's
//!    `decrypt_any` and re-encrypts with `encrypt_active`. A v2 blob is
//!    rejected by the v3-only decrypt path and stops the invocation.
//! 4. UPDATEs each row independently. A successful row write remains
//!    committed if a later row fails or the rotation future is
//!    cancelled; a retry encounters the already-rotated rows again.
//!
//! With unchanged rows and an unchanged active key after a successful
//! invocation, a second run sees the encrypted values on that key_id
//! and returns `reencrypted = 0`.
//!
//! ### Current closed encrypted-column inventory
//!
//! Updates here have to track every column whose write path goes
//! through `Store::encrypt_active_to_base64`. The
//! `encrypted_columns_inventory` test records the expected list but
//! does not discover new write paths automatically. Adding a new
//! at-rest field requires updating the rotation and scan dispatch plus
//! that test in the same change.
//!
//! * `secrets.value` (cookie_secret and the ACME
//!   account credential identified by [`ACCOUNT_CREDENTIALS_KEY`])
//! * `identity_signing_keys.private_key_encrypted` (current row only)
//! * `identity_providers.data` → `oidc_config.client_secret_encrypted`
//! * `sessions.data` → `id_token_encrypted`, `refresh_token_encrypted`
//! * `certificates.data` → `key_pem_encrypted`
//!
//! Out of scope (intentionally KEK-direct, not DEK-routed):
//!
//! * `instance_config.value` (with `encrypted = 1`) — per-node,
//!   encrypts the service DB URL before the ring is even loadable.
//! * `master_keys.key_encrypted` — by definition, the DEKs themselves
//!   are KEK-encrypted.

use crate::crypto;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::acme_account::ACCOUNT_CREDENTIALS_KEY;
use zeroize::Zeroizing;

/// Iteration-slice size after a table's rows have been loaded. It does
/// not define a transaction boundary; each row update is issued
/// independently.
const CHUNK_SIZE: usize = 100;

/// Every DEK-routed value stored in the scalar `secrets` table.
const WELL_KNOWN_SECRET_KEYS: [&str; 2] = ["cookie_secret", ACCOUNT_CREDENTIALS_KEY];

/// Outcome returned by a single rotation invocation as
/// `examined / reencrypted / skipped`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RotationReport {
    pub examined: u64,
    pub reencrypted: u64,
    pub skipped: u64,
}

impl RotationReport {
    fn merge(&mut self, other: RotationReport) {
        self.examined += other.examined;
        self.reencrypted += other.reencrypted;
        self.skipped += other.skipped;
    }
}

/// Outcome of [`scan_key_id_usage`]. Returned to the retire safety
/// check so the operator can see why retire refused.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScanReport {
    pub total: u64,
}

/// Re-encrypt every at-rest blob onto the currently-active DEK.
pub async fn reencrypt_all(store: &Store) -> Result<RotationReport> {
    let mut total = RotationReport::default();
    total.merge(reencrypt_secrets(store).await?);
    total.merge(
        reencrypt_json_column(
            store,
            "identity_providers",
            &["oidc_config", "client_secret_encrypted"],
        )
        .await?,
    );
    total.merge(reencrypt_json_column(store, "sessions", &["id_token_encrypted"]).await?);
    total.merge(reencrypt_json_column(store, "sessions", &["refresh_token_encrypted"]).await?);
    total.merge(reencrypt_json_column(store, "certificates", &["key_pem_encrypted"]).await?);
    let identity = store.identity_signing_reencrypt_current().await?;
    total.merge(RotationReport {
        examined: identity.examined,
        reencrypted: identity.reencrypted,
        skipped: identity.skipped,
    });
    Ok(total)
}

/// Count rows in any at-rest column whose blob is encrypted with
/// `key_id`. Used by the retire safety check; a non-zero count means
/// retire would silently brick those rows.
pub async fn scan_key_id_usage(store: &Store, key_id: u8) -> Result<ScanReport> {
    let mut count = 0u64;
    count += scan_secrets(store, key_id).await?;
    count += scan_json_column(
        store,
        "identity_providers",
        &["oidc_config", "client_secret_encrypted"],
        key_id,
    )
    .await?;
    count += scan_json_column(store, "sessions", &["id_token_encrypted"], key_id).await?;
    count += scan_json_column(store, "sessions", &["refresh_token_encrypted"], key_id).await?;
    count += scan_json_column(store, "certificates", &["key_pem_encrypted"], key_id).await?;
    count += store.identity_signing_scan_key_id(key_id).await?;
    Ok(ScanReport { total: count })
}

// ───── secrets table (scalar value column) ─────

async fn reencrypt_secrets(store: &Store) -> Result<RotationReport> {
    let mut report = RotationReport::default();
    let active = store.key_ring_snapshot().await.active_key_id();
    let rows = secrets_list(store).await?;
    for chunk in rows.chunks(CHUNK_SIZE) {
        for (key, value) in chunk {
            report.examined += 1;
            match crypto::peek_key_id_from_base64(value) {
                Ok(Some(id)) if id == active => {
                    report.skipped += 1;
                    continue;
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(Error::Internal(format!(
                        "secrets[{key}] blob malformed: {e}"
                    )));
                }
            }
            let plaintext: Zeroizing<Vec<u8>> = store
                .decrypt_any_from_base64_zeroizing(value)
                .await
                .map_err(|e| Error::Internal(format!("decrypt secrets[{key}]: {e}")))?;
            let encrypted = store.encrypt_active_to_base64(&plaintext).await;
            drop(plaintext);
            let new_blob = encrypted.map_err(|e| match e {
                Error::Crypto(inner) => Error::Internal(format!("encrypt secrets[{key}]: {inner}")),
                other => other,
            })?;
            store.set_secret(key, &new_blob).await?;
            report.reencrypted += 1;
        }
    }
    Ok(report)
}

async fn scan_secrets(store: &Store, key_id: u8) -> Result<u64> {
    let mut count = 0u64;
    for (_, value) in secrets_list(store).await? {
        if let Ok(Some(id)) = crypto::peek_key_id_from_base64(&value)
            && id.get() == key_id
        {
            count += 1;
        }
    }
    Ok(count)
}

async fn secrets_list(store: &Store) -> Result<Vec<(String, String)>> {
    // No facade method exists for "list every secret"; the secrets
    // table is small, so this closed inventory is shared by rotation,
    // retirement scans, and the inventory test below. Adding a new
    // DEK-routed secret means extending this one authority.
    let mut out = Vec::new();
    for key in WELL_KNOWN_SECRET_KEYS {
        if let Some(v) = store.get_secret(key).await? {
            out.push((key.to_string(), v));
        }
    }
    Ok(out)
}

// ───── JSON `data` columns (idps, sessions, certificates) ─────
//
// Walked generically with raw SQL so a new at-rest field on an
// existing table doesn't require yet another typed list/update method
// pair. The `path` argument names the JSON key chain to the encrypted
// string; missing keys are skipped (e.g. SAML-only IdP rows have no
// `oidc_config.client_secret_encrypted`).

async fn reencrypt_json_column(
    store: &Store,
    table: &str,
    path: &[&str],
) -> Result<RotationReport> {
    let mut report = RotationReport::default();
    let active = store.key_ring_snapshot().await.active_key_id();
    let rows = list_id_data(store, table).await?;
    for chunk in rows.chunks(CHUNK_SIZE) {
        for (id, data_str) in chunk {
            let mut data: serde_json::Value = match serde_json::from_str(data_str) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(table, %id, error = %e, "skipping unparseable row during rotation");
                    continue;
                }
            };
            let Some(blob) = lookup_string(&data, path) else {
                continue;
            };
            report.examined += 1;
            if let Ok(Some(id_byte)) = crypto::peek_key_id_from_base64(&blob)
                && id_byte == active
            {
                report.skipped += 1;
                continue;
            }
            let plaintext: Zeroizing<Vec<u8>> = store
                .decrypt_any_from_base64_zeroizing(&blob)
                .await
                .map_err(|e| Error::Internal(format!("decrypt {table}[{id}]: {e}")))?;
            let encrypted = store.encrypt_active_to_base64(&plaintext).await;
            drop(plaintext);
            let new_blob = encrypted.map_err(|e| match e {
                Error::Crypto(inner) => Error::Internal(format!("encrypt {table}[{id}]: {inner}")),
                other => other,
            })?;
            set_string(&mut data, path, new_blob);
            let new_data_str = serde_json::to_string(&data)
                .map_err(|e| Error::Internal(format!("reserialize {table}[{id}]: {e}")))?;
            update_data_only(store, table, id, &new_data_str).await?;
            report.reencrypted += 1;
        }
    }
    Ok(report)
}

async fn scan_json_column(store: &Store, table: &str, path: &[&str], key_id: u8) -> Result<u64> {
    let mut count = 0u64;
    let rows = list_id_data(store, table).await?;
    for (_, data_str) in rows {
        let data: serde_json::Value = match serde_json::from_str(&data_str) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(blob) = lookup_string(&data, path) else {
            continue;
        };
        if let Ok(Some(id_byte)) = crypto::peek_key_id_from_base64(&blob)
            && id_byte.get() == key_id
        {
            count += 1;
        }
    }
    Ok(count)
}

fn lookup_string(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut cur = value;
    for seg in path {
        cur = cur.get(seg)?;
    }
    cur.as_str().map(|s| s.to_string())
}

fn set_string(value: &mut serde_json::Value, path: &[&str], new: String) {
    let mut cur = value;
    let last = path.len() - 1;
    for seg in &path[..last] {
        cur = match cur.get_mut(*seg) {
            Some(v) => v,
            None => return,
        };
    }
    if let Some(obj) = cur.as_object_mut() {
        obj.insert(path[last].to_string(), serde_json::Value::String(new));
    }
}

// ───── raw helpers (per-backend SQL) ─────
//
// We dip into the underlying pool here because the backend trait
// doesn't model "give me every row's id+data" — it only models the
// per-resource shapes. Adding two trait methods for what amounts to a
// rotation utility would bloat the trait surface for everyone. Each
// backend gets its own arm so the SQL placeholder syntax stays right.
//
// The table identifier is interpolated rather than bound. These private
// helpers receive it only from the closed internal inventory:
// `identity_providers`, `sessions`, and `certificates`; it is not request
// or other user input. This is a call-site boundary, not general
// identifier validation for future callers.

async fn list_id_data(store: &Store, table: &str) -> Result<Vec<(String, String)>> {
    use crate::store::backend::Backend;
    match &store.backend {
        Backend::Sqlite(b) => {
            let pool = b.pool_for_rotation();
            let q = format!("SELECT id, data FROM {table}");
            let rows: Vec<(String, String)> = sqlx::query_as(&q)
                .fetch_all(pool)
                .await
                .map_err(Error::Database)?;
            Ok(rows)
        }
        Backend::Postgres(b) => {
            let pool = b.pool_for_rotation();
            let q = format!("SELECT id::text, data FROM {table}");
            let rows: Vec<(String, String)> = sqlx::query_as(&q)
                .fetch_all(pool)
                .await
                .map_err(Error::Database)?;
            Ok(rows)
        }
        Backend::Unavailable { reason } => Err(Error::ServiceUnavailable(reason.clone())),
    }
}

async fn update_data_only(store: &Store, table: &str, id: &str, data: &str) -> Result<()> {
    use crate::store::backend::Backend;
    match &store.backend {
        Backend::Sqlite(b) => {
            let pool = b.pool_for_rotation();
            let q = format!("UPDATE {table} SET data = ? WHERE id = ?");
            sqlx::query(&q)
                .bind(data)
                .bind(id)
                .execute(pool)
                .await
                .map_err(Error::Database)?;
            Ok(())
        }
        Backend::Postgres(b) => {
            let pool = b.pool_for_rotation();
            let q = format!("UPDATE {table} SET data = $1 WHERE id::text = $2");
            sqlx::query(&q)
                .bind(data)
                .bind(id)
                .execute(pool)
                .await
                .map_err(Error::Database)?;
            Ok(())
        }
        Backend::Unavailable { reason } => Err(Error::ServiceUnavailable(reason.clone())),
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::store::acme_account::AcmeAccountCredentialInsert;

    struct TempSqliteDb(std::path::PathBuf);

    impl TempSqliteDb {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};

            static NEXT: AtomicU64 = AtomicU64::new(0);
            Self(std::env::temp_dir().join(format!(
                "sekisho-dek-rotation-{}-{}.sqlite3",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            )))
        }

        fn url(&self) -> String {
            format!("sqlite:{}", self.0.display())
        }
    }

    impl Drop for TempSqliteDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(format!("{}-shm", self.0.display()));
            let _ = std::fs::remove_file(format!("{}-wal", self.0.display()));
        }
    }

    /// Records the six-entry encrypted-column inventory. The assertion
    /// pins this local count only; it does not inspect write paths or
    /// compare the rotation and scan dispatch automatically.
    #[test]
    fn encrypted_columns_inventory() {
        let expected: [(&str, &[&str]); 6] = [
            ("secrets", &["value"]),
            ("identity_signing_keys", &["private_key_encrypted"]),
            (
                "identity_providers",
                &["oidc_config", "client_secret_encrypted"],
            ),
            ("sessions", &["id_token_encrypted"]),
            ("sessions", &["refresh_token_encrypted"]),
            ("certificates", &["key_pem_encrypted"]),
        ];
        // Six entries, deliberately spelled out. If you're adding a
        // seventh, plumb it through reencrypt_all + scan_key_id_usage
        // first, then bump this list.
        assert_eq!(expected.len(), 6);
        assert_eq!(WELL_KNOWN_SECRET_KEYS.len(), 2);
        assert!(WELL_KNOWN_SECRET_KEYS.contains(&ACCOUNT_CREDENTIALS_KEY));
    }

    #[tokio::test]
    async fn rotation_is_idempotent_on_steady_state() {
        let kek = [0x42u8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        // Seed a secret via the normal write path (lands on active key).
        let blob = store.encrypt_active_to_base64(b"x").await.unwrap();
        store.set_secret("cookie_secret", &blob).await.unwrap();
        let r1 = reencrypt_all(&store).await.unwrap();
        assert_eq!(r1.reencrypted, 0, "fresh writes are already on active");
        let r2 = reencrypt_all(&store).await.unwrap();
        assert_eq!(r2.reencrypted, 0);
    }

    #[tokio::test]
    async fn rotation_refuses_v2_blob() {
        // A v2 row makes rotation return an error and remains outside
        // the v3 rotation path until it is separately remediated.
        let kek = [0x55u8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        let v2 = crypto::encrypt_to_base64(&kek, b"legacy-cookie").unwrap();
        store.set_secret("cookie_secret", &v2).await.unwrap();
        let err = reencrypt_all(&store).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown ciphertext version") || msg.contains("0x02") || msg.contains("2"),
            "expected v2-rejection error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn scan_counts_rows_on_target_key_id() {
        let kek = [0x77u8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        let blob = store.encrypt_active_to_base64(b"v").await.unwrap();
        store.set_secret("cookie_secret", &blob).await.unwrap();
        let active = store.key_ring_snapshot().await.active_key_id().get();
        let scan = scan_key_id_usage(&store, active).await.unwrap();
        assert!(scan.total >= 1, "at least the cookie_secret row");
    }

    /// Add → activate → rotate end-to-end: a row encrypted under key_id 0
    /// should land on key_id 1 after rotation, and a second rotate should
    /// be a no-op.
    #[tokio::test]
    async fn add_activate_rotate_migrates_secret_between_keys() {
        let kek = [0xCCu8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        // Plant a secret under the boot DEK (key_id 0).
        let original = store
            .encrypt_active_to_base64(b"cookie-secret")
            .await
            .unwrap();
        store.set_secret("cookie_secret", &original).await.unwrap();
        assert_eq!(
            crypto::peek_key_id_from_base64(&original)
                .unwrap()
                .map(|k| k.get()),
            Some(0)
        );
        let old_snapshot = store.key_ring_snapshot().await;
        assert_eq!(old_snapshot.active_key_id().get(), 0);

        // Add + activate a new DEK at key_id 1, then refresh the ring so
        // the active pointer moves.
        let dek2 = [0x77u8; 32];
        let blob2 = crypto::encrypt_to_base64(&kek, &dek2).unwrap();
        store.master_keys_insert(1, &blob2).await.unwrap();
        store.master_keys_activate(1).await.unwrap();
        let master_key = crate::crypto::MasterKey::from_test_bytes(kek);
        let ring = crate::store::key_ring_loader::refresh(&store, &master_key)
            .await
            .unwrap();
        store.replace_key_ring(ring).await;
        let new_snapshot = store.key_ring_snapshot().await;
        assert!(!std::sync::Arc::ptr_eq(&old_snapshot, &new_snapshot));
        assert_eq!(new_snapshot.active_key_id().get(), 1);
        assert_eq!(old_snapshot.active_key_id().get(), 0);
        assert_eq!(
            old_snapshot
                .decrypt_from_base64(&original)
                .unwrap()
                .as_slice(),
            b"cookie-secret"
        );

        // First rotate: the existing secret moves from key_id 0 to 1.
        let r = reencrypt_all(&store).await.unwrap();
        assert!(r.reencrypted >= 1);
        let stored = store.get_secret("cookie_secret").await.unwrap().unwrap();
        assert_eq!(
            crypto::peek_key_id_from_base64(&stored)
                .unwrap()
                .map(|k| k.get()),
            Some(1)
        );
        let pt = store.decrypt_any_from_base64(&stored).await.unwrap();
        assert_eq!(pt, b"cookie-secret");

        // Second rotate: nothing to do.
        let r2 = reencrypt_all(&store).await.unwrap();
        assert_eq!(r2.reencrypted, 0, "second rotate is a no-op");
    }

    /// After rotation finishes, scanning for the old key_id reports zero,
    /// which is what the retire safety check uses to decide it's safe to
    /// drop the DEK.
    #[tokio::test]
    async fn after_rotate_old_key_has_zero_usage() {
        let kek = [0xDDu8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        let original = store.encrypt_active_to_base64(b"x").await.unwrap();
        store.set_secret("cookie_secret", &original).await.unwrap();
        let dek2 = [0x99u8; 32];
        let blob2 = crypto::encrypt_to_base64(&kek, &dek2).unwrap();
        store.master_keys_insert(1, &blob2).await.unwrap();
        store.master_keys_activate(1).await.unwrap();
        let master_key = crate::crypto::MasterKey::from_test_bytes(kek);
        let ring = crate::store::key_ring_loader::refresh(&store, &master_key)
            .await
            .unwrap();
        store.replace_key_ring(ring).await;
        reencrypt_all(&store).await.unwrap();
        let scan = scan_key_id_usage(&store, 0).await.unwrap();
        assert_eq!(scan.total, 0, "no rows should still reference retired key");
    }

    /// ACME account credentials must survive retiring the DEK that first
    /// encrypted them, including a full Store close and reopen.
    #[tokio::test]
    async fn rotation_reencrypts_acme_credentials_before_old_key_retirement() {
        let kek = [0xE1u8; 32];
        let database = TempSqliteDb::new();
        let url = database.url();
        let credential_bytes = b"opaque-acme-account-credentials";
        let store = Store::new_for_test(&url, kek, None).await.unwrap();
        let credentials = acme_core::AcmeAccountCredentials::from_zeroizing(Zeroizing::new(
            credential_bytes.to_vec(),
        ));
        assert!(matches!(
            store
                .insert_acme_account_credentials_if_absent(credentials)
                .await
                .unwrap(),
            AcmeAccountCredentialInsert::Inserted
        ));

        let original = store
            .get_secret(ACCOUNT_CREDENTIALS_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            crypto::peek_key_id_from_base64(&original)
                .unwrap()
                .map(|key| key.get()),
            Some(0)
        );

        let next_dek = [0xE2u8; 32];
        let next_blob = crypto::encrypt_to_base64(&kek, &next_dek).unwrap();
        store.master_keys_insert(1, &next_blob).await.unwrap();
        store.master_keys_activate(1).await.unwrap();
        let master_key = crate::crypto::MasterKey::from_test_bytes(kek);
        let ring = crate::store::key_ring_loader::refresh(&store, &master_key)
            .await
            .unwrap();
        store.replace_key_ring(ring).await;

        let report = reencrypt_all(&store).await.unwrap();
        assert_eq!(report.examined, 2);
        assert_eq!(report.reencrypted, 2);
        assert_eq!(report.skipped, 0);
        let rotated = store
            .get_secret(ACCOUNT_CREDENTIALS_KEY)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            crypto::peek_key_id_from_base64(&rotated)
                .unwrap()
                .map(|key| key.get()),
            Some(1)
        );
        assert_eq!(scan_key_id_usage(&store, 0).await.unwrap().total, 0);

        store.master_keys_retire(0).await.unwrap();
        let master_key = crate::crypto::MasterKey::from_test_bytes(kek);
        let ring = crate::store::key_ring_loader::refresh(&store, &master_key)
            .await
            .unwrap();
        store.replace_key_ring(ring).await;
        store.close().await;
        drop(store);

        let reopened = Store::new_for_test(&url, kek, None).await.unwrap();
        let restored = reopened
            .load_acme_account_credentials()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.as_bytes(), credential_bytes);
        reopened.close().await;
    }
}
