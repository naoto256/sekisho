//! Bootstrap and refresh helpers for the in-memory `MasterKeyRing`.
//!
//! Two entry points:
//!
//! * [`load_or_init`] — boot path. Reads `master_keys`, decrypts every
//!   non-retired row with the KEK, and assembles a [`MasterKeyRing`].
//!   An empty table, regardless of why it is empty, starts first-DEK
//!   initialization through the backend's atomic empty-table insert.
//!   A peer that already initialized the table and the winning peer both
//!   continue through the same persisted-row ring-build path.
//!
//! * [`refresh`] — polling path. Same as `load_or_init` minus the
//!   first-time init branch (boot has already populated the table). The
//!   polling loop runs this on every `key_ring_version` mismatch.
//!
//! Boot errors propagate through `Store::new`. `refresh` returns a new
//! snapshot or an error; production refresh callers replace the current
//! ring only on `Ok`, so an error leaves their previous snapshot installed.

use crate::audit;
use crate::crypto::{MasterKey, MasterKeyRing};
use crate::error::{Error, Result};

use super::{Store, backend::FirstDekInsertOutcome};

/// Boot-time loader. See module docs.
///
/// `master_key` supplies a short-lived KEK capability used to decrypt
/// persisted DEKs. This function never caches or persists it.
pub async fn load_or_init(store: &Store, master_key: &MasterKey) -> Result<MasterKeyRing> {
    let rows = store.master_keys_load_active_set().await?;
    if rows.is_empty() {
        return init_first_dek(store, master_key).await;
    }
    build_ring(store, master_key, rows).await
}

/// Polling-time refresh. Same shape as `load_or_init` but treats an
/// empty table as an error (it should never happen post-boot — even a
/// retire-everything pathway is blocked by `master_keys_retire`).
pub async fn refresh(store: &Store, master_key: &MasterKey) -> Result<MasterKeyRing> {
    let rows = store.master_keys_load_active_set().await?;
    if rows.is_empty() {
        return Err(Error::ConfigurationError(
            "master_keys table is empty after boot — refusing to rebuild ring".into(),
        ));
    }
    build_ring(store, master_key, rows).await
}

async fn build_ring(
    store: &Store,
    master_key: &MasterKey,
    rows: Vec<super::backend::MasterKeyRow>,
) -> Result<MasterKeyRing> {
    let version = store.key_ring_version_current().await?;
    // envelope-aead's ring loader wants encrypted DEK bytes (not
    // pre-decrypted plaintexts) plus a `Kek`. Base64-decode each row's
    // KEK-envelope here and hand the batch off — the crate then runs the
    // KEK-open per record and enforces the "exactly one active, no
    // duplicate key_id" invariants for us in one place.
    use base64::Engine;
    let mut records: Vec<crate::crypto::EncryptedDekRecord<Vec<u8>>> =
        Vec::with_capacity(rows.len());
    for row in &rows {
        let key_id: u16 = row.key_id.try_into().map_err(|_| {
            Error::ConfigurationError(format!("key_id {} out of range", row.key_id))
        })?;
        let encrypted_blob = base64::engine::general_purpose::STANDARD
            .decode(&row.key_encrypted)
            .map_err(|e| {
                Error::ConfigurationError(format!(
                    "master_keys.key_id={} base64-decode failed: {e}",
                    row.key_id
                ))
            })?;
        records.push(crate::crypto::EncryptedDekRecord {
            key_id,
            encrypted_blob,
            active: row.active,
            retired: row.retired,
        });
    }
    let kek = master_key.kek_capability();
    MasterKeyRing::from_encrypted_records(&kek, records, version)
        .map_err(|e| Error::ConfigurationError(format!("ring construction failed: {e}")))
}

async fn init_first_dek(store: &Store, master_key: &MasterKey) -> Result<MasterKeyRing> {
    use rand::Rng;
    let dek: [u8; 32] = rand::rng().random();

    match store
        .master_keys_insert_first_active_plaintext(&dek, master_key)
        .await?
    {
        FirstDekInsertOutcome::Inserted => {
            tracing::warn!(
                target: audit::TARGET,
                event = "crypto.dek_ring.bootstrap",
                category = "crypto",
                result = "success",
                key_id = 0,
                "auto-generated initial DEK at key_id=0"
            );
        }
        FirstDekInsertOutcome::AlreadyInitialized => {
            tracing::info!("lost first-DEK insert race to a peer; loading peer-installed ring");
        }
    }
    let rows = store.master_keys_load_active_set().await?;
    build_ring(store, master_key, rows).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::store::backend::SqliteBackend;
    use uuid::Uuid;

    #[tokio::test]
    async fn first_boot_generates_initial_dek() {
        let kek = [0xAAu8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        let master_key = crypto::MasterKey::from_test_bytes(kek);
        let ring = load_or_init(&store, &master_key).await.unwrap();
        assert_eq!(ring.active_key_id().get(), 0);
        assert_eq!(
            ring.known_key_ids()
                .iter()
                .map(|k| k.get())
                .collect::<Vec<_>>(),
            vec![0]
        );
        // Round-trip.
        let blob = ring.encrypt_active(b"hello").unwrap();
        let pt = ring.decrypt(&blob).unwrap();
        assert_eq!(&*pt, b"hello");
    }

    #[tokio::test]
    async fn second_boot_reloads_existing_ring() {
        let kek = [0xBBu8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        let master_key = crypto::MasterKey::from_test_bytes(kek);
        let r1 = load_or_init(&store, &master_key).await.unwrap();
        let blob = r1.encrypt_active(b"persist").unwrap();
        // Reload — should find the existing row, not generate a new one.
        let r2 = load_or_init(&store, &master_key).await.unwrap();
        assert_eq!(r2.active_key_id().get(), 0);
        let pt = r2.decrypt(&blob).unwrap();
        assert_eq!(&*pt, b"persist");
    }

    #[tokio::test]
    async fn refresh_picks_up_new_inactive_dek() {
        // After `add encryption-key` (insert without activate), refresh
        // should load the new key into the ring even though it's not
        // active yet — needed so peers can decrypt-test before activate.
        let kek = [0xCCu8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        let master_key = crypto::MasterKey::from_test_bytes(kek);
        let r1 = load_or_init(&store, &master_key).await.unwrap();
        assert_eq!(
            r1.known_key_ids()
                .iter()
                .map(|k| k.get())
                .collect::<Vec<_>>(),
            vec![0]
        );
        // Add a second DEK as if `add encryption-key` ran.
        let dek2 = [0x77u8; 32];
        let blob2 = crypto::encrypt_to_base64(&kek, &dek2).unwrap();
        store.master_keys_insert(1, &blob2).await.unwrap();
        let r2 = refresh(&store, &master_key).await.unwrap();
        assert_eq!(r2.active_key_id().get(), 0, "active should not flip on add");
        let mut ids: Vec<u8> = r2.known_key_ids().iter().map(|k| k.get()).collect();
        ids.sort();
        assert_eq!(ids, vec![0, 1]);
        assert!(r2.version() > r1.version(), "ring version must advance");
    }

    #[tokio::test]
    async fn activate_then_refresh_flips_active() {
        let kek = [0xDDu8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        let master_key = crypto::MasterKey::from_test_bytes(kek);
        load_or_init(&store, &master_key).await.unwrap();
        let dek2 = [0x33u8; 32];
        let blob2 = crypto::encrypt_to_base64(&kek, &dek2).unwrap();
        store.master_keys_insert(1, &blob2).await.unwrap();
        store.master_keys_activate(1).await.unwrap();
        let ring = refresh(&store, &master_key).await.unwrap();
        assert_eq!(ring.active_key_id().get(), 1);
    }

    #[tokio::test]
    async fn refresh_with_wrong_kek_errors() {
        let kek = [0xEEu8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        let master_key = crypto::MasterKey::from_test_bytes(kek);
        load_or_init(&store, &master_key).await.unwrap();
        let wrong = [0x11u8; 32];
        let wrong = crypto::MasterKey::from_test_bytes(wrong);
        let err = refresh(&store, &wrong).await.unwrap_err();
        assert!(matches!(err, Error::ConfigurationError(_)));
    }

    #[tokio::test]
    async fn bootstrap_does_not_repair_nonempty_zero_active_tables() {
        for retired in [false, true] {
            let path = std::env::temp_dir().join(format!(
                "sekishod-zero-active-bootstrap-{}-{}.sqlite3",
                retired,
                Uuid::new_v4()
            ));
            let url = format!("sqlite://{}", path.display());
            let kek = [0xE1; 32];
            let backend = SqliteBackend::new_service(&url, crypto::MasterKey::from_test_bytes(kek))
                .await
                .expect("test backend must migrate");
            backend.close().await;

            let pool = sqlx::SqlitePool::connect(&url)
                .await
                .expect("fixture pool must connect");
            let blob = crypto::encrypt_to_base64(&kek, &[0xE2; 32]).unwrap();
            sqlx::query(
                "INSERT INTO master_keys \
                 (key_id, key_encrypted, active, retired) VALUES (7, ?, 0, ?)",
            )
            .bind(blob)
            .bind(i64::from(retired))
            .execute(&pool)
            .await
            .unwrap();
            pool.close().await;

            let error = match Store::new_for_test(&url, kek, None).await {
                Ok(_) => panic!("zero-active table must fail closed"),
                Err(error) => error,
            };
            assert!(
                matches!(
                    error,
                    sqlx::Error::Protocol(ref message)
                        if message.contains("ring construction failed")
                ),
                "zero-active bootstrap must surface ring construction failure"
            );

            let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
            let rows = sqlx::query_as::<_, (i64, i64, i64)>(
                "SELECT key_id, active, retired FROM master_keys ORDER BY key_id",
            )
            .fetch_all(&pool)
            .await
            .unwrap();
            assert_eq!(rows, vec![(7, 0, i64::from(retired))]);
            pool.close().await;
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(format!("{}-wal", path.display()));
            let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        }
    }
}
