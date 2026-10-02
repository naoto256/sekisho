//! Store-facade methods for the DEK ring (`master_keys` table).
//!
//! The actual DDL + per-backend SQL lives under `store::backend::*`;
//! this file is a thin pass-through so callers can speak to the ring
//! through `Store` without knowing which backend is mounted underneath.

use crate::error::Result;

use super::Store;
use super::backend::{FirstDekInsertOutcome, MasterKeyRow};
use super::dispatch;

impl Store {
    /// Read every non-retired DEK row. The returned blobs are still
    /// KEK-encrypted — the caller (`crypto::MasterKeyRing` loader)
    /// decrypts each before assembling the in-memory ring.
    pub async fn master_keys_load_active_set(&self) -> Result<Vec<MasterKeyRow>> {
        dispatch!(self, master_keys_load_active_set)
    }

    /// Atomically seed key ID 0 as active only when no master-key row
    /// exists. Used exclusively by the boot-time ring loader.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn master_keys_insert_first_active_if_empty(
        &self,
        key_encrypted: &str,
    ) -> Result<FirstDekInsertOutcome> {
        dispatch!(
            self,
            master_keys_insert_first_active_if_empty,
            key_encrypted
        )
    }

    pub(crate) async fn master_keys_insert_first_active_plaintext(
        &self,
        key_plaintext: &[u8],
        master_key: &crate::crypto::MasterKey,
    ) -> Result<FirstDekInsertOutcome> {
        dispatch!(
            self,
            master_keys_insert_first_active_plaintext,
            key_plaintext,
            master_key
        )
    }

    /// Test-only explicit-ID insert used to construct rotation fixtures.
    #[cfg(test)]
    pub async fn master_keys_insert(&self, key_id: i16, key_encrypted: &str) -> Result<()> {
        dispatch!(self, master_keys_insert, key_id, key_encrypted)
    }

    /// Allocate the smallest free v3 key ID and insert an inactive DEK.
    /// Selection, insertion, and ring-version publication are one backend
    /// transaction so concurrent nodes cannot select the same slot.
    #[cfg(test)]
    pub async fn master_keys_allocate_inactive(&self, key_encrypted: &str) -> Result<i16> {
        dispatch!(self, master_keys_allocate_inactive, key_encrypted)
    }

    pub async fn master_keys_allocate_inactive_plaintext(
        &self,
        key_plaintext: &[u8],
        master_key: &crate::crypto::MasterKey,
    ) -> Result<i16> {
        dispatch!(
            self,
            master_keys_allocate_inactive_plaintext,
            key_plaintext,
            master_key
        )
    }

    /// Promote `key_id` to active, demoting whichever row was active
    /// before. Same transaction, atomic from a peer's POV. Bumps
    /// `key_ring_version`.
    pub async fn master_keys_activate(&self, key_id: i16) -> Result<()> {
        dispatch!(self, master_keys_activate, key_id)
    }

    /// Mark `key_id` retired. Refuses the active row; idempotent on an
    /// already-retired one. Bumps `key_ring_version`.
    pub async fn master_keys_retire(&self, key_id: i16) -> Result<()> {
        dispatch!(self, master_keys_retire, key_id)
    }

    /// Current value of the `key_ring_version` counter. Polled by every
    /// daemon to detect peer-side rotations.
    pub async fn key_ring_version_current(&self) -> Result<u64> {
        dispatch!(self, key_ring_version_current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    /// Boot path leaves the table with exactly one active row at key_id 0.
    #[tokio::test]
    async fn boot_seeds_single_active_dek() {
        let store = Store::new_for_test("sqlite::memory:", [0x10u8; 32], None)
            .await
            .unwrap();
        let rows = store.master_keys_load_active_set().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key_id, 0);
        assert!(rows[0].active);
        assert!(!rows[0].retired);
    }

    /// Activate flips active and bumps the ring version.
    #[tokio::test]
    async fn activate_demotes_previous_active_and_bumps_version() {
        let kek = [0x20u8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        let v0 = store.key_ring_version_current().await.unwrap();
        // Add a second DEK at key_id 1.
        let dek2 = [0x33u8; 32];
        let blob = crypto::encrypt_to_base64(&kek, &dek2).unwrap();
        store.master_keys_insert(1, &blob).await.unwrap();
        // Activate it.
        store.master_keys_activate(1).await.unwrap();
        let rows = store.master_keys_load_active_set().await.unwrap();
        assert_eq!(rows.len(), 2);
        let active: Vec<_> = rows.iter().filter(|r| r.active).collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].key_id, 1);
        let v1 = store.key_ring_version_current().await.unwrap();
        assert!(v1 > v0, "ring version should advance on activate");
    }

    /// Retire refuses to drop the active row — that would brick every
    /// at-rest blob until the operator manually re-promoted another key.
    #[tokio::test]
    async fn retire_refuses_active_key() {
        let store = Store::new_for_test("sqlite::memory:", [0x30u8; 32], None)
            .await
            .unwrap();
        let err = store.master_keys_retire(0).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::ConfigurationError(_)));
        // Row remains active and non-retired.
        let rows = store.master_keys_load_active_set().await.unwrap();
        assert!(rows[0].active);
        assert!(!rows[0].retired);
    }

    /// Activate refuses a retired row.
    #[tokio::test]
    async fn activate_refuses_retired_key() {
        let kek = [0x40u8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        // Add + activate key_id 1 so we can retire 0 instead of the
        // active one (retire refuses the active row).
        let dek2 = [0x55u8; 32];
        let blob = crypto::encrypt_to_base64(&kek, &dek2).unwrap();
        store.master_keys_insert(1, &blob).await.unwrap();
        store.master_keys_activate(1).await.unwrap();
        store.master_keys_retire(0).await.unwrap();
        // Now try to re-activate 0.
        let err = store.master_keys_activate(0).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::ConfigurationError(_)));
    }

    #[tokio::test]
    async fn allocate_inactive_key_picks_smallest_gap_atomically() {
        let kek = [0x51u8; 32];
        let store = Store::new_for_test("sqlite::memory:", kek, None)
            .await
            .unwrap();
        let blob = crypto::encrypt_to_base64(&kek, &[0x67u8; 32]).unwrap();

        assert_eq!(store.master_keys_allocate_inactive(&blob).await.unwrap(), 1);
        assert_eq!(store.key_ring_version_current().await.unwrap(), 2);
    }
}
