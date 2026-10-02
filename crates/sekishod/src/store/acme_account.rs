//! Durable storage boundary for the process ACME account capability.

use acme_core::AcmeAccountCredentials;

use crate::error::Result;
use crate::store::backend::SecretInsertOutcome;
use crate::store::{Store, dispatch};

/// Private service-DB key for the encrypted opaque credential envelope.
pub(super) const ACCOUNT_CREDENTIALS_KEY: &str = "_sekisho_acme_account_credentials_v1";

/// Outcome of racing to persist credentials for a previously missing account.
pub(crate) enum AcmeAccountCredentialInsert {
    /// This process installed its candidate and may keep the matching account.
    Inserted,
    /// Another process won; restore this durable winner instead.
    Existing(AcmeAccountCredentials),
}

impl Store {
    /// Load the durable account credential capability, when one exists.
    pub(crate) async fn load_acme_account_credentials(
        &self,
    ) -> Result<Option<AcmeAccountCredentials>> {
        let Some(encrypted) = dispatch!(self, get_secret, ACCOUNT_CREDENTIALS_KEY)? else {
            return Ok(None);
        };
        let plaintext = self.decrypt_any_from_base64_zeroizing(&encrypted).await?;
        Ok(Some(AcmeAccountCredentials::from_zeroizing(plaintext)))
    }

    /// Atomically install missing credentials and report the durable winner.
    ///
    /// Encryption happens before the database race. A losing caller discards
    /// its local account and receives the winner as a zeroizing capability;
    /// the external ACME account creation itself is intentionally at-least-once.
    pub(crate) async fn insert_acme_account_credentials_if_absent(
        &self,
        credentials: AcmeAccountCredentials,
    ) -> Result<AcmeAccountCredentialInsert> {
        let encrypted = self
            .encrypt_active_to_base64(credentials.as_bytes())
            .await?;
        let SecretInsertOutcome { inserted, value } = dispatch!(
            self,
            insert_secret_if_absent,
            ACCOUNT_CREDENTIALS_KEY,
            &encrypted,
        )?;
        if inserted {
            return Ok(AcmeAccountCredentialInsert::Inserted);
        }

        let plaintext = self.decrypt_any_from_base64_zeroizing(&value).await?;
        Ok(AcmeAccountCredentialInsert::Existing(
            AcmeAccountCredentials::from_zeroizing(plaintext),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zeroize::Zeroizing;

    use super::{ACCOUNT_CREDENTIALS_KEY, AcmeAccountCredentialInsert};
    use crate::store::Store;

    const TEST_MASTER_KEY: [u8; 32] = [0; 32];

    struct TempSqliteDb(std::path::PathBuf);

    impl TempSqliteDb {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            Self(std::env::temp_dir().join(format!(
                "sekisho-acme-account-{}-{}.sqlite3",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            )))
        }
    }

    impl Drop for TempSqliteDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(format!("{}-shm", self.0.display()));
            let _ = std::fs::remove_file(format!("{}-wal", self.0.display()));
        }
    }

    fn credentials(bytes: &[u8]) -> acme_core::AcmeAccountCredentials {
        acme_core::AcmeAccountCredentials::from_zeroizing(Zeroizing::new(bytes.to_vec()))
    }

    #[tokio::test]
    async fn credential_roundtrip_stays_encrypted_at_rest() {
        let store = Store::new(
            "sqlite::memory:",
            crate::crypto::MasterKey::from_test_bytes(TEST_MASTER_KEY),
        )
        .await
        .unwrap();
        let secret = b"opaque-account-credential-sentinel";
        assert!(matches!(
            store
                .insert_acme_account_credentials_if_absent(credentials(secret))
                .await
                .unwrap(),
            AcmeAccountCredentialInsert::Inserted
        ));

        let stored = store
            .get_secret(ACCOUNT_CREDENTIALS_KEY)
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.as_bytes().windows(secret.len()).any(|w| w == secret));
        let loaded = store
            .load_acme_account_credentials()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.as_bytes(), secret);
        store.close().await;
    }

    #[tokio::test]
    async fn concurrent_missing_candidates_converge_on_one_winner() {
        let store = Arc::new(
            Store::new(
                "sqlite::memory:",
                crate::crypto::MasterKey::from_test_bytes(TEST_MASTER_KEY),
            )
            .await
            .unwrap(),
        );
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for candidate in [b"candidate-a".as_slice(), b"candidate-b".as_slice()] {
            let store = store.clone();
            let barrier = barrier.clone();
            let candidate = candidate.to_vec();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .insert_acme_account_credentials_if_absent(credentials(&candidate))
                    .await
            }));
        }
        barrier.wait().await;

        let mut inserted = 0;
        let mut loser_winner = None;
        for task in tasks {
            match task.await.unwrap().unwrap() {
                AcmeAccountCredentialInsert::Inserted => inserted += 1,
                AcmeAccountCredentialInsert::Existing(value) => {
                    loser_winner = Some(value.as_bytes().to_vec());
                }
            }
        }
        assert_eq!(inserted, 1);
        let durable = store
            .load_acme_account_credentials()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loser_winner.as_deref(), Some(durable.as_bytes()));
        store.close().await;
    }

    #[tokio::test]
    async fn credential_survives_store_restart_with_same_identity() {
        let db = TempSqliteDb::new();
        let path = db.0.to_str().unwrap();
        let secret = b"durable-account-identity";
        let first = Store::new(
            path,
            crate::crypto::MasterKey::from_test_bytes(TEST_MASTER_KEY),
        )
        .await
        .unwrap();
        assert!(matches!(
            first
                .insert_acme_account_credentials_if_absent(credentials(secret))
                .await
                .unwrap(),
            AcmeAccountCredentialInsert::Inserted
        ));
        first.close().await;

        let second = Store::new(
            path,
            crate::crypto::MasterKey::from_test_bytes(TEST_MASTER_KEY),
        )
        .await
        .unwrap();
        let restored = second
            .load_acme_account_credentials()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.as_bytes(), secret);
        second.close().await;
    }

    #[tokio::test]
    async fn corrupt_ciphertext_fails_without_replacement() {
        let store = Store::new(
            "sqlite::memory:",
            crate::crypto::MasterKey::from_test_bytes(TEST_MASTER_KEY),
        )
        .await
        .unwrap();
        store
            .set_secret(ACCOUNT_CREDENTIALS_KEY, "not-an-envelope")
            .await
            .unwrap();
        assert!(store.load_acme_account_credentials().await.is_err());
        assert_eq!(
            store
                .get_secret(ACCOUNT_CREDENTIALS_KEY)
                .await
                .unwrap()
                .as_deref(),
            Some("not-an-envelope")
        );
        store.close().await;
    }
}
