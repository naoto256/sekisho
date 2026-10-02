//! Per-instance SQLite database.
//!
//! `InstanceStore` owns the node-local bootstrap file. Two things live here:
//!
//! * **instance_config** — single key/value table that holds every
//!   per-node setting: bind addresses, the `cluster_db_url` pointer,
//!   and any future node-local knob. Each row carries an `encrypted`
//!   flag (0 = stored verbatim, 1 = ChaCha20-Poly1305 + base64 with
//!   the process-supplied master key, see `crate::crypto`).
//!
//!   Whether a given key is encrypted is **fixed in code**: the
//!   `get_*` / `set_*` accessors below pass the same `encrypted`
//!   argument every time, so an operator hand-editing the SQLite
//!   can't toggle a row from secret to plaintext or vice versa
//!   without breaking the next read. The flag is in the row, not in
//!   a side table, so `sqlite3` diagnostics can tell at a glance
//!   which rows are blobs vs strings.
//!
//!   When adding a new well-known key, ask "would leaking the
//!   bootstrap file leak this value's secret content?" If yes →
//!   pass `encrypted = true`. If no → `encrypted = false`. Listen
//!   addresses are bind targets, not secrets — `ss -tlnp` would
//!   reveal them anyway, so they live unencrypted to spare the
//!   crypto round-trip on every read.
//!
//! * **service tables** — created _only_ in single-node mode, where the
//!   bootstrap SQLite also serves as the operational store. When a
//!   separate service DB (Postgres or a distinct SQLite file) is
//!   configured, `Store::new` skips the service migrations against this
//!   file so it stays bootstrap-only. Dev boxes that were initialised
//!   under the pre-2.5c behaviour may carry empty operational tables
//!   here; they are harmless and never queried.
//!
//! Design note: the pool is exposed to the rest of `store` via the
//! crate-private `pool()` accessor so `SqliteBackend` can piggy-back on
//! the same connection pool when bootstrap and service share a file.
//! Opening the file twice would duplicate the WAL journal's writers and
//! defeat cache-invalidation wiring.

use crate::crypto::MasterKey;
use crate::error::{Error, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::KeyPair as _;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;
use std::sync::Arc;
use zeroize::Zeroize;

/// Well-known key inside `instance_config` that stores the
/// cluster-shared DB connection string (encrypted). Declared as a
/// constant so typos don't create ghost rows the server ignores.
/// Older DBs may carry the same value under the legacy key name
/// `service_db_url`; the migration in `run_instance_migrations`
/// renames it on first boot.
const KEY_CLUSTER_DB_URL: &str = "cluster_db_url";

/// Well-known plaintext keys for bind addresses. Listen addresses are
/// per-node bind targets, not secrets, so they live unencrypted.
/// Keep these names stable — they're the wire-level keys the
/// management API exposes (`PATCH /instance`) and the column the
/// operator sees when running `sqlite3` against the bootstrap file
/// for diagnostics.
const KEY_PROXY_LISTEN: &str = "proxy_listen";
const KEY_API_LISTEN: &str = "api_listen";
const KEY_HTTP_LISTEN: &str = "http_listen";

/// Plaintext keys for per-listener source-IP ACLs ("accept_from").
/// Empty / unset row means ANY source — matches the historical
/// behaviour. Stored unencrypted: a CIDR list is not a secret, and
/// the bind address it pairs with is also unencrypted.
const KEY_PROXY_ACCEPT_FROM: &str = "proxy_accept_from";
const KEY_API_ACCEPT_FROM: &str = "api_accept_from";
const KEY_HTTP_ACCEPT_FROM: &str = "http_accept_from";
const KEY_MANAGEMENT_RPK: &str = "management_rpk";
const MANAGEMENT_RPK_ENVELOPE_VERSION: u8 = 1;

/// Per-node defaults for listen addresses. Returned when the
/// corresponding row is absent so a fresh install boots without
/// requiring the operator to seed every bind manually.
pub const DEFAULT_PROXY_LISTEN: &str = "0.0.0.0:443";
pub const DEFAULT_HTTP_LISTEN: &str = "0.0.0.0:80";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ManagementApiBindingUpdate {
    pub(crate) listen_changed: bool,
    pub(crate) accept_from_changed: bool,
}

/// The management listener's Ed25519 identity: private key plus the SPKI
/// clients pin against.
///
/// Both halves travel together because the pin is meaningless without the key
/// that proves it, and every consumer needs to know they match — [`Self::validate`]
/// re-derives the public half from the private one rather than trusting the
/// stored pair, so a corrupted or hand-edited row fails at load instead of
/// producing a listener whose advertised pin nobody can satisfy.
///
/// Hand-written `Debug` and a `Drop` that zeroizes: this struct is passed
/// through startup and would otherwise be a plausible thing to log.
#[derive(Clone)]
pub(crate) struct ManagementRpkMaterial {
    private_pkcs8: Vec<u8>,
    public_spki: Vec<u8>,
}

impl std::fmt::Debug for ManagementRpkMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagementRpkMaterial")
            .field("private_pkcs8", &"[REDACTED]")
            .field("public_spki_len", &self.public_spki.len())
            .finish()
    }
}

impl Drop for ManagementRpkMaterial {
    fn drop(&mut self) {
        self.private_pkcs8.zeroize();
    }
}

impl ManagementRpkMaterial {
    /// Mint a fresh key pair and check it round-trips before returning.
    ///
    /// Validating at generation costs one derivation and means an unusable key
    /// can never be persisted — the alternative is discovering it at the next
    /// boot, when the management listener is the thing an operator needs in
    /// order to fix anything.
    pub(crate) fn generate() -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| Error::Internal("failed to generate management Ed25519 key".into()))?;
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| Error::Internal("failed to parse generated management key".into()))?;
        let public_spki =
            sekisho_management_rpk_tls::ed25519_spki_from_public_key(pair.public_key().as_ref())
                .map_err(|error| Error::Internal(error.to_string()))?;
        let material = Self {
            private_pkcs8: pkcs8.as_ref().to_vec(),
            public_spki,
        };
        material.validate()?;
        Ok(material)
    }

    /// Re-derive the public key from the private one and require it to match
    /// the stored SPKI. Run on both generation and load.
    fn validate(&self) -> Result<()> {
        sekisho_management_rpk_tls::validate_ed25519_spki(&self.public_spki)
            .map_err(|_| Error::Internal("stored management RPK SPKI is invalid".into()))?;
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&self.private_pkcs8)
            .map_err(|_| Error::Internal("stored management RPK private key is invalid".into()))?;
        let derived =
            sekisho_management_rpk_tls::ed25519_spki_from_public_key(pair.public_key().as_ref())
                .map_err(|error| Error::Internal(error.to_string()))?;
        if derived != self.public_spki {
            return Err(Error::Internal(
                "stored management RPK private/public material does not match".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn private_pkcs8(&self) -> &[u8] {
        &self.private_pkcs8
    }

    pub(crate) fn public_spki(&self) -> &[u8] {
        &self.public_spki
    }

    pub(crate) fn pin(&self) -> sekisho_api_protocol::management_rpk::ManagementRpkPin {
        sekisho_api_protocol::management_rpk::ManagementRpkPin::from_opaque_bytes(
            self.public_spki.clone(),
        )
        .expect("validated management SPKI is non-empty")
    }
}

#[derive(Serialize, Deserialize)]
struct StoredManagementRpk {
    version: u8,
    private_pkcs8: String,
    public_spki: String,
}

impl Drop for StoredManagementRpk {
    fn drop(&mut self) {
        self.private_pkcs8.zeroize();
        self.public_spki.zeroize();
    }
}

/// Per-instance SQLite wrapper. Cheap to clone (holds an `Arc`-backed
/// pool and the process-shared master-key capability).
#[derive(Clone)]
pub struct InstanceStore {
    pool: SqlitePool,
    master_key: Arc<MasterKey>,
}

impl InstanceStore {
    #[cfg(test)]
    pub(crate) fn shares_master_key(&self, expected: &Arc<MasterKey>) -> bool {
        Arc::ptr_eq(&self.master_key, expected)
    }

    /// Open (or create) the bootstrap SQLite at `bootstrap_path`, run
    /// the bootstrap migrations, and retain the master key in memory
    /// so subsequent `get_*` / `set_*` calls can decrypt and encrypt.
    ///
    /// `bootstrap_path` accepts anything `SqliteConnectOptions::from_str`
    /// understands, including `sqlite::memory:` for tests.
    pub async fn new(
        bootstrap_path: &str,
        master_key: Arc<MasterKey>,
    ) -> std::result::Result<Self, sqlx::Error> {
        // Auto-rename legacy on-disk file if present. The historical
        // name `bootstrap.db` was renamed to `instance_config.db` to
        // match the table name; do the rename before opening so the
        // pool sees the new path. Idempotent: if the new file
        // already exists we leave the old one alone (the new file
        // is authoritative). Skipped for in-memory and non-default
        // basenames so a custom `--instance-config /tmp/foo.db`
        // doesn't get renamed under the operator's feet.
        rename_legacy_bootstrap_file(bootstrap_path);

        let options = SqliteConnectOptions::from_str(bootstrap_path)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        let store = Self { pool, master_key };
        store.run_instance_migrations().await?;
        Ok(store)
    }

    /// Bootstrap-only schema. The service schema (routes, idps, ...) is
    /// handled separately by `SqliteBackend::from_pool_as_service` (and
    /// only on the single-node path) so a node running against a remote
    /// service DB never grows operational tables in this file.
    ///
    /// Migration shape (idempotent — fresh installs and any
    /// historical layout converge to the same final schema):
    ///
    /// 1. Create `instance_config` IF NOT EXISTS — the new single
    ///    table, key + value + encrypted flag + updated_at.
    /// 2. If the legacy split-era `bootstrap_secret` table exists,
    ///    copy its rows into `instance_config` with `encrypted = 1`
    ///    and DROP it.
    /// 3. If the legacy split-era `bootstrap_config` table exists in
    ///    its plaintext shape (i.e. has a `value` column rather than
    ///    the older `value_encrypted` column), copy its rows into
    ///    `instance_config` with `encrypted = 0` and DROP it.
    /// 4. If the pre-split `bootstrap_config` table exists (recognised
    ///    by a `value_encrypted` column), copy its rows into
    ///    `instance_config` with `encrypted = 1` and DROP it.
    ///
    /// Steps 2/3/4 are mutually compatible: a file can carry any
    /// subset, and steps run in order so the post-split plaintext
    /// `bootstrap_config` is detected (step 3) before we'd misclassify
    /// it as the pre-split encrypted shape (step 4).
    async fn run_instance_migrations(&self) -> std::result::Result<(), sqlx::Error> {
        // Step 1: the destination table.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS instance_config (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                encrypted  INTEGER NOT NULL DEFAULT 0 CHECK (encrypted IN (0, 1)),
                updated_at INTEGER NOT NULL DEFAULT (unixepoch())
            )"#,
        )
        .execute(&self.pool)
        .await?;

        // Step 2: encrypted secret table from the split era.
        let secret_exists: Option<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='bootstrap_secret'",
        )
        .fetch_optional(&self.pool)
        .await?;
        if secret_exists.is_some() {
            // The `service_db_url` key has been renamed to
            // `cluster_db_url` — fold the rename into the migration
            // copy so a freshly-migrated DB lands on the new key
            // names without a follow-up UPDATE.
            sqlx::query(
                r#"
                INSERT OR IGNORE INTO instance_config (key, value, encrypted, updated_at)
                SELECT
                    CASE WHEN key = 'service_db_url' THEN 'cluster_db_url' ELSE key END,
                    value_encrypted,
                    1,
                    updated_at
                FROM bootstrap_secret
                "#,
            )
            .execute(&self.pool)
            .await?;
            sqlx::query("DROP TABLE bootstrap_secret")
                .execute(&self.pool)
                .await?;
        }

        // Steps 3/4: the bootstrap_config table comes in two shapes.
        // Tell them apart by inspecting the CREATE statement before
        // we copy.
        let cfg_sql: Option<String> = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='bootstrap_config'",
        )
        .fetch_optional(&self.pool)
        .await?;
        if let Some(sql) = cfg_sql {
            // Order matters: the split-era plaintext table also has a
            // `value` column but no `value_encrypted`. The pre-split
            // table has `value_encrypted`. Check the encrypted column
            // first so we don't misclassify.
            if sql.contains("value_encrypted") {
                // Step 4: pre-split, single table held encrypted rows.
                // Same `service_db_url` → `cluster_db_url` key rename
                // as the bootstrap_secret copy above.
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO instance_config (key, value, encrypted, updated_at)
                    SELECT
                        CASE WHEN key = 'service_db_url' THEN 'cluster_db_url' ELSE key END,
                        value_encrypted,
                        1,
                        updated_at
                    FROM bootstrap_config
                    "#,
                )
                .execute(&self.pool)
                .await?;
            } else {
                // Step 3: split-era plaintext table. No renames here
                // — listen address keys are stable.
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO instance_config (key, value, encrypted, updated_at)
                    SELECT key, value, 0, updated_at FROM bootstrap_config
                    "#,
                )
                .execute(&self.pool)
                .await?;
            }
            sqlx::query("DROP TABLE bootstrap_config")
                .execute(&self.pool)
                .await?;
        }

        Ok(())
    }

    /// Borrow the inner pool so `SqliteBackend` can share it when the
    /// bootstrap SQLite also serves as the service backend (single-node
    /// default). Crate-private — production callers go through `Store`.
    pub(super) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Decrypt and return the stored cluster-shared DB URL, or
    /// `None` if not set. A decrypt failure surfaces as
    /// `Error::Crypto`, not silently as `None`: losing the master
    /// key while the bootstrap DB still points at a production
    /// Postgres is an operator-visible emergency.
    pub async fn get_cluster_db_url(&self) -> Result<Option<String>> {
        self.get_value(KEY_CLUSTER_DB_URL, true).await
    }

    /// Encrypt and persist the cluster-shared DB URL, overwriting
    /// any previous value. Callers that need the new URL to take
    /// effect must restart the daemon — the backend selection
    /// happens once at `Store::new`.
    pub async fn set_cluster_db_url(&self, url: &str) -> Result<()> {
        self.set_value(KEY_CLUSTER_DB_URL, url, true).await
    }

    /// Remove any stored cluster-shared DB URL. After a restart the
    /// node will fall back to single-node SQLite mode (the bootstrap
    /// file plays both roles).
    pub async fn clear_cluster_db_url(&self) -> Result<()> {
        self.delete_value(KEY_CLUSTER_DB_URL).await
    }

    // ───── listen addresses (plaintext, per-node) ─────
    //
    // Bind addresses are local-to-the-node by definition: in HA the
    // service DB is shared, but each peer listens on its own NIC. So
    // they live in the per-instance bootstrap file, not in
    // `GlobalConfig`. They're not secret either — `ss -tlnp` reveals
    // them to anyone on the box — so they're stored unencrypted.

    /// Proxy (data-plane) listen address. Falls back to the package
    /// default `0.0.0.0:443` when no row is set so a fresh install
    /// boots without operator intervention.
    pub async fn get_proxy_listen(&self) -> Result<String> {
        Ok(self
            .get_value(KEY_PROXY_LISTEN, false)
            .await?
            .unwrap_or_else(|| DEFAULT_PROXY_LISTEN.to_string()))
    }

    pub async fn set_proxy_listen(&self, addr: &str) -> Result<()> {
        self.set_value(KEY_PROXY_LISTEN, addr, false).await
    }

    pub async fn clear_proxy_listen(&self) -> Result<()> {
        self.delete_value(KEY_PROXY_LISTEN).await
    }

    /// Management API extra bind. Empty/unset means "localhost only"
    /// — `127.0.0.1:9443` is always listened on regardless, so a node
    /// is never unreachable from on-host tooling. Returns `""` (not
    /// `None`) when unset so call sites can do a single
    /// `is_empty()` check.
    pub async fn get_api_listen(&self) -> Result<String> {
        Ok(self
            .get_value(KEY_API_LISTEN, false)
            .await?
            .unwrap_or_default())
    }

    /// HTTP-side listen used for ACME http-01 challenges and the
    /// HTTPS redirect. Empty string disables it (e.g. when running
    /// behind another TLS terminator that handles ACME). Default
    /// `0.0.0.0:80`.
    pub async fn get_http_listen(&self) -> Result<String> {
        Ok(self
            .get_value(KEY_HTTP_LISTEN, false)
            .await?
            .unwrap_or_else(|| DEFAULT_HTTP_LISTEN.to_string()))
    }

    pub async fn set_http_listen(&self, addr: &str) -> Result<()> {
        self.set_value(KEY_HTTP_LISTEN, addr, false).await
    }

    pub async fn clear_http_listen(&self) -> Result<()> {
        self.delete_value(KEY_HTTP_LISTEN).await
    }

    // ───── per-listener source-IP ACLs (plaintext) ─────
    //
    // accept_from is a comma-separated CIDR / IP list. Empty string
    // (or absent row) means ANY source. We store the operator's
    // canonical form verbatim — `acl::AcceptFrom::parse` is the
    // single source of truth for the parse rules; the store is just
    // an opaque string column.

    pub async fn get_proxy_accept_from(&self) -> Result<String> {
        Ok(self
            .get_value(KEY_PROXY_ACCEPT_FROM, false)
            .await?
            .unwrap_or_default())
    }

    pub async fn set_proxy_accept_from(&self, v: &str) -> Result<()> {
        self.set_value(KEY_PROXY_ACCEPT_FROM, v, false).await
    }

    pub async fn clear_proxy_accept_from(&self) -> Result<()> {
        self.delete_value(KEY_PROXY_ACCEPT_FROM).await
    }

    pub async fn get_api_accept_from(&self) -> Result<String> {
        Ok(self
            .get_value(KEY_API_ACCEPT_FROM, false)
            .await?
            .unwrap_or_default())
    }

    pub async fn set_api_accept_from(&self, v: &str) -> Result<()> {
        self.set_value(KEY_API_ACCEPT_FROM, v, false).await
    }

    pub async fn clear_api_accept_from(&self) -> Result<()> {
        self.delete_value(KEY_API_ACCEPT_FROM).await
    }

    /// Atomically merge, validate, and persist the management listener and
    /// source ACL. Validation happens after reading both durable values under
    /// BEGIN IMMEDIATE and before either row is written.
    pub(crate) async fn update_management_api_binding(
        &self,
        api_listen: Option<Option<String>>,
        api_accept_from: Option<Option<String>>,
    ) -> Result<ManagementApiBindingUpdate> {
        let mut connection = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await?;
        let result: Result<ManagementApiBindingUpdate> = async {
            let current_listen: Option<(String, i64)> =
                sqlx::query_as("SELECT value, encrypted FROM instance_config WHERE key = ?")
                    .bind(KEY_API_LISTEN)
                    .fetch_optional(&mut *connection)
                    .await?;
            let current_accept: Option<(String, i64)> =
                sqlx::query_as("SELECT value, encrypted FROM instance_config WHERE key = ?")
                    .bind(KEY_API_ACCEPT_FROM)
                    .fetch_optional(&mut *connection)
                    .await?;
            if current_listen.as_ref().is_some_and(|row| row.1 != 0)
                || current_accept.as_ref().is_some_and(|row| row.1 != 0)
            {
                return Err(Error::Internal(
                    "management binding row has an invalid encrypted flag".into(),
                ));
            }
            let old_listen = current_listen.map(|row| row.0).unwrap_or_default();
            let old_accept = current_accept.map(|row| row.0).unwrap_or_default();
            let new_listen = match api_listen {
                None => old_listen.clone(),
                Some(None) => String::new(),
                Some(Some(value)) => value.trim().to_owned(),
            };
            let new_accept = match api_accept_from {
                None => old_accept.clone(),
                Some(None) => String::new(),
                Some(Some(value)) => crate::acl::AcceptFrom::parse(&value)
                    .map_err(|error| {
                        Error::BadRequest(format!("invalid api_accept_from: {error}"))
                    })?
                    .to_string_canonical(),
            };
            crate::validation::validate_management_api_binding(&new_listen, &new_accept)?;

            let update = ManagementApiBindingUpdate {
                listen_changed: old_listen != new_listen,
                accept_from_changed: old_accept != new_accept,
            };
            if update.listen_changed {
                write_plain_binding_row(&mut connection, KEY_API_LISTEN, &new_listen).await?;
            }
            if update.accept_from_changed {
                write_plain_binding_row(&mut connection, KEY_API_ACCEPT_FROM, &new_accept).await?;
            }
            Ok(update)
        }
        .await;
        match result {
            Ok(update) => {
                sqlx::query("COMMIT").execute(&mut *connection).await?;
                Ok(update)
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                Err(error)
            }
        }
    }

    pub async fn get_http_accept_from(&self) -> Result<String> {
        Ok(self
            .get_value(KEY_HTTP_ACCEPT_FROM, false)
            .await?
            .unwrap_or_default())
    }

    pub async fn set_http_accept_from(&self, v: &str) -> Result<()> {
        self.set_value(KEY_HTTP_ACCEPT_FROM, v, false).await
    }

    pub async fn clear_http_accept_from(&self) -> Result<()> {
        self.delete_value(KEY_HTTP_ACCEPT_FROM).await
    }

    // ───── management TLS raw public key (encrypted, per-instance) ─────

    #[cfg(test)]
    pub(crate) async fn load_management_rpk(&self) -> Result<Option<ManagementRpkMaterial>> {
        let row: Option<(String, i64)> =
            sqlx::query_as("SELECT value, encrypted FROM instance_config WHERE key = ?")
                .bind(KEY_MANAGEMENT_RPK)
                .fetch_optional(&self.pool)
                .await?;
        row.map(|row| self.decode_management_rpk(row)).transpose()
    }

    pub(crate) async fn ensure_management_rpk(
        &self,
        candidate: ManagementRpkMaterial,
    ) -> Result<ManagementRpkMaterial> {
        candidate.validate()?;
        let mut connection = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await?;
        let result: Result<ManagementRpkMaterial> = async {
            let row: Option<(String, i64)> =
                sqlx::query_as("SELECT value, encrypted FROM instance_config WHERE key = ?")
                    .bind(KEY_MANAGEMENT_RPK)
                    .fetch_optional(&mut *connection)
                    .await?;
            if let Some(row) = row {
                return self.decode_management_rpk(row);
            }

            let stored = self.encode_management_rpk(&candidate)?;
            sqlx::query("INSERT INTO instance_config (key, value, encrypted) VALUES (?, ?, 1)")
                .bind(KEY_MANAGEMENT_RPK)
                .bind(stored)
                .execute(&mut *connection)
                .await?;
            Ok(candidate)
        }
        .await;
        match result {
            Ok(material) => {
                sqlx::query("COMMIT").execute(&mut *connection).await?;
                Ok(material)
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                Err(error)
            }
        }
    }

    pub(crate) async fn rotate_management_rpk(
        &self,
        candidate: ManagementRpkMaterial,
    ) -> Result<ManagementRpkMaterial> {
        candidate.validate()?;
        let mut connection = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await?;
        let result: Result<()> = async {
            let current: Option<(String, i64)> = sqlx::query_as(
                "SELECT value, encrypted FROM instance_config WHERE key = ?",
            )
            .bind(KEY_MANAGEMENT_RPK)
            .fetch_optional(&mut *connection)
            .await?;
            let current = current.ok_or_else(|| {
                Error::Internal("management RPK is not initialized; print it first".into())
            })?;
            self.decode_management_rpk(current)?;

            let stored = self.encode_management_rpk(&candidate)?;
            sqlx::query(
                "UPDATE instance_config SET value = ?, encrypted = 1, updated_at = unixepoch() WHERE key = ?",
            )
            .bind(stored)
            .bind(KEY_MANAGEMENT_RPK)
            .execute(&mut *connection)
            .await?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                sqlx::query("COMMIT").execute(&mut *connection).await?;
                Ok(candidate)
            }
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                Err(error)
            }
        }
    }

    fn encode_management_rpk(&self, material: &ManagementRpkMaterial) -> Result<String> {
        material.validate()?;
        let envelope = StoredManagementRpk {
            version: MANAGEMENT_RPK_ENVELOPE_VERSION,
            private_pkcs8: URL_SAFE_NO_PAD.encode(material.private_pkcs8()),
            public_spki: URL_SAFE_NO_PAD.encode(material.public_spki()),
        };
        let plaintext = serde_json::to_vec(&envelope)
            .map_err(|error| Error::Internal(format!("serialize management RPK: {error}")))?;
        Ok(self.master_key.encrypt_to_base64(&plaintext)?)
    }

    fn decode_management_rpk(&self, row: (String, i64)) -> Result<ManagementRpkMaterial> {
        let (ciphertext, encrypted) = row;
        if encrypted != 1 {
            return Err(Error::Internal(
                "management RPK row is not encrypted".into(),
            ));
        }
        let mut plaintext = self.master_key.decrypt_from_base64(&ciphertext)?;
        let decoded = serde_json::from_slice(&plaintext);
        plaintext.zeroize();
        let envelope: StoredManagementRpk = decoded
            .map_err(|error| Error::Internal(format!("decode management RPK envelope: {error}")))?;
        if envelope.version != MANAGEMENT_RPK_ENVELOPE_VERSION {
            return Err(Error::Internal(
                "unsupported management RPK envelope version".into(),
            ));
        }
        let material = ManagementRpkMaterial {
            private_pkcs8: URL_SAFE_NO_PAD
                .decode(envelope.private_pkcs8.as_bytes())
                .map_err(|_| Error::Internal("invalid management RPK private encoding".into()))?,
            public_spki: URL_SAFE_NO_PAD
                .decode(envelope.public_spki.as_bytes())
                .map_err(|_| Error::Internal("invalid management RPK public encoding".into()))?,
        };
        material.validate()?;
        Ok(material)
    }

    // ───── unified accessors ─────
    //
    // One pair of `get_value` / `set_value` for every well-known key.
    // The `encrypted` argument is fixed at the call site so a row's
    // secrecy is encoded in code, not in operator data — flipping the
    // bit on disk would cause the next read to fail (decrypt error if
    // we expected encrypted; non-utf8 / garbage if we expected plain),
    // which is the correct outcome rather than silently exposing a
    // secret as plaintext.

    /// Read the row at `key` and decrypt iff `expected_encrypted` is
    /// true. A row whose stored `encrypted` flag disagrees with the
    /// caller's expectation surfaces as `Error::Internal`: that's
    /// almost certainly tampering or a key-name collision, and a
    /// silent `None` would mask both.
    async fn get_value(&self, key: &str, expected_encrypted: bool) -> Result<Option<String>> {
        let row: Option<(String, i64)> =
            sqlx::query_as("SELECT value, encrypted FROM instance_config WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;

        let Some((value, enc)) = row else {
            return Ok(None);
        };
        let stored_encrypted = enc != 0;
        if stored_encrypted != expected_encrypted {
            return Err(Error::Internal(format!(
                "instance_config row '{key}' has encrypted={stored_encrypted} but caller expected {expected_encrypted}"
            )));
        }
        if expected_encrypted {
            let plaintext = self.master_key.decrypt_from_base64(&value)?;
            let s = String::from_utf8(plaintext)
                .map_err(|e| Error::Internal(format!("instance_config value is not UTF-8: {e}")))?;
            Ok(Some(s))
        } else {
            Ok(Some(value))
        }
    }

    /// Insert or replace the row at `key`. The `encrypted` argument
    /// must match the rest of the codebase's expectation for that
    /// key: see the call sites above for how the well-known keys are
    /// classified.
    async fn set_value(&self, key: &str, value: &str, encrypted: bool) -> Result<()> {
        let stored = if encrypted {
            self.master_key.encrypt_to_base64(value.as_bytes())?
        } else {
            value.to_string()
        };
        let flag: i64 = if encrypted { 1 } else { 0 };
        sqlx::query(
            r#"
            INSERT INTO instance_config (key, value, encrypted)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                encrypted = excluded.encrypted,
                updated_at = unixepoch()
            "#,
        )
        .bind(key)
        .bind(&stored)
        .bind(flag)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_value(&self, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM instance_config WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Return `Some(_)` iff a row exists at `key`, regardless of its
    /// `encrypted` flag. Used by callers that only need the
    /// presence-vs-absence signal (e.g. PATCH handlers that decide
    /// whether to emit a `*_cleared` audit event).
    pub(crate) async fn has_value(&self, key: &str) -> Result<bool> {
        let row: Option<i64> = sqlx::query_scalar("SELECT 1 FROM instance_config WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Test-visible alias for the file-rename helper so the
    /// migration test can invoke it with a synthesised path.
    #[cfg(test)]
    pub(crate) fn rename_legacy_for_test(bootstrap_path: &str) {
        rename_legacy_bootstrap_file(bootstrap_path);
    }

    /// Flush and drop the underlying SQLite pool. Called from
    /// `Store::close` on the shutdown path. Idempotent; if the service
    /// backend is sharing this pool (single-node topology), the backend's
    /// own `close()` observes an already-closed pool and no-ops.
    pub(crate) async fn close(&self) {
        self.pool.close().await;
    }
}

async fn write_plain_binding_row(
    connection: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
    key: &str,
    value: &str,
) -> Result<()> {
    if value.is_empty() {
        sqlx::query("DELETE FROM instance_config WHERE key = ?")
            .bind(key)
            .execute(&mut **connection)
            .await?;
    } else {
        sqlx::query(
            "INSERT INTO instance_config (key, value, encrypted) VALUES (?, ?, 0) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, encrypted = 0, updated_at = unixepoch()",
        )
        .bind(key)
        .bind(value)
        .execute(&mut **connection)
        .await?;
    }
    Ok(())
}

/// Auto-rename the legacy on-disk SQLite file from the historical
/// `bootstrap.db` basename to the new `instance_config.db` basename.
///
/// Triggers only when the operator-supplied path *ends* with the new
/// basename and a sibling file with the legacy basename exists while
/// the new one doesn't. That keeps it scoped to the default packaging
/// path (`/var/lib/sekisho/instance_config.db`) without surprising an
/// operator who explicitly points `--instance-config` at a custom
/// filename. Idempotent in every other case (no-op on memory URLs,
/// already-renamed installs, fresh installs, custom basenames).
///
/// SQLite's WAL companion files (`-wal`, `-shm`) are renamed
/// alongside the main file when present so a reopen after the
/// rename resumes against a consistent journal — leaving a stale
/// `bootstrap.db-wal` next to the new `instance_config.db` would
/// silently abandon any committed transactions still living in WAL.
fn rename_legacy_bootstrap_file(bootstrap_path: &str) {
    // Strip an optional `sqlite:` URL scheme. In-memory URLs
    // (`sqlite::memory:`) collapse to `:memory:` here, which has no
    // parent directory and is correctly skipped below.
    let raw = bootstrap_path
        .strip_prefix("sqlite:")
        .unwrap_or(bootstrap_path);
    if raw.starts_with(':') {
        return;
    }
    let new_path = std::path::Path::new(raw);
    let Some(basename) = new_path.file_name().and_then(|s| s.to_str()) else {
        return;
    };
    if basename != "instance_config.db" {
        return;
    }
    let Some(parent) = new_path.parent() else {
        return;
    };
    let legacy_path = parent.join("bootstrap.db");
    if !legacy_path.exists() || new_path.exists() {
        return;
    }
    if let Err(e) = std::fs::rename(&legacy_path, new_path) {
        // Log and proceed: the open below will fail loudly if the
        // file genuinely isn't there, and a partial rename failure
        // is more useful as a separate signal than a silently-
        // squashed boot abort.
        tracing::warn!(
            from = %legacy_path.display(),
            to = %new_path.display(),
            error = %e,
            "failed to rename legacy bootstrap.db; continuing with the new path"
        );
        return;
    }
    tracing::info!(
        from = %legacy_path.display(),
        to = %new_path.display(),
        "renamed legacy bootstrap.db to instance_config.db"
    );
    // Best-effort WAL/shm move. SQLite recreates them on open if
    // missing, but any committed-but-uncheckpointed transactions
    // would be lost without this — abandoning data the operator
    // already saw as committed.
    for ext in ["-wal", "-shm"] {
        let from = parent.join(format!("bootstrap.db{ext}"));
        let to = parent.join(format!("instance_config.db{ext}"));
        if from.exists() && !to.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Arc<MasterKey> {
        MasterKey::from_test_bytes([7u8; 32])
    }

    #[tokio::test]
    async fn roundtrip_cluster_db_url() {
        let s = InstanceStore::new("sqlite::memory:", key()).await.unwrap();
        assert_eq!(s.get_cluster_db_url().await.unwrap(), None);

        s.set_cluster_db_url("postgres://u:p@h/db").await.unwrap();
        assert_eq!(
            s.get_cluster_db_url().await.unwrap().as_deref(),
            Some("postgres://u:p@h/db"),
        );

        s.clear_cluster_db_url().await.unwrap();
        assert_eq!(s.get_cluster_db_url().await.unwrap(), None);
    }

    #[tokio::test]
    async fn stored_secret_is_encrypted_at_rest() {
        let s = InstanceStore::new("sqlite::memory:", key()).await.unwrap();
        s.set_cluster_db_url("postgres://secret@h/db")
            .await
            .unwrap();

        let raw: String = sqlx::query_scalar("SELECT value FROM instance_config WHERE key = ?")
            .bind(KEY_CLUSTER_DB_URL)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert!(
            !raw.contains("secret"),
            "plaintext leaked into instance_config: {raw}",
        );

        // The encrypted flag must be set so a future read knows to
        // route through the crypto path.
        let flag: i64 = sqlx::query_scalar("SELECT encrypted FROM instance_config WHERE key = ?")
            .bind(KEY_CLUSTER_DB_URL)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(flag, 1);
    }

    #[tokio::test]
    async fn plain_string_roundtrip_is_not_encrypted() {
        // Plaintext rows store values verbatim. Verifies the listen
        // accessors don't accidentally pull values through the crypto
        // path.
        let s = InstanceStore::new("sqlite::memory:", key()).await.unwrap();
        assert_eq!(s.get_api_listen().await.unwrap(), "");

        s.set_proxy_listen("0.0.0.0:443").await.unwrap();
        assert_eq!(s.get_proxy_listen().await.unwrap(), "0.0.0.0:443");

        // Stored verbatim — the row equals the input and the encrypted
        // flag is 0.
        let (raw, flag): (String, i64) =
            sqlx::query_as("SELECT value, encrypted FROM instance_config WHERE key = ?")
                .bind(KEY_PROXY_LISTEN)
                .fetch_one(&s.pool)
                .await
                .unwrap();
        assert_eq!(raw, "0.0.0.0:443");
        assert_eq!(flag, 0);

        s.clear_proxy_listen().await.unwrap();
        assert_eq!(s.get_proxy_listen().await.unwrap(), "0.0.0.0:443");
    }

    #[tokio::test]
    async fn accept_from_roundtrip_and_default_empty() {
        // Default for an unset row is the empty string ⇒ ANY policy at
        // the parser layer. Set / get must round-trip verbatim — the
        // store doesn't try to canonicalise; that's the caller's job.
        let s = InstanceStore::new("sqlite::memory:", key()).await.unwrap();
        assert_eq!(s.get_proxy_accept_from().await.unwrap(), "");
        assert_eq!(s.get_api_accept_from().await.unwrap(), "");
        assert_eq!(s.get_http_accept_from().await.unwrap(), "");

        s.set_proxy_accept_from("127.0.0.1/32,10.0.0.0/8")
            .await
            .unwrap();
        assert_eq!(
            s.get_proxy_accept_from().await.unwrap(),
            "127.0.0.1/32,10.0.0.0/8"
        );
        s.clear_proxy_accept_from().await.unwrap();
        assert_eq!(s.get_proxy_accept_from().await.unwrap(), "");
    }

    #[tokio::test]
    async fn encrypted_and_plain_keys_coexist() {
        // Same row table, different encrypted flags — must not collide
        // and writes to one must not disturb the other.
        let s = InstanceStore::new("sqlite::memory:", key()).await.unwrap();
        s.set_cluster_db_url("postgres://u@h/db").await.unwrap();
        s.set_proxy_listen("10.0.0.1:443").await.unwrap();

        assert_eq!(
            s.get_cluster_db_url().await.unwrap().as_deref(),
            Some("postgres://u@h/db")
        );
        assert_eq!(s.get_proxy_listen().await.unwrap(), "10.0.0.1:443");
    }

    #[tokio::test]
    async fn flag_mismatch_surfaces_as_error() {
        // Tamper guard: if the encrypted flag doesn't match the
        // caller's expectation we fail loudly. Operator who hand-edits
        // the SQLite to flip a flag gets an immediate boot failure
        // instead of a silently-wrong read.
        let s = InstanceStore::new("sqlite::memory:", key()).await.unwrap();
        s.set_cluster_db_url("postgres://u@h/db").await.unwrap();
        // Flip the flag on disk.
        sqlx::query("UPDATE instance_config SET encrypted = 0 WHERE key = ?")
            .bind(KEY_CLUSTER_DB_URL)
            .execute(&s.pool)
            .await
            .unwrap();
        let err = s.get_cluster_db_url().await.unwrap_err();
        assert!(
            matches!(err, Error::Internal(_)),
            "expected Internal error on flag mismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn decrypt_fails_with_wrong_master_key() {
        // Tests that rotating / losing the master key surfaces a crypto
        // error rather than an ambiguous `None`. Guards against the
        // failure mode where an operator silently loses access to their
        // Postgres pointer and the node quietly boots in single-node
        // mode on top of the wrong data.
        let bootstrap_path = tempdir_path("decrypt-wrong-key");
        let s1 = InstanceStore::new(&bootstrap_path, key()).await.unwrap();
        s1.set_cluster_db_url("postgres://x@h/db").await.unwrap();
        drop(s1);

        let other = MasterKey::from_test_bytes([9u8; 32]);
        let s2 = InstanceStore::new(&bootstrap_path, other).await.unwrap();
        assert!(
            matches!(s2.get_cluster_db_url().await, Err(Error::Crypto(_))),
            "decrypt with mismatched key should surface Error::Crypto",
        );
    }

    #[tokio::test]
    async fn migration_from_split_era_two_tables() {
        // DBs from the bootstrap_secret + bootstrap_config split era
        // must collapse into the single `instance_config` table on
        // first boot. Encrypted rows preserve their ciphertext (same
        // master key, no re-encryption needed) and plaintext rows
        // come over verbatim.
        let path = tempdir_path("split-migration");

        {
            let opts = SqliteConnectOptions::from_str(&path)
                .unwrap()
                .create_if_missing(true);
            let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
            sqlx::query(
                r#"CREATE TABLE bootstrap_secret (
                    key TEXT PRIMARY KEY,
                    value_encrypted TEXT NOT NULL,
                    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
                )"#,
            )
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                r#"CREATE TABLE bootstrap_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
                )"#,
            )
            .execute(&pool)
            .await
            .unwrap();
            let encoded = key().encrypt_to_base64(b"postgres://legacy@h/db").unwrap();
            // Seed under the LEGACY key name `service_db_url`. The
            // migration renames it to `cluster_db_url` during the
            // copy; the assertion below verifies that path.
            sqlx::query("INSERT INTO bootstrap_secret (key, value_encrypted) VALUES (?, ?)")
                .bind("service_db_url")
                .bind(&encoded)
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO bootstrap_config (key, value) VALUES (?, ?)")
                .bind(KEY_PROXY_LISTEN)
                .bind("10.0.0.1:443")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }

        let s = InstanceStore::new(&path, key()).await.unwrap();

        assert_eq!(
            s.get_cluster_db_url().await.unwrap().as_deref(),
            Some("postgres://legacy@h/db"),
        );
        assert_eq!(s.get_proxy_listen().await.unwrap(), "10.0.0.1:443");

        // Old tables are gone.
        let old_secret: Option<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='bootstrap_secret'",
        )
        .fetch_optional(&s.pool)
        .await
        .unwrap();
        assert!(old_secret.is_none(), "bootstrap_secret should be dropped");
        let old_cfg: Option<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='bootstrap_config'",
        )
        .fetch_optional(&s.pool)
        .await
        .unwrap();
        assert!(old_cfg.is_none(), "bootstrap_config should be dropped");
    }

    #[tokio::test]
    async fn migration_from_pre_split_encrypted_bootstrap_config() {
        // DBs from the pre-split era have a single `bootstrap_config`
        // table whose `value_encrypted` column held every value
        // through the master key. The migration must move them into
        // `instance_config` with `encrypted = 1`.
        let path = tempdir_path("pre-split-migration");

        {
            let opts = SqliteConnectOptions::from_str(&path)
                .unwrap()
                .create_if_missing(true);
            let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
            sqlx::query(
                r#"CREATE TABLE bootstrap_config (
                    key TEXT PRIMARY KEY,
                    value_encrypted TEXT NOT NULL,
                    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
                )"#,
            )
            .execute(&pool)
            .await
            .unwrap();
            let encoded = key().encrypt_to_base64(b"postgres://ancient@h/db").unwrap();
            sqlx::query("INSERT INTO bootstrap_config (key, value_encrypted) VALUES (?, ?)")
                .bind("service_db_url")
                .bind(&encoded)
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }

        let s = InstanceStore::new(&path, key()).await.unwrap();
        assert_eq!(
            s.get_cluster_db_url().await.unwrap().as_deref(),
            Some("postgres://ancient@h/db"),
        );
    }

    #[tokio::test]
    async fn fresh_install_creates_instance_config_only() {
        // No legacy data — only the new table comes into existence.
        let s = InstanceStore::new("sqlite::memory:", key()).await.unwrap();

        let new_table: Option<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='instance_config'",
        )
        .fetch_optional(&s.pool)
        .await
        .unwrap();
        assert_eq!(new_table.as_deref(), Some("instance_config"));

        let old_secret: Option<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='bootstrap_secret'",
        )
        .fetch_optional(&s.pool)
        .await
        .unwrap();
        assert!(old_secret.is_none());
        let old_cfg: Option<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='bootstrap_config'",
        )
        .fetch_optional(&s.pool)
        .await
        .unwrap();
        assert!(old_cfg.is_none());
    }

    #[tokio::test]
    async fn migration_is_idempotent_on_already_migrated_db() {
        // After the migration has run once, re-running it must be a
        // no-op — no duplicate rows, no data loss, no errors.
        let path = tempdir_path("idempotent-migration");
        let s1 = InstanceStore::new(&path, key()).await.unwrap();
        s1.set_cluster_db_url("postgres://x@h/db").await.unwrap();
        s1.set_proxy_listen("0.0.0.0:443").await.unwrap();
        drop(s1);

        let s2 = InstanceStore::new(&path, key()).await.unwrap();
        assert_eq!(
            s2.get_cluster_db_url().await.unwrap().as_deref(),
            Some("postgres://x@h/db"),
        );
        assert_eq!(s2.get_proxy_listen().await.unwrap(), "0.0.0.0:443");
    }

    #[tokio::test]
    async fn rename_legacy_bootstrap_db_file_on_first_open() {
        // Simulates an upgraded host: a `bootstrap.db` exists from
        // the previous packaging and the new daemon points at
        // `instance_config.db` in the same directory. The rename
        // must happen before sqlx opens the file so the existing
        // rows survive the upgrade.
        let dir = std::env::temp_dir().join(format!(
            "sekisho-rename-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Seed a legacy bootstrap.db with one row through a fresh
        // InstanceStore opened against the legacy path.
        let legacy = dir.join("bootstrap.db");
        let legacy_url = format!("sqlite:{}", legacy.display());
        let s1 = InstanceStore::new(&legacy_url, key()).await.unwrap();
        s1.set_cluster_db_url("postgres://kept@h/db").await.unwrap();
        s1.close().await;

        // Now open under the new name. The helper must rename the
        // file in-place, and the row must be readable.
        let new = dir.join("instance_config.db");
        let new_url = format!("sqlite:{}", new.display());
        let s2 = InstanceStore::new(&new_url, key()).await.unwrap();
        assert_eq!(
            s2.get_cluster_db_url().await.unwrap().as_deref(),
            Some("postgres://kept@h/db"),
        );

        // Legacy file is gone; new file exists.
        assert!(!legacy.exists(), "legacy file should have been renamed");
        assert!(new.exists(), "new file should exist after rename");

        s2.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rename_skipped_when_new_file_already_present() {
        // Both files present (e.g. operator copied the old file by
        // accident or the daemon was downgraded then upgraded).
        // The new file is authoritative; we must not overwrite it.
        let dir = std::env::temp_dir().join(format!(
            "sekisho-rename-skip-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let legacy = dir.join("bootstrap.db");
        let new = dir.join("instance_config.db");
        // Plant authoritative content in the new file.
        let new_url = format!("sqlite:{}", new.display());
        let s_new = InstanceStore::new(&new_url, key()).await.unwrap();
        s_new
            .set_cluster_db_url("postgres://winner@h/db")
            .await
            .unwrap();
        s_new.close().await;
        // And different content in the legacy file.
        let legacy_url = format!("sqlite:{}", legacy.display());
        let s_legacy = InstanceStore::new(&legacy_url, key()).await.unwrap();
        s_legacy
            .set_cluster_db_url("postgres://loser@h/db")
            .await
            .unwrap();
        s_legacy.close().await;

        // Open through the new path — rename must be skipped.
        let s = InstanceStore::new(&new_url, key()).await.unwrap();
        assert_eq!(
            s.get_cluster_db_url().await.unwrap().as_deref(),
            Some("postgres://winner@h/db"),
            "new file should stay authoritative when both exist"
        );
        assert!(
            legacy.exists(),
            "legacy file should be left in place when the new file already exists"
        );

        s.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_helper_is_a_noop_for_in_memory_paths() {
        // Just exercise the path-stripping; if it tried to touch
        // the filesystem on `sqlite::memory:` the test environment
        // would surface a permission or IO error.
        InstanceStore::rename_legacy_for_test("sqlite::memory:");
        InstanceStore::rename_legacy_for_test(":memory:");
    }

    #[tokio::test]
    async fn management_binding_invalid_pair_is_atomic() {
        let store = InstanceStore::new("sqlite::memory:", key()).await.unwrap();
        store
            .update_management_api_binding(
                Some(Some("192.0.2.10:9443".into())),
                Some(Some("192.0.2.0/24".into())),
            )
            .await
            .unwrap();

        let error = store
            .update_management_api_binding(Some(Some("0.0.0.0:9443".into())), Some(None))
            .await
            .expect_err("invalid effective pair must fail before either write");
        assert!(error.to_string().contains("unspecified"));
        assert_eq!(store.get_api_listen().await.unwrap(), "192.0.2.10:9443");
        assert_eq!(store.get_api_accept_from().await.unwrap(), "192.0.2.0/24");
    }

    #[tokio::test]
    async fn concurrent_management_rpk_ensure_has_one_durable_winner() {
        let path = tempdir_path("rpk-concurrent-ensure");
        let store = InstanceStore::new(&path, key()).await.unwrap();
        let first = ManagementRpkMaterial::generate().unwrap();
        let second = ManagementRpkMaterial::generate().unwrap();
        let expected = [first.pin().to_string(), second.pin().to_string()];

        let left_store = store.clone();
        let right_store = store.clone();
        let (left, right) = tokio::join!(
            left_store.ensure_management_rpk(first),
            right_store.ensure_management_rpk(second),
        );
        let left = left.unwrap().pin().to_string();
        let right = right.unwrap().pin().to_string();
        assert_eq!(left, right);
        assert!(expected.contains(&left));
        assert_eq!(
            store
                .load_management_rpk()
                .await
                .unwrap()
                .unwrap()
                .pin()
                .to_string(),
            left,
        );
        let (stored, encrypted): (String, i64) = sqlx::query_as(
            "SELECT value, encrypted FROM instance_config WHERE key = 'management_rpk'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(encrypted, 1);
        assert!(!stored.contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn management_rpk_rotate_failure_and_cancel_preserve_old_key() {
        let path = tempdir_path("rpk-rotate-rollback");
        let store = InstanceStore::new(&path, key()).await.unwrap();
        let old = store
            .ensure_management_rpk(ManagementRpkMaterial::generate().unwrap())
            .await
            .unwrap()
            .pin()
            .to_string();

        sqlx::query(
            "CREATE TRIGGER reject_management_rpk_rotate BEFORE UPDATE ON instance_config \
             WHEN OLD.key = 'management_rpk' BEGIN SELECT RAISE(ABORT, 'injected'); END",
        )
        .execute(store.pool())
        .await
        .unwrap();
        assert!(
            store
                .rotate_management_rpk(ManagementRpkMaterial::generate().unwrap())
                .await
                .is_err()
        );
        sqlx::query("DROP TRIGGER reject_management_rpk_rotate")
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            store
                .load_management_rpk()
                .await
                .unwrap()
                .unwrap()
                .pin()
                .to_string(),
            old,
        );

        let mut lock = store.pool().acquire().await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *lock)
            .await
            .unwrap();
        let rotating = store.clone();
        let task = tokio::spawn(async move {
            rotating
                .rotate_management_rpk(ManagementRpkMaterial::generate().unwrap())
                .await
        });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        sqlx::query("ROLLBACK").execute(&mut *lock).await.unwrap();
        assert_eq!(
            store
                .load_management_rpk()
                .await
                .unwrap()
                .unwrap()
                .pin()
                .to_string(),
            old,
        );
    }

    #[tokio::test]
    async fn management_rpk_wrong_master_corruption_and_spki_mismatch_fail_closed() {
        let path = tempdir_path("rpk-fail-closed");
        let right_key = key();
        let store = InstanceStore::new(&path, right_key.clone()).await.unwrap();
        store
            .ensure_management_rpk(ManagementRpkMaterial::generate().unwrap())
            .await
            .unwrap();

        let wrong = InstanceStore::new(&path, MasterKey::from_test_bytes([9u8; 32]))
            .await
            .unwrap();
        assert!(wrong.load_management_rpk().await.is_err());
        wrong.close().await;

        sqlx::query("UPDATE instance_config SET value = 'not-an-envelope' WHERE key = ?")
            .bind(KEY_MANAGEMENT_RPK)
            .execute(store.pool())
            .await
            .unwrap();
        assert!(store.load_management_rpk().await.is_err());

        let private = ManagementRpkMaterial::generate().unwrap();
        let public = ManagementRpkMaterial::generate().unwrap();
        let envelope = StoredManagementRpk {
            version: MANAGEMENT_RPK_ENVELOPE_VERSION,
            private_pkcs8: URL_SAFE_NO_PAD.encode(private.private_pkcs8()),
            public_spki: URL_SAFE_NO_PAD.encode(public.public_spki()),
        };
        let mut plaintext = serde_json::to_vec(&envelope).unwrap();
        let ciphertext = right_key.encrypt_to_base64(&plaintext).unwrap();
        plaintext.zeroize();
        sqlx::query("UPDATE instance_config SET value = ?, encrypted = 1 WHERE key = ?")
            .bind(ciphertext)
            .bind(KEY_MANAGEMENT_RPK)
            .execute(store.pool())
            .await
            .unwrap();
        assert!(store.load_management_rpk().await.is_err());
    }

    fn tempdir_path(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        let unique = format!(
            "sekisho-instance-{tag}-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4(),
        );
        p.push(unique);
        format!("sqlite:{}", p.display())
    }
}
