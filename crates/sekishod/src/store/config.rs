//! Config facade. The backend is responsible for the raw load / merge /
//! persist; the facade layers in the in-memory cache and the version-
//! mismatch reload. Splitting it this way keeps the SQLite-specific
//! `BEGIN IMMEDIATE` + version-bump tx inside the backend, while the
//! process-local `config_cache` stays with `Store` (a future Postgres
//! backend will reuse the same cache logic unchanged).

use crate::error::Result;
use crate::models::config::GlobalConfig;
use std::sync::atomic::Ordering;

use super::Store;
use super::dispatch;

impl Store {
    pub async fn get_config(&self) -> Result<GlobalConfig> {
        // Check the DB-sourced version first. If a peer (or a local writer
        // we haven't observed yet) bumped it, drop the cache before reading
        // so we don't return stale data. One indexed SELECT; the bump itself
        // is rare, so the common path stays hot.
        let current_version = self.config_version_current().await?;
        let seen = self.config_seen_version.load(Ordering::Relaxed);
        if current_version != seen {
            let mut cache = self.config_cache.write().unwrap_or_else(|e| e.into_inner());
            *cache = None;
        }

        {
            let cache = self.config_cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(ref config) = *cache {
                return Ok(config.clone());
            }
        }

        let config = dispatch!(self, load_config)?;

        // Populate cache and record the version we loaded at. A concurrent
        // writer bumping between the load and the store() is fine — the
        // next read will still detect the mismatch and reload.
        let mut cache = self.config_cache.write().unwrap_or_else(|e| e.into_inner());
        *cache = Some(config.clone());
        self.config_seen_version
            .store(current_version, Ordering::Relaxed);

        Ok(config)
    }

    pub async fn update_config(&self, update: serde_json::Value) -> Result<GlobalConfig> {
        let result = dispatch!(self, update_config, update);
        if result.is_ok() {
            let mut cache = self.config_cache.write().unwrap_or_else(|e| e.into_inner());
            *cache = None;
        }
        result
    }
}
