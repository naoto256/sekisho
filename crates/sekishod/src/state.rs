//! Per-run application state for the proxy request path.
//!
//! `AppState` was originally `proxy::ProxyState` — naming carried over
//! from when the daemon was just a proxy. Today it is the shared state
//! for the proxy request path and the auth callbacks that redeem
//! sessions on it. The management API has its own `api::AppState`; the
//! periodic background tasks in `runtime::run` clone their concrete
//! dependencies (`Store`, `AcmeElection`, `CertResolver`, …) directly
//! and do not consume this `AppState`.
//!
//! Keeping the type in a top-level module avoids
//! `auth/* → proxy::ProxyState` reach-arounds and makes the dependency
//! direction obvious: consumers above may take `AppState`; nothing in
//! `state` reaches back into a consumer's application logic (only
//! their type definitions, which are leaf pieces of the API).
//!
//! `Clone` is cheap: every field is either a `Clone`-able primitive or
//! an `Arc<…>`. Cloning happens once per request via axum's
//! `with_state` machinery.

use crate::auth::handoff::HandoffCipher;
use crate::auth::middleware::AuthStateStore;
use crate::error::Result;
use crate::proxy::transform::TransformPipeline;
use crate::session::cookie_manager::CookieManager;
use crate::session::manager::SessionManager;
use crate::store::Store;
use crate::tls::acme::AcmeManager;
use crate::tls::acme::challenge::Http01Provider;
use auth_idp::oidc::OidcClient;
use auth_idp::saml::SamlClient;
use hyper_util::client::legacy::Client;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub client: Client<hyper_util::client::legacy::connect::HttpConnector, axum::body::Body>,
    /// One coherently published route snapshot and its generation-owned
    /// upstream clients, load-balancing counters, and admission budgets.
    pub(crate) route_generation: Arc<crate::route_generation::RouteGeneration>,
    pub auth_state_store: Arc<AuthStateStore>,
    pub session_manager: Arc<SessionManager>,
    pub cookie_manager: Arc<CookieManager>,
    pub acme_manager: Arc<AcmeManager<Http01Provider>>,
    pub(crate) handoff_cipher: HandoffCipher,
    /// Atomically published Ed25519 identity-signing key ring.
    #[cfg(not(test))]
    pub identity_key_ring: Arc<crate::crypto::IdentityKeyRingSnapshot>,
    #[cfg(test)]
    pub jwt_signing_key: Arc<crate::crypto::IdentityKeyRingSnapshot>,
    /// Canonical auth-domain snapshot established before any listener binds.
    /// It is deliberately immutable for the process lifetime; config updates
    /// advertise a required restart.
    pub(crate) identity_authority: Arc<crate::identity::IdentityAuthority>,
    pub tls_enabled: bool,
    /// Name of the Sekisho-controlled session cookie (`global_config
    /// .cookie_name`). Cached here so the request hot-path doesn't
    /// re-read config; `StripInternalHeaders` removes this entry
    /// from the outbound `Cookie:` header before forwarding so a
    /// large encrypted session value doesn't blow upstream nginx's
    /// header-buffer budget.
    pub session_cookie_name: String,
    pub pipeline: Arc<TransformPipeline>,
    pub(crate) oidc_clients: Arc<RwLock<std::collections::HashMap<Uuid, Arc<OidcClient>>>>,
    pub(crate) saml_clients: Arc<RwLock<std::collections::HashMap<Uuid, Arc<SamlClient>>>>,
    /// Last seen IdP version — used to invalidate client caches when IdP config changes.
    /// Version source of truth lives in the DB (`schema_versions.idps`) so
    /// peer-node mutations are observable here; this counter is just the
    /// per-process "have we reloaded since?" marker.
    pub(crate) idp_version_seen: Arc<std::sync::atomic::AtomicU64>,
}

/// Look up `key` in `cache` under a shared read lock. Returns
/// `Some(arc)` on hit so the caller can short-circuit without
/// touching the write lock; `None` on miss tells the caller to do
/// whatever it takes to build the value and then call
/// [`cache_insert_or_existing`].
///
/// Generic over the value so every `RwLock<HashMap<K, Arc<V>>>` cache
/// in `AppState` (OIDC and SAML clients)
/// shares one read primitive. The `Arc<V>` shape is the only
/// constraint — we never store `V` directly because all callers want
/// to hand out cheap clones.
async fn cache_try_get<K, V>(
    cache: &RwLock<std::collections::HashMap<K, Arc<V>>>,
    key: &K,
) -> Option<Arc<V>>
where
    K: Eq + std::hash::Hash,
{
    cache.read().await.get(key).cloned()
}

/// Insert `value` into `cache` under the write lock, returning the
/// `Arc<V>` that ends up cached. If a concurrent caller raced ahead
/// and already inserted (between our read-miss and write-lock
/// acquisition), we keep *their* entry and drop the one we built —
/// idempotent builds make this safe and avoid pointless replacement
/// of an Arc whose `OidcClient` / `SamlClient` is functionally
/// identical to ours.
async fn cache_insert_or_existing<K, V>(
    cache: &RwLock<std::collections::HashMap<K, Arc<V>>>,
    key: K,
    value: Arc<V>,
) -> Arc<V>
where
    K: Eq + std::hash::Hash,
{
    cache.write().await.entry(key).or_insert(value).clone()
}

impl AppState {
    pub(crate) fn identity_key_ring(&self) -> &crate::crypto::IdentityKeyRingSnapshot {
        #[cfg(not(test))]
        {
            self.identity_key_ring.as_ref()
        }
        #[cfg(test)]
        {
            self.jwt_signing_key.as_ref()
        }
    }

    /// Clear OIDC/SAML client caches if IdP config has been updated since last check.
    async fn invalidate_idp_clients_if_stale(&self) {
        // Read the DB version — this is the handoff point that will let a
        // peer node's write trigger our cache flush once the backend is
        // Postgres. On a DB error, skip the check rather than risk tearing
        // down the cache: wrong cache state is worse than slightly-stale.
        let current = match self.store.idp_version_current().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "failed to read idp version; keeping cache");
                return;
            }
        };
        let seen = self
            .idp_version_seen
            .load(std::sync::atomic::Ordering::Relaxed);
        if current != seen {
            self.oidc_clients.write().await.clear();
            self.saml_clients.write().await.clear();
            self.idp_version_seen
                .store(current, std::sync::atomic::Ordering::Relaxed);
            tracing::info!("IdP client caches cleared (generation {seen} -> {current})");
        }
    }

    // `idp_id` is propagated as a tracing span field so that
    // auth_idp-internal `tracing::info!(...)` events emitted under this
    // call (e.g. JWKS fetch, IdP metadata load) carry the IdP context
    // without auth_idp itself needing to know about Uuid.
    #[tracing::instrument(skip(self), fields(idp_id = %idp_id))]
    pub async fn get_oidc_client(&self, idp_id: Uuid) -> Result<Arc<OidcClient>> {
        self.invalidate_idp_clients_if_stale().await;
        if let Some(client) = cache_try_get(&self.oidc_clients, &idp_id).await {
            return Ok(client);
        }
        let idp = self.store.get_idp(idp_id).await?;
        let auth_origin = self
            .identity_authority
            .auth_origin()
            .map_err(|error| crate::error::Error::ConfigurationError(error.to_string()))?;
        let redirect_url = auth_origin.url("/.sekisho/callback");
        let oidc_config = idp
            .oidc_config
            .as_ref()
            .ok_or_else(|| crate::error::Error::ConfigurationError("missing oidc_config".into()))?;
        let secret = crate::auth::oidc::decrypt_oidc_client_secret(
            &self.store,
            &oidc_config.client_secret_encrypted,
        )
        .await?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| crate::error::Error::Internal(format!("HTTP client error: {e}")))?;
        let idp_cfg = auth_idp::oidc::OidcIdpConfig::from(&idp);
        let client_cfg = auth_idp::oidc::OidcClientConfig {
            client_id: oidc_config.client_id.clone(),
            redirect_url,
            scopes: oidc_config.scopes.clone(),
        };
        let client = Arc::new(OidcClient::new(http, &idp_cfg, &client_cfg, secret).await?);
        Ok(cache_insert_or_existing(&self.oidc_clients, idp_id, client).await)
    }

    #[tracing::instrument(skip(self), fields(idp_id = %idp_id))]
    pub async fn get_saml_client(&self, idp_id: Uuid) -> Result<Arc<SamlClient>> {
        self.invalidate_idp_clients_if_stale().await;
        if let Some(client) = cache_try_get(&self.saml_clients, &idp_id).await {
            return Ok(client);
        }
        let idp = self.store.get_idp(idp_id).await?;
        let auth_origin = self
            .identity_authority
            .auth_origin()
            .map_err(|error| crate::error::Error::ConfigurationError(error.to_string()))?;
        let entity_id = auth_origin.as_str().to_string();
        let acs_url = auth_origin.url("/.sekisho/saml/acs");
        let sp_slo_url = auth_origin.url("/.sekisho/saml/slo");
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| crate::error::Error::Internal(format!("HTTP client error: {e}")))?;
        let idp_cfg = auth_idp::saml::SamlIdpConfig::from(&idp);
        let sp_cfg = auth_idp::saml::SamlSpConfig {
            entity_id,
            acs_url,
            sp_slo_url: Some(sp_slo_url),
            request_id_prefix: "_sekisho".into(),
        };
        let client = Arc::new(SamlClient::new(&http, &idp_cfg, &sp_cfg).await?);
        Ok(cache_insert_or_existing(&self.saml_clients, idp_id, client).await)
    }
}
