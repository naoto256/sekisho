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
        // Converted first: an IdP of the wrong type fails here, before its
        // secret is decrypted or a client is built.
        let idp_cfg = auth_idp::oidc::OidcIdpConfig::try_from(&idp)?;
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
        // Converted first: an IdP of the wrong type fails here, before a
        // client is built.
        let idp_cfg = auth_idp::saml::SamlIdpConfig::try_from(&idp)?;
        let auth_origin = self
            .identity_authority
            .auth_origin()
            .map_err(|error| crate::error::Error::ConfigurationError(error.to_string()))?;
        let entity_id = auth_origin.as_str().to_string();
        let acs_url = auth_origin.url("/.sekisho/saml/acs");
        let sp_slo_url = auth_origin.url("/.sekisho/saml/slo");
        // Redirects are not followed, as for the OIDC client above. The SAML
        // client fetches the IdP metadata with this, so a redirect cannot move
        // that fetch away from the configured `metadata_url`.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| crate::error::Error::Internal(format!("HTTP client error: {e}")))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hardening_saml_metadata_does_not_follow_redirects() {
        use axum::{Router, response::IntoResponse, routing::get};
        use base64::Engine;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["idp.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = base64::engine::general_purpose::STANDARD.encode(cert.der());
        let metadata = format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>{der}</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/login"/></IDPSSODescriptor></EntityDescriptor>"#
        );
        let direct_hits = Arc::new(AtomicUsize::new(0));
        let redirected_hits = Arc::new(AtomicUsize::new(0));
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let count = redirected_hits.clone();
        let target_app = Router::new().fallback(get(move || {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                "unexpected follow"
            }
        }));
        let target_task = tokio::spawn(async move {
            axum::serve(target, target_app).await.unwrap();
        });
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let count = direct_hits.clone();
        let document = metadata.clone();
        let app = Router::new()
            .route(
                "/direct",
                get(move || {
                    let count = count.clone();
                    let document = document.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        document
                    }
                }),
            )
            .route(
                "/same",
                get(|| async {
                    (axum::http::StatusCode::FOUND, [("location", "/direct")], "").into_response()
                }),
            )
            .route(
                "/cross",
                get(move || async move {
                    (
                        axum::http::StatusCode::FOUND,
                        [("location", format!("http://{target_addr}/target"))],
                        "",
                    )
                        .into_response()
                }),
            )
            .route(
                "/http",
                get(move || async move {
                    (
                        axum::http::StatusCode::TEMPORARY_REDIRECT,
                        [(
                            "location",
                            format!("http://localhost:{}/target", target_addr.port()),
                        )],
                        "",
                    )
                        .into_response()
                }),
            );
        let origin_task = tokio::spawn(async move {
            axum::serve(origin, app).await.unwrap();
        });
        let store = Store::new_for_test("sqlite::memory:", [0x66; 32], None)
            .await
            .unwrap();
        let state = AppState {
            client: Client::builder(hyper_util::rt::TokioExecutor::new()).build_http(),
            route_generation: crate::route_generation::RouteGeneration::new_ready_empty_for_test(
                store.clone(),
            ),
            auth_state_store: Arc::new(AuthStateStore::new(store.clone())),
            session_manager: Arc::new(SessionManager::new(store.clone(), 8)),
            cookie_manager: Arc::new(CookieManager::new(&[1; 64])),
            acme_manager: Arc::new(AcmeManager::new(
                store.clone(),
                Arc::new(Http01Provider::new(store.clone())),
                "https://acme.invalid/directory",
                None,
            )),
            handoff_cipher: HandoffCipher::new(crate::crypto::MasterKey::from_test_bytes([2; 32])),
            jwt_signing_key: crate::crypto::IdentityKeyRingSnapshot::from_test_bytes([3; 32]),
            identity_authority: Arc::new(crate::identity::IdentityAuthority::for_test(
                "auth.example",
            )),
            tls_enabled: true,
            session_cookie_name: "sekisho_session".into(),
            pipeline: Arc::new(crate::proxy::transform::default_pipeline()),
            oidc_clients: Arc::new(RwLock::new(Default::default())),
            saml_clients: Arc::new(RwLock::new(Default::default())),
            idp_version_seen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            store: store.clone(),
        };
        for path in ["direct", "same", "cross", "http"] {
            let idp: crate::models::idp::IdentityProvider =
                serde_json::from_value(serde_json::json!({
                    "id": Uuid::new_v4(), "name": path, "type": "saml",
                    "saml_config": {"metadata_url": format!("http://{origin_addr}/{path}")}
                }))
                .unwrap();
            store.create_idp(&idp).await.unwrap();
            let result = state.get_saml_client(idp.id).await;
            if path == "direct" {
                assert!(result.is_ok());
            }
            assert_eq!(
                direct_hits.load(Ordering::SeqCst),
                1,
                "same-origin redirect was followed"
            );
            assert_eq!(
                redirected_hits.load(Ordering::SeqCst),
                0,
                "redirect destination received a request"
            );
        }
        origin_task.abort();
        target_task.abort();
        let _ = origin_task.await;
        let _ = target_task.await;
    }
}
