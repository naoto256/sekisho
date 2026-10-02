//! Cross-host session handoff.
//!
//! Pomerium-style: cookies stay host-only, and SSO across subdomains
//! is achieved by redirecting the just-authenticated user through
//! `/.sekisho/session-handoff` on the *target* host with a short-lived,
//! encrypted handoff token. The target host verifies the token,
//! issues its own cookie, and redirects to the original path.
//!
//! The token is encrypted (ChaCha20-Poly1305) with the server master
//! key and carries a 60-second expiry. The shared service database
//! records consumed nonces so a duplicate redemption is rejected
//! across every HA node.

use std::sync::Arc;

use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{CryptoError, MasterKey};

/// Handoff token lifetime, in seconds.
const TOKEN_TTL_SECONDS: i64 = 60;

/// Why a handoff token was refused.
///
/// Every variant is a distinct rejection reason for the log; none of them
/// reaches the browser, which sees a uniform failure. Telling a caller
/// *which* check failed would turn this endpoint into an oracle for probing
/// token structure, expiry and host binding one attempt at a time.
#[derive(Debug, thiserror::Error)]
pub enum HandoffError {
    #[error("token decode failed: {0}")]
    DecodeFailed(String),
    #[error("token decrypt failed: {0}")]
    DecryptFailed(#[from] CryptoError),
    #[error("token payload invalid: {0}")]
    PayloadInvalid(String),
    #[error("token expired")]
    Expired,
    #[error("token already used")]
    Replayed,
    #[error("nonce store unavailable")]
    NonceStoreUnavailable,
    #[error("host mismatch")]
    HostMismatch,
}

/// Validate a handoff token and burn its nonce, in that order.
///
/// The nonce consume is the commit point, and it is a single atomic insert
/// rather than a read followed by a write: two nodes redeeming the same token
/// at the same instant both reach the database, and exactly one of them wins
/// the primary key. Checking first and inserting second would leave both
/// convinced they were first.
///
/// A store that cannot answer fails the redemption. Treating an unavailable
/// nonce table as "probably not replayed" would turn a database outage into a
/// replay window, which is precisely the situation the guard exists for.
async fn redeem_once(
    cipher: &HandoffCipher,
    store: &crate::store::Store,
    token: &str,
    request_host: &str,
) -> Result<HandoffClaims, HandoffError> {
    let claims = cipher.redeem(token, request_host)?;
    match store.handoff_nonce_consume(claims.nonce).await {
        Ok(true) => Ok(claims),
        Ok(false) => Err(HandoffError::Replayed),
        Err(_) => Err(HandoffError::NonceStoreUnavailable),
    }
}

/// The sealed payload of a handoff token.
///
/// Three independent restrictions, because the token travels in a URL and so
/// lands in browser history, referrers and any intermediate log: it is bound
/// to one host, it expires in seconds, and its nonce is single-use. Any one of
/// them alone leaves a usable window — together, a leaked token is inert.
#[derive(Debug, Serialize, Deserialize)]
pub struct HandoffClaims {
    /// Session ID to attach the new cookie to.
    pub sid: Uuid,
    /// Host that must serve the handoff. Verified against the Host
    /// header at consumption — prevents a token minted for host A from
    /// being redeemed on host B.
    pub host: String,
    /// Path (or full URL) to send the browser to after cookie set.
    pub to: String,
    /// Unix timestamp (seconds) after which the token is rejected.
    pub exp: i64,
    /// Unique per token; recorded in the service DB on redemption.
    pub nonce: Uuid,
}

/// Seals and opens handoff tokens with the process master key.
///
/// Authenticated encryption rather than a signature: the claims name a session
/// id, and a signed-but-readable token would expose it to anything that sees
/// the URL.
#[derive(Clone)]
pub(crate) struct HandoffCipher {
    key: Arc<MasterKey>,
}

impl HandoffCipher {
    pub(crate) fn new(key: Arc<MasterKey>) -> Self {
        Self { key }
    }

    /// Mint an encrypted handoff token.
    fn mint(
        &self,
        session_id: Uuid,
        target_host: &str,
        final_redirect: &str,
    ) -> Result<String, HandoffError> {
        let claims = HandoffClaims {
            sid: session_id,
            host: target_host.to_string(),
            to: final_redirect.to_string(),
            exp: chrono::Utc::now().timestamp() + TOKEN_TTL_SECONDS,
            nonce: Uuid::new_v4(),
        };
        let plaintext =
            serde_json::to_vec(&claims).map_err(|e| HandoffError::PayloadInvalid(e.to_string()))?;
        let ciphertext = self.key.encrypt(&plaintext)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ciphertext))
    }

    /// Decrypt and validate a handoff token's expiry and target host.
    /// The caller must atomically consume the returned nonce before
    /// validating the referenced session.
    fn redeem(&self, token: &str, request_host: &str) -> Result<HandoffClaims, HandoffError> {
        let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|e| HandoffError::DecodeFailed(e.to_string()))?;
        let plaintext = self.key.decrypt(&ciphertext)?;
        let claims: HandoffClaims = serde_json::from_slice(&plaintext)
            .map_err(|e| HandoffError::PayloadInvalid(e.to_string()))?;

        let now = chrono::Utc::now().timestamp();
        if now > claims.exp {
            return Err(HandoffError::Expired);
        }

        if !host_matches(&claims.host, request_host) {
            tracing::warn!(
                claimed = %claims.host,
                actual = %request_host,
                "handoff token host mismatch"
            );
            return Err(HandoffError::HostMismatch);
        }

        Ok(claims)
    }
}

/// Compare canonical host identities while intentionally ignoring ports.
///
/// Both inputs cross an HTTP authority boundary, so malformed authorities
/// fail closed before their host components are parsed as typed URL hosts.
/// The typed comparison normalizes DNS/IDNA names and IP address spellings;
/// parsing the optional port still prevents an invalid suffix from being
/// ignored as though it were absent.
fn host_matches(claim_host: &str, request_host: &str) -> bool {
    fn canonical_host(authority: &str) -> Option<url::Host<String>> {
        // `http::uri::Authority` accepts userinfo for generic URI use, but a
        // Host header or handoff target must consist of host and optional port.
        if authority.contains('@') {
            return None;
        }

        let authority = authority.parse::<axum::http::uri::Authority>().ok()?;
        let host = authority.host();
        let suffix = authority.as_str().strip_prefix(host)?;
        if !suffix.is_empty() && authority.port_u16().is_none() {
            return None;
        }

        url::Host::parse(host).ok()
    }

    canonical_host(claim_host)
        .zip(canonical_host(request_host))
        .is_some_and(|(claimed, requested)| claimed == requested)
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Response, StatusCode, header};

use crate::state::AppState;

/// Query string of the handoff endpoint: the sealed token, nothing else.
/// Deliberately minimal — anything additional here would be attacker-supplied
/// input influencing a flow whose whole security rests on the sealed payload.
#[derive(serde::Deserialize)]
pub struct HandoffParams {
    pub t: String,
}

/// `GET /.sekisho/session-handoff?t=<token>`
///
/// Redeemed on the *target* host. Verifies the token, confirms the
/// server-side session is still valid, sets the session cookie on the
/// current host, and redirects the browser to the original URL.
pub async fn session_handoff(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HandoffParams>,
) -> Result<Response<Body>, StatusCode> {
    let request_host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let claims =
        match redeem_once(&state.handoff_cipher, &state.store, &params.t, request_host).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    target: crate::audit::TARGET,
                    event = "handoff.reject",
                    category = "auth",
                    result = "failure",
                    actor_type = "user",
                    actor_id = "anonymous",
                    host = %request_host,
                    reason = ?e,
                    "session handoff rejected"
                );
                return Err(if matches!(e, HandoffError::NonceStoreUnavailable) {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::BAD_REQUEST
                });
            }
        };

    // Defensive: ensure the session still exists before minting a cookie
    // on this host. If someone saved a session-handoff URL from a logged-
    // out session we must not resurrect it.
    if state.session_manager.validate(claims.sid).await.is_err() {
        tracing::warn!(
            target: crate::audit::TARGET,
            event = "handoff.reject",
            category = "auth",
            result = "failure",
            actor_type = "user",
            actor_id = "anonymous",
            target_resource = "session",
            target_id = %claims.sid,
            host = %request_host,
            reason = "session_missing_or_expired",
            "session-handoff for missing/expired session"
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Look up the route serving this host so per-route SameSite
    // override (notably `none` for upstreams that run their own
    // SAML SP) lands on the cookie we mint here. The handoff
    // endpoint always lives on the target host, so a host-only
    // route lookup is the right scope.
    let same_site = match state.store.list_routes().await {
        Ok(routes) => routes
            .iter()
            .find(|r| {
                sekisho_api_protocol::hostname_from_url(&r.from).as_deref() == Some(request_host)
            })
            .and_then(|r| r.session_cookie_samesite)
            .map(|m| m.as_cookie())
            .unwrap_or(crate::session::cookie_manager::DEFAULT_SAME_SITE),
        Err(e) => {
            tracing::warn!(
                error = %e,
                host = %request_host,
                "could not load routes for SameSite lookup; falling back to default"
            );
            crate::session::cookie_manager::DEFAULT_SAME_SITE
        }
    };
    let cookie_value = state.cookie_manager.create_cookie(claims.sid, same_site);
    let redirect = crate::auth::safe_redirect(&claims.to, &state.store).await;

    tracing::info!(
        target: crate::audit::TARGET,
        event = "handoff.consume",
        category = "auth",
        result = "success",
        actor_type = "user",
        actor_id = "anonymous",
        target_resource = "session",
        target_id = %claims.sid,
        host = %request_host,
        "session handoff completed"
    );

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::SET_COOKIE, cookie_value)
        .header(header::LOCATION, redirect)
        // `no-referrer` so the `?t=<token>` in this URL cannot leak
        // to pages or analytics on the target host. Complements the
        // 60 s TTL and shared-database duplicate rejection.
        .header("Referrer-Policy", "no-referrer")
        .body(Body::empty())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

impl HandoffCipher {
    /// Build the URL to 302 to when the authenticated user's target host
    /// differs from the auth host. Returns `Err` if `original_url` can't
    /// be parsed or has no host — callers should fall back to a local
    /// set-cookie + redirect in that case.
    pub(crate) fn build_redirect_url(
        &self,
        session_id: Uuid,
        original_url: &str,
    ) -> Result<(String, String), HandoffError> {
        let parsed = url::Url::parse(original_url)
            .map_err(|e| HandoffError::PayloadInvalid(format!("bad redirect URL: {e}")))?;
        let target_host = parsed
            .host_str()
            .ok_or_else(|| HandoffError::PayloadInvalid("redirect URL has no host".into()))?
            .to_string();

        let final_path = {
            let mut pq = parsed.path().to_string();
            if let Some(q) = parsed.query() {
                pq.push('?');
                pq.push_str(q);
            }
            if pq.is_empty() { "/".to_string() } else { pq }
        };

        let token = self.mint(session_id, &target_host, &final_path)?;

        // Preserve port if the original URL had a non-default one, so dev
        // setups on `:8443` etc keep working.
        let host_with_port = match parsed.port() {
            Some(p) => format!("{target_host}:{p}"),
            None => target_host.clone(),
        };
        let url = format!(
            "https://{host_with_port}/.sekisho/session-handoff?t={}",
            urlencoding::encode(&token)
        );
        Ok((target_host, url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyHandoffClaims {
        sid: Uuid,
        host: String,
        to: String,
        exp: i64,
        nonce: Uuid,
    }

    fn key() -> Arc<MasterKey> {
        MasterKey::from_test_bytes([7u8; 32])
    }

    fn cipher() -> HandoffCipher {
        HandoffCipher::new(key())
    }

    #[test]
    fn cipher_shares_the_master_key_owner() {
        let owner = key();
        let cipher = HandoffCipher::new(Arc::clone(&owner));
        assert!(Arc::ptr_eq(&owner, &cipher.key));
    }

    fn legacy_token(claims: &LegacyHandoffClaims) -> String {
        let plaintext = serde_json::to_vec(claims).unwrap();
        let ciphertext = crypto::encrypt(&[7u8; 32], &plaintext).unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ciphertext)
    }

    #[test]
    fn redeems_pre_refactor_wire_fixture() {
        let token = "AmSDkk_xULp6ug-ZgMpItzWY9ChyLOXj1mtYZfxff1ylKjW5U6HjqXWG-mPGDGO_yUrzHxw8E0qgpkGAn8dSDF1IWot8d8kmVO3BoEu5QfTFScBlb1Ez1MX02NTRbzPBq9f0rhBR2B9DdfM9LhJK3ctLkaXH-FMPuYT6AqIBs7ZDUFDPIJzisezVDSVG4wLRsDhzNqu_skUWsbcgAsNYjsuJQEmgavuNvVykcE4WnlAbfQdFR5MVkt_XZjnjHVGY1VOEbsWO";
        let claims = cipher().redeem(token, "app.example.com").unwrap();
        assert_eq!(
            claims.sid,
            Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap()
        );
        assert_eq!(claims.host, "app.example.com");
        assert_eq!(claims.to, "/dashboard?x=1");
        assert_eq!(claims.exp, 4_102_444_800);
        assert_eq!(
            claims.nonce,
            Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap()
        );
    }

    #[test]
    fn minted_token_matches_legacy_wire_contract() {
        let sid = Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap();
        let before = chrono::Utc::now().timestamp();
        let token = cipher()
            .mint(sid, "app.example.com", "/dashboard?x=1")
            .unwrap();
        let after = chrono::Utc::now().timestamp();

        let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .unwrap();
        assert_eq!(ciphertext.first(), Some(&0x02));
        assert!(ciphertext.len() >= 1 + 24 + 16);
        let plaintext = crypto::decrypt(&[7u8; 32], &ciphertext).unwrap();
        let claims: LegacyHandoffClaims = serde_json::from_slice(&plaintext).unwrap();

        assert_eq!(claims.sid, sid);
        assert_eq!(claims.host, "app.example.com");
        assert_eq!(claims.to, "/dashboard?x=1");
        assert!(claims.exp >= before + TOKEN_TTL_SECONDS);
        assert!(claims.exp <= after + TOKEN_TTL_SECONDS);
        assert_ne!(claims.nonce, Uuid::nil());
    }

    #[test]
    fn expired_token_is_rejected_before_host_and_nonce_checks() {
        let sid = Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap();
        let nonce = Uuid::parse_str("55555555-5555-4555-8555-555555555555").unwrap();
        let expired_token = legacy_token(&LegacyHandoffClaims {
            sid,
            host: "app.example.com".to_owned(),
            to: "/dashboard?x=1".to_owned(),
            exp: 0,
            nonce,
        });

        assert!(matches!(
            cipher().redeem(&expired_token, "other.example.com"),
            Err(HandoffError::Expired)
        ));

        let live_token = legacy_token(&LegacyHandoffClaims {
            sid,
            host: "app.example.com".to_owned(),
            to: "/dashboard?x=1".to_owned(),
            exp: 4_102_444_800,
            nonce,
        });
        let claims = cipher().redeem(&live_token, "app.example.com").unwrap();
        assert_eq!(claims.nonce, nonce);
    }

    #[test]
    fn mint_and_redeem_roundtrip() {
        let sid = Uuid::new_v4();
        let token = cipher().mint(sid, "app.example.com", "/dashboard").unwrap();
        let claims = cipher().redeem(&token, "app.example.com").unwrap();
        assert_eq!(claims.sid, sid);
        assert_eq!(claims.to, "/dashboard");
    }

    #[tokio::test]
    async fn consume_precedes_session_validation_and_failed_validation_does_not_restore_nonce() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [9; 32], None)
            .await
            .unwrap();
        let sid = Uuid::new_v4();
        let token = cipher().mint(sid, "app.example.com", "/").unwrap();
        let claims = redeem_once(&cipher(), &store, &token, "app.example.com")
            .await
            .unwrap();
        assert_eq!(claims.sid, sid);
        let manager = crate::session::manager::SessionManager::new(store.clone(), 24);
        assert!(manager.validate(sid).await.is_err());
        assert!(matches!(
            redeem_once(&cipher(), &store, &token, "app.example.com").await,
            Err(HandoffError::Replayed)
        ));
    }

    #[tokio::test]
    async fn nonce_database_failure_is_distinct_and_fail_closed() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [10; 32], None)
            .await
            .unwrap();
        let token = cipher()
            .mint(Uuid::new_v4(), "app.example.com", "/")
            .unwrap();
        store.close().await;
        assert!(matches!(
            redeem_once(&cipher(), &store, &token, "app.example.com").await,
            Err(HandoffError::NonceStoreUnavailable)
        ));
    }

    #[tokio::test]
    async fn host_rejection_does_not_consume_the_nonce() {
        let store = crate::store::Store::new_for_test("sqlite::memory:", [11; 32], None)
            .await
            .unwrap();
        let token = cipher().mint(Uuid::new_v4(), "[2001:db8::1]", "/").unwrap();

        assert!(matches!(
            redeem_once(&cipher(), &store, &token, "[2001:db8::2]").await,
            Err(HandoffError::HostMismatch)
        ));
        assert!(
            redeem_once(&cipher(), &store, &token, "[2001:db8::1]")
                .await
                .is_ok(),
            "host validation must finish before the nonce is consumed"
        );
    }

    #[test]
    fn host_with_port_is_accepted() {
        let token = cipher()
            .mint(Uuid::new_v4(), "app.example.com", "/")
            .unwrap();
        assert!(cipher().redeem(&token, "app.example.com:443").is_ok());
    }

    #[test]
    fn canonical_hosts_match_without_comparing_ports() {
        assert!(host_matches("APP.EXAMPLE.COM", "app.example.com:443"));
        assert!(host_matches(
            "XN--BCHER-KVA.EXAMPLE:8443",
            "xn--bcher-kva.example:443"
        ));
        assert!(host_matches("127.0.0.1:8443", "127.1:443"));
        assert!(host_matches(
            "[2001:db8::1]:8443",
            "[2001:0db8:0:0:0:0:0:1]:443"
        ));

        assert!(!host_matches("a.example.com", "b.example.com"));
        assert!(!host_matches("127.0.0.1", "127.0.0.2"));
        assert!(!host_matches("[2001:db8::1]", "[2001:db8::2]"));
    }

    #[test]
    fn malformed_authorities_fail_closed() {
        for malformed in [
            "",
            "user@app.example.com",
            "https://app.example.com",
            "app.example.com/path",
            "app.example.com?query",
            "app.example.com#fragment",
            "2001:db8::1",
            "[2001:db8::1",
            "2001:db8::1]",
            "[]",
            "app.example.com:",
            "app.example.com:not-a-port",
            "app.example.com:65536",
        ] {
            assert!(
                !host_matches(malformed, malformed),
                "identical malformed authorities matched: {malformed}"
            );
            assert!(
                !host_matches(malformed, "app.example.com"),
                "malformed claim authority matched: {malformed}"
            );
            assert!(
                !host_matches("app.example.com", malformed),
                "malformed request authority matched: {malformed}"
            );
        }
    }

    #[test]
    fn redeem_uses_canonical_ipv6_identity() {
        let token = cipher().mint(Uuid::new_v4(), "[2001:db8::1]", "/").unwrap();
        assert!(
            cipher()
                .redeem(&token, "[2001:0db8:0:0:0:0:0:1]:443")
                .is_ok()
        );
        assert!(matches!(
            cipher().redeem(&token, "[2001:db8::2]:443"),
            Err(HandoffError::HostMismatch)
        ));
    }

    #[test]
    fn host_mismatch_rejected() {
        let token = cipher().mint(Uuid::new_v4(), "a.example.com", "/").unwrap();
        match cipher().redeem(&token, "b.example.com") {
            Err(HandoffError::HostMismatch) => {}
            other => panic!("expected HostMismatch, got {other:?}"),
        }
    }

    #[test]
    fn tampered_token_rejected() {
        let token = cipher()
            .mint(Uuid::new_v4(), "app.example.com", "/")
            .unwrap();
        // Flip a character in the middle — base64 stays valid but the
        // underlying ciphertext fails AEAD verification.
        let idx = token.len() / 2;
        let flipped_char = if token.as_bytes()[idx] == b'A' {
            'B'
        } else {
            'A'
        };
        let mut tampered = String::new();
        tampered.push_str(&token[..idx]);
        tampered.push(flipped_char);
        tampered.push_str(&token[idx + 1..]);
        assert!(cipher().redeem(&tampered, "app.example.com").is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let token = cipher()
            .mint(Uuid::new_v4(), "app.example.com", "/")
            .unwrap();
        assert!(
            HandoffCipher::new(MasterKey::from_test_bytes([0u8; 32]))
                .redeem(&token, "app.example.com")
                .is_err()
        );
    }

    // `build_redirect_url` is the bridge between the callback handlers
    // and the token encoding. These tests lock in its behavior so that
    // a refactor of the URL shape, host/port handling, or path+query
    // stripping cannot silently break the cross-host login flow.

    fn parse_token_from_handoff_url(url: &str) -> String {
        let parsed = url::Url::parse(url).expect("handoff url must parse");
        let (_, token) = parsed
            .query_pairs()
            .find(|(k, _)| k == "t")
            .expect("handoff url must have ?t=");
        token.into_owned()
    }

    #[test]
    fn build_redirect_url_round_trips() {
        let sid = Uuid::new_v4();
        let (target, url) = cipher()
            .build_redirect_url(sid, "https://app.example.com/dashboard?x=1")
            .unwrap();
        assert_eq!(target, "app.example.com");
        assert!(
            url.starts_with("https://app.example.com/.sekisho/session-handoff?t="),
            "unexpected handoff url: {url}"
        );

        let token = parse_token_from_handoff_url(&url);
        let claims = cipher().redeem(&token, "app.example.com").unwrap();
        assert_eq!(claims.sid, sid);
        assert_eq!(claims.host, "app.example.com");
        assert_eq!(
            claims.to, "/dashboard?x=1",
            "claim.to must carry path+query, not the full origin URL \
             — otherwise the final-redirect leg could be coerced off-host",
        );
    }

    #[test]
    fn build_redirect_url_preserves_port() {
        let (_, url) = cipher()
            .build_redirect_url(Uuid::new_v4(), "https://app.example.com:8443/")
            .unwrap();
        assert!(url.starts_with("https://app.example.com:8443/"));
    }

    #[test]
    fn build_redirect_url_serializes_and_redeems_ipv6_authorities() {
        let sid = Uuid::new_v4();
        let (target, url) = cipher()
            .build_redirect_url(sid, "https://[2001:db8::1]:8443/dashboard?x=1")
            .unwrap();
        assert_eq!(target, "[2001:db8::1]");
        assert!(url.starts_with("https://[2001:db8::1]:8443/.sekisho/session-handoff?t="));

        let token = parse_token_from_handoff_url(&url);
        let claims = cipher()
            .redeem(&token, "[2001:0db8:0:0:0:0:0:1]:443")
            .unwrap();
        assert_eq!(claims.sid, sid);
        assert_eq!(claims.host, "[2001:db8::1]");
        assert_eq!(claims.to, "/dashboard?x=1");
    }

    #[test]
    fn build_redirect_url_rejects_urls_without_host() {
        // Relative paths have no host, so there is no target to bounce
        // the cookie onto. The caller is expected to handle this as a
        // same-host redirect instead.
        let err = cipher()
            .build_redirect_url(Uuid::new_v4(), "/just/a/path")
            .unwrap_err();
        assert!(matches!(err, HandoffError::PayloadInvalid(_)));
    }

    #[test]
    fn build_redirect_url_defaults_root_path() {
        let (_, url) = cipher()
            .build_redirect_url(Uuid::new_v4(), "https://app.example.com")
            .unwrap();
        let token = parse_token_from_handoff_url(&url);
        let claims = cipher().redeem(&token, "app.example.com").unwrap();
        assert_eq!(claims.to, "/");
    }
}
