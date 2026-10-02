//! Signing and shaping the cookies sekisho sets on the browser.
//!
//! Two kinds, with different lifetimes and different scopes.
//!
//! The **session cookie** carries a signed session id and nothing else. It is
//! host-only — no `Domain` attribute — so a session on one subdomain is not
//! automatically presented to every other one; crossing hosts goes through the
//! explicit handoff flow instead. `Secure` and `HttpOnly` are unconditional:
//! the id is a bearer credential, so script access and cleartext transmission
//! are both out.
//!
//! The **pre-auth cookie** holds the per-flow nonce between the redirect to
//! the IdP and the callback. It is named per flow (`__Secure-sekisho_pre_<state>`),
//! scoped to `/.sekisho/`, and short-lived. Naming it per flow is what lets two
//! login attempts from the same browser — a second tab, a retried
//! authentication — complete independently instead of overwriting each other's
//! nonce; the `__Secure-` prefix is a browser-enforced guarantee that the
//! cookie was set over HTTPS and carries no `Domain`.
//!
//! `SameSite` defaults to `Lax` and is overridable per route, because an
//! upstream running its own SAML SP needs the IdP's cross-site POST to carry
//! the session cookie. Every relaxation widens CSRF exposure, so it is opt-in
//! per route rather than global.

use cookie::{Cookie, Key, SameSite};
use uuid::Uuid;

/// Fallback session cookie name, overridden by `global_config.cookie_name`.
const COOKIE_NAME: &str = "_sekisho_session";

/// Per-flow pre-auth cookie prefix. `__Secure-` is browser-enforced: the
/// cookie is rejected unless it was set over HTTPS, so the nonce cannot be
/// planted by a cleartext man-in-the-middle.
const PRE_AUTH_COOKIE_PREFIX: &str = "__Secure-sekisho_pre_";

/// Pre-auth cookies are scoped to sekisho's own callback paths — no upstream
/// ever needs to see one.
const PRE_AUTH_COOKIE_PATH: &str = "/.sekisho/";

/// Ten minutes: long enough for a human to finish an IdP login including MFA,
/// short enough that an abandoned flow leaves nothing usable behind.
const PRE_AUTH_COOKIE_MAX_AGE_SECONDS: i64 = 600;

/// Default `SameSite` value for any issued session cookie. Lax is
/// the right CSRF posture for the typical deployment. The auth
/// domain's cookie (set in the OIDC/SAML callback) always uses
/// this default because no route applies to a Sekisho-internal
/// callback path; per-route overrides apply at the handoff step
/// (see [`super::cookie_manager::CookieManager::create_cookie`]
/// and `proxy::handoff` for the lookup that picks the override).
pub const DEFAULT_SAME_SITE: SameSite = SameSite::Lax;

/// Signs and parses sekisho's cookies. One instance per process, holding the
/// signing key for the life of the daemon.
pub struct CookieManager {
    key: Key,
    cookie_name: String,
}

impl CookieManager {
    /// Build a manager from the stored cookie secret.
    ///
    /// The caller's plaintext is not retained — `cookie::Key` copies it — and
    /// the padding buffer used to reach the required 64 bytes is zeroized on
    /// drop. See [`crate::runtime`] for the matching guarantee that the
    /// caller's own copy dies before any task starts.
    pub fn new(secret: &[u8]) -> Self {
        // `cookie::Key::from` takes a byte slice and requires at
        // least 64 bytes. Normalize the caller's `secret` into a
        // fixed 64-byte local buffer: shorter inputs are zero-padded
        // in the tail, longer inputs are truncated.
        //
        // Wrap the temporary in `Zeroizing` so the local copy of the
        // padded secret is wiped after `Key::from` has copied it into
        // its own buffer (which we cannot reach in to zeroize because
        // `cookie::Key`'s internal storage isn't exposed).
        let mut key_bytes: zeroize::Zeroizing<[u8; 64]> = zeroize::Zeroizing::new([0u8; 64]);
        let len = secret.len().min(64);
        key_bytes[..len].copy_from_slice(&secret[..len]);
        let key = Key::from(&*key_bytes);
        Self {
            key,
            cookie_name: COOKIE_NAME.to_string(),
        }
    }

    /// Override the session cookie name from `global_config`. Builder-shaped
    /// so construction stays one expression at the single call site.
    pub fn with_name(mut self, name: String) -> Self {
        self.cookie_name = name;
        self
    }

    /// Extract session ID from the request cookies
    pub fn get_session_id(&self, cookie_header: Option<&str>) -> Option<Uuid> {
        let cookie_header = cookie_header?;
        let mut jar = cookie::CookieJar::new();
        for cookie_str in cookie_header.split(';') {
            if let Ok(c) = Cookie::parse_encoded(cookie_str.trim().to_string()) {
                jar.add_original(c);
            }
        }

        let signed_jar = jar.signed(&self.key);
        let cookie = signed_jar.get(&self.cookie_name)?;
        cookie.value().parse().ok()
    }

    /// Mint a signed Set-Cookie value carrying `session_id` with the
    /// supplied `SameSite`. The cookie is host-only (no `Domain`
    /// attribute): it binds to the exact host that set it. Cross-host
    /// SSO is implemented by the handoff flow, which mints a fresh
    /// cookie on each target host rather than sharing one across a
    /// parent domain. Callers pass a per-route `SameSite` override
    /// where one applies (notably the SAML-SP-friendly `None`); use
    /// [`DEFAULT_SAME_SITE`] otherwise (e.g. the auth domain's own
    /// callback cookie).
    pub fn create_cookie(&self, session_id: Uuid, same_site: SameSite) -> String {
        let builder = Cookie::build((self.cookie_name.clone(), session_id.to_string()))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(same_site);
        let mut jar = cookie::CookieJar::new();
        jar.signed_mut(&self.key).add(builder.build());

        jar.get(&self.cookie_name)
            .map(|c| c.to_string())
            .unwrap_or_default()
    }

    /// Emit a Set-Cookie value that deletes the session cookie.
    /// Cookie identity is name + domain + path (RFC 6265 §5.3), so a
    /// delete issued on the same host with the same cookie name and
    /// `Path=/`, and `Max-Age=0`, removes the entry. `SameSite` is
    /// not part of that identity and does not need to match the
    /// original Set-Cookie's `SameSite`.
    pub fn clear_cookie(&self) -> String {
        Cookie::build((self.cookie_name.clone(), ""))
            .path("/")
            .max_age(cookie::time::Duration::ZERO)
            .http_only(true)
            .secure(true)
            .same_site(DEFAULT_SAME_SITE)
            .build()
            .to_string()
    }

    /// Create the browser-binding cookie for one authentication flow.
    ///
    /// The state suffix gives parallel logins independent cookie identities;
    /// the value is a separate random nonce whose hash is stored with the
    /// pending flow. The cookie is intentionally unsigned: possession is
    /// proven by the constant-time hash check at the callback boundary.
    pub fn create_pre_auth_cookie(
        &self,
        state: &str,
        browser_nonce: &str,
        same_site: SameSite,
    ) -> String {
        Cookie::build((pre_auth_cookie_name(state), browser_nonce.to_owned()))
            .path(PRE_AUTH_COOKIE_PATH)
            .max_age(cookie::time::Duration::seconds(
                PRE_AUTH_COOKIE_MAX_AGE_SECONDS,
            ))
            .http_only(true)
            .secure(true)
            .same_site(same_site)
            .build()
            .to_string()
    }

    /// Read the nonce for exactly one flow without accepting a sibling
    /// flow's cookie.
    pub fn pre_auth_nonce(&self, cookie_header: Option<&str>, state: &str) -> Option<String> {
        let wanted = pre_auth_cookie_name(state);
        cookie_header?
            .split(';')
            .filter_map(|raw| Cookie::parse_encoded(raw.trim().to_owned()).ok())
            .find(|cookie| cookie.name() == wanted)
            .map(|cookie| cookie.value().to_owned())
    }

    /// Count outstanding per-flow cookies for the browser. Expired cookies
    /// are removed by the user agent, so only cookies carried on this request
    /// count toward the parallel-login cap.
    pub fn pre_auth_cookie_count(&self, cookie_header: Option<&str>) -> usize {
        cookie_header
            .into_iter()
            .flat_map(|header| header.split(';'))
            .filter_map(|raw| Cookie::parse_encoded(raw.trim().to_owned()).ok())
            .filter(|cookie| cookie.name().starts_with(PRE_AUTH_COOKIE_PREFIX))
            .count()
    }

    /// Delete only the cookie for the callback flow that completed.
    pub fn clear_pre_auth_cookie(&self, state: &str) -> String {
        Cookie::build((pre_auth_cookie_name(state), ""))
            .path(PRE_AUTH_COOKIE_PATH)
            .max_age(cookie::time::Duration::ZERO)
            .http_only(true)
            .secure(true)
            .build()
            .to_string()
    }
}

/// Derive the per-flow pre-auth cookie name from the OAuth/SAML `state`.
///
/// Keying on `state` is what makes concurrent logins from one browser
/// independent: a shared name would mean the second flow overwrites the first
/// one's nonce, and whichever callback arrived second would fail validation.
fn pre_auth_cookie_name(state: &str) -> String {
    format!("{PRE_AUTH_COOKIE_PREFIX}{state}")
}

#[cfg(test)]
mod pre_auth_tests {
    use super::*;

    #[test]
    fn pre_auth_cookie_contract_is_flow_scoped_and_counted() {
        let manager = CookieManager::new(&[0x41; 64]);
        let state = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let nonce = "independent-browser-nonce";

        let set_cookie = manager.create_pre_auth_cookie(state, nonce, SameSite::None);
        assert!(
            set_cookie
                .starts_with("__Secure-sekisho_pre_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        );
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("Secure"));
        assert!(set_cookie.contains("SameSite=None"));
        assert!(set_cookie.contains("Path=/.sekisho/"));
        assert!(set_cookie.contains("Max-Age=600"));
        let oidc_cookie = manager.create_pre_auth_cookie(state, nonce, SameSite::Lax);
        assert!(oidc_cookie.contains("SameSite=Lax"));

        let cookie_header = format!("unrelated=x; {}", set_cookie.split(';').next().unwrap());
        assert_eq!(manager.pre_auth_cookie_count(Some(&cookie_header)), 1);
        assert_eq!(
            manager
                .pre_auth_nonce(Some(&cookie_header), state)
                .as_deref(),
            Some(nonce)
        );

        let clear = manager.clear_pre_auth_cookie(state);
        assert!(
            clear.starts_with("__Secure-sekisho_pre_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        );
        assert!(clear.contains("Path=/.sekisho/"));
        assert!(clear.contains("Max-Age=0"));
    }
}
