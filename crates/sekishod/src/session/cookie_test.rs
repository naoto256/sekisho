//! Cookie signing and rejection contract.
//!
//! The session cookie is a bearer credential, so these tests are less about
//! the happy round trip than about everything that must *not* be accepted: a
//! tampered value, a cookie signed with a different key, and every shape of
//! malformed or absent header. Any of those being read as a valid session
//! would be an authentication bypass, and none of them produces a visible
//! symptom otherwise.

#[cfg(test)]
mod tests {
    use crate::session::cookie_manager::CookieManager;
    use uuid::Uuid;

    fn make_manager() -> CookieManager {
        let secret = [0xABu8; 64];
        CookieManager::new(&secret)
    }

    #[test]
    fn roundtrip_session_id() {
        let mgr = make_manager();
        let id = Uuid::new_v4();
        let cookie_header = mgr.create_cookie(id, cookie::SameSite::Lax);
        let extracted = mgr.get_session_id(Some(&cookie_header));
        assert_eq!(extracted, Some(id));
    }

    #[test]
    fn tampered_cookie_rejected() {
        let mgr = make_manager();
        let id = Uuid::new_v4();
        let mut cookie_header = mgr.create_cookie(id, cookie::SameSite::Lax);
        // Flip a character in the signed value
        if let Some(pos) = cookie_header.find('=') {
            let bytes = unsafe { cookie_header.as_bytes_mut() };
            if pos + 5 < bytes.len() {
                bytes[pos + 5] ^= 0x20;
            }
        }
        let extracted = mgr.get_session_id(Some(&cookie_header));
        assert_eq!(extracted, None, "tampered cookie must be rejected");
    }

    #[test]
    fn different_key_cannot_read() {
        let mgr1 = CookieManager::new(&[0xAB; 64]);
        let mgr2 = CookieManager::new(&[0xCD; 64]);
        let id = Uuid::new_v4();
        let cookie = mgr1.create_cookie(id, cookie::SameSite::Lax);
        assert_eq!(mgr2.get_session_id(Some(&cookie)), None);
    }

    #[test]
    fn no_cookie_header_returns_none() {
        let mgr = make_manager();
        assert_eq!(mgr.get_session_id(None), None);
    }

    #[test]
    fn empty_cookie_header_returns_none() {
        let mgr = make_manager();
        assert_eq!(mgr.get_session_id(Some("")), None);
    }

    #[test]
    fn garbage_cookie_header_returns_none() {
        let mgr = make_manager();
        assert_eq!(mgr.get_session_id(Some("foo=bar; baz=qux")), None);
    }

    #[test]
    fn clear_cookie_has_max_age_zero() {
        let mgr = make_manager();
        let clear = mgr.clear_cookie();
        assert!(
            clear.contains("Max-Age=0"),
            "clear cookie must set Max-Age=0, got: {clear}"
        );
    }

    #[test]
    fn cookie_attributes() {
        let mgr = make_manager();
        let cookie = mgr.create_cookie(Uuid::new_v4(), cookie::SameSite::Lax);
        // RFC 6265bis: confirm the security-critical attributes the
        // session cookie must carry. cookie::Display does include
        // these on the wire — `HttpOnly`, `Secure`, `SameSite=Lax`,
        // `Path=/`. Lock the contract so a future refactor of
        // CookieManager that drops one is caught immediately.
        assert!(cookie.contains("_sekisho_session="));
        assert!(cookie.contains("HttpOnly"), "missing HttpOnly: {cookie}");
        assert!(cookie.contains("Secure"), "missing Secure: {cookie}");
        assert!(
            cookie.contains("SameSite=Lax"),
            "missing SameSite=Lax: {cookie}"
        );
        assert!(cookie.contains("Path=/"), "missing Path=/: {cookie}");
    }

    #[test]
    fn clear_cookie_carries_same_attributes_as_set() {
        // The deletion cookie must match the set-side attributes,
        // otherwise some browsers refuse the deletion as
        // attribute-mismatched (specifically when the original was
        // SameSite/Secure and the deletion is not).
        let mgr = make_manager();
        let cleared = mgr.clear_cookie();
        assert!(cleared.contains("_sekisho_session="));
        assert!(cleared.contains("HttpOnly"), "{cleared}");
        assert!(cleared.contains("Secure"), "{cleared}");
        assert!(cleared.contains("SameSite=Lax"), "{cleared}");
        assert!(cleared.contains("Path=/"), "{cleared}");
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
    }
}
