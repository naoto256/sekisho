//! HTTP Basic authentication. Passwords are stored as Argon2id PHC hashes
//! (salted + memory-hard) rather than a fast unsalted digest so a leaked hash
//! is costly to brute-force.

use anyhow::{Context, Result, anyhow};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use base64::Engine;
use subtle::ConstantTimeEq;

use super::GuardMode;

/// Parse `user:argon2:<PHC>` (production) or `user:plain:<password>` (dev).
///
/// The `plain` form is convenient for local testing — it generates a fresh
/// Argon2id hash at startup — but operators should store only the PHC form in
/// production so the password never appears in CLI args, env vars, or ps
/// output.
pub fn parse_basic_auth(raw: &str) -> Result<GuardMode> {
    let (user, rest) = raw
        .split_once(':')
        .ok_or_else(|| anyhow!("expected user:scheme:value"))?;
    let (scheme, value) = rest
        .split_once(':')
        .ok_or_else(|| anyhow!("expected user:scheme:value"))?;
    let password_hash = match scheme {
        "argon2" => {
            // Validate it parses as a PHC hash so we fail at startup rather
            // than at first login.
            PasswordHash::new(value).map_err(|e| anyhow!("invalid argon2 PHC hash: {e}"))?;
            value.to_string()
        }
        "plain" => {
            // The plaintext password lives in `argv` (and therefore in
            // `/proc/{pid}/cmdline`) and in any shell history for as long
            // as the process runs. Fine for local dev, not for production;
            // prefer `user:argon2:<PHC-hash>`.
            tracing::warn!(
                user = user,
                "basic-auth scheme `plain` leaks the cleartext password via \
                 argv / /proc; use `user:argon2:<PHC-hash>` in production"
            );
            hash_password(value)?
        }
        other => {
            return Err(anyhow!(
                "unknown basic-auth scheme `{other}` (expected argon2 or plain)"
            ));
        }
    };
    Ok(GuardMode::Basic {
        user: user.to_string(),
        password_hash,
    })
}

/// Generate a fresh Argon2id PHC hash of `password` using default parameters.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2 hash failed: {e}"))?;
    Ok(hash.to_string())
}

pub(super) fn verify_basic(
    headers: &axum::http::HeaderMap,
    expected_user: &str,
    expected_password_hash: &str,
) -> Result<()> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("missing authorization header"))?;
    let b64 = raw
        .strip_prefix("Basic ")
        .ok_or_else(|| anyhow!("not a Basic credential"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("decode basic credential")?;
    let text = std::str::from_utf8(&decoded).context("basic credential not UTF-8")?;
    let (user, pass) = text
        .split_once(':')
        .ok_or_else(|| anyhow!("malformed basic credential"))?;

    let parsed = PasswordHash::new(expected_password_hash)
        .map_err(|e| anyhow!("stored password hash is invalid: {e}"))?;
    let pass_ok = Argon2::default()
        .verify_password(pass.as_bytes(), &parsed)
        .is_ok();

    // Username compare is still constant-time so we don't leak the username
    // length or bytes via timing. (Argon2 is already hard to time-attack on
    // the password side.)
    let user_ok: bool = user.as_bytes().ct_eq(expected_user.as_bytes()).into();
    if user_ok && pass_ok {
        Ok(())
    } else {
        Err(anyhow!("basic auth mismatch"))
    }
}

/// 401 response carrying a `WWW-Authenticate: Basic` challenge so the browser
/// reprompts.
pub(super) fn basic_challenge() -> Response {
    let mut resp = Response::new(Body::from("authentication required"));
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Basic realm="sekisho-webui""#),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn parse_basic_auth_plain_hashes_and_verifies() {
        let mode = parse_basic_auth("admin:plain:hunter2").unwrap();
        match mode {
            GuardMode::Basic {
                user,
                password_hash,
            } => {
                assert_eq!(user, "admin");
                // PHC format: starts with `$argon2id$` or similar.
                assert!(password_hash.starts_with("$argon2"));
                let parsed = PasswordHash::new(&password_hash).unwrap();
                assert!(
                    Argon2::default()
                        .verify_password(b"hunter2", &parsed)
                        .is_ok()
                );
                assert!(
                    Argon2::default()
                        .verify_password(b"wrong", &parsed)
                        .is_err()
                );
            }
            _ => panic!("wrong mode"),
        }
    }

    #[test]
    fn parse_basic_auth_accepts_argon2_phc() {
        let hash = hash_password("pw").unwrap();
        let raw = format!("admin:argon2:{hash}");
        let mode = parse_basic_auth(&raw).unwrap();
        match mode {
            GuardMode::Basic { password_hash, .. } => assert_eq!(password_hash, hash),
            _ => panic!(),
        }
    }

    #[test]
    fn parse_basic_auth_rejects_unknown_scheme_and_bad_phc() {
        assert!(parse_basic_auth("admin:bcrypt:xxx").is_err());
        assert!(parse_basic_auth("missing").is_err());
        // sha256 was the old format; reject so operators notice the break.
        assert!(parse_basic_auth("admin:sha256:abcd").is_err());
        assert!(parse_basic_auth("admin:argon2:not-a-valid-phc-hash").is_err());
    }

    #[test]
    fn verify_basic_accepts_matching() {
        let hash = hash_password("pw").unwrap();
        let creds = base64::engine::general_purpose::STANDARD.encode("admin:pw");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {creds}").parse().unwrap(),
        );
        assert!(verify_basic(&headers, "admin", &hash).is_ok());
    }

    #[test]
    fn verify_basic_rejects_mismatch() {
        let hash = hash_password("pw").unwrap();
        let creds = base64::engine::general_purpose::STANDARD.encode("admin:wrong");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {creds}").parse().unwrap(),
        );
        assert!(verify_basic(&headers, "admin", &hash).is_err());
    }
}
