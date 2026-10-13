//! Strict Ed25519 JWT verification using Sekisho's public JWKS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;

use super::{IdentityClaims, JwtConstraints};

/// The daemon's verified signing keys, indexed by `kid`.
///
/// Only Ed25519 signing keys are ever stored — see [`Jwks::parse`].
#[derive(Clone, Debug)]
pub struct Jwks {
    keys: HashMap<String, [u8; 32]>,
}

/// The key set as held at runtime: shared, and swapped wholesale by the
/// refresh loop so a rotation is observed atomically rather than key by key.
pub type SharedJwks = Arc<RwLock<Jwks>>;

impl Jwks {
    /// Parse a JWKS document, rejecting the whole thing on anything
    /// unexpected.
    ///
    /// Strict rather than lenient on purpose. The usual JWKS parser skips keys
    /// it does not understand, which here would mean silently accepting a
    /// document where an algorithm was downgraded or an extra key injected,
    /// and carrying on with whatever remained. Since the only legitimate
    /// producer is a sekisho daemon that emits exactly one shape — `OKP` /
    /// `Ed25519` / `EdDSA` / `use: sig` — anything else means the document is
    /// not the one we think it is, and the right response is to keep the
    /// previously verified key set.
    ///
    /// A duplicate `kid` is an error for the same reason: it makes key
    /// selection depend on iteration order, which is exactly the ambiguity an
    /// attacker would want.
    pub(super) fn parse(value: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Document {
            keys: Vec<Key>,
        }
        #[derive(Deserialize)]
        struct Key {
            kty: String,
            crv: String,
            alg: String,
            #[serde(rename = "use")]
            use_: String,
            kid: String,
            x: String,
        }

        let document: Document = serde_json::from_slice(value).context("JWKS body not JSON")?;
        let mut keys = HashMap::with_capacity(document.keys.len());
        for key in document.keys {
            if key.kty != "OKP"
                || key.crv != "Ed25519"
                || key.alg != "EdDSA"
                || key.use_ != "sig"
                || key.kid.is_empty()
            {
                return Err(anyhow!("JWKS contains an unsupported key"));
            }
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(key.x)
                .context("JWKS contains an invalid public key")?;
            let public: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("JWKS contains an invalid Ed25519 public key"))?;
            if keys.insert(key.kid, public).is_some() {
                return Err(anyhow!("JWKS contains a duplicate kid"));
            }
        }
        if keys.is_empty() {
            return Err(anyhow!("JWKS contains no usable keys"));
        }
        Ok(Self { keys })
    }
}

/// Wrap a parsed key set for sharing with the refresh loop.
pub fn shared(keys: Jwks) -> SharedJwks {
    Arc::new(RwLock::new(keys))
}

pub(super) fn verify_local(
    headers: &axum::http::HeaderMap,
    keys: &Jwks,
    constraints: &JwtConstraints,
) -> Result<IdentityClaims> {
    let raw = headers
        .get("x-sekisho-jwt")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow!("no X-Sekisho-Jwt header"))?;
    let header = jsonwebtoken::decode_header(raw).context("decode JWT header")?;
    if header.alg != Algorithm::EdDSA {
        return Err(anyhow!("JWT algorithm is not EdDSA"));
    }
    let kid = header.kid.ok_or_else(|| anyhow!("JWT has no kid"))?;
    let public = keys
        .keys
        .get(&kid)
        .ok_or_else(|| anyhow!("JWT kid is not in the current JWKS"))?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    // As of jsonwebtoken 10 this list is consulted for five names — exp, sub,
    // iss, aud, nbf — and any other entry is ignored. `email`, `groups` and
    // `iat` are made mandatory by the `IdentityClaims` type instead.
    validation.required_spec_claims = ["exp", "sub", "iss", "aud", "nbf"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    validation.set_audience(&[constraints.expected_aud.as_str()]);
    validation.set_issuer(&[constraints.expected_iss.as_str()]);
    validation.validate_aud = true;
    validation.validate_nbf = true;

    let data =
        jsonwebtoken::decode::<IdentityClaims>(raw, &DecodingKey::from_ed_der(public), &validation)
            .context("JWT verification failed")?;
    Ok(data.claims)
}

pub async fn fetch_jwks(
    api_url: &str,
    management_rpk_pin: &sekisho_api_protocol::management_rpk::ManagementRpkPin,
) -> Result<Jwks> {
    let url = format!(
        "{}/.sekisho/api/v1/auth/jwks",
        api_url.trim_end_matches('/')
    );
    let response = crate::client::http_client(management_rpk_pin)?
        .get(url)
        .send()
        .await
        .context("fetch identity JWKS")?
        .error_for_status()
        .context("identity JWKS request rejected")?;
    let (_, bytes) =
        crate::client::read_bounded(response, crate::client::MAX_UPSTREAM_BODY).await?;
    Jwks::parse(&bytes)
}

pub fn spawn_refresh_loop(
    keys: SharedJwks,
    api_url: String,
    management_rpk_pin: sekisho_api_protocol::management_rpk::ManagementRpkPin,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            match fetch_jwks(&api_url, &management_rpk_pin).await {
                Ok(replacement) => {
                    *keys.write().await = replacement;
                    tracing::info!("refreshed public identity JWKS");
                }
                Err(error) => {
                    tracing::warn!(%error, "JWKS refresh failed; retaining previous keys");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    const PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL2MOtYQb2Z9wJrtkrL8tZ2H0LGgEqKnBN46MrVivE0V
-----END PRIVATE KEY-----
"#;

    fn key_set() -> Jwks {
        let x = "1_EqSxWHGu97Epc5QXKRABez7q3F2L21RPEHQq8LsPQ";
        Jwks::parse(
            serde_json::json!({"keys":[{
                "kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig",
                "kid":"current","x":x
            }]})
            .to_string()
            .as_bytes(),
        )
        .unwrap()
    }

    fn token(kid: &str, exp: i64, aud: &str, iss: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut header = jsonwebtoken::Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "sub":"alice@example.com",
                "email":"alice@example.com",
                "groups":["admins"],
                "exp":exp,
                "iat":now,
                "nbf":now,
                "aud":aud,
                "iss":iss
            }),
            &jsonwebtoken::EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap()
    }

    fn headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-sekisho-jwt", token.parse().unwrap());
        headers
    }

    fn identity_claims() -> serde_json::Value {
        let now = chrono::Utc::now().timestamp();
        serde_json::json!({
            "sub": "guard-subject-sentinel",
            "email": "guard-email-sentinel@example.com",
            "groups": ["guard-group-sentinel"],
            "exp": now + 300,
            "iat": now,
            "nbf": now,
            "aud": "https://admin.example.com",
            "iss": "https://auth.example.com"
        })
    }

    fn sign_identity_claims(claims: &serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::EdDSA);
        header.kid = Some("current".into());
        jsonwebtoken::encode(
            &header,
            claims,
            &jsonwebtoken::EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap()
    }

    fn identity_constraints() -> JwtConstraints {
        JwtConstraints {
            expected_aud: "https://admin.example.com".into(),
            expected_iss: "https://auth.example.com".into(),
        }
    }

    fn assert_missing_identity_claim_rejected(field: &str) {
        let mut claims = identity_claims();
        claims.as_object_mut().unwrap().remove(field);
        let signed = sign_identity_claims(&claims);
        assert!(
            verify_local(&headers(&signed), &key_set(), &identity_constraints()).is_err(),
            "missing {field} must be rejected"
        );
    }

    #[test]
    fn hardening_identity_jwt_requires_email() {
        assert_missing_identity_claim_rejected("email");
    }

    #[test]
    fn hardening_identity_jwt_requires_groups() {
        assert_missing_identity_claim_rejected("groups");
    }

    #[test]
    fn hardening_identity_jwt_requires_iat() {
        assert_missing_identity_claim_rejected("iat");
    }

    #[test]
    fn hardening_identity_jwt_rejects_null_and_wrong_claim_types() {
        for (field, wrong_type) in [
            ("email", serde_json::json!(42)),
            ("groups", serde_json::json!("not-an-array")),
            ("iat", serde_json::json!("not-an-integer")),
        ] {
            for value in [serde_json::Value::Null, wrong_type] {
                let mut claims = identity_claims();
                claims[field] = value;
                let signed = sign_identity_claims(&claims);
                assert!(
                    verify_local(&headers(&signed), &key_set(), &identity_constraints()).is_err(),
                    "invalid {field} must be rejected"
                );
            }
        }
    }

    #[test]
    fn hardening_identity_jwt_accepts_empty_email_and_groups() {
        let mut claims = identity_claims();
        claims["email"] = serde_json::json!("");
        claims["groups"] = serde_json::json!([]);
        claims["iat"] = serde_json::json!(chrono::Utc::now().timestamp() + 300);
        let signed = sign_identity_claims(&claims);
        let verified =
            verify_local(&headers(&signed), &key_set(), &identity_constraints()).unwrap();
        assert!(verified.email.is_empty());
        assert!(verified.groups.is_empty());
    }

    #[tokio::test]
    async fn hardening_identity_jwt_rejection_is_unauthorized_and_redacted() {
        if sekisho_test_support::run_in_child(
            "auth::guard::jwt::tests::hardening_identity_jwt_rejection_is_unauthorized_and_redacted",
        ) {
            return;
        }
        use axum::{Router, extract::Request, middleware::Next, routing::get};
        use std::{io::Write, sync::Mutex, time::Duration};

        struct LogWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for LogWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let log = Arc::new(Mutex::new(Vec::new()));
        let writer = log.clone();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::WARN)
                .without_time()
                .with_ansi(false)
                .with_writer(move || LogWriter(writer.clone()))
                .finish(),
        );
        let args = serde_yaml::from_str::<crate::yaml_config::WebuiConfig>(
            "sekisho_api_url: https://127.0.0.1:9443\n",
        )
        .unwrap();
        let pin =
            "sekisho-rpk-v1:ed25519:MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .parse()
                .unwrap();
        let cred = crate::auth::new_shared(crate::auth::Credential::None);
        let state = crate::AppState {
            client: crate::client::SekishoClient::new(
                args.sekisho_api_url.clone(),
                cred.clone(),
                &pin,
            )
            .unwrap(),
            args: Arc::new(args),
            cred,
            guard: super::super::shared(super::super::GuardMode::TrustSekishoJwt {
                keys: shared(key_set()),
                constraints: identity_constraints(),
            }),
            server_version: Arc::new(std::sync::RwLock::new(crate::ServerVersion::Match)),
            management_rpk_pin: Arc::new(pin),
        };
        let app = Router::new()
            .route("/", get(|| async { "accepted" }))
            .layer(axum::middleware::from_fn(
                move |request: Request, next: Next| {
                    sekisho_test_support::with_subscriber(
                        super::super::guard(axum::extract::State(state.clone()), request, next),
                        dispatch.clone(),
                    )
                },
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        for (field, value) in [
            ("email", None),
            ("groups", None),
            ("iat", None),
            ("email", Some(serde_json::Value::Null)),
            ("groups", Some(serde_json::Value::Null)),
            ("iat", Some(serde_json::Value::Null)),
            ("email", Some(serde_json::json!(42))),
            ("groups", Some(serde_json::json!("guard-group-sentinel"))),
            ("iat", Some(serde_json::json!("guard-iat-sentinel"))),
        ] {
            let mut claims = identity_claims();
            if let Some(value) = value {
                claims[field] = value;
            } else {
                claims.as_object_mut().unwrap().remove(field);
            }
            let signed = sign_identity_claims(&claims);
            let response = client
                .get(format!("http://{address}/"))
                .header("x-sekisho-jwt", &signed)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
            let body = response.text().await.unwrap();
            assert_eq!(body, "missing or invalid X-Sekisho-Jwt");
            let warnings = String::from_utf8(log.lock().unwrap().clone()).unwrap();
            assert!(warnings.contains("JWT guard rejected request"));
            for secret in [
                &signed,
                "guard-subject-sentinel",
                "guard-email-sentinel",
                "guard-group-sentinel",
                "guard-iat-sentinel",
            ] {
                assert!(!body.contains(secret));
                assert!(!warnings.contains(secret));
            }
        }
        assert_eq!(
            String::from_utf8(log.lock().unwrap().clone())
                .unwrap()
                .matches("JWT guard rejected request")
                .count(),
            9
        );
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn jwks_requires_supported_unique_eddsa_keys() {
        let public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let valid = serde_json::json!({
            "keys": [{
                "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                "kid": "current", "x": public
            }]
        });
        assert!(Jwks::parse(valid.to_string().as_bytes()).is_ok());

        let duplicate = serde_json::json!({
            "keys": [
                {"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"same","x":public},
                {"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"same","x":public}
            ]
        });
        assert!(Jwks::parse(duplicate.to_string().as_bytes()).is_err());
        assert!(Jwks::parse(br#"{"keys":[]}"#).is_err());
    }

    #[test]
    fn verifies_only_matching_kid_issuer_audience_and_lifetime() {
        let constraints = JwtConstraints {
            expected_aud: "https://admin.example.com".into(),
            expected_iss: "https://auth.example.com".into(),
        };
        let now = chrono::Utc::now().timestamp();
        let valid = token(
            "current",
            now + 300,
            &constraints.expected_aud,
            &constraints.expected_iss,
        );
        assert!(verify_local(&headers(&valid), &key_set(), &constraints).is_ok());

        let unknown = token(
            "unknown",
            now + 300,
            &constraints.expected_aud,
            &constraints.expected_iss,
        );
        assert!(verify_local(&headers(&unknown), &key_set(), &constraints).is_err());
        let expired = token(
            "current",
            now - 300,
            &constraints.expected_aud,
            &constraints.expected_iss,
        );
        assert!(verify_local(&headers(&expired), &key_set(), &constraints).is_err());
        let wrong_aud = token(
            "current",
            now + 300,
            "https://other.example.com",
            &constraints.expected_iss,
        );
        assert!(verify_local(&headers(&wrong_aud), &key_set(), &constraints).is_err());
    }
}
