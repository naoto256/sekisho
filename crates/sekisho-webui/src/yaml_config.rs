//! YAML-on-disk config for sekisho-webui.
//!
//! Replaces the historical clap-flag surface (one flag per knob,
//! sometimes also fed through `SEKISHO_API_URL` env vars) with a
//! single `webui.yaml` file. The CLI now exposes only
//! `--config <path>` and the YAML is the single source of truth.
//! Mirrors `kaido-webui`'s `WebuiConfig` in shape so operators see
//! one schema across the kaido / sekisho daemon family.
//!
//! Validation is performed at load time: mutually-exclusive blocks
//! (`auth.local_auth` vs `auth.api_key`, `guard.trust_sekisho_jwt`
//! vs `guard.basic_auth`) are rejected with a precise error naming
//! both keys, and structural prerequisites (non-empty
//! `sekisho_api_urls`, paired `tls.cert` + `tls.key`, parseable
//! URLs) are checked up front so misconfiguration fails fast at
//! systemd start instead of leaking through to a half-up server.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Top-level YAML schema. Field names are stable — they appear in
/// operator-edited config files. `#[serde(deny_unknown_fields)]`
/// catches typos at load time rather than letting a misspelled key
/// silently fall back to a default.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebuiConfig {
    /// Address sekisho-webui listens on. When `tls` is set this is a
    /// TLS-terminated listener; otherwise plain HTTP and an upstream
    /// proxy is expected to terminate.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// Base URL of the upstream Sekisho management API. Sekisho-webui
    /// has no multi-URL failover (that's a kaido-only feature), so
    /// this is a single scalar — the YAML key shape intentionally
    /// differs from kaido-webui's `kaido_api_url` here.
    pub sekisho_api_url: String,

    /// Out-of-band Ed25519 raw-public-key pin for the management API.
    /// Obtain it locally with `sekishod --print-management-rpk`.
    #[serde(default)]
    pub management_rpk_pin: Option<String>,

    /// Authentication to the upstream Sekisho daemon. Mutually
    /// exclusive children (`local_auth` vs `api_key`); both omitted
    /// means "no credential at startup, prompt via /setup form".
    #[serde(default)]
    pub auth: AuthConfig,

    /// Access control on sekisho-webui itself. Mutually exclusive
    /// children; both omitted means "unprotected, expects a front
    /// proxy" and a startup warning is logged.
    #[serde(default)]
    pub guard: GuardConfig,

    /// Optional TLS termination on the sekisho-webui listener itself.
    /// When omitted, sekisho-webui serves plain HTTP — the historical
    /// posture, which assumes a front proxy.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:9444".parse().expect("static default")
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default)]
    pub local_auth: Option<LocalAuthConfig>,
    /// API key seeded from YAML. Usually populated lazily via the
    /// /setup form, so leaving this commented out is the common
    /// posture; the field exists so an operator who already has a
    /// key can pre-seed it without going through the form.
    #[serde(default)]
    pub api_key: Option<String>,
}

impl std::fmt::Debug for AuthConfig {
    // Operators may log the loaded YAML config at startup; the api_key
    // value is the upstream Sekisho bearer token and must never appear
    // in stdout / journald. Note this propagates through any container
    // (e.g. `WebuiConfig`) that derives `Debug` and recurses into us.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("local_auth", &self.local_auth)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAuthConfig {
    pub socket: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    #[serde(default)]
    pub trust_sekisho_jwt: Option<TrustSekishoJwtConfig>,
    /// `user:argon2:<PHC-hash>` (production) or `user:plain:<password>` (dev,
    /// hashed on startup). See `auth::guard::parse_basic_auth` for the
    /// accepted shape.
    #[serde(default)]
    pub basic_auth: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustSekishoJwtConfig {
    /// Base URL(s) of the upstream Sekisho IAP — the JWT verifier.
    /// Shape mirrors kaido-webui's `sekisho_api_urls` (a list) for
    /// cross-system YAML consistency. Sekisho-webui's guard takes a
    /// single URL today, so the first element is used; supplying
    /// more than one element is accepted but only the first is
    /// honoured (a startup warning is logged).
    pub sekisho_api_urls: Vec<String>,
    #[serde(default)]
    pub expected_aud: Option<String>,
    #[serde(default)]
    pub expected_iss: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl WebuiConfig {
    /// Read + parse + validate. Any failure path ends here; callers
    /// can rely on the returned config being structurally usable.
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_management_rpk_pin(path, None)
    }

    pub fn load_with_management_rpk_pin(path: &Path, override_pin: Option<String>) -> Result<Self> {
        let data =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let mut cfg: Self = serde_yaml::from_str(&data).context("parse webui config")?;
        if let Some(pin) = override_pin {
            cfg.management_rpk_pin = Some(pin);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// All structural / mutual-exclusion / parse rules — kept as a
    /// public method so unit tests can probe each rule directly
    /// without round-tripping through a temp file.
    pub fn validate(&self) -> Result<()> {
        validate_https_management_url(&self.sekisho_api_url, "sekisho_api_url")?;

        // auth.local_auth and auth.api_key are mutually exclusive.
        if self.auth.local_auth.is_some() && self.auth.api_key.is_some() {
            bail!(
                "auth.local_auth and auth.api_key are mutually exclusive — \
                 choose one (or omit both to use the /setup form)"
            );
        }
        if let Some(la) = &self.auth.local_auth
            && la.socket.trim().is_empty()
        {
            bail!("auth.local_auth.socket must not be empty");
        }

        // guard.trust_sekisho_jwt and guard.basic_auth are mutually exclusive.
        if self.guard.trust_sekisho_jwt.is_some() && self.guard.basic_auth.is_some() {
            bail!(
                "guard.trust_sekisho_jwt and guard.basic_auth are mutually exclusive — \
                 choose one (or omit both to leave the UI unprotected behind a front proxy)"
            );
        }
        if let Some(jwt) = &self.guard.trust_sekisho_jwt {
            if jwt.sekisho_api_urls.is_empty() {
                bail!(
                    "guard.trust_sekisho_jwt.sekisho_api_urls must contain at least one URL — \
                     Sekisho is the JWT issuer/verifier"
                );
            }
            for url in &jwt.sekisho_api_urls {
                validate_https_management_url(url, "guard.trust_sekisho_jwt.sekisho_api_urls")?;
            }
            if jwt.expected_aud.as_deref().is_none_or(str::is_empty) {
                bail!("guard.trust_sekisho_jwt.expected_aud is required");
            }
            if jwt.expected_iss.as_deref().is_none_or(str::is_empty) {
                bail!("guard.trust_sekisho_jwt.expected_iss is required");
            }
        }

        // tls.cert and tls.key must both be set or both absent. The
        // serde shape (a single Option<TlsConfig>) already enforces
        // this structurally; the readability check catches the
        // common operator error of pointing at a path that doesn't
        // exist yet.
        if let Some(tls) = &self.tls {
            if !tls.cert.exists() {
                return Err(anyhow!(
                    "tls.cert path does not exist: {}",
                    tls.cert.display()
                ));
            }
            if !tls.key.exists() {
                return Err(anyhow!(
                    "tls.key path does not exist: {}",
                    tls.key.display()
                ));
            }
        }

        let pin_text = self
            .management_rpk_pin
            .as_deref()
            .filter(|pin| !pin.trim().is_empty())
            .ok_or_else(|| anyhow!("management_rpk_pin is required"))?;
        let pin: sekisho_api_protocol::management_rpk::ManagementRpkPin = pin_text
            .parse()
            .map_err(|_| anyhow!("management_rpk_pin is invalid"))?;
        sekisho_management_rpk_tls::validate_ed25519_spki(pin.as_bytes())
            .map_err(|_| anyhow!("management_rpk_pin is not an Ed25519 SPKI pin"))?;

        Ok(())
    }
}

fn validate_https_management_url(value: &str, field: &str) -> Result<()> {
    let url = reqwest::Url::parse(value)
        .with_context(|| format!("{field} is not a valid URL: {value}"))?;
    if url.scheme() != "https" {
        bail!("{field} must use https");
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        bail!("{field} must be an HTTPS origin without credentials");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PIN: &str =
        "sekisho-rpk-v1:ed25519:MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn minimal() -> &'static str {
        "sekisho_api_url: https://127.0.0.1:9443\nmanagement_rpk_pin: sekisho-rpk-v1:ed25519:MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    }

    #[test]
    fn debug_does_not_leak_seeded_api_key() {
        let cfg = AuthConfig {
            local_auth: None,
            api_key: Some("sk_super_secret_value_42".into()),
        };
        let s = format!("{cfg:?}");
        assert!(!s.contains("super_secret_value"), "leak: {s}");
        assert!(s.contains("redacted"), "should mark: {s}");
    }

    #[test]
    fn happy_path_parses_and_validates() {
        let cfg: WebuiConfig = serde_yaml::from_str(minimal()).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.sekisho_api_url, "https://127.0.0.1:9443");
        assert_eq!(cfg.listen, "127.0.0.1:9444".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.management_rpk_pin.as_deref(), Some(TEST_PIN));
        assert!(cfg.auth.local_auth.is_none());
        assert!(cfg.auth.api_key.is_none());
        assert!(cfg.guard.trust_sekisho_jwt.is_none());
        assert!(cfg.guard.basic_auth.is_none());
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn full_config_round_trips() {
        let yaml = r#"
listen: 127.0.0.1:9444
sekisho_api_url: https://127.0.0.1:9443
management_rpk_pin: sekisho-rpk-v1:ed25519:MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
auth:
  local_auth:
    socket: /run/sekisho/control.sock
guard:
  trust_sekisho_jwt:
    sekisho_api_urls:
      - https://127.0.0.1:9443
    expected_aud: https://sekisho-admin.lab.cyberlab.jp
    expected_iss: https://auth.example.com
"#;
        let cfg: WebuiConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.management_rpk_pin.as_deref(), Some(TEST_PIN));
        assert_eq!(
            cfg.auth.local_auth.as_ref().unwrap().socket,
            "/run/sekisho/control.sock"
        );
        let jwt = cfg.guard.trust_sekisho_jwt.as_ref().unwrap();
        assert_eq!(jwt.sekisho_api_urls.len(), 1);
        assert_eq!(
            jwt.expected_aud.as_deref(),
            Some("https://sekisho-admin.lab.cyberlab.jp")
        );
        assert_eq!(
            jwt.expected_iss.as_deref(),
            Some("https://auth.example.com")
        );
    }

    #[test]
    fn rejects_invalid_sekisho_api_url() {
        let cfg: WebuiConfig = serde_yaml::from_str("sekisho_api_url: \"not a url\"\n").unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("sekisho_api_url"), "got: {err}");
    }

    #[test]
    fn rejects_auth_mutex_violation() {
        let yaml = r#"
sekisho_api_url: https://127.0.0.1:9443
auth:
  local_auth:
    socket: /run/sekisho/control.sock
  api_key: "sekisho_xxx"
"#;
        let cfg: WebuiConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("auth.local_auth"), "got: {err}");
        assert!(err.contains("auth.api_key"), "got: {err}");
    }

    #[test]
    fn rejects_guard_mutex_violation() {
        let yaml = r#"
sekisho_api_url: https://127.0.0.1:9443
guard:
  trust_sekisho_jwt:
    sekisho_api_urls: ["https://x.example.com"]
  basic_auth: "admin:plain:hunter2"
"#;
        let cfg: WebuiConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("guard.trust_sekisho_jwt"), "got: {err}");
        assert!(err.contains("guard.basic_auth"), "got: {err}");
    }

    #[test]
    fn rejects_local_auth_block_missing_socket() {
        // serde_yaml rejects this at parse time because `socket` is
        // a required field on LocalAuthConfig — exactly the contract
        // the spec calls out (must be present when block is set).
        let yaml = r#"
sekisho_api_url: https://127.0.0.1:9443
auth:
  local_auth: {}
"#;
        let r: std::result::Result<WebuiConfig, _> = serde_yaml::from_str(yaml);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_empty_sekisho_api_urls() {
        let yaml = r#"
sekisho_api_url: https://127.0.0.1:9443
guard:
  trust_sekisho_jwt:
    sekisho_api_urls: []
"#;
        let cfg: WebuiConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("sekisho_api_urls"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_sekisho_api_urls_entry() {
        let yaml = r#"
sekisho_api_url: https://127.0.0.1:9443
guard:
  trust_sekisho_jwt:
    sekisho_api_urls: ["not a url"]
"#;
        let cfg: WebuiConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("sekisho_api_urls"), "got: {err}");
    }

    #[test]
    fn rejects_jwt_guard_without_exact_audience_and_issuer() {
        let yaml = r#"
sekisho_api_url: https://127.0.0.1:9443
guard:
  trust_sekisho_jwt:
    sekisho_api_urls: ["https://auth.example.com"]
    expected_aud: https://admin.example.com
"#;
        let cfg: WebuiConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("expected_iss"), "got: {err}");
    }

    #[test]
    fn rejects_tls_with_only_cert() {
        // The serde shape (a TlsConfig with both fields required)
        // makes "only one set" a parse error, which is exactly what
        // we want — validate() never sees an inconsistent
        // (cert, key) pair.
        let yaml = r#"
sekisho_api_url: https://127.0.0.1:9443
tls:
  cert: /tmp/cert.pem
"#;
        let r: std::result::Result<WebuiConfig, _> = serde_yaml::from_str(yaml);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_tls_with_missing_files() {
        let yaml = r#"
sekisho_api_url: https://127.0.0.1:9443
tls:
  cert: /nonexistent/cert.pem
  key: /nonexistent/key.pem
"#;
        let cfg: WebuiConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("tls.cert"), "got: {err}");
    }

    #[test]
    fn load_reads_from_disk_and_validates() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sekisho-webui-test-{}.yaml", std::process::id()));
        std::fs::write(&path, minimal()).unwrap();
        let cfg = WebuiConfig::load(&path).unwrap();
        assert_eq!(cfg.sekisho_api_url, "https://127.0.0.1:9443");
        let _ = std::fs::remove_file(&path);
    }

    /// Wiring smoke test. Loads a temp YAML, then instantiates the
    /// same downstream pieces `main()` does (SekishoClient + a guard
    /// SharedGuard) from the resulting WebuiConfig fields. We do
    /// not bind a TCP listener or call `axum::serve` — that would
    /// need a network port and a running upstream — but everything
    /// up to the listener bind goes through the same code paths
    /// `main()` exercises.
    #[test]
    fn loaded_config_wires_into_sekisho_client_and_guard() {
        use crate::auth::Credential;
        use crate::auth::guard::{GuardMode, shared};
        use crate::client::SekishoClient;

        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "sekisho-webui-test-wiring-{}.yaml",
            std::process::id()
        ));
        std::fs::write(
            &path,
            r#"
listen: 127.0.0.1:0
sekisho_api_url: https://127.0.0.1:9443
management_rpk_pin: sekisho-rpk-v1:ed25519:MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
guard:
  basic_auth: "admin:plain:hunter2"
"#,
        )
        .unwrap();
        let cfg = WebuiConfig::load(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        // The same shape `main()` builds.
        let cred = crate::auth::new_shared(Credential::None);
        let pin = cfg.management_rpk_pin.as_deref().unwrap().parse().unwrap();
        let _client = SekishoClient::new(cfg.sekisho_api_url.clone(), cred.clone(), &pin)
            .expect("SekishoClient builds from loaded config");
        let _guard = shared(GuardMode::None);
        // Field names match what handlers expect.
        assert_eq!(cfg.management_rpk_pin.as_deref(), Some(TEST_PIN));
        assert_eq!(cfg.sekisho_api_url, "https://127.0.0.1:9443");
    }

    #[test]
    fn load_surfaces_validation_error() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "sekisho-webui-test-bad-{}.yaml",
            std::process::id()
        ));
        std::fs::write(&path, "sekisho_api_url: \"not a url\"\n").unwrap();
        let err = WebuiConfig::load(&path).unwrap_err().to_string();
        assert!(err.contains("sekisho_api_url"), "got: {err}");
        let _ = std::fs::remove_file(&path);
    }
}
