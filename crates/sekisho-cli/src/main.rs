//! `sekisho-cli` — the JunOS-style interactive management shell.
//!
//! A REPL over the daemon's management REST API. It carries its own
//! compile-time knowledge of every resource and field ([`resources`]) rather
//! than discovering the schema at runtime: client and server ship together, so
//! a compiled-in table gives better completion and better forms than anything
//! derived from a schema document. The API-version handshake below keeps that
//! compiled knowledge honest while product-version skew remains diagnostic.
//!
//! ## Refusals happen before credentials move
//!
//! Startup order is deliberate. The RPK pin is parsed, then the URL is checked
//! for HTTPS, and only after both does anything authenticate. A management API
//! key must never be sent over a connection that was not the pinned TLS one,
//! and once bytes are on the wire noticing is too late. The `--healthz` probe
//! short-circuits ahead of authentication entirely, because the readiness
//! endpoint is unauthenticated and a health check should not need a credential
//! to answer.
//!
//! ## Two ways to authenticate
//!
//! An API key, or `--local-auth`, which proves local access through the
//! control socket instead. The daemon checks `SO_PEERCRED` and accepts only
//! the service user — not root — so the local path is a statement about which
//! account is running, not merely about being on the box.

mod api;
mod resources;
mod shell;
mod table;
mod timefmt;
mod version;

/// Compile-time product version used for diagnostics. Management compatibility
/// is gated separately by `sekisho_api_protocol::version::API_VERSION`.
pub(crate) const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

use clap::Parser;

#[derive(Parser)]
#[command(name = "sekisho-cli", about = "Interactive shell for Sekisho IAP")]
struct Cli {
    /// Management API URL. Must be HTTPS — the server always serves TLS.
    #[arg(default_value = "https://127.0.0.1:9443")]
    url: String,

    /// API key (if not provided, will prompt — unless --local-auth is used)
    #[arg(long, env = "SEKISHO_API_KEY")]
    api_key: Option<String>,

    /// Authenticate via local Unix socket challenge (no API key needed).
    /// Obtains a management token by proving local access through the control
    /// socket. Must run as the sekishod service user — the daemon checks
    /// `SO_PEERCRED` and rejects every other UID, including root. Use
    /// `sudo -u sekisho sekisho-cli --local-auth ...`. The management
    /// RPK pin is still required for the HTTPS challenge round-trip.
    #[arg(long)]
    local_auth: bool,

    /// Unix socket path for local auth challenge
    #[arg(long, default_value = "/run/sekisho/control.sock")]
    socket: String,

    /// Out-of-band management RPK pin printed by `sekishod --print-management-rpk`.
    #[arg(long, env = "SEKISHO_MANAGEMENT_RPK_PIN")]
    management_rpk_pin: String,

    /// One-shot readiness probe for k8s / Docker HEALTHCHECK: hit
    /// `/readyz` on the management API and exit 0 on HTTP 200, 1
    /// otherwise. Does not require auth (the probe endpoint is
    /// intentionally unauthenticated). Prints nothing on success;
    /// prints the failure reason to stderr on non-zero exit so
    /// HEALTHCHECK logs stay useful. Takes precedence over the
    /// interactive shell: when set, nothing else runs.
    #[arg(long)]
    healthz: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let management_rpk_pin = match cli.management_rpk_pin.parse() {
        Ok(pin) => pin,
        Err(_) => {
            eprintln!("error: invalid --management-rpk-pin");
            std::process::exit(2);
        }
    };
    if let Err(error) = api::validate_management_url(&cli.url) {
        eprintln!("error: {error}");
        std::process::exit(2);
    }

    // One-shot readiness probe. Handled *before* any auth / version
    // handshake: the point of the probe is that it works when auth
    // isn't set up yet (first boot) and when the version skew we'd
    // otherwise refuse is legitimate (e.g. mid-rollout). Exits the
    // process directly — k8s / Docker read the exit code, not stdout.
    if cli.healthz {
        std::process::exit(run_healthz(&cli.url, &management_rpk_pin).await);
    }

    /// `Ok(Some(_))` is a product-skew warning for the caller to print; `Err`
    /// is fatal.
    async fn verify_server_version(client: &api::ApiClient) -> Result<Option<String>, String> {
        // `/version` is deliberately unauthenticated so this check runs before
        // any credential prompt or local-auth exchange.
        let verdict = version::probe(client).await;
        version::startup_check(&verdict)
    }

    // Establish API compatibility before prompting for or exchanging
    // credentials.
    let version_client = match api::ApiClient::new(&cli.url, "", &management_rpk_pin) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };
    let version_warning = match verify_server_version(&version_client).await {
        Ok(warning) => warning,
        Err(msg) => {
            eprintln!("compatibility check failed: {msg}");
            std::process::exit(1);
        }
    };

    let api_key = if cli.local_auth {
        // Challenge-response via Unix socket
        eprint!("Authenticating via local socket {} ... ", cli.socket);
        match local_auth_challenge(&cli.url, &cli.socket, &management_rpk_pin).await {
            Ok(token) => {
                eprintln!("ok");
                token
            }
            Err(e) => {
                eprintln!("failed: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match cli.api_key {
            Some(key) => key,
            None => {
                let key = prompt_api_key("API key: ");
                if key.is_empty() {
                    eprintln!("error: API key required (use --local-auth for socket auth)");
                    std::process::exit(1);
                }
                key
            }
        }
    };

    let client = match api::ApiClient::new(&cli.url, &api_key, &management_rpk_pin) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };

    if !cli.local_auth {
        // Verify connection and the supplied credential.
        eprint!("Connecting to {} ... ", cli.url);
        match client.get("/health").await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("failed: {e}");
                std::process::exit(1);
            }
        }
        match client.get("/_internal/host").await {
            Ok(_) => eprintln!("ok"),
            Err(e) => {
                eprintln!("authentication failed: {e}");
                std::process::exit(1);
            }
        }
    }
    // Held until any connection/authentication status line is complete so the
    // warning does not land in the middle of it.
    if let Some(warning) = version_warning {
        eprintln!("warning: {warning}");
    }

    eprintln!();
    shell::run(client).await;
}

/// Perform local auth: get challenge from HTTPS, verify via Unix socket, get token.
async fn local_auth_challenge(
    api_url: &str,
    socket_path: &str,
    management_rpk_pin: &sekisho_api_protocol::management_rpk::ManagementRpkPin,
) -> Result<String, String> {
    // 1. Request challenge nonce from HTTPS API
    let http = api::http_client(management_rpk_pin, std::time::Duration::from_secs(30))?;

    let challenge_url = format!(
        "{}/.sekisho/api/v1/auth/challenge",
        api_url.trim_end_matches('/')
    );
    let resp: serde_json::Value = http
        .post(&challenge_url)
        .send()
        .await
        .map_err(|e| format!("challenge request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("challenge parse failed: {e}"))?;

    let nonce = resp
        .get("nonce")
        .and_then(|n| n.as_str())
        .ok_or("missing nonce in challenge response")?;

    // 2. Send nonce to Unix socket, receive token
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("socket connect failed: {e}{}", local_auth_uid_hint()))?;

    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(format!("{nonce}\n").as_bytes())
        .await
        .map_err(|e| format!("socket write failed: {e}"))?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("socket read failed: {e}"))?;

    let token = line.trim().to_string();
    // An empty reply means the daemon accepted the connection at the kernel
    // level (file mode / group) but rejected it via `SO_PEERCRED` because
    // our UID does not match the daemon's. The most common cause is running
    // the CLI as root; the fix is `sudo -u sekisho`, not more privilege.
    if token.is_empty() {
        return Err(format!(
            "challenge verification failed: empty response (likely UID mismatch — \
             the daemon only accepts its own service user){}",
            local_auth_uid_hint()
        ));
    }
    if token.starts_with("error") {
        return Err(format!("challenge verification failed: {token}"));
    }

    Ok(token)
}

/// Hint string appended to local-auth socket errors. Runtime UID is included
/// so operators see at a glance that they are running as the wrong user
/// (typically root) — the daemon rejects every UID except its own.
fn local_auth_uid_hint() -> String {
    #[cfg(unix)]
    {
        // SAFETY: `getuid` is a thread-safe libc call with no preconditions.
        let uid = unsafe { libc::getuid() };
        format!(
            "\nhint: running as uid={uid}; the sekishod control socket only accepts \
             its own service user. Try: sudo -u sekisho sekisho-cli --local-auth ..."
        )
    }
    #[cfg(not(unix))]
    {
        String::new()
    }
}

/// Hit the server's `/readyz` endpoint and return a Unix exit code
/// (0 = ready, 1 = not ready / unreachable). Deliberately short and
/// self-contained — not sharing the `ApiClient` machinery — because
/// HEALTHCHECK callers must not pay the cost of `/version` preflight
/// or API-key resolution. Any HTTP 200 is success; anything else
/// (including network errors) is a failure.
async fn run_healthz(
    api_url: &str,
    management_rpk_pin: &sekisho_api_protocol::management_rpk::ManagementRpkPin,
) -> i32 {
    let http = match api::http_client(management_rpk_pin, std::time::Duration::from_secs(5)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("healthz: HTTP client error: {e}");
            return 1;
        }
    };
    let url = format!(
        "{}/.sekisho/api/v1{}",
        api_url.trim_end_matches('/'),
        sekisho_api_protocol::api_paths::READYZ
    );
    match http.get(&url).send().await {
        Ok(resp) if resp.status() == reqwest::StatusCode::OK => 0,
        Ok(resp) => {
            eprintln!("healthz: not ready (HTTP {})", resp.status());
            1
        }
        Err(e) => {
            eprintln!("healthz: request failed: {e}");
            1
        }
    }
}

fn prompt_api_key(prompt: &str) -> String {
    eprint!("{prompt}");
    rpassword::read_password().unwrap_or_default()
}

#[cfg(all(test, unix))]
mod tests {
    use super::local_auth_uid_hint;

    /// The local-auth hint must (a) include the runtime UID so the operator
    /// can immediately see they are running as the wrong user, and (b)
    /// recommend `sudo -u sekisho` rather than plain `sudo`. If either of
    /// those drifts away (the help text and the runtime hint should agree),
    /// this test catches it.
    #[test]
    fn uid_hint_mentions_runtime_uid_and_sudo_u_sekisho() {
        let hint = local_auth_uid_hint();
        let uid = unsafe { libc::getuid() };
        assert!(
            hint.contains(&format!("uid={uid}")),
            "hint should include runtime uid: {hint}"
        );
        assert!(
            hint.contains("sudo -u sekisho"),
            "hint should recommend sudo -u sekisho: {hint}"
        );
        // We deliberately do NOT recommend bare `sudo` (which lands on
        // root and gets rejected by SO_PEERCRED).
        assert!(
            !hint.contains("sudo sekisho-cli"),
            "hint must not recommend bare sudo: {hint}"
        );
    }
}
