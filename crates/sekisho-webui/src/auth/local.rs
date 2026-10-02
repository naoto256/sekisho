//! Local-auth client: challenge via HTTPS, respond via Unix socket, refresh.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration, Utc};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::{Credential, SharedCredential};

/// Hard-coded on the server side; rebuild this before it elapses. See
/// `sekishod::api::local_auth::SESSION_TTL_SECS`.
const TOKEN_LIFETIME_MIN: i64 = 60;
/// Refresh a little before the token expires to avoid in-flight races.
const REFRESH_LEAD_MIN: i64 = 5;

/// Execute a single challenge/response round and produce a fresh token.
pub async fn authenticate(
    api_url: &str,
    socket_path: &str,
    management_rpk_pin: &sekisho_api_protocol::management_rpk::ManagementRpkPin,
) -> Result<(String, DateTime<Utc>)> {
    let challenge_url = format!(
        "{}/.sekisho/api/v1/auth/challenge",
        api_url.trim_end_matches('/')
    );

    let http = crate::client::http_client(management_rpk_pin)?;

    let resp = http
        .post(&challenge_url)
        .send()
        .await
        .context("challenge request failed")?
        .error_for_status()
        .context("challenge rejected")?;
    let (_, bytes) = crate::client::read_bounded(resp, crate::client::MAX_UPSTREAM_BODY).await?;
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).context("challenge body not JSON")?;

    let nonce = body
        .get("nonce")
        .and_then(|n| n.as_str())
        .ok_or_else(|| anyhow!("challenge response missing `nonce`"))?;

    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connect control socket {socket_path}"))?;

    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(format!("{nonce}\n").as_bytes())
        .await
        .context("write nonce to control socket")?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("read token from control socket")?;

    let token = line.trim().to_string();
    if token.is_empty() || token.starts_with("error") {
        return Err(anyhow!("control socket rejected challenge: {token}"));
    }

    let expires_at = Utc::now() + Duration::minutes(TOKEN_LIFETIME_MIN - REFRESH_LEAD_MIN);
    Ok((token, expires_at))
}

/// Spawn a background task that keeps a `Credential::LocalSession` fresh by
/// re-running the challenge before the server-side TTL elapses. The task
/// runs for the lifetime of the process; transient failures are logged and
/// retried with short backoff so a brief socket outage doesn't knock us out.
pub fn spawn_refresh_loop(
    api_url: String,
    socket_path: String,
    cred: SharedCredential,
    management_rpk_pin: sekisho_api_protocol::management_rpk::ManagementRpkPin,
) {
    tokio::spawn(async move {
        loop {
            let wait = match cred.read().await.clone() {
                Credential::LocalSession { expires_at, .. } => {
                    let now = Utc::now();
                    if expires_at > now {
                        (expires_at - now)
                            .to_std()
                            .unwrap_or(std::time::Duration::from_secs(30))
                    } else {
                        std::time::Duration::from_secs(0)
                    }
                }
                _ => std::time::Duration::from_secs(30),
            };
            tokio::time::sleep(wait).await;

            match authenticate(&api_url, &socket_path, &management_rpk_pin).await {
                Ok((token, expires_at)) => {
                    tracing::info!(%expires_at, "refreshed local-auth session token");
                    *cred.write().await = Credential::LocalSession { token, expires_at };
                }
                Err(e) => {
                    tracing::error!(error = %e, "local-auth refresh failed; retrying in 30s");
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                }
            }
        }
    });
}
