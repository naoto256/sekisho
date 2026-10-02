//! Thin reqwest wrapper around the Sekisho management API.

use anyhow::{Context, Result, anyhow};
use sekisho_api_protocol::ResourceClient;
use sekisho_api_protocol::management_rpk::ManagementRpkPin;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::auth::SharedCredential;

/// Build a `reqwest::Client` configured for talking to the Sekisho
/// management API. Every management call uses the same out-of-band pin.
pub(crate) fn http_client(pin: &ManagementRpkPin) -> anyhow::Result<reqwest::Client> {
    use anyhow::Context;
    let tls =
        sekisho_management_rpk_tls::client_config(pin).context("invalid management RPK pin")?;
    management_client_builder(reqwest::Client::builder())
        .tls_backend_preconfigured(tls)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build HTTP client")
}

fn management_client_builder(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder.redirect(reqwest::redirect::Policy::none())
}

/// Upper bound on any upstream response body we buffer into memory.
/// The Sekisho management API deals in small JSON documents (config, lists of
/// a few hundred routes at most); 1 MiB is comfortably above realistic sizes
/// while still small enough that a runaway / hostile upstream can't OOM the
/// web process.
pub(crate) const MAX_UPSTREAM_BODY: usize = 1 << 20;

/// Read an upstream response body with an enforced cap. Uses chunked reads so
/// a streamed response that grows past the limit is aborted mid-flight rather
/// than fully buffered before we notice. When `Content-Length` is advertised
/// and already over the cap we fail before reading any body at all.
pub(crate) async fn read_bounded(
    resp: reqwest::Response,
    cap: usize,
) -> Result<(reqwest::StatusCode, Vec<u8>)> {
    let status = resp.status();
    if let Some(len) = resp.content_length()
        && len as usize > cap
    {
        return Err(anyhow!("upstream Content-Length {len} exceeds cap {cap}"));
    }
    let mut resp = resp;
    let mut buf = Vec::with_capacity(1024);
    while let Some(chunk) = resp.chunk().await.context("read upstream chunk")? {
        if buf.len() + chunk.len() > cap {
            return Err(anyhow!("upstream body exceeded cap of {cap} bytes"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok((status, buf))
}

/// Convenience: cap the body then decode as UTF-8 text.
pub(crate) async fn read_bounded_text(
    resp: reqwest::Response,
) -> Result<(reqwest::StatusCode, String)> {
    let (status, bytes) = read_bounded(resp, MAX_UPSTREAM_BODY).await?;
    let text = String::from_utf8(bytes).context("upstream body not valid UTF-8")?;
    Ok((status, text))
}

#[derive(Clone)]
/// The BFF's client for the daemon's management API.
///
/// Holds the credential behind a shared lock rather than a copy, so a key
/// installed at `/setup` takes effect on the next request without rebuilding
/// the client — and so a revoked one stops working just as promptly.
///
/// `base_url` is the operator-configured origin; the `/.sekisho/api/v1` prefix
/// is added per call by [`Self::url`], which keeps handler call sites reading
/// as bare resource paths.
pub struct SekishoClient {
    http: reqwest::Client,
    base_url: String,
    cred: SharedCredential,
}

impl SekishoClient {
    /// Build a client pinned to the daemon's management RPK.
    ///
    /// Constructing this is the only way to reach the daemon, so there is no
    /// path in the web UI that talks to it over an unpinned connection.
    pub fn new(
        base_url: impl Into<String>,
        cred: SharedCredential,
        pin: &ManagementRpkPin,
    ) -> Result<Self> {
        let http = http_client(pin)?;
        Ok(Self {
            http,
            base_url: base_url.into(),
            cred,
        })
    }

    /// Snapshot the current credential. `None` means setup has not happened
    /// yet, which every caller turns into an error rather than an
    /// unauthenticated request.
    async fn bearer(&self) -> Option<String> {
        self.cred.read().await.bearer().map(|s| s.to_string())
    }

    /// Join the configured origin with the API prefix and a resource path.
    fn url(&self, path: &str) -> String {
        format!(
            "{}/.sekisho/api/v1{}",
            self.base_url.trim_end_matches('/'),
            path
        )
    }

    /// GET and deserialize, with the response body read under
    /// [`MAX_UPSTREAM_BODY`].
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let bearer = self
            .bearer()
            .await
            .ok_or_else(|| anyhow!("no credential configured"))?;
        let resp = self
            .http
            .get(self.url(path))
            .bearer_auth(&bearer)
            .send()
            .await
            .context("GET request failed")?;
        let (status, text) = read_bounded_text(resp).await?;
        if !status.is_success() {
            return Err(anyhow!("GET {path} -> {status}: {text}"));
        }
        serde_json::from_str(&text).with_context(|| format!("decode response from {path}: {text}"))
    }

    pub async fn post_json<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        self.send_with_body(reqwest::Method::POST, path, body).await
    }

    pub async fn patch_json<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        self.send_with_body(reqwest::Method::PATCH, path, body)
            .await
    }

    pub async fn delete(&self, path: &str) -> Result<()> {
        let bearer = self
            .bearer()
            .await
            .ok_or_else(|| anyhow!("no credential configured"))?;
        let resp = self
            .http
            .delete(self.url(path))
            .bearer_auth(&bearer)
            .send()
            .await
            .context("DELETE failed")?;
        let (status, text) = read_bounded_text(resp).await?;
        if !status.is_success() {
            return Err(anyhow!("DELETE {path} -> {status}: {text}"));
        }
        Ok(())
    }

    async fn send_with_body<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let bearer = self
            .bearer()
            .await
            .ok_or_else(|| anyhow!("no credential configured"))?;
        let resp = self
            .http
            .request(method, self.url(path))
            .bearer_auth(&bearer)
            .json(body)
            .send()
            .await
            .context("request failed")?;
        let (status, text) = read_bounded_text(resp).await?;
        if !status.is_success() {
            return Err(anyhow!("{path} -> {status}: {text}"));
        }
        serde_json::from_str(&text).with_context(|| format!("decode response from {path}: {text}"))
    }

    /// Quick probe — used by the setup handler to verify the entered API key
    /// before we accept it.
    pub async fn probe(&self) -> Result<()> {
        let _: serde_json::Value = self
            .get_json(sekisho_api_protocol::api_paths::CONFIG)
            .await?;
        Ok(())
    }

    /// Fetch `/version` without sending Authorization. Used at startup
    /// to gate a version-lock check; the endpoint is explicitly public
    /// server-side so that operators can diagnose a mismatched pair
    /// without first fighting through auth errors.
    pub async fn get_unauthenticated_version(&self) -> Result<String> {
        let resp = self
            .http
            .get(self.url("/version"))
            .send()
            .await
            .context("GET /version failed")?;
        let (status, text) = read_bounded_text(resp).await?;
        if !status.is_success() {
            return Err(anyhow!("GET /version -> {status}: {text}"));
        }
        let v: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("decode /version: {text}"))?;
        v.get("version")
            .and_then(|x| x.as_str())
            .map(String::from)
            .ok_or_else(|| anyhow!("/version response missing `version` field: {text}"))
    }

    /// Fetch a complete list resource. Paginated Sekisho responses are
    /// followed until `has_more` is false; bare arrays and `{items}`-only
    /// responses remain terminal compatibility shapes.
    pub async fn get_list(&self, path: &str) -> Result<Vec<serde_json::Value>> {
        let mut request_path = path.to_string();
        let mut expected_offset = 0_i64;
        let mut all = Vec::new();
        loop {
            let value: serde_json::Value = self.get_json(&request_path).await?;
            let page = sekisho_api_protocol::parse_list_page(value, expected_offset)
                .map_err(anyhow::Error::msg)?;
            all.extend(page.items);
            let Some(next) = page.next else {
                return Ok(all);
            };
            expected_offset = next.offset;
            request_path = sekisho_api_protocol::list_page_path(path, next);
        }
    }
}

/// Lets the shared `sekisho_api_protocol::ensure_cert_before_enable` call
/// into `SekishoClient`. The server error-type (`anyhow::Error`) is
/// mapped to `String` here so the shared code doesn't have to care
/// which error family each client uses.
impl ResourceClient for SekishoClient {
    async fn get_route(&self, id: &str) -> Result<Value, String> {
        self.get_json(&format!("/routes/{id}"))
            .await
            .map_err(|e| e.to_string())
    }

    async fn list_certs(&self) -> Result<Vec<Value>, String> {
        self.get_list(sekisho_api_protocol::api_paths::CERTS)
            .await
            .map_err(|e| e.to_string())
    }

    async fn issue_cert(&self, domain: &str) -> Result<Value, String> {
        let body = serde_json::json!({ "domain": domain });
        let v = self
            .post_json::<Value>(sekisho_api_protocol::api_paths::CERTS, &body)
            .await
            .map_err(|e| e.to_string())?;

        // Every node responds with a durable queue row (HTTP 202).
        if let Some(queue_id) = v.get("queue_id").and_then(|q| q.as_str()) {
            return self.poll_acme_queue(queue_id, domain).await;
        }
        Err("ACME issuance response did not contain queue_id".into())
    }
}

impl SekishoClient {
    /// Poll the ACME queue until the leader finishes the order.
    ///
    /// The webui runs this inside a request handler that already has
    /// a client-side timeout, so a deliberately modest in-function
    /// cap (120 s) is all we need — and it keeps a stuck leader from
    /// parking an HTMX request forever. Polling cadence (2 s) matches
    /// the CLI.
    async fn poll_acme_queue(&self, queue_id: &str, domain: &str) -> Result<Value, String> {
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
        const POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

        let path = format!(
            "{}/{}",
            sekisho_api_protocol::api_paths::CERTS_QUEUE,
            queue_id
        );
        let deadline = std::time::Instant::now() + POLL_TIMEOUT;
        loop {
            let row: Value = self.get_json(&path).await.map_err(|e| e.to_string())?;
            match row.get("status").and_then(|s| s.as_str()).unwrap_or("") {
                "completed" => return Ok(row),
                "failed" => {
                    let msg = row
                        .get("error_msg")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown error");
                    return Err(format!("ACME issuance failed on leader: {msg}"));
                }
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "ACME issuance for {domain} did not complete within {:?}",
                    POLL_TIMEOUT
                ));
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone, Copy)]
    enum RedirectTarget {
        Http,
        OtherHttps,
        SameOrigin,
    }

    async fn assert_management_redirect_not_followed(target: RedirectTarget) {
        let source = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source_address = source.local_addr().unwrap();
        let target_listener = match target {
            RedirectTarget::SameOrigin => None,
            RedirectTarget::Http | RedirectTarget::OtherHttps => {
                Some(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap())
            }
        };
        let location = match (&target, &target_listener) {
            (RedirectTarget::Http, Some(listener)) => {
                format!("http://{}/capture", listener.local_addr().unwrap())
            }
            (RedirectTarget::OtherHttps, Some(listener)) => {
                format!("https://{}/capture", listener.local_addr().unwrap())
            }
            (RedirectTarget::SameOrigin, None) => {
                format!("http://{source_address}/redirected")
            }
            _ => unreachable!(),
        };
        let target_task = target_listener.map(|listener| {
            tokio::spawn(async move {
                tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
                    .await
                    .is_ok()
            })
        });
        let source_task = tokio::spawn(async move {
            let (mut stream, _) = source.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..read]);
                if read == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            let same_origin_followed =
                tokio::time::timeout(std::time::Duration::from_millis(300), source.accept())
                    .await
                    .is_ok();
            (String::from_utf8(request).unwrap(), same_origin_followed)
        });

        let client = management_client_builder(reqwest::Client::builder())
            .build()
            .unwrap();
        let response = client
            .get(format!("http://{source_address}/start"))
            .bearer_auth("redirect-secret")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        let (request, same_origin_followed) = source_task.await.unwrap();
        assert!(request.contains("authorization: Bearer redirect-secret"));
        assert!(!same_origin_followed, "followed same-origin redirect");
        if let Some(target_task) = target_task {
            assert!(!target_task.await.unwrap(), "contacted redirect target");
        }
    }

    #[tokio::test]
    async fn management_client_does_not_follow_redirect_to_http() {
        assert_management_redirect_not_followed(RedirectTarget::Http).await;
    }

    #[tokio::test]
    async fn management_client_does_not_follow_redirect_to_other_https_origin() {
        assert_management_redirect_not_followed(RedirectTarget::OtherHttps).await;
    }

    #[tokio::test]
    async fn management_client_does_not_follow_same_origin_redirect() {
        assert_management_redirect_not_followed(RedirectTarget::SameOrigin).await;
    }
}
