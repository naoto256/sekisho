//! HTTP client for the management API.
//!
//! Thin on purpose: response shapes stay `serde_json::Value` because the shell
//! renders them through its own compiled-in field table, and deserializing
//! into typed structs here would mean a second copy of the server's model to
//! keep in step.
//!
//! Two properties are enforced at construction rather than per request.
//! [`validate_management_url`] rejects anything that is not HTTPS before a
//! client exists, so there is no code path that can send the API key in
//! cleartext. [`http_client`] pins the management RPK, so the connection is
//! authenticated against the operator's out-of-band pin rather than against a
//! PKI the daemon does not have.
//!
//! Every request is bounded by a connect and total timeout: the shell is
//! interactive, and a stalled server must produce an error the operator can
//! act on rather than a hang.

use reqwest::Client;
use sekisho_api_protocol::ResourceClient;
use sekisho_api_protocol::management_rpk::ManagementRpkPin;
use serde_json::Value;

/// A configured, pinned client for one daemon.
///
/// `base_url` already carries the `/.sekisho/api/v1` prefix so every call site
/// passes a bare resource path — which is also why [`Self::server_url`] has to
/// strip it back off to show the operator what they connected to.
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
    api_key: String,
}

impl ApiClient {
    pub fn new(base_url: &str, api_key: &str, pin: &ManagementRpkPin) -> Result<Self, String> {
        validate_management_url(base_url)?;
        // Symmetric with sekisho-webui's upstream client: bound connect + total
        // request time so a stalled or slow-loris server can't hang the
        // interactive shell indefinitely.
        let client = http_client(pin, std::time::Duration::from_secs(30))?;
        Ok(Self {
            client,
            base_url: format!("{}/.sekisho/api/v1", base_url.trim_end_matches('/')),
            api_key: api_key.to_string(),
        })
    }

    /// The sekisho daemon's base URL (without the `/.sekisho/api/v1`
    /// prefix). Used by `show version` to render the connected daemon's
    /// origin alongside its reported version.
    pub fn server_url(&self) -> &str {
        // `base_url` always ends with `/.sekisho/api/v1`; strip that to
        // recover what the operator passed on the command line.
        self.base_url
            .strip_suffix("/.sekisho/api/v1")
            .unwrap_or(&self.base_url)
    }

    pub async fn get(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.handle(resp).await
    }

    /// GET a public endpoint without attaching the management credential.
    pub(crate) async fn get_unauthenticated(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.handle(resp).await
    }

    /// Fetch every page of a management-API collection.
    pub async fn get_list(&self, path: &str) -> Result<Vec<Value>, String> {
        let mut request_path = path.to_string();
        let mut expected_offset = 0_i64;
        let mut all = Vec::new();
        loop {
            let value = self.get(&request_path).await?;
            let page = sekisho_api_protocol::parse_list_page(value, expected_offset)?;
            all.extend(page.items);
            let Some(next) = page.next else {
                return Ok(all);
            };
            expected_offset = next.offset;
            request_path = sekisho_api_protocol::list_page_path(path, next);
        }
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.handle(resp).await
    }

    pub async fn patch(&self, path: &str, body: &Value) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .patch(&url)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.handle(resp).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .delete(&url)
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().as_u16() == 204 {
            return Ok(Value::String("deleted".into()));
        }
        self.handle(resp).await
    }

    async fn handle(&self, resp: reqwest::Response) -> Result<Value, String> {
        let status = resp.status();
        let body = resp.text().await.map_err(|e| e.to_string())?;
        if status.is_success() {
            serde_json::from_str(&body).map_err(|_| body)
        } else {
            // Extract message from {"error": {"code": "...", "message": "..."}} or {"error": "..."}
            let msg = serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|v| {
                    let err = v.get("error")?;
                    if let Some(obj) = err.as_object() {
                        obj.get("message")
                            .and_then(|m| m.as_str())
                            .map(String::from)
                    } else {
                        err.as_str().map(String::from)
                    }
                })
                .unwrap_or(body);
            Err(format!("HTTP {status}: {msg}"))
        }
    }
}

/// Require an HTTPS management URL.
///
/// Called both from [`ApiClient::new`] and from startup before anything else
/// runs, so a plain-HTTP URL is refused before a credential is read, let alone
/// sent.
pub(crate) fn validate_management_url(base_url: &str) -> Result<(), String> {
    let url =
        reqwest::Url::parse(base_url).map_err(|_| "management API URL is invalid".to_string())?;
    if url.scheme() != "https" {
        return Err("management API URL must use https".to_string());
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err("management API URL must be an HTTPS origin without credentials".to_string());
    }
    Ok(())
}

/// Build a reqwest client that trusts exactly one key: the management RPK the
/// operator passed in.
///
/// Shared with the local-auth challenge round trip, so both paths get the same
/// pinning and the same timeout rather than one of them quietly using defaults.
pub(crate) fn http_client(
    pin: &ManagementRpkPin,
    timeout: std::time::Duration,
) -> Result<Client, String> {
    let tls = sekisho_management_rpk_tls::client_config(pin)
        .map_err(|_| "invalid management RPK pin".to_string())?;
    management_client_builder(Client::builder())
        .tls_backend_preconfigured(tls)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(timeout)
        .build()
        .map_err(|error| format!("build pinned management client: {error}"))
}

fn management_client_builder(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder.redirect(reqwest::redirect::Policy::none())
}

/// Let the shared `sekisho_api_protocol::ensure_cert_before_enable` call us
/// through the trait rather than binding it to `ApiClient` directly.
/// The server's list endpoint wraps items in `{items: [...]}`; unwrap
/// here so the shared code sees a plain `Vec`.
impl ResourceClient for ApiClient {
    async fn get_route(&self, id: &str) -> Result<Value, String> {
        self.get(&format!("/routes/{id}")).await
    }

    async fn list_certs(&self) -> Result<Vec<Value>, String> {
        self.get_list(sekisho_api_protocol::api_paths::CERTS).await
    }

    async fn issue_cert(&self, domain: &str) -> Result<Value, String> {
        eprintln!("enabling route: queueing ACME certificate for {domain}...");
        let body = serde_json::json!({ "domain": domain });
        let v = self
            .post(sekisho_api_protocol::api_paths::CERTS, &body)
            .await?;

        // Every node returns the durable queue row with HTTP 202.
        if let Some(queue_id) = v.get("queue_id").and_then(|q| q.as_str()) {
            eprintln!("queued, waiting for leader...");
            return self.poll_queue(queue_id, domain).await;
        }
        Err("ACME issuance response did not contain queue_id".into())
    }
}

impl ApiClient {
    /// Poll `GET /certs/queue/{id}` until the row is `completed` or
    /// `failed`. The leader's tick interval is 5 s; we poll at 2 s so
    /// the user-facing delay is dominated by ACME itself, not the
    /// polling cadence.
    ///
    /// `POLL_TIMEOUT` is sized above a worst-case ACME order
    /// (authorization + challenge validation + finalize + cert
    /// retrieval, each with its own waits — typically 30–60 s,
    /// occasionally 90 s) plus the tick-pickup delay. 120 s is
    /// generous but not infinite; a caller hitting the ceiling is
    /// probably looking at a stuck leader, and a timeout with a
    /// hint is more useful than a CLI that spins forever.
    async fn poll_queue(&self, queue_id: &str, domain: &str) -> Result<Value, String> {
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
        const POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

        let path = format!(
            "{}/{}",
            sekisho_api_protocol::api_paths::CERTS_QUEUE,
            queue_id
        );
        let deadline = std::time::Instant::now() + POLL_TIMEOUT;
        loop {
            let row = self.get(&path).await?;
            let status = row.get("status").and_then(|s| s.as_str()).unwrap_or("");
            match status {
                "completed" => {
                    eprintln!("certificate for {domain} issued");
                    return Ok(row);
                }
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
                    "ACME issuance for {domain} still {status:?} after {:?}; \
                     check leader health (`show acme leader_election`)",
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
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone, Copy)]
    enum RedirectTarget {
        Http,
        OtherHttps,
        SameOrigin,
    }

    struct ExpectedResponse {
        target: String,
        status: u16,
        body: String,
    }

    fn test_client(base_url: &str) -> ApiClient {
        ApiClient {
            client: reqwest::Client::new(),
            base_url: format!("{}/.sekisho/api/v1", base_url.trim_end_matches('/')),
            api_key: "test-key".to_owned(),
        }
    }

    async fn spawn_server(
        responses: Vec<ExpectedResponse>,
    ) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut responses = VecDeque::from(responses);
            while let Some(expected) = responses.pop_front() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..read]);
                    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(bytes).unwrap();
                let first_line = request.lines().next().unwrap();
                let target = first_line.split_ascii_whitespace().nth(1).unwrap();
                captured.lock().unwrap().push(target.to_string());
                assert_eq!(target, expected.target);
                let reason = if expected.status == 200 {
                    "OK"
                } else {
                    "Internal Server Error"
                };
                let response = format!(
                    "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    expected.status,
                    reason,
                    expected.body.len(),
                    expected.body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (format!("http://{address}"), requests, task)
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

    #[tokio::test]
    async fn certificate_preflight_follows_page_101_before_issuing() {
        let first_items = (0..100)
            .map(|index| serde_json::json!({"domain": format!("other-{index}.example.com")}))
            .collect::<Vec<_>>();
        let (base_url, requests, server) = spawn_server(vec![
            ExpectedResponse {
                target: "/.sekisho/api/v1/routes/route-id".into(),
                status: 200,
                body: serde_json::json!({
                    "from": "https://app.example.com",
                    "tls_downstream": "acme"
                })
                .to_string(),
            },
            ExpectedResponse {
                target: "/.sekisho/api/v1/certs".into(),
                status: 200,
                body: serde_json::json!({
                    "items": first_items,
                    "limit": 100,
                    "offset": 0,
                    "has_more": true
                })
                .to_string(),
            },
            ExpectedResponse {
                target: "/.sekisho/api/v1/certs?limit=100&offset=100".into(),
                status: 200,
                body: serde_json::json!({
                    "items": [{"domain": "app.example.com"}],
                    "limit": 100,
                    "offset": 100,
                    "has_more": false
                })
                .to_string(),
            },
        ])
        .await;
        let client = test_client(&base_url);

        sekisho_api_protocol::ensure_cert_before_enable(&client, "route-id")
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn certificate_preflight_returns_later_page_error_without_issuing() {
        let (base_url, requests, server) = spawn_server(vec![
            ExpectedResponse {
                target: "/.sekisho/api/v1/routes/route-id".into(),
                status: 200,
                body: serde_json::json!({
                    "from": "https://app.example.com",
                    "tls_downstream": "acme"
                })
                .to_string(),
            },
            ExpectedResponse {
                target: "/.sekisho/api/v1/certs".into(),
                status: 200,
                body: serde_json::json!({
                    "items": [{"domain": "other.example.com"}],
                    "limit": 100,
                    "offset": 0,
                    "has_more": true
                })
                .to_string(),
            },
            ExpectedResponse {
                target: "/.sekisho/api/v1/certs?limit=100&offset=1".into(),
                status: 500,
                body: serde_json::json!({"error": "page failed"}).to_string(),
            },
        ])
        .await;
        let client = test_client(&base_url);

        let error = sekisho_api_protocol::ensure_cert_before_enable(&client, "route-id")
            .await
            .unwrap_err();
        assert!(error.contains("page failed"));
        server.await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), 3);
    }
}
