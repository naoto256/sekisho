//! End-to-end security-header, CSRF and guard contract for the real
//! `sekishoweb` binary.
//!
//! The web UI is the one surface a browser renders, so its protections are
//! browser-enforced ones — security headers, a CSRF token bound to a cookie,
//! and the guard that keeps unauthenticated callers out. All three are
//! properties of what actually goes over the wire, and an in-process router
//! test can be made to pass while the shipped binary sets different headers
//! (or none) because of middleware order or a build-time difference.
//!
//! So this spawns the binary, drives it against a stub management API, and
//! asserts on raw responses. Slower than a unit test, and the only form of
//! this test that means anything.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::AlwaysResolvesServerRawPublicKeys,
    sign::CertifiedKey,
};
use sekisho_api_protocol::management_rpk::ManagementRpkPin;

const UPSTREAM_API_KEY: &str = "webui-upstream-integration-secret";
const BASIC_PASSWORD: &str = "hunter2";
const VALID_BASIC: &str = "Basic YWRtaW46aHVudGVyMg==";
const BAD_BASIC: &str = "Basic YWRtaW46d3Jvbmc=";
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
     img-src 'self' data:; font-src 'self'; connect-src 'self'; \
     frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'";
const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), bluetooth=(), \
     browsing-topics=(), camera=(), display-capture=(), encrypted-media=(), \
     fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), \
     interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), \
     picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), \
     serial=(), usb=(), xr-spatial-tracking=()";

// RFC 8032 section 7.1, test vector 1. These bytes are public test material.
const TEST_RPK_PRIVATE_PKCS8: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const TEST_RPK_PUBLIC_SPKI: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xd7, 0x5a, 0x98, 0x01,
    0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3,
    0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

fn test_rpk_server_config() -> Arc<ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(TEST_RPK_PRIVATE_PKCS8.to_vec()));
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .expect("RFC Ed25519 test key is supported");
    assert_eq!(
        signing_key
            .public_key()
            .expect("test key public SPKI")
            .as_ref(),
        TEST_RPK_PUBLIC_SPKI
    );
    let certified_key = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(TEST_RPK_PUBLIC_SPKI.to_vec())],
        signing_key,
    ));
    Arc::new(
        ServerConfig::builder_with_provider(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 test server configuration")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            certified_key,
        ))),
    )
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sekisho-webui-security-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create webui temp directory");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct MockServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind webui upstream mock");
        listener
            .set_nonblocking(true)
            .expect("set webui mock nonblocking");
        let addr = listener.local_addr().expect("webui mock local address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let server_config = test_rpk_server_config();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("set webui mock connection blocking");
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("set webui mock read timeout");
                        let connection = ServerConnection::new(Arc::clone(&server_config))
                            .expect("create webui RPK server connection");
                        let mut stream = StreamOwned::new(connection, stream);
                        let mut request = Vec::new();
                        let mut buf = [0_u8; 1024];
                        loop {
                            match stream.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    request.extend_from_slice(&buf[..n]);
                                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) =>
                                {
                                    break;
                                }
                                Err(e) => panic!("read webui mock request: {e}"),
                            }
                        }
                        let first_line = String::from_utf8_lossy(&request)
                            .lines()
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        thread_requests
                            .lock()
                            .expect("lock webui mock requests")
                            .push(first_line.clone());
                        let target = first_line
                            .split_ascii_whitespace()
                            .nth(1)
                            .unwrap_or_default();
                        let body = match target {
                            "/.sekisho/api/v1/routes" => serde_json::json!({
                                "items": [{
                                    "id": "route-first",
                                    "name": "first-page-route",
                                    "from": "https://first.example.com",
                                    "enabled": true
                                }],
                                "limit": 100,
                                "offset": 0,
                                "has_more": true
                            })
                            .to_string(),
                            "/.sekisho/api/v1/routes?limit=100&offset=1" => serde_json::json!({
                                "items": [{
                                    "id": "route-second",
                                    "name": "second-page-route",
                                    "from": "https://second.example.com",
                                    "enabled": false
                                }],
                                "limit": 100,
                                "offset": 1,
                                "has_more": false
                            })
                            .to_string(),
                            _ => format!(r#"{{"version":"{}"}}"#, env!("CARGO_PKG_VERSION")),
                        };
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                             content-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream
                            .write_all(response.as_bytes())
                            .expect("write webui mock response");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept webui mock request: {e}"),
                }
            }
        });
        Self {
            addr,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("https://{}", self.addr)
    }

    fn pin(&self) -> ManagementRpkPin {
        ManagementRpkPin::from_opaque_bytes(TEST_RPK_PUBLIC_SPKI.to_vec())
            .expect("RFC Ed25519 test SPKI is a valid pin payload")
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("lock webui requests").len()
    }

    fn request_lines(&self) -> Vec<String> {
        self.requests.lock().expect("lock webui requests").clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join webui mock thread");
        }
    }
}

struct ChildCapture {
    child: Child,
    stdout: Option<thread::JoinHandle<Vec<u8>>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
}

impl ChildCapture {
    fn spawn(config: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sekisho-webui"))
            .arg("--config")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sekisho-webui");
        let mut stdout = child.stdout.take().expect("capture webui stdout");
        let mut stderr = child.stderr.take().expect("capture webui stderr");
        let stdout = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).expect("read webui stdout");
            bytes
        });
        let stderr = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).expect("read webui stderr");
            bytes
        });
        Self {
            child,
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }

    fn assert_running(&mut self) {
        assert!(
            self.child.try_wait().expect("poll sekisho-webui").is_none(),
            "sekisho-webui exited before serving the security contract"
        );
    }

    fn stop(mut self) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        if self.child.try_wait().expect("poll sekisho-webui").is_none() {
            self.child.kill().expect("kill sekisho-webui");
        }
        let status = self.child.wait().expect("wait for sekisho-webui");
        let stdout = self
            .stdout
            .take()
            .expect("webui stdout handle")
            .join()
            .expect("join webui stdout");
        let stderr = self
            .stderr
            .take()
            .expect("webui stderr handle")
            .join()
            .expect("join webui stderr");
        (status, stdout, stderr)
    }
}

impl Drop for ChildCapture {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn reserve_loopback_port() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve webui port");
    let port = listener
        .local_addr()
        .expect("webui reserved address")
        .port();
    (listener, port)
}

fn assert_security_headers(headers: &reqwest::header::HeaderMap) {
    assert_eq!(
        headers.get("content-security-policy").expect("CSP header"),
        CSP
    );
    assert_eq!(
        headers
            .get("strict-transport-security")
            .expect("HSTS header"),
        "max-age=63072000; includeSubDomains"
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .expect("nosniff header"),
        "nosniff"
    );
    assert_eq!(
        headers
            .get("x-frame-options")
            .expect("frame-options header"),
        "DENY"
    );
    assert_eq!(
        headers
            .get("referrer-policy")
            .expect("referrer-policy header"),
        "no-referrer"
    );
    assert_eq!(
        headers
            .get("permissions-policy")
            .expect("permissions-policy header"),
        PERMISSIONS_POLICY
    );
}

fn csrf_cookie_token(set_cookie: &str) -> &str {
    let token = set_cookie
        .split(';')
        .next()
        .and_then(|pair| pair.strip_prefix("_sekisho_csrf="))
        .expect("CSRF cookie pair");
    assert_eq!(token.len(), 43, "CSRF token must encode 256 bits");
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "CSRF token must be unpadded base64url"
    );
    token
}

fn rendered_csrf_token(page: &str) -> &str {
    let marker = r#"<meta name="csrf-token" content=""#;
    let token_start = page.find(marker).expect("rendered CSRF meta tag") + marker.len();
    let remainder = &page[token_start..];
    let token_end = remainder.find('"').expect("CSRF meta content terminator");
    &remainder[..token_end]
}

async fn wait_for_webui(
    child: &mut ChildCapture,
    client: &reqwest::Client,
    base_url: &str,
) -> reqwest::Response {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        child.assert_running();
        if let Ok(response) = client
            .get(format!("{base_url}/healthz"))
            .header(reqwest::header::AUTHORIZATION, VALID_BASIC)
            .send()
            .await
        {
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "sekisho-webui did not become ready before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn actual_binary_enforces_guard_csrf_and_security_headers() {
    let temp = TempDir::new();
    let upstream = MockServer::start();
    let (reservation, webui_port) = reserve_loopback_port();
    let config_path = temp.path.join("webui.yaml");
    let config = format!(
        "listen: 127.0.0.1:{webui_port}\n\
         sekisho_api_url: {}\n\
         management_rpk_pin: \"{}\"\n\
         auth:\n  api_key: \"{UPSTREAM_API_KEY}\"\n\
         guard:\n  basic_auth: \"admin:plain:{BASIC_PASSWORD}\"\n",
        upstream.url(),
        upstream.pin()
    );
    std::fs::write(&config_path, config).expect("write webui config");
    drop(reservation);

    let mut child = ChildCapture::spawn(&config_path);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(250))
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build webui test client");
    let base_url = format!("http://127.0.0.1:{webui_port}");

    let response = wait_for_webui(&mut child, &client, &base_url).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_security_headers(response.headers());
    let set_cookie = response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("CSRF Set-Cookie")
        .to_str()
        .expect("Set-Cookie is text");
    assert!(set_cookie.starts_with("_sekisho_csrf="));
    assert!(set_cookie.contains("; Path=/"));
    assert!(set_cookie.contains("; Secure"));
    assert!(set_cookie.contains("; HttpOnly"));
    assert!(set_cookie.contains("; SameSite=Lax"));
    let csrf_token = csrf_cookie_token(set_cookie).to_string();
    assert_eq!(response.text().await.expect("read health body"), "ok");

    let response = client
        .get(&base_url)
        .header(reqwest::header::AUTHORIZATION, VALID_BASIC)
        .header(
            reqwest::header::COOKIE,
            format!("_sekisho_csrf={csrf_token}"),
        )
        .send()
        .await
        .expect("request rendered page");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_security_headers(response.headers());
    let page = response.text().await.expect("read rendered page");
    assert_eq!(rendered_csrf_token(&page), csrf_token);

    let response = client
        .get(format!("{base_url}/routes"))
        .header(reqwest::header::AUTHORIZATION, VALID_BASIC)
        .header(
            reqwest::header::COOKIE,
            format!("_sekisho_csrf={csrf_token}"),
        )
        .send()
        .await
        .expect("request paginated route page");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let routes_page = response.text().await.expect("read route page");
    assert!(routes_page.contains("first-page-route"));
    assert!(routes_page.contains("second-page-route"));
    let upstream_lines = upstream.request_lines();
    assert!(
        upstream_lines
            .iter()
            .any(|line| line.starts_with("GET /.sekisho/api/v1/routes HTTP/1.1"))
    );
    assert!(upstream_lines.iter().any(|line| {
        line.starts_with("GET /.sekisho/api/v1/routes?limit=100&offset=1 HTTP/1.1")
    }));
    let upstream_before_rejections = upstream.request_count();

    let response = client
        .get(format!("{base_url}/general/backup/export"))
        .header(reqwest::header::AUTHORIZATION, VALID_BASIC)
        .header(
            reqwest::header::COOKIE,
            format!("_sekisho_csrf={csrf_token}"),
        )
        .send()
        .await
        .expect("request removed backup export path");
    let export_status = response.status();
    let upstream_after_export = upstream.request_count();

    let boundary = "sekisho-removed-backup-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"confirm\"\r\n\r\n\
         yes\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"backup.json\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"version\":1,\"routes\":[],\"idps\":[],\"policies\":[],\"config\":{{}}}}\r\n\
         --{boundary}--\r\n"
    );
    let response = client
        .post(format!("{base_url}/general/backup"))
        .header(reqwest::header::AUTHORIZATION, VALID_BASIC)
        .header(
            reqwest::header::COOKIE,
            format!("_sekisho_csrf={csrf_token}"),
        )
        .header("x-csrf-token", &csrf_token)
        .header(
            reqwest::header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await
        .expect("request removed backup import path");
    let import_status = response.status();
    let upstream_after_import = upstream.request_count();

    assert_eq!(
        (
            export_status,
            import_status,
            upstream_after_export,
            upstream_after_import,
            page.to_ascii_lowercase().contains("backup"),
        ),
        (
            reqwest::StatusCode::NOT_FOUND,
            reqwest::StatusCode::NOT_FOUND,
            upstream_before_rejections,
            upstream_before_rejections,
            false,
        ),
        "removed backup surfaces must be absent and must not reach the management API",
    );

    let response = client
        .post(format!("{base_url}/routes"))
        .header(reqwest::header::AUTHORIZATION, VALID_BASIC)
        .header(reqwest::header::COOKIE, "_sekisho_csrf=cookie-token")
        .header("x-csrf-token", "different-header-token")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body("")
        .send()
        .await
        .expect("send CSRF mismatch request");
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert_security_headers(response.headers());
    assert_eq!(
        response.text().await.expect("read CSRF rejection"),
        "CSRF token missing or invalid"
    );

    for authorization in [None, Some(BAD_BASIC)] {
        let mut request = client.get(format!("{base_url}/healthz"));
        if let Some(value) = authorization {
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        let response = request.send().await.expect("send guard failure request");
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_security_headers(response.headers());
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .expect("Basic challenge"),
            r#"Basic realm="sekisho-webui""#
        );
    }

    assert_eq!(
        upstream.request_count(),
        upstream_before_rejections,
        "CSRF and guard rejections must not reach the upstream"
    );
    let (_status, stdout, stderr) = child.stop();
    let stdout = String::from_utf8_lossy(&stdout);
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(!stdout.contains(UPSTREAM_API_KEY));
    assert!(!stderr.contains(UPSTREAM_API_KEY));
    assert!(!stdout.contains(BASIC_PASSWORD));
    assert!(!stderr.contains(BASIC_PASSWORD));
}
