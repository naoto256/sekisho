//! End-to-end tests around the CLI's startup handshake.
//!
//! Client and server ship together and are version-locked, and the stub server
//! here is deliberately configured with a mismatching version. The test that
//! exists, however, pins something that happens *earlier*: given a plain-HTTP
//! management URL the binary exits non-zero, writes nothing to stdout, and
//! never sends a request — so the API key cannot reach a connection that was
//! not the pinned TLS one. Noticing after the bytes are on the wire would be
//! too late.
//!
//! Note the gap implied by the filename: because the transport refusal
//! short-circuits first, no test here currently reaches the version exchange,
//! so the mismatch refusal itself is not covered end to end.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

const API_KEY: &str = "cli-integration-secret";
const SERVER_VERSION: &str = "0.0.0-test-mismatch";

struct MockServer {
    addr: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind CLI mock server");
        listener
            .set_nonblocking(true)
            .expect("set CLI mock nonblocking");
        let addr = listener.local_addr().expect("CLI mock local address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("set mock read timeout");
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
                                Err(e) => panic!("read CLI mock request: {e}"),
                            }
                        }
                        let first_line = String::from_utf8_lossy(&request)
                            .lines()
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        thread_requests
                            .lock()
                            .expect("lock CLI requests")
                            .push(first_line.clone());
                        let body = if first_line.contains("/version ") {
                            format!(r#"{{"version":"{SERVER_VERSION}"}}"#)
                        } else {
                            r#"{"status":"ok"}"#.to_string()
                        };
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                             content-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream
                            .write_all(response.as_bytes())
                            .expect("write CLI mock response");
                        stream.flush().expect("flush CLI mock response");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept CLI mock request: {e}"),
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
        format!("http://{}", self.addr)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("lock CLI requests").clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("join CLI mock thread");
        }
    }
}

struct ChildGuard {
    child: Option<Child>,
    stdout: Option<thread::JoinHandle<Vec<u8>>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
}

impl ChildGuard {
    fn spawn(mock_url: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sekisho-cli"))
            .arg(mock_url)
            .arg("--api-key")
            .arg(API_KEY)
            .arg("--management-rpk-pin")
            .arg("sekisho-rpk-v1:ed25519:MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sekisho-cli");
        let mut stdout = child.stdout.take().expect("capture sekisho-cli stdout");
        let mut stderr = child.stderr.take().expect("capture sekisho-cli stderr");
        let stdout = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .read_to_end(&mut bytes)
                .expect("read sekisho-cli stdout");
            bytes
        });
        let stderr = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr
                .read_to_end(&mut bytes)
                .expect("read sekisho-cli stderr");
            bytes
        });
        Self {
            child: Some(child),
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .expect("sekisho-cli child")
                .try_wait()
                .expect("poll sekisho-cli")
            {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "sekisho-cli did not exit before the deadline"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn finish(mut self, observed: ExitStatus) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        let mut child = self.child.take().expect("sekisho-cli child");
        let status = child.wait().expect("reap sekisho-cli");
        assert_eq!(observed, status);
        let stdout = self
            .stdout
            .take()
            .expect("sekisho-cli stdout handle")
            .join()
            .expect("join sekisho-cli stdout");
        let stderr = self
            .stderr
            .take()
            .expect("sekisho-cli stderr handle")
            .join()
            .expect("join sekisho-cli stderr");
        (status, stdout, stderr)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}

fn safe_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace(API_KEY, "<redacted-api-key>")
}

#[test]
fn actual_binary_rejects_plain_http_before_any_request() {
    let mock = MockServer::start();
    let mut child = ChildGuard::spawn(&mock.url());
    let status = child.wait_for_exit(Duration::from_secs(10));
    let (status, stdout, stderr) = child.finish(status);
    let safe_stdout = safe_output(&stdout);
    let safe_stderr = safe_output(&stderr);
    let diagnostic = format!("stdout={safe_stdout:?} stderr={safe_stderr:?}");

    assert_eq!(
        status.code(),
        Some(2),
        "unexpected CLI exit status; {diagnostic}"
    );
    assert!(
        !stdout
            .windows(API_KEY.len())
            .any(|w| w == API_KEY.as_bytes())
    );
    assert!(
        !stderr
            .windows(API_KEY.len())
            .any(|w| w == API_KEY.as_bytes())
    );
    assert!(
        safe_stdout.is_empty(),
        "unexpected stdout from HTTP refusal; {diagnostic}"
    );
    assert!(
        safe_stderr.contains("management API URL must use https"),
        "missing HTTPS-only diagnostic; {diagnostic}"
    );

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        0,
        "plain HTTP must fail before network access; requests={requests:?}; {diagnostic}"
    );
}

#[test]
fn startup_auth_probe_is_the_internal_read_endpoint() {
    let main_source = include_str!("../src/main.rs");
    let health = main_source
        .find("client.get(\"/health\")")
        .expect("startup health probe");
    let version = main_source[health..]
        .find("verify_server_version(&client)")
        .map(|offset| health + offset)
        .expect("startup version probe");
    let authentication = main_source[version..]
        .find("client.get(\"/_internal/host\")")
        .map(|offset| version + offset)
        .expect("startup authentication probe");
    assert!(
        health < version && version < authentication,
        "startup request order must remain health, version, authentication"
    );
    assert!(
        !main_source.contains("client.get(sekisho_api_protocol::api_paths::CONFIG)"),
        "startup must not require the admin-scoped config endpoint"
    );
    assert!(
        main_source[authentication..].contains("authentication failed: {e}"),
        "invalid credentials must remain a startup failure"
    );
}
