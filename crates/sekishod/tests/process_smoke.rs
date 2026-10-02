#![cfg(unix)]

//! End-to-end tests that spawn the real `sekishod` binary.
//!
//! Everything else in the suite exercises the library in-process, which cannot
//! observe the properties that only exist for an actual process: that it boots
//! with a real TLS listener and shuts down cleanly, that the management-RPK
//! one-shots touch neither the service database nor any listener before
//! exiting, and that a rejected master-key configuration fails without the
//! rejected value appearing in stdout, stderr or the exit path.
//!
//! That last group is why these are process tests rather than unit tests: "the
//! secret did not leak" is a claim about what the process wrote to its
//! descriptors, and it can only be checked from outside.
//!
//! Unix-only, because the harness drives the control socket and process
//! signals directly.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

use sekisho_api_protocol::management_rpk::ManagementRpkPin;

const MASTER_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const MASTER_KEY_PREFIX: &str = "0123456789abcdef";
const MAX_ATTEMPTS: usize = 4;

enum MasterKeyIngress<'a> {
    File(&'a Path),
    LegacyEnvironment,
    BothWithEmptyLegacy(&'a Path),
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        // Keep the control-socket pathname below macOS' short SUN_LEN limit.
        let path = PathBuf::from("/tmp").join(format!("sks-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).expect("create sekishod smoke directory");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct ChildCapture {
    child: Child,
    stdout: Option<thread::JoinHandle<Vec<u8>>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
}

impl ChildCapture {
    fn spawn(db: &Path, socket: &Path, ingress: MasterKeyIngress<'_>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sekishod"));
        command
            .arg("--instance-config")
            .arg(db)
            .arg("--control-socket")
            .arg(socket)
            .arg("--log-format")
            .arg("json")
            .arg("--log-level")
            .arg("info")
            .env_remove("SEKISHO_SERVICE_DB")
            .env_remove("SEKISHO_INSTANCE_CONFIG")
            .env_remove("SEKISHO_CONTROL_SOCKET")
            .env_remove("SEKISHO_NO_TLS")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match ingress {
            MasterKeyIngress::File(path) => {
                command
                    .env("SEKISHO_MASTER_KEY_FILE", path)
                    .env_remove("SEKISHO_MASTER_KEY");
            }
            MasterKeyIngress::LegacyEnvironment => {
                command
                    .env("SEKISHO_MASTER_KEY", MASTER_KEY)
                    .env_remove("SEKISHO_MASTER_KEY_FILE");
            }
            MasterKeyIngress::BothWithEmptyLegacy(path) => {
                command
                    .env("SEKISHO_MASTER_KEY", "")
                    .env("SEKISHO_MASTER_KEY_FILE", path);
            }
        }
        let mut child = command.spawn().expect("spawn sekishod");
        let mut stdout = child.stdout.take().expect("capture sekishod stdout");
        let mut stderr = child.stderr.take().expect("capture sekishod stderr");
        let stdout = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .read_to_end(&mut bytes)
                .expect("read sekishod stdout");
            bytes
        });
        let stderr = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr
                .read_to_end(&mut bytes)
                .expect("read sekishod stderr");
            bytes
        });
        Self {
            child,
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }

    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().expect("poll sekishod")
    }

    fn signal_term(&self) {
        // The child PID remains owned by this guard until wait(), so it is
        // valid for the duration of this signal call.
        let rc = unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        assert_eq!(rc, 0, "send SIGTERM to sekishod");
    }

    fn wait_until_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn finish(mut self, status: ExitStatus) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        let waited = self.child.wait().expect("reap sekishod");
        assert_eq!(status, waited);
        let stdout = self
            .stdout
            .take()
            .expect("sekishod stdout handle")
            .join()
            .expect("join sekishod stdout");
        let stderr = self
            .stderr
            .take()
            .expect("sekishod stderr handle")
            .join()
            .expect("join sekishod stderr");
        (status, stdout, stderr)
    }

    fn kill_and_finish(mut self) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        if self.try_wait().is_none() {
            let _ = self.child.kill();
        }
        let status = self.child.wait().expect("reap killed sekishod");
        let stdout = self
            .stdout
            .take()
            .expect("sekishod stdout handle")
            .join()
            .expect("join sekishod stdout");
        let stderr = self
            .stderr
            .take()
            .expect("sekishod stderr handle")
            .join()
            .expect("join sekishod stderr");
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

struct PortReservations {
    proxy: TcpListener,
    api: TcpListener,
    proxy_port: u16,
    api_port: u16,
}

impl PortReservations {
    fn new() -> Self {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("reserve proxy port");
        let api = TcpListener::bind("0.0.0.0:0").expect("reserve management API port");
        let proxy_port = proxy
            .local_addr()
            .expect("proxy reservation address")
            .port();
        let api_port = api.local_addr().expect("API reservation address").port();
        assert!(![80, 443, 9443].contains(&proxy_port));
        assert!(![80, 443, 9443].contains(&api_port));
        Self {
            proxy,
            api,
            proxy_port,
            api_port,
        }
    }

    fn release(self) {
        drop(self.proxy);
        drop(self.api);
    }
}

async fn seed_instance_config(db: &Path, proxy_port: u16, api_port: u16) {
    let options = SqliteConnectOptions::new()
        .filename(db)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open smoke instance DB");
    sqlx::query(
        r#"CREATE TABLE instance_config (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            encrypted  INTEGER NOT NULL DEFAULT 0 CHECK (encrypted IN (0, 1)),
            updated_at INTEGER NOT NULL DEFAULT (unixepoch())
        )"#,
    )
    .execute(&pool)
    .await
    .expect("create instance_config fixture");
    for (key, value) in [
        ("proxy_listen", format!("127.0.0.1:{proxy_port}")),
        ("api_listen", format!("127.0.0.1:{api_port}")),
        ("http_listen", String::new()),
    ] {
        sqlx::query("INSERT INTO instance_config (key, value, encrypted) VALUES (?1, ?2, 0)")
            .bind(key)
            .bind(value)
            .execute(&pool)
            .await
            .expect("insert instance listener fixture");
    }
    pool.close().await;
}

fn redacted(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace(MASTER_KEY, "<redacted-master-key>")
}

fn address_in_use(stdout: &[u8], stderr: &[u8]) -> bool {
    let combined = format!("{}\n{}", redacted(stdout), redacted(stderr));
    combined.contains("Address already in use")
        || combined.contains("os error 48")
        || combined.contains("os error 98")
}

fn run_management_rpk_one_shot(
    db: &Path,
    master_key_file: &Path,
    control_socket: &Path,
    flag: &str,
) -> ManagementRpkPin {
    let output = Command::new(env!("CARGO_BIN_EXE_sekishod"))
        .arg("--instance-config")
        .arg(db)
        .arg("--control-socket")
        .arg(control_socket)
        .arg(flag)
        .env("SEKISHO_MASTER_KEY_FILE", master_key_file)
        .env_remove("SEKISHO_MASTER_KEY")
        .env(
            "SEKISHO_SERVICE_DB",
            "postgres://127.0.0.1:1/one_shot_must_not_connect",
        )
        .stdin(Stdio::null())
        .output()
        .expect("run management RPK one-shot");
    assert!(
        output.status.success(),
        "management RPK one-shot failed: {}",
        redacted(&output.stderr)
    );
    assert!(
        !control_socket.exists(),
        "management RPK one-shot must not create the control socket"
    );
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !stream
                .windows(MASTER_KEY_PREFIX.len())
                .any(|window| { window == MASTER_KEY_PREFIX.as_bytes() })
        );
        assert!(!String::from_utf8_lossy(stream).contains("PRIVATE KEY"));
    }
    let stdout = String::from_utf8(output.stdout).expect("RPK output is UTF-8");
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(
        lines.len(),
        1,
        "one-shot stdout must contain exactly one pin"
    );
    lines[0]
        .parse()
        .expect("one-shot emitted a canonical RPK pin")
}

async fn wait_for_tls_health(
    child: &mut ChildCapture,
    api_port: u16,
    socket: &Path,
    pin: &ManagementRpkPin,
) -> Result<reqwest::Client, String> {
    let tls = sekisho_management_rpk_tls::client_config(pin)
        .map_err(|error| format!("build pinned TLS config: {error}"))?;
    let client = reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .connect_timeout(Duration::from_millis(250))
        .timeout(Duration::from_secs(1))
        .build()
        .map_err(|e| format!("build TLS health client: {e}"))?;
    let url = format!(
        "https://127.0.0.1:{api_port}/.sekisho/api/v1{}",
        sekisho_api_protocol::api_paths::HEALTH
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait() {
            return Err(format!("sekishod exited before TLS readiness: {status}"));
        }
        if socket.exists()
            && let Ok(response) = client.get(&url).send().await
            && response.status() == reqwest::StatusCode::OK
        {
            return Ok(client);
        }
        if Instant::now() >= deadline {
            return Err("sekishod TLS health did not become ready before deadline".to_string());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn actual_process_boots_serves_tls_and_shuts_down_cleanly() {
    for attempt in 1..=MAX_ATTEMPTS {
        let temp = TempDir::new();
        let db = temp.path.join("instance.db");
        let socket = temp.path.join("control.sock");
        let master_key_file = temp.path.join("master-key");
        std::fs::write(&master_key_file, format!("{MASTER_KEY}\n"))
            .expect("write master-key credential");
        let ports = PortReservations::new();
        let proxy_port = ports.proxy_port;
        let api_port = ports.api_port;
        seed_instance_config(&db, proxy_port, api_port).await;
        let management_rpk_pin =
            run_management_rpk_one_shot(&db, &master_key_file, &socket, "--print-management-rpk");
        ports.release();

        let mut child = ChildCapture::spawn(&db, &socket, MasterKeyIngress::File(&master_key_file));
        match wait_for_tls_health(&mut child, api_port, &socket, &management_rpk_pin).await {
            Ok(client) => {
                drop(client);
                child.signal_term();
                let Some(status) = child.wait_until_exit(Duration::from_secs(15)) else {
                    let (_status, stdout, stderr) = child.kill_and_finish();
                    panic!(
                        "sekishod did not exit after SIGTERM; stdout={} stderr={}",
                        redacted(&stdout),
                        redacted(&stderr)
                    );
                };
                let (status, stdout, stderr) = child.finish(status);
                assert!(status.success(), "sekishod exit status: {status}");
                assert!(!socket.exists(), "control socket must be removed");

                assert!(
                    !stdout
                        .windows(MASTER_KEY_PREFIX.len())
                        .any(|window| window == MASTER_KEY_PREFIX.as_bytes()),
                    "sekishod stdout exposed a stable master-key prefix"
                );
                assert!(
                    !stderr
                        .windows(MASTER_KEY_PREFIX.len())
                        .any(|window| window == MASTER_KEY_PREFIX.as_bytes()),
                    "sekishod stderr exposed a stable master-key prefix"
                );
                assert!(
                    !stdout
                        .windows(MASTER_KEY.len())
                        .any(|window| window == MASTER_KEY.as_bytes()),
                    "sekishod stdout exposed the master key"
                );
                assert!(
                    !stderr
                        .windows(MASTER_KEY.len())
                        .any(|window| window == MASTER_KEY.as_bytes()),
                    "sekishod stderr exposed the master key"
                );
                let stdout_text = String::from_utf8_lossy(&stdout);
                let stderr_text = String::from_utf8_lossy(&stderr);
                let combined = format!("{stdout_text}\n{stderr_text}");
                let start = combined
                    .find("\"event\":\"daemon.shutdown.start\"")
                    .expect("shutdown start audit");
                let complete = combined
                    .find("\"event\":\"daemon.shutdown.complete\"")
                    .expect("shutdown complete audit");
                assert!(start < complete, "shutdown audit order must be preserved");
                return;
            }
            Err(reason) => {
                let (_status, stdout, stderr) = child.kill_and_finish();
                if attempt < MAX_ATTEMPTS && address_in_use(&stdout, &stderr) {
                    continue;
                }
                panic!(
                    "{reason}; attempt={attempt}; stdout={} stderr={}",
                    redacted(&stdout),
                    redacted(&stderr)
                );
            }
        }
    }
    unreachable!("bounded process smoke attempts exhausted")
}

#[test]
fn management_rpk_one_shots_skip_service_database_listener_and_background_edges() {
    let temp = TempDir::new();
    let db = temp.path.join("instance.db");
    let socket = temp.path.join("must-not-exist.sock");
    let master_key_file = temp.path.join("master-key");
    std::fs::write(&master_key_file, format!("{MASTER_KEY}\n"))
        .expect("write master-key credential");

    let initial =
        run_management_rpk_one_shot(&db, &master_key_file, &socket, "--print-management-rpk");
    let printed_again =
        run_management_rpk_one_shot(&db, &master_key_file, &socket, "--print-management-rpk");
    assert_eq!(
        initial, printed_again,
        "print must preserve the durable key"
    );

    let rotated =
        run_management_rpk_one_shot(&db, &master_key_file, &socket, "--rotate-management-rpk");
    assert_ne!(initial, rotated, "rotate must atomically replace the key");
    let printed_after_rotate =
        run_management_rpk_one_shot(&db, &master_key_file, &socket, "--print-management-rpk");
    assert_eq!(rotated, printed_after_rotate);
}

#[test]
fn actual_process_rejects_legacy_value_environment_without_leaking_it() {
    let temp = TempDir::new();
    let db = temp.path.join("legacy-instance.db");
    let socket = temp.path.join("legacy-control.sock");
    let mut child = ChildCapture::spawn(&db, &socket, MasterKeyIngress::LegacyEnvironment);
    let status = child
        .wait_until_exit(Duration::from_secs(10))
        .expect("legacy value-environment process must fail before startup");
    let (status, stdout, stderr) = child.finish(status);
    assert!(!status.success());
    assert!(
        !db.exists(),
        "legacy ingress must fail before Store creation"
    );
    assert!(
        !stdout
            .windows(MASTER_KEY.len())
            .any(|w| w == MASTER_KEY.as_bytes())
    );
    assert!(
        !stderr
            .windows(MASTER_KEY.len())
            .any(|w| w == MASTER_KEY.as_bytes())
    );
    assert!(
        format!("{}\n{}", redacted(&stdout), redacted(&stderr))
            .contains("SEKISHO_MASTER_KEY is no longer accepted")
    );
}

#[test]
fn actual_process_rejects_both_present_even_when_legacy_value_is_empty() {
    let temp = TempDir::new();
    let db = temp.path.join("both-present-instance.db");
    let socket = temp.path.join("both-present-control.sock");
    let master_key_file = temp.path.join("master-key");
    std::fs::write(&master_key_file, format!("{MASTER_KEY}\n")).expect("write master key file");

    let mut child = ChildCapture::spawn(
        &db,
        &socket,
        MasterKeyIngress::BothWithEmptyLegacy(&master_key_file),
    );
    let status = child
        .wait_until_exit(Duration::from_secs(10))
        .expect("both-present process must fail before startup");
    let (status, stdout, stderr) = child.finish(status);

    assert!(!status.success());
    assert!(
        !db.exists(),
        "both-present ingress must fail before Store creation"
    );
    assert!(
        !socket.exists(),
        "both-present ingress must fail before listener creation"
    );
    let output = format!("{}\n{}", redacted(&stdout), redacted(&stderr));
    assert!(output.contains("SEKISHO_MASTER_KEY is no longer accepted"));
    assert!(!output.contains(master_key_file.to_string_lossy().as_ref()));
}
