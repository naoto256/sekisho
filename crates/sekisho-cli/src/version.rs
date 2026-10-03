//! `show version` — render the local CLI version alongside the
//! connected daemon's reported version.
//!
//! The daemon endpoint is `/version` (mapped through `api_paths::VERSION`),
//! intentionally unauthenticated so the same handshake works before
//! credentials are wired up — see the startup check in `main.rs`. This
//! module shares product and API compatibility verdicts with that handshake so
//! the operator sees the same result in both places.
//!
//! ANSI color is best-effort: emitted only when stdout is a TTY (so
//! piping to a file or grepping the output stays clean).

use crate::CLIENT_VERSION;
use crate::api::ApiClient;
use sekisho_api_protocol::version::{API_VERSION, VersionCompatibility, classify_version_response};

/// Version-probe outcomes. Kept as an enum so startup and `show version`
/// consume the same classification without parsing rendered text.
#[derive(Debug, PartialEq, Eq)]
pub enum VersionVerdict {
    /// Daemon reachable and both product and API versions match.
    Match,
    /// Product builds differ, but the management API is compatible.
    ProductMismatch { daemon: String },
    /// The daemon speaks a different management API version.
    ApiMismatch {
        daemon: String,
        daemon_api_version: u64,
    },
    /// The endpoint returned JSON that cannot establish compatibility.
    InvalidResponse { reason: String },
    /// Daemon `/version` could not be fetched. `show version` renders the
    /// reason, while startup rejects the connection because compatibility
    /// could not be established.
    Unreachable { reason: String },
}

/// Probe the daemon's `/version` endpoint and classify the result.
/// Public so `cmd_show` and the startup handshake share one rule.
pub async fn probe(client: &ApiClient) -> VersionVerdict {
    match client
        .get_unauthenticated(sekisho_api_protocol::api_paths::VERSION)
        .await
    {
        Ok(v) => match classify_version_response(&v, CLIENT_VERSION) {
            VersionCompatibility::Match => VersionVerdict::Match,
            VersionCompatibility::ProductMismatch { server_version } => {
                VersionVerdict::ProductMismatch {
                    daemon: server_version,
                }
            }
            VersionCompatibility::ApiMismatch {
                server_version,
                server_api_version,
            } => VersionVerdict::ApiMismatch {
                daemon: server_version,
                daemon_api_version: server_api_version,
            },
            VersionCompatibility::InvalidResponse { reason } => {
                VersionVerdict::InvalidResponse { reason }
            }
        },
        Err(e) => VersionVerdict::Unreachable { reason: e },
    }
}

/// Startup action for a probed daemon. Product skew is a warning; API skew or
/// an invalid response is fatal because the shell cannot safely infer fields.
pub fn startup_check(verdict: &VersionVerdict) -> Result<Option<String>, String> {
    match verdict {
        VersionVerdict::Match => Ok(None),
        VersionVerdict::ProductMismatch { daemon } => Ok(Some(format!(
            "product version differs (sekisho-cli={CLIENT_VERSION}, daemon={daemon}); \
             management API v{API_VERSION} is compatible, continuing"
        ))),
        VersionVerdict::ApiMismatch {
            daemon_api_version, ..
        } => Err(format!(
            "management API version mismatch: sekisho-cli supports v{API_VERSION}, \
             daemon reports v{daemon_api_version}"
        )),
        VersionVerdict::InvalidResponse { reason } => {
            Err(format!("invalid /version response: {reason}"))
        }
        VersionVerdict::Unreachable { reason } => {
            Err(format!("could not reach /version: {reason}"))
        }
    }
}

/// Format the verdict as the multi-line `show version` output. `colorize`
/// controls whether ANSI escapes are emitted around the mismatch /
/// unreachable lines — callers pass `true` for an interactive TTY,
/// `false` otherwise (and the unit tests).
pub fn render(server_url: &str, verdict: &VersionVerdict, colorize: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!("sekisho-cli   : {CLIENT_VERSION}\n"));
    match verdict {
        VersionVerdict::Match => {
            out.push_str(&format!(
                "sekisho daemon: {CLIENT_VERSION}  ({server_url})\n"
            ));
            out.push_str("product match : ok\n");
            out.push_str(&format!("API version   : {API_VERSION} (ok)\n"));
        }
        VersionVerdict::ProductMismatch { daemon } => {
            out.push_str(&format!("sekisho daemon: {daemon}  ({server_url})\n"));
            let line = format!("product match : MISMATCH (cli={CLIENT_VERSION}, daemon={daemon})");
            if colorize {
                // ANSI red — the same hue we'd reach for elsewhere if
                // we ever standardize on a palette. Bracketed on its
                // own line so a paste into a ticket still reads right.
                out.push_str(&format!("\x1b[31m{line}\x1b[0m\n"));
            } else {
                out.push_str(&line);
                out.push('\n');
            }
            out.push_str(&format!("API version   : {API_VERSION} (ok)\n"));
        }
        VersionVerdict::ApiMismatch {
            daemon,
            daemon_api_version,
        } => {
            out.push_str(&format!("sekisho daemon: {daemon}  ({server_url})\n"));
            let line = format!(
                "API version   : MISMATCH (cli={API_VERSION}, daemon={daemon_api_version})"
            );
            if colorize {
                out.push_str(&format!("\x1b[31m{line}\x1b[0m\n"));
            } else {
                out.push_str(&line);
                out.push('\n');
            }
        }
        VersionVerdict::InvalidResponse { reason } => {
            out.push_str(&format!(
                "sekisho daemon: <invalid>  ({server_url})  -- {reason}\n"
            ));
            out.push_str("API version   : unknown\n");
        }
        VersionVerdict::Unreachable { reason } => {
            // Fail-soft: the operator may be running `show version`
            // *because* the daemon looks dead. Print what we know.
            let line = format!("sekisho daemon: <unreachable>  ({server_url})  -- {reason}");
            if colorize {
                out.push_str(&format!("\x1b[31m{line}\x1b[0m\n"));
            } else {
                out.push_str(&line);
                out.push('\n');
            }
            out.push_str("product match : n/a\n");
            out.push_str("API version   : n/a\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_match_has_no_ansi_and_includes_url() {
        let out = render(
            "https://127.0.0.1:9443",
            &VersionVerdict::Match,
            /*colorize=*/ false,
        );
        assert!(out.contains("sekisho-cli   :"));
        assert!(out.contains(CLIENT_VERSION));
        assert!(out.contains("https://127.0.0.1:9443"));
        assert!(out.contains("product match : ok"));
        assert!(out.contains(&format!("API version   : {API_VERSION} (ok)")));
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn render_mismatch_includes_both_versions() {
        let v = VersionVerdict::ProductMismatch {
            daemon: "9.9.9".into(),
        };
        let out = render("https://h:9443", &v, false);
        assert!(out.contains("sekisho daemon: 9.9.9"));
        assert!(out.contains(&format!("MISMATCH (cli={CLIENT_VERSION}, daemon=9.9.9)")));
        assert!(out.contains(&format!("API version   : {API_VERSION} (ok)")));
    }

    #[test]
    fn render_mismatch_with_colorize_wraps_match_line_in_ansi() {
        let v = VersionVerdict::ProductMismatch {
            daemon: "9.9.9".into(),
        };
        let out = render("https://h", &v, true);
        assert!(out.contains("\x1b[31m"));
        assert!(out.contains("\x1b[0m"));
    }

    #[tokio::test]
    async fn probe_against_unreachable_endpoint_returns_unreachable_verdict() {
        // Bind-and-immediately-drop a port so we have a guaranteed-
        // closed address. The probe should classify this as
        // Unreachable rather than panic or hang.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let pin =
            "sekisho-rpk-v1:ed25519:MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .parse()
                .unwrap();
        let client = ApiClient::new(&format!("https://{addr}"), "fake-key", &pin).unwrap();
        let verdict = probe(&client).await;
        assert!(
            matches!(verdict, VersionVerdict::Unreachable { .. }),
            "expected Unreachable, got {verdict:?}"
        );
    }

    #[test]
    fn render_unreachable_marks_daemon_and_match_as_unknown() {
        let v = VersionVerdict::Unreachable {
            reason: "connection refused".into(),
        };
        let out = render("https://h:9443", &v, false);
        assert!(out.contains("<unreachable>"));
        assert!(out.contains("connection refused"));
        assert!(out.contains("product match : n/a"));
        assert!(out.contains("API version   : n/a"));
    }

    #[test]
    fn startup_allows_product_mismatch_with_warning() {
        let verdict = VersionVerdict::ProductMismatch {
            daemon: "9.9.9".to_string(),
        };
        let warning = startup_check(&verdict).unwrap().unwrap();
        assert!(warning.contains("product version differs"));
        assert!(warning.contains("continuing"));
    }

    #[test]
    fn startup_rejects_api_mismatch() {
        let verdict = VersionVerdict::ApiMismatch {
            daemon: "0.1.1".to_string(),
            daemon_api_version: API_VERSION + 1,
        };
        let error = startup_check(&verdict).unwrap_err();
        assert!(error.contains("management API version mismatch"));
    }

    #[test]
    fn render_api_mismatch_names_both_versions() {
        let verdict = VersionVerdict::ApiMismatch {
            daemon: "0.1.1".to_string(),
            daemon_api_version: API_VERSION + 1,
        };
        let out = render("https://h", &verdict, false);
        assert!(out.contains(&format!("cli={API_VERSION}")));
        assert!(out.contains(&format!("daemon={}", API_VERSION + 1)));
    }
}
