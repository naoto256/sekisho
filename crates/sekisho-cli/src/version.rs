//! `show version` — render the local CLI version alongside the
//! connected daemon's reported version.
//!
//! The daemon endpoint is `/version` (mapped through `api_paths::VERSION`),
//! intentionally unauthenticated so the same handshake works before
//! credentials are wired up — see the startup check in `main.rs`. This
//! module shares its match / mismatch / unreachable verdict with that
//! handshake so the operator sees the same words in both places.
//!
//! ANSI color is best-effort: emitted only when stdout is a TTY (so
//! piping to a file or grepping the output stays clean).

use crate::CLIENT_VERSION;
use crate::api::ApiClient;

/// Three possible outcomes. Kept as an enum (not a string) so the unit
/// tests can match on the verdict without parsing rendered output.
#[derive(Debug, PartialEq, Eq)]
pub enum VersionVerdict {
    /// Daemon reachable and version matches the CLI build tag.
    Match,
    /// Daemon reachable but its version differs — operator likely
    /// upgraded one side without the other.
    Mismatch { daemon: String },
    /// Daemon `/version` could not be fetched. Reason is included for
    /// the operator's benefit; we do not exit on this — the rest of
    /// the shell can still operate against a partially-up daemon.
    Unreachable { reason: String },
}

/// Probe the daemon's `/version` endpoint and classify the result.
/// Public so `cmd_show` and the startup handshake share one rule.
pub async fn probe(client: &ApiClient) -> VersionVerdict {
    match client.get(sekisho_api_protocol::api_paths::VERSION).await {
        Ok(v) => {
            let daemon = v
                .get("version")
                .and_then(|s| s.as_str())
                .unwrap_or("<unknown>")
                .to_string();
            if daemon == CLIENT_VERSION {
                VersionVerdict::Match
            } else {
                VersionVerdict::Mismatch { daemon }
            }
        }
        Err(e) => VersionVerdict::Unreachable { reason: e },
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
            out.push_str("match         : ok\n");
        }
        VersionVerdict::Mismatch { daemon } => {
            out.push_str(&format!("sekisho daemon: {daemon}  ({server_url})\n"));
            let line = format!("match         : MISMATCH (cli={CLIENT_VERSION}, daemon={daemon})");
            if colorize {
                // ANSI red — the same hue we'd reach for elsewhere if
                // we ever standardize on a palette. Bracketed on its
                // own line so a paste into a ticket still reads right.
                out.push_str(&format!("\x1b[31m{line}\x1b[0m\n"));
            } else {
                out.push_str(&line);
                out.push('\n');
            }
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
            out.push_str("match         : n/a\n");
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
        assert!(out.contains("match         : ok"));
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn render_mismatch_includes_both_versions() {
        let v = VersionVerdict::Mismatch {
            daemon: "9.9.9".into(),
        };
        let out = render("https://h:9443", &v, false);
        assert!(out.contains("sekisho daemon: 9.9.9"));
        assert!(out.contains(&format!("MISMATCH (cli={CLIENT_VERSION}, daemon=9.9.9)")));
    }

    #[test]
    fn render_mismatch_with_colorize_wraps_match_line_in_ansi() {
        let v = VersionVerdict::Mismatch {
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
        assert!(out.contains("match         : n/a"));
    }
}
