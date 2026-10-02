//! Process-start command-line and environment configuration.
//!
//! This struct holds only what must be known *before* any database is open:
//! where the per-instance SQLite lives, how to log, and the two RPK
//! maintenance one-shots. Everything else — listen addresses, ACME settings,
//! session policy — deliberately moved out of here over time, into either the
//! per-instance config table (node-local values, so each HA peer can differ)
//! or the cluster-wide service DB (values that must be identical fleet-wide).
//!
//! The reason is single-source-of-truth: a setting that exists both as a flag
//! and as a stored row has two answers and no rule for which wins. Flags that
//! were removed are documented as inline `//` notes at their old positions
//! rather than deleted outright, so an operator grepping for the old name
//! finds where the knob went instead of nothing.
//!
//! Note also what is *not* here: the master key has no flag, because argv is
//! world-readable on Linux. It arrives only as a path to an
//! operator-provisioned credential file (`SEKISHO_MASTER_KEY_FILE`, read by
//! `crate::runtime`); even the older `SEKISHO_MASTER_KEY` *value* form is
//! now rejected at boot. The tests below pin that the flag has not crept back
//! in as a flag or as a bare positional argument.

use clap::{Parser, ValueEnum};

/// Subscriber output format. JSON is the default because journald
/// captures stdout per-line into `MESSAGE` and downstream forwarders
/// (vector, fluent-bit, syslog → SIEM) parse JSON natively. Text mode
/// stays available for interactive `cargo run` / `journalctl -f`
/// debugging where the structured form is hard on the eyes.
#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object per line. The production default.
    Json,
    /// Human-readable lines for interactive use.
    Text,
}

/// Parsed command line. Re-exported from the crate root because it is part of
/// the binary's contract with the library — `main` parses this and hands it to
/// `run`.
#[derive(Parser, Debug)]
#[command(name = "sekisho", about = "Identity-Aware Proxy")]
pub struct CliConfig {
    /// Print the current per-instance management RPK pin and exit without
    /// opening the service database or starting listeners.
    #[arg(long, conflicts_with = "rotate_management_rpk")]
    pub print_management_rpk: bool,

    /// Atomically replace the per-instance management RPK, print the new pin,
    /// and exit. The daemon must be restarted before the new key is served.
    #[arg(long, conflicts_with = "print_management_rpk")]
    pub rotate_management_rpk: bool,

    /// Path to the per-instance SQLite that holds node-local
    /// configuration (`instance_config` table). Always opened as
    /// SQLite. When no cluster DB is configured (via the
    /// `/instance` management API or, on first boot, the
    /// `SEKISHO_SERVICE_DB` import env var), operational data
    /// (routes, idps, policies, sessions, ...) also lives in this
    /// file.
    ///
    /// The previous packaging used `bootstrap.db` for this file; the
    /// daemon auto-renames `bootstrap.db` → `instance_config.db` in
    /// the same directory on first boot when the legacy filename is
    /// in use. Operators with hand-set `SEKISHO_INSTANCE_CONFIG`
    /// values pointing at a custom path are responsible for their
    /// own filenames.
    #[arg(
        long = "instance-config",
        env = "SEKISHO_INSTANCE_CONFIG",
        default_value = "/var/lib/sekisho/instance_config.db"
    )]
    pub instance_config: String,

    // Cluster DB URL is no longer a CLI flag. It lives in the
    // encrypted instance_config row inside the per-instance SQLite,
    // managed through the management API (`/instance`). The
    // environment variable `SEKISHO_SERVICE_DB` is still honoured on
    // first boot as an import source — useful for provisioning
    // scripts that don't yet have credentials for the management API
    // — but after a single boot the DB is authoritative and the env
    // var is ignored with a loud warning on mismatch.
    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "SEKISHO_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// Subscriber output format. Defaults to `json` because production
    /// runs under systemd → journald → downstream SIEM, where structured
    /// fields are non-negotiable for forensics. Override to `text` for
    /// interactive development.
    #[arg(
        long,
        env = "SEKISHO_LOG_FORMAT",
        value_enum,
        default_value_t = LogFormat::Json,
    )]
    pub log_format: LogFormat,

    // HTTP listen address (for ACME challenges and HTTPS redirect),
    // proxy listen, and management-API listen are no longer CLI
    // flags. They live in the per-instance plaintext bootstrap config
    // — each node binds its own address in HA, and the management
    // API (`PATCH /instance`) is the only knob. To set them
    // headlessly on a fresh install, use `sekisho-cli` against the
    // local socket before opening the public listeners.
    /// Disable TLS on the proxy listener (useful for dev/testing behind another TLS terminator)
    #[arg(long, env = "SEKISHO_NO_TLS", default_value = "false")]
    pub no_tls: bool,

    /// Unix socket path for local authentication challenge.
    #[arg(
        long,
        env = "SEKISHO_CONTROL_SOCKET",
        default_value = "/run/sekisho/control.sock"
    )]
    pub control_socket: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};

    const DUMMY_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn help_does_not_expose_master_key_ingress() {
        let help = CliConfig::command().render_long_help().to_string();
        assert!(!help.contains("--master-key"));
        assert!(!help.contains("SEKISHO_MASTER_KEY"));
        assert!(!help.contains(DUMMY_SECRET));
    }

    #[test]
    fn removed_master_key_flag_is_rejected() {
        let separated =
            CliConfig::try_parse_from(["sekishod", "--master-key", DUMMY_SECRET]).unwrap_err();
        assert_eq!(separated.kind(), ErrorKind::UnknownArgument);

        let joined = format!("--master-key={DUMMY_SECRET}");
        let equals = CliConfig::try_parse_from(["sekishod", &joined]).unwrap_err();
        assert_eq!(equals.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn bare_master_key_is_rejected_as_positional_input() {
        let error = CliConfig::try_parse_from(["sekishod", DUMMY_SECRET]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn unrelated_invalid_option_is_still_rejected() {
        let error = CliConfig::try_parse_from(["sekishod", "--definitely-invalid"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn management_rpk_one_shots_are_mutually_exclusive() {
        let error = CliConfig::try_parse_from([
            "sekishod",
            "--print-management-rpk",
            "--rotate-management-rpk",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }
}
