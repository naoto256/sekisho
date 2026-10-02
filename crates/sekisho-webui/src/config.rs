//! Clap surface for sekisho-webui.
//!
//! Every operational knob lives in `webui.yaml` — see
//! [`crate::yaml_config::WebuiConfig`]. The CLI exposes a single
//! `--config` flag that points at that YAML; everything else
//! (listen address, upstream URL, auth, guard, optional TLS
//! termination) is configured there.

use clap::Parser;
use std::path::PathBuf;

/// sekisho-webui — Web admin UI (BFF) for Sekisho IAP.
#[derive(Parser, Debug, Clone)]
#[command(name = "sekisho-webui", about, version)]
pub struct Args {
    /// Path to the webui YAML config.
    #[arg(long, default_value = "/etc/sekisho-webui/webui.yaml")]
    pub config: PathBuf,

    /// Out-of-band management RPK pin. Overrides the YAML value and is
    /// convenient for container config injection.
    #[arg(long, env = "SEKISHO_MANAGEMENT_RPK_PIN")]
    pub management_rpk_pin: Option<String>,
}
