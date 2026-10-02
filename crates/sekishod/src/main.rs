//! Binary entry point for the sekisho daemon.
//!
//! Deliberately thin: everything real lives in the `sekishod` library so
//! integration tests exercise the same code path. The only logic here is
//! dispatching the two management-RPK maintenance flags, which must run
//! *before* the async runtime stands up listeners — they only touch the
//! instance config and the key material, then exit.

use clap::Parser as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = sekishod::CliConfig::parse();
    if cli.print_management_rpk {
        return sekishod::management_rpk_one_shot(
            sekishod::ManagementRpkCommand::Print,
            &cli.instance_config,
        )
        .await;
    }
    if cli.rotate_management_rpk {
        return sekishod::management_rpk_one_shot(
            sekishod::ManagementRpkCommand::Rotate,
            &cli.instance_config,
        )
        .await;
    }
    sekishod::run(cli).await
}
