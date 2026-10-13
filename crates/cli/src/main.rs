//! rsk-cli — run the RSK One node from the command line.
//!
//! This is the user-facing way to run things; the crates below it are
//! libraries (`btc-p2p` protocol client, `rsk-core` chain engine) with no CLI
//! of their own, so the node stays embeddable.
//!
//! `probe` reaches a real Bitcoin P2P peer and pulls one `headers` batch.
//! `sync` downloads real Bitcoin headers into the `rsk-core` store, which
//! PoW-, continuity-, difficulty- and timestamp-validates every one and
//! finalizes difficulty periods as it goes. `export-checkpoints` writes the
//! store's period-boundary headers back out as a `checkpoints.txt`.
//!
//! Logs go to stderr (tracing); data (e.g. exported checkpoints) goes to
//! stdout, so `rsk-cli export-checkpoints > file` stays clean.

mod export;
mod peers;
mod probe;
mod sync;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// Who we are on the wire (BIP 14).
pub const USER_AGENT: &str = "/rsk-one:0.1.0/";

/// Where the chain store lives by default, relative to the working directory
/// (the repo gitignores `data/`). Product-scoped rather than bitcoin-scoped
/// because the same store will later carry RSK chain state. The absolute path
/// is logged at startup so there is never a question of *where*.
pub const DEFAULT_DATA_DIR: &str = "data/rsk-one";

#[derive(Parser)]
#[command(
    name = "rsk-cli",
    version,
    about = "The RSK One node: talk to real Bitcoin peers and sync headers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Contact a real Bitcoin P2P peer and prove headers flow
    Probe(probe::Args),
    /// Download Bitcoin headers over P2P into the rsk-core store
    Sync(sync::Args),
    /// Export the store's period-boundary headers as a checkpoints.txt
    #[command(name = "export-checkpoints")]
    ExportCheckpoints(export::Args),
}

fn main() -> Result<()> {
    init_tracing();
    match Cli::parse().command {
        Command::Probe(args) => probe::run(args),
        Command::Sync(args) => sync::run(args),
        Command::ExportCheckpoints(args) => export::run(args),
    }
}

/// Logs to stderr (`RUST_LOG` override, default `info`); stdout is left for
/// data output.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
