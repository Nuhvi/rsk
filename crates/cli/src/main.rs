//! rsk-cli — run the RSK One node from the command line.
//!
//! This is the user-facing way to run things; the crates below it are
//! libraries (`btc-p2p` protocol client, `rsk-core` chain engine) with no CLI
//! of their own, so the node stays embeddable.
//!
//! `probe` reaches a real Bitcoin P2P peer and pulls one `headers` batch.
//! `sync` downloads real Bitcoin headers into the `rsk-core` store, which
//! PoW-, continuity-, difficulty- and timestamp-validates every one and
//! finalizes difficulty periods as it goes.

mod peers;
mod probe;
mod sync;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Who we are on the wire (BIP 14).
pub const USER_AGENT: &str = "/rsk-one:0.1.0/";

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
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Probe(args) => probe::run(args),
        Command::Sync(args) => sync::run(args),
    }
}
