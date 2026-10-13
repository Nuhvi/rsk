//! `rsk-cli export-checkpoints` — write the store's **finalized** period
//! boundaries as a `checkpoints.txt` (one hex header per line, line `i` at
//! height `i * DIFFICULTY_PERIOD`).
//!
//! Only checkpoints at or below the finalized floor are written — those that
//! have satisfied the finality rule (the tail above them outweighs the period
//! before them) and are safe to treat as irreversible. The tip's nearest
//! boundary is deliberately excluded: it is not final yet, so embedding it as a
//! trust anchor would be unsafe.
//!
//! This is the inverse of the embedded spine: run it against a store synced
//! from genesis and the output can be dropped straight into
//! `crates/core/data/checkpoints.txt` and rebuilt in — no server needed.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use bitcoin::Network;
use bitcoin::consensus::Encodable;
use rsk_core::Chain;

use crate::DEFAULT_DATA_DIR;

#[derive(clap::Args)]
pub struct Args {
    /// Directory of the chain store to read
    #[arg(long, value_name = "DIR", default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,

    /// Write to this file instead of stdout
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    let store_path = args.data_dir.join("chain.redb");
    let chain = Chain::open(&store_path, Network::Bitcoin)
        .with_context(|| format!("opening store {}", store_path.display()))?;
    let finalized = chain
        .finalized_height()?
        .with_context(|| format!("store {} is not seeded", store_path.display()))?;

    // Everything at or below the finalized floor — never the raw tip.
    let checkpoints = chain.finalized_checkpoints()?;
    if checkpoints.is_empty() {
        bail!("no finalized checkpoints at or below the floor {finalized}");
    }

    let mut text = String::new();
    for (_, header) in &checkpoints {
        let mut bytes = Vec::with_capacity(80);
        header
            .consensus_encode(&mut bytes)
            .expect("encoding to vec is infallible");
        text.push_str(&hex::encode(&bytes));
        text.push('\n');
    }

    match args.out {
        Some(path) => {
            std::fs::write(&path, &text).with_context(|| format!("writing {}", path.display()))?;
            tracing::info!(
                "exported {} finalized checkpoints (floor {finalized}) to {}",
                checkpoints.len(),
                path.display()
            );
        }
        None => {
            std::io::stdout()
                .write_all(text.as_bytes())
                .context("writing checkpoints to stdout")?;
            tracing::info!(
                "exported {} finalized checkpoints (floor {finalized}) to stdout",
                checkpoints.len()
            );
        }
    }
    Ok(())
}
