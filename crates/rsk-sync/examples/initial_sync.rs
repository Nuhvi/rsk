//! Run an initial P2P header sync from a bootnode down to the
//! cumulative-difficulty checkpoint, verifying every header and storing it in
//! redb.
//!
//! ```sh
//! cargo run -p rsk-sync --example initial_sync -- --data-dir ./data \
//!   --bootnode bootstrap12.rsk.co:5050
//! ```
//!
//! The run is idempotent: a second run anchors at the highest previously
//! verified grid boundary instead of re-downloading the chain.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use rsk_consensus::config::ActivationHeights;
use rsk_store::Store;
use rsk_sync::{SyncConfig, SyncEngine};
use tracing_subscriber::EnvFilter;

fn parse_args() -> Result<(PathBuf, Vec<String>, usize)> {
    let args: Vec<String> = std::env::args().collect();
    let mut data_dir = PathBuf::from("data");
    let mut bootnodes: Vec<String> = Vec::new();
    let mut pipeline = 8usize;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                data_dir = args.get(i).cloned().unwrap_or_default().into();
            }
            "--bootnode" => {
                i += 1;
                if let Some(h) = args.get(i) {
                    bootnodes.push(h.clone());
                }
            }
            "--pipeline" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    pipeline = p.parse()?;
                }
            }
            "--help" => {
                eprintln!(
                    "usage: initial_sync \
                     --data-dir <dir> [--bootnode <host:port>]... [--pipeline N]"
                );
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    Ok((data_dir, bootnodes, pipeline))
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,rsk_sync=debug")),
        )
        .init();

    // Resolved up front, before any async runtime is built.
    ActivationHeights::mainnet().install();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run())
}

async fn run() -> Result<()> {
    let (data_dir, bootnodes, pipeline) = parse_args()?;
    std::fs::create_dir_all(&data_dir)?;

    let store = Arc::new(Store::open(&data_dir.join("store.redb"))?);
    let mut config = SyncConfig::mainnet(data_dir);
    config.pipeline = pipeline.max(4);
    if !bootnodes.is_empty() {
        config.bootnodes = bootnodes;
    }

    let mut engine = SyncEngine::new(store.clone(), config);
    let outcome = engine.sync().await?;

    println!("----------------------------------------");
    println!(
        "anchored at:      block {} (work between anchor and tip is verified)",
        outcome.anchored_at
    );
    println!("established work: {}", outcome.established_difficulty);
    println!(
        "peer claimed TD:  {}",
        outcome
            .peer_claimed_td
            .map(|td| td.to_string())
            .unwrap_or_else(|| "<unset>".to_string())
    );
    println!(
        "gate:             claimed={:?} established={} ceiling={} samples={} plausible={}",
        outcome.gate_report.claimed,
        outcome.gate_report.established,
        outcome.gate_report.ceiling,
        outcome.gate_report.samples,
        outcome.gate_report.plausible,
    );

    let tip = store.rsk_get_tip_height()?.unwrap_or(0);
    println!("stored RSK headers:  {}", count_stored(&store)?);
    println!("stored RSK tip:      {tip}");
    println!("----------------------------------------");
    Ok(())
}

fn count_stored(store: &Store) -> Result<u64> {
    // Count headers above the checkpoint (the walk's trusted floor).
    let tip = store.rsk_get_tip_height()?.unwrap_or(0);
    let start = 9_020_001u64;
    let mut count = 0u64;
    for h in start..=tip {
        if store.rsk_get_header_at_height(h)?.is_some() {
            count += 1;
        }
    }
    Ok(count)
}
