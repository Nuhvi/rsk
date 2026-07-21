mod bitcoin;
mod config;
mod error;
mod rsk;

use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::bitcoin::difficulty::DifficultyTracker;
use crate::bitcoin::storage::BitcoinHeaderStorage;
use crate::bitcoin::sync;
use crate::config::NodeConfig;
use crate::rsk::rpc::RskRpc;
use crate::rsk::storage::RskHeaderStorage;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = NodeConfig::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    info!("RSK One node");
    std::fs::create_dir_all(&config.data_dir)?;

    // Open databases
    let btc_storage = BitcoinHeaderStorage::open(&config.data_dir.join("btc_headers.redb"))?;
    let rsk_storage = RskHeaderStorage::open(&config.data_dir.join("rsk_headers.redb"))?;

    // Connect to Electrum
    let electrum_clients = sync::connect_electrum(&config.electrum_servers)?;
    let mut electrum_idx = 0usize;

    // Difficulty tracker
    let mut diff_tracker = DifficultyTracker::new(config.btc_window_size);
    if let Some(tip) = btc_storage.get_tip_height()? {
        info!(tip = tip, "rebuilding difficulty tracker");
        diff_tracker.rebuild_from_chain(&btc_storage, tip)?;
    }

    // Phase 1: Bitcoin headers
    info!("=== Phase 1: Bitcoin headers ===");
    let btc_tip = sync::sync_bitcoin_headers(
        &btc_storage,
        &electrum_clients,
        &mut electrum_idx,
        &mut diff_tracker,
        config.btc_checkpoint_height,
    )?;
    info!(btc_tip = btc_tip, work = %diff_tracker.cumulative_work(), "Bitcoin done");

    // Phase 2: RSK headers
    info!("=== Phase 2: RSK headers ===");
    let rsk_rpc = RskRpc::new(&config.rsk_rpc_url)?;

    let rsk_tip = rsk_rpc.get_block_number().await?;
    info!(rsk_tip = rsk_tip);

    let safe_height = rsk_tip.saturating_sub(config.rsk_safe_block_margin);
    let btc_work = diff_tracker.cumulative_work();
    info!(safe_height = safe_height, btc_work = %btc_work, "target");

    // Resume from where we left off
    let rsk_start = match rsk_storage.get_tip_height()? {
        Some(h) => h + 1,
        None => {
            // First run — need to figure out where to start
            // Start from the estimated point where cumulative RSK difficulty exceeds BTC work
            // For now, start from safe_height and walk back
            safe_height
        }
    };

    let mut cumulative_work = primitive_types::U256::zero();
    let mut current = rsk_start.min(safe_height);
    let mut batch_num = 0u64;

    info!(starting_at = current, "walking backwards from RSK tip");

    loop {
        if current == 0 {
            break;
        }

        let batch_end = current.saturating_sub(config.sync_batch_size as u64 - 1);
        let batch_start = batch_end.max(1);
        let batch_numbers: Vec<u64> = (batch_start..=current).rev().collect();

        if batch_numbers.is_empty() {
            break;
        }

        // Fetch headers + merge-mining data
        let raw_headers = rsk_rpc.get_raw_block_headers_batch(&batch_numbers).await?;
        let merge_blocks = rsk_rpc
            .get_blocks_with_merge_mining_batch(&batch_numbers)
            .await?;

        let merge_map: std::collections::HashMap<u64, &rsk::rpc::RskBlockWithMergeMining> =
            merge_blocks
                .iter()
                .map(|b| {
                    let num =
                        u64::from_str_radix(b.number.strip_prefix("0x").unwrap_or(&b.number), 16)
                            .expect("invalid block number");
                    (num, b)
                })
                .collect();

        for (num, raw) in &raw_headers {
            // Decode header to get difficulty
            let header = rsk::storage::decode_rsk_header(raw)
                .map_err(|e| error::NodeError::Validation(format!("block {num}: {e}")))?;

            // Store header + merge-mining data
            if let Some(merge_block) = merge_map.get(num) {
                if let (Some(btc_hex), Some(coinbase_hex), Some(proof_hex), Some(hfm_hex)) = (
                    &merge_block.bitcoin_header,
                    &merge_block.compressed_coinbase,
                    &merge_block.merkle_proof,
                    &merge_block.hash_for_merged_mining,
                ) {
                    let mm_data = rsk::storage::MergeMiningData {
                        bitcoin_header_hex: btc_hex.clone(),
                        compressed_coinbase_hex: coinbase_hex.clone(),
                        merkle_proof_hex: proof_hex.clone(),
                        hash_for_merged_mining_hex: hfm_hex.clone(),
                    };
                    rsk_storage.store_header(*num, raw, &mm_data)?;
                }
            }

            cumulative_work = cumulative_work
                .checked_add(header.difficulty)
                .unwrap_or(cumulative_work);
        }

        batch_num += 1;
        if batch_num % 10 == 0 {
            let pct = if btc_work.is_zero() {
                100
            } else {
                (cumulative_work * primitive_types::U256::from(100) / btc_work).low_u64()
            };
            info!(
                height = batch_start,
                validated = batch_num * config.sync_batch_size as u64,
                cumulative_work = %cumulative_work,
                pct = %pct,
                "RSK sync progress"
            );
        }

        // Check if we've accumulated enough work
        if cumulative_work >= btc_work {
            info!(
                cumulative_work = %cumulative_work,
                target = %btc_work,
                "RSK work target reached"
            );
            rsk_storage.set_lowest_validated_height(batch_start)?;
            break;
        }

        current = batch_start.saturating_sub(1);
    }

    // Summary
    info!("=== Done ===");
    if let Some(btc_tip) = btc_storage.get_tip_height()? {
        info!(btc_tip = btc_tip, "Bitcoin headers stored");
    }
    if let Some(rsk_tip) = rsk_storage.get_tip_height()? {
        info!(rsk_tip = rsk_tip, "RSK headers stored");
    }

    Ok(())
}
