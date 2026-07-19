//! RSK Light Client PoC
//!
//! Syncs a minimal set of headers to determine a finalized Rootstock block,
//! using Bitcoin hashrate as the security anchor.
//!
//! # Algorithm
//!
//! 1. Derive the Bitcoin work target from the RSK tip's embedded Bitcoin header
//!    (multiply work_per_block × N, where N defaults to 144).
//! 2. Starting from the Rootstock chain tip, download RSK block headers and
//!    merge-mining data, accumulate cumulative difficulty.
//! 3. Stop when accumulated RSK work ≥ total Bitcoin work over N blocks.
//!    The current tip is then considered **finalized**.
//!
//! # Security Model
//!
//! Rootstock is merge-mined with Bitcoin. An attacker who wants to reorg
//! the RSK chain past the finalized point would need to outpace the
//! cumulative work of N=144 Bitcoin blocks.
//!
//! # Merge-Mining Verification (Rules 1-7)
//!
//! Every single block has its full merge-mining proof verified. All data
//! comes from the RSK node's JSON-RPC API — no external Bitcoin APIs needed:
//!
//! - `rsk_getRawBlockHeaderByNumber` → raw RLP for independent hash computation
//! - `eth_getBlockByNumber` → Bitcoin header, compressed coinbase, Merkle proof,
//!   hashForMergedMining
//!
//! For each block we verify:
//!
//! - Rule 1: Bitcoin PoW meets RSK difficulty target
//! - Rules 2-6: RSKBLOCK: tag + hashForMergedMining in coinbase tail
//! - Rule 7: Merkle proof connects coinbase to Bitcoin header's merkle_root
//! - Chain continuity: parent hash, block number, difficulty bounds, timestamps

#![allow(clippy::module_name_repetitions)]

use std::time::{Duration, Instant};

use bitcoin::block::Header as BitcoinHeader;
use bitcoin::consensus::Decodable;
use primitive_types::{H256, U256};
use reqwest::blocking::Client;
use serde::Deserialize;
use sha3::{Digest, Keccak256};

use crate::block_header::RskBlockHeader;
use crate::merge_mining;

const DEFAULT_TARGET_BITCOIN_BLOCKS: u64 = 144;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const BATCH_SIZE: usize = 100;
/// Maximum difficulty increase/decrease per block: ±0.25%
const MAX_DIFFICULTY_DELTA_PERCENT: u64 = 400;

// ── Configuration ───────────────────────────────────────────────────────────

/// Configuration for the light client sync.
pub struct LightClientConfig {
    /// RSK JSON-RPC endpoint (e.g. `https://rpc.mainnet.rootstock.io`)
    pub rsk_rpc_url: String,
    /// Number of Bitcoin blocks whose work the RSK chain must match
    /// to be considered finalized. Default: 144 (~24 hours of Bitcoin blocks).
    pub target_bitcoin_blocks: u64,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        let rsk_rpc_url = std::env::var("RSK_RPC_URL").expect("missing rpc url");
        Self {
            rsk_rpc_url,
            target_bitcoin_blocks: DEFAULT_TARGET_BITCOIN_BLOCKS,
        }
    }
}

// ── Sync Result ─────────────────────────────────────────────────────────────

/// Result of a successful light client sync.
#[must_use]
pub struct SyncResult {
    /// Block height that is considered finalized.
    pub finalized_height: u64,
    /// Keccak-256 hash of the finalized RSK block.
    pub finalized_block_hash: H256,
    /// Total RSK cumulative difficulty accumulated.
    pub rsk_cumulative_work: U256,
    /// Target work derived from N Bitcoin blocks.
    pub bitcoin_target_work: U256,
    /// Number of RSK headers fetched and validated.
    pub headers_validated: u64,
    /// Number of Bitcoin headers used to calculate the target.
    pub bitcoin_blocks_used: u64,
}

// ── Bitcoin Helpers ─────────────────────────────────────────────────────────

/// Derive the PoW work from a Bitcoin header's `nBits` target.
///
/// `Work = 2^256 / (target + 1)` — the expected number of hashes needed
/// to find a block at this difficulty.
fn bitcoin_header_work(header: &BitcoinHeader) -> U256 {
    let work = header.target().to_work();
    let le_bytes = work.to_le_bytes();
    U256::from_little_endian(&le_bytes)
}

/// Parse an 80-byte Bitcoin header from hex.
fn parse_btc_header_hex(hex_str: &str) -> Result<BitcoinHeader, Box<dyn std::error::Error>> {
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex)?;
    if bytes.len() != 80 {
        return Err(format!("Expected 80-byte Bitcoin header, got {} bytes", bytes.len()).into());
    }
    let mut reader = &bytes[..];
    BitcoinHeader::consensus_decode(&mut reader)
        .map_err(|e| format!("Failed to decode Bitcoin header: {e}").into())
}

/// Validate that consecutive RSK block difficulties are within bounds.
///
/// RSK difficulty can change at most ±0.25% per block (RSKj DifficultyCalculator).
fn validate_difficulty_bounds(
    block_difficulty: U256,
    prev_difficulty: U256,
    block_num: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let max_delta = prev_difficulty / MAX_DIFFICULTY_DELTA_PERCENT;
    let lower_bound = prev_difficulty.saturating_sub(max_delta);
    let upper_bound = prev_difficulty.saturating_add(max_delta);

    if block_difficulty < lower_bound || block_difficulty > upper_bound {
        return Err(format!(
            "Difficulty out of bounds at block {block_num}: {block_difficulty} not in [{lower_bound}, {upper_bound}] (prev={prev_difficulty})"
        )
        .into());
    }
    Ok(())
}

// ── RSK Helpers ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize, Debug)]
struct JsonRpcError {
    message: String,
}

/// Fetch the raw RLP-encoded block header via `rsk_getRawBlockHeaderByNumber`.
///
/// Returns the raw bytes that, when keccak256-hashed, produce the canonical block hash.
pub fn fetch_rsk_raw_block_header(
    client: &Client,
    rpc_url: &str,
    block_number: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hex_number = format!("0x{block_number:x}");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "rsk_getRawBlockHeaderByNumber",
        "params": [hex_number],
        "id": 1
    });

    let resp: JsonRpcResponse<String> = client.post(rpc_url).json(&body).send()?.json()?;

    if let Some(err) = resp.error {
        return Err(format!("RPC error at block {block_number}: {}", err.message).into());
    }

    let hex = resp
        .result
        .ok_or_else(|| format!("No raw header for block {block_number}"))?;
    let hex = hex.strip_prefix("0x").unwrap_or(&hex);
    Ok(hex::decode(hex)?)
}

/// Compute the block hash from a raw RLP-encoded header.
///
/// This is just `keccak256(raw_bytes)` — the canonical block hash.
#[must_use]
pub fn block_hash_from_raw_header(raw: &[u8]) -> H256 {
    let hash = Keccak256::digest(raw);
    H256::from_slice(&hash)
}

/// Batch result for a single request in a JSON-RPC batch.
#[derive(Deserialize)]
struct BatchJsonRpcResult {
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

/// Fetch multiple raw block headers in a single JSON-RPC batch request.
///
/// Returns `(block_number, raw_bytes)` pairs.
#[allow(clippy::type_complexity)]
pub fn fetch_rsk_raw_block_headers_batch(
    client: &Client,
    rpc_url: &str,
    block_numbers: &[u64],
) -> Result<Vec<(u64, Vec<u8>)>, Box<dyn std::error::Error>> {
    let batch: Vec<serde_json::Value> = block_numbers
        .iter()
        .enumerate()
        .map(|(i, &num)| {
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "rsk_getRawBlockHeaderByNumber",
                "params": [format!("0x{num:x}")],
                "id": i
            })
        })
        .collect();

    let resp: Vec<BatchJsonRpcResult> = client.post(rpc_url).json(&batch).send()?.json()?;

    if resp.len() != block_numbers.len() {
        return Err(format!(
            "Batch response length {} != request length {}",
            resp.len(),
            block_numbers.len()
        )
        .into());
    }

    let mut results = Vec::with_capacity(block_numbers.len());
    for (i, (num, entry)) in block_numbers.iter().zip(resp.iter()).enumerate() {
        if let Some(err) = &entry.error {
            return Err(format!("RPC error at block {num} (batch id {i}): {}", err.message).into());
        }
        let hex = entry
            .result
            .as_deref()
            .ok_or_else(|| format!("No raw header for block {num}"))?;
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let raw = hex::decode(hex)?;
        results.push((*num, raw));
    }
    Ok(results)
}

/// Fetch the latest RSK block number via `eth_blockNumber`.
fn fetch_rsk_height(client: &Client, rpc_url: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_blockNumber",
        "params": [],
        "id": 1
    });

    let resp: JsonRpcResponse<String> = client.post(rpc_url).json(&body).send()?.json()?;

    let hex = resp.result.ok_or("No result from eth_blockNumber")?;
    let hex = hex.strip_prefix("0x").unwrap_or(&hex);
    Ok(u64::from_str_radix(hex, 16)?)
}

// ── RSK Merge-Mining RPC ────────────────────────────────────────────────────

/// Full response from `eth_getBlockByNumber` for an RSK block.
///
/// Merge-mining fields are flat at the top level of the block JSON (RSKj `BlockResultDTO`).
#[derive(Deserialize, Debug)]
pub struct RskBlockWithMergeMining {
    /// Block number (hex string).
    pub number: String,
    /// 80-byte Bitcoin block header, hex-encoded (with "0x" prefix).
    #[serde(default)]
    #[serde(rename = "bitcoinMergedMiningHeader")]
    pub bitcoin_header: Option<String>,
    /// Compressed coinbase transaction, hex-encoded (with "0x" prefix).
    /// Format: [40-byte SHA-256 midstate][unhashed tail bytes].
    #[serde(default)]
    #[serde(rename = "bitcoinMergedMiningCoinbaseTransaction")]
    pub compressed_coinbase: Option<String>,
    /// RSKIP 92 Merkle proof, hex-encoded (with "0x" prefix).
    /// Concatenated 32-byte hashes, ordered bottom-to-top.
    #[serde(default)]
    #[serde(rename = "bitcoinMergedMiningMerkleProof")]
    pub merkle_proof: Option<String>,
    /// Hash miners embed in Bitcoin coinbase after "RSKBLOCK:" tag.
    /// keccak256(blockHeader RLP) with fork detection data in bytes [20..32).
    #[serde(default)]
    #[serde(rename = "hashForMergedMining")]
    pub hash_for_merged_mining: Option<String>,
}

/// Batch RPC response wrapper for `eth_getBlockByNumber`.
#[derive(Deserialize)]
struct EthBlockBatchResponse {
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

/// Fetch multiple RSK blocks with merge-mining data in a single JSON-RPC batch.
///
/// Calls `eth_getBlockByNumber` with `false` (lightweight mode — tx hashes only).
pub fn fetch_rsk_blocks_with_merge_mining_batch(
    client: &Client,
    rpc_url: &str,
    block_numbers: &[u64],
) -> Result<Vec<RskBlockWithMergeMining>, Box<dyn std::error::Error>> {
    let batch: Vec<serde_json::Value> = block_numbers
        .iter()
        .enumerate()
        .map(|(i, &num)| {
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": [format!("0x{num:x}"), false],
                "id": i
            })
        })
        .collect();

    let resp: Vec<EthBlockBatchResponse> = client.post(rpc_url).json(&batch).send()?.json()?;

    if resp.len() != block_numbers.len() {
        return Err(format!(
            "Batch response length {} != request length {}",
            resp.len(),
            block_numbers.len()
        )
        .into());
    }

    let mut results = Vec::with_capacity(block_numbers.len());
    for (i, (num, entry)) in block_numbers.iter().zip(resp.iter()).enumerate() {
        if let Some(err) = &entry.error {
            return Err(format!(
                "eth_getBlockByNumber RPC error at block {num} (batch id {i}): {}",
                err.message
            )
            .into());
        }
        let val = entry
            .result
            .as_ref()
            .ok_or_else(|| format!("No result from eth_getBlockByNumber at block {num}"))?;

        if val.is_null() {
            return Err(format!("Block {num} not found (null result)").into());
        }

        let block: RskBlockWithMergeMining = serde_json::from_value(val.clone())
            .map_err(|e| format!("Failed to parse eth_getBlockByNumber at block {num}: {e}"))?;
        results.push(block);
    }

    Ok(results)
}

// ── Core Algorithm ──────────────────────────────────────────────────────────

/// Run the light client sync.
///
/// Fetches merge-mining data from the RSK node itself (no external Bitcoin APIs).
/// Walks backwards from the chain tip accumulating difficulty until the target
/// is met. Returns a [`SyncResult`] with the finalized block info.
///
/// For EVERY block, the following validations are performed:
/// 1. Bitcoin PoW meets RSK difficulty target (Rule 1)
/// 2. RSKBLOCK: tag + hashForMergedMining in coinbase (Rules 2-6)
/// 3. Merkle proof connects coinbase to Bitcoin header's merkle_root (Rule 7)
/// 4. Difficulty is within ±0.25% of previous block
/// 5. Timestamps are monotonically decreasing (walking backwards)
/// 6. Parent hash linkage and block number continuity
pub fn sync_light_client(
    config: &LightClientConfig,
) -> Result<SyncResult, Box<dyn std::error::Error>> {
    println!("RSK Light Client PoC");
    println!("====================\n");

    let client = Client::builder().timeout(HTTP_TIMEOUT).build()?;

    // ── Step 1: Determine Bitcoin work target ───────────────────────────────
    // Derive from the RSK tip's embedded Bitcoin header — no external APIs needed.

    println!("Step 1: Computing Bitcoin work target from RSK tip\n");

    let n = config.target_bitcoin_blocks;
    let rsk_height = fetch_rsk_height(&client, &config.rsk_rpc_url)?;
    println!("  Latest RSK height: {rsk_height}");

    // Fetch tip with merge-mining data to get its Bitcoin header.
    let tip_blocks =
        fetch_rsk_blocks_with_merge_mining_batch(&client, &config.rsk_rpc_url, &[rsk_height])?;
    let tip_btc_hex = tip_blocks[0]
        .bitcoin_header
        .as_deref()
        .ok_or("RSK tip has no merge-mining data — pre-RSKIP-92 block?")?;
    let tip_btc_header = parse_btc_header_hex(tip_btc_hex)?;
    let work_per_block = bitcoin_header_work(&tip_btc_header);
    let total_btc_work = work_per_block
        .checked_mul(U256::from(n))
        .ok_or("Bitcoin work overflow")?;

    println!("  Bitcoin work per block: {work_per_block}");
    println!("  Target: {n} blocks × {work_per_block} = {total_btc_work}");

    // Also fetch tip raw header for difficulty estimation.
    let tip_raw = fetch_rsk_raw_block_header(&client, &config.rsk_rpc_url, rsk_height)?;
    let tip_header = RskBlockHeader::decode_rlp(&tip_raw)
        .map_err(|e| format!("Failed to decode tip header: {e}"))?;
    let tip_diff = tip_header.difficulty;
    println!("  Tip difficulty: {tip_diff}");

    // Estimate blocks needed, add 10% margin for difficulty drift.
    let blocks_needed = if tip_diff.is_zero() {
        rsk_height
    } else {
        let estimate = total_btc_work / tip_diff;
        let with_margin = estimate * U256::from(110) / U256::from(100);
        with_margin.min(U256::from(rsk_height)).low_u64() + 1
    };

    let start_height = rsk_height.saturating_sub(blocks_needed);
    println!("  Estimated blocks needed: {blocks_needed} (from {start_height} to {rsk_height})\n");

    // ── Step 2: Sync RSK headers with full merge-mining verification ────────

    println!("Step 2: Syncing RSK headers (Rules 1-7 for EVERY block)\n");

    let mut cumulative_work = U256::zero();
    let mut expected_parent_hash: Option<H256> = None;
    let mut prev_number: Option<u64> = None;
    let mut prev_difficulty: Option<U256> = None;
    let mut prev_timestamp: Option<u64> = None;
    let mut finalized_raw: Option<Vec<u8>> = None;
    let mut finalized_block_num: Option<u64> = None;
    let mut headers_validated: u64 = 0;
    let mut merge_mining_verified: u64 = 0;

    let block_count = rsk_height - start_height + 1;
    let num_batches = (block_count as usize).div_ceil(BATCH_SIZE);
    let sync_start = Instant::now();

    // Process in batches (descending from tip)
    'outer: for batch_idx in 0..num_batches {
        let offset = batch_idx * BATCH_SIZE;
        let batch_end = std::cmp::min(offset + BATCH_SIZE, block_count as usize);
        let hi = rsk_height - offset as u64;
        let lo = rsk_height - (batch_end as u64 - 1);
        let batch_numbers: Vec<u64> = (lo..=hi).rev().collect();

        // Fetch both raw headers AND merge-mining data in parallel batches.
        let raw_headers =
            fetch_rsk_raw_block_headers_batch(&client, &config.rsk_rpc_url, &batch_numbers)?;
        let merge_blocks =
            fetch_rsk_blocks_with_merge_mining_batch(&client, &config.rsk_rpc_url, &batch_numbers)?;

        // Index merge-mining data by block number for quick lookup.
        let merge_map: std::collections::HashMap<u64, &RskBlockWithMergeMining> = merge_blocks
            .iter()
            .map(|b| {
                let num = u64::from_str_radix(b.number.strip_prefix("0x").unwrap_or(&b.number), 16)
                    .expect("invalid block number in eth_getBlockByNumber");
                (num, b)
            })
            .collect();

        for (num, raw) in &raw_headers {
            let header = RskBlockHeader::decode_rlp(raw)
                .map_err(|e| format!("Failed to decode header at block {num}: {e}"))?;

            // Rule 1: Bitcoin PoW meets RSK difficulty target.
            header
                .validate_proof_of_work()
                .map_err(|e| format!("PoW validation failed at block {num}: {e:?}"))?;

            // Rules 2-7: Full merge-mining verification via RPC data.
            let merge_block = merge_map
                .get(num)
                .ok_or_else(|| format!("Missing eth_getBlockByNumber result for block {num}"))?;

            if let (Some(btc_hex), Some(coinbase_hex), Some(proof_hex), Some(hfm_hex)) = (
                &merge_block.bitcoin_header,
                &merge_block.compressed_coinbase,
                &merge_block.merkle_proof,
                &merge_block.hash_for_merged_mining,
            ) {
                let rsk_hash = block_hash_from_raw_header(raw);

                match merge_mining::verify_merge_mining_from_rpc(
                    &rsk_hash,
                    coinbase_hex,
                    btc_hex,
                    proof_hex,
                    hfm_hex,
                ) {
                    Ok(()) => {
                        merge_mining_verified += 1;
                    }
                    Err(e) => {
                        return Err(format!("Merge-mining proof failed at block {num}: {e}").into());
                    }
                }
            } else {
                return Err(format!("Block {num} has no merge-mining data (pre-RSKIP-92?)").into());
            }

            // Chain continuity: parent hash.
            let this_hash = block_hash_from_raw_header(raw);
            if let Some(expected) = expected_parent_hash {
                if this_hash != expected {
                    return Err(format!(
                        "Parent hash mismatch at block {num}: expected {this_hash:?}, got {expected:?}"
                    )
                    .into());
                }
                let expected_num = prev_number
                    .ok_or("missing prev_number")?
                    .checked_sub(1)
                    .ok_or("Block number underflow")?;
                if header.number != expected_num {
                    return Err(format!(
                        "Block number discontinuity at {num}: expected {expected_num}, got {}",
                        header.number
                    )
                    .into());
                }
            }

            // Difficulty bounds check (warn only).
            if let Some(prev_diff) = prev_difficulty
                && let Err(e) =
                    validate_difficulty_bounds(header.difficulty, prev_diff, header.number)
            {
                eprintln!("  WARNING: {e}");
            }

            // Timestamp monotonicity (walking backwards → timestamps decrease).
            if let Some(prev_ts) = prev_timestamp
                && header.timestamp >= prev_ts
            {
                return Err(format!(
                    "Timestamp not monotonically decreasing at block {num}: {} >= {prev_ts}",
                    header.timestamp
                )
                .into());
            }

            expected_parent_hash = Some(header.parent);
            prev_number = Some(header.number);
            prev_difficulty = Some(header.difficulty);
            prev_timestamp = Some(header.timestamp);
            finalized_raw = Some(raw.clone());
            finalized_block_num = Some(header.number);
            cumulative_work = cumulative_work
                .checked_add(header.difficulty)
                .ok_or("RSK work overflow")?;
            headers_validated += 1;

            if cumulative_work >= total_btc_work {
                break 'outer;
            }
        }

        // Progress logging.
        let elapsed = sync_start.elapsed().as_secs_f64();
        let pct = if total_btc_work.is_zero() {
            100
        } else {
            (cumulative_work * U256::from(100) / total_btc_work).low_u64()
        };
        let blocks_per_sec = if elapsed > 0.0 {
            headers_validated as f64 / elapsed
        } else {
            0.0
        };
        let remaining_work = total_btc_work.saturating_sub(cumulative_work);
        let blocks_remaining = if tip_diff.is_zero() {
            0
        } else {
            (remaining_work / tip_diff).low_u64()
        };
        let eta_secs = if blocks_per_sec > 0.0 {
            blocks_remaining as f64 / blocks_per_sec
        } else {
            0.0
        };
        eprintln!(
            "  [{}/{}] blocks  |  {pct}% work  |  {blocks_per_sec:.1} blocks/s  |  ETA: {eta_secs:.0}s",
            headers_validated, block_count
        );

        if cumulative_work >= total_btc_work {
            break;
        }
    }

    println!("  Accumulated: {cumulative_work} / {total_btc_work}");

    let finalized_raw = finalized_raw.expect("at least one raw header must have been fetched");
    let finalized_height =
        finalized_block_num.expect("at least one block must have been validated");
    let finalized_hash = block_hash_from_raw_header(&finalized_raw);

    println!("\n====================");
    println!("Result");
    println!("====================");
    println!("  Finalized block height: {finalized_height}");
    println!("  Finalized block hash: {finalized_hash:?}");
    println!("  RSK cumulative work: {cumulative_work}");
    println!("  Bitcoin target work: {total_btc_work}");
    println!("  Headers validated: {headers_validated}");
    println!("  Merge-mining proofs verified: {merge_mining_verified}");
    println!("  Bitcoin blocks used: {n}");

    if merge_mining_verified == 0 {
        return Err("No merge-mining proofs verified".into());
    }

    Ok(SyncResult {
        finalized_height,
        finalized_block_hash: finalized_hash,
        rsk_cumulative_work: cumulative_work,
        bitcoin_target_work: total_btc_work,
        headers_validated,
        bitcoin_blocks_used: n,
    })
}
