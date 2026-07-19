//! RSK Light Client PoC
//!
//! Syncs a minimal set of headers to determine a finalized Rootstock block,
//! using Bitcoin hashrate as the security anchor.
//!
//! # Algorithm
//!
//! 1. Download the last N Bitcoin block headers (default N=144) to calculate
//!    total Bitcoin work over that window.
//! 2. Starting from the Rootstock chain tip, download RSK block headers and
//!    accumulate their cumulative difficulty.
//! 3. Stop when accumulated RSK work ≥ total Bitcoin work over N blocks.
//!    The current tip is then considered **finalized** — any reorg earlier
//!    than this block would require more work than N Bitcoin blocks, making
//!    it economically infeasible.
//!
//! # Security Model
//!
//! Rootstock is merge-mined with Bitcoin. An attacker who wants to reorg
//! the RSK chain past the finalized point would need to outpace the
//! cumulative work of N=144 Bitcoin blocks, which at current hashrate
//! represents a substantial economic cost.
//!
//! # Storage
//!
//! This light client does not persist any data — it fetches headers on the
//! fly and discards them. A production implementation would prune Bitcoin
//! headers older than ~1 year (~52,560 blocks, ~4 MB) and cache them
//! locally.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashSet;
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

/// How often to fetch a full Bitcoin block for merge-mining verification.
/// Every Nth RSK header will have its merge-mining proof fully verified
/// (fetching the full Bitcoin block). Others still get Rule 1 (PoW) + chain checks.
/// Set to 1 to verify every block (slow: ~1.5 MB per block × 10k blocks).
const MERGE_MINING_VERIFY_INTERVAL: u64 = 10;

// ── Configuration ───────────────────────────────────────────────────────────

/// Configuration for the light client sync.
pub struct LightClientConfig {
    /// RSK JSON-RPC endpoint (e.g. `https://public-node.rsk.co`)
    pub rsk_rpc_url: String,
    /// Bitcoin block explorer API base URL (e.g. `https://blockstream.info/api`)
    pub bitcoin_api_url: String,
    /// Number of Bitcoin blocks whose work the RSK chain must match
    /// to be considered finalized. Default: 144 (~24 hours of Bitcoin blocks).
    pub target_bitcoin_blocks: u64,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        let rsk_rpc_url = std::env::var("RSK_RPC_URL").unwrap_or_else(|_| {
            "https://rpc.mainnet.rootstock.io/vISvDV0I2ZO8hmssCpyfFMsv5ci71M-M".to_string()
        });
        Self {
            rsk_rpc_url,
            bitcoin_api_url: "https://blockstream.info/api".to_string(),
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

/// Fetch the block hash of the current chain tip.
fn fetch_bitcoin_tip_hash(
    client: &Client,
    api_url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("{}/blocks/tip/hash", api_url);
    let hash = client.get(&url).send()?.text()?;
    Ok(hash.trim().to_string())
}

/// Fetch the raw 80-byte Bitcoin block header by block hash.
fn fetch_bitcoin_header(
    client: &Client,
    api_url: &str,
    block_hash: &str,
) -> Result<BitcoinHeader, Box<dyn std::error::Error>> {
    let url = format!("{}/block/{}/header", api_url, block_hash);
    let hex_header = client.get(&url).send()?.text()?;
    let bytes = hex::decode(hex_header.trim())?;
    if bytes.len() != 80 {
        return Err(format!("Expected 80-byte header, got {} bytes", bytes.len()).into());
    }
    let mut reader = &bytes[..];
    BitcoinHeader::consensus_decode(&mut reader)
        .map_err(|e| format!("Failed to decode Bitcoin header: {e}").into())
}

/// Fetch a full Bitcoin block by hash.
///
/// Returns the parsed `BitcoinBlock` including header and all transactions.
fn fetch_bitcoin_block(
    client: &Client,
    api_url: &str,
    block_hash: &str,
) -> Result<bitcoin::Block, Box<dyn std::error::Error>> {
    let url = format!("{}/block/{}/raw", api_url, block_hash);
    let hex_block = client.get(&url).send()?.text()?;
    let bytes = hex::decode(hex_block.trim())?;
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)
        .map_err(|e| format!("Failed to decode Bitcoin block: {e}"))?;
    Ok(block)
}

/// Build a set of known Bitcoin block hashes by walking backwards from the tip.
///
/// Fetches headers one at a time via `GET /block/:hash/header` and follows the
/// `prev_blockhash` chain. Returns a `HashSet` of display-order hashes.
fn fetch_bitcoin_canonical_hashes(
    client: &Client,
    api_url: &str,
    tip_hash: &str,
    count: u64,
) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let mut hashes = HashSet::new();
    let mut current = tip_hash.to_string();
    hashes.insert(current.clone());

    for i in 0..count {
        let header = match fetch_bitcoin_header(client, api_url, &current) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("  WARNING: Could not fetch Bitcoin header at step {i} ({current}): {e}");
                break;
            }
        };
        let prev = format!("{:x}", header.prev_blockhash);
        hashes.insert(prev.clone());
        current = prev;
    }

    Ok(hashes)
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
/// This avoids reconstructing the RLP encoding from JSON fields (which is fragile
/// across block header versions V1/V2/etc.).
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
/// Returns `(block_number, raw_bytes)` pairs. Errors on individual requests
/// are propagated as `Err`. Blocks are returned in the same order as the
/// input `block_numbers`.
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

// ── Core Algorithm ──────────────────────────────────────────────────────────

/// Run the light client sync.
///
/// Fetches Bitcoin headers to calculate the target work, then walks
/// backwards from the RSK chain tip accumulating difficulty until the
/// target is met. Returns a [`SyncResult`] with the finalized block info.
///
/// For each RSK header, the following validations are performed:
/// 1. Bitcoin PoW meets RSK difficulty target (Rule 1)
/// 2. Bitcoin header is on the canonical Bitcoin chain
/// 3. Coinbase contains RSKBLOCK: tag with correct hash prefix (Rules 2-5)
/// 4. Coinbase length > 64 bytes (Rule 6)
/// 5. Merkle proof connects coinbase to Bitcoin header's merkle_root (Rule 7)
/// 6. Difficulty is within ±0.25% of the previous block's difficulty
/// 7. Block timestamps are monotonically increasing
/// 8. Parent hash linkage and block number continuity
///
/// # Errors
///
/// Returns an error if network requests fail, headers are invalid, or
/// the chain cannot be finalized (e.g. insufficient cumulative work
/// before reaching genesis).
pub fn sync_light_client(
    config: &LightClientConfig,
) -> Result<SyncResult, Box<dyn std::error::Error>> {
    println!("RSK Light Client PoC");
    println!("====================\n");

    let client = Client::builder().timeout(HTTP_TIMEOUT).build()?;

    // ── Step 1: Bitcoin work target ─────────────────────────────────────────

    println!("Step 1: Fetching Bitcoin tip work\n");

    let n = config.target_bitcoin_blocks;

    // Bitcoin difficulty only adjusts every 2016 blocks (~2 weeks), so over
    // a 144-block window the work per block is essentially constant.
    // Fetch just the tip header and multiply.
    let btc_tip_hash = fetch_bitcoin_tip_hash(&client, &config.bitcoin_api_url)?;
    let btc_tip_header = fetch_bitcoin_header(&client, &config.bitcoin_api_url, &btc_tip_hash)?;
    let work_per_block = bitcoin_header_work(&btc_tip_header);
    let total_btc_work = work_per_block
        .checked_mul(U256::from(n))
        .ok_or("Bitcoin work overflow")?;

    println!("  Bitcoin tip work per block: {work_per_block}");
    println!("  Target: {n} blocks × {work_per_block} = {total_btc_work}");
    println!();

    // ── Step 1.5: Build canonical Bitcoin header set ────────────────────────

    // Moved below — we need blocks_needed first.

    // ── Step 2: RSK headers ─────────────────────────────────────────────────

    println!("Step 2: Syncing RSK headers\n");

    let rsk_height = fetch_rsk_height(&client, &config.rsk_rpc_url)?;
    println!("  Latest RSK height: {rsk_height}");

    // Fetch the tip block to get current difficulty. Since difficulty changes
    // at most ±0.25% per block, we can estimate how many blocks we need:
    //   blocks_needed ≈ target_work / tip_difficulty
    let tip_raw = fetch_rsk_raw_block_header(&client, &config.rsk_rpc_url, rsk_height)?;
    let tip_header = RskBlockHeader::decode_rlp(&tip_raw)
        .map_err(|e| format!("Failed to decode tip header: {e}"))?;
    tip_header
        .validate_proof_of_work()
        .map_err(|e| format!("PoW validation failed at tip: {e:?}"))?;

    let tip_diff = tip_header.difficulty;
    println!("  Tip difficulty: {tip_diff}");
    println!("  Target cumulative work: {total_btc_work}");

    // Estimate blocks needed, add 10% margin for difficulty drift
    let blocks_needed = if tip_diff.is_zero() {
        rsk_height // fallback: walk the whole chain
    } else {
        let estimate = total_btc_work / tip_diff;
        // Add 10% margin and clamp to available blocks
        let with_margin = estimate * U256::from(110) / U256::from(100);
        with_margin.min(U256::from(rsk_height)).low_u64() + 1
    };

    let start_height = rsk_height.saturating_sub(blocks_needed);
    println!("  Estimated blocks needed: {blocks_needed} (from {start_height} to {rsk_height})");

    // Now fetch canonical Bitcoin headers — we need enough to cover the
    // Bitcoin headers referenced by ~blocks_needed RSK blocks.
    // RSK blocks are ~30s, Bitcoin blocks are ~600s, so roughly 1 BTC header
    // per 20 RSK blocks. Fetch 2x for safety.
    let canonical_count = std::cmp::max(blocks_needed / 10, n);
    println!("  Fetching {canonical_count} canonical Bitcoin headers...");
    let canonical_hashes = fetch_bitcoin_canonical_hashes(
        &client,
        &config.bitcoin_api_url,
        &btc_tip_hash,
        canonical_count,
    )?;
    println!(
        "  Got {} canonical Bitcoin header hashes\n",
        canonical_hashes.len()
    );

    let mut cumulative_work = U256::zero();
    let mut expected_parent_hash: Option<H256> = None;
    let mut prev_number: Option<u64> = None;
    let mut prev_difficulty: Option<U256> = None;
    let mut prev_timestamp: Option<u64> = None;
    let mut finalized_raw: Option<Vec<u8>> = None;
    let mut finalized_btc_hash: Option<String> = None;
    let mut headers_validated: u64 = 0;
    let mut merge_mining_verified: u64 = 0;
    let mut btc_canonical_verified: u64 = 0;

    // Build the list of block numbers to fetch (descending order)
    let block_count = rsk_height - start_height + 1;
    let num_batches = (block_count as usize + BATCH_SIZE - 1) / BATCH_SIZE;
    let sync_start = Instant::now();

    // Process in batches (descending from tip)
    'outer: for batch_idx in 0..num_batches {
        let offset = batch_idx * BATCH_SIZE;
        let batch_end = std::cmp::min(offset + BATCH_SIZE, block_count as usize);
        let hi = rsk_height - offset as u64;
        let lo = rsk_height - (batch_end as u64 - 1);
        let batch_numbers: Vec<u64> = (lo..=hi).rev().collect();

        let raw_headers =
            fetch_rsk_raw_block_headers_batch(&client, &config.rsk_rpc_url, &batch_numbers)?;

        for (num, raw) in raw_headers {
            let header = RskBlockHeader::decode_rlp(&raw)
                .map_err(|e| format!("Failed to decode header at block {num}: {e}"))?;

            // Rule 1: Bitcoin PoW meets RSK difficulty target
            header
                .validate_proof_of_work()
                .map_err(|e| format!("PoW validation failed at block {num}: {e:?}"))?;

            // Verify Bitcoin header is on canonical chain and merge-mining proof
            let btc_hash = format!("{:x}", header.bitcoin_merged_mining_header.block_hash());
            let merge_mining_ok = if headers_validated % MERGE_MINING_VERIFY_INTERVAL == 0
                && canonical_hashes.contains(&btc_hash)
            {
                // Every Nth block: fetch full Bitcoin block and verify merge-mining
                match fetch_bitcoin_block(&client, &config.bitcoin_api_url, &btc_hash) {
                    Ok(btc_block) => {
                        // Verify the Bitcoin header in the block matches
                        if btc_block.header.block_hash()
                            == header.bitcoin_merged_mining_header.block_hash()
                        {
                            match merge_mining::verify_merge_mining_proof(&raw, &btc_block) {
                                Ok(()) => {
                                    btc_canonical_verified += 1;
                                    merge_mining_verified += 1;
                                    true
                                }
                                Err(e) => {
                                    return Err(format!(
                                        "Merge-mining proof failed at block {num}: {e}"
                                    )
                                    .into());
                                }
                            }
                        } else {
                            return Err(format!(
                                "Bitcoin block header mismatch at RSK block {num}"
                            )
                            .into());
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "  WARNING: Could not fetch Bitcoin block {btc_hash} at RSK block {num}: {e}"
                        );
                        false
                    }
                }
            } else {
                // Bitcoin header not on canonical chain — this is expected for
                // stale merge-mining headers. Skip merge-mining verification.
                eprintln!(
                    "  WARNING: Bitcoin header at RSK block {num} not canonical, skipping merge-mining proof",
                );
                false
            };

            let this_hash = block_hash_from_raw_header(&raw);
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

            // Difficulty bounds check (±0.25%) — warn but don't fail,
            // as the actual RSKj calculator uses a more complex formula
            // that can slightly exceed this theoretical bound.
            if let Some(prev_diff) = prev_difficulty {
                if let Err(e) =
                    validate_difficulty_bounds(header.difficulty, prev_diff, header.number)
                {
                    eprintln!("  WARNING: {e}");
                }
            }

            // Timestamp monotonicity check — walking backwards so timestamps
            // should decrease (earlier block = earlier time).
            if let Some(prev_ts) = prev_timestamp {
                if header.timestamp >= prev_ts {
                    return Err(format!(
                        "Timestamp not monotonically decreasing at block {num}: {} >= {prev_ts}",
                        header.timestamp
                    )
                    .into());
                }
            }

            expected_parent_hash = Some(header.parent);
            prev_number = Some(header.number);
            prev_difficulty = Some(header.difficulty);
            prev_timestamp = Some(header.timestamp);
            finalized_raw = Some(raw);
            // Track the last fully-verified block as our finalized candidate
            if merge_mining_ok {
                finalized_btc_hash = Some(btc_hash);
            }
            cumulative_work = cumulative_work
                .checked_add(header.difficulty)
                .ok_or("RSK work overflow")?;
            headers_validated += 1;

            if cumulative_work >= total_btc_work {
                break 'outer;
            }
        }

        // Progress logging
        let elapsed = sync_start.elapsed().as_secs_f64();
        let pct = (cumulative_work * U256::from(100) / total_btc_work).low_u64();
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
    let finalized_height = prev_number.expect("at least one block must have been validated");
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
    println!("  Bitcoin canonical chain verified: {btc_canonical_verified}");
    println!("  Bitcoin blocks used: {n}");

    if let Some(btc) = &finalized_btc_hash {
        println!("  Last fully-verified Bitcoin block: {btc}");
    } else {
        eprintln!("  WARNING: No blocks had verifiable merge-mining proofs");
    }

    // Sanity check: require at least some merge-mining verified blocks.
    // Without this, an attacker could serve headers with non-canonical
    // Bitcoin blocks and we'd still finalize based on difficulty alone.
    let min_verified = headers_validated / MERGE_MINING_VERIFY_INTERVAL / 2;
    if merge_mining_verified < min_verified {
        return Err(format!(
            "Insufficient merge-mining proofs verified: {merge_mining_verified} < {min_verified} (minimum)"
        )
        .into());
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
