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

use std::time::{Duration, Instant};

use bitcoin::block::Header as BitcoinHeader;
use bitcoin::consensus::Decodable;
use primitive_types::{H256, U256};
use reqwest::blocking::Client;
use serde::Deserialize;
use sha3::{Digest, Keccak256};

use crate::block_header::RskBlockHeader;

const DEFAULT_TARGET_BITCOIN_BLOCKS: u64 = 144;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const BATCH_SIZE: usize = 100;

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

/// Minimal RSK block representation for JSON-RPC deserialization.
/// Only the fields needed for `RskBlockHeader` conversion are populated.
#[derive(Deserialize)]
struct RskRpcBlock {
    #[serde(rename = "number", deserialize_with = "deserialize_hex_u64")]
    number: u64,
    #[serde(rename = "parentHash", deserialize_with = "deserialize_hex_h256")]
    parent: H256,
    #[serde(rename = "difficulty", deserialize_with = "deserialize_hex_u256")]
    difficulty: U256,
    #[serde(rename = "timestamp", deserialize_with = "deserialize_hex_u64")]
    timestamp: u64,
    #[serde(rename = "sha3Uncles", deserialize_with = "deserialize_hex_h256")]
    uncles_hash: H256,
    #[serde(rename = "miner", deserialize_with = "deserialize_hex_bytes_20")]
    coinbase: [u8; 20],
    #[serde(rename = "stateRoot", deserialize_with = "deserialize_hex_h256")]
    state_root: H256,
    #[serde(rename = "transactionsRoot", deserialize_with = "deserialize_hex_h256")]
    tx_trie_root: H256,
    #[serde(rename = "receiptsRoot", deserialize_with = "deserialize_hex_h256")]
    receipt_trie_root: H256,
    #[serde(rename = "logsBloom", deserialize_with = "deserialize_hex_bytes")]
    extension_data: Vec<u8>,
    #[serde(rename = "gasLimit", deserialize_with = "deserialize_hex_bytes")]
    gas_limit: Vec<u8>,
    #[serde(rename = "gasUsed", deserialize_with = "deserialize_hex_u64")]
    gas_used: u64,
    #[serde(rename = "extraData", deserialize_with = "deserialize_hex_bytes")]
    extra_data: Vec<u8>,
    #[serde(rename = "paidFees", deserialize_with = "deserialize_hex_u256")]
    paid_fees: U256,
    #[serde(
        rename = "minimumGasPrice",
        deserialize_with = "deserialize_hex_u256_option"
    )]
    minimum_gas_price: Option<U256>,
    #[allow(dead_code)]
    #[serde(
        rename = "rskPteEdges",
        default,
        deserialize_with = "deserialize_optional_u16_vec"
    )]
    rsk_pte_edges: Option<Vec<u16>>,
    #[serde(
        rename = "uncles",
        deserialize_with = "deserialize_vec_hex_h256",
        default
    )]
    uncles: Vec<H256>,
    #[serde(
        rename = "bitcoinMergedMiningHeader",
        deserialize_with = "deserialize_hex_bytes"
    )]
    bitcoin_merged_mining_header: Vec<u8>,
}

impl From<RskRpcBlock> for RskBlockHeader {
    fn from(b: RskRpcBlock) -> Self {
        let bitcoin_merged_mining_header =
            BitcoinHeader::consensus_decode(&mut b.bitcoin_merged_mining_header.as_slice())
                .expect("Invalid Bitcoin header in RSK block — is the RPC returning full headers?");

        // Normalize gas_limit: strip leading zero bytes so RLP encodes it as
        // an integer, matching the RSK node's encoding.
        let gas_limit = {
            let mut bytes = b.gas_limit;
            while bytes.first() == Some(&0) && bytes.len() > 1 {
                bytes.remove(0);
            }
            bytes
        };

        // Normalize logsBloom: pad or truncate to exactly 256 bytes so the
        // RLP encoding matches regardless of what the RPC returns.
        let mut extension_data = b.extension_data;
        extension_data.resize(256, 0);

        RskBlockHeader {
            number: b.number,
            parent: b.parent,
            difficulty: b.difficulty,
            timestamp: b.timestamp,
            uncles_hash: b.uncles_hash,
            coinbase: b.coinbase,
            state_root: b.state_root,
            tx_trie_root: b.tx_trie_root,
            receipt_trie_root: b.receipt_trie_root,
            extension_data,
            gas_limit,
            gas_used: b.gas_used,
            extra_data: b.extra_data,
            paid_fees: b.paid_fees,
            minimum_gas_price: b.minimum_gas_price,
            uncles: b.uncles,
            // rskPteEdges determines extension encoding version:
            //   null/omitted → None → V0 (raw logsBloom)
            //   [] or [edges] → Some(vec![...]) → V1 (hashed extension)
            // For hash calculation, pass through the RPC value as-is.
            rsk_pte_edges: b.rsk_pte_edges,
            bitcoin_merged_mining_header,
        }
    }
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

/// Fetch a single RSK block header by number via `eth_getBlockByNumber`.
pub fn fetch_rsk_block(
    client: &Client,
    rpc_url: &str,
    block_number: u64,
) -> Result<RskBlockHeader, Box<dyn std::error::Error>> {
    let hex_number = format!("0x{block_number:x}");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [hex_number, false],
        "id": 1
    });

    let resp: JsonRpcResponse<RskRpcBlock> = client.post(rpc_url).json(&body).send()?.json()?;

    if let Some(err) = resp.error {
        return Err(format!("RPC error at block {block_number}: {}", err.message).into());
    }

    resp.result
        .map(RskBlockHeader::from)
        .ok_or_else(|| format!("Block {block_number} not found").into())
}

// ── Core Algorithm ──────────────────────────────────────────────────────────

/// Run the light client sync.
///
/// Fetches Bitcoin headers to calculate the target work, then walks
/// backwards from the RSK chain tip accumulating difficulty until the
/// target is met. Returns a [`SyncResult`] with the finalized block info.
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
    println!("  Estimated blocks needed: {blocks_needed} (from {start_height} to {rsk_height})\n");

    let mut cumulative_work = U256::zero();
    let mut expected_parent_hash: Option<H256> = None;
    let mut prev_number: Option<u64> = None;
    let mut finalized_raw: Option<Vec<u8>> = None;
    let mut headers_validated: u64 = 0;

    // Build the list of block numbers to fetch (descending order)
    let block_count = rsk_height - start_height + 1;
    let num_batches = (block_count as usize + BATCH_SIZE - 1) / BATCH_SIZE;
    let sync_start = Instant::now();

    // Process in batches (descending from tip)
    for batch_idx in 0..num_batches {
        let offset = batch_idx * BATCH_SIZE;
        let batch_end = std::cmp::min(offset + BATCH_SIZE, block_count as usize);
        let hi = rsk_height - offset as u64;
        let lo = rsk_height - (batch_end as u64 - 1);
        let batch_numbers: Vec<u64> = (lo..=hi).rev().collect();

        let raw_headers = fetch_rsk_raw_block_headers_batch(
            &client,
            &config.rsk_rpc_url,
            &batch_numbers,
        )?;

        for (num, raw) in raw_headers {
            let header = RskBlockHeader::decode_rlp(&raw)
                .map_err(|e| format!("Failed to decode header at block {num}: {e}"))?;

            header
                .validate_proof_of_work()
                .map_err(|e| format!("PoW validation failed at block {num}: {e:?}"))?;

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

            expected_parent_hash = Some(header.parent);
            prev_number = Some(header.number);
            finalized_raw = Some(raw);
            cumulative_work = cumulative_work
                .checked_add(header.difficulty)
                .ok_or("RSK work overflow")?;
            headers_validated += 1;

            if cumulative_work >= total_btc_work {
                break;
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
    println!("  Bitcoin blocks used: {n}");

    Ok(SyncResult {
        finalized_height,
        finalized_block_hash: finalized_hash,
        rsk_cumulative_work: cumulative_work,
        bitcoin_target_work: total_btc_work,
        headers_validated,
        bitcoin_blocks_used: n,
    })
}

// ── Deserialization Helpers ─────────────────────────────────────────────────

fn deserialize_hex_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

fn deserialize_hex_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    U256::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

fn deserialize_hex_u256_option<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => {
            let s = s.strip_prefix("0x").unwrap_or(&s);
            U256::from_str_radix(s, 16)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
        None => Ok(None),
    }
}

fn deserialize_hex_h256<'de, D>(deserializer: D) -> Result<H256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
    if bytes.len() != 32 {
        return Err(serde::de::Error::custom(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(H256::from_slice(&bytes))
}

fn deserialize_hex_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    hex::decode(s).map_err(serde::de::Error::custom)
}

fn deserialize_hex_bytes_20<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
    if bytes.len() != 20 {
        return Err(serde::de::Error::custom(format!(
            "expected 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut array = [0u8; 20];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn deserialize_vec_hex_h256<'de, D>(deserializer: D) -> Result<Vec<H256>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let strings: Vec<String> = Deserialize::deserialize(deserializer)?;
    strings
        .iter()
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom(format!(
                    "Expected 32 bytes, got {}",
                    bytes.len()
                )));
            }
            Ok(H256::from_slice(&bytes))
        })
        .collect()
}

fn deserialize_optional_u16_vec<'de, D>(deserializer: D) -> Result<Option<Vec<u16>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Vec<u16>>::deserialize(deserializer)
}
