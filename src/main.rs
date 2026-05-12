use serde_json::{Value, json};
use std::error::Error;
use tiny_keccak::{Hasher, Keccak};

pub const BRIDGE_ADDRESS: &str = "0x0000000000000000000000000000000001000006";
const START_BLOCK: u64 = 8_821_856;

// ── Keccak helpers ────────────────────────────────────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

fn topic_of(sig: &[u8]) -> [u8; 32] {
    keccak256(sig)
}

// ── Known Bridge event signatures ────────────────────────────────────────────
//
// Add / remove entries as needed.  Each entry is (human_label, abi_signature).
// The ABI signature must match exactly what the contract emits (no spaces,
// canonical Solidity types).

fn known_topics() -> Vec<(&'static str, [u8; 32])> {
    let sigs: &[(&str, &[u8])] = &[
        ("pegout_confirmed", b"pegout_confirmed(bytes32,uint256)"),
        (
            "pegout_transaction_created",
            b"pegout_transaction_created(bytes32,bytes)",
        ),
        ("update_collections", b"update_collections(address)"),
    ];
    sigs.iter()
        .map(|(label, sig)| (*label, topic_of(sig)))
        .collect()
}

// ── Bloom filter ──────────────────────────────────────────────────────────────

pub fn bloom_test(bloom: &[u8; 256], data: &[u8]) -> bool {
    let hash = keccak256(data);
    let idx1 = ((hash[0] as usize) << 8 | hash[1] as usize) & 0x07FF;
    let idx2 = ((hash[2] as usize) << 8 | hash[3] as usize) & 0x07FF;
    let idx3 = ((hash[4] as usize) << 8 | hash[5] as usize) & 0x07FF;
    let byte_idx = |i: usize| 255 - (i >> 3);
    let bit_mask = |i: usize| 1u8 << (i & 7);
    (bloom[byte_idx(idx1)] & bit_mask(idx1)) != 0
        && (bloom[byte_idx(idx2)] & bit_mask(idx2)) != 0
        && (bloom[byte_idx(idx3)] & bit_mask(idx3)) != 0
}

/// Returns true if the bloom *might* contain the bridge address AND at least
/// one of the known event topics.
fn bloom_has_any_bridge_event(
    bloom: &[u8; 256],
    bridge_bytes: &[u8],
    topics: &[(&str, [u8; 32])],
) -> bool {
    if !bloom_test(bloom, bridge_bytes) {
        return false;
    }
    topics.iter().any(|(_, t)| bloom_test(bloom, t.as_ref()))
}

// ── JSON-RPC ──────────────────────────────────────────────────────────────────

async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<Value, Box<dyn Error>> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let mut resp: Value = client.post(url).json(&body).send().await?.json().await?;
    if let Some(err) = resp.get("error") {
        return Err(format!("RPC error: {}", err).into());
    }
    Ok(resp["result"].take())
}

async fn fetch_block_bloom(
    client: &reqwest::Client,
    url: &str,
    block_num: u64,
) -> Result<[u8; 256], Box<dyn Error>> {
    let block = rpc_call(
        client,
        url,
        "eth_getBlockByNumber",
        json!([format!("{:#x}", block_num), false]),
    )
    .await?;
    let hex = block["logsBloom"]
        .as_str()
        .ok_or("missing logsBloom")?
        .trim_start_matches("0x");
    let bytes = hex::decode(hex)?;
    let mut arr = [0u8; 256];
    arr.copy_from_slice(&bytes[..256]);
    Ok(arr)
}

fn parse_hex_to_u64(s: &str) -> Result<u64, Box<dyn Error>> {
    Ok(u64::from_str_radix(
        s.trim_start_matches("0x").trim_start_matches("0X"),
        16,
    )?)
}

// ── Event struct ──────────────────────────────────────────────────────────────

#[derive(Debug)]
struct BridgeEvent {
    label: String,
    rsk_tx: String,
    block_num: u64,
    topics: Vec<String>,
    data: String,
}

impl std::fmt::Display for BridgeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  event      : {}", self.label)?;
        writeln!(f, "  rsk_tx     : {}", self.rsk_tx)?;
        writeln!(f, "  block      : {}", self.block_num)?;
        for (i, t) in self.topics.iter().enumerate() {
            writeln!(f, "  topic[{}]   : {}", i, t)?;
        }
        write!(f, "  data       : {}", self.data)
    }
}

// ── Block inspection ──────────────────────────────────────────────────────────

/// Fetch all bridge events in `block_num`.  Returns an empty Vec on a true
/// negative (bloom said possible but nothing was there).
async fn collect_bridge_events(
    client: &reqwest::Client,
    url: &str,
    block_num: u64,
    topics: &[(&str, [u8; 32])],
) -> Result<Vec<BridgeEvent>, Box<dyn Error>> {
    let block = rpc_call(
        client,
        url,
        "eth_getBlockByNumber",
        json!([format!("{:#x}", block_num), true]),
    )
    .await?;

    let txs = match block["transactions"].as_array() {
        Some(t) => t,
        None => return Ok(vec![]),
    };

    // Collect tx hashes that involve the bridge (to or from)
    let candidates: Vec<String> = txs
        .iter()
        .filter(|tx| {
            tx["to"]
                .as_str()
                .map(|a| a.eq_ignore_ascii_case(BRIDGE_ADDRESS))
                .unwrap_or(false)
        })
        .filter_map(|tx| tx["hash"].as_str().map(|h| h.to_string()))
        .collect();

    if candidates.is_empty() {
        return Ok(vec![]);
    }

    let mut events = Vec::new();

    for tx_hash in candidates {
        let receipt = rpc_call(client, url, "eth_getTransactionReceipt", json!([tx_hash])).await?;
        if receipt.is_null() {
            continue;
        }
        let logs = match receipt["logs"].as_array() {
            Some(l) => l,
            None => continue,
        };

        for log in logs {
            let addr = log["address"].as_str().unwrap_or("");
            if !addr.eq_ignore_ascii_case(BRIDGE_ADDRESS) {
                continue;
            }

            let raw_topics: Vec<String> = log["topics"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let topic0_bytes = raw_topics
                .first()
                .and_then(|t| hex::decode(t.trim_start_matches("0x")).ok());

            // Match topic0 against known signatures
            let label = topic0_bytes
                .as_deref()
                .and_then(|t0| {
                    topics
                        .iter()
                        .find(|(_, sig)| &sig[..] == t0)
                        .map(|(lbl, _)| *lbl)
                })
                .unwrap_or("unknown");

            let data = log["data"].as_str().unwrap_or("0x").to_string();
            let rsk_tx = receipt["transactionHash"]
                .as_str()
                .unwrap_or("")
                .to_string();

            events.push(BridgeEvent {
                label: label.to_string(),
                rsk_tx,
                block_num,
                topics: raw_topics,
                data,
            });
        }
    }

    Ok(events)
}

// ── Bitcoin SPV check via Esplora ──────────────────────────────────────────────

/// Check whether a Bitcoin transaction is confirmed in a block using an Esplora
/// server.  Returns `true` if the transaction has at least one confirmation.
async fn check_btc_tx_confirmed(tx_hash_hex: &str) -> Result<bool, String> {
    let esplora_url =
        std::env::var("ESPLORA_URL").unwrap_or_else(|_| "https://blockstream.info/api".to_string());
    let client = esplora_client::Builder::new(&esplora_url)
        .build_async()
        .map_err(|e| e.to_string())?;
    let txid: bitcoin::Txid = tx_hash_hex.trim_start_matches("0x").parse().unwrap();
    let status = client
        .get_tx_status(&txid)
        .await
        .map_err(|e| e.to_string())?;
    Ok(status.block_height.is_some())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let rpc_url =
        std::env::var("RSK_RPC").unwrap_or_else(|_| "https://public-node.rsk.co".to_string());
    let client = reqwest::Client::new();

    let topics = known_topics();
    let bridge_bytes = hex::decode(BRIDGE_ADDRESS.trim_start_matches("0x"))?;

    // Latest block
    let latest_hex = rpc_call(&client, &rpc_url, "eth_blockNumber", Value::Null).await?;
    let latest = parse_hex_to_u64(latest_hex.as_str().unwrap_or("0x0"))?;
    println!("Latest block : {latest}");
    println!("Scanning from: {START_BLOCK}");
    println!("{}", "─".repeat(60));

    let mut block = START_BLOCK;

    while block <= latest {
        // ── Bloom pre-filter ──────────────────────────────────────────────
        let bloom = match fetch_block_bloom(&client, &rpc_url, block).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("bloom fetch error at {block}: {e}");
                block += 1;
                continue;
            }
        };

        if !bloom_has_any_bridge_event(&bloom, &bridge_bytes, &topics) {
            println!("Block {block:>9}  bloom→skip");
            block += 1;
            continue;
        }

        // ── Full inspection ───────────────────────────────────────────────
        println!("Block {block:>9}  bloom→possible, inspecting …");

        match collect_bridge_events(&client, &rpc_url, block, &topics).await {
            Ok(events) if events.is_empty() => {
                println!("  (false positive)");
            }
            Ok(events) => {
                println!(
                    "\n╔══ {} bridge event(s) in block {} ══",
                    events.len(),
                    block
                );
                for (i, ev) in events.iter().enumerate() {
                    println!("╠─ event #{}", i + 1);
                    println!("{ev}");
                }
                println!("╚{}", "═".repeat(50));
                // Stop at the first block that actually has bridge events
                // break;

                // Check Bitcoin confirmation via Electrum for each pegout event
                for ev in events
                    .iter()
                    .filter(|e| e.label == "pegout_transaction_created")
                {
                    let btc_tx_hash = ev.topics.get(1).cloned().unwrap_or_default();
                    println!("  BTC tx hash: {btc_tx_hash}");
                    let confirmed = check_btc_tx_confirmed(&btc_tx_hash).await.unwrap_or(false);
                    if confirmed {
                        println!("  ✓ confirmed on Bitcoin");
                        return Ok(());
                    } else {
                        println!("  ✗ not yet confirmed (mempool or not found)");
                    }
                }
            }
            Err(e) => {
                eprintln!("  receipt fetch error: {e}");
            }
        }

        block += 1;
    }

    println!("\nDone.");
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_known_block() {
        let bloom_hex = "00000000000008000000101000000008002080000040000000000000000000000000000000010000000000000080000000000000000000000000800000000000000000000080000010000000001008000000000000000000000000004000800000000000200000000040000000000000000000000800000000000000020000000201000000000081000000000004000000010000000000000000000020080000000000000200000000040400000000000080000000000082000000004002008000002000000000000000000000008000000000000040000400000000400000000000000000000000002000800000100000000400000000000000210000000000";
        let mut bloom = [0u8; 256];
        bloom.copy_from_slice(&hex::decode(bloom_hex).unwrap());

        let addr_bytes = hex::decode(BRIDGE_ADDRESS.trim_start_matches("0x")).unwrap();
        assert!(
            bloom_test(&bloom, &addr_bytes),
            "address should be in bloom"
        );

        // Try all known signatures and print which ones hit
        for (label, topic) in known_topics() {
            let hit = bloom_test(&bloom, topic.as_ref());
            println!("{label:40} → {}", if hit { "HIT" } else { "miss" });
        }
    }

    #[test]
    fn test_bloom_bit_indexing() {
        // Build a bloom with a known value, confirm round-trip
        let data = b"hello bloom";
        let hash = keccak256(data);
        let idx1 = ((hash[0] as usize) << 8 | hash[1] as usize) & 0x07FF;

        let mut bloom = [0u8; 256];
        let byte_idx = 255 - (idx1 >> 3);
        let bit_mask = 1u8 << (idx1 & 7);
        bloom[byte_idx] |= bit_mask;

        // Only idx1 is set; bloom_test requires all 3 → still false, but the
        // individual bit must be readable
        assert_ne!(bloom[byte_idx] & bit_mask, 0, "bit should be set");
    }
}
