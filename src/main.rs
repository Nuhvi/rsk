use serde_json::Value;
use tiny_keccak::{Hasher, Keccak};

const BRIDGE_ADDRESS: &str = "0x0000000000000000000000000000000001000006";
const SCAN_BLOCKS: u64 = 5000;

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url =
        std::env::var("RSK_RPC").unwrap_or_else(|_| "https://public-node.rsk.co".to_string());
    let client = reqwest::Client::new();

    let pegout_confirmed_topic = keccak256(b"pegout_confirmed(bytes32,uint256)");

    async fn rpc_call(
        client: &reqwest::Client,
        url: &str,
        method: &str,
        params: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let mut resp: Value = client.post(url).json(&body).send().await?.json().await?;
        Ok(resp["result"].take())
    }

    let block_hex = rpc_call(&client, &rpc_url, "eth_blockNumber", Value::Null)
        .await?
        .as_str()
        .unwrap()
        .to_string();
    let latest = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16)?;
    println!("Latest Rootstock block: {}\n", latest);

    let params = serde_json::json!([format!("{:#x}", latest), false]);
    let block = rpc_call(&client, &rpc_url, "eth_getBlockByNumber", params).await?;
    println!("=== Block Header ===");
    println!("Hash:        {}", block["hash"]);
    println!("Parent:      {}", block["parentHash"]);
    println!("Sha3Uncles:  {}", block["sha3Uncles"]);
    println!("Miner:       {}", block["miner"]);
    println!("State Root:  {}", block["stateRoot"]);
    println!("Tx Root:     {}", block["transactionsRoot"]);
    println!("Receipts:    {}", block["receiptsRoot"]);
    println!("Difficulty:  {}", block["difficulty"]);
    println!("Gas Limit:   {}", block["gasLimit"]);
    println!("Gas Used:    {}", block["gasUsed"]);
    println!("Timestamp:   {}", block["timestamp"]);
    println!("Extra Data:  {}", block["extraData"]);
    println!("Mix Hash:    {}", block["mixHash"]);
    println!("Nonce:       {}", block["nonce"]);
    println!();

    let from = latest.saturating_sub(SCAN_BLOCKS);

    let rpc_supports_logs = rpc_call(
        &client,
        &rpc_url,
        "eth_getLogs",
        serde_json::json!([{
            "fromBlock": format!("{:#x}", from),
            "toBlock": format!("{:#x}", latest),
            "address": BRIDGE_ADDRESS,
        }]),
    )
    .await;

    if let Ok(Value::Array(arr)) = &rpc_supports_logs {
        let matched: Vec<&Value> = arr
            .iter()
            .filter(|log| {
                log["topics"]
                    .as_array()
                    .and_then(|t| t.first())
                    .and_then(|t| t.as_str())
                    .and_then(|t| hex::decode(t.strip_prefix("0x").unwrap_or(t)).ok())
                    .map(|b| b.as_slice() == &pegout_confirmed_topic[..])
                    .unwrap_or(false)
            })
            .collect();

        if !matched.is_empty() {
            println!("=== pegout_confirmed Events ===");
            for (i, log) in matched.iter().enumerate() {
                let btc_tx = log["topics"]
                    .as_array()
                    .and_then(|t| t.get(1))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                let raw = log["data"]
                    .as_str()
                    .unwrap_or("0x")
                    .trim_start_matches("0x");
                let created = u64::from_str_radix(raw, 16).unwrap_or(0);
                println!("{}. BTC tx:   {}", i + 1, btc_tx);
                println!(
                    "   RSK tx:   {}",
                    log["transactionHash"].as_str().unwrap_or("")
                );
                println!("   Block:    {}", log["blockNumber"].as_str().unwrap_or(""));
                println!("   Created:  block {}", created);
                println!();
            }
            return Ok(());
        }
        println!(
            "eth_getLogs returned {} logs, none are pegout_confirmed.\n",
            arr.len()
        );
        return Ok(());
    }

    println!(
        "Scanning {} blocks for pegout_confirmed events...\n",
        SCAN_BLOCKS
    );

    let mut found = 0usize;
    let blocks: Vec<u64> = (from..=latest).collect();

    for chunk in blocks.chunks(20) {
        let mut batch = Vec::new();
        for b in chunk {
            batch.push(serde_json::json!({
                "jsonrpc": "2.0",
                "id": b,
                "method": "eth_getBlockByNumber",
                "params": [format!("{:#x}", b), true],
            }));
        }

        let resp: Vec<Value> = match client.post(&rpc_url).json(&batch).send().await {
            Ok(r) => r.json().await.unwrap_or_default(),
            Err(_) => continue,
        };

        let mut bridge_tx_hashes: Vec<String> = Vec::new();

        for item in resp {
            let block = &item["result"];
            if block.is_null() {
                continue;
            }
            let txs = match block["transactions"].as_array() {
                Some(t) => t,
                None => continue,
            };
            for tx in txs {
                if tx["to"]
                    .as_str()
                    .unwrap_or("")
                    .eq_ignore_ascii_case(BRIDGE_ADDRESS)
                {
                    if let Some(h) = tx["hash"].as_str() {
                        bridge_tx_hashes.push(h.to_string());
                    }
                }
            }
        }

        if bridge_tx_hashes.is_empty() {
            continue;
        }

        for tx_chunk in bridge_tx_hashes.chunks(20) {
            let mut rcp_batch: Vec<Value> = Vec::new();
            for (i, h) in tx_chunk.iter().enumerate() {
                rcp_batch.push(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": i + 1,
                    "method": "eth_getTransactionReceipt",
                    "params": [h],
                }));
            }
            let rcp_resp: Vec<Value> = match client.post(&rpc_url).json(&rcp_batch).send().await {
                Ok(r) => r.json().await.unwrap_or_default(),
                Err(_) => continue,
            };
            for item in rcp_resp {
                let receipt = &item["result"];
                if receipt.is_null() {
                    continue;
                }
                let logs = match receipt["logs"].as_array() {
                    Some(l) => l,
                    None => continue,
                };
                for log in logs {
                    if !log["address"]
                        .as_str()
                        .unwrap_or("")
                        .eq_ignore_ascii_case(BRIDGE_ADDRESS)
                    {
                        continue;
                    }
                    let topic0 = log["topics"]
                        .as_array()
                        .and_then(|t| t.first())
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let topic0_bytes =
                        match hex::decode(topic0.strip_prefix("0x").unwrap_or(topic0)) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                    if topic0_bytes.as_slice() != &pegout_confirmed_topic[..] {
                        continue;
                    }

                    found += 1;
                    let btc_tx = log["topics"]
                        .as_array()
                        .and_then(|t| t.get(1))
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let raw = log["data"]
                        .as_str()
                        .unwrap_or("0x")
                        .trim_start_matches("0x");
                    let created = u64::from_str_radix(raw, 16).unwrap_or(0);
                    println!("{}. BTC tx:   {}", found, btc_tx);
                    println!(
                        "   RSK tx:   {}",
                        log["transactionHash"].as_str().unwrap_or("")
                    );
                    println!("   Block:    {}", log["blockNumber"].as_str().unwrap_or(""));
                    println!("   Created:  block {}", created);
                    println!();
                }
            }
        }
    }

    if found == 0 {
        println!(
            "No pegout_confirmed events found in the last {} blocks.",
            SCAN_BLOCKS
        );
        println!(
            "Set RSK_RPC to a Rootstock RPC API endpoint (https://rpc.rootstock.io) for eth_getLogs support."
        );
    }

    Ok(())
}
