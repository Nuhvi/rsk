use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

use crate::error::NodeError;

use tracing::debug;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize, Debug)]
struct JsonRpcError {
    message: String,
}

#[derive(Deserialize)]
struct BatchRawHeaderResult {
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Deserialize, Debug)]
pub struct RskBlockWithMergeMining {
    pub number: String,
    #[serde(default)]
    #[serde(rename = "bitcoinMergedMiningHeader")]
    pub bitcoin_header: Option<String>,
    #[serde(default)]
    #[serde(rename = "bitcoinMergedMiningCoinbaseTransaction")]
    pub compressed_coinbase: Option<String>,
    #[serde(default)]
    #[serde(rename = "bitcoinMergedMiningMerkleProof")]
    pub merkle_proof: Option<String>,
    #[serde(default)]
    #[serde(rename = "hashForMergedMining")]
    pub hash_for_merged_mining: Option<String>,
}

#[derive(Deserialize)]
struct EthBlockBatchResult {
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

pub struct RskRpc {
    client: Client,
    url: String,
}

impl RskRpc {
    pub fn new(url: &str) -> Result<Self, NodeError> {
        let client = Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| NodeError::RskRpc(format!("HTTP client: {e}")))?;
        Ok(Self {
            client,
            url: url.to_string(),
        })
    }

    pub async fn get_block_number(&self) -> Result<u64, NodeError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        });

        let resp: JsonRpcResponse<String> = self.post(&body).await?;
        let hex = resp
            .result
            .ok_or_else(|| NodeError::RskRpc("no result".into()))?;
        let hex = hex.strip_prefix("0x").unwrap_or(&hex);
        u64::from_str_radix(hex, 16)
            .map_err(|e| NodeError::RskRpc(format!("parse block number: {e}")))
    }

    pub async fn get_raw_block_headers_batch(
        &self,
        block_numbers: &[u64],
    ) -> Result<Vec<(u64, Vec<u8>)>, NodeError> {
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

        let resp: Vec<BatchRawHeaderResult> = self.post_batch(&batch).await?;

        if resp.len() != block_numbers.len() {
            return Err(NodeError::RskRpc(format!(
                "batch len {} != {}",
                resp.len(),
                block_numbers.len()
            )));
        }

        let mut results = Vec::with_capacity(block_numbers.len());
        for (num, entry) in block_numbers.iter().zip(resp.iter()) {
            if let Some(err) = &entry.error {
                return Err(NodeError::RskRpc(format!("block {num}: {}", err.message)));
            }
            let hex = entry
                .result
                .as_deref()
                .ok_or_else(|| NodeError::RskRpc(format!("no header for block {num}")))?;
            let hex = hex.strip_prefix("0x").unwrap_or(hex);
            let raw = hex::decode(hex)
                .map_err(|e| NodeError::RskRpc(format!("hex at block {num}: {e}")))?;
            results.push((*num, raw));
        }
        Ok(results)
    }

    pub async fn get_blocks_with_merge_mining_batch(
        &self,
        block_numbers: &[u64],
    ) -> Result<Vec<RskBlockWithMergeMining>, NodeError> {
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

        let resp: Vec<EthBlockBatchResult> = self.post_batch(&batch).await?;

        if resp.len() != block_numbers.len() {
            return Err(NodeError::RskRpc(format!(
                "batch len {} != {}",
                resp.len(),
                block_numbers.len()
            )));
        }

        let mut results = Vec::with_capacity(block_numbers.len());
        for (num, entry) in block_numbers.iter().zip(resp.iter()) {
            if let Some(err) = &entry.error {
                return Err(NodeError::RskRpc(format!("block {num}: {}", err.message)));
            }
            let val = entry
                .result
                .as_ref()
                .ok_or_else(|| NodeError::RskRpc(format!("no result for block {num}")))?;
            if val.is_null() {
                return Err(NodeError::RskRpc(format!("block {num} not found")));
            }
            let block: RskBlockWithMergeMining = serde_json::from_value(val.clone())
                .map_err(|e| NodeError::RskRpc(format!("parse block {num}: {e}")))?;
            results.push(block);
        }
        Ok(results)
    }

    async fn post(&self, body: &serde_json::Value) -> Result<JsonRpcResponse<String>, NodeError> {
        debug!(
            method = body.get("method").and_then(|v| v.as_str()).unwrap_or("?"),
            "RSK RPC request"
        );
        let resp = self
            .client
            .post(&self.url)
            .json(body)
            .send()
            .await
            .map_err(|e| NodeError::RskRpc(format!("HTTP: {e}")))?;
        debug!(status = %resp.status(), "RSK RPC response");
        resp.json()
            .await
            .map_err(|e| NodeError::RskRpc(format!("JSON: {e}")))
    }

    async fn post_batch<T: for<'de> Deserialize<'de>>(
        &self,
        batch: &[serde_json::Value],
    ) -> Result<Vec<T>, NodeError> {
        debug!(count = batch.len(), "RSK RPC batch request");
        let resp = self
            .client
            .post(&self.url)
            .json(batch)
            .send()
            .await
            .map_err(|e| NodeError::RskRpc(format!("HTTP: {e}")))?;
        debug!(status = %resp.status(), "RSK RPC batch response");
        resp.json()
            .await
            .map_err(|e| NodeError::RskRpc(format!("JSON: {e}")))
    }
}
