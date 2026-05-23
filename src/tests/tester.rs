//! Copied from and based on <https://github.com/rsksmart/union-bridge-client/blob/main/check-fork/tester/src/lib.rs>

#![forbid(unsafe_code)]

use std::error::Error;
use std::str::FromStr;
use std::string::ToString;

use crate::block_header::{
    RskBlockHeader, deserialize_hex_bytes, deserialize_hex_bytes_20, deserialize_hex_h256,
    deserialize_hex_u64, deserialize_hex_u256, deserialize_hex_u256_option,
    deserialize_vec_hex_h256,
};
use crate::{BridgeEvent, RskBlock};
use bitcoin::blockdata::block::Header;
use bitcoin::consensus::encode::deserialize as btc_deserialize;
use primitive_types::{H256, U256};
// use reqwest::Client;
use serde::{Deserialize, Serialize};
// use serde_json::{Value, json};

// const RSK_RPC_URL: &str = "https://public-node.rsk.co";

// const SUPERBLOCK_THRESHOLD_FACTOR: u64 = 20;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TesterRskBlockHeader {
    #[serde(rename = "number", deserialize_with = "deserialize_hex_u64")]
    pub number: u64,
    #[serde(rename = "hash", deserialize_with = "deserialize_hex_h256")]
    pub hash: H256,
    #[serde(rename = "parentHash", deserialize_with = "deserialize_hex_h256")]
    pub parent: H256,
    #[serde(rename = "difficulty", deserialize_with = "deserialize_hex_u256")]
    pub difficulty: U256,
    #[serde(rename = "timestamp", deserialize_with = "deserialize_hex_u64")]
    pub timestamp: u64,
    #[serde(rename = "sha3Uncles", deserialize_with = "deserialize_hex_h256")]
    pub uncles_hash: H256,
    #[serde(rename = "miner", deserialize_with = "deserialize_hex_bytes_20")]
    pub coinbase: [u8; 20],
    #[serde(rename = "stateRoot", deserialize_with = "deserialize_hex_h256")]
    pub state_root: H256,
    #[serde(rename = "transactionsRoot", deserialize_with = "deserialize_hex_h256")]
    pub tx_trie_root: H256,
    #[serde(rename = "receiptsRoot", deserialize_with = "deserialize_hex_h256")]
    pub receipt_trie_root: H256,
    // This is the json-rpc logsBloom field.
    // check-fork derives the compressed v1 extension data from it when hashing headers.
    #[serde(rename = "logsBloom", deserialize_with = "deserialize_hex_bytes")]
    pub extension_data: Vec<u8>,
    #[serde(rename = "gasLimit", deserialize_with = "deserialize_hex_bytes")]
    pub gas_limit: Vec<u8>,
    #[serde(rename = "gasUsed", deserialize_with = "deserialize_hex_u64")]
    pub gas_used: u64,
    #[serde(rename = "extraData", deserialize_with = "deserialize_hex_bytes")]
    pub extra_data: Vec<u8>,
    #[serde(rename = "paidFees", deserialize_with = "deserialize_hex_u256")]
    pub paid_fees: U256,
    #[serde(
        rename = "minimumGasPrice",
        deserialize_with = "deserialize_hex_u256_option"
    )]
    pub minimum_gas_price: Option<U256>,
    #[serde(
        rename = "rskPteEdges",
        default,
        deserialize_with = "deserialize_optional_u16_vec"
    )]
    pub rsk_pte_edges: Option<Vec<u16>>,
    #[serde(
        rename = "uncles",
        deserialize_with = "deserialize_vec_hex_h256",
        default
    )]
    pub uncles: Vec<H256>,
    #[serde(
        rename = "bitcoinMergedMiningHeader",
        deserialize_with = "deserialize_hex_bytes"
    )]
    pub bitcoin_merged_mining_header: Vec<u8>,
}

impl From<&TesterRskBlockHeader> for RskBlockHeader {
    fn from(t: &TesterRskBlockHeader) -> Self {
        RskBlockHeader {
            number: t.number,
            hash: t.hash,
            parent: t.parent,
            difficulty: t.difficulty,
            timestamp: t.timestamp,
            uncles_hash: t.uncles_hash,
            coinbase: t.coinbase,
            state_root: t.state_root,
            tx_trie_root: t.tx_trie_root,
            receipt_trie_root: t.receipt_trie_root,
            extension_data: t.extension_data.clone(),
            gas_limit: t.gas_limit.clone(),
            gas_used: t.gas_used,
            extra_data: t.extra_data.clone(),
            paid_fees: t.paid_fees,
            minimum_gas_price: t.minimum_gas_price,
            uncles: t.uncles.clone(),
            rsk_pte_edges: t.rsk_pte_edges.clone(),
            bitcoin_merged_mining_header: t.bitcoin_merged_mining_header.clone(),
        }
    }
}

// used mainly for deserialization and also to avoid adding
// dependencies (bitcoin) to the check_fork crate
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TesterRskBlock {
    #[serde(flatten)]
    header: TesterRskBlockHeader,
    bridge_event: Option<BridgeEvent>,
    #[serde(skip)]
    uncles: Vec<TesterRskBlock>, // this field should be filled later
}

fn deserialize_optional_u16_vec<'de, D>(deserializer: D) -> Result<Option<Vec<u16>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Vec<u16>>::deserialize(deserializer)
}

impl From<&TesterRskBlock> for RskBlock {
    fn from(tester_block: &TesterRskBlock) -> Self {
        RskBlock {
            bridge_event: tester_block.bridge_event.clone(),
            uncles: tester_block.uncles.iter().map(RskBlock::from).collect(),
            pow: tester_block.pow().expect("pow is not valid"),
            header: RskBlockHeader::from(&tester_block.header),
        }
    }
}

impl TesterRskBlock {
    fn pow(&self) -> Result<H256, Box<dyn Error>> {
        if self.header.bitcoin_merged_mining_header.len() != 80 {
            return Err("bitcoin_merged_mining_header is not 80 bytes long".into());
        }
        let btc_header: Header = btc_deserialize(&self.header.bitcoin_merged_mining_header)
            .map_err(|e| {
                format!(
                    "Failed to deserialize btc header: {e:?}, data: {:?}",
                    self.header.bitcoin_merged_mining_header
                )
            })?;
        let hash = H256::from_str(&btc_header.block_hash().to_string())?;
        Ok(hash)
    }

    // fn add_uncle(&mut self, uncle: TesterRskBlock) {
    //     self.uncles.push(uncle);
    // }
}
//
// ///
// /// # Errors
// ///
// /// Returns an error if the HTTP request fails, JSON parsing fails, or block deserialization fails.
// ///
// /// # Panics
// ///
// /// This function may panic if `result.unwrap()` is called on a `None` value when processing block results.
// pub async fn get_blocks(
//     start_block_number: u64,
//     num_of_blocks: u32,
//     log_super_block: bool,
//     has_bridge_event: bool,
// ) -> Result<Vec<RskBlock>, Box<dyn Error>> {
//     let client = Client::new();
//     let mut blocks = vec![];
//
//     for i in 0..num_of_blocks {
//         fetch_block_by_num(start_block_number, log_super_block, &client, &mut blocks, i).await?;
//     }
//
//     if has_bridge_event {
//         let result: Vec<RskBlock> = add_bridge_event(&blocks);
//         return Ok(result);
//     }
//
//     let mut blocks_with_uncles = Vec::new();
//     for block in blocks {
//         let uncles_hashes = block.header.uncles.clone();
//         let fetched = fetch_uncles(&client, uncles_hashes, block).await;
//         blocks_with_uncles.push(fetched);
//     }
//     let result = blocks_with_uncles.iter().map(RskBlock::from).collect();
//     Ok(result)
// }
//
// async fn fetch_uncles(
//     client: &Client,
//     uncles_hashes: Vec<H256>,
//     mut block: TesterRskBlock,
// ) -> TesterRskBlock {
//     for uncle_hash in uncles_hashes {
//         let uncle = fetch_block_by_hash(uncle_hash, client)
//             .await
//             .expect("Failed to fetch uncle");
//         block.add_uncle(uncle);
//     }
//     block.clone()
// }
//
// async fn fetch_block_by_hash(
//     hash: H256,
//     client: &Client,
// ) -> Result<TesterRskBlock, Box<dyn Error>> {
//     let hash_hex = format!("0x{hash:x}");
//     let request_body = json!({
//         "jsonrpc": "2.0",
//         "method": "eth_getBlockByHash",
//         "params": [hash_hex, true],
//         "id": 1,
//     });
//     let response = client.post(RSK_RPC_URL).json(&request_body).send().await?;
//     let response_json: Value = response.json().await?;
//     let error = response_json.get("error");
//     let result = response_json.get("result");
//     if error.is_some() {
//         // todo(fede) print error
//         return Err(format!("Error fetching block by hash {hash_hex}: {response_json:?}").into());
//     }
//     let Some(result) = result else {
//         return Err(format!("No result for block hash {hash_hex}").into());
//     };
//     let block: TesterRskBlock = serde_json::from_str(&result.to_string())?;
//     Ok(block)
// }
//
// async fn fetch_block_by_num(
//     start_block_number: u64,
//     log_super_block: bool,
//     client: &Client,
//     blocks: &mut Vec<TesterRskBlock>,
//     num: u32,
// ) -> Result<(), Box<dyn Error>> {
//     let block_number_hex = format!("{:#x}", start_block_number + u64::from(num));
//     let request_body = json!({
//         "jsonrpc": "2.0",
//         "method": "eth_getBlockByNumber",
//         "params": [block_number_hex, true],
//         "id": 1,
//     });
//     let response = client.post(RSK_RPC_URL).json(&request_body).send().await?;
//     let response_json: Value = response.json().await?;
//     let error = response_json.get("error");
//     let result = response_json.get("result");
//     if error.is_some() {
//         println!(
//             "Error fetching block {}: {:?}",
//             start_block_number + u64::from(num),
//             response_json
//         );
//     } else if let Some(result) = result {
//         let block: TesterRskBlock = serde_json::from_str(&result.to_string())?;
//         if log_super_block {
//             log_if_superblock(&block)?;
//         }
//         blocks.push(block);
//     }
//     Ok(())
// }
//
// fn add_bridge_event(blocks: &[TesterRskBlock]) -> Vec<RskBlock> {
//     blocks
//         .iter()
//         .enumerate()
//         .map(|(i, b)| {
//             let mut input_block = RskBlock::from(b);
//             if i == 0 {
//                 input_block.bridge_event = Some(BridgeEvent {
//                     utxo_id: "FAKE_UTXO_ID".to_string(),         // tmp
//                     pegout_id: "FAKE_PEGOUT_ID".to_string(),     // tmp
//                     operator_id: "FAKE_OPERATOR_ID".to_string(), // tmp
//                 });
//             }
//             input_block
//         })
//         .collect()
// }
//
// fn log_if_superblock(block: &TesterRskBlock) -> Result<(), Box<dyn Error>> {
//     // parse the block's actual PoW (from bitcoinMergedMiningHeader field) to decimal
//     let actual_block_pow =
//         U256::from_big_endian(block.header.bitcoin_merged_mining_header.as_slice());
//
//     // compute the PoW target from difficulty by inversion
//     // U256::MAX, the "difficulty 1" target, represents the easiest possible target
//     // this conversion allows comparing target difficulty with the actual block PoW
//     let target_block_pow = U256::MAX
//         .checked_div(block.header.difficulty)
//         .ok_or("0 division on log_if_superblock")?;
//
//     // define a superblock as one whose PoW is at least N times harder than the required target
//     let superblock_pow = target_block_pow / SUPERBLOCK_THRESHOLD_FACTOR;
//
//     // if the actual block PoW is lower (i.e., harder) than the SuperBlock threshold, we found a SuperBlock
//     if actual_block_pow < superblock_pow {
//         let timestamp_i64 = i64::try_from(block.header.timestamp).unwrap_or(i64::MAX);
//         let formatted_time = chrono::DateTime::from_timestamp(timestamp_i64, 0)
//             .unwrap()
//             .format("%Y-%m-%d %H:%M:%S");
//
//         println!(
//             "SuperBlock: {}, pow: {:?}, threshold: 0x{:064x}, time: {}",
//             block.header.number,
//             &block.header.bitcoin_merged_mining_header,
//             superblock_pow,
//             formatted_time
//         );
//     }
//
//     Ok(())
// }
