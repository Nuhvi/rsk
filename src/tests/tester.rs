//! Copied from and based on <https://github.com/rsksmart/union-bridge-client/blob/main/check-fork/tester/src/lib.rs>

#![forbid(unsafe_code)]

use crate::RskBlock;
use crate::block_header::{
    RskBlockHeader, deserialize_hex_bytes, deserialize_hex_bytes_20, deserialize_hex_h256,
    deserialize_hex_u64, deserialize_hex_u256, deserialize_hex_u256_option,
    deserialize_vec_hex_h256,
};
use bitcoin::consensus::Decodable;
use primitive_types::{H256, U256};
use serde::{Deserialize, Serialize};

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
            bitcoin_merged_mining_header: bitcoin::block::Header::consensus_decode(
                &mut t.bitcoin_merged_mining_header.as_slice(),
            )
            .expect("Invalid block header"),
        }
    }
}

// used mainly for deserialization and also to avoid adding
// dependencies (bitcoin) to the check_fork crate
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TesterRskBlock {
    #[serde(flatten)]
    header: TesterRskBlockHeader,
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
            uncles: tester_block.uncles.iter().map(RskBlock::from).collect(),
            header: RskBlockHeader::from(&tester_block.header),
        }
    }
}
