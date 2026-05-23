//! Copied from and based on <https://github.com/rsksmart/union-bridge-client/blob/main/check-fork/src/block_header.rs>

#![allow(clippy::missing_errors_doc)]

use std::fmt;

use bitcoin::block::Header as BitcoinHeader;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use primitive_types::{H256, U256};
use serde::{Deserialize, Deserializer, Serialize};
use sha3::{Digest, Keccak256};

use crate::rlp::{encode_coin_value, encode_signed_coin_value_as_byte};

pub mod validator;

const RSK_HEADER_EXTENSION_TYPE_V1: u8 = 1_u8;
const MAX_RSK_PTE_EDGES: usize = 0; // for the moment is better to keep zero because parallel tx is not fully activated

#[derive(Serialize, Deserialize, Clone)]
pub struct RskBlockHeader {
    /// Block height (genesis = 0)
    pub number: u64,
    /// Keccak-256 of the encoded header
    pub hash: H256,
    /// Keccak-256 hash of the parent block
    pub parent: H256,
    /// Target difficulty for this block
    pub difficulty: U256,
    /// Unix time (seconds) when the block was created
    pub timestamp: u64,
    /// SHA3-256 hash of the uncles list
    pub uncles_hash: H256,
    /// 160-bit address (RskAddress) - miner's address
    pub coinbase: [u8; 20],
    /// SHA3-256 hash of the root node of the state trie
    pub state_root: H256,
    /// SHA3-256 hash of the root node of the transaction trie
    pub tx_trie_root: H256,
    /// SHA3-256 hash of the root node of the receipt trie
    pub receipt_trie_root: H256,
    /// RPC logsBloom bytes (expanded format only)
    pub extension_data: Vec<u8>,
    /// Current limit of gas expenditure per block
    pub gas_limit: Vec<u8>,
    /// Total gas used in transactions in this block
    pub gas_used: u64,
    /// Arbitrary byte array (max 32 bytes, except genesis)
    pub extra_data: Vec<u8>,
    /// Total paid fees in transactions (Coin, RLP encoded)
    pub paid_fees: U256,
    /// Minimum gas price for a tx to be included
    pub minimum_gas_price: Option<U256>,
    /// Hashes of uncle blocks
    pub uncles: Vec<H256>,
    /// None: omit field in hash input, Some([]): include empty field
    pub rsk_pte_edges: Option<Vec<u16>>,
    /// 80-byte Bitcoin block header for merged mining
    pub bitcoin_merged_mining_header: BitcoinHeader,
}

impl Default for RskBlockHeader {
    fn default() -> Self {
        Self {
            number: 0,
            hash: H256::zero(),
            parent: H256::zero(),
            difficulty: U256::zero(),
            timestamp: 0,
            uncles_hash: H256::zero(),
            coinbase: [0u8; 20],
            state_root: H256::zero(),
            tx_trie_root: H256::zero(),
            receipt_trie_root: H256::zero(),
            extension_data: vec![0u8; 256],
            gas_limit: vec![0u8],
            gas_used: 0,
            extra_data: Vec::new(),
            paid_fees: U256::zero(),
            minimum_gas_price: Some(U256::zero()),
            uncles: Vec::new(),
            rsk_pte_edges: None,
            // genesis
            bitcoin_merged_mining_header: BitcoinHeader::consensus_decode(
                &mut hex::decode(
                    "010000000000000000000000000000000000000000000000000000000000000000000000\
                    3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a\
                    29ab5f49ffff001d1dac2b7c",
                )
                .expect("infallible")
                .as_slice(),
            )
            .expect("infallible"),
        }
    }
}

impl RskBlockHeader {
    pub fn calculate_block_hash(&self) -> Result<H256, &'static str> {
        let rlp_encoded: Vec<u8> = self.encode_rlp()?;
        let mut hasher = Keccak256::new();
        hasher.update(&rlp_encoded);
        let block_hash = H256::from_slice(&hasher.finalize());
        Ok(block_hash)
    }

    pub fn encode_rlp(&self) -> Result<Vec<u8>, &'static str> {
        let Some(minimum_gas_price) = self.minimum_gas_price else {
            return Err("minimum_gas_price is None");
        };

        let extension_field = if self.rsk_pte_edges.is_some() {
            self.compressed_extension_data_v1()?
        } else {
            self.logs_bloom_v0()?.to_vec()
        };

        let mut bitcoin_merged_mining_header = vec![];
        self.bitcoin_merged_mining_header
            .consensus_encode(&mut bitcoin_merged_mining_header)
            .expect("infallible: Invalid bitcoin_merged_mining_header after already parsing it");

        let encoded_fields: Vec<Vec<u8>> = vec![
            alloy_rlp::encode(self.parent.as_bytes()),
            alloy_rlp::encode(self.uncles_hash.as_bytes()),
            alloy_rlp::encode(self.coinbase.as_slice()),
            alloy_rlp::encode(self.state_root.as_bytes()),
            alloy_rlp::encode(self.tx_trie_root.as_bytes()),
            alloy_rlp::encode(self.receipt_trie_root.as_bytes()),
            alloy_rlp::encode(extension_field.as_slice()),
            encode_coin_value(&self.difficulty),
            alloy_rlp::encode(self.number),
            alloy_rlp::encode(self.gas_limit.as_slice()),
            alloy_rlp::encode(self.gas_used),
            alloy_rlp::encode(self.timestamp),
            alloy_rlp::encode(self.extra_data.as_slice()),
            encode_coin_value(&self.paid_fees),
            encode_signed_coin_value_as_byte(&minimum_gas_price),
            alloy_rlp::encode(self.uncles.len()), // uncle_count
            alloy_rlp::encode::<&[u8]>(&self.umm_root()),
            alloy_rlp::encode(bitcoin_merged_mining_header.as_slice()),
        ];
        let out = encode_list(encoded_fields);
        Ok(out)
    }

    fn logs_bloom_v0(&self) -> Result<&[u8], &'static str> {
        if self.extension_data.len() != 256 {
            return Err("unsupported extension_data format: expected RPC logsBloom (256 bytes)");
        }
        Ok(self.extension_data.as_slice())
    }

    fn compressed_extension_data_v1(&self) -> Result<Vec<u8>, &'static str> {
        let logs_bloom = self.logs_bloom_v0()?;

        let logs_bloom_hash = Keccak256::digest(logs_bloom);
        let mut extension_for_hash_fields = vec![alloy_rlp::encode(logs_bloom_hash.as_slice())];

        if let Some(edges) = &self.rsk_pte_edges {
            let edge_bytes_len = edges
                .len()
                .checked_mul(std::mem::size_of::<u16>())
                .ok_or("rsk_pte_edges byte length overflow")?;
            if edge_bytes_len > MAX_RSK_PTE_EDGES {
                return Err("rsk_pte_edges exceeds maximum allowed length");
            }
            let mut edges_little_endian = Vec::with_capacity(edge_bytes_len);
            for edge in edges {
                edges_little_endian.extend_from_slice(&edge.to_le_bytes());
            }
            extension_for_hash_fields.push(alloy_rlp::encode(edges_little_endian.as_slice()));
        }

        let extension_for_hash = encode_list(extension_for_hash_fields);
        let extension_hash = Keccak256::digest(&extension_for_hash);

        Ok(encode_list(vec![
            alloy_rlp::encode(RSK_HEADER_EXTENSION_TYPE_V1),
            alloy_rlp::encode(extension_hash.as_slice()),
        ]))
    }

    #[must_use]
    pub fn umm_root(&self) -> [u8; 0] {
        // umm_root is always empty at least until a fork defines how it should be used.
        []
    }
}

pub fn encode_list(rlp_list: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let payload_length: usize = rlp_list.iter().map(Vec::len).sum();
    alloy_rlp::Header {
        list: true,
        payload_length,
    }
    .encode(&mut out);
    for field in rlp_list {
        out.extend_from_slice(&field);
    }

    out
}

pub fn deserialize_hex_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

pub fn deserialize_hex_h256<'de, D>(deserializer: D) -> Result<H256, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
    from_bytes_vec_to_h256(&bytes)
}

pub fn deserialize_hex_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    hex::decode(s).map_err(serde::de::Error::custom)
}

pub fn deserialize_hex_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    U256::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

pub fn deserialize_hex_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    u32::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

pub fn deserialize_vec_hex_h256<'de, D>(deserializer: D) -> Result<Vec<H256>, D::Error>
where
    D: Deserializer<'de>,
{
    let strings: Vec<String> = Deserialize::deserialize(deserializer)?;
    strings
        .iter()
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            from_bytes_vec_to_h256(&bytes)
        })
        .collect()
}

fn from_bytes_vec_to_h256<E>(bytes: &[u8]) -> Result<H256, E>
where
    E: serde::de::Error,
{
    if bytes.len() != 32 {
        return Err(serde::de::Error::custom(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    Ok(H256::from_slice(bytes))
}

pub fn deserialize_hex_bytes_20<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
where
    D: Deserializer<'de>,
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

pub fn deserialize_hex_u256_option<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
where
    D: Deserializer<'de>,
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

impl fmt::Debug for RskBlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let short = |h: &H256| {
            let hex = hex::encode(h);
            format!("0x{}…{}", &hex[..8], &hex[hex.len().saturating_sub(4)..])
        };

        write!(
            f,
            "RskBlockHeader {{ number: {}, hash: {}, parent: {}, diff: {}, ts: {}, uncles_hash: {}, coinbase: 0x{}, state_root: {}, tx_root: {}, receipt_root: {}, extension_data: {} bytes, rsk_pte_edges: {:?}, gas_limit: 0x{}, gas_used: {}, extra_data: {} bytes, paid_fees: {}, min_gas_price: {:?}, uncle_count: {}, umm_root: {:?}, mm_header_hash: {} }}",
            self.number,
            short(&self.hash),
            short(&self.parent),
            self.difficulty,
            self.timestamp,
            short(&self.uncles_hash),
            hex::encode(self.coinbase),
            short(&self.state_root),
            short(&self.tx_trie_root),
            short(&self.receipt_trie_root),
            self.extension_data.len(),
            &self.rsk_pte_edges,
            hex::encode(&self.gas_limit),
            self.gas_used,
            self.extra_data.len(),
            self.paid_fees,
            self.minimum_gas_price,
            self.uncles.len(),
            self.umm_root(),
            self.bitcoin_merged_mining_header.block_hash()
        )
    }
}
