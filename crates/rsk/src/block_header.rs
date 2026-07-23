//! Copied from and based on <https://github.com/rsksmart/union-bridge-client/blob/main/check-fork/src/block_header.rs>

#![allow(clippy::missing_errors_doc)]

use std::fmt;

use bitcoin::block::Header as BitcoinHeader;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use primitive_types::{H256, U256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

pub mod validator;

use crate::rlp;

const RSK_HEADER_EXTENSION_TYPE_V1: u8 = 1_u8;
const MAX_RSK_PTE_EDGES: usize = 0; // for the moment is better to keep zero because parallel tx is not fully activated

#[derive(Serialize, Deserialize, Clone)]
pub struct RskBlockHeader {
    /// Block height (genesis = 0)
    pub number: u64,
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
        let genesis: Vec<u8> = vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 59, 163, 237, 253, 122, 123, 18, 178, 122, 199, 44, 62, 103, 118,
            143, 97, 127, 200, 27, 195, 136, 138, 81, 50, 58, 159, 184, 170, 75, 30, 94, 74, 41,
            171, 95, 73, 255, 255, 0, 29, 29, 172, 43, 124,
        ];
        let mut reader: &[u8] = genesis.as_ref();

        Self {
            number: 0,
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
            bitcoin_merged_mining_header: BitcoinHeader::consensus_decode(&mut reader)
                .expect("infallible"),
        }
    }
}

impl RskBlockHeader {
    #[must_use]
    pub fn calculate_block_hash(&self) -> H256 {
        let rlp_encoded: Vec<u8> = self.encode_rlp();
        let mut hasher = Keccak256::new();
        hasher.update(&rlp_encoded);

        H256::from_slice(&hasher.finalize())
    }

    #[must_use]
    /// Encode the [RskBlockHeader] according to [RSKIP194](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP194.md)
    /// for the purpose of calculating block hash, not for the purpose of serialization.
    pub fn encode_rlp(&self) -> Vec<u8> {
        let minimum_gas_price = self.minimum_gas_price.unwrap_or_default();
        // TODO: where does this check in encoding come from?
        // else {
        //     // return Err("minimum_gas_price is None");
        //     Some(0)
        // };

        let extension_field = if self.rsk_pte_edges.is_some() {
            self.compressed_extension_data_v1()
        } else {
            self.logs_bloom_v0().to_vec()
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
            rlp::encode_coin_value(&self.difficulty),
            alloy_rlp::encode(self.number),
            alloy_rlp::encode(self.gas_limit.as_slice()),
            alloy_rlp::encode(self.gas_used),
            alloy_rlp::encode(self.timestamp),
            alloy_rlp::encode(self.extra_data.as_slice()),
            rlp::encode_coin_value(&self.paid_fees),
            rlp::encode_signed_coin_value_as_byte(&minimum_gas_price),
            alloy_rlp::encode(self.uncles.len()), // uncle_count
            alloy_rlp::encode::<&[u8]>(&self.umm_root()),
            alloy_rlp::encode(bitcoin_merged_mining_header.as_slice()),
        ];

        encode_list(encoded_fields)
    }

    fn logs_bloom_v0(&self) -> &[u8] {
        // TODO: validate elsewhere
        // if self.extension_data.len() != 256 {
        //     return Err("unsupported extension_data format: expected RPC logsBloom (256 bytes)");
        // }
        self.extension_data.as_slice()
    }

    fn compressed_extension_data_v1(&self) -> Vec<u8> {
        let logs_bloom = self.logs_bloom_v0();

        let logs_bloom_hash = Keccak256::digest(logs_bloom);
        let mut extension_for_hash_fields = vec![alloy_rlp::encode(logs_bloom_hash.as_slice())];

        if let Some(edges) = &self.rsk_pte_edges {
            let edge_bytes_len = edges
                .len()
                .checked_mul(std::mem::size_of::<u16>())
                // TODO: validate elsewhere
                // .ok_or("rsk_pte_edges byte length overflow")?;
                .unwrap_or_default();

            // TODO: validate elsewhere
            // if edge_bytes_len > MAX_RSK_PTE_EDGES {
            //     return Err("rsk_pte_edges exceeds maximum allowed length");
            // }
            let mut edges_little_endian = Vec::with_capacity(edge_bytes_len);
            for edge in edges {
                edges_little_endian.extend_from_slice(&edge.to_le_bytes());
            }
            extension_for_hash_fields.push(alloy_rlp::encode(edges_little_endian.as_slice()));
        }

        let extension_for_hash = encode_list(extension_for_hash_fields);
        let extension_hash = Keccak256::digest(&extension_for_hash);

        encode_list(vec![
            alloy_rlp::encode(RSK_HEADER_EXTENSION_TYPE_V1),
            alloy_rlp::encode(extension_hash.as_slice()),
        ])
    }

    #[must_use]
    pub fn umm_root(&self) -> [u8; 0] {
        // umm_root is always empty at least until a fork defines how it should be used.
        []
    }

    pub fn decode_rlp(data: &[u8]) -> Result<Self, &'static str> {
        let mut decoder = data;
        let header =
            alloy_rlp::Header::decode(&mut decoder).map_err(|_| "failed to decode RLP header")?;
        if !header.list {
            return Err("expected RLP list");
        }
        // Decode each of the 18 fields in order
        let parent = rlp::decode_h256(&mut decoder)?;
        let uncles_hash = rlp::decode_h256(&mut decoder)?;
        let coinbase = rlp::decode_fixed_bytes(&mut decoder)?;
        let state_root = rlp::decode_h256(&mut decoder)?;
        let tx_trie_root = rlp::decode_h256(&mut decoder)?;
        let receipt_trie_root = rlp::decode_h256(&mut decoder)?;
        let extension_data =
            rlp::decode_bytes(&mut decoder).map_err(|_| "failed to decode extension_data")?;
        let difficulty = rlp::decode_u256_be(&mut decoder)?;
        let number = rlp::decode_u64(&mut decoder)?;
        let gas_limit =
            rlp::decode_bytes(&mut decoder).map_err(|_| "failed to decode gas_limit")?;
        let gas_used = rlp::decode_u64(&mut decoder).map_err(|_| "failed to decode gas_used")?;
        let timestamp = rlp::decode_u64(&mut decoder).map_err(|_| "failed to decode timestamp")?;
        let extra_data =
            rlp::decode_bytes(&mut decoder).map_err(|_| "failed to decode extra_data")?;
        let paid_fees = rlp::decode_u256_be(&mut decoder)?;
        let min_gas_bytes =
            rlp::decode_bytes(&mut decoder).map_err(|_| "failed to decode minimum_gas_price")?;
        let minimum_gas_price = if min_gas_bytes.is_empty() {
            None
        } else {
            Some(U256::from_big_endian(&min_gas_bytes))
        };
        let _uncle_count =
            rlp::decode_u64(&mut decoder).map_err(|_| "failed to decode uncle_count")?;
        let _umm_root = rlp::decode_bytes(&mut decoder).map_err(|_| "failed to decode umm_root")?;
        let mm_header_bytes = rlp::decode_bytes(&mut decoder)
            .map_err(|_| "failed to decode bitcoin_merged_mining_header")?;

        let bitcoin_merged_mining_header =
            bitcoin::block::Header::consensus_decode(&mut mm_header_bytes.as_slice())
                .map_err(|_| "failed to decode Bitcoin header")?;

        Ok(Self {
            number,
            parent,
            difficulty,
            timestamp,
            uncles_hash,
            coinbase,
            state_root,
            tx_trie_root,
            receipt_trie_root,
            extension_data,
            gas_limit,
            gas_used,
            extra_data,
            paid_fees,
            minimum_gas_price,
            uncles: Vec::new(), // populated from separate data
            rsk_pte_edges: if MAX_RSK_PTE_EDGES == 0 {
                None
            } else {
                todo!("support parallel transactions")
            },
            bitcoin_merged_mining_header,
        })
    }
}

pub(crate) fn encode_list(rlp_list: Vec<Vec<u8>>) -> Vec<u8> {
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

impl fmt::Debug for RskBlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let short = |h: &H256| {
            let hex = encode_hex(h.as_ref());
            format!("0x{}…{}", &hex[..8], &hex[hex.len().saturating_sub(4)..])
        };

        write!(
            f,
            "RskBlockHeader {{ number: {}, hash: {}, parent: {}, diff: {}, ts: {}, uncles_hash: {}, coinbase: 0x{}, state_root: {}, tx_root: {}, receipt_root: {}, extension_data: {} bytes, rsk_pte_edges: {:?}, gas_limit: 0x{}, gas_used: {}, extra_data: {} bytes, paid_fees: {}, min_gas_price: {:?}, uncle_count: {}, umm_root: {:?}, mm_header_hash: {} }}",
            self.number,
            short(&self.calculate_block_hash()),
            short(&self.parent),
            self.difficulty,
            self.timestamp,
            short(&self.uncles_hash),
            encode_hex(&self.coinbase),
            short(&self.state_root),
            short(&self.tx_trie_root),
            short(&self.receipt_trie_root),
            self.extension_data.len(),
            &self.rsk_pte_edges,
            encode_hex(&self.gas_limit),
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

fn encode_hex(data: &[u8]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(data.len() * 2 + 2);
    out.push_str("0x");
    for &b in data {
        write!(&mut out, "{:02x}", b).expect("infallible");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const RAW_BLOCK_HEADER_8329127: [u8; 581] = [
        249, 2, 66, 160, 139, 39, 189, 14, 132, 144, 210, 198, 3, 166, 231, 204, 52, 81, 201, 21,
        58, 204, 46, 36, 138, 146, 122, 12, 25, 233, 195, 59, 34, 229, 69, 209, 160, 29, 204, 77,
        232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212, 26, 211, 18, 69, 27, 148, 138,
        116, 19, 240, 161, 66, 253, 64, 212, 147, 71, 148, 206, 120, 100, 168, 181, 191, 54, 11, 1,
        9, 149, 2, 161, 99, 129, 12, 236, 132, 93, 74, 160, 126, 131, 143, 111, 131, 130, 90, 68,
        89, 59, 119, 166, 203, 32, 201, 10, 63, 1, 2, 98, 55, 136, 15, 89, 150, 90, 97, 216, 95,
        67, 116, 232, 160, 95, 149, 93, 32, 71, 27, 198, 140, 93, 84, 121, 49, 43, 147, 240, 11,
        196, 78, 174, 50, 99, 57, 255, 50, 5, 204, 254, 225, 197, 75, 215, 10, 160, 184, 163, 238,
        122, 216, 81, 131, 26, 83, 55, 213, 17, 41, 178, 115, 219, 155, 170, 183, 38, 55, 128, 223,
        162, 239, 62, 175, 125, 110, 185, 210, 111, 185, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 64, 0, 16,
        24, 0, 34, 0, 0, 2, 0, 130, 0, 0, 64, 64, 0, 0, 0, 0, 0, 0, 0, 65, 0, 0, 32, 64, 0, 0, 1,
        128, 0, 0, 0, 128, 0, 0, 20, 0, 64, 0, 0, 0, 0, 1, 0, 0, 3, 0, 8, 128, 0, 2, 96, 0, 0, 0,
        0, 0, 8, 0, 0, 0, 64, 4, 0, 0, 8, 0, 0, 8, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 128, 0, 32, 0, 96, 8, 0, 0, 0, 0, 0, 1, 0, 0, 32, 0, 8, 0, 0, 0, 0, 0,
        80, 2, 0, 0, 2, 0, 1, 8, 0, 0, 0, 0, 193, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 4, 0, 34, 0, 0, 32,
        2, 0, 0, 0, 48, 0, 128, 128, 2, 0, 0, 0, 2, 128, 16, 0, 32, 0, 16, 0, 0, 0, 0, 0, 0, 128,
        0, 0, 0, 0, 0, 128, 0, 16, 0, 2, 0, 0, 64, 0, 4, 16, 0, 3, 4, 0, 0, 0, 0, 0, 0, 4, 0, 2,
        128, 0, 0, 0, 32, 0, 4, 0, 0, 0, 0, 32, 0, 0, 16, 0, 32, 64, 4, 16, 0, 0, 32, 0, 0, 0, 0,
        40, 0, 0, 0, 128, 0, 8, 0, 32, 4, 0, 128, 0, 64, 0, 32, 0, 32, 2, 0, 0, 0, 0, 138, 2, 134,
        45, 244, 88, 169, 149, 151, 65, 202, 131, 127, 23, 167, 131, 103, 194, 128, 131, 10, 17,
        159, 132, 105, 69, 98, 67, 136, 199, 1, 133, 82, 69, 69, 68, 45, 134, 21, 8, 117, 104, 153,
        250, 132, 1, 105, 146, 128, 128, 128, 184, 80, 0, 0, 0, 36, 222, 188, 184, 154, 12, 210,
        248, 154, 82, 53, 114, 133, 162, 107, 126, 244, 161, 197, 79, 206, 33, 154, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 118, 243, 12, 180, 71, 31, 83, 218, 232, 168, 146, 66, 202, 134, 223, 51,
        203, 83, 92, 166, 166, 33, 101, 236, 243, 89, 3, 93, 224, 115, 200, 225, 93, 98, 69, 105,
        58, 230, 1, 23, 83, 244, 94, 6,
    ];

    #[test]
    fn test_decode_raw_block_header() {
        let header = RskBlockHeader::decode_rlp(&RAW_BLOCK_HEADER_8329127).unwrap();
        assert_eq!(header.number, 8_329_127);
        dbg!(&header);

        let encoded = header.encode_rlp();
        assert_eq!(encoded, &RAW_BLOCK_HEADER_8329127);
    }

    #[test]
    #[ignore]
    fn test_decode_parallel_transactions() {
        todo!()
    }
}
