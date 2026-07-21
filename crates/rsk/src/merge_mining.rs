//! Merge-mining proof verification (RSKj Rules 2-7).
//!
//! Reference: <https://github.com/rsksmart/rskj/blob/6a4c9a24/rskj-core/src/main/java/co/rsk/validators/ProofOfWorkRule.java#L50-L147>
//!
//! All merge-mining data comes from `eth_getBlockByNumber` on the RSK node:
//! - `bitcoinMergedMiningHeader`: raw 80-byte Bitcoin header (for merkle_root extraction + PoW)
//! - `bitcoinMergedMiningCoinbaseTransaction`: compressed coinbase (40-byte midstate + tail)
//! - `bitcoinMergedMiningMerkleProof`: RSKIP 92 serialized proof (concatenated 32-byte hashes)
//! - `hashForMergedMining`: hash embedded in Bitcoin coinbase after "RSKBLOCK:" tag
//!
//! # Verification Pipeline (RSKj ProofOfWorkRule.isValid)
//!
//! 1. Parse 80-byte Bitcoin header → extract merkle_root
//! 2. Decompress coinbase: [40-byte midstate][tail] → reconstruct SHA-256 state
//! 3. Find "RSKBLOCK:" + hashForMergedMining in tail (Rules 2-6)
//! 4. Compute coinbase hash: SHA256(midstate + tail) → double-SHA-256
//! 5. Verify PMT proof: reduce(combineLeftRight, proof_hashes, coinbaseHash) == merkle_root
//!
//! All hashes are in natural SHA-256 output order (big-endian, MSB first) — no
//! byte reversal. This matches Bitcoin Core's `Hash(left, right)` = `SHA256d(left || right)`
//! where both inputs and output are raw `m_data` bytes.

use bitcoin::consensus::Decodable;
use primitive_types::H256;

use crate::sha256_midstate::{coinbase_hash_from_compressed, sha256d};

/// The ASCII prefix that identifies an RSK block commitment inside a Bitcoin
/// coinbase: "RSKBLOCK:" == [0x52,0x53,0x4b,0x42,0x4c,0x4f,0x43,0x4b,0x3a]
const RSKBLOCK_TAG: &[u8] = b"RSKBLOCK:";

/// Number of bytes of the RSK block hash that are embedded in the merge-mining
/// tag. The full keccak256 digest is 32 bytes, but only the first 20 are
/// committed to in the Bitcoin coinbase (RSKIP177 / legacy format).
const RSK_HASH_PREFIX_LEN: usize = 20;

/// Maximum number of bytes allowed after the merged-mining hash in the coinbase.
const MAX_BYTES_AFTER_MERGED_MINING_HASH: usize = 128;

/// Errors that can occur during merge-mining verification.
#[derive(Debug)]
pub enum MergeMiningError {
    /// RSKBLOCK: tag not found in coinbase tail
    TagNotFound,
    /// Coinbase tail too short to contain the hash prefix
    CoinbaseTooShort,
    /// RSK hash prefix in coinbase does not match this block's hash
    HashMismatch,
    /// RSK tag position >= 64 bytes (midstate malleability)
    TagPositionTooFar,
    /// Duplicate RSK tags found (tag is not the last occurrence)
    DuplicateTag,
    /// Too many bytes after the merged-mining hash
    ExcessTrailingData,
    /// Coinbase transaction is <= 64 bytes total
    CoinbaseTooShort64,
    /// Merkle proof does not connect coinbase to Bitcoin header's merkle_root
    MerkleProofInvalid,
    /// Failed to parse Bitcoin header
    BitcoinHeaderParse,
    /// Failed to decode hex string
    HexDecode(String),
}

impl std::fmt::Display for MergeMiningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TagNotFound => write!(f, "RSKBLOCK: tag not found in coinbase tail"),
            Self::CoinbaseTooShort => write!(f, "coinbase tail too short to contain hash prefix"),
            Self::HashMismatch => {
                write!(f, "RSK hash prefix in coinbase does not match block hash")
            }
            Self::TagPositionTooFar => write!(f, "RSK tag position >= 64 bytes"),
            Self::DuplicateTag => write!(f, "duplicate RSK tags found"),
            Self::ExcessTrailingData => write!(f, "excess trailing data after merged-mining hash"),
            Self::CoinbaseTooShort64 => write!(f, "coinbase total length <= 64 bytes"),
            Self::MerkleProofInvalid => write!(
                f,
                "Merkle proof does not connect coinbase to Bitcoin header"
            ),
            Self::BitcoinHeaderParse => write!(f, "failed to parse 80-byte Bitcoin header"),
            Self::HexDecode(s) => write!(f, "hex decode failed: {s}"),
        }
    }
}

impl std::error::Error for MergeMiningError {}

// ── Coinbase Tag Verification (Rules 2-6) ──────────────────────────────────

/// Verify that the RSK block hash is committed to in the compressed coinbase tail.
///
/// Checks Rules 2-6:
/// - Rule 2: RSKBLOCK: tag present, followed by first 20 bytes of hashForMergedMining
/// - Rule 3: Tag position < 64 bytes (relative to start of tail)
/// - Rule 4: Tag is the last occurrence in the tail
/// - Rule 5: At most 128 bytes after the hash
/// - Rule 6: Coinbase total length > 64 bytes (checked externally via byte_count + tail.len())
pub fn verify_coinbase_tag(
    tail: &[u8],
    hash_for_merged_mining: &H256,
    total_coinbase_len: usize,
) -> Result<(), MergeMiningError> {
    // Rule 6: Coinbase total length > 64 bytes
    if total_coinbase_len <= 64 {
        return Err(MergeMiningError::CoinbaseTooShort64);
    }

    // Rule 2: Find RSKBLOCK: tag (last occurrence in tail)
    let tag_pos = tail
        .windows(RSKBLOCK_TAG.len())
        .rposition(|w| w == RSKBLOCK_TAG)
        .ok_or(MergeMiningError::TagNotFound)?;

    // Rule 4: rposition already gives us the last occurrence — verified by construction.

    // Rule 3: Tag position < 64 bytes (relative to tail start)
    if tag_pos >= 64 {
        return Err(MergeMiningError::TagPositionTooFar);
    }

    let hash_start = tag_pos + RSKBLOCK_TAG.len();
    let hash_end = hash_start + RSK_HASH_PREFIX_LEN;

    if tail.len() < hash_end {
        return Err(MergeMiningError::CoinbaseTooShort);
    }

    // Rule 2 continued: verify first 20 bytes of hashForMergedMining
    let committed_prefix = &tail[hash_start..hash_end];
    let expected_prefix = &hash_for_merged_mining.as_bytes()[..RSK_HASH_PREFIX_LEN];

    if committed_prefix != expected_prefix {
        return Err(MergeMiningError::HashMismatch);
    }

    // Rule 5: At most 128 bytes after the merged-mining hash
    let bytes_after_hash = tail.len() - hash_end;
    if bytes_after_hash > MAX_BYTES_AFTER_MERGED_MINING_HASH {
        return Err(MergeMiningError::ExcessTrailingData);
    }

    Ok(())
}

// ── Merkle Proof Verification (Rule 7) ─────────────────────────────────────

/// Parse the RSKIP 92 Merkle proof into a sequence of 32-byte hashes.
///
/// The proof is concatenated 32-byte hashes (no length prefix).
/// Must be a multiple of 32 bytes. Empty proof = single-transaction block
/// (coinbase = merkle root).
///
/// RSKj stores `Sha256Hash` internally in **little-endian** byte order and
/// serializes raw internal bytes to JSON-RPC hex. We reverse each hash to
/// big-endian (natural SHA-256 output order) so that `combine_left_right`
/// can process them directly, matching Bitcoin Core's algorithm.
pub fn parse_merkle_proof(proof_bytes: &[u8]) -> Result<Vec<[u8; 32]>, MergeMiningError> {
    if !proof_bytes.len().is_multiple_of(32) {
        return Err(MergeMiningError::MerkleProofInvalid);
    }
    let mut hashes = Vec::with_capacity(proof_bytes.len() / 32);
    for chunk in proof_bytes.chunks(32) {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(chunk);
        // Reverse from RSKj's internal LE to BE (natural SHA-256 output order).
        hash.reverse();
        hashes.push(hash);
    }
    Ok(hashes)
}

/// Combine two sibling hashes in a Bitcoin Merkle tree.
///
/// `combineLeftRight(left, right) = SHA256d(left || right)`
///
/// Both inputs and the output are in natural SHA-256 output order (big-endian,
/// MSB first). No byte reversal occurs — this matches Bitcoin Core exactly:
/// ```cpp
/// uint256 Hash(const T1* p1, size_t len1, const T2* p2, size_t len2) {
///     SHA256_Init(&ctx);
///     SHA256_Update(&ctx, p1, len1);  // raw m_data bytes
///     SHA256_Update(&ctx, p2, len2);  // raw m_data bytes
///     SHA256_Final((unsigned char*)&result, &ctx);
///     SHA256_Init(&ctx);
///     SHA256_Update(&ctx, result.begin(), 32);
///     SHA256_Final((unsigned char*)&result, &ctx);
///     return result;
/// }
/// ```
fn combine_left_right(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256d(&combined)
}

/// Verify the RSKIP 92 Merkle proof (Rule 7).
///
/// Takes the coinbase hash (in natural SHA-256 output order), the serialized
/// proof (concatenated 32-byte sibling hashes), and the expected merkle root
/// from the 80-byte Bitcoin header.
///
/// Algorithm: reduce(combineLeftRight, proof_hashes, coinbaseHash) == merkleRoot
pub fn verify_merkle_proof(
    coinbase_hash: &[u8; 32],
    proof_bytes: &[u8],
    expected_root: &[u8; 32],
) -> Result<(), MergeMiningError> {
    let proof_hashes = parse_merkle_proof(proof_bytes)?;

    let mut accumulator = *coinbase_hash;
    for hash in &proof_hashes {
        accumulator = combine_left_right(&accumulator, hash);
    }

    if accumulator != *expected_root {
        return Err(MergeMiningError::MerkleProofInvalid);
    }

    Ok(())
}

// ── Full Verification from RPC Data ────────────────────────────────────────

/// Decode the 80-byte Bitcoin header and extract the merkle root.
pub fn extract_merkle_root_from_btc_header(
    btc_header_hex: &str,
) -> Result<[u8; 32], MergeMiningError> {
    let hex = btc_header_hex.strip_prefix("0x").unwrap_or(btc_header_hex);
    let bytes = hex::decode(hex).map_err(|e| MergeMiningError::HexDecode(e.to_string()))?;
    if bytes.len() != 80 {
        return Err(MergeMiningError::BitcoinHeaderParse);
    }
    let mut reader = &bytes[..];
    let _header: bitcoin::block::Header = Decodable::consensus_decode(&mut reader)
        .map_err(|_| MergeMiningError::BitcoinHeaderParse)?;
    // Merkle root is at bytes [36..68] of the 80-byte header.
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[36..68]);
    Ok(root)
}

/// Parse the compressed coinbase into midstate (40 bytes) and tail.
///
/// The `compressCoinbase()` algorithm hashes complete 64-byte blocks before
/// the RSK tag and stores: `[40-byte trimmed SHA-256 midstate][remaining tail bytes]`.
pub fn parse_compressed_coinbase(
    compressed_hex: &str,
) -> Result<([u8; 40], Vec<u8>), MergeMiningError> {
    let hex = compressed_hex.strip_prefix("0x").unwrap_or(compressed_hex);
    let bytes = hex::decode(hex).map_err(|e| MergeMiningError::HexDecode(e.to_string()))?;
    if bytes.len() < 40 {
        return Err(MergeMiningError::CoinbaseTooShort);
    }
    let mut midstate = [0u8; 40];
    midstate.copy_from_slice(&bytes[..40]);
    let tail = bytes[40..].to_vec();
    Ok((midstate, tail))
}

/// Verify the full merge-mining proof for an RSK block using RPC-sourced data.
///
/// This is the main entry point called from the sync loop. It validates:
/// 1. Bitcoin PoW meets RSK difficulty target (Rule 1 — done externally)
/// 2. RSKBLOCK: tag + hashForMergedMining in coinbase tail (Rules 2-6)
/// 3. Coinbase total length > 64 bytes (Rule 6)
/// 4. Merkle proof connects coinbase hash to Bitcoin header's merkle_root (Rule 7)
///
/// # Arguments
/// * `rsk_block_hash` — keccak256(raw_rlp) of the RSK block header
/// * `compressed_coinbase_hex` — from `eth_getBlockByNumber` field `bitcoinMergedMiningCoinbaseTransaction`
/// * `btc_header_hex` — from `eth_getBlockByNumber` field `bitcoinMergedMiningHeader`
/// * `merkle_proof_hex` — from `eth_getBlockByNumber` field `bitcoinMergedMiningMerkleProof`
/// * `hash_for_merged_mining_hex` — from `eth_getBlockByNumber` field `hashForMergedMining`
pub fn verify_merge_mining_from_rpc(
    _rsk_block_hash: &H256,
    compressed_coinbase_hex: &str,
    btc_header_hex: &str,
    merkle_proof_hex: &str,
    hash_for_merged_mining_hex: &str,
) -> Result<(), MergeMiningError> {
    // 1. Extract merkle_root from 80-byte Bitcoin header.
    let merkle_root = extract_merkle_root_from_btc_header(btc_header_hex)?;

    // 2. Parse compressed coinbase → midstate + tail.
    let (midstate, tail) = parse_compressed_coinbase(compressed_coinbase_hex)?;

    // 3. Compute total coinbase length (byteCount from midstate + tail length).
    let byte_count = u64::from_be_bytes(
        midstate[0..8]
            .try_into()
            .expect("midstate slice is always 8 bytes"),
    ) as usize;
    let total_coinbase_len = byte_count + tail.len();

    // 4. Parse hashForMergedMining.
    let hfm_hex = hash_for_merged_mining_hex
        .strip_prefix("0x")
        .unwrap_or(hash_for_merged_mining_hex);
    let hfm_bytes = hex::decode(hfm_hex)
        .map_err(|e| MergeMiningError::HexDecode(format!("hashForMergedMining: {e}")))?;
    if hfm_bytes.len() != 32 {
        return Err(MergeMiningError::HexDecode(format!(
            "hashForMergedMining expected 32 bytes, got {}",
            hfm_bytes.len()
        )));
    }
    let hash_for_merged_mining = H256::from_slice(&hfm_bytes);

    // 5. Rules 2-6: Verify RSK tag in coinbase tail.
    verify_coinbase_tag(&tail, &hash_for_merged_mining, total_coinbase_len)?;

    // 6. Compute coinbase hash from compressed coinbase (SHA-256 midstate + tail → double-SHA-256).
    let compressed_bytes = {
        let hex_str = compressed_coinbase_hex
            .strip_prefix("0x")
            .unwrap_or(compressed_coinbase_hex);
        hex::decode(hex_str)
            .map_err(|e| MergeMiningError::HexDecode(format!("compressed coinbase: {e}")))?
    };
    let coinbase_hash = coinbase_hash_from_compressed(&compressed_bytes)
        .map_err(|e| MergeMiningError::HexDecode(e.to_string()))?;

    // 7. Rule 7: Verify Merkle proof.
    let proof_bytes = {
        let hex_str = merkle_proof_hex
            .strip_prefix("0x")
            .unwrap_or(merkle_proof_hex);
        hex::decode(hex_str)
            .map_err(|e| MergeMiningError::HexDecode(format!("merkle proof: {e}")))?
    };
    verify_merkle_proof(&coinbase_hash, &proof_bytes, &merkle_root)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_not_found() {
        let tail = vec![0u8; 100];
        let hash = H256::zero();
        assert!(matches!(
            verify_coinbase_tag(&tail, &hash, 200),
            Err(MergeMiningError::TagNotFound)
        ));
    }

    #[test]
    fn test_coinbase_too_short_64() {
        // Coinbase exactly 64 bytes with tag at position 0
        let mut tail = vec![0u8; 64];
        tail[0..RSKBLOCK_TAG.len()].copy_from_slice(RSKBLOCK_TAG);
        let hash = H256::zero();
        let hash_start = RSKBLOCK_TAG.len();
        tail[hash_start..hash_start + RSK_HASH_PREFIX_LEN]
            .copy_from_slice(&hash.as_bytes()[..RSK_HASH_PREFIX_LEN]);
        assert!(matches!(
            verify_coinbase_tag(&tail, &hash, 64),
            Err(MergeMiningError::CoinbaseTooShort64)
        ));
    }

    #[test]
    fn test_valid_tag() {
        let hash = H256::zero();
        let mut tail = vec![0u8; 100];
        let tag_pos = 10;
        tail[tag_pos..tag_pos + RSKBLOCK_TAG.len()].copy_from_slice(RSKBLOCK_TAG);
        let hash_start = tag_pos + RSKBLOCK_TAG.len();
        tail[hash_start..hash_start + RSK_HASH_PREFIX_LEN]
            .copy_from_slice(&hash.as_bytes()[..RSK_HASH_PREFIX_LEN]);
        assert!(verify_coinbase_tag(&tail, &hash, 200).is_ok());
    }

    #[test]
    fn test_tag_too_far() {
        let hash = H256::zero();
        let mut tail = vec![0u8; 200];
        let tag_pos = 70; // >= 64
        tail[tag_pos..tag_pos + RSKBLOCK_TAG.len()].copy_from_slice(RSKBLOCK_TAG);
        let hash_start = tag_pos + RSKBLOCK_TAG.len();
        tail[hash_start..hash_start + RSK_HASH_PREFIX_LEN]
            .copy_from_slice(&hash.as_bytes()[..RSK_HASH_PREFIX_LEN]);
        assert!(matches!(
            verify_coinbase_tag(&tail, &hash, 300),
            Err(MergeMiningError::TagPositionTooFar)
        ));
    }

    #[test]
    fn test_hash_mismatch() {
        let hash = H256::zero();
        let mut wrong_bytes = [0u8; 32];
        wrong_bytes[0] = 42;
        let wrong_hash = H256::from_slice(&wrong_bytes);
        let mut tail = vec![0u8; 100];
        let tag_pos = 10;
        tail[tag_pos..tag_pos + RSKBLOCK_TAG.len()].copy_from_slice(RSKBLOCK_TAG);
        let hash_start = tag_pos + RSKBLOCK_TAG.len();
        tail[hash_start..hash_start + RSK_HASH_PREFIX_LEN]
            .copy_from_slice(&wrong_hash.as_bytes()[..RSK_HASH_PREFIX_LEN]);
        assert!(matches!(
            verify_coinbase_tag(&tail, &hash, 200),
            Err(MergeMiningError::HashMismatch)
        ));
    }

    #[test]
    fn test_excess_trailing_data() {
        let hash = H256::zero();
        let mut tail = vec![0u8; 10 + RSKBLOCK_TAG.len() + RSK_HASH_PREFIX_LEN + 200];
        let tag_pos = 10;
        tail[tag_pos..tag_pos + RSKBLOCK_TAG.len()].copy_from_slice(RSKBLOCK_TAG);
        let hash_start = tag_pos + RSKBLOCK_TAG.len();
        tail[hash_start..hash_start + RSK_HASH_PREFIX_LEN]
            .copy_from_slice(&hash.as_bytes()[..RSK_HASH_PREFIX_LEN]);
        assert!(matches!(
            verify_coinbase_tag(&tail, &hash, 300),
            Err(MergeMiningError::ExcessTrailingData)
        ));
    }

    #[test]
    fn test_parse_merkle_proof_valid() {
        // Empty proof is valid (single-tx block).
        let proof = parse_merkle_proof(&[]).unwrap();
        assert!(proof.is_empty());

        // 32 bytes = one hash = valid.
        let mut data = [0u8; 32];
        data[0] = 1;
        let proof = parse_merkle_proof(&data).unwrap();
        assert_eq!(proof.len(), 1);
    }

    #[test]
    fn test_parse_merkle_proof_invalid_length() {
        let data = [0u8; 33];
        assert!(matches!(
            parse_merkle_proof(&data),
            Err(MergeMiningError::MerkleProofInvalid)
        ));
    }

    #[test]
    fn test_merkle_proof_empty_matches_root() {
        // Empty proof: accumulator stays as coinbase_hash, must equal root.
        let coinbase_hash = [1u8; 32];
        let root = coinbase_hash;
        assert!(verify_merkle_proof(&coinbase_hash, &[], &root).is_ok());
    }

    #[test]
    fn test_merkle_proof_empty_mismatch_root() {
        let coinbase_hash = [1u8; 32];
        let root = [2u8; 32];
        assert!(matches!(
            verify_merkle_proof(&coinbase_hash, &[], &root),
            Err(MergeMiningError::MerkleProofInvalid)
        ));
    }

    #[test]
    fn test_combine_left_right_deterministic() {
        let left = [0xAAu8; 32];
        let right = [0xBBu8; 32];
        let result1 = combine_left_right(&left, &right);
        let result2 = combine_left_right(&left, &right);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_combine_left_right_not_commutative() {
        // Bitcoin Merkle combine is NOT commutative — order matters.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let ab = combine_left_right(&a, &b);
        let ba = combine_left_right(&b, &a);
        assert_ne!(ab, ba);
    }

    #[test]
    fn test_combine_left_right_matches_bitcoin_core() {
        // Verify our implementation matches Bitcoin Core's Hash(left, right):
        // SHA256d(left.m_data || right.m_data) — no byte reversal.
        //
        // RSKj reverses bytes because Java's internal representation differs
        // from wire format, but the fundamental algorithm is just SHA256d of
        // the concatenation. Our implementation matches the Bitcoin Core native
        // algorithm directly.
        use crate::sha256_midstate::sha256;

        let left: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let right: [u8; 32] = [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
            0x3d, 0x3e, 0x3f, 0x40,
        ];

        // Bitcoin Core: SHA256d(left || right) — no reversal
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&left);
        concat[32..].copy_from_slice(&right);
        let h1 = sha256(&concat);
        let expected = sha256(&h1);

        let actual = combine_left_right(&left, &right);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_extract_merkle_root_invalid_hex() {
        assert!(matches!(
            extract_merkle_root_from_btc_header("not_hex"),
            Err(MergeMiningError::HexDecode(_))
        ));
    }

    #[test]
    fn test_extract_merkle_root_wrong_length() {
        let short_hex = "aabb".repeat(20); // 40 bytes, not 80
        assert!(matches!(
            extract_merkle_root_from_btc_header(&format!("0x{short_hex}")),
            Err(MergeMiningError::BitcoinHeaderParse)
        ));
    }
}
