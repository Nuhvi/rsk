//! Merge-mining proof verification (RSKj Rules 2-7).
//!
//! Reference: <https://github.com/rsksmart/rskj/blob/6a4c9a24/rskj-core/src/main/java/co/rsk/validators/ProofOfWorkRule.java#L50-L147>
//!
//! The RSK block header contains an 80-byte Bitcoin merged-mining header.
//! To verify the merge-mining proof, we need the full Bitcoin block to extract:
//! - The coinbase transaction (to check for the RSKBLOCK: tag + hash)
//! - The Merkle proof (to verify the coinbase is part of the Bitcoin block)
//!
//! This module provides standalone verification functions that take both the
//! RSK header data and the Bitcoin block data.

use bitcoin::Block;
use primitive_types::H256;
use sha3::{Digest, Keccak256};

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
    /// RSKBLOCK: tag not found in coinbase
    TagNotFound,
    /// Coinbase transaction too short to contain the hash prefix
    CoinbaseTooShort,
    /// RSK hash prefix in coinbase does not match this block's hash
    HashMismatch,
    /// RSK tag position >= 64 bytes (midstate malleability)
    TagPositionTooFar,
    /// Duplicate RSK tags found (tag is not the last occurrence)
    DuplicateTag,
    /// Too many bytes after the merged-mining hash
    ExcessTrailingData,
    /// Coinbase transaction is <= 64 bytes
    CoinbaseTooShort64,
    /// Merkle proof does not connect coinbase to Bitcoin header's merkle_root
    MerkleProofInvalid,
}

impl std::fmt::Display for MergeMiningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TagNotFound => write!(f, "RSKBLOCK: tag not found in coinbase"),
            Self::CoinbaseTooShort => write!(f, "coinbase too short to contain hash prefix"),
            Self::HashMismatch => {
                write!(f, "RSK hash prefix in coinbase does not match block hash")
            }
            Self::TagPositionTooFar => write!(f, "RSK tag position >= 64 bytes"),
            Self::DuplicateTag => write!(f, "duplicate RSK tags found"),
            Self::ExcessTrailingData => write!(f, "excess trailing data after merged-mining hash"),
            Self::CoinbaseTooShort64 => write!(f, "coinbase <= 64 bytes"),
            Self::MerkleProofInvalid => write!(
                f,
                "Merkle proof does not connect coinbase to Bitcoin header"
            ),
        }
    }
}

impl std::error::Error for MergeMiningError {}

/// Extract the coinbase transaction raw bytes from a Bitcoin block.
///
/// The coinbase is always `txdata[0]`.
pub fn extract_coinbase(block: &Block) -> Vec<u8> {
    let coinbase_tx = &block.txdata[0];
    bitcoin::consensus::serialize(coinbase_tx)
}

/// Verify that the RSK block hash is committed to in the Bitcoin coinbase.
///
/// Checks Rules 2-6:
/// - Rule 2: RSKBLOCK: tag present, followed by first 20 bytes of block hash
/// - Rule 3: Tag position < 64 bytes
/// - Rule 4: Tag is the last occurrence
/// - Rule 5: At most 128 bytes after the hash
/// - Rule 6: Coinbase length > 64 bytes
pub fn verify_coinbase_tag(
    coinbase_bytes: &[u8],
    rsk_block_hash: &H256,
) -> Result<(), MergeMiningError> {
    // Rule 6: Coinbase length > 64 bytes
    if coinbase_bytes.len() <= 64 {
        return Err(MergeMiningError::CoinbaseTooShort64);
    }

    // Rule 2: Find RSKBLOCK: tag (last occurrence)
    let tag_pos = coinbase_bytes
        .windows(RSKBLOCK_TAG.len())
        .rposition(|w| w == RSKBLOCK_TAG)
        .ok_or(MergeMiningError::TagNotFound)?;

    // Rule 4: Verify this is the LAST occurrence by checking no duplicate after
    // (rposition already gives us the last one, so if we found it, it IS the last)
    // But we need to verify there isn't an earlier valid one that should be used.
    // Per RSKj: `lastIndexOf(RSK_TAG)` must equal the position found.
    // Since rposition returns the last occurrence, this is satisfied by construction.

    // Rule 3: Tag position < 64 bytes
    if tag_pos >= 64 {
        return Err(MergeMiningError::TagPositionTooFar);
    }

    let hash_start = tag_pos + RSKBLOCK_TAG.len();
    let hash_end = hash_start + RSK_HASH_PREFIX_LEN;

    if coinbase_bytes.len() < hash_end {
        return Err(MergeMiningError::CoinbaseTooShort);
    }

    let committed_prefix = &coinbase_bytes[hash_start..hash_end];
    let expected_prefix = &rsk_block_hash.as_bytes()[..RSK_HASH_PREFIX_LEN];

    if committed_prefix != expected_prefix {
        return Err(MergeMiningError::HashMismatch);
    }

    // Rule 5: At most 128 bytes after the merged-mining hash
    let bytes_after_hash = coinbase_bytes.len() - hash_end;
    if bytes_after_hash > MAX_BYTES_AFTER_MERGED_MINING_HASH {
        return Err(MergeMiningError::ExcessTrailingData);
    }

    Ok(())
}

/// Verify the Merkle proof connecting the coinbase transaction to the Bitcoin
/// block header's merkle_root (Rule 7).
///
/// Uses the bitcoin crate's built-in `check_merkle_root()` which verifies
/// that the header's merkle_root matches the computed root from all transactions.
pub fn verify_merkle_proof(block: &Block) -> Result<(), MergeMiningError> {
    if !block.check_merkle_root() {
        return Err(MergeMiningError::MerkleProofInvalid);
    }
    Ok(())
}

/// Compute the keccak256 hash of an RSK block header's RLP encoding.
///
/// This is the hash that should appear (first 20 bytes) in the Bitcoin
/// coinbase's RSKBLOCK: tag.
pub fn rsk_block_hash_from_rlp(rlp_bytes: &[u8]) -> H256 {
    let hash = Keccak256::digest(rlp_bytes);
    H256::from_slice(&hash)
}

/// Verify the full merge-mining proof for an RSK block.
///
/// Given the raw RLP bytes of the RSK block header and the corresponding
/// Bitcoin block, validates:
/// 1. The coinbase contains the correct RSKBLOCK: tag + hash (Rules 2-5)
/// 2. The coinbase is > 64 bytes (Rule 6)
/// 3. The Merkle proof connects coinbase to the Bitcoin header (Rule 7)
pub fn verify_merge_mining_proof(
    rsk_rlp_bytes: &[u8],
    bitcoin_block: &Block,
) -> Result<(), MergeMiningError> {
    let rsk_hash = rsk_block_hash_from_rlp(rsk_rlp_bytes);
    let coinbase_bytes = extract_coinbase(bitcoin_block);

    // Rules 2-6: Verify RSK tag in coinbase
    verify_coinbase_tag(&coinbase_bytes, &rsk_hash)?;

    // Rule 7: Verify Merkle proof
    verify_merkle_proof(bitcoin_block)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_not_found() {
        let coinbase = vec![0u8; 100];
        let hash = H256::zero();
        assert!(matches!(
            verify_coinbase_tag(&coinbase, &hash),
            Err(MergeMiningError::TagNotFound)
        ));
    }

    #[test]
    fn test_coinbase_too_short_64() {
        // Coinbase exactly 64 bytes with tag at position 0
        // Tag found (pos 0 < 64), hash fits (29 bytes), but total len is 64 <= 64
        let mut coinbase = vec![0u8; 64];
        coinbase[0..RSKBLOCK_TAG.len()].copy_from_slice(RSKBLOCK_TAG);
        let hash = H256::zero();
        let hash_start = RSKBLOCK_TAG.len();
        coinbase[hash_start..hash_start + RSK_HASH_PREFIX_LEN]
            .copy_from_slice(&hash.as_bytes()[..RSK_HASH_PREFIX_LEN]);
        assert!(matches!(
            verify_coinbase_tag(&coinbase, &hash),
            Err(MergeMiningError::CoinbaseTooShort64)
        ));
    }

    #[test]
    fn test_valid_tag() {
        let hash = H256::zero();
        let mut coinbase = vec![0u8; 100];
        let tag_pos = 10;
        coinbase[tag_pos..tag_pos + RSKBLOCK_TAG.len()].copy_from_slice(RSKBLOCK_TAG);
        let hash_start = tag_pos + RSKBLOCK_TAG.len();
        coinbase[hash_start..hash_start + RSK_HASH_PREFIX_LEN]
            .copy_from_slice(&hash.as_bytes()[..RSK_HASH_PREFIX_LEN]);
        assert!(verify_coinbase_tag(&coinbase, &hash).is_ok());
    }

    #[test]
    fn test_tag_too_far() {
        let hash = H256::zero();
        let mut coinbase = vec![0u8; 200];
        let tag_pos = 70; // >= 64
        coinbase[tag_pos..tag_pos + RSKBLOCK_TAG.len()].copy_from_slice(RSKBLOCK_TAG);
        let hash_start = tag_pos + RSKBLOCK_TAG.len();
        coinbase[hash_start..hash_start + RSK_HASH_PREFIX_LEN]
            .copy_from_slice(&hash.as_bytes()[..RSK_HASH_PREFIX_LEN]);
        assert!(matches!(
            verify_coinbase_tag(&coinbase, &hash),
            Err(MergeMiningError::TagPositionTooFar)
        ));
    }

    #[test]
    fn test_hash_mismatch() {
        let hash = H256::zero();
        // Put non-zero bytes in the HIGH part (first 20 bytes) so prefix differs
        let mut wrong_bytes = [0u8; 32];
        wrong_bytes[0] = 42;
        let wrong_hash = H256::from_slice(&wrong_bytes);
        let mut coinbase = vec![0u8; 100];
        let tag_pos = 10;
        coinbase[tag_pos..tag_pos + RSKBLOCK_TAG.len()].copy_from_slice(RSKBLOCK_TAG);
        let hash_start = tag_pos + RSKBLOCK_TAG.len();
        coinbase[hash_start..hash_start + RSK_HASH_PREFIX_LEN]
            .copy_from_slice(&wrong_hash.as_bytes()[..RSK_HASH_PREFIX_LEN]);
        assert!(matches!(
            verify_coinbase_tag(&coinbase, &hash),
            Err(MergeMiningError::HashMismatch)
        ));
    }

    #[test]
    fn test_excess_trailing_data() {
        let hash = H256::zero();
        // Coinbase with tag at pos 10, hash, then 200 trailing bytes (>128)
        let mut coinbase = vec![0u8; 10 + RSKBLOCK_TAG.len() + RSK_HASH_PREFIX_LEN + 200];
        let tag_pos = 10;
        coinbase[tag_pos..tag_pos + RSKBLOCK_TAG.len()].copy_from_slice(RSKBLOCK_TAG);
        let hash_start = tag_pos + RSKBLOCK_TAG.len();
        coinbase[hash_start..hash_start + RSK_HASH_PREFIX_LEN]
            .copy_from_slice(&hash.as_bytes()[..RSK_HASH_PREFIX_LEN]);
        assert!(matches!(
            verify_coinbase_tag(&coinbase, &hash),
            Err(MergeMiningError::ExcessTrailingData)
        ));
    }
}
