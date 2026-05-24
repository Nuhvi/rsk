//! Proof of Work rules
//!
//! Reference: <https://github.com/rsksmart/rskj/blob/6a4c9a24/rskj-core/src/main/java/co/rsk/validators/ProofOfWorkRule.java#L50-L147>
//!
//! # Validation rules (in order)
//!
//! ## Rule 1 — Hash ≤ Target  
//! The double-SHA256 of the 80-byte Bitcoin merged-mining header, interpreted
//! as a big-endian [`U256`], must be **less than or equal to** the RSK target:
//!
//! ```text
//! target = U256::MAX / difficulty          (difficulty > 0)
//! target = U256::MAX                       (difficulty == 0)
//! ```
//!
//! Equality is **valid** (`hash <= target`), matching the Java reference:
//! `bitcoinMergedMiningBlockHashBI.compareTo(target) > 0 → reject`.
//!
//! TODO:
//!
//! ## Rule 2 — RSK tag present in coinbase tail
//! The decompressed coinbase transaction tail must contain the byte sequence
//! `RSK_TAG ++ header.getHashForMergedMining()` (the last occurrence is used).
//! If absent the block is rejected.
//!
//! ## Rule 3 — RSK tag position < 64
//! The position of the RSK tag within the coinbase tail must be strictly less
//! than 64 bytes. This prevents a midstate-malleability attack where an
//! attacker could produce two blocks with different hashes but the same SPV
//! proof by prepending an extra 64-byte chunk before the tag.
//!
//! ## Rule 4 — RSK tag is the last RSK tag
//! `lastIndexOf(RSK_TAG)` must equal the position found in Rule 2. Duplicate
//! RSK tags before the valid one are rejected.
//!
//! ## Rule 5 — At most 128 bytes after the merged-mining hash
//! The number of bytes that follow `RSK_TAG ++ block_hash` in the coinbase
//! tail must not exceed `MAX_BYTES_AFTER_MERGED_MINING_HASH` (128). Excess
//! trailing data is rejected.
//!
//! ## Rule 6 — Coinbase length > 64 bytes
//! The total coinbase length (`midstate_byte_count + tail_length`) must be
//! greater than 64. Bitcoin's serialisation requires at least one full SHA-256
//! block of input.
//!
//! ## Rule 7 — Merkle proof valid
//! The SHA-256d hash of the reconstructed coinbase transaction must connect to
//! the `merkleRoot` field of the Bitcoin header via the supplied Merkle branch.
//! Two proof formats are supported depending on the active consensus rules:
//! - **Pre-RSKIP92**: genesis format (`GenesisMerkleProofValidator`)
//! - **RSKIP92+**: compact format (`Rskip92MerkleProofValidator`), with an
//!   additional RSKIP180 flag that tightens branch-length limits.
//!
//! ## Out of scope — Fallback mining (pre-RSKIP98)
//! Before RSKIP98 activation, blocks with difficulty ≤ `fallbackMiningDifficulty`
//! and no coinbase/merkle-proof fields may be authenticated by an ECDSA
//! signature over the block header instead of PoW. This path is not
//! implemented here.

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use primitive_types::U256;

use crate::block_header::{RskBlockHeader, validator::ValidationError};

impl RskBlockHeader {
    #[must_use]
    /// Return this [RskBlockHeader] target.
    ///
    /// `target = U256::MAX / difficulty`, or `U256::MAX` when difficulty is zero.
    pub fn target(&self) -> U256 {
        if self.difficulty.is_zero() {
            U256::MAX
        } else {
            U256::MAX / self.difficulty.max(1.into())
        }
    }

    /// Compute the double-SHA256 hash of the 80-byte Bitcoin block header and
    /// verify that it sits at or below the declared Rootstock difficulty target
    /// (Rule 1). See module-level docs for the full rule set.
    pub fn validate_proof_of_work(&self) -> Result<(), ValidationError> {
        let hash = self.bitcoin_merged_mining_header.block_hash();
        self.validate_proof_of_work_with_hash(&hash)
    }

    fn validate_proof_of_work_with_hash(&self, hash: &BlockHash) -> Result<(), ValidationError> {
        // Bitcoin hashes are stored little-endian internally; reverse before
        // converting to U256 so the numeric comparison is big-endian correct.
        let mut hash_be = hash.to_byte_array();
        hash_be.reverse();
        let pow_hash = U256::from_big_endian(&hash_be);

        // Java reference: `compareTo(target) > 0 → reject`, so equality passes.
        if pow_hash > self.target() {
            return Err(ValidationError::InsufficientWork);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_header::tests::RAW_BLOCK_HEADER_8329127;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use primitive_types::U256;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn block_with_difficulty(difficulty: U256) -> RskBlockHeader {
        RskBlockHeader {
            difficulty,
            ..RskBlockHeader::default()
        }
    }

    /// Build a [`BlockHash`] whose numeric (big-endian) value equals `value`.
    ///
    /// `validate_proof_of_work_with_hash` reverses the bytes before interpreting
    /// them as a [`U256`], so we store them little-endian here so the round-trip
    /// produces exactly `value`.
    fn hash_from_u256(value: U256) -> BlockHash {
        let mut bytes = value.to_big_endian();
        bytes.reverse();
        BlockHash::from_byte_array(bytes)
    }

    // ── target() ─────────────────────────────────────────────────────────────

    #[test]
    fn target_difficulty_one_returns_max() {
        // MAX / 1 == MAX
        assert_eq!(block_with_difficulty(1.into()).target(), U256::MAX);
    }

    #[test]
    fn target_difficulty_two_returns_half_max() {
        assert_eq!(block_with_difficulty(2.into()).target(), U256::MAX / 2);
    }

    #[test]
    fn target_zero_difficulty_returns_max() {
        // Zero difficulty must not panic and must return U256::MAX.
        assert_eq!(block_with_difficulty(U256::zero()).target(), U256::MAX);
    }

    #[test]
    fn target_max_difficulty_returns_one() {
        // MAX / MAX == 1 — the hardest possible target.
        assert_eq!(block_with_difficulty(U256::MAX).target(), U256::one());
    }

    #[test]
    fn target_scales_inversely_with_difficulty() {
        let easy = block_with_difficulty(2.into()).target();
        let hard = block_with_difficulty(1_000_000.into()).target();
        assert!(easy > hard, "higher difficulty must produce a lower target");
    }

    // ── validate_proof_of_work — real block ───────────────────────────────────

    #[test]
    fn valid_block_passes() {
        let block = RskBlockHeader::decode_rlp(&RAW_BLOCK_HEADER_8329127).unwrap();
        assert!(block.validate_proof_of_work().is_ok());
    }

    // ── validate_proof_of_work_with_hash — Rule 1 boundary ───────────────────
    //
    // Java: `bitcoinMergedMiningBlockHashBI.compareTo(target) > 0 → reject`
    // i.e. valid range is [0, target] inclusive — equality passes.

    #[test]
    fn hash_well_below_target_passes() {
        let block = block_with_difficulty(4.into());
        let hash = hash_from_u256(block.target() - 1);
        assert!(block.validate_proof_of_work_with_hash(&hash).is_ok());
    }

    #[test]
    fn hash_equal_to_target_passes() {
        // Equality is the exact boundary: compareTo == 0, which is NOT > 0, so it passes.
        let block = block_with_difficulty(4.into());
        let hash = hash_from_u256(block.target());
        assert!(
            block.validate_proof_of_work_with_hash(&hash).is_ok(),
            "hash == target must pass (Java uses >, not >=)"
        );
    }

    #[test]
    fn hash_one_above_target_fails() {
        // One above the target is the exact first failing value.
        let block = block_with_difficulty(4.into());
        let hash = hash_from_u256(block.target() + 1);
        assert_eq!(
            block.validate_proof_of_work_with_hash(&hash),
            Err(ValidationError::InsufficientWork),
        );
    }

    #[test]
    fn hash_zero_passes_hardest_difficulty() {
        // All-zeros hash is numerically 0, which is ≤ any target.
        let block = block_with_difficulty(U256::MAX);
        let hash = hash_from_u256(U256::zero());
        assert!(block.validate_proof_of_work_with_hash(&hash).is_ok());
    }

    #[test]
    fn hash_max_fails_easiest_difficulty() {
        // target == U256::MAX when difficulty == 1, and U256::MAX is NOT > U256::MAX,
        // so this is the one case where MAX hash still passes — test the
        // immediately-harder difficulty instead to get a genuine failure.
        let block = block_with_difficulty(2.into()); // target == MAX/2
        let hash = hash_from_u256(U256::MAX); // hash >> target
        assert_eq!(
            block.validate_proof_of_work_with_hash(&hash),
            Err(ValidationError::InsufficientWork),
        );
    }

    #[test]
    fn hash_max_passes_when_difficulty_is_one() {
        // Special case: difficulty == 1 → target == U256::MAX.
        // hash == U256::MAX == target, so equality rule means it passes.
        let block = block_with_difficulty(1.into());
        let hash = hash_from_u256(U256::MAX);
        assert!(
            block.validate_proof_of_work_with_hash(&hash).is_ok(),
            "hash == U256::MAX == target must pass when difficulty is 1"
        );
    }

    #[test]
    fn zero_difficulty_passes_with_any_hash() {
        // difficulty == 0 → target == U256::MAX; must not panic.
        let block = block_with_difficulty(U256::zero());
        let hash = hash_from_u256(U256::MAX - 1);
        assert!(block.validate_proof_of_work_with_hash(&hash).is_ok());
    }
}
