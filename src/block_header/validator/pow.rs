use bitcoin::hashes::Hash;
use primitive_types::U256;

use crate::block_header::{RskBlockHeader, validator::ValidationError};

impl RskBlockHeader {
    #[must_use]
    /// Return this [RskBlockHeader] target.
    pub fn target(&self) -> U256 {
        // RSK target = 2^256 / difficulty.
        // We approximate 2^256 as U256::MAX (off by 1, same as Bitcoin does).
        if self.difficulty.is_zero() {
            U256::MAX
        } else {
            U256::MAX / self.difficulty.max(1.into())
        }
    }

    /// Compute the double-SHA256 hash of the 80-byte Bitcoin block header and
    /// verify that it actually sits below the declared Rootstock difficulty target.
    pub fn validate_proof_of_work(&self) -> Result<(), ValidationError> {
        // Compute double-SHA256 of the 80-byte Bitcoin header.
        let hash = self.bitcoin_merged_mining_header.block_hash();

        // Bitcoin hashes are displayed reversed but stored
        // little-endian internally, so we reverse before converting to U256.
        let mut hash_be = hash.to_byte_array();
        hash_be.reverse();
        let pow_hash = U256::from_big_endian(&hash_be);

        if pow_hash > self.target() {
            return Err(ValidationError::InsufficientWork);
        }

        Ok(())
    }
}
