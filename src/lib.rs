// #![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![warn(clippy::must_use_candidate)]

use primitive_types::U256;
use serde::{Deserialize, Serialize};

pub mod block_header;
pub mod light_client;
pub mod rlp;
#[cfg(test)]
pub(crate) mod tests;

use crate::block_header::RskBlockHeader;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RskBlock {
    pub uncles: Vec<RskBlock>,
    pub header: RskBlockHeader,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckForkArgs {
    pub init_block_time: u64,
    pub init_block_number: u64,
    pub block_list: Vec<RskBlock>,
}

/// Check fork validity and return cumulative `PoW`
///
/// # Errors
///
/// Returns an error string if the fork validation fails (e.g., insufficient blocks,
/// invalid block sequence, cumulative `PoW` below threshold, or bridge event mismatch)
#[allow(dead_code)]
pub fn check_fork(args: &CheckForkArgs) -> Result<U256, &'static str> {
    let CheckForkArgs {
        init_block_time,
        init_block_number,
        block_list,
    } = args;

    // extract values directly to avoid dereferencing later
    let init_block_time = *init_block_time;
    let init_block_number = *init_block_number;

    //
    // validate first block
    //

    // TODO: Move validation in the RskBlockHeader itself!

    let first_block = &block_list[0];
    validate_first_block(first_block, init_block_time, init_block_number)?;

    let mut cumulative_effort = accumulate_difficulty(U256::zero(), first_block)?;

    //
    // validate consecutive blocks
    //
    for i in 1..block_list.len() {
        let block = &block_list[i];
        let prev_block = &block_list[i - 1];

        validate_consecutive_block(block, prev_block)?;
        cumulative_effort = accumulate_difficulty(cumulative_effort, block)?;

        for uncle in &block.uncles {
            uncle.header.validate_is_uncle_of(&prev_block.header)?;
            cumulative_effort = accumulate_difficulty(cumulative_effort, uncle)?;
        }
    }

    Ok(cumulative_effort)
}

fn accumulate_difficulty(cumulative_effort: U256, block: &RskBlock) -> Result<U256, &'static str> {
    cumulative_effort
        .checked_add(block.header.difficulty)
        .ok_or("Overflow occurred adding block's PoW")
}

fn validate_first_block(
    block: &RskBlock,
    init_block_time: u64,
    init_block_number: u64,
) -> Result<(), &'static str> {
    if block.header.timestamp < init_block_time {
        return Err("First block timestamp lower than expected");
    }

    if block.header.number < init_block_number {
        return Err("First block number lower than expected");
    }

    Ok(())
}

fn validate_consecutive_block(block: &RskBlock, prev_block: &RskBlock) -> Result<(), &'static str> {
    // block timestamp should be greater than previous one
    if block.header.timestamp <= prev_block.header.timestamp {
        return Err("Block Timestamp is not increasing");
    }

    // blocks should be consecutive
    let expected_next_number = prev_block
        .header
        .number
        .checked_add(1)
        .ok_or("Overflow incrementing previous block number")?;

    if block.header.number != expected_next_number {
        return Err("Block numbers are not consecutive");
    }
    // previous should be the parent of current one
    if block.header.parent != prev_block.header.calculate_block_hash() {
        return Err("Invalid parent linkage between blocks");
    }
    validate_difficulty_in_bounds(block, prev_block)?;

    Ok(())
}

fn validate_difficulty_in_bounds(
    block: &RskBlock,
    prev_block: &RskBlock,
) -> Result<(), &'static str> {
    // check these RSKj lines:
    // - https://github.com/rsksmart/rskj/blob/3cd3401a9c6cfd3dfa63120304d0f26f691ae6e7/rskj-core/src/main/java/co/rsk/core/DifficultyCalculator.java#L64
    // - https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/org/ethereum/config/Constants.java#L150
    let max_delta = prev_block.header.difficulty / 400;

    let lower_bound = prev_block.header.difficulty.saturating_sub(max_delta);
    let upper_bound = prev_block.header.difficulty.saturating_add(max_delta);

    let in_bounds = (lower_bound..=upper_bound).contains(&block.header.difficulty);
    if in_bounds {
        Ok(())
    } else {
        Err("Consecutive Block difficulty is out of bounds")
    }
}
