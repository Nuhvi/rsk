// #![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![warn(clippy::must_use_candidate)]

pub mod block_header;
pub mod rlp;
#[cfg(test)]
mod tests;

// --- RSK Core Logic Simulation ---

use primitive_types::{H256, U256};
use serde::{Deserialize, Serialize};

use crate::block_header::RskBlockHeader;

pub const SUPERBLOCK_TIMES_DIFFICULTY: u8 = 20;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RskBlock {
    pub uncles: Vec<RskBlock>,
    pub pow: H256, // used to accumulate effort (from check_fork_accumulator)
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
    // 2. validate first block
    //

    let first_block = &block_list[0];
    validate_first_block(first_block, init_block_time, init_block_number)?;
    validate_block_hash(&first_block.header)?;

    let mut cumulative_effort = accumulate_effort(U256::zero(), first_block)?;

    //
    // 3. validate consecutive blocks
    //
    for i in 1..block_list.len() {
        let block = &block_list[i];
        let prev_block = &block_list[i - 1];

        validate_consecutive_block(block, prev_block)?;
        validate_block_hash(&block.header)?;
        cumulative_effort = accumulate_effort(cumulative_effort, block)?;

        for uncle in &block.uncles {
            validate_uncle(prev_block, uncle)?;
            cumulative_effort = accumulate_effort(cumulative_effort, uncle)?;
        }
    }

    //
    // 4. validate enough cumulative PoW
    //
    dbg!((block_list.len(), cumulative_effort));

    Ok(cumulative_effort)
}

fn accumulate_effort(cumulative_effort: U256, block: &RskBlock) -> Result<U256, &'static str> {
    let effort = calculate_block_effort(block)?;

    cumulative_effort
        .checked_add(effort)
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

    validate_enough_effort_superblock(block, "first")?;

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
    if block.header.parent != prev_block.header.hash {
        return Err("Invalid parent linkage between blocks");
    }
    validate_enough_effort_superblock(block, "consecutive")?;
    validate_difficulty_in_bounds(block, prev_block)?;

    Ok(())
}

fn validate_uncle(trunk_block: &RskBlock, uncle: &RskBlock) -> Result<(), &'static str> {
    if uncle.header.number != trunk_block.header.number {
        return Err("Uncle's block number does not match trunk block number");
    }

    if uncle.header.parent != trunk_block.header.parent {
        return Err("Uncle's parent does not match trunk block's parent");
    }

    if uncle.header.difficulty != trunk_block.header.difficulty {
        return Err("Uncle's difficulty does not match trunk block's difficulty");
    }

    validate_block_hash(&uncle.header)?;
    validate_enough_effort_superblock(uncle, "uncle")?;

    Ok(())
}

fn validate_enough_effort_superblock(
    block: &RskBlock,
    _block_type: &str,
) -> Result<(), &'static str> {
    let expected_effort = block
        .header
        .difficulty
        .checked_mul(SUPERBLOCK_TIMES_DIFFICULTY.into())
        .ok_or("Overflow occurred multiplying difficulty by times")?;
    let actual_effort = calculate_block_effort(block)?;

    if actual_effort >= expected_effort {
        return Ok(());
    }

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

fn calculate_block_effort(block: &RskBlock) -> Result<U256, &'static str> {
    let pow = U256::from_big_endian(block.pow.as_bytes());
    // compute the effort by inverting the pow
    // U256::MAX, the "difficulty 1" target, represents the easiest possible target
    U256::MAX
        .checked_div(pow)
        .ok_or("0 division on calculate_block_effort")
}

fn validate_block_hash(header: &RskBlockHeader) -> Result<(), &'static str> {
    let actual_hash = header.calculate_block_hash()?;
    if header.hash != actual_hash {
        println!("Block number: {}", header.number);
        return Err("Block header hash is not matching");
    }
    Ok(())
}
