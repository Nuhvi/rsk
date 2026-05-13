// TODO: do we have to use this crate?
use num_bigint::BigUint;
use std::collections::HashMap;

// --- RSK Core Logic Simulation ---

#[derive(Clone, Debug)]
pub struct BlockHeader {
    pub hash: String,
    pub parent_hash: String,
    pub difficulty: BigUint,
    pub number: u64,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub uncle_list: Vec<BlockHeader>,
}

impl Block {
    pub fn new(hash: String, parent_hash: String, difficulty: u32, number: u64) -> Self {
        Self {
            header: BlockHeader {
                hash,
                parent_hash,
                difficulty: BigUint::from(difficulty),
                number,
            },
            uncle_list: vec![],
        }
    }

    pub fn get_hash(&self) -> String {
        self.header.hash.clone()
    }

    pub fn get_parent_hash(&self) -> String {
        self.header.parent_hash.clone()
    }

    /// Ported logic: Sum of header difficulty + all uncles
    pub fn get_cumulative_difficulty(&self) -> BigUint {
        self.uncle_list
            .iter()
            .fold(self.header.difficulty.clone(), |acc, uncle| {
                acc + &uncle.difficulty
            })
    }
}

// --- Block Store Simulation ---

pub struct IndexedBlockStore {
    // Stores: Block Hash -> (Block, TotalDifficulty)
    pub blocks: HashMap<String, (Block, BigUint)>,
}

impl IndexedBlockStore {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
        }
    }

    pub fn save_block(&mut self, block: Block, total_difficulty: BigUint) {
        self.blocks
            .insert(block.get_hash(), (block, total_difficulty));
    }

    pub fn get_block_by_hash(&self, hash: &str) -> Option<&Block> {
        self.blocks.get(hash).map(|(b, _)| b)
    }

    pub fn get_total_difficulty_for_hash(&self, hash: &str) -> BigUint {
        self.blocks
            .get(hash)
            .map(|(_, td)| td.clone())
            .unwrap_or_default()
    }
}

// --- The Ported Test ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsk_cumulative_work_calculation() {
        let mut indexed_block_store = IndexedBlockStore::new();

        // 1. Setup Genesis
        let genesis = Block::new("genesis".to_string(), "0".to_string(), 100, 0);
        let genesis_hash = genesis.get_hash();
        let mut td = genesis.get_cumulative_difficulty(); // In RSK, genesis TD starts with its own work

        indexed_block_store.save_block(genesis.clone(), td.clone());

        // 2. Build "Best Line" (Main Chain) - 100 blocks
        let mut best_line = Vec::new();
        let mut prev_hash = genesis_hash;

        for i in 1..=100 {
            let mut block = Block::new(format!("hash_{}", i), prev_hash.clone(), 10, i as u64);

            // Simulate an uncle to test your get_cumulative_difficulty logic
            if i % 10 == 0 {
                block.uncle_list.push(BlockHeader {
                    hash: format!("uncle_{}", i),
                    parent_hash: prev_hash.clone(),
                    difficulty: BigUint::from(2u32),
                    number: i as u64,
                });
            }

            td += block.get_cumulative_difficulty();
            indexed_block_store.save_block(block.clone(), td.clone());

            prev_hash = block.get_hash();
            best_line.push(block);
        }

        // 3. Create Fork at block 60 - 50 blocks
        let fork_parent = &best_line[59]; // index 59 is block 60
        let mut fork_line = Vec::new();
        let mut fork_prev_hash = fork_parent.get_hash();

        // Get TD at the fork point
        let mut fork_td = indexed_block_store.get_total_difficulty_for_hash(&fork_prev_hash);

        for i in 1..=50 {
            let block = Block::new(
                format!("fork_hash_{}", i),
                fork_prev_hash.clone(),
                12, // slightly higher diff
                fork_parent.header.number + i as u64,
            );

            fork_td += block.get_cumulative_difficulty();
            indexed_block_store.save_block(block.clone(), fork_td.clone());

            fork_prev_hash = block.get_hash();
            fork_line.push(block);
        }

        // 4. Manual Verification Calculations (Replicating the HashMap logic in Java test)
        let mut expected_tds = HashMap::new();
        let mut manual_td = genesis.get_cumulative_difficulty();

        for b in &best_line {
            manual_td += b.get_cumulative_difficulty();
            expected_tds.insert(b.get_hash(), manual_td.clone());
        }

        let mut manual_fork_td = expected_tds.get(&fork_parent.get_hash()).unwrap().clone();
        for b in &fork_line {
            manual_fork_td += b.get_cumulative_difficulty();
            expected_tds.insert(b.get_hash(), manual_fork_td.clone());
        }

        // 5. Final Assertions
        // Check Best Line
        for block in &best_line {
            let stored_td = indexed_block_store.get_total_difficulty_for_hash(&block.get_hash());
            let expected = expected_tds.get(&block.get_hash()).unwrap();
            assert_eq!(
                stored_td, *expected,
                "Main chain TD mismatch at block {}",
                block.header.number
            );
        }

        // Check Fork Line
        for block in &fork_line {
            let stored_td = indexed_block_store.get_total_difficulty_for_hash(&block.get_hash());
            let expected = expected_tds.get(&block.get_hash()).unwrap();
            assert_eq!(
                stored_td, *expected,
                "Fork chain TD mismatch at block {}",
                block.header.number
            );
        }

        println!("Test Passed: All cumulative difficulties match across branches.");
    }
}
