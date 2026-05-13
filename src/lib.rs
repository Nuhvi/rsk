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

    pub fn save_block_with_total_difficulty_calculation(&mut self, block: Block) {
        let parent_total_difficulty = self.get_total_difficulty_for_hash(&block.get_parent_hash());
        let total_difficulty = parent_total_difficulty + block.get_cumulative_difficulty();
        self.save_block(block, total_difficulty);
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

    #[tokio::test]
    async fn real_blocks_indexed_store_with_uncles() {
        let rpc_url =
            std::env::var("RSK_RPC").unwrap_or_else(|_| "https://public-node.rsk.co".to_string());
        let client = reqwest::Client::new();

        async fn rpc_call(
            client: &reqwest::Client,
            url: &str,
            method: &str,
            params: serde_json::Value,
        ) -> serde_json::Value {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            });
            let mut resp: serde_json::Value = client
                .post(url)
                .json(&body)
                .send()
                .await
                .expect("RPC request failed")
                .json()
                .await
                .expect("JSON parse failed");
            resp["result"].take()
        }

        fn parse_difficulty(value: &serde_json::Value) -> BigUint {
            let hex = value.as_str().unwrap_or("0x0").trim_start_matches("0x");
            BigUint::parse_bytes(hex.as_bytes(), 16).unwrap_or_default()
        }

        fn parse_hex_u64(value: &serde_json::Value) -> u64 {
            let hex = value.as_str().unwrap_or("0x0").trim_start_matches("0x");
            u64::from_str_radix(hex, 16).unwrap_or(0)
        }

        fn display_eh(val: &BigUint) -> String {
            let one_eh = BigUint::from(10u64).pow(18);
            let whole = val / &one_eh;
            let rem = val % &one_eh;
            let dec = rem * BigUint::from(1000u32) / &one_eh;
            let d: u64 = dec.iter_u64_digits().next().unwrap_or(0);
            format!("{whole}.{d:03} EH")
        }

        fn fetch_uncles<'a>(
            client: &'a reqwest::Client,
            rpc_url: &'a str,
            hex: &'a str,
        ) -> impl std::future::Future<Output = Vec<BlockHeader>> + 'a {
            async move {
                let count = rpc_call(
                    client,
                    rpc_url,
                    "eth_getUncleCountByBlockNumber",
                    serde_json::json!([hex]),
                )
                .await;
                let n = parse_hex_u64(&count) as usize;
                let mut uncles = Vec::with_capacity(n);
                for i in 0..n {
                    let u = rpc_call(
                        client,
                        rpc_url,
                        "eth_getUncleByBlockNumberAndIndex",
                        serde_json::json!([hex, format!("{i:#x}")]),
                    )
                    .await;
                    uncles.push(BlockHeader {
                        hash: u["hash"].as_str().unwrap_or("").to_string(),
                        parent_hash: u["parentHash"].as_str().unwrap_or("").to_string(),
                        difficulty: parse_difficulty(&u["difficulty"]),
                        number: parse_hex_u64(&u["number"]),
                    });
                }
                uncles
            }
        }

        let hex_8375 = "0x86c29f";
        let hex_8376 = "0x86c2a0";
        let hex_8377 = "0x86c2a1";

        let raw_8375 = rpc_call(
            &client,
            &rpc_url,
            "eth_getBlockByNumber",
            serde_json::json!([hex_8375, false]),
        )
        .await;

        let raw_8376 = rpc_call(
            &client,
            &rpc_url,
            "eth_getBlockByNumber",
            serde_json::json!([hex_8376, false]),
        )
        .await;

        let raw_8377 = rpc_call(
            &client,
            &rpc_url,
            "eth_getBlockByNumber",
            serde_json::json!([hex_8377, false]),
        )
        .await;

        let uncles_8376 = fetch_uncles(&client, &rpc_url, hex_8376).await;
        let uncles_8377 = fetch_uncles(&client, &rpc_url, hex_8377).await;

        // Starting TD comes from the RPC (block 8_833_375)
        // The explorer shows it as ≈54,543,886,113.12 EH at time of viewing
        let td_8375 = parse_difficulty(&raw_8375["totalDifficulty"]);

        let block_8376 = Block {
            header: BlockHeader {
                hash: raw_8376["hash"].as_str().unwrap_or("").to_string(),
                parent_hash: raw_8376["parentHash"].as_str().unwrap_or("").to_string(),
                difficulty: parse_difficulty(&raw_8376["difficulty"]),
                number: parse_hex_u64(&raw_8376["number"]),
            },
            uncle_list: uncles_8376,
        };

        let block_8377 = Block {
            header: BlockHeader {
                hash: raw_8377["hash"].as_str().unwrap_or("").to_string(),
                parent_hash: raw_8377["parentHash"].as_str().unwrap_or("").to_string(),
                difficulty: parse_difficulty(&raw_8377["difficulty"]),
                number: parse_hex_u64(&raw_8377["number"]),
            },
            uncle_list: uncles_8377,
        };

        let expected_td = parse_difficulty(&raw_8377["totalDifficulty"]);

        let mut store = IndexedBlockStore::new();

        store.save_block(
            Block {
                header: BlockHeader {
                    hash: block_8376.header.parent_hash.clone(),
                    parent_hash: String::new(),
                    difficulty: BigUint::from(0u32),
                    number: 8_833_375,
                },
                uncle_list: vec![],
            },
            td_8375,
        );

        store.save_block_with_total_difficulty_calculation(block_8376);
        let hash_8377 = block_8377.get_hash();
        store.save_block_with_total_difficulty_calculation(block_8377);

        let stored_td = store.get_total_difficulty_for_hash(&hash_8377);

        println!("block 8_833_377 total difficulty:");
        println!("  stored:   {}", display_eh(&stored_td));
        println!("  RPC:      {}", display_eh(&expected_td));
        println!();
        println!("(explorer showed ≈54,543,940,517.27 EH at time of viewing)");

        assert_eq!(stored_td, expected_td);
    }
}
