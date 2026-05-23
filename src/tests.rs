//! Copied from and based on <https://github.com/rsksmart/union-bridge-client/blob/main/check-fork/src/tests/lib_tests.rs>

mod tester;

use std::fs;
use std::str::FromStr;

use primitive_types::{H256, U256};
use serde::{Deserialize, Serialize};
use tester::TesterRskBlockHeader;

use crate::block_header::{RskBlockHeader, encode_list};
use crate::{CheckForkArgs, RskBlock, check_fork};

const DEFAULT_DIFFICULTY: u128 = 5_904_436_352_267_687_415_636;
const DEFAULT_TIMESTAMP: u64 = 1000;
const DEFAULT_INIT_BLOCK_NUMBER: u64 = 100;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct TestCaseBlockHashValidation {
    pub header: TesterRskBlockHeader,
    #[serde(rename = "expectedHash")]
    pub expected_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct TestCaseMiniChainHashValidation {
    pub chain: Vec<TestCaseBlockHashValidation>,
}

#[test]
fn succeeds_with_two_blocks_when_all_conditions_met() {
    let mut actual_difficulty = U256::zero();

    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);
    actual_difficulty += first_block.header.difficulty;

    let second_block = create_child_block(&first_block);
    actual_difficulty += second_block.header.difficulty;

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();
    let result = check_fork(&args);

    assert_eq!(
        result,
        Ok(actual_difficulty),
        "Expected to succeed for valid input"
    );
}

#[test]
fn succeeds_with_two_blocks_and_one_uncle_when_all_conditions_met() {
    let mut actual_difficulty = U256::zero();

    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);
    actual_difficulty += first_block.header.difficulty;

    let second_block_uncle = create_uncle(&first_block);
    actual_difficulty += second_block_uncle.header.difficulty;

    let mut second_block = create_child_block(&first_block);
    second_block.uncles = vec![second_block_uncle];

    actual_difficulty += second_block.header.difficulty;

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Ok(actual_difficulty),
        "Expected to succeed for valid input"
    );
}

#[test]
fn fails_when_first_block_timestamp_is_lower_than_min_requested() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let second_block = create_child_block(&first_block);

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list)
        .init_block_time(1_000_000)
        .build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("First block timestamp lower than expected"),
        "Expected to fail if first block timestamp is lower than min requested"
    );
}

#[test]
fn fails_when_first_block_number_is_lower_than_min_requested() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let second_block = create_child_block(&first_block);

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list)
        .init_block_number(1_000_000)
        .build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("First block number lower than expected"),
        "Expected to fail if first block number is lower than min requested"
    );
}

#[test]
fn fails_when_blocks_are_not_consecutive() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block = create_child_block(&first_block);
    second_block.header.number = first_block.header.number + 2;

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Block numbers are not consecutive"),
        "Expected to fail if blocks are not consecutive"
    );
}

#[test]
fn fails_when_consecutive_blocks_are_not_parent_child() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block = create_child_block(&first_block);
    second_block.header.parent = H256::from_low_u64_be(1);

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Invalid parent linkage between blocks"),
        "Expected to fail if consecutive blocks are not parent-child"
    );
}

#[test]
fn fails_when_consecutive_block_difficulty_is_lower_than_bounds() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block = create_child_block(&first_block);
    second_block.header.difficulty = first_block
        .header
        .difficulty
        .saturating_sub(first_block.header.difficulty / 399);

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Consecutive Block difficulty is out of bounds"),
        "Expected to fail if the consecutive block difficulty is too low"
    );
}

#[test]
fn fails_when_consecutive_block_difficulty_is_higher_than_bounds() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block = create_child_block(&first_block);
    second_block.header.difficulty = first_block
        .header
        .difficulty
        .saturating_add(first_block.header.difficulty / 399);

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Consecutive Block difficulty is out of bounds"),
        "Expected to fail if the consecutive block difficulty is too high"
    );
}

#[test]
fn fails_when_consecutive_block_timestamp_is_lower() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block = create_child_block(&first_block);
    second_block.header.timestamp = first_block.header.timestamp;

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Block Timestamp is not increasing"),
        "Expected to fail if the consecutive block timestamp is not higher"
    );
}

#[test]
fn fails_when_uncle_number_is_different_from_trunk() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block_uncle = create_uncle(&first_block);
    second_block_uncle.header.number = first_block.header.number + 1;

    let mut second_block = create_child_block(&first_block);
    second_block.uncles = vec![second_block_uncle];

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Uncle's block number does not match trunk block number"),
        "Expected to fail if uncle number is different from trunk number"
    );
}

#[test]
fn fails_when_uncle_parent_is_different_from_trunk() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block_uncle = create_uncle(&first_block);
    second_block_uncle.header.parent = H256::from_low_u64_be(1);

    let mut second_block = create_child_block(&first_block);
    second_block.uncles = vec![second_block_uncle];

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Uncle's parent does not match trunk block's parent"),
        "Expected to fail if uncle parent is different from trunk parent"
    );
}

#[test]
fn fails_when_uncle_difficulty_is_different_from_trunk() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block_uncle = create_uncle(&first_block);
    second_block_uncle.header.difficulty = &first_block.header.difficulty + 1;

    let mut second_block = create_child_block(&first_block);
    second_block.uncles = vec![second_block_uncle];

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Uncle's difficulty does not match trunk block's difficulty"),
        "Expected to fail if uncle has different difficulty from trunk"
    );
}

#[test]
fn fails_when_first_block_pow_is_lower_than_required() {
    let mut first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);
    // make pow lower than required
    first_block.header.difficulty -= 1.into();

    let second_block = create_child_block(&first_block);

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("First block's PoW is less than the required difficulty"),
        "Expected to fail if first block has lower pow than required"
    );
}

#[test]
fn fails_when_consecutive_block_pow_is_lower_than_required() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block = create_child_block(&first_block);

    // make pow lower than required
    second_block.header.difficulty -= 1.into();

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Consecutive Block's PoW is less than the required difficulty"),
        "Expected to fail if consecutive block has lower pow than required"
    );
}

#[test]
fn fails_when_uncle_block_pow_is_lower_than_required() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block_uncle = create_uncle(&first_block);
    // make pow lower than required
    second_block_uncle.header.difficulty -= 1.into();

    let mut second_block = create_child_block(&first_block);
    second_block.uncles = vec![second_block_uncle];

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Uncle's Block PoW is less than the required difficulty"),
        "Expected to fail if uncle block has lower pow than required"
    );
}

#[test]
fn succeed_if_block_hash_eq_expected_hash() {
    let test_case = serde_json::from_slice::<TestCaseBlockHashValidation>(
        &fs::read("src/tests/block-regtest-min-gas-price-zero.json").unwrap(),
    )
    .unwrap();

    let header = RskBlockHeader::from(&test_case.header);
    let hash = header.calculate_block_hash().unwrap();
    let expected_hash = H256::from_str(&test_case.expected_hash).unwrap();

    assert_eq!(expected_hash, hash);
    assert_eq!(test_case.header.hash, hash);
}

#[test]
fn succeed_if_minichain_hashes_are_valid() {
    assert_minichain_hashes_are_valid_from_fixture("src/tests/blockhash-mini-chain.json");
}

#[test]
fn succeed_if_testnet_minichain_hashes_are_valid() {
    assert_minichain_hashes_are_valid_from_fixture("src/tests/blockhash-mini-chain-testnet.json");
}

#[test]
fn fails_if_extension_data_is_precompressed_v1() {
    let mut header = create_first_block(DEFAULT_INIT_BLOCK_NUMBER).header;
    let precompressed_extension_data = encode_list(vec![
        alloy_rlp::encode(1_u8),
        alloy_rlp::encode([0_u8; 32].as_slice()),
    ]);
    header.extension_data = precompressed_extension_data;

    let err = header.calculate_block_hash().expect_err(
        "precompressed extension_data should fail because check-fork expects expanded RPC logsBloom",
    );

    assert_eq!(
        err,
        "unsupported extension_data format: expected RPC logsBloom (256 bytes)"
    );
}

fn create_base_block(number: u64, parent: Option<H256>) -> RskBlock {
    let difficulty = U256::from(DEFAULT_DIFFICULTY);
    let timestamp = DEFAULT_TIMESTAMP;
    let mut header = RskBlockHeader {
        number,
        difficulty,
        parent: parent.unwrap_or_default(),
        timestamp,
        ..Default::default()
    };
    header.hash = header
        .calculate_block_hash()
        .expect("could not calculate block hash");

    RskBlock {
        uncles: vec![],
        header,
    }
}

fn create_first_block(number: u64) -> RskBlock {
    create_base_block(number, None)
}

fn create_child_block(parent: &RskBlock) -> RskBlock {
    let mut child = create_base_block(parent.header.number + 1, Some(parent.header.hash));
    child.header.timestamp = parent.header.timestamp + 100;
    child.header.difficulty = build_valid_consecutive_difficulty(parent);
    // we modified the child, we need to recalculate the hash
    child.header.hash = child
        .header
        .calculate_block_hash()
        .expect("could not calculate block hash");
    child
}

fn create_uncle(brother: &RskBlock) -> RskBlock {
    let mut uncle = create_base_block(brother.header.number, Some(brother.header.parent));
    uncle.header.timestamp = brother.header.timestamp + 10;
    uncle.header.difficulty = brother.header.difficulty;
    // we modified the uncle, we need to recalculate the hash
    uncle.header.hash = uncle
        .header
        .calculate_block_hash()
        .expect("could not calculate block hash");
    uncle
}

fn build_valid_consecutive_difficulty(first_block: &RskBlock) -> U256 {
    first_block.header.difficulty + first_block.header.difficulty / 400 // limit threshold
}

fn assert_minichain_hashes_are_valid_from_fixture(path: &str) {
    let test_cases =
        serde_json::from_slice::<TestCaseMiniChainHashValidation>(&fs::read(path).unwrap())
            .unwrap();

    for (i, block) in test_cases.chain.iter().enumerate() {
        let header = RskBlockHeader::from(&block.header);
        let calculated_hash = header.calculate_block_hash().unwrap();
        let expected_hash = H256::from_str(&block.expected_hash).unwrap();

        assert_eq!(
            calculated_hash, header.hash,
            "Block hash mismatch at index {i} (height {})",
            header.number
        );
        assert_eq!(
            calculated_hash, expected_hash,
            "Block hash mismatch with expectedHash at index {i} (height {})",
            header.number
        );
    }
}

#[derive(Default)]
struct CheckForkArgsBuilder {
    init_block_time: Option<u64>,
    init_block_number: Option<u64>,
    block_list: Vec<RskBlock>,
}

impl CheckForkArgsBuilder {
    fn new(block_list: Vec<RskBlock>) -> Self {
        CheckForkArgsBuilder {
            block_list,
            ..Default::default()
        }
    }

    fn init_block_time(mut self, init_block_time: u64) -> Self {
        self.init_block_time = Some(init_block_time);
        self
    }

    fn init_block_number(mut self, init_block_number: u64) -> Self {
        self.init_block_number = Some(init_block_number);
        self
    }

    fn build(self) -> CheckForkArgs {
        CheckForkArgs {
            init_block_time: self.init_block_time.unwrap_or(DEFAULT_TIMESTAMP),
            init_block_number: self.init_block_number.unwrap_or(DEFAULT_INIT_BLOCK_NUMBER),
            block_list: self.block_list,
        }
    }
}
