//! Copied from and based on <https://github.com/rsksmart/union-bridge-client/blob/main/check-fork/src/tests/lib_tests.rs>

mod tester;

use std::fs;
use std::str::FromStr;

use primitive_types::{H256, U256};
use serde::{Deserialize, Serialize};
use tester::TesterRskBlockHeader;

use crate::block_header::{RskBlockHeader, encode_list};
use crate::{BridgeEvent, CheckForkArgs, RskBlock, SUPERBLOCK_TIMES_DIFFICULTY, check_fork};

const DEFAULT_DIFFICULTY: u128 = 5_904_436_352_267_687_415_636;
const DEFAULT_TIMESTAMP: u64 = 1000;
const DEFAULT_INIT_BLOCK_NUMBER: u64 = 100;
const DEFAULT_REQ_NUMBER_OF_BLOCKS: u32 = 2;

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
    let mut actual_effort = U256::zero();

    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);
    actual_effort += calculate_effort_from_pow(first_block.pow);

    let second_block = create_child_block(&first_block);
    actual_effort += calculate_effort_from_pow(second_block.pow);

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();
    let result = check_fork(&args);

    assert_eq!(
        result,
        Ok(actual_effort),
        "Expected to succeed for valid input"
    );
}

#[test]
fn succeeds_with_two_blocks_and_one_uncle_when_all_conditions_met() {
    let mut actual_effort = U256::zero();

    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);
    actual_effort += calculate_effort_from_pow(first_block.pow);

    let second_block_uncle = create_uncle(&first_block);
    actual_effort += calculate_effort_from_pow(second_block_uncle.pow);

    let mut second_block = create_child_block(&first_block);
    second_block.uncles = vec![second_block_uncle];

    actual_effort += calculate_effort_from_pow(second_block.pow);

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Ok(actual_effort),
        "Expected to succeed for valid input"
    );
}

#[test]
fn fails_when_required_block_number_is_invalid() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let second_block = create_child_block(&first_block);

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list)
        .required_num_blocks(0)
        .build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Invalid number of required blocks"),
        "Expected to fail if requested number of blocks are invalid"
    );
}

#[test]
fn fails_when_provided_blocks_are_less_than_required() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let second_block = create_child_block(&first_block);

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list)
        .required_num_blocks(3)
        .build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Insufficient number of blocks"),
        "Expected to fail if provided blocks are less than requested"
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
fn fails_when_event_found_in_second_block() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block = create_child_block(&first_block);
    second_block.bridge_event = Some(BridgeEvent {
        utxo_id: "utxo_2".to_string(),
    });

    let block_list = vec![first_block, second_block];

    let args = CheckForkArgsBuilder::new(block_list).build();

    let result = check_fork(&args);
    assert_eq!(
        result,
        Err("Only the first block should contain a BridgeEvent"),
        "Expected to fail if an event is found in second block"
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
    second_block.pow = calculate_superblock_effort(second_block.header.difficulty);

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
    second_block.pow = calculate_superblock_effort(second_block.header.difficulty);

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
#[ignore = "TODO: re-enable this check when Superchain is implemented and checked in check_fork (now just logging)"]
fn fails_when_first_block_pow_is_lower_than_required() {
    let mut first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);
    // make pow lower than required
    first_block.pow = calculate_superblock_effort(first_block.header.difficulty - 1);

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
#[ignore = "TODO: re-enable this check when Superchain is implemented and checked in check_fork (now just logging)"]
fn fails_when_consecutive_block_pow_is_lower_than_required() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block = create_child_block(&first_block);

    // make pow lower than required
    second_block.pow = calculate_superblock_effort(second_block.header.difficulty - 1);

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
#[ignore = "TODO: re-enable this check when Superchain is implemented and checked in check_fork (now just logging)"]
fn fails_when_uncle_block_pow_is_lower_than_required() {
    let first_block = create_first_block(DEFAULT_INIT_BLOCK_NUMBER);

    let mut second_block_uncle = create_uncle(&first_block);
    // make pow lower than required
    second_block_uncle.pow = calculate_superblock_effort(second_block_uncle.header.difficulty - 1);

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

fn create_base_block(number: u64, bridge_event: bool, parent: Option<H256>) -> RskBlock {
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
        // this will be removed
        bridge_event: bridge_event.then(|| BridgeEvent {
            utxo_id: format!("utxo_{number}"),
        }),
        uncles: vec![],
        pow: calculate_superblock_effort(U256::from(DEFAULT_DIFFICULTY)),
        header,
    }
}

fn create_first_block(number: u64) -> RskBlock {
    create_base_block(number, true, None)
}

fn create_child_block(parent: &RskBlock) -> RskBlock {
    let mut child = create_base_block(parent.header.number + 1, false, Some(parent.header.hash));
    child.header.timestamp = parent.header.timestamp + 100;
    child.header.difficulty = build_valid_consecutive_difficulty(parent);
    child.pow = calculate_superblock_effort(child.header.difficulty);
    // we modified the child, we need to recalculate the hash
    child.header.hash = child
        .header
        .calculate_block_hash()
        .expect("could not calculate block hash");
    child
}

fn create_uncle(brother: &RskBlock) -> RskBlock {
    let mut uncle = create_base_block(brother.header.number, false, Some(brother.header.parent));
    uncle.header.timestamp = brother.header.timestamp + 10;
    uncle.header.difficulty = brother.header.difficulty;
    uncle.pow = calculate_superblock_effort(uncle.header.difficulty);
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

fn calculate_superblock_effort(difficulty: U256) -> H256 {
    H256::from(
        U256::MAX
            .checked_div(difficulty)
            .and_then(|n| n.checked_div(U256::from(SUPERBLOCK_TIMES_DIFFICULTY)))
            .expect("0 division on calculate_superblock_effort")
            .to_big_endian(),
    )
}

fn calculate_effort_from_pow(pow: H256) -> U256 {
    let pow_dec = U256::from_big_endian(pow.as_bytes());
    U256::MAX
        .checked_div(pow_dec)
        .expect("0 division on calculate_effort_from_pow")
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
    required_num_blocks: Option<u32>,
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

    fn required_num_blocks(mut self, required_num_blocks: u32) -> Self {
        self.required_num_blocks = Some(required_num_blocks);
        self
    }

    fn build(self) -> CheckForkArgs {
        CheckForkArgs {
            init_block_time: self.init_block_time.unwrap_or(DEFAULT_TIMESTAMP),
            init_block_number: self.init_block_number.unwrap_or(DEFAULT_INIT_BLOCK_NUMBER),
            required_num_blocks: self
                .required_num_blocks
                .unwrap_or(DEFAULT_REQ_NUMBER_OF_BLOCKS),
            block_list: self.block_list,
        }
    }
}
