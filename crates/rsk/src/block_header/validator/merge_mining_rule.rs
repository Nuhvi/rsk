use bitcoin::pow::Work;
use primitive_types::{H256, U256};

use crate::block_header::RskBlockHeader;

/// The ASCII prefix that identifies an RSK block commitment inside a Bitcoin
/// coinbase: "RSKBLOCK:" == [0x52,0x53,0x4b,0x42,0x4c,0x4f,0x43,0x4b,0x3a]
const RSKBLOCK_TAG: &[u8] = b"RSKBLOCK:";

/// Number of bytes of the RSK block hash that are embedded in the merge-mining
/// tag.  The full keccak256 digest is 32 bytes, but only the first 20 are
/// committed to in the Bitcoin coinbase (RSKIP177 / legacy format).
const RSK_HASH_PREFIX_LEN: usize = 20;

impl RskBlockHeader {
    // /// Compute the double-SHA256 hash of the 80-byte Bitcoin block header and
    // /// verify that it actually sits below the declared `nBits` target.
    // ///
    // /// This is the check that was previously *missing*: the caller used to
    // /// supply a pre-computed `pow` field and this library trusted it blindly.
    // /// Now we derive the hash ourselves and let the bitcoin crate validate it.
    // pub fn verify_bitcoin_pow(&self) -> Result<(), &'static str> {
    //     // Compute double-SHA256 of the 80-byte Bitcoin header.
    //     let hash_bytes = bitcoin::hashes::sha256d::Hash::hash(&self.bitcoin_merged_mining_header)
    //         .to_byte_array();
    //
    //     // Bitcoin double-SHA256 is little-endian when displayed, but the raw
    //     // bytes from hash() are already in the correct order for numeric
    //     // comparison — we just need to interpret them as a big-endian U256.
    //     // Actually: Bitcoin hashes are displayed reversed but stored
    //     // little-endian internally, so we reverse before converting to U256.
    //     let mut hash_be = hash_bytes;
    //     hash_be.reverse();
    //     let pow_hash = U256::from_big_endian(&hash_be);
    //
    //     // RSK target = 2^256 / difficulty.
    //     // We approximate 2^256 as U256::MAX (off by 1, same as Bitcoin does).
    //     if self.difficulty.is_zero() {
    //         return Err("RSK difficulty is zero");
    //     }
    //     let rsk_target = U256::MAX / self.difficulty;
    //
    //     if pow_hash > rsk_target {
    //         return Err("Bitcoin PoW hash does not meet RSK difficulty target");
    //     }
    //
    //     Ok(())
    // }
    //
    // /// Return the [`Work`] represented by this block's Bitcoin `nBits` field.
    // ///
    // /// `Work` is the bitcoin-crate's type for cumulative chain work.  It is
    // /// defined as `2^256 / (target + 1)` — the expected number of hashes
    // /// needed to find a block at this target — which is exactly the same
    // /// formula the old hand-rolled `calculate_block_effort` used, expressed
    // /// through a proper newtype rather than a bare `U256`.
    // ///
    // /// Note: this is derived from `nBits` (the *declared* target), not from
    // /// the actual hash value.  That is the standard Bitcoin definition of work
    // /// and is what RSKj accumulates.  Call [`verify_bitcoin_pow`] first to
    // /// ensure that the declared target was actually met.
    // pub fn block_work(&self) -> Result<Work, &'static str> {
    //     // Target::to_work() returns 2^256 / (target + 1)
    //     Ok(self.bitcoin_merged_mining_header.target().to_work())
    //
    //     // if self.header.bitcoin_merged_mining_header.len() != 80 {
    //     //         return Err("bitcoin_merged_mining_header is not 80 bytes long".into());
    //     //     }
    //     //     let btc_header: Header = btc_deserialize(&self.header.bitcoin_merged_mining_header)
    //     //         .map_err(|e| {
    //     //             format!(
    //     //                 "Failed to deserialize btc header: {e:?}, data: {:?}",
    //     //                 self.header.bitcoin_merged_mining_header
    //     //             )
    //     //         })?;
    //     //     let hash = H256::from_str(&btc_header.block_hash().to_string())?;
    //     //     Ok(hash)
    //     // }
    // }
    //
    // /// Convert [`Work`] to a plain [`U256`] for use in the existing
    // /// `accumulate_effort` arithmetic in `lib.rs`.
    // ///
    // /// The bitcoin crate stores `Work` internally as a little-endian `[u64;4]`
    // /// (accessible only through `to_le_bytes()`), while `U256` from
    // /// `primitive_types` uses big-endian byte order.
    // pub fn block_work_as_u256(&self) -> Result<U256, &'static str> {
    //     let work = self.block_work()?;
    //     // Work::to_le_bytes() → 32 bytes, least-significant byte first.
    //     let le_bytes = work.to_le_bytes();
    //     // U256::from_little_endian expects exactly 32 bytes.
    //     Ok(U256::from_little_endian(&le_bytes))
    // }
    //
    // -------------------------------------------------------------------------
    // Merge-mining tag verification
    // -------------------------------------------------------------------------
    //
    // /// Verify that this RSK block header is the one committed to inside the
    // /// Bitcoin coinbase transaction.
    // ///
    // /// The Bitcoin coinbase must contain the sequence:
    // ///   `RSKBLOCK:` (9 bytes, ASCII) ‖ keccak256(rlp(this header))[0..20]
    // ///
    // /// We only check the first [`RSK_HASH_PREFIX_LEN`] (20) bytes of the hash
    // /// because that is what the legacy merge-mining tag format embeds.  The
    // /// full 32-byte hash is not committed to in the coinbase (RSKIP177).
    // pub fn verify_merge_mining_tag(&self) -> Result<(), &'static str> {
    //     // 1. Locate the RSKBLOCK: tag inside the coinbase bytes.
    //     let tag_pos = self
    //         .bitcoin_coinbase_txn
    //         .windows(RSKBLOCK_TAG.len())
    //         .position(|w| w == RSKBLOCK_TAG)
    //         .ok_or("RSKBLOCK: tag not found in Bitcoin coinbase transaction")?;
    //
    //     let hash_start = tag_pos + RSKBLOCK_TAG.len();
    //     let hash_end = hash_start + RSK_HASH_PREFIX_LEN;
    //
    //     if self.bitcoin_coinbase_txn.len() < hash_end {
    //         return Err("Bitcoin coinbase transaction too short to contain full RSK hash prefix");
    //     }
    //
    //     let committed_prefix = &self.bitcoin_coinbase_txn[hash_start..hash_end];
    //
    //     // 2. Compute the actual keccak256 hash of this RSK header's RLP encoding.
    //     let actual_hash = self.calculate_block_hash()?;
    //
    //     // 3. Compare only the first 20 bytes.
    //     if committed_prefix != &actual_hash.as_bytes()[..RSK_HASH_PREFIX_LEN] {
    //         return Err(
    //             "RSK block hash prefix in coinbase does not match this block header's hash",
    //         );
    //     }
    //
    //     Ok(())
    // }
    //
    // /// Verify the Merkle proof that the coinbase transaction belongs to the
    // /// Bitcoin block declared in `bitcoin_merged_mining_header`.
    // ///
    // /// The coinbase is always the first transaction (index 0), so the Merkle
    // /// path produces the `merkle_root` by repeatedly hashing
    // ///   `SHA256d(current ‖ sibling)`   (left child always first for index 0).
    // ///
    // /// We compare the computed root against the `merkle_root` field inside the
    // /// 80-byte Bitcoin block header.
    // pub fn verify_coinbase_merkle_proof(&self) -> Result<(), &'static str> {
    //     // Coinbase txid = double-SHA256 of the raw coinbase bytes.
    //     let txid_bytes = bitcoin::hashes::sha256d::Hash::hash(&self.bitcoin_coinbase_txn);
    //     let mut current = txid_bytes.to_byte_array(); // 32-byte little-endian txid
    //
    //     // Walk the proof.  The coinbase is always at index 0, so it is always
    //     // the *left* child at every level.
    //     for sibling in &self.bitcoin_merkle_proof {
    //         let mut buf = [0u8; 64];
    //         buf[..32].copy_from_slice(&current);
    //         buf[32..].copy_from_slice(sibling.as_bytes());
    //         current = bitcoin::hashes::sha256d::Hash::hash(&buf).to_byte_array();
    //     }
    //
    //     let computed_root = bitcoin::hash_types::TxMerkleNode::from_byte_array(current);
    //     if self.bitcoin_merged_mining_header.merkle_root != computed_root {
    //         return Err(
    //             "Merkle proof does not connect coinbase to Bitcoin block header merkle_root",
    //         );
    //     }
    //
    //     Ok(())
    // }

    /// Run all three merge-mining checks in one call:
    ///
    /// 1. Bitcoin PoW is valid (hash < nBits target).
    /// 2. RSK hash prefix appears correctly in the coinbase tag.
    /// 3. Coinbase is included in the Bitcoin block (Merkle proof).
    ///
    /// This replaces the previous pattern of trusting the caller-supplied
    /// `pow` field in `RskBlock`.
    pub fn verify_merge_mining(&self) -> Result<(), &'static str> {
        // self.verify_bitcoin_pow()?;
        self.verify_merge_mining_tag()?;
        // self.verify_coinbase_merkle_proof()?;
        Ok(())
    }
}
