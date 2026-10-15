//! The pure Rootstock finality rules: where the trusted block `F` is, and when
//! a Rootstock tail is final.
//!
//! Everything here is a function of its inputs — a [`Core`] (the Bitcoin chain)
//! and a descending run of Rootstock headers — with no I/O, so it is unit
//! testable. The *state* (the Rootstock tree) lives in [`crate::rsk`].
//!
//! ## The anchor is the parent
//!
//! A Rootstock header's `bitcoin_merged_mining_header` is a Bitcoin-header-
//! shaped **solution** meeting Rootstock's (easier) difficulty, so its own hash
//! is rarely a canonical Bitcoin block. What ties it to Bitcoin is its
//! `prev_blockhash`: the real Bitcoin tip it was built on. That parent is the
//! anchor.
//!
//! `F` is the deepest canonical Rootstock block whose **own** anchor is inside
//! the trust tail `[B, tip − ANCHOR_DEPTH]`. The tail is final once the work
//! built on `F` (GHOST-weighted, see [`crate::rsk`]) exceeds `2/3` of the
//! Bitcoin tail's work.
//!
// TODO(VETIVER-731b9d8): every block we validate is newer than the Vetiver
// hardfork, because `F` is always newer given >67% participation. The
// pre-Vetiver validation rules (and the activation-height branches that only
// apply to older blocks) can therefore be dropped.

use std::sync::Arc;

use alloy_primitives::U256;
use bitcoin::block::Header as BitcoinHeader;
use rsk_consensus::Header as RskHeader;
use rsk_consensus::config::ChainConfig;
use rsk_consensus::validation::HeaderVerifier;

use crate::Core;
use crate::error::Error;
use crate::store::DIFFICULTY_PERIOD;

/// How deep an anchor must be buried in Bitcoin before we trust it: an anchor
/// at `btc_tip - ANCHOR_DEPTH` or older. A fixed safety margin — we never rely
/// on a Bitcoin block that could still be reorged.
pub const ANCHOR_DEPTH: u64 = 100;

/// The finality threshold, `2/3`: the Rootstock tail's work must exceed
/// `FINALITY_NUM / FINALITY_DEN` of the Bitcoin tail's work. Kept as a fraction
/// so the comparison stays exact in integer arithmetic.
pub const FINALITY_NUM: u64 = 2;
pub const FINALITY_DEN: u64 = 3;

/// The embedded merge-mining solution header of a Rootstock header, decoded.
/// `None` if it is absent or not a decodable 80-byte Bitcoin header.
pub fn merge_mining_header(header: &RskHeader) -> Option<BitcoinHeader> {
    let bytes = header.bitcoin_merged_mining_header.as_ref()?;
    if bytes.len() != 80 {
        return None;
    }
    bitcoin::consensus::deserialize(bytes.as_ref()).ok()
}

/// The canonical Bitcoin height a Rootstock header was built on — the anchor.
/// `None` if the header carries no usable merge-mining header, or its anchor is
/// not on the Bitcoin chain we hold.
pub fn anchor_height(btc: &Core, header: &RskHeader) -> Result<Option<u64>, Error> {
    let Some(solution) = merge_mining_header(header) else {
        return Ok(None);
    };
    btc.height_of(&solution.prev_blockhash)
}

/// Whether a Bitcoin anchor height is inside the trust tail: at or after the
/// tail start, and buried by at least [`ANCHOR_DEPTH`] Bitcoin blocks.
pub fn in_tail(anchor: u64, btc_tail_start: u64, btc_tip: u64) -> bool {
    anchor >= btc_tail_start && anchor + ANCHOR_DEPTH <= btc_tip
}

/// Validate a descending Rootstock run (newest first): reverse to ascending,
/// and run every header through `rsk-consensus` against its parent, linkage
/// included ([`rsk_consensus::validation::HeaderVerifier`]).
pub fn validate_run(descending: &[RskHeader]) -> Result<(), Error> {
    let verifier = HeaderVerifier::default_rsk(Arc::new(ChainConfig::mainnet()));
    let mut parent: Option<RskHeader> = None;
    for header in descending.iter().rev() {
        verifier
            .verify(header, parent.as_ref())
            .map_err(|e| Error::Rootstock(format!("header #{}: {e}", header.number)))?;
        parent = Some(header.clone());
    }
    Ok(())
}

/// A scan of a Rootstock tail against the Bitcoin chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailScan {
    /// Headers scanned.
    pub headers: usize,
    /// Cumulative Rootstock difficulty over the run (trunk only; the GHOST
    /// weighting lives in [`crate::rsk`]).
    pub work: U256,
    /// Headers whose anchor is on the canonical Bitcoin chain.
    pub canonical: usize,
    /// Of those, how many anchor inside the tail.
    pub in_tail: usize,
    /// Headers whose anchor is absent from the Bitcoin chain we hold.
    pub absent: usize,
    /// The **deepest** header whose anchor is inside the tail — `F`, or `None`.
    pub candidate: Option<u64>,
    /// Rootstock work strictly above the candidate (`F..tip`).
    pub work_above_candidate: U256,
}

/// Scan a descending Rootstock run against the Bitcoin chain, treating anchors
/// inside `[tail_start, tip − ANCHOR_DEPTH]` as inside the tail.
pub fn scan(btc: &Core, descending: &[RskHeader], tail_start: u64) -> Result<TailScan, Error> {
    let mut scan = TailScan {
        headers: descending.len(),
        work: U256::ZERO,
        canonical: 0,
        in_tail: 0,
        absent: 0,
        candidate: None,
        work_above_candidate: U256::ZERO,
    };
    let Some(tip) = btc.tip_height()? else {
        return Ok(scan);
    };
    for header in descending {
        scan.work = scan.work.saturating_add(header.difficulty);
        match anchor_height(btc, header)? {
            None => scan.absent += 1,
            Some(height) => {
                scan.canonical += 1;
                if in_tail(height, tail_start, tip) {
                    scan.in_tail += 1;
                    // Descending order: the last in-tail header is the deepest,
                    // and the work accumulated so far is exactly the work above
                    // it (all headers newer than it have been processed).
                    scan.candidate = Some(header.number);
                    scan.work_above_candidate = scan.work;
                }
            }
        }
    }
    Ok(scan)
}

/// The deepest Rootstock block whose **own** Bitcoin anchor is inside the tail —
/// the checkpoint block `F`. `None` when the run has no in-tail block. This is
/// the piece the p2p bisect drives; uncles do not affect it.
pub fn find_f(btc: &Core, descending: &[RskHeader], tail_start: u64) -> Result<Option<u64>, Error> {
    let Some(tip) = btc.tip_height()? else {
        return Ok(None);
    };
    let mut f = None;
    for header in descending {
        if let Some(anchor) = anchor_height(btc, header)?
            && in_tail(anchor, tail_start, tip)
        {
            f = Some(header.number); // descending: the last in-tail is the deepest
        }
    }
    Ok(f)
}

/// Bitcoin work carried by the tail `[tail_start, tip]`.
pub fn bitcoin_tail_work(btc: &Core, tail_start: u64) -> Result<Option<U256>, Error> {
    let Some(tip) = btc.tip_height()? else {
        return Ok(None);
    };
    let (Some(top), Some(base)) = (btc.chainwork_at(tip)?, btc.chainwork_at(tail_start)?) else {
        return Ok(None);
    };
    let delta = top - base;
    Ok(Some(U256::from_be_slice(&delta.to_be_bytes())))
}

/// The finality rule: the Rootstock tail's work exceeds `2/3` of the Bitcoin
/// tail's work. (Strict `>`, so a tie is not final.)
pub fn is_final(rsk_work: U256, btc_tail_work: U256) -> bool {
    rsk_work * U256::from(FINALITY_DEN) > btc_tail_work * U256::from(FINALITY_NUM)
}

/// A Rootstock FINAL block: the earliest block whose anchor is inside the
/// Bitcoin tail, whose work above it exceeds `2/3` of the Bitcoin tail's work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Final {
    /// The Rootstock number of the FINAL block (the candidate `F`).
    pub final_height: u64,
    /// Rootstock work `F..tip`.
    pub rsk_work: U256,
    /// Bitcoin tail work for the window that satisfied the test.
    pub btc_tail_work: U256,
    /// The Bitcoin tail start the test passed at.
    pub tail_start: u64,
}

/// The Bitcoin-anchored finality test, with the extension rule.
///
/// Walks the descending Rootstock run against the Bitcoin chain starting at the
/// finalized checkpoint, and extends the Bitcoin tail back one difficulty
/// period at a time if the work test fails. Returns the FINAL block once
/// `work(F..tip) > ⅔·work(tail)`, or `None` if no window satisfies it
/// (participation below two-thirds).
pub fn finalize(btc: &Core, descending: &[RskHeader]) -> Result<Option<Final>, Error> {
    let mut tail_start = btc.finalized_height()?.unwrap_or(0);
    loop {
        let scan = scan(btc, descending, tail_start)?;
        if let Some(candidate) = scan.candidate {
            let btc_work = bitcoin_tail_work(btc, tail_start)?.unwrap_or(U256::ZERO);
            if is_final(scan.work_above_candidate, btc_work) {
                return Ok(Some(Final {
                    final_height: candidate,
                    rsk_work: scan.work_above_candidate,
                    btc_tail_work: btc_work,
                    tail_start,
                }));
            }
        }
        if tail_start == 0 {
            return Ok(None);
        }
        tail_start = tail_start.saturating_sub(DIFFICULTY_PERIOD);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::block::{BlockHash, Version};
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;

    /// The easiest valid Bitcoin target: nearly any hash passes.
    const EASY_BITS: u32 = 0x207f_ffff;

    fn mine(prev: BlockHash, tag: u32) -> BitcoinHeader {
        let target = CompactTarget::from_consensus(EASY_BITS);
        let mut nonce = 0u32;
        loop {
            let header = BitcoinHeader {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: Hash::all_zeros(),
                time: 1_600_000_000 + tag,
                bits: target,
                nonce,
            };
            if header.validate_pow(header.target()).is_ok() {
                return header;
            }
            nonce += 1;
        }
    }

    /// An RSK header whose embedded merge-mining solution points at `anchor`.
    fn rsk(anchor: BlockHash, number: u64, difficulty: u64) -> RskHeader {
        let solution = BitcoinHeader {
            version: Version::ONE,
            prev_blockhash: anchor,
            merkle_root: Hash::all_zeros(),
            time: 1_600_000_000,
            bits: CompactTarget::from_consensus(EASY_BITS),
            nonce: 0,
        };
        let mut bytes = Vec::new();
        solution.consensus_encode(&mut bytes).unwrap();
        RskHeader {
            parent_hash: Default::default(),
            ommers_hash: Default::default(),
            beneficiary: Default::default(),
            state_root: Default::default(),
            transactions_root: Default::default(),
            receipts_root: Default::default(),
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(difficulty),
            number,
            gas_limit: Default::default(),
            gas_used: 0,
            timestamp: 1_600_000_000,
            extra_data: Default::default(),
            paid_fees: Default::default(),
            minimum_gas_price: Default::default(),
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: Some(bytes.into()),
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }

    #[test]
    fn merge_mining_header_decodes_only_real_headers() {
        let solution = mine(BlockHash::all_zeros(), 0);
        let mut bytes = Vec::new();
        solution.consensus_encode(&mut bytes).unwrap();
        let mut header = rsk(BlockHash::all_zeros(), 1, 1);
        header.bitcoin_merged_mining_header = Some(bytes.into());
        assert!(merge_mining_header(&header).is_some());

        header.bitcoin_merged_mining_header = Some(vec![1, 2, 3].into());
        assert!(merge_mining_header(&header).is_none());

        header.bitcoin_merged_mining_header = None;
        assert!(merge_mining_header(&header).is_none());
    }

    #[test]
    fn anchor_resolves_to_the_bitcoin_parent_height() {
        let chain = Core::in_memory(Network::Regtest).unwrap();
        let h0 = mine(BlockHash::all_zeros(), 0);
        let h2016 = mine(h0.block_hash(), 1);
        chain.seed_checkpoints(&[(0, h0), (2016, h2016)]).unwrap();

        // Anchored on the 2016 checkpoint.
        let header = rsk(h2016.block_hash(), 5_000_000, 10);
        assert_eq!(anchor_height(&chain, &header).unwrap(), Some(2016));

        // Anchored on an unknown Bitcoin block.
        let header = rsk(BlockHash::all_zeros(), 5_000_001, 10);
        assert_eq!(anchor_height(&chain, &header).unwrap(), None);
    }

    #[test]
    fn scan_sums_work_and_finds_the_deepest_in_tail_header() {
        let chain = Core::in_memory(Network::Regtest).unwrap();
        let h0 = mine(BlockHash::all_zeros(), 0);
        let h2016 = mine(h0.block_hash(), 1);
        chain.seed_checkpoints(&[(0, h0), (2016, h2016)]).unwrap();

        // Descending: newest anchored at 2016 (too near the tip to trust at
        // depth 100), older at 0 (buried), oldest absent.
        let descending = vec![
            rsk(h2016.block_hash(), 100, 3),
            rsk(h0.block_hash(), 99, 5),
            rsk(BlockHash::all_zeros(), 98, 7),
        ];
        let report = scan(&chain, &descending, 0).unwrap();
        assert_eq!(report.headers, 3);
        assert_eq!(report.work, U256::from(15));
        assert_eq!(report.canonical, 2);
        assert_eq!(report.in_tail, 1, "only the deeply-buried anchor counts");
        assert_eq!(report.absent, 1);
        assert_eq!(report.candidate, Some(99));

        // A tail start above the buried anchor leaves nothing in tail.
        let report = scan(&chain, &descending, 2016).unwrap();
        assert_eq!(report.in_tail, 0);
        assert_eq!(report.candidate, None);
    }

    #[test]
    fn finality_needs_more_than_two_thirds() {
        assert!(is_final(U256::from(100), U256::from(100)));
        assert!(!is_final(U256::from(66), U256::from(100)));
        assert!(is_final(U256::from(67), U256::from(100)));
        assert!(!is_final(U256::from(0), U256::from(0)));
    }

    #[test]
    fn find_f_is_the_deepest_in_tail_block() {
        let chain = Core::in_memory(Network::Regtest).unwrap();
        let h0 = mine(BlockHash::all_zeros(), 0);
        let h2016 = mine(h0.block_hash(), 1);
        chain.seed_checkpoints(&[(0, h0), (2016, h2016)]).unwrap();

        let descending = vec![
            rsk(h2016.block_hash(), 100, 3),
            rsk(h0.block_hash(), 99, 5),
            rsk(BlockHash::all_zeros(), 98, 7),
        ];
        assert_eq!(find_f(&chain, &descending, 0).unwrap(), Some(99));
        assert_eq!(find_f(&chain, &descending, 2016).unwrap(), None);
    }
}
