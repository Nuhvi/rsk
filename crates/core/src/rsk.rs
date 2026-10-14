//! The Rootstock header tree.
//!
//! Each trusted root `F` (supplied by the p2p layer) roots a **forest**:
//! headers are stored keyed by hash and each block links to its parent. Work
//! follows rskj's rule — a block's own contribution is `difficulty + Σ(included
//! uncle difficulty)` — and the tree is weighted by **GHOST**: a block's weight
//! is the sum over its whole subtree, so side branches count, not just the one
//! chain. `W_rsk(F) = rsk_subtree_work(F)`; the finality test compares it to
//! `2/3` of the Bitcoin tail's work (see [`crate::rootstock`]).

use std::collections::HashSet;

use alloy_primitives::{B256, U256};
use redb::ReadableTable;
use rsk_consensus::Header;
use rsk_consensus::types::block::Block;
use rsk_consensus::validation::HeaderVerifier;
use rsk_consensus::validation::uncles::{
    AncestorSource, UNCLE_GENERATION_LIMIT, UNCLE_LIST_LIMIT, UnclesValidationRule,
};

use crate::Core;
use crate::error::Error;
use crate::store::{
    RSK_BLOCKS, RSK_CHILDREN, RSK_HEADERS, RSK_ROOTS, RSK_UNCLES, ReadTxn, WriteTxn,
};

/// A Rootstock header and the uncle headers it references, each with the wire
/// bytes its hash is taken over.
#[derive(Debug, Clone)]
pub struct RskEntry {
    pub header: Header,
    pub raw: Vec<u8>,
    pub uncles: Vec<RskUncle>,
}

/// One uncle header and its wire bytes.
#[derive(Debug, Clone)]
pub struct RskUncle {
    pub header: Header,
    pub raw: Vec<u8>,
}

/// Outcome of a [`Core::connect_rsk_headers`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RskConnectOutcome {
    /// Headers newly stored.
    pub connected: usize,
}

/// The stored per-block index: `number(8) | parent(32) | own_work(32)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RskBlock {
    pub number: u64,
    pub parent: [u8; 32],
    pub own_work: U256,
}

impl RskBlock {
    fn encode(&self) -> [u8; 72] {
        let mut out = [0u8; 72];
        out[..8].copy_from_slice(&self.number.to_be_bytes());
        out[8..40].copy_from_slice(&self.parent);
        out[40..72].copy_from_slice(&self.own_work.to_be_bytes::<32>());
        out
    }

    fn decode(bytes: &[u8]) -> RskBlock {
        let mut parent = [0u8; 32];
        parent.copy_from_slice(&bytes[8..40]);
        RskBlock {
            number: u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes")),
            parent,
            own_work: U256::from_be_slice(&bytes[40..72]),
        }
    }
}

// ── store access (rsk_* tables) ─────────────────────────────────────────────

/// Reads over the RSK tables, shared by [`ReadTxn`] and [`WriteTxn`] so a
/// connect can validate against what it has already staged.
macro_rules! rsk_read_methods {
    () => {
        pub(crate) fn rsk_raw_header(&self, hash: &[u8]) -> Result<Option<Vec<u8>>, Error> {
            let table = self.txn.open_table(RSK_HEADERS)?;
            Ok(table.get(hash)?.map(|v| v.value().to_vec()))
        }

        pub(crate) fn rsk_block(&self, hash: &[u8]) -> Result<Option<RskBlock>, Error> {
            let table = self.txn.open_table(RSK_BLOCKS)?;
            Ok(table.get(hash)?.map(|v| RskBlock::decode(v.value())))
        }

        pub(crate) fn rsk_has_block(&self, hash: &[u8]) -> Result<bool, Error> {
            Ok(self.rsk_block(hash)?.is_some())
        }

        pub(crate) fn rsk_children(&self, hash: &[u8]) -> Result<Vec<[u8; 32]>, Error> {
            let table = self.txn.open_table(RSK_CHILDREN)?;
            Ok(table
                .get(hash)?
                .map(|v| decode_hashes(v.value()))
                .unwrap_or_default())
        }

        pub(crate) fn rsk_uncle_raw(&self, hash: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
            let table = self.txn.open_table(RSK_UNCLES)?;
            Ok(table
                .get(hash)?
                .map(|v| decode_blobs(v.value()))
                .unwrap_or_default())
        }

        pub(crate) fn rsk_roots(&self) -> Result<Vec<[u8; 32]>, Error> {
            let table = self.txn.open_table(RSK_ROOTS)?;
            let mut out = Vec::new();
            for entry in table.iter()? {
                let (key, _) = entry.map_err(Error::Storage)?;
                let mut hash = [0u8; 32];
                hash.copy_from_slice(key.value());
                out.push(hash);
            }
            Ok(out)
        }
    };
}

#[allow(dead_code)] // some reads are only used on one transaction kind
impl ReadTxn {
    rsk_read_methods!();
}

#[allow(dead_code)] // some reads are only used on one transaction kind
impl WriteTxn {
    rsk_read_methods!();

    pub(crate) fn rsk_put_block(
        &self,
        hash: &[u8],
        raw: &[u8],
        block: &RskBlock,
    ) -> Result<(), Error> {
        {
            let mut table = self.txn.open_table(RSK_HEADERS)?;
            table.insert(hash, raw)?;
        }
        {
            let mut table = self.txn.open_table(RSK_BLOCKS)?;
            table.insert(hash, block.encode().as_slice())?;
        }
        Ok(())
    }

    pub(crate) fn rsk_put_uncles(&self, hash: &[u8], raws: &[Vec<u8>]) -> Result<(), Error> {
        let mut table = self.txn.open_table(RSK_UNCLES)?;
        table.insert(hash, encode_blobs(raws).as_slice())?;
        Ok(())
    }

    pub(crate) fn rsk_add_child(&self, parent: &[u8], child: &[u8]) -> Result<(), Error> {
        let mut table = self.txn.open_table(RSK_CHILDREN)?;
        let mut buf = table
            .get(parent)?
            .map(|v| v.value().to_vec())
            .unwrap_or_default();
        buf.extend_from_slice(child);
        table.insert(parent, buf.as_slice())?;
        Ok(())
    }

    pub(crate) fn rsk_put_root(&self, hash: &[u8]) -> Result<(), Error> {
        let mut table = self.txn.open_table(RSK_ROOTS)?;
        table.insert(hash, &[][..])?;
        Ok(())
    }
}

// ── the tree on `Core` ──────────────────────────────────────────────────────

impl Core {
    /// Store a trusted root `F` and mark it a root of the forest. `F` is taken
    /// on faith (its anchor proved by the p2p layer); it is not validated.
    pub fn seed_rsk_root(&self, entry: &RskEntry) -> Result<B256, Error> {
        let txn = self.store.write()?;
        let hash = store_entry(&txn, entry)?;
        txn.rsk_put_root(hash.as_slice())?;
        txn.commit()?;
        Ok(hash)
    }

    /// Validate and store a contiguous ascending run of RSK headers (with their
    /// uncles). Each header must link to a stored block; the batch is stored as
    /// it validates, so later entries see earlier ones.
    ///
    /// Validation is `rsk-consensus`': static + parent rules on each header, the
    /// `ommers_hash` commitment on the uncle list, and the full uncle rule
    /// (generation window, no reuse, and the uncle's parent must be one of the
    /// including block's ancestors) against a store-backed [`AncestorSource`].
    pub fn connect_rsk_headers(&self, entries: &[RskEntry]) -> Result<RskConnectOutcome, Error> {
        let txn = self.store.write()?;
        let verifier = HeaderVerifier::default_rsk(self.rsk_chain.clone());
        let mut connected = 0usize;
        for entry in entries {
            validate_entry(&txn, &verifier, entry)?;
            store_entry(&txn, entry)?;
            connected += 1;
        }
        txn.commit()?;
        Ok(RskConnectOutcome { connected })
    }

    /// GHOST weight of the subtree rooted at `root`: `Σ own_work` over `root`
    /// and every descendant. This is `W_rsk(F)`.
    pub fn rsk_subtree_work(&self, root: &B256) -> Result<U256, Error> {
        let txn = self.store.read()?;
        subtree_work(&txn, root.as_slice())
    }

    /// The root with the heaviest subtree, if any.
    pub fn rsk_best_root(&self) -> Result<Option<(B256, U256)>, Error> {
        let txn = self.store.read()?;
        let mut best: Option<(B256, U256)> = None;
        for root in txn.rsk_roots()? {
            let work = subtree_work(&txn, &root)?;
            if best.as_ref().is_none_or(|(_, w)| work > *w) {
                best = Some((B256::from(root), work));
            }
        }
        Ok(best)
    }

    /// The header stored under `hash`, if any.
    pub fn rsk_header(&self, hash: &B256) -> Result<Option<Header>, Error> {
        Ok(self
            .store
            .read()?
            .rsk_raw_header(hash.as_slice())?
            .and_then(|raw| decode_header(&raw)))
    }

    /// Whether `hash` is a stored RSK block.
    pub fn rsk_has_block(&self, hash: &B256) -> Result<bool, Error> {
        self.store.read()?.rsk_has_block(hash.as_slice())
    }
}

/// Store a header, its uncle list, and the child edge to its parent.
fn store_entry(txn: &WriteTxn, entry: &RskEntry) -> Result<B256, Error> {
    let header = &entry.header;
    let hash = header.hash();
    let block = RskBlock {
        number: header.number,
        parent: header.parent_hash.0,
        own_work: own_work(header, &entry.uncles),
    };
    txn.rsk_put_block(hash.as_slice(), &entry.raw, &block)?;
    let uncle_raws: Vec<Vec<u8>> = entry.uncles.iter().map(|u| u.raw.clone()).collect();
    txn.rsk_put_uncles(hash.as_slice(), &uncle_raws)?;
    if txn.rsk_has_block(header.parent_hash.as_slice())? {
        txn.rsk_add_child(header.parent_hash.as_slice(), hash.as_slice())?;
    }
    Ok(hash)
}

/// rskj's per-block contribution: `difficulty + Σ(included uncle difficulty)`.
fn own_work(header: &Header, uncles: &[RskUncle]) -> U256 {
    let mut work = header.difficulty;
    for uncle in uncles {
        work = work.saturating_add(uncle.header.difficulty);
    }
    work
}

/// Sum `own_work` over `root`'s whole subtree (GHOST).
fn subtree_work(txn: &ReadTxn, root: &[u8]) -> Result<U256, Error> {
    let mut total = U256::ZERO;
    let mut stack: Vec<Vec<u8>> = vec![root.to_vec()];
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    while let Some(hash) = stack.pop() {
        if !seen.insert(hash.clone()) {
            continue;
        }
        if let Some(block) = txn.rsk_block(&hash)? {
            total = total.saturating_add(block.own_work);
        }
        for child in txn.rsk_children(&hash)? {
            stack.push(child.to_vec());
        }
    }
    Ok(total)
}

/// Validate one entry: commitment, header rules against its parent, and the
/// full uncle rule.
fn validate_entry(
    txn: &WriteTxn,
    verifier: &HeaderVerifier,
    entry: &RskEntry,
) -> Result<(), Error> {
    let header = &entry.header;

    if entry.uncles.len() as u64 != header.uncle_count {
        return Err(Error::Rootstock(format!(
            "block #{} says {} uncle(s) but {} came with it",
            header.number,
            header.uncle_count,
            entry.uncles.len()
        )));
    }
    let committed = alloy_primitives::keccak256(encoded_uncles(&entry.uncles));
    if committed != header.ommers_hash {
        return Err(Error::Rootstock(format!(
            "block #{}: uncle list does not match the header's ommers hash",
            header.number
        )));
    }

    let parent = txn
        .rsk_raw_header(header.parent_hash.as_slice())?
        .and_then(|raw| decode_header(&raw));
    verifier
        .verify(header, parent.as_ref())
        .map_err(|e| Error::Rootstock(format!("header #{}: {e}", header.number)))?;

    if !entry.uncles.is_empty() {
        let source = TxnAncestors { txn };
        let rule = UnclesValidationRule {
            store: &source,
            uncle_list_limit: UNCLE_LIST_LIMIT,
            uncle_generation_limit: UNCLE_GENERATION_LIMIT,
            header_rules: verifier.static_rules(),
            parent_rules: verifier.parent_rules(),
        };
        let block = Block {
            header: header.clone(),
            transactions: Vec::new(),
            ommers: entry.uncles.iter().map(|u| u.header.clone()).collect(),
        };
        rule.validate(&block)
            .map_err(|e| Error::Rootstock(format!("uncles of #{}: {e}", header.number)))?;
    }

    Ok(())
}

/// The RLP of the uncle list as `ommers_hash` commits to it: the wire encodings
/// of the uncles wrapped in a list.
fn encoded_uncles(uncles: &[RskUncle]) -> Vec<u8> {
    let mut payload = Vec::new();
    for uncle in uncles {
        payload.extend_from_slice(&uncle.raw);
    }
    let mut out = Vec::with_capacity(payload.len() + 9);
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

/// Decode a header from its wire bytes, hashing from those bytes.
fn decode_header(raw: &[u8]) -> Option<Header> {
    let mut slice = raw;
    Header::decode_with_hash(&mut slice).ok()
}

/// The store-backed ancestry the uncle rule walks.
struct TxnAncestors<'a> {
    txn: &'a WriteTxn,
}

impl AncestorSource for TxnAncestors<'_> {
    fn header(&self, hash: B256) -> Option<Header> {
        self.txn
            .rsk_raw_header(hash.as_slice())
            .ok()
            .flatten()
            .and_then(|raw| decode_header(&raw))
    }

    fn uncles_of(&self, hash: B256) -> Vec<Header> {
        self.txn
            .rsk_uncle_raw(hash.as_slice())
            .ok()
            .unwrap_or_default()
            .iter()
            .filter_map(|raw| decode_header(raw))
            .collect()
    }
}

// ── encodings ───────────────────────────────────────────────────────────────

fn decode_hashes(bytes: &[u8]) -> Vec<[u8; 32]> {
    bytes
        .chunks(32)
        .filter(|chunk| chunk.len() == 32)
        .map(|chunk| {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(chunk);
            hash
        })
        .collect()
}

fn encode_blobs(blobs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(blobs.len() as u32).to_be_bytes());
    for blob in blobs {
        out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        out.extend_from_slice(blob);
    }
    out
}

fn decode_blobs(bytes: &[u8]) -> Vec<Vec<u8>> {
    if bytes.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_be_bytes(bytes[..4].try_into().expect("4 bytes")) as usize;
    let mut out = Vec::with_capacity(count);
    let mut at = 4;
    for _ in 0..count {
        if at + 4 > bytes.len() {
            break;
        }
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().expect("4 bytes")) as usize;
        at += 4;
        if at + len > bytes.len() {
            break;
        }
        out.push(bytes[at..at + len].to_vec());
        at += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::Encodable;
    use bitcoin::Network;
    use rsk_consensus::config::ChainConfig;
    use rsk_consensus::types::header::Header as RskHeader;
    use std::sync::Arc;

    /// A synthetic RSK header. No PoW — these tests exercise the tree/work
    /// layer, not consensus validation. `tag` makes otherwise-identical
    /// siblings distinct (a different timestamp).
    fn header(number: u64, parent: B256, difficulty: u64, tag: u64) -> RskHeader {
        RskHeader {
            parent_hash: parent,
            ommers_hash: B256::ZERO,
            beneficiary: Default::default(),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(difficulty),
            number,
            gas_limit: U256::from(10_000_000u64),
            gas_used: 0,
            timestamp: 1_600_000_000 + number + tag,
            extra_data: Default::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(1),
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }

    /// A raw-encoded entry (canonical RLP) for the unvalidated tree tests.
    fn entry(number: u64, parent: B256, difficulty: u64, tag: u64) -> RskEntry {
        let header = header(number, parent, difficulty, tag);
        let mut raw = Vec::new();
        header.encode(&mut raw);
        RskEntry {
            header,
            raw,
            uncles: Vec::new(),
        }
    }

    fn core() -> Core {
        Core::in_memory(Network::Regtest).unwrap()
    }

    /// Store an unvalidated entry straight into the tree (bypassing consensus).
    fn put(core: &Core, entry: &RskEntry) -> B256 {
        let txn = core.store.write().unwrap();
        let hash = store_entry(&txn, entry).unwrap();
        txn.commit().unwrap();
        hash
    }

    #[test]
    fn ghost_weight_counts_side_branches() {
        let core = core();
        let f = put(&core, &entry(0, B256::ZERO, 100, 0));

        // A chain of five blocks above F.
        let mut parent = f;
        let mut a_tip = f;
        for n in 1..=5u64 {
            a_tip = put(&core, &entry(n, parent, 10, 0));
            parent = a_tip;
        }
        // A fork off block #2, four blocks long (tagged so its blocks differ
        // from the main chain's).
        let fork_base = {
            // block #2's hash
            let txn = core.store.read().unwrap();
            // walk: F's child #1, #2
            let c1 = txn.rsk_children(f.as_slice()).unwrap()[0];
            let c2 = txn.rsk_children(&c1).unwrap()[0];
            B256::from(c2)
        };
        let mut parent = fork_base;
        for n in 3..=6u64 {
            parent = put(&core, &entry(n, parent, 10, 1));
        }

        // F(100) + chain A(5*10=50) + fork B(4*10=40) = 190.
        assert_eq!(core.rsk_subtree_work(&f).unwrap(), U256::from(190));

        // The linear chain alone (F + A) would be 150; GHOST sees 190.
        let linear = U256::from(100 + 5 * 10);
        assert!(core.rsk_subtree_work(&f).unwrap() > linear);

        let _ = (a_tip, fork_base);
    }

    #[test]
    fn roots_are_ranked_by_subtree_work() {
        let core = core();
        let small = put(&core, &entry(0, B256::ZERO, 10, 0));
        let big = put(&core, &entry(100, B256::ZERO, 1000, 0));
        {
            let txn = core.store.write().unwrap();
            txn.rsk_put_root(small.as_slice()).unwrap();
            txn.rsk_put_root(big.as_slice()).unwrap();
            txn.commit().unwrap();
        }

        let (best, work) = core.rsk_best_root().unwrap().unwrap();
        assert_eq!(best, big);
        assert_eq!(work, U256::from(1000));
    }

    #[test]
    fn connect_rejects_a_mismatched_uncle_list() {
        let core = core();
        let f = put(&core, &entry(0, B256::ZERO, 100, 0));

        // A header claiming one uncle but carrying none.
        let mut bad = entry(1, f, 10, 0);
        bad.header.uncle_count = 1;
        let err = core.connect_rsk_headers(&[bad]).unwrap_err();
        assert!(matches!(err, Error::Rootstock(_)), "got {err:?}");
    }

    #[test]
    fn rsk_config_matches_the_network() {
        // Smoke: the Core carries an RSK chain config.
        let core = core();
        assert_eq!(core.rsk_chain.chain_id, ChainConfig::regtest().chain_id);
        let _ = Arc::new(core.rsk_chain.clone());
    }
}
