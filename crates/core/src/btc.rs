//! Finding the Bitcoin canonical chain — the Electrum SPV model.
//!
//! This is the side-effect-free core's chain logic. It mirrors Electrum's
//! `BlockchainManager`: a **tree of chains** (forks), each with a `forkpoint`
//! and a `parent`, and the **best chain** is the one with the most cumulative
//! work. Incoming headers are attached to whichever chain they extend; a header
//! whose parent is a known block but not a chain tip starts a **new fork**,
//! which is kept (not rejected) and can later win if it becomes heavier.
//!
//! The trust anchor is a **checkpoint spine**: one header per difficulty period
//! (2016 blocks), seeded from this crate's embedded `checkpoints.txt`. Because Bitcoin
//! difficulty is constant within a period, each spine header pins the work of
//! its whole period, so the cumulative work of the *entire* chain is known
//! without holding every block. The spine also sets the **finalized
//! checkpoint**: like Electrum (which refuses forks below its hardcoded max
//! checkpoint), we refuse forks whose `forkpoint` falls at or below it (so no
//! reorg can ever cross a full difficulty period), but we **do not prune** the
//! chain when it advances — headers are retained until Rootstock reaches its
//! FINAL block (see the RSK IBD design), at which point pruning can occur.
//!
//! Simplifications for this slice, stated explicitly so they are easy to lift:
//!
//! - The spine is trusted wholesale. Nothing before the first checkpoint is
//!   ever validated.
//! - Future-time, version and transaction/merkle checks are not made: the core
//!   has no clock, and the first two add no SPV value. See [`crate::btc::validation`]
//!   for the exact rule set.

use bitcoin::block::BlockHash;
use bitcoin::block::Header as BitcoinHeader;
use bitcoin::consensus::Params;
use bitcoin::hashes::Hash;
use bitcoin::pow::Work;

use crate::Core;
use crate::error::Error;
use crate::store::{DIFFICULTY_PERIOD, ReadTxn, WriteTxn};

pub mod checkpoints;
pub mod validation;

/// How far below the tip a period boundary must be before we consider it
/// settled and advance the finalized checkpoint to it.
pub const FINALITY_MARGIN_BLOCKS: u64 = DIFFICULTY_PERIOD;

/// Outcome of a [`Core::connect_headers`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectOutcome {
    /// Headers newly accepted and stored (across whatever fork they landed on).
    pub connected: usize,
    /// The fork that was current before this batch. `None` on the very first
    /// connection or when the batch stayed on the same chain.
    pub prev_best_fork: Option<u64>,
    /// The chain that is best after this batch.
    pub best_fork: Option<u64>,
    /// Canonical tip height after this batch.
    pub tip_height: u64,
    /// The new finalized checkpoint, if this batch advanced it: the checkpoint
    /// is advanced automatically, inside the same transaction as the connect.
    pub finalized: Option<u64>,
}

impl Core {
    /// Plant the trust anchor: the checkpoint spine, one header per difficulty
    /// period, accepted without validating its ancestors. This makes the whole
    /// chain's work computable and creates the root chain. The network is
    /// recorded in the same transaction so a later connect with different
    /// parameters is refused.
    pub fn seed_checkpoints(&self, entries: &[(u64, BitcoinHeader)]) -> Result<(), Error> {
        let txn = self.store.write()?;
        txn.seed_checkpoints(entries)?;
        txn.set_network(self.network)?;
        txn.commit()
    }

    /// The best (heaviest) chain id, if seeded.
    pub fn best_fork(&self) -> Result<Option<u64>, Error> {
        self.store.read()?.best_fork()
    }

    /// The canonical tip height, if the chain has been seeded.
    pub fn tip_height(&self) -> Result<Option<u64>, Error> {
        let txn = self.store.read()?;
        match txn.best_fork()? {
            None => Ok(None),
            Some(f) => Ok(txn.fork_tip(f)?.map(|(h, _)| h)),
        }
    }

    /// Cumulative proof-of-work of the best chain through its tip — the number
    /// chain selection compares across forks, observable from outside the
    /// crate (drivers print it; nothing in the logic depends on it).
    pub fn chainwork(&self) -> Result<Option<Work>, Error> {
        let txn = self.store.read()?;
        match txn.best_fork()? {
            None => Ok(None),
            Some(best) => txn.fork_chainwork(best),
        }
    }

    /// Cumulative proof-of-work of the best chain at `height`.
    pub fn chainwork_at(&self, height: u64) -> Result<Option<Work>, Error> {
        let txn = self.store.read()?;
        let Some(best) = txn.best_fork()? else {
            return Ok(None);
        };
        txn.work_at(best, height)
    }

    /// The latest finalized checkpoint.
    pub fn finalized_height(&self) -> Result<Option<u64>, Error> {
        self.store.read()?.finalized_height()
    }

    /// The work of the first difficulty period after `tail_start`:
    /// `work[tail_start .. tail_start + DIFFICULTY_PERIOD)`, or `None` if that
    /// period is not stored. Rootstock's tail work is measured against 2/3 of
    /// this. The caller picks `tail_start` (typically `finalized_height()`, then
    /// stepping back a period at a time).
    pub fn btc_tail_work(&self, tail_start: u64) -> Result<Option<Work>, Error> {
        let txn = self.store.read()?;
        let Some(best) = txn.best_fork()? else {
            return Ok(None);
        };
        let end_height = tail_start.saturating_add(DIFFICULTY_PERIOD);
        let (Some(begin), Some(end)) = (
            txn.work_at(best, tail_start)?,
            txn.work_at(best, end_height)?,
        ) else {
            return Ok(None);
        };
        Ok(Some(end - begin))
    }

    /// The period-boundary headers at or below the latest settled checkpoint, in
    /// height order (height `0` first).
    ///
    /// These are the checkpoints that have satisfied the rule — the work above
    /// them outweighs the period before them — so they are safe to treat as
    /// irreversible, e.g. to embed as a trust anchor. The tip's nearest boundary
    /// is deliberately **excluded**: it is not settled yet.
    pub fn finalized_checkpoints(&self) -> Result<Vec<(u64, BitcoinHeader)>, Error> {
        let txn = self.store.read()?;
        let Some(finalized) = txn.finalized_height()? else {
            return Ok(Vec::new());
        };
        let Some(best) = txn.best_fork()? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let mut height = 0u64;
        while height <= finalized {
            if let Some(header) = txn.header_at(best, height)? {
                out.push((height, header));
            }
            height += DIFFICULTY_PERIOD;
        }
        Ok(out)
    }

    /// Height of a known block hash on the canonical chain, if it is canonical.
    pub fn height_of(&self, hash: &BlockHash) -> Result<Option<u64>, Error> {
        let txn = self.store.read()?;
        let Some((fork, height)) = txn.locate(hash)? else {
            return Ok(None);
        };
        Ok(is_canonical_at(&txn, fork, height)?.then_some(height))
    }

    /// The header at `height` on the canonical chain, if stored.
    pub fn header_at(&self, height: u64) -> Result<Option<BitcoinHeader>, Error> {
        let txn = self.store.read()?;
        let Some(best) = txn.best_fork()? else {
            return Ok(None);
        };
        txn.header_at(best, height)
    }

    /// True if `hash` is the canonical block at `height`.
    ///
    /// Test-only: nothing outside the core reads it.
    #[cfg(test)]
    pub fn is_canonical(&self, height: u64, hash: &BlockHash) -> Result<bool, Error> {
        let txn = self.store.read()?;
        let Some(best) = txn.best_fork()? else {
            return Ok(false);
        };
        Ok(txn
            .header_at(best, height)?
            .is_some_and(|h| h.block_hash() == *hash))
    }

    /// Validate and store a contiguous ascending run of headers, attaching them
    /// to whichever chain they extend — Electrum's `can_connect` model.
    ///
    /// For each run:
    ///
    /// - The first header's parent must be a known block. If that block is a
    ///   chain tip, the run extends that chain; otherwise it starts a **new
    ///   fork** (kept, not rejected).
    /// - Every header is PoW-, continuity-, difficulty- and
    ///   median-time-past-checked (see [`crate::btc::validation`]).
    /// - The best chain is re-selected by cumulative work; a fork only wins
    ///   when it is strictly heavier.
    /// - A fork whose `forkpoint` is at or below the finalized checkpoint is
    ///   refused ([`Error::ForkBelowFinalized`]) — the checkpoint's floor.
    ///
    /// Returns [`Error::NetworkMismatch`] if the store was seeded for a
    /// different network than this [`Core`] validates against.
    ///
    /// The whole operation — reads, validation, writes and the automatic
    /// tail advance below — runs inside one write transaction, so nothing can
    /// change the store between the reads a decision is based on and the writes
    /// that act on it.
    pub fn connect_headers(&self, headers: &[BitcoinHeader]) -> Result<ConnectOutcome, Error> {
        // One transaction for the entire read → validate → write → advance
        // sequence. Dropping it without committing (the early returns) aborts.
        let txn = self.store.write()?;

        // The store records the network it was seeded for; refuse to validate
        // real headers against the wrong consensus parameters.
        if let Some(seeded) = txn.network()?
            && seeded != self.network
        {
            return Err(Error::NetworkMismatch {
                seeded,
                opened: self.network,
            });
        }

        let prev_best = txn.best_fork()?;

        // Nothing to connect: report the current tip (the transaction aborts).
        if headers.is_empty() {
            let tip = match prev_best {
                Some(f) => txn.fork_tip(f)?.unwrap_or((0, BlockHash::all_zeros())).0,
                None => 0,
            };
            return Ok(ConnectOutcome {
                connected: 0,
                prev_best_fork: prev_best,
                best_fork: prev_best,
                tip_height: tip,
                finalized: None,
            });
        }

        // Skip a leading prefix that is already stored anywhere (reconnects).
        let mut start = 0usize;
        while start < headers.len() && txn.locate(&headers[start].block_hash())?.is_some() {
            start += 1;
        }
        if start == headers.len() {
            let tip = match prev_best {
                Some(f) => txn.fork_tip(f)?.unwrap_or((0, BlockHash::all_zeros())).0,
                None => 0,
            };
            return Ok(ConnectOutcome {
                connected: 0,
                prev_best_fork: prev_best,
                best_fork: prev_best,
                tip_height: tip,
                finalized: None,
            });
        }

        // Parent of the first *new* header: must be a known block.
        let parent = if start == 0 {
            headers[0].prev_blockhash
        } else {
            headers[start - 1].block_hash()
        };
        let (parent_fork, parent_height) =
            txn.locate(&parent)?.ok_or(Error::UnknownAncestor(parent))?;

        // Decide the target chain: extend the chain whose tip is the parent, or
        // start a new fork from the parent block.
        let parent_tip = txn
            .fork_tip(parent_fork)?
            .unwrap_or((0, BlockHash::all_zeros()))
            .0;
        let (target_fork, forkpoint) = if parent_height == parent_tip {
            (parent_fork, parent_height + 1)
        } else {
            let forkpoint = parent_height + 1;
            if let Some(finalized) = txn.finalized_height()?
                && forkpoint <= finalized
            {
                return Err(Error::ForkBelowFinalized {
                    fork: forkpoint,
                    finalized,
                });
            }
            let id = txn.create_fork(parent_fork, forkpoint, headers[start].block_hash())?;
            (id, forkpoint)
        };

        // Validate continuity, expected difficulty, median-time-past and PoW
        // for the new run. Earlier headers of this batch are visible to later
        // ones, so a long run validates itself.
        let params = Params::new(self.network);
        let enforce_difficulty = validation::enforces_difficulty(&params);
        let new_headers = &headers[start..];
        // Header at `height` on the chain being extended: a header already
        // accepted in this batch, or a stored ancestor (walking to ancestor
        // forks below the forkpoint).
        let at = |height: u64| -> Result<Option<BitcoinHeader>, Error> {
            if height >= forkpoint
                && let Some(header) = new_headers.get((height - forkpoint) as usize)
            {
                return Ok(Some(*header));
            }
            txn.header_at(target_fork, height)
        };

        let mut prev = parent;
        for (offset, header) in new_headers.iter().enumerate() {
            let height = forkpoint + offset as u64;
            if header.prev_blockhash != prev {
                return Err(Error::LinkBreak {
                    height,
                    expected: prev,
                });
            }

            if enforce_difficulty {
                let parent_header = at(height - 1)?
                    .ok_or_else(|| Error::Internal(format!("missing parent at {height}")))?;
                let period_start = match height.checked_sub(DIFFICULTY_PERIOD) {
                    Some(h) => at(h)?,
                    None => None,
                };
                if let Some(expected) = validation::expected_bits(
                    height,
                    &parent_header,
                    period_start.as_ref(),
                    &params,
                ) && header.bits != expected
                {
                    return Err(Error::BadDifficulty {
                        height,
                        expected: expected.to_consensus(),
                        got: header.bits.to_consensus(),
                    });
                }
            }

            if let Some(median) = median_time_past_at(&at, height)?
                && header.time <= median
            {
                return Err(Error::BadTimestamp {
                    height,
                    median,
                    got: header.time,
                });
            }

            header
                .validate_pow(header.target())
                .map_err(|e| Error::BadPow {
                    height,
                    detail: e.to_string(),
                })?;
            prev = header.block_hash();
        }

        // Cumulative work of the run, starting from the parent's work.
        let base_work = txn.work_at(parent_fork, parent_height)?.ok_or_else(|| {
            Error::Internal(format!("no work at ({parent_fork}, {parent_height})"))
        })?;
        let mut entries: Vec<(u64, &BitcoinHeader, Work)> =
            Vec::with_capacity(headers.len() - start);
        let mut cumulative = base_work;
        for (offset, header) in headers[start..].iter().enumerate() {
            cumulative = cumulative + header.target().to_work();
            entries.push((forkpoint + offset as u64, header, cumulative));
        }
        txn.put_headers(target_fork, &entries)?;

        // Re-select the best chain by cumulative work (strictly heavier wins).
        let mut best = txn.best_fork()?.unwrap_or(0);
        let best_work = txn
            .fork_chainwork(best)?
            .unwrap_or(Work::from_be_bytes([0; 32]));
        let target_work = txn
            .fork_chainwork(target_fork)?
            .unwrap_or(Work::from_be_bytes([0; 32]));
        if target_fork != best && target_work > best_work {
            txn.set_best_fork(target_fork)?;
            best = target_fork;
        }

        let tip_height = match prev_best {
            Some(_) => txn.fork_tip(best)?.unwrap_or((0, BlockHash::all_zeros())).0,
            None => forkpoint + (headers.len() - start) as u64 - 1,
        };

        // Advancing the finalized checkpoint is part of connecting headers: move
        // it if this batch tipped a period boundary over the margin.
        let finalized = finalize_in_txn(&txn)?;
        txn.commit()?;

        Ok(ConnectOutcome {
            connected: headers.len() - start,
            prev_best_fork: prev_best,
            best_fork: Some(best),
            tip_height,
            finalized,
        })
    }

    /// Connect a single header (Electrum's near-tip `save_header` path).
    ///
    /// Test-only: the sync callers use [`Core::connect_headers`] directly.
    #[cfg(test)]
    pub fn connect_header(&self, header: &BitcoinHeader) -> Result<ConnectOutcome, Error> {
        self.connect_headers(std::slice::from_ref(header))
    }

    /// Advance the finalized checkpoint to the newest difficulty-period boundary
    /// that is at least a full period below the tip, and move the Bitcoin tail to
    /// it. Returns the new checkpoint.
    ///
    /// This runs automatically at the end of every [`Core::connect_headers`]
    /// batch (reported in [`ConnectOutcome::finalized`]); you do not normally
    /// need to call it.
    ///
    /// Only advances if the work built on top of the boundary (boundary to tip)
    /// is at least the work of the full period before it. This prevents moving
    /// the checkpoint across a difficulty drop — e.g. from X to 0.1X — that could
    /// otherwise be reorged if the higher-difficulty chain returns: the tail has
    /// to grow until it outweighs what it would be replacing.
    ///
    /// Cumulative work is known at every period boundary (the spine), so both
    /// sides are plain differences of stored cumulative work.
    ///
    /// Nothing advances while a fork is the best chain, since the spine
    /// (fork 0) is assumed canonical.
    ///
    /// Test-only: production advancement rides inside
    /// [`Core::connect_headers`].
    #[cfg(test)]
    pub fn finalize_period(&self) -> Result<Option<u64>, Error> {
        let txn = self.store.write()?;
        match finalize_in_txn(&txn)? {
            Some(height) => {
                txn.commit()?;
                Ok(Some(height))
            }
            // No writes were staged; dropping the transaction aborts it.
            None => Ok(None),
        }
    }
}

/// The checkpoint rule, applied through an open transaction. Factored out so
/// `connect_headers` can run it inside the same transaction as the connect.
fn finalize_in_txn(txn: &WriteTxn) -> Result<Option<u64>, Error> {
    if txn.best_fork()? != Some(0) {
        return Ok(None);
    }
    let Some((tip, _)) = txn.fork_tip(0)? else {
        return Ok(None);
    };
    if tip < FINALITY_MARGIN_BLOCKS {
        return Ok(None);
    }
    let boundary = ((tip - FINALITY_MARGIN_BLOCKS) / DIFFICULTY_PERIOD) * DIFFICULTY_PERIOD;
    let current = txn.finalized_height()?.unwrap_or(0);
    if boundary <= current {
        return Ok(None);
    }

    let work = |height: u64| -> Result<Work, Error> {
        txn.work_at(0, height)?
            .ok_or_else(|| Error::Internal(format!("no cumulative work at height {height}")))
    };
    // One full period ending at the boundary, and everything built above it.
    let before = work(boundary)? - work(boundary - DIFFICULTY_PERIOD)?;
    let after = work(tip)? - work(boundary)?;
    if after < before {
        return Ok(None);
    }

    // RETENTION POLICY (RSK IBD design):
    // Do NOT prune the Bitcoin chain here. We keep all headers so Rootstock can
    // cross-link against the full canonical chain; the caller prunes below the
    // Bitcoin tail start only once Rootstock reaches FINAL.
    txn.set_finalized(boundary)?;
    Ok(Some(boundary))
}

/// Whether a stored `(fork, height)` block lies on the canonical chain.
fn is_canonical_at(txn: &ReadTxn, fork: u64, height: u64) -> Result<bool, Error> {
    let Some(best) = txn.best_fork()? else {
        return Ok(false);
    };
    if fork == best {
        return Ok(true);
    }
    // Walk the fork's ancestry: a block is canonical if it is at or below the
    // best chain's forkpoint and on the best chain's ancestors.
    let mut f = best;
    loop {
        let Some(meta) = txn.fork_meta(f)? else {
            return Ok(false);
        };
        if fork == f {
            return Ok(height >= meta.forkpoint);
        }
        let Some(parent) = meta.parent else {
            return Ok(false);
        };
        f = parent;
    }
}

// ── validation helpers ──────────────────────────────────────────────────────

/// The median-time-past the header at `height` must exceed: the median of the
/// previous [`validation::MEDIAN_TIME_PAST`] timestamps. Returns `None` when
/// any of them is unavailable (e.g. just above a checkpoint that stores only
/// period boundaries), in which case the check is skipped for that header.
fn median_time_past_at(
    at: &impl Fn(u64) -> Result<Option<BitcoinHeader>, Error>,
    height: u64,
) -> Result<Option<u32>, Error> {
    let mut times = [0u32; validation::MEDIAN_TIME_PAST];
    for (k, slot) in times.iter_mut().enumerate() {
        let Some(h) = height.checked_sub(1 + k as u64) else {
            return Ok(None);
        };
        match at(h)? {
            Some(header) => *slot = header.time,
            None => return Ok(None),
        }
    }
    Ok(Some(validation::median_time_past(times)))
}

// ── proof-of-work helper ────────────────────────────────────────────────────

/// Compute the `Work` carried by a header (needed by callers that assemble
/// branches before handing them to [`Core::connect_headers`]).
pub fn header_work(header: &BitcoinHeader) -> Work {
    header.target().to_work()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::block::Version;
    use bitcoin::consensus::Decodable;
    use bitcoin::pow::CompactTarget;

    /// A fixed base timestamp for synthetic headers.
    const BASE_TIME: u32 = 1_600_000_000;

    /// The easiest valid Bitcoin target (`0x207fffff`): nearly any hash passes,
    /// so we can synthesize long chains quickly without a real miner. It is
    /// also exactly the regtest proof-of-work limit, which is the network the
    /// synthetic tests use.
    const EASY_BITS: u32 = 0x207f_ffff;

    /// Targets with per-block work exactly 20 and 22 (a 1.1x difficulty step).
    ///
    /// `Target::to_work` is an integer division (`2^256 / (target + 1)`), so
    /// near the top of the target range only whole multiples of `EASY_BITS`'s
    /// work of 2 are reachable (`0x207effff` also floors to 2). Starting from a
    /// larger base gives finer steps while still passing about one hash in 20,
    /// so mining stays instant.
    const WORK20_BITS: u32 = 0x200c_cccc;
    const WORK22_BITS: u32 = 0x200b_a2e8;

    /// Mine a header on top of `prev` with an explicit timestamp and target.
    fn mine_at(prev: BlockHash, time: u32, bits: u32) -> BitcoinHeader {
        let target = CompactTarget::from_consensus(bits);
        let mut nonce = 0u32;
        loop {
            let h = BitcoinHeader {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::hashes::Hash::all_zeros(),
                time,
                bits: target,
                nonce,
            };
            if h.validate_pow(h.target()).is_ok() {
                return h;
            }
            nonce = nonce.wrapping_add(1);
            assert!(nonce != 0, "could not mine a header");
        }
    }

    /// Mine a child of `parent`. `tag` shifts the timestamp forward from the
    /// parent's, which keeps timestamps monotonic across separate runs (so the
    /// median-time-past rule holds) and makes two children of the same parent
    /// distinct.
    fn mine_child(parent: &BitcoinHeader, bits: u32, tag: u32) -> BitcoinHeader {
        mine_at(parent.block_hash(), parent.time + 1 + tag, bits)
    }

    /// Mine `n` contiguous headers above `parent` with the given target bits.
    fn mine_chain_from(
        parent: &BitcoinHeader,
        n: usize,
        bits: u32,
        tag_offset: u32,
    ) -> Vec<BitcoinHeader> {
        let mut out = Vec::with_capacity(n);
        let mut cur = *parent;
        for i in 0..n {
            let h = mine_child(&cur, bits, tag_offset + i as u32);
            cur = h;
            out.push(h);
        }
        out
    }

    /// Mine the synthetic genesis (parent is the virtual all-zero block).
    fn mine_genesis(tag: u32) -> BitcoinHeader {
        mine_at(BlockHash::all_zeros(), BASE_TIME + tag, EASY_BITS)
    }

    /// Easy-target chain above `parent`; `tag_offset` separates competing forks.
    fn easy_chain(parent: &BitcoinHeader, n: usize, tag_offset: u32) -> Vec<BitcoinHeader> {
        mine_chain_from(parent, n, EASY_BITS, tag_offset)
    }

    /// A fresh in-memory regtest chain seeded with a synthetic checkpoint at 0.
    ///
    /// Regtest permits minimum-difficulty blocks, so (like Electrum) the
    /// difficulty rule is skipped; the tests here exercise the fork/finality
    /// machinery and the median-time-past rule. The difficulty rule itself is
    /// tested in [`crate::btc::validation`] and against real mainnet data.
    fn seeded() -> Core {
        let chain = Core::in_memory(Network::Regtest).expect("in-memory store");
        let genesis = mine_genesis(0);
        chain.seed_checkpoints(&[(0, genesis)]).expect("seed");
        chain
    }

    /// The header at `height` on the canonical chain.
    fn canonical(chain: &Core, height: u64) -> BitcoinHeader {
        chain
            .header_at(height)
            .unwrap()
            .unwrap_or_else(|| panic!("no canonical header at {height}"))
    }

    /// The hash of the block at `height` on the canonical chain.
    fn canonical_hash(chain: &Core, height: u64) -> BlockHash {
        canonical(chain, height).block_hash()
    }

    fn real_genesis() -> BitcoinHeader {
        let hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
        let bytes = hex::decode(hex).unwrap();
        let mut reader = bytes.as_slice();
        BitcoinHeader::consensus_decode(&mut reader).unwrap()
    }

    #[test]
    fn seeds_and_extends() -> eyre::Result<()> {
        let chain = seeded();
        assert_eq!(chain.tip_height()?, Some(0));
        assert_eq!(chain.finalized_height()?, Some(0));
        assert_eq!(chain.best_fork()?, Some(0));

        let run = easy_chain(&canonical(&chain, 0), 5, 1);
        let out = chain.connect_headers(&run)?;
        assert_eq!(out.connected, 5);
        assert_eq!(out.best_fork, Some(0));
        assert_eq!(out.tip_height, 5);

        let h3 = canonical_hash(&chain, 3);
        assert!(chain.is_canonical(3, &h3)?);
        assert_eq!(chain.height_of(&h3)?, Some(3));
        Ok(())
    }

    #[test]
    fn seeding_twice_is_refused_and_leaves_the_chain_intact() -> eyre::Result<()> {
        let chain = seeded();
        let run = easy_chain(&canonical(&chain, 0), 5, 1);
        chain.connect_headers(&run)?;
        let tip = chain.tip_height()?;
        let work = chain.chainwork()?;

        // Re-seeding an anchored store is refused rather than clobbering the
        // taller tip and the finality floor.
        let other = mine_genesis(42);
        let err = chain.seed_checkpoints(&[(0, other)]).unwrap_err();
        assert!(matches!(err, Error::AlreadySeeded), "got {err:?}");

        assert_eq!(chain.tip_height()?, tip);
        assert_eq!(chain.chainwork()?, work);
        Ok(())
    }

    #[test]
    fn rejects_bad_pow() -> eyre::Result<()> {
        let chain = seeded();
        let mut bad = easy_chain(&canonical(&chain, 0), 1, 1);
        bad[0].bits = CompactTarget::from_consensus(0x1d00_ffff);
        let err = chain.connect_headers(&bad).unwrap_err();
        assert!(matches!(err, Error::BadPow { .. }), "got {err:?}");
        Ok(())
    }

    #[test]
    fn rejects_unknown_ancestor() -> eyre::Result<()> {
        let chain = seeded();
        let run = [mine_at(BlockHash::all_zeros(), BASE_TIME + 1, EASY_BITS)]; // links to nothing stored
        let err = chain.connect_headers(&run).unwrap_err();
        assert!(matches!(err, Error::UnknownAncestor(_)), "got {err:?}");
        Ok(())
    }

    #[test]
    fn single_header_connects() -> eyre::Result<()> {
        let chain = seeded();
        let h = mine_child(&canonical(&chain, 0), EASY_BITS, 1);
        let out = chain.connect_header(&h)?;
        assert_eq!(out.connected, 1);
        assert_eq!(out.tip_height, 1);
        assert!(chain.is_canonical(1, &h.block_hash())?);
        Ok(())
    }

    #[test]
    fn lighter_fork_is_kept_not_rejected() -> eyre::Result<()> {
        let chain = seeded();
        let main = easy_chain(&canonical(&chain, 0), 5, 1);
        chain.connect_headers(&main)?;
        assert_eq!(chain.tip_height()?, Some(5));

        // A lighter fork from height 3 (parent = main[2]) with 2 blocks. Its
        // tip (height 5) ties, but with strictly less work it must not become
        // best — and crucially it must be *stored*, not rejected.
        let fork = easy_chain(&main[2], 2, 1000);
        let out = chain.connect_headers(&fork)?;
        assert_eq!(out.connected, 2);
        assert_eq!(out.best_fork, Some(0), "best chain must stay the root");

        // The fork survives in the tree and its headers are locatable.
        assert_eq!(chain.store.read()?.fork_count()?, 2);
        let (f, h) = chain.store.read()?.locate(&fork[0].block_hash())?.unwrap();
        assert_eq!(h, 4);
        assert_ne!(f, 0);
        // The fork's blocks are not canonical.
        assert!(!chain.is_canonical(4, &fork[0].block_hash())?);
        Ok(())
    }

    /// A fork's cumulative work below its forkpoint lives on its ancestors, so
    /// `chainwork_at` must resolve through them rather than read the fork's own
    /// (absent) rows.
    #[test]
    fn chainwork_at_resolves_the_ancestor_fork() -> eyre::Result<()> {
        let chain = seeded();
        let main = easy_chain(&canonical(&chain, 0), 5, 1);
        chain.connect_headers(&main)?;

        // A heavier fork from height 3 (parent = main[2]) wins; its forkpoint is
        // 4, so heights below it live on the root chain.
        let fork = easy_chain(&main[2], 5, 1000);
        chain.connect_headers(&fork)?;
        let best = chain.best_fork()?.expect("a best fork");
        assert_ne!(best, 0);

        let txn = chain.store.read()?;
        // Below the forkpoint both reads resolve to the root chain's row.
        assert_eq!(chain.chainwork_at(2)?, txn.work_at(0, 2)?);
        assert_eq!(txn.work_at(best, 2)?, txn.work_at(0, 2)?);
        // At/above the forkpoint the fork's own row is used.
        assert_eq!(chain.chainwork_at(4)?, txn.work_at(best, 4)?);
        Ok(())
    }

    #[test]
    fn failed_batch_leaves_no_partial_state() -> eyre::Result<()> {
        // A batch whose parent is not a chain tip starts a new fork; if a later
        // header in the same batch fails validation, the fork must be rolled
        // back too — the whole read/validate/write/advance runs in one txn.
        let chain = seeded();
        let main = easy_chain(&canonical(&chain, 0), 5, 1);
        chain.connect_headers(&main)?;
        assert_eq!(chain.store.read()?.fork_count()?, 1);

        // Fork from height 3 (parent = main[2], not the tip), second header
        // with bad PoW (a much harder target than it was mined for).
        let mut fork = easy_chain(&main[2], 2, 1000);
        fork[1].bits = CompactTarget::from_consensus(0x1d00_ffff);
        let err = chain.connect_headers(&fork).unwrap_err();
        assert!(matches!(err, Error::BadPow { .. }), "got {err:?}");

        // No orphan fork, and no header of the batch was committed.
        assert_eq!(chain.store.read()?.fork_count()?, 1, "no orphan fork");
        assert!(chain.store.read()?.locate(&fork[0].block_hash())?.is_none());
        Ok(())
    }

    #[test]
    fn heavier_fork_wins() -> eyre::Result<()> {
        let chain = seeded();
        let main = easy_chain(&canonical(&chain, 0), 5, 1);
        chain.connect_headers(&main)?;

        // Fork from height 3 with 5 blocks → tip 8, strictly more work.
        let fork = easy_chain(&main[2], 5, 1000);
        let out = chain.connect_headers(&fork)?;
        assert_eq!(out.connected, 5);
        assert_eq!(out.tip_height, 8);
        let best = chain.best_fork()?.unwrap();
        assert_ne!(best, 0, "fork must become best");
        assert_eq!(out.best_fork, Some(best));

        // Fork tip is canonical; old branch tip is not.
        assert!(chain.is_canonical(8, &fork[4].block_hash())?);
        assert!(!chain.is_canonical(5, &main[4].block_hash())?);
        // Canonical reads below the forkpoint fall back to the shared parent.
        assert!(chain.is_canonical(3, &main[2].block_hash())?);
        Ok(())
    }

    #[test]
    fn fork_below_finalized_is_refused() -> eyre::Result<()> {
        let chain = seeded();
        let main = easy_chain(&canonical(&chain, 0), 6, 1);
        chain.connect_headers(&main)?;

        // Advance the finalized checkpoint to height 1, as an advance would.
        let txn = chain.store.write()?;
        txn.set_finalized(1)?;
        txn.commit()?;
        assert_eq!(chain.finalized_height()?, Some(1));

        // A fork starting at height 1 (forkpoint 1 <= finalized 1) is refused.
        let fork = easy_chain(&canonical(&chain, 0), 3, 1000);
        let err = chain.connect_headers(&fork).unwrap_err();
        assert!(
            matches!(err, Error::ForkBelowFinalized { .. }),
            "got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn lighter_fork_then_extends_to_win() -> eyre::Result<()> {
        // Electrum's grace: a fork is kept even while lighter, so it can win
        // later when more of its headers arrive.
        let chain = seeded();
        let main = easy_chain(&canonical(&chain, 0), 5, 1);
        chain.connect_headers(&main)?;
        assert_eq!(chain.best_fork()?, Some(0));

        // First arrives a short, lighter slice of a fork from height 3.
        let fork_part1 = easy_chain(&main[2], 1, 1000);
        let out = chain.connect_headers(&fork_part1)?;
        assert_eq!(out.connected, 1);
        assert_eq!(chain.best_fork()?, Some(0), "still root while lighter");

        // Later, more headers of the same fork arrive, tipping it heavier.
        let fork_part2 = easy_chain(&fork_part1[0], 4, 1001);
        let out = chain.connect_headers(&fork_part2)?;
        assert_eq!(out.connected, 4);
        assert_eq!(out.tip_height, 8);
        let best = chain.best_fork()?.unwrap();
        assert_ne!(best, 0, "fork wins once it becomes heavier");
        // The two batches landed on the same fork.
        let txn = chain.store.read()?;
        let (f1, _) = txn.locate(&fork_part1[0].block_hash())?.unwrap();
        let (f2, _) = txn.locate(&fork_part2[3].block_hash())?.unwrap();
        assert_eq!(f1, f2);
        assert!(chain.is_canonical(8, &fork_part2[3].block_hash())?);
        Ok(())
    }

    #[test]
    fn finalizes_period_retains_headers() -> eyre::Result<()> {
        let chain = seeded();
        // Build past two full difficulty periods (4032) plus a bit, so
        // boundary 2016 is a full period below the tip and is finalized.
        let run = easy_chain(
            &canonical(&chain, 0),
            2 * DIFFICULTY_PERIOD as usize + 100,
            1,
        );
        let out = chain.connect_headers(&run)?;
        assert_eq!(chain.tip_height()?, Some(2 * DIFFICULTY_PERIOD + 100));

        // The checkpoint was finalized automatically as part of the connect.
        assert_eq!(out.finalized, Some(DIFFICULTY_PERIOD));
        assert_eq!(chain.finalized_height()?, Some(DIFFICULTY_PERIOD));

        // The tail work is the first period after the checkpoint: work[2016 ..
        // 4032), computed on the fly.
        let expected = chain.chainwork_at(2 * DIFFICULTY_PERIOD)?.unwrap()
            - chain.chainwork_at(DIFFICULTY_PERIOD)?.unwrap();
        assert_eq!(chain.btc_tail_work(DIFFICULTY_PERIOD)?, Some(expected));
        assert!(expected > Work::from_be_bytes([0; 32]));

        // Headers BELOW the checkpoint are RETAINED (no pruning when it
        // finalizes; pruning happens later when RSK reaches FINAL).
        assert!(chain.header_at(1)?.is_some());
        assert!(chain.header_at(DIFFICULTY_PERIOD)?.is_some());
        assert!(
            chain
                .header_at(2 * DIFFICULTY_PERIOD + 100)
                .unwrap()
                .is_some()
        );

        // Finalizing again with no new period is a no-op.
        assert_eq!(chain.finalize_period()?, None);
        Ok(())
    }

    #[test]
    fn finalized_checkpoints_stop_at_the_floor() -> eyre::Result<()> {
        let chain = seeded();
        // Two full periods plus a bit: boundary 2016 is finalized, and the
        // tip's nearest boundary (the next ones up to 4032) is not.
        let parent = canonical(&chain, 0);
        let run = easy_chain(&parent, 2 * DIFFICULTY_PERIOD as usize + 100, 1);
        chain.connect_headers(&run)?;

        let finalized = chain.finalized_height()?.expect("a finalized floor");
        assert_eq!(finalized, DIFFICULTY_PERIOD);
        let cps = chain.finalized_checkpoints()?;

        // Every exported checkpoint is at or below the floor, and the newest
        // one *is* the floor — never the un-finalized boundary above it.
        assert_eq!(cps.first().map(|(h, _)| *h), Some(0));
        assert_eq!(cps.last().map(|(h, _)| *h), Some(finalized));
        assert!(cps.iter().all(|(h, _)| *h <= finalized));
        assert_eq!(cps.len() as u64, finalized / DIFFICULTY_PERIOD + 1);

        // The tip is well past the floor: the boundary just above it was
        // deliberately not exported.
        let tip = chain.tip_height()?.expect("a tip");
        assert!(tip > finalized + DIFFICULTY_PERIOD);
        Ok(())
    }

    #[test]
    fn checkpoint_spine_survives_pruning() -> eyre::Result<()> {
        let chain = seeded();
        let run = easy_chain(
            &canonical(&chain, 0),
            2 * DIFFICULTY_PERIOD as usize + 100,
            1,
        );
        // The connect advances the tail and does NOT prune.
        let out = chain.connect_headers(&run)?;
        assert_eq!(out.finalized, Some(DIFFICULTY_PERIOD));

        // The checkpoint spine still resolves: height 0 (the seeded genesis)
        // survives, its hash maps to its height, and its work is intact.
        assert!(chain.header_at(0)?.is_some());
        let genesis_hash = canonical_hash(&chain, 0);
        assert_eq!(chain.height_of(&genesis_hash)?, Some(0));
        assert!(chain.store.read()?.work_at(0, 0)?.is_some());

        Ok(())
    }

    #[test]
    fn spine_work_scales_by_full_periods() -> eyre::Result<()> {
        // Two spine checkpoints, each an easy-target header with per-block work
        // `w`. The spine must report cumulative work as if every one of the
        // 2016 blocks in the intervening period were stored:
        //   work_at(0)     = w                    (just the boundary block)
        //   work_at(2016)  = w + 2015*w + w = 2017*w
        let chain = Core::in_memory(Network::Regtest).unwrap();
        let g0 = mine_genesis(0);
        let g2016 = mine_genesis(1);
        let w = header_work(&g0);
        chain
            .seed_checkpoints(&[(0, g0), (DIFFICULTY_PERIOD, g2016)])
            .unwrap();

        assert_eq!(chain.store.read()?.work_at(0, 0).unwrap(), Some(w));
        let expected = {
            let mut acc = w; // block 0
            for _ in 1..DIFFICULTY_PERIOD {
                acc = acc + w; // the rest of period 0
            }
            acc + header_work(&g2016) // this boundary block
        };
        assert_eq!(
            chain.store.read()?.work_at(0, DIFFICULTY_PERIOD).unwrap(),
            Some(expected)
        );
        Ok(())
    }

    #[test]
    fn real_genesis_is_a_valid_pow_checkpoint() -> eyre::Result<()> {
        let genesis = real_genesis();
        // The real mainnet genesis satisfies the difficulty-1 target.
        genesis
            .validate_pow(genesis.target())
            .expect("real genesis PoW");
        let chain = Core::in_memory(Network::Regtest).unwrap();
        chain.seed_checkpoints(&[(0, genesis)]).unwrap();
        assert_eq!(
            chain.header_at(0)?.unwrap().block_hash(),
            genesis.block_hash()
        );
        // And we can extend on top of the real genesis hash with synthetic
        // headers (continuity is what matters here, not difficulty).
        let run = mine_chain_from(&genesis, 2, EASY_BITS, 1);
        let out = chain.connect_headers(&run)?;
        assert_eq!(out.connected, 2);
        assert_eq!(out.tip_height, 2);
        Ok(())
    }

    #[test]
    fn finalizes_period_only_when_tail_work_exceeds_pre_check() -> eyre::Result<()> {
        // At constant difficulty, the work from the boundary to the tip (a full
        // period plus the extra blocks) exceeds the work of the period before
        // the boundary, so the checkpoint finalizes.
        let chain = seeded();
        let checkpoint = DIFFICULTY_PERIOD as usize;

        // Build a chain to the checkpoint height.
        let run1 = easy_chain(&canonical(&chain, 0), checkpoint, 1);
        chain.connect_headers(&run1)?;
        assert_eq!(chain.tip_height()?, Some(checkpoint as u64));

        // Now extend past the checkpoint with blocks at the same difficulty.
        let run2 = easy_chain(&canonical(&chain, checkpoint as u64), checkpoint + 100, 1);
        let out = chain.connect_headers(&run2)?;
        assert_eq!(chain.tip_height()?, Some((2 * checkpoint + 100) as u64));

        // Finalization should succeed because the tail has accumulated a full
        // period of work after the checkpoint.
        assert_eq!(out.finalized, Some(DIFFICULTY_PERIOD));
        assert_eq!(chain.finalized_height()?, Some(DIFFICULTY_PERIOD));
        Ok(())
    }

    #[test]
    fn finalizes_only_once_tail_work_catches_up() -> eyre::Result<()> {
        // Difficulty drops by 10% right at the checkpoint (per-block work
        // 22 -> 20). A tail of one full period at the lower difficulty carries
        // ~9% less work than the period before the checkpoint, so finalization
        // must wait until the tail has grown by about a tenth — and then go
        // ahead. The boundary stays 2016 throughout (tip < 6048).
        let chain = seeded();
        let period = DIFFICULTY_PERIOD as usize;

        // Guard the constants: 11 * 20 == 10 * 22.
        let w20 = header_work(&mine_at(BlockHash::all_zeros(), BASE_TIME, WORK20_BITS));
        let w22 = header_work(&mine_at(BlockHash::all_zeros(), BASE_TIME, WORK22_BITS));
        let times = |w: Work, n: u32| (0..n).fold(Work::from_be_bytes([0; 32]), |acc, _| acc + w);
        assert_eq!(times(w20, 11), times(w22, 10));

        // The period before the checkpoint: 2016 blocks at work 22.
        let run1 = mine_chain_from(&canonical(&chain, 0), period, WORK22_BITS, 1);
        chain.connect_headers(&run1)?;
        assert_eq!(chain.tip_height()?, Some(period as u64));

        // Smallest tail at work 20 that reaches 2016 * 22: ceil(44352 / 20).
        let tail_needed = (period * 22).div_ceil(20);
        let tail = mine_chain_from(
            &canonical(&chain, period as u64),
            tail_needed,
            WORK20_BITS,
            1,
        );

        // One block short of enough: the automatic finalization is refused.
        let short = chain.connect_headers(&tail[..tail_needed - 1])?;
        assert_eq!(chain.tip_height()?, Some((period + tail_needed - 1) as u64));
        assert_eq!(
            short.finalized, None,
            "must not finalize while the tail is lighter than the period before it"
        );
        assert_eq!(chain.finalized_height()?, Some(0));

        // The last block tips the tail over: now it finalizes.
        let out = chain.connect_headers(&tail[tail_needed - 1..])?;
        assert_eq!(out.finalized, Some(DIFFICULTY_PERIOD));
        assert_eq!(chain.finalized_height()?, Some(DIFFICULTY_PERIOD));
        Ok(())
    }

    #[test]
    fn rejects_timestamp_at_or_below_median_time_past() -> eyre::Result<()> {
        let chain = seeded();
        // 11 headers so a 12th has a full median-time-past window.
        let run = easy_chain(&canonical(&chain, 0), 11, 1);
        chain.connect_headers(&run)?;

        // A sibling of height 12 whose timestamp is below the median of the
        // previous 11 (the median is the 6th, well above the first block's time).
        let parent = canonical(&chain, 11);
        let too_early = canonical(&chain, 1).time;
        let bad = mine_at(parent.block_hash(), too_early, EASY_BITS);
        let err = chain.connect_headers(&[bad]).unwrap_err();
        assert!(
            matches!(err, Error::BadTimestamp { height: 12, .. }),
            "got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn connecting_with_the_wrong_network_is_refused() -> eyre::Result<()> {
        let chain = Core::in_memory(Network::Regtest)?;
        chain.seed_checkpoints(&[(0, mine_genesis(0))])?;
        assert_eq!(chain.store.read()?.network()?, Some(Network::Regtest));

        // Re-open the same store believing it is mainnet: the recorded network
        // wins over the caller's claim.
        let Core { store, .. } = chain;
        let chain = Core {
            store,
            network: Network::Bitcoin,
            rsk_chain: crate::rsk::chain_config(Network::Bitcoin),
        };
        let header = mine_child(&canonical(&chain, 0), EASY_BITS, 1);
        let err = chain.connect_headers(&[header]).unwrap_err();
        assert!(
            matches!(
                err,
                Error::NetworkMismatch {
                    seeded: Network::Regtest,
                    opened: Network::Bitcoin,
                }
            ),
            "got {err:?}"
        );
        Ok(())
    }

    // ── btc tail work tests ─────────────────────────────────────────────────

    /// The work is computed on the fly for the given tail start; not seeded,
    /// there is nothing to compute.
    #[test]
    fn btc_tail_work_none_without_seed() -> eyre::Result<()> {
        let chain = Core::in_memory(Network::Regtest)?;
        assert_eq!(chain.finalized_height()?, None);
        assert_eq!(chain.btc_tail_work(0)?, None);
        Ok(())
    }

    /// With less than a full period above the start there is no first period to
    /// measure.
    #[test]
    fn btc_tail_work_none_before_a_full_period() -> eyre::Result<()> {
        let chain = seeded();
        assert_eq!(chain.finalized_height()?.unwrap(), 0);

        // 100 blocks is less than a period: work[0 .. 2016) is not stored.
        let run = easy_chain(&canonical(&chain, 0), 100, 1);
        chain.connect_headers(&run)?;
        assert_eq!(chain.finalized_height()?.unwrap(), 0, "no finalize yet");
        assert_eq!(chain.btc_tail_work(0)?, None);
        Ok(())
    }

    /// After two full periods + 100 blocks the tail work at 2016 is the work of
    /// the first period after it, [2016 .. 4032).
    #[test]
    fn btc_tail_work_is_the_first_tail_period() -> eyre::Result<()> {
        let chain = seeded();
        let parent = canonical(&chain, 0);
        let n = 2 * DIFFICULTY_PERIOD as usize + 100;
        let run = mine_chain_from(&parent, n, EASY_BITS, 1);
        chain.connect_headers(&run)?;

        assert_eq!(chain.finalized_height()?.unwrap(), DIFFICULTY_PERIOD);
        let window = chain.chainwork_at(2 * DIFFICULTY_PERIOD)?.unwrap()
            - chain.chainwork_at(DIFFICULTY_PERIOD)?.unwrap();
        assert_eq!(chain.btc_tail_work(DIFFICULTY_PERIOD)?, Some(window));
        assert!(window > chain.chainwork_at(0)?.unwrap());
        Ok(())
    }

    /// The work is the first period *after* the tail start, at that period's own
    /// difficulty — not the (heavier) period before it. With a drop to work 20
    /// after the boundary, it is 2016 * 20, below the preceding ~2015 * 22.
    #[test]
    fn btc_tail_work_uses_the_period_after_the_start() -> eyre::Result<()> {
        let chain = seeded();
        let period = DIFFICULTY_PERIOD as usize;

        // Genesis has easy-target work. Period 0 blocks use work 22.
        let run1 = mine_chain_from(&canonical(&chain, 0), period, WORK22_BITS, 1);
        chain.connect_headers(&run1)?;

        // Tail after boundary 2016 at the lower work 20, enough to outweigh the
        // period before it and finalize.
        let tail_needed = (period * 22).div_ceil(20);
        let tail = mine_chain_from(
            &canonical(&chain, period as u64),
            tail_needed,
            WORK20_BITS,
            1,
        );
        chain.connect_headers(&tail)?;

        assert_eq!(chain.finalized_height()?.unwrap(), DIFFICULTY_PERIOD);
        let after = chain.chainwork_at(2 * DIFFICULTY_PERIOD)?.unwrap()
            - chain.chainwork_at(DIFFICULTY_PERIOD)?.unwrap();
        let before =
            chain.chainwork_at(DIFFICULTY_PERIOD)?.unwrap() - chain.chainwork_at(0)?.unwrap();
        assert_eq!(chain.btc_tail_work(DIFFICULTY_PERIOD)?, Some(after));
        assert!(after < before, "the drop makes the after-period lighter");
        Ok(())
    }
}
