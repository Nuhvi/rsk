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
//! (2016 blocks), seeded from `bitcoin-spv/checkpoints.txt`. Because Bitcoin
//! difficulty is constant within a period, each spine header pins the work of
//! its whole period, so the cumulative work of the *entire* chain is known
//! without holding every block. The spine also sets the **finality floor**:
//! like Electrum (which refuses forks below its hardcoded max checkpoint), we
//! prune forks whose `forkpoint` falls at or below the finalized point — no
//! reorg can ever cross a full difficulty period.
//!
//! Simplifications for this slice, stated explicitly so they are easy to lift:
//!
//! - The spine is trusted wholesale. Nothing before the first checkpoint is
//!   ever validated.
//! - Difficulty retargeting between periods is not yet validated (headers are
//!   only PoW- and continuity-checked); see CONTRIBUTING.md.

use bitcoin::block::BlockHash;
use bitcoin::block::Header as BitcoinHeader;
use bitcoin::hashes::Hash;
use bitcoin::pow::Work;

use crate::error::Error;
use crate::store::{DIFFICULTY_PERIOD, Store};

/// How far below the tip a period boundary must be before we consider it
/// settled and prune the non-checkpoint headers below it.
pub const FINALITY_MARGIN_BLOCKS: u64 = DIFFICULTY_PERIOD;

/// Outcome of a [`Chain::connect_headers`] call.
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
}

/// The canonical-chain engine: a thin, deterministic layer over [`Store`].
///
/// No concurrency, no network, no clock, no hidden I/O — the caller supplies
/// headers and reads back outcomes.
pub struct Chain {
    store: Store,
}

impl Chain {
    /// Open a file-backed chain store.
    pub fn open(path: &std::path::Path) -> Result<Self, Error> {
        Ok(Self {
            store: Store::open(path)?,
        })
    }

    /// Open an in-memory chain store (tests, no disk I/O).
    pub fn in_memory() -> Result<Self, Error> {
        Ok(Self {
            store: Store::in_memory()?,
        })
    }

    /// Plant the trust anchor: the checkpoint spine, one header per difficulty
    /// period, accepted without validating its ancestors. This makes the whole
    /// chain's work computable and creates the root chain.
    pub fn seed_checkpoints(&self, entries: &[(u64, BitcoinHeader)]) -> Result<(), Error> {
        self.store.seed_checkpoints(entries)
    }

    /// The best (heaviest) chain id, if seeded.
    pub fn best_fork(&self) -> Result<Option<u64>, Error> {
        self.store.best_fork()
    }

    /// The canonical tip height, if the chain has been seeded.
    pub fn tip_height(&self) -> Result<Option<u64>, Error> {
        match self.store.best_fork()? {
            None => Ok(None),
            Some(f) => Ok(self.store.fork_tip(f)?.map(|(h, _)| h)),
        }
    }

    /// The current finalized (pruned) height.
    pub fn finalized_height(&self) -> Result<Option<u64>, Error> {
        self.store.finalized_height()
    }

    /// Height of a known block hash on the canonical chain, if it is canonical.
    pub fn height_of(&self, hash: &BlockHash) -> Result<Option<u64>, Error> {
        let Some((fork, height)) = self.store.locate(hash)? else {
            return Ok(None);
        };
        Ok(self.is_canonical_at(fork, height)?.then_some(height))
    }

    /// The header at `height` on the canonical chain, if stored.
    pub fn header_at(&self, height: u64) -> Result<Option<BitcoinHeader>, Error> {
        let Some(best) = self.store.best_fork()? else {
            return Ok(None);
        };
        self.canonical_header(best, height)
    }

    /// True if `hash` is the canonical block at `height`.
    pub fn is_canonical(&self, height: u64, hash: &BlockHash) -> Result<bool, Error> {
        Ok(self
            .header_at(height)?
            .is_some_and(|h| h.block_hash() == *hash))
    }

    /// Whether a stored `(fork, height)` block lies on the canonical chain.
    fn is_canonical_at(&self, fork: u64, height: u64) -> Result<bool, Error> {
        let Some(best) = self.store.best_fork()? else {
            return Ok(false);
        };
        if fork == best {
            return Ok(true);
        }
        // Walk the fork's ancestry: a block is canonical if it is at or below
        // the best chain's forkpoint and on the best chain's ancestors.
        let mut f = best;
        loop {
            let Some(meta) = self.store.fork_meta(f)? else {
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

    /// The header at `height` on chain `fork` (falling back to its ancestors
    /// below the forkpoint, and to the spine on the root chain).
    fn canonical_header(&self, fork: u64, height: u64) -> Result<Option<BitcoinHeader>, Error> {
        let mut f = fork;
        loop {
            let Some(meta) = self.store.fork_meta(f)? else {
                return Ok(None);
            };
            if height >= meta.forkpoint {
                return self.store.header_at(f, height);
            }
            let Some(parent) = meta.parent else {
                return Ok(None);
            };
            f = parent;
        }
    }

    /// Validate and store a contiguous ascending run of headers, attaching them
    /// to whichever chain they extend — Electrum's `can_connect` model.
    ///
    /// For each run:
    ///
    /// - The first header's parent must be a known block. If that block is a
    ///   chain tip, the run extends that chain; otherwise it starts a **new
    ///   fork** (kept, not rejected).
    /// - Every header is PoW- and continuity-checked.
    /// - The best chain is re-selected by cumulative work; a fork only wins
    ///   when it is strictly heavier.
    /// - A fork whose `forkpoint` is at or below the finalized floor is refused
    ///   ([`Error::ForkBelowFinalized`]) — the spine's finality floor.
    pub fn connect_headers(&self, headers: &[BitcoinHeader]) -> Result<ConnectOutcome, Error> {
        let prev_best = self.store.best_fork()?;
        if headers.is_empty() {
            let tip = match prev_best {
                Some(f) => {
                    self.store
                        .fork_tip(f)?
                        .unwrap_or((0, BlockHash::all_zeros()))
                        .0
                }
                None => 0,
            };
            return Ok(ConnectOutcome {
                connected: 0,
                prev_best_fork: prev_best,
                best_fork: prev_best,
                tip_height: tip,
            });
        }

        // Skip a leading prefix that is already stored anywhere (reconnects).
        let mut start = 0usize;
        while start < headers.len() && self.store.locate(&headers[start].block_hash())?.is_some() {
            start += 1;
        }
        if start == headers.len() {
            let tip = match prev_best {
                Some(f) => {
                    self.store
                        .fork_tip(f)?
                        .unwrap_or((0, BlockHash::all_zeros()))
                        .0
                }
                None => 0,
            };
            return Ok(ConnectOutcome {
                connected: 0,
                prev_best_fork: prev_best,
                best_fork: prev_best,
                tip_height: tip,
            });
        }

        // Parent of the first *new* header: must be a known block.
        let parent = if start == 0 {
            headers[0].prev_blockhash
        } else {
            headers[start - 1].block_hash()
        };
        let (parent_fork, parent_height) = self
            .store
            .locate(&parent)?
            .ok_or(Error::UnknownAncestor(parent))?;

        // Decide the target chain: extend the chain whose tip is the parent, or
        // start a new fork from the parent block.
        let parent_tip = self
            .store
            .fork_tip(parent_fork)?
            .unwrap_or((0, BlockHash::all_zeros()))
            .0;
        let (target_fork, forkpoint) = if parent_height == parent_tip {
            (parent_fork, parent_height + 1)
        } else {
            let forkpoint = parent_height + 1;
            if let Some(finalized) = self.store.finalized_height()?
                && forkpoint <= finalized
            {
                return Err(Error::ForkBelowFinalized {
                    fork: forkpoint,
                    finalized,
                });
            }
            let id = self
                .store
                .create_fork(parent_fork, forkpoint, headers[start].block_hash())?;
            (id, forkpoint)
        };

        // Validate continuity + PoW for the new run.
        let mut prev = parent;
        for (offset, header) in headers[start..].iter().enumerate() {
            let height = forkpoint + offset as u64;
            if header.prev_blockhash != prev {
                return Err(Error::LinkBreak {
                    height,
                    expected: prev,
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
        let base_work = self
            .store
            .work_at(parent_fork, parent_height)?
            .ok_or_else(|| {
                Error::Internal(format!("no work at ({parent_fork}, {parent_height})"))
            })?;
        let mut entries: Vec<(u64, &BitcoinHeader, Work)> =
            Vec::with_capacity(headers.len() - start);
        let mut cumulative = base_work;
        for (offset, header) in headers[start..].iter().enumerate() {
            cumulative = cumulative + header.target().to_work();
            entries.push((forkpoint + offset as u64, header, cumulative));
        }
        self.store.put_headers(target_fork, &entries)?;

        // Re-select the best chain by cumulative work (strictly heavier wins).
        let mut best = self.store.best_fork()?.unwrap_or(0);
        let mut best_work = self
            .store
            .fork_chainwork(best)?
            .unwrap_or(Work::from_be_bytes([0; 32]));
        let target_work = self
            .store
            .fork_chainwork(target_fork)?
            .unwrap_or(Work::from_be_bytes([0; 32]));
        if target_fork != best && target_work > best_work {
            self.store.set_best_fork(target_fork)?;
            best = target_fork;
            best_work = target_work;
        }
        let _ = best_work;

        let tip_height = match prev_best {
            Some(_) => {
                self.store
                    .fork_tip(best)?
                    .unwrap_or((0, BlockHash::all_zeros()))
                    .0
            }
            None => forkpoint + (headers.len() - start) as u64 - 1,
        };

        Ok(ConnectOutcome {
            connected: headers.len() - start,
            prev_best_fork: prev_best,
            best_fork: Some(best),
            tip_height,
        })
    }

    /// Connect a single header (Electrum's near-tip `save_header` path).
    pub fn connect_header(&self, header: &BitcoinHeader) -> Result<ConnectOutcome, Error> {
        self.connect_headers(std::slice::from_ref(header))
    }

    /// Advance the finalized checkpoint to the newest difficulty-period
    /// boundary that is at least a full period below the tip, and prune
    /// everything at or below it. Returns the new finalized height, if any.
    ///
    /// Only finalizes if the work built on top of the boundary (boundary to tip)
    /// is at least the work of the full period before it. This prevents
    /// finalizing across a difficulty drop — e.g. from X to 0.1X — that could
    /// otherwise be reorged if the higher-difficulty chain returns: the tail has
    /// to grow until it outweighs what it would be replacing.
    ///
    /// Cumulative work is known at every period boundary (the spine), so both
    /// sides are plain differences of stored cumulative work.
    ///
    /// Pruning assumes the root chain is canonical, so nothing is finalized
    /// while a fork is the best chain.
    pub fn finalize_period(&self) -> Result<Option<u64>, Error> {
        if self.store.best_fork()? != Some(0) {
            return Ok(None);
        }
        let Some(tip) = self.tip_height()? else {
            return Ok(None);
        };
        if tip < FINALITY_MARGIN_BLOCKS {
            return Ok(None);
        }
        let boundary = ((tip - FINALITY_MARGIN_BLOCKS) / DIFFICULTY_PERIOD) * DIFFICULTY_PERIOD;
        let current = self.store.finalized_height()?.unwrap_or(0);
        if boundary <= current {
            return Ok(None);
        }

        let work = |height: u64| -> Result<Work, Error> {
            self.store
                .work_at(0, height)?
                .ok_or_else(|| Error::Internal(format!("no cumulative work at height {height}")))
        };
        // One full period ending at the boundary, and everything built above it.
        let before = work(boundary)? - work(boundary - DIFFICULTY_PERIOD)?;
        let after = work(tip)? - work(boundary)?;
        if after < before {
            return Ok(None);
        }

        self.store.prune_below(boundary)?;
        Ok(Some(boundary))
    }
}

// ── proof-of-work helper ────────────────────────────────────────────────────

/// Compute the `Work` carried by a header (needed by callers that assemble
/// branches before handing them to [`Chain::connect_headers`]).
pub fn header_work(header: &BitcoinHeader) -> Work {
    header.target().to_work()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Version;
    use bitcoin::consensus::Decodable;
    use bitcoin::pow::CompactTarget;

    /// The easiest valid Bitcoin target (`0x207fffff`): nearly any hash passes,
    /// so we can synthesize long chains quickly without a real miner.
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

    /// Mine a header on top of `prev` whose hash meets the given target. `tag`
    /// makes the header unique (used as the timestamp) so two headers with the
    /// same parent never collide.
    fn mine_with_target(prev: BlockHash, bits: u32, tag: u32) -> BitcoinHeader {
        let target = CompactTarget::from_consensus(bits);
        let mut nonce = 0u32;
        loop {
            let h = BitcoinHeader {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::hashes::Hash::all_zeros(),
                time: 1_600_000_000 + tag,
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

    /// Mine `n` contiguous headers above `prev` with the given target bits.
    fn mine_chain_with_target(prev: BlockHash, n: usize, bits: u32) -> Vec<BitcoinHeader> {
        let mut out = Vec::with_capacity(n);
        let mut parent = prev;
        for i in 0..n {
            let h = mine_with_target(parent, bits, i as u32);
            parent = h.block_hash();
            out.push(h);
        }
        out
    }

    /// Mine a header on top of `prev` whose hash meets the easy target. The
    /// returned header is PoW-valid by construction; `tag` makes the header
    /// unique (used as the timestamp) so two headers with the same parent never
    /// collide.
    fn mine(prev: BlockHash, tag: u32) -> BitcoinHeader {
        mine_with_target(prev, EASY_BITS, tag)
    }

    /// Mine `n` contiguous headers above `prev` (chain order: parent first).
    /// `tag_offset` shifts the per-header timestamp so two runs above the same
    /// parent produce distinct chains.
    fn mine_chain_off(prev: BlockHash, n: usize, tag_offset: u32) -> Vec<BitcoinHeader> {
        let mut out = Vec::with_capacity(n);
        let mut parent = prev;
        for i in 0..n {
            let h = mine(parent, tag_offset + i as u32);
            parent = h.block_hash();
            out.push(h);
        }
        out
    }

    fn mine_chain(prev: BlockHash, n: usize) -> Vec<BitcoinHeader> {
        mine_chain_off(prev, n, 1)
    }

    /// A fresh in-memory chain seeded with a synthetic checkpoint at height 0.
    fn seeded() -> Chain {
        let chain = Chain::in_memory().expect("in-memory store");
        let genesis = mine(BlockHash::all_zeros(), 0);
        chain.seed_checkpoints(&[(0, genesis)]).expect("seed");
        chain
    }

    /// The hash of the block at `height` on the canonical chain.
    fn canonical_hash(chain: &Chain, height: u64) -> BlockHash {
        chain
            .header_at(height)
            .unwrap()
            .unwrap_or_else(|| panic!("no canonical header at {height}"))
            .block_hash()
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

        let run = mine_chain(canonical_hash(&chain, 0), 5);
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
    fn rejects_bad_pow() -> eyre::Result<()> {
        let chain = seeded();
        let mut bad = mine_chain(canonical_hash(&chain, 0), 1);
        bad[0].bits = CompactTarget::from_consensus(0x1d00_ffff);
        let err = chain.connect_headers(&bad).unwrap_err();
        assert!(matches!(err, Error::BadPow { .. }), "got {err:?}");
        Ok(())
    }

    #[test]
    fn rejects_unknown_ancestor() -> eyre::Result<()> {
        let chain = seeded();
        let run = mine_chain(BlockHash::all_zeros(), 1); // links to nothing stored
        let err = chain.connect_headers(&run).unwrap_err();
        assert!(matches!(err, Error::UnknownAncestor(_)), "got {err:?}");
        Ok(())
    }

    #[test]
    fn single_header_connects() -> eyre::Result<()> {
        let chain = seeded();
        let h = mine(canonical_hash(&chain, 0), 1);
        let out = chain.connect_header(&h)?;
        assert_eq!(out.connected, 1);
        assert_eq!(out.tip_height, 1);
        assert!(chain.is_canonical(1, &h.block_hash())?);
        Ok(())
    }

    #[test]
    fn lighter_fork_is_kept_not_rejected() -> eyre::Result<()> {
        let chain = seeded();
        let main = mine_chain(canonical_hash(&chain, 0), 5);
        chain.connect_headers(&main)?;
        assert_eq!(chain.tip_height()?, Some(5));

        // A lighter fork from height 3 (parent = main[2]) with 2 blocks. Its
        // tip (height 5) ties, but with strictly less work it must not become
        // best — and crucially it must be *stored*, not rejected.
        let fork_base = main[2].block_hash();
        let fork = mine_chain_off(fork_base, 2, 1000);
        let out = chain.connect_headers(&fork)?;
        assert_eq!(out.connected, 2);
        assert_eq!(out.best_fork, Some(0), "best chain must stay the root");

        // The fork survives in the tree and its headers are locatable.
        assert_eq!(chain.store.fork_count()?, 2);
        let (f, h) = chain.store.locate(&fork[0].block_hash())?.unwrap();
        assert_eq!(h, 4);
        assert_ne!(f, 0);
        // The fork's blocks are not canonical.
        assert!(!chain.is_canonical(4, &fork[0].block_hash())?);
        Ok(())
    }

    #[test]
    fn heavier_fork_wins() -> eyre::Result<()> {
        let chain = seeded();
        let main = mine_chain(canonical_hash(&chain, 0), 5);
        chain.connect_headers(&main)?;

        // Fork from height 3 with 5 blocks → tip 8, strictly more work.
        let fork_base = main[2].block_hash();
        let fork = mine_chain_off(fork_base, 5, 1000);
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
        let main = mine_chain(canonical_hash(&chain, 0), 6);
        chain.connect_headers(&main)?;

        // Advance the floor to height 1 (via store pruning path).
        chain.store.prune_below(1)?;
        assert_eq!(chain.finalized_height()?, Some(1));

        // A fork starting at height 1 (forkpoint 1 <= finalized 1) is refused.
        let fork = mine_chain_off(canonical_hash(&chain, 0), 3, 1000);
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
        let main = mine_chain(canonical_hash(&chain, 0), 5);
        chain.connect_headers(&main)?;
        assert_eq!(chain.best_fork()?, Some(0));

        // First arrives a short, lighter slice of a fork from height 3.
        let fork_base = main[2].block_hash();
        let fork_part1 = mine_chain_off(fork_base, 1, 1000);
        let out = chain.connect_headers(&fork_part1)?;
        assert_eq!(out.connected, 1);
        assert_eq!(chain.best_fork()?, Some(0), "still root while lighter");

        // Later, more headers of the same fork arrive, tipping it heavier.
        let fork_part2 = mine_chain_off(fork_part1[0].block_hash(), 4, 1001);
        let out = chain.connect_headers(&fork_part2)?;
        assert_eq!(out.connected, 4);
        assert_eq!(out.tip_height, 8);
        let best = chain.best_fork()?.unwrap();
        assert_ne!(best, 0, "fork wins once it becomes heavier");
        // The two batches landed on the same fork.
        let (f1, _) = chain.store.locate(&fork_part1[0].block_hash())?.unwrap();
        let (f2, _) = chain.store.locate(&fork_part2[3].block_hash())?.unwrap();
        assert_eq!(f1, f2);
        assert!(chain.is_canonical(8, &fork_part2[3].block_hash())?);
        Ok(())
    }

    #[test]
    fn finalizes_period_and_prunes() -> eyre::Result<()> {
        let chain = seeded();
        // Build past two full difficulty periods (4032) plus a bit, so
        // boundary 2016 is a full period below the tip and becomes final.
        let run = mine_chain(
            canonical_hash(&chain, 0),
            2 * DIFFICULTY_PERIOD as usize + 100,
        );
        chain.connect_headers(&run)?;
        assert_eq!(chain.tip_height()?, Some(2 * DIFFICULTY_PERIOD + 100));

        let finalized = chain.finalize_period()?;
        assert_eq!(finalized, Some(DIFFICULTY_PERIOD));
        assert_eq!(chain.finalized_height()?, Some(DIFFICULTY_PERIOD));

        // Non-checkpoint headers below the boundary are pruned; the boundary
        // checkpoint itself and the tip remain.
        assert!(chain.header_at(1)?.is_none());
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
    fn checkpoint_spine_survives_pruning() -> eyre::Result<()> {
        let chain = seeded();
        let run = mine_chain(
            canonical_hash(&chain, 0),
            2 * DIFFICULTY_PERIOD as usize + 100,
        );
        chain.connect_headers(&run)?;
        chain.finalize_period()?;

        // The checkpoint spine still resolves: height 0 (the seeded genesis)
        // survives, its hash maps to its height, and its work is intact.
        assert!(chain.header_at(0)?.is_some());
        let genesis_hash = canonical_hash(&chain, 0);
        assert_eq!(chain.height_of(&genesis_hash)?, Some(0));
        assert!(chain.store.work_at(0, 0)?.is_some());

        Ok(())
    }

    #[test]
    fn spine_work_scales_by_full_periods() -> eyre::Result<()> {
        // Two spine checkpoints, each an easy-target header with per-block work
        // `w`. The spine must report cumulative work as if every one of the
        // 2016 blocks in the intervening period were stored:
        //   work_at(0)     = w                    (just the boundary block)
        //   work_at(2016)  = w + 2015*w + w = 2017*w
        let chain = Chain::in_memory().unwrap();
        let g0 = mine(BlockHash::all_zeros(), 0);
        let g2016 = mine(BlockHash::all_zeros(), 1);
        let w = header_work(&g0);
        chain
            .seed_checkpoints(&[(0, g0), (DIFFICULTY_PERIOD, g2016)])
            .unwrap();

        assert_eq!(chain.store.work_at(0, 0).unwrap(), Some(w));
        let expected = {
            let mut acc = w; // block 0
            for _ in 1..DIFFICULTY_PERIOD {
                acc = acc + w; // the rest of period 0
            }
            acc + header_work(&g2016) // this boundary block
        };
        assert_eq!(
            chain.store.work_at(0, DIFFICULTY_PERIOD).unwrap(),
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
        let chain = Chain::in_memory().unwrap();
        chain.seed_checkpoints(&[(0, genesis)]).unwrap();
        assert_eq!(
            chain.header_at(0)?.unwrap().block_hash(),
            genesis.block_hash()
        );
        // And we can extend on top of the real genesis hash with synthetic
        // headers (continuity is what matters here, not difficulty).
        let run = mine_chain(genesis.block_hash(), 2);
        let out = chain.connect_headers(&run)?;
        assert_eq!(out.connected, 2);
        assert_eq!(out.tip_height, 2);
        Ok(())
    }

    #[test]
    fn finalizes_period_only_when_tail_work_exceeds_pre_check() -> eyre::Result<()> {
        // At constant difficulty, the work from the boundary to the tip (a full
        // period plus the extra blocks) exceeds the work of the period before
        // the boundary, so finalization proceeds.
        let chain = seeded();
        let checkpoint = DIFFICULTY_PERIOD as usize;

        // Build a chain to the checkpoint height.
        let run1 = mine_chain(canonical_hash(&chain, 0), checkpoint);
        chain.connect_headers(&run1)?;
        assert_eq!(chain.tip_height()?, Some(checkpoint as u64));

        // Now extend past the checkpoint with blocks at the same difficulty.
        let run2 = mine_chain(
            canonical_hash(&chain, checkpoint as u64),
            checkpoint + 100, // one full period + 100 more
        );
        chain.connect_headers(&run2)?;
        assert_eq!(chain.tip_height()?, Some((2 * checkpoint + 100) as u64));

        // Finalization should succeed because the tail has accumulated a full
        // period of work after the checkpoint.
        let finalized = chain.finalize_period()?;
        assert_eq!(finalized, Some(DIFFICULTY_PERIOD));
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
        let w20 = header_work(&mine_with_target(BlockHash::all_zeros(), WORK20_BITS, 0));
        let w22 = header_work(&mine_with_target(BlockHash::all_zeros(), WORK22_BITS, 0));
        let times = |w: Work, n: u32| (0..n).fold(Work::from_be_bytes([0; 32]), |acc, _| acc + w);
        assert_eq!(times(w20, 11), times(w22, 10));

        // The period before the checkpoint: 2016 blocks at work 22.
        let run1 = mine_chain_with_target(canonical_hash(&chain, 0), period, WORK22_BITS);
        chain.connect_headers(&run1)?;
        assert_eq!(chain.tip_height()?, Some(period as u64));

        // Smallest tail at work 20 that reaches 2016 * 22: ceil(44352 / 20).
        let tail_needed = (period * 22).div_ceil(20);
        let tail = mine_chain_with_target(
            canonical_hash(&chain, period as u64),
            tail_needed,
            WORK20_BITS,
        );

        // One block short of enough: refused.
        chain.connect_headers(&tail[..tail_needed - 1])?;
        assert_eq!(chain.tip_height()?, Some((period + tail_needed - 1) as u64));
        assert_eq!(
            chain.finalize_period()?,
            None,
            "must not finalize while the tail is lighter than the period before it"
        );
        assert_eq!(chain.finalized_height()?, Some(0));

        // The last block tips the tail over: now it finalizes.
        chain.connect_headers(&tail[tail_needed - 1..])?;
        assert_eq!(chain.finalize_period()?, Some(DIFFICULTY_PERIOD));
        assert_eq!(chain.finalized_height()?, Some(DIFFICULTY_PERIOD));
        Ok(())
    }
}
