//! Persistent Bitcoin + Rootstock chain state, backed by redb.
//!
//! This is the *state* of the side-effect-free core. The Bitcoin side is a
//! **tree of chains** (forks), each with a `forkpoint` and a `parent`, plus a
//! trusted **checkpoint spine** (one header per difficulty period) that makes
//! the whole chain's work computable without holding every block. The Rootstock
//! side is a **forest** of trees, each rooted at a trusted `F`. Header
//! validation lives in [`crate::validation`] and [`crate::btc`]. Tests construct
//! the store with the redb **in-memory** backend, so the exact same code path
//! runs with zero disk I/O.
//!
//! The store is only ever touched through a transaction: [`Store::read`] opens
//! a consistent snapshot ([`ReadTxn`]) and [`Store::write`] opens the single
//! writer ([`WriteTxn`]). A read-modify-write (in particular, connecting
//! headers) therefore runs entirely inside one [`WriteTxn`]: redb serialises
//! writers, so nothing can change between the reads a decision is based on and
//! the writes that act on it.
//!
//! Table values are the record types in [`records`], so a table reads as
//! `TableDefinition<Key, Record>` rather than `TableDefinition<_, &[u8]>`.

use std::path::Path;

use bitcoin::Network;
use bitcoin::block::BlockHash;
use bitcoin::block::Header as BitcoinHeader;
use bitcoin::hashes::Hash;
use bitcoin::pow::Work;
use redb::{Database, ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};

pub mod records;

use crate::error::Error;
use records::{BlobList, BtcHeader, BtcRow, ForkMeta, HashList, Meta, RskBlock};

/// Bitcoin difficulty period, in blocks. Difficulty retargets only at period
/// boundaries, so every block in a period carries the same work.
pub const DIFFICULTY_PERIOD: u64 = 2016;

// ── Bitcoin tables ──────────────────────────────────────────────────────────

/// Headers + cumulative work keyed by `(fork_id, height)`.
const BTC_HEADERS: TableDefinition<(u64, u64), BtcRow> = TableDefinition::new("btc_headers");
/// `hash → (fork_id, height)`.
const BTC_HASH_LOC: TableDefinition<&[u8], (u64, u64)> = TableDefinition::new("btc_hash_loc");
/// Fork metadata: `fork_id → ForkMeta`.
const BTC_FORKS: TableDefinition<u64, ForkMeta> = TableDefinition::new("btc_forks");
/// The checkpoint spine: one trusted header per difficulty period, never
/// pruned — the cheap whole-chain work ladder.
const BTC_CHECKPOINTS: TableDefinition<u64, BtcHeader> = TableDefinition::new("btc_checkpoints");
const BTC_META: TableDefinition<&str, Meta> = TableDefinition::new("btc_meta");

// ── Rootstock tables (one tree per trusted root `F`) ────────────────────────

/// RSK headers, keyed by block hash: raw RLP bytes.
pub(crate) const RSK_HEADERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rsk_headers");
/// `hash → RskBlock`.
pub(crate) const RSK_BLOCKS: TableDefinition<&[u8], RskBlock> = TableDefinition::new("rsk_blocks");
/// `hash → child hashes` (the GHOST subtree edges).
pub(crate) const RSK_CHILDREN: TableDefinition<&[u8], HashList> =
    TableDefinition::new("rsk_children");
/// `hash → raw uncle headers` (for the uncle rule's ancestry).
pub(crate) const RSK_UNCLES: TableDefinition<&[u8], BlobList> = TableDefinition::new("rsk_uncles");
/// Trusted root anchors (`F`): a set of block hashes.
pub(crate) const RSK_ROOTS: TableDefinition<&[u8], ()> = TableDefinition::new("rsk_roots");
pub(crate) const RSK_META: TableDefinition<&str, Meta> = TableDefinition::new("rsk_meta");

const META_SEED_HEIGHT: &str = "seed_height";
/// The latest finalized checkpoint: a difficulty-period boundary whose
/// above-work outweighs the period before it. Advanced only forward.
const META_FINALIZED: &str = "finalized_height";
const META_BEST_FORK: &str = "best_fork";
const META_NEXT_FORK: &str = "next_fork";
const META_NETWORK: &str = "network";

/// redb-backed chain state, threaded by [`crate::Core`]. It is only reachable
/// through [`Store::read`] and [`Store::write`]: there are no per-call read or
/// write shortcuts, so every operation declares up front whether it takes a
/// read snapshot or the writer.
pub(crate) struct Store {
    db: Database,
}

impl Store {
    /// Open (creating if needed) a file-backed store at `path`.
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        let db = Database::create(path)?;
        Self::new(db)
    }

    /// Create a store over the redb in-memory backend. No disk I/O: this is
    /// what tests use, and what "I control everything going on" means.
    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Self, Error> {
        let db = Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::new(db)
    }

    fn new(db: Database) -> Result<Self, Error> {
        let txn = db.begin_write()?;
        txn.open_table(BTC_HEADERS)?;
        txn.open_table(BTC_HASH_LOC)?;
        txn.open_table(BTC_FORKS)?;
        txn.open_table(BTC_CHECKPOINTS)?;
        txn.open_table(BTC_META)?;
        txn.open_table(RSK_HEADERS)?;
        txn.open_table(RSK_BLOCKS)?;
        txn.open_table(RSK_CHILDREN)?;
        txn.open_table(RSK_UNCLES)?;
        txn.open_table(RSK_ROOTS)?;
        txn.open_table(RSK_META)?;
        txn.commit()?;
        Ok(Self { db })
    }

    /// Begin a consistent read snapshot. Every read through it sees one
    /// committed state, and any number of readers may run concurrently.
    pub(crate) fn read(&self) -> Result<ReadTxn, Error> {
        Ok(ReadTxn {
            txn: self.db.begin_read()?,
        })
    }

    /// Begin a single read-write transaction. While it is open no other writer
    /// can run, and every read through it sees one consistent snapshot — so a
    /// read → decide → write sequence cannot be interleaved. Call
    /// [`WriteTxn::commit`] to persist; dropping without committing aborts.
    pub(crate) fn write(&self) -> Result<WriteTxn, Error> {
        Ok(WriteTxn {
            txn: self.db.begin_write()?,
        })
    }
}

/// Read methods shared by [`ReadTxn`] and [`WriteTxn`], which each wrap a redb
/// transaction with an `open_table`. Generating both from one macro keeps the
/// read surface identical: a [`WriteTxn`] can read exactly what a [`ReadTxn`]
/// can, which is what makes an atomic read-modify-write possible.
macro_rules! read_methods {
    () => {
        pub(crate) fn fork_meta(&self, fork_id: u64) -> Result<Option<ForkMeta>, Error> {
            let table = self.txn.open_table(BTC_FORKS)?;
            Ok(table.get(fork_id)?.map(|v| v.value()))
        }

        /// The current best (heaviest) chain id.
        pub(crate) fn best_fork(&self) -> Result<Option<u64>, Error> {
            self.meta_u64(META_BEST_FORK)
        }

        /// The tip of a fork: `(height, hash)`.
        pub(crate) fn fork_tip(&self, fork_id: u64) -> Result<Option<(u64, BlockHash)>, Error> {
            Ok(self.fork_meta(fork_id)?.map(|m| (m.tip_height, m.tip_hash)))
        }

        /// Where `hash` lives, if stored: `(fork_id, height)`.
        pub(crate) fn locate(&self, hash: &BlockHash) -> Result<Option<(u64, u64)>, Error> {
            let table = self.txn.open_table(BTC_HASH_LOC)?;
            Ok(table
                .get(hash.as_byte_array().as_slice())?
                .map(|v| v.value()))
        }

        /// The header at `height` on `fork_id`'s chain: the fork's own row, or an
        /// ancestor's below its forkpoint.
        pub(crate) fn header_at(
            &self,
            fork_id: u64,
            height: u64,
        ) -> Result<Option<BitcoinHeader>, Error> {
            let Some(owner) = self.owner_fork(fork_id, height)? else {
                return Ok(None);
            };
            let table = self.txn.open_table(BTC_HEADERS)?;
            Ok(table.get((owner, height))?.map(|v| v.value().header))
        }

        /// The cumulative work at `height` on `fork_id`'s chain. Resolves the
        /// owning fork exactly as [`header_at`](Self::header_at) does.
        pub(crate) fn work_at(&self, fork_id: u64, height: u64) -> Result<Option<Work>, Error> {
            let Some(owner) = self.owner_fork(fork_id, height)? else {
                return Ok(None);
            };
            let table = self.txn.open_table(BTC_HEADERS)?;
            Ok(table.get((owner, height))?.map(|v| v.value().work))
        }

        /// The fork on `fork_id`'s ancestor chain that owns `height`: the first
        /// fork whose forkpoint is at or below it. `None` when even the root
        /// chain starts above `height`.
        fn owner_fork(&self, fork_id: u64, height: u64) -> Result<Option<u64>, Error> {
            let mut f = fork_id;
            loop {
                let Some(meta) = self.fork_meta(f)? else {
                    return Ok(None);
                };
                if height >= meta.forkpoint {
                    return Ok(Some(f));
                }
                let Some(parent) = meta.parent else {
                    return Ok(None);
                };
                f = parent;
            }
        }

        /// Cumulative work of a fork at its tip — the number chain selection
        /// compares across forks (Electrum's `get_chainwork`).
        pub(crate) fn fork_chainwork(&self, fork_id: u64) -> Result<Option<Work>, Error> {
            match self.fork_meta(fork_id)? {
                None => Ok(None),
                Some(m) => self.work_at(fork_id, m.tip_height),
            }
        }

        /// The latest finalized checkpoint, if seeded. Monotonic: only the
        /// connect path advances it, and only forward.
        pub(crate) fn finalized_height(&self) -> Result<Option<u64>, Error> {
            self.meta_u64(META_FINALIZED)
        }

        fn meta_u64(&self, key: &str) -> Result<Option<u64>, Error> {
            let table = self.txn.open_table(BTC_META)?;
            Ok(table.get(key)?.and_then(|v| v.value().as_u64()))
        }
    };
}

/// A read-only snapshot: a consistent view of committed state for the life of
/// the transaction.
pub(crate) struct ReadTxn {
    pub(crate) txn: ReadTransaction,
}

impl ReadTxn {
    read_methods!();

    /// Number of live forks (test-only).
    #[cfg(test)]
    pub(crate) fn fork_count(&self) -> Result<u64, Error> {
        let table = self.txn.open_table(BTC_FORKS)?;
        Ok(table.iter()?.count() as u64)
    }

    /// The network the chain was seeded for, if any (test-only).
    #[cfg(test)]
    pub(crate) fn network(&self) -> Result<Option<Network>, Error> {
        let table = self.txn.open_table(BTC_META)?;
        Ok(table
            .get(META_NETWORK)?
            .and_then(|v| v.value().as_text().and_then(|t| t.parse().ok())))
    }
}

/// A single read-write transaction: a consistent snapshot plus the exclusive
/// right to write. It carries the same read surface as [`ReadTxn`], so a
/// sequence of reads feeding a decision and the writes acting on it are atomic
/// with respect to any other writer.
pub(crate) struct WriteTxn {
    pub(crate) txn: WriteTransaction,
}

impl WriteTxn {
    read_methods!();

    /// The network the chain was seeded for, if any. Recorded at seed time so
    /// a resume with the wrong network is refused rather than silently
    /// validated against the wrong consensus parameters.
    pub(crate) fn network(&self) -> Result<Option<Network>, Error> {
        let table = self.txn.open_table(BTC_META)?;
        Ok(table
            .get(META_NETWORK)?
            .and_then(|v| v.value().as_text().and_then(|t| t.parse().ok())))
    }

    /// Plant the trust anchor: one header per difficulty period (the
    /// checkpoint spine from this crate's embedded `checkpoints.txt`), taken on faith
    /// without validating ancestors, and create the root chain on top of it.
    ///
    /// This is a one-time operation: it is refused ([`Error::AlreadySeeded`])
    /// if the store already carries a chain, so it can never clobber a taller
    /// tip or a more advanced finality floor. Resume by connecting the headers
    /// above the existing tip.
    ///
    /// Because difficulty is constant within a period, each checkpoint header
    /// pins the work of its whole 2016-block period, so cumulative work is
    /// known at every boundary without holding every block. The entries must be
    /// one period apart (contiguous, ascending), starting at a period boundary.
    pub(crate) fn seed_checkpoints(&self, entries: &[(u64, BitcoinHeader)]) -> Result<(), Error> {
        if self.fork_meta(0)?.is_some() {
            return Err(Error::AlreadySeeded);
        }
        if entries.is_empty() {
            return Err(Error::Internal("no checkpoints to seed".into()));
        }
        let mut sorted = entries.to_vec();
        sorted.sort_by_key(|(h, _)| *h);
        for w in sorted.windows(2) {
            if w[1].0 != w[0].0 + DIFFICULTY_PERIOD {
                return Err(Error::Internal(format!(
                    "checkpoints must be contiguous difficulty periods: {} then {}",
                    w[0].0, w[1].0
                )));
            }
        }

        let mut headers = self.txn.open_table(BTC_HEADERS)?;
        let mut hash_loc = self.txn.open_table(BTC_HASH_LOC)?;
        let mut forks = self.txn.open_table(BTC_FORKS)?;
        let mut checkpoints = self.txn.open_table(BTC_CHECKPOINTS)?;
        let mut meta = self.txn.open_table(BTC_META)?;
        let mut cum = Work::from_be_bytes([0; 32]);
        let mut prev_w = Work::from_be_bytes([0; 32]);
        for (i, (height, header)) in sorted.iter().enumerate() {
            let w = header.target().to_work();
            cum = if i == 0 {
                w // just the boundary block itself
            } else {
                // Period (i-1) had `DIFFICULTY_PERIOD` blocks at `prev_w`;
                // the boundary block `prev_w` was already counted, so add
                // the remaining `DIFFICULTY_PERIOD - 1` plus this block.
                cum + work_scaled(prev_w, DIFFICULTY_PERIOD - 1) + w
            };
            prev_w = w;
            checkpoints.insert(*height, BtcHeader(*header))?;
            hash_loc.insert(header.block_hash().as_byte_array().as_slice(), (0, *height))?;
            // The spine doubles as the root chain's headers at these
            // heights, with cumulative work.
            headers.insert(
                (0, *height),
                BtcRow {
                    header: *header,
                    work: cum,
                },
            )?;
        }
        let first = sorted.first().expect("checked non-empty above").0;
        let last = sorted.last().expect("checked non-empty above").0;
        let last_hash = sorted
            .last()
            .expect("checked non-empty above")
            .1
            .block_hash();
        let root = ForkMeta {
            forkpoint: 0,
            parent: None,
            forkpoint_hash: sorted[0].1.block_hash(),
            tip_height: last,
            tip_hash: last_hash,
            tip_work: cum,
        };
        forks.insert(0, root)?;
        meta.insert(META_SEED_HEIGHT, Meta::U64(first))?;
        meta.insert(META_FINALIZED, Meta::U64(last))?;
        meta.insert(META_BEST_FORK, Meta::U64(0))?;
        meta.insert(META_NEXT_FORK, Meta::U64(1))?;
        Ok(())
    }

    /// Create a new fork diverging from `parent` at `forkpoint`; the block at
    /// `forkpoint` is `forkpoint_hash`. Returns the new fork id.
    ///
    /// The new fork's tip starts empty (`tip_height = forkpoint - 1`, pointing
    /// at its parent block) and is overwritten by the first `put_headers`.
    pub(crate) fn create_fork(
        &self,
        parent: u64,
        forkpoint: u64,
        forkpoint_hash: BlockHash,
    ) -> Result<u64, Error> {
        let id = {
            let mut meta = self.txn.open_table(BTC_META)?;
            let next = meta
                .get(META_NEXT_FORK)?
                .and_then(|v| v.value().as_u64())
                .unwrap_or(1);
            meta.insert(META_NEXT_FORK, Meta::U64(next + 1))?;
            next
        };
        let meta = ForkMeta {
            forkpoint,
            parent: Some(parent),
            forkpoint_hash,
            tip_height: forkpoint.saturating_sub(1),
            tip_hash: BlockHash::all_zeros(),
            tip_work: Work::from_be_bytes([0; 32]),
        };
        {
            let mut forks = self.txn.open_table(BTC_FORKS)?;
            forks.insert(id, meta)?;
        }
        Ok(id)
    }

    /// Append a contiguous run of headers to a fork in this transaction. Each
    /// entry carries its cumulative work (through that header, on this fork).
    /// Period-boundary heights on the root chain also extend the checkpoint
    /// spine.
    pub(crate) fn put_headers(
        &self,
        fork_id: u64,
        entries: &[(u64, &BitcoinHeader, Work)],
    ) -> Result<(), Error> {
        if entries.is_empty() {
            return Ok(());
        }
        {
            let mut headers = self.txn.open_table(BTC_HEADERS)?;
            let mut hash_loc = self.txn.open_table(BTC_HASH_LOC)?;
            let mut checkpoints = self.txn.open_table(BTC_CHECKPOINTS)?;
            let mut forks = self.txn.open_table(BTC_FORKS)?;
            for &(height, header, cum) in entries {
                headers.insert(
                    (fork_id, height),
                    BtcRow {
                        header: *header,
                        work: cum,
                    },
                )?;
                hash_loc.insert(
                    header.block_hash().as_byte_array().as_slice(),
                    (fork_id, height),
                )?;
                // Extend the spine when the root chain crosses a period
                // boundary (the spine stays a full-chain work ladder).
                if fork_id == 0 && height % DIFFICULTY_PERIOD == 0 {
                    checkpoints.insert(height, BtcHeader(*header))?;
                }
            }
            let last = entries.last().expect("checked non-empty above");
            let last_hash = last.1.block_hash();
            let mut meta = forks.get(fork_id)?.map(|v| v.value());
            if let Some(m) = meta.as_mut() {
                m.tip_height = last.0;
                m.tip_hash = last_hash;
                m.tip_work = last.2;
            }
            let meta = meta.expect("fork meta must exist before appending headers");
            forks.insert(fork_id, meta)?;
        }
        Ok(())
    }

    /// Mark `fork_id` as the best (heaviest) chain.
    pub(crate) fn set_best_fork(&self, fork_id: u64) -> Result<(), Error> {
        let mut meta = self.txn.open_table(BTC_META)?;
        meta.insert(META_BEST_FORK, Meta::U64(fork_id))?;
        Ok(())
    }

    /// Record the network this chain is seeded for (read back by the network
    /// check at the top of [`crate::Core::connect_headers`]).
    pub(crate) fn set_network(&self, network: Network) -> Result<(), Error> {
        let mut meta = self.txn.open_table(BTC_META)?;
        meta.insert(META_NETWORK, Meta::Text(network.to_string()))?;
        Ok(())
    }

    /// Record the latest finalized checkpoint.
    pub(crate) fn set_finalized(&self, height: u64) -> Result<(), Error> {
        let mut meta = self.txn.open_table(BTC_META)?;
        meta.insert(META_FINALIZED, Meta::U64(height))?;
        Ok(())
    }

    /// Persist every change made through this transaction.
    pub(crate) fn commit(self) -> Result<(), Error> {
        self.txn.commit()?;
        Ok(())
    }
}

// ── Rootstock table access ──────────────────────────────────────────────────

/// Reads over the RSK tables, shared by [`ReadTxn`] and [`WriteTxn`] so a
/// connect can validate against what it has already staged.
macro_rules! rsk_read_methods {
    () => {
        /// Raw wire header bytes for `hash`.
        pub(crate) fn rsk_raw_header(&self, hash: &[u8]) -> Result<Option<Vec<u8>>, Error> {
            let table = self.txn.open_table(RSK_HEADERS)?;
            Ok(table.get(hash)?.map(|v| v.value().to_vec()))
        }

        /// The stored block index for `hash`.
        pub(crate) fn rsk_block(&self, hash: &[u8]) -> Result<Option<RskBlock>, Error> {
            let table = self.txn.open_table(RSK_BLOCKS)?;
            Ok(table.get(hash)?.map(|v| v.value()))
        }

        pub(crate) fn rsk_has_block(&self, hash: &[u8]) -> Result<bool, Error> {
            Ok(self.rsk_block(hash)?.is_some())
        }

        /// Child hashes of `hash` (the GHOST subtree edges).
        pub(crate) fn rsk_children(&self, hash: &[u8]) -> Result<Vec<[u8; 32]>, Error> {
            let table = self.txn.open_table(RSK_CHILDREN)?;
            Ok(table.get(hash)?.map(|v| v.value().0).unwrap_or_default())
        }

        /// Raw uncle headers of `hash`.
        pub(crate) fn rsk_uncle_raw(&self, hash: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
            let table = self.txn.open_table(RSK_UNCLES)?;
            Ok(table.get(hash)?.map(|v| v.value().0).unwrap_or_default())
        }

        /// The trusted root (`F`) hashes.
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
        block: RskBlock,
    ) -> Result<(), Error> {
        {
            let mut table = self.txn.open_table(RSK_HEADERS)?;
            table.insert(hash, raw)?;
        }
        {
            let mut table = self.txn.open_table(RSK_BLOCKS)?;
            table.insert(hash, block)?;
        }
        Ok(())
    }

    pub(crate) fn rsk_put_uncles(&self, hash: &[u8], raws: &[Vec<u8>]) -> Result<(), Error> {
        let mut table = self.txn.open_table(RSK_UNCLES)?;
        table.insert(hash, BlobList(raws.to_vec()))?;
        Ok(())
    }

    pub(crate) fn rsk_add_child(&self, parent: &[u8], child: &[u8]) -> Result<(), Error> {
        let mut table = self.txn.open_table(RSK_CHILDREN)?;
        let mut children = table.get(parent)?.map(|v| v.value()).unwrap_or_default();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(child);
        children.0.push(hash);
        table.insert(parent, children)?;
        Ok(())
    }

    pub(crate) fn rsk_put_root(&self, hash: &[u8]) -> Result<(), Error> {
        let mut table = self.txn.open_table(RSK_ROOTS)?;
        table.insert(hash, ())?;
        Ok(())
    }
}

/// `work` added to itself `n` times. (`Work` has no `Mul`, and the per-period
/// scaling only ever happens at seed time, so a loop is fine.)
fn work_scaled(work: Work, n: u64) -> Work {
    let mut acc = Work::from_be_bytes([0; 32]);
    for _ in 0..n {
        acc = acc + work;
    }
    acc
}
