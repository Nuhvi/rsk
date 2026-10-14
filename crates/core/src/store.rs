//! Persistent Bitcoin chain state, backed by redb.
//!
//! This is the *state* of the side-effect-free core, modelled on Electrum's
//! `BlockchainManager`: a **tree of chains** (forks), each with a `forkpoint`
//! and a `parent`, plus a trusted **checkpoint spine** (one header per
//! difficulty period) that makes the whole chain's work computable without
//! holding every block. Header validation lives in [`crate::validation`] and
//! [`crate::chain`]. Tests construct the store with the redb **in-memory**
//! backend, so the exact same code path runs with zero disk I/O.
//!
//! The store is only ever touched through a transaction: [`Store::read`] opens
//! a consistent snapshot ([`ReadTxn`]) and [`Store::write`] opens the single
//! writer ([`WriteTxn`]). A read-modify-write (in particular, connecting
//! headers) therefore runs entirely inside one [`WriteTxn`]: redb serialises
//! writers, so nothing can change between the reads a decision is based on and
//! the writes that act on it.

use std::path::Path;

use bitcoin::Network;
use bitcoin::block::BlockHash;
use bitcoin::block::Header as BitcoinHeader;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::pow::Work;
use redb::{Database, ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};

use crate::error::Error;

/// Bitcoin difficulty period, in blocks. Difficulty retargets only at period
/// boundaries, so every block in a period carries the same work.
pub const DIFFICULTY_PERIOD: u64 = 2016;

/// Sentinel `parent` for the root chain (fork id 0).
const NO_PARENT: u64 = u64::MAX;

/// Headers+work keyed by `(fork_id, height)`: value is 80-byte header followed
/// by the 32-byte cumulative work at that height.
const BTC_HEADERS: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("btc_headers");
/// `hash → (fork_id, height)`.
const BTC_HASH_LOC: TableDefinition<&[u8], (u64, u64)> = TableDefinition::new("btc_hash_loc");
/// Fork metadata: `fork_id → ForkMeta` (see `ForkMeta::encode`).
const BTC_FORKS: TableDefinition<u64, &[u8]> = TableDefinition::new("btc_forks");
/// The checkpoint spine: one trusted header per difficulty period, never
/// pruned — the cheap whole-chain work ladder.
const BTC_CHECKPOINTS: TableDefinition<u64, &[u8]> = TableDefinition::new("btc_checkpoints");
const BTC_META: TableDefinition<&str, &[u8]> = TableDefinition::new("btc_meta");

const META_SEED_HEIGHT: &str = "seed_height";
/// The latest finalized checkpoint: a difficulty-period boundary whose
/// above-work outweighs the period before it. Advanced only forward.
const META_FINALIZED: &str = "finalized_height";
const META_BEST_FORK: &str = "best_fork";
const META_NEXT_FORK: &str = "next_fork";
const META_NETWORK: &str = "network";

/// Metadata for one chain (fork) in the tree. The root chain (id 0) has
/// `forkpoint == 0`, `parent == None`, and is the initial best chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForkMeta {
    /// Height of this fork's first header.
    pub forkpoint: u64,
    /// The chain this one diverged from; `None` for the root chain.
    pub parent: Option<u64>,
    /// Hash of the block at `forkpoint` (this fork's identity).
    pub forkpoint_hash: BlockHash,
    /// Highest connected height on this fork.
    pub tip_height: u64,
    /// Hash of the block at `tip_height`.
    pub tip_hash: BlockHash,
    /// Cumulative work at `tip_height`.
    pub tip_work: Work,
}

impl ForkMeta {
    /// Wire encoding: `forkpoint(8) parent(8) forkpoint_hash(32) tip_height(8)
    /// tip_hash(32) tip_work(32)` = 120 bytes.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(120);
        out.extend(self.forkpoint.to_be_bytes());
        out.extend(self.parent.unwrap_or(NO_PARENT).to_be_bytes());
        out.extend(self.forkpoint_hash.as_byte_array());
        out.extend(self.tip_height.to_be_bytes());
        out.extend(self.tip_hash.as_byte_array());
        out.extend(self.tip_work.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> ForkMeta {
        let parent = u64::from_be_bytes(bytes[8..16].try_into().expect("8 bytes"));
        let mut fp_hash = [0u8; 32];
        fp_hash.copy_from_slice(&bytes[16..48]);
        let tip_work = Work::from_be_bytes(bytes[80..112].try_into().expect("32 bytes"));
        ForkMeta {
            forkpoint: u64::from_be_bytes(bytes[0..8].try_into().expect("8 bytes")),
            parent: (parent != NO_PARENT).then_some(parent),
            forkpoint_hash: BlockHash::from_byte_array(fp_hash),
            tip_height: u64::from_be_bytes(bytes[48..56].try_into().expect("8 bytes")),
            tip_hash: BlockHash::from_byte_array(bytes[56..88].try_into().expect("32 bytes")),
            tip_work,
        }
    }
}

/// redb-backed Bitcoin chain state, threaded by [`crate::Chain`]. It is only
/// reachable through [`Store::read`] and [`Store::write`]: there are no
/// per-call read or write shortcuts, so every operation declares up front
/// whether it takes a read snapshot or the writer.
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
            read_fork_meta(&table, fork_id)
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
            read_loc(&table, hash.as_byte_array())
        }

        pub(crate) fn header_at(
            &self,
            fork_id: u64,
            height: u64,
        ) -> Result<Option<BitcoinHeader>, Error> {
            let table = self.txn.open_table(BTC_HEADERS)?;
            Ok(read_row(&table, fork_id, height)?.map(|(h, _)| h))
        }

        pub(crate) fn work_at(&self, fork_id: u64, height: u64) -> Result<Option<Work>, Error> {
            let table = self.txn.open_table(BTC_HEADERS)?;
            Ok(read_row(&table, fork_id, height)?.map(|(_, w)| w))
        }

        /// Cumulative work of a fork at its tip — the number chain selection
        /// compares across forks (Electrum's `get_chainwork`).
        pub(crate) fn fork_chainwork(&self, fork_id: u64) -> Result<Option<Work>, Error> {
            match self.fork_meta(fork_id)? {
                None => Ok(None),
                Some(m) => self.work_at(fork_id, m.tip_height),
            }
        }

        /// The latest settled checkpoint, if seeded. Monotonic: only the
        /// connect path advances it, and only forward.
        pub(crate) fn finalized_height(&self) -> Result<Option<u64>, Error> {
            self.meta_u64(META_FINALIZED)
        }

        fn meta_u64(&self, key: &str) -> Result<Option<u64>, Error> {
            let table = self.txn.open_table(BTC_META)?;
            read_meta_u64(&table, key)
        }
    };
}

/// A read-only snapshot: a consistent view of committed state for the life of
/// the transaction.
pub(crate) struct ReadTxn {
    txn: ReadTransaction,
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
        read_meta_network(&table)
    }
}

/// A single read-write transaction: a consistent snapshot plus the exclusive
/// right to write. It carries the same read surface as [`ReadTxn`], so a
/// sequence of reads feeding a decision and the writes acting on it are atomic
/// with respect to any other writer.
pub(crate) struct WriteTxn {
    txn: WriteTransaction,
}

impl WriteTxn {
    read_methods!();

    /// The network the chain was seeded for, if any. Recorded at seed time so
    /// a resume with the wrong network is refused rather than silently
    /// validated against the wrong consensus parameters.
    pub(crate) fn network(&self) -> Result<Option<Network>, Error> {
        let table = self.txn.open_table(BTC_META)?;
        read_meta_network(&table)
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
            let bytes = encode(header)?;
            checkpoints.insert(*height, bytes.as_slice())?;
            hash_loc.insert(header.block_hash().as_byte_array().as_slice(), (0, *height))?;
            // The spine doubles as the root chain's headers at these
            // heights, with cumulative work.
            let mut row = Vec::with_capacity(112);
            row.extend_from_slice(&bytes);
            row.extend_from_slice(&cum.to_be_bytes());
            headers.insert((0, *height), row.as_slice())?;
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
        forks.insert(0, root.encode().as_slice())?;
        meta.insert(META_SEED_HEIGHT, first.to_be_bytes().as_slice())?;
        meta.insert(META_FINALIZED, last.to_be_bytes().as_slice())?;
        meta.insert(META_BEST_FORK, 0u64.to_be_bytes().as_slice())?;
        meta.insert(META_NEXT_FORK, 1u64.to_be_bytes().as_slice())?;
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
                .map(|v| u64::from_be_bytes(v.value().try_into().expect("8 bytes")))
                .unwrap_or(1);
            meta.insert(META_NEXT_FORK, (next + 1).to_be_bytes().as_slice())?;
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
            forks.insert(id, meta.encode().as_slice())?;
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
                let bytes = encode(header)?;
                let mut row = Vec::with_capacity(112);
                row.extend_from_slice(&bytes);
                row.extend_from_slice(&cum.to_be_bytes());
                headers.insert((fork_id, height), row.as_slice())?;
                hash_loc.insert(
                    header.block_hash().as_byte_array().as_slice(),
                    (fork_id, height),
                )?;
                // Extend the spine when the root chain crosses a period
                // boundary (the spine stays a full-chain work ladder).
                if fork_id == 0 && height % DIFFICULTY_PERIOD == 0 {
                    checkpoints.insert(height, bytes.as_slice())?;
                }
            }
            let last = entries.last().expect("checked non-empty above");
            let last_hash = last.1.block_hash();
            let mut meta = forks.get(fork_id)?.map(|v| ForkMeta::decode(v.value()));
            if let Some(m) = meta.as_mut() {
                m.tip_height = last.0;
                m.tip_hash = last_hash;
                m.tip_work = last.2;
            }
            let meta = meta.expect("fork meta must exist before appending headers");
            forks.insert(fork_id, meta.encode().as_slice())?;
        }
        Ok(())
    }

    /// Mark `fork_id` as the best (heaviest) chain.
    pub(crate) fn set_best_fork(&self, fork_id: u64) -> Result<(), Error> {
        let mut meta = self.txn.open_table(BTC_META)?;
        meta.insert(META_BEST_FORK, fork_id.to_be_bytes().as_slice())?;
        Ok(())
    }

    /// Record the network this chain is seeded for (read back by the network
    /// check at the top of [`crate::Chain::connect_headers`]).
    pub(crate) fn set_network(&self, network: Network) -> Result<(), Error> {
        let mut meta = self.txn.open_table(BTC_META)?;
        meta.insert(META_NETWORK, network.to_string().as_bytes())?;
        Ok(())
    }

    /// Record the latest finalized checkpoint.
    pub(crate) fn set_finalized(&self, height: u64) -> Result<(), Error> {
        let mut meta = self.txn.open_table(BTC_META)?;
        meta.insert(META_FINALIZED, height.to_be_bytes().as_slice())?;
        Ok(())
    }

    /// Persist every change made through this transaction.
    pub(crate) fn commit(self) -> Result<(), Error> {
        self.txn.commit()?;
        Ok(())
    }
}

// ── shared read helpers (used by both ReadTxn and WriteTxn) ─────────────────

fn decode_row(bytes: &[u8]) -> (BitcoinHeader, Work) {
    let mut reader = &bytes[..80];
    let header =
        BitcoinHeader::consensus_decode(&mut reader).expect("stored header is always valid");
    let work = Work::from_be_bytes(bytes[80..112].try_into().expect("32-byte work"));
    (header, work)
}

fn read_row<T>(table: &T, fork_id: u64, height: u64) -> Result<Option<(BitcoinHeader, Work)>, Error>
where
    T: ReadableTable<(u64, u64), &'static [u8]>,
{
    Ok(table.get((fork_id, height))?.map(|v| decode_row(v.value())))
}

fn read_fork_meta<T>(table: &T, fork_id: u64) -> Result<Option<ForkMeta>, Error>
where
    T: ReadableTable<u64, &'static [u8]>,
{
    Ok(table.get(fork_id)?.map(|v| ForkMeta::decode(v.value())))
}

fn read_loc<T>(table: &T, hash: &[u8; 32]) -> Result<Option<(u64, u64)>, Error>
where
    T: ReadableTable<&'static [u8], (u64, u64)>,
{
    Ok(table.get(hash.as_slice())?.map(|v| v.value()))
}

fn read_meta_u64<T>(table: &T, key: &str) -> Result<Option<u64>, Error>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    Ok(table
        .get(key)?
        .map(|v| u64::from_be_bytes(v.value().try_into().expect("8-byte meta"))))
}

fn read_meta_network<T>(table: &T) -> Result<Option<Network>, Error>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    let Some(value) = table.get(META_NETWORK)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(value.value())
        .map_err(|e| Error::Internal(format!("network meta is not utf-8: {e}")))?;
    Ok(text.parse().ok())
}

fn encode(header: &BitcoinHeader) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(80);
    header
        .consensus_encode(&mut buf)
        .map_err(|e| Error::Internal(format!("encode header: {e}")))?;
    Ok(buf)
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
