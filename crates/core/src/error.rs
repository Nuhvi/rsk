use bitcoin::block::BlockHash;
use thiserror::Error;

/// Errors from the side-effect-free core.
///
/// Everything here is deterministic given the store contents and the inputs:
/// there is no network, no clock, no concurrency and no hidden I/O behind any
/// of these.
#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[from] redb::DatabaseError),

    #[error("transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),

    #[error("storage error: {0}")]
    Storage(#[from] redb::StorageError),

    #[error("table error: {0}")]
    Table(#[from] redb::TableError),

    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),

    #[error("no chain seeded: call Chain::seed_checkpoints first")]
    Unseeded,

    #[error("unknown ancestor {0}: the batch does not link to any stored header or checkpoint")]
    UnknownAncestor(BlockHash),

    #[error("bad proof of work at height {height}: {detail}")]
    BadPow { height: u64, detail: String },

    #[error("header at height {height} does not link to {expected}")]
    LinkBreak { height: u64, expected: BlockHash },

    #[error("fork at height {fork} is at or below the finalized checkpoint {finalized}")]
    ForkBelowFinalized { fork: u64, finalized: u64 },

    #[error("internal: {0}")]
    Internal(String),
}
