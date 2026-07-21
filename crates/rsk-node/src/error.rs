use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeError {
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

    #[error("electrum error: {0}")]
    Electrum(String),

    #[error("RSK RPC error: {0}")]
    RskRpc(String),

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("merge-mining proof failed: {0}")]
    MergeMining(#[from] rsk::merge_mining::MergeMiningError),

    #[error("sync error: {0}")]
    Sync(String),

    #[error("decode error: {0}")]
    Decode(String),
}
