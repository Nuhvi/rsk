use rsk_store::StoreError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    #[error("electrum error: {0}")]
    Electrum(String),

    #[error("RSK RPC error: {0}")]
    RskRpc(String),

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("merge-mining proof failed: {0}")]
    MergeMining(#[from] rsk::merge_mining::MergeMiningError),
}
