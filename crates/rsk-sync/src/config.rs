use std::path::PathBuf;
use std::time::Duration;

use alloy_primitives::B256;
use rsk_consensus::checkpoint::{DifficultyCheckpoint, MAINNET_CHECKPOINT};
use rsk_consensus::config::ChainConfig;

/// Configuration for a header sync run.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub chain: ChainConfig,
    pub genesis_hash: B256,
    /// `host:port` bootnodes to try, in order.
    pub bootnodes: Vec<String>,
    /// Where the redb store lives.
    pub data_dir: PathBuf,
    /// The cumulative-difficulty checkpoint the chain anchors on.
    pub checkpoint: DifficultyCheckpoint,
    /// How many header/skeleton requests may be in flight at once.
    pub pipeline: usize,
    /// How long to wait for any single protocol response.
    pub read_timeout: Duration,
    /// How long a single RLPx/status handshake may take.
    pub handshake_timeout: Duration,
}

impl SyncConfig {
    pub fn mainnet(data_dir: PathBuf) -> Self {
        let chain = ChainConfig::mainnet();
        let genesis_hash = chain.known_genesis_hash().expect("mainnet genesis hash");
        Self {
            bootnodes: chain.bootnodes(),
            checkpoint: MAINNET_CHECKPOINT,
            chain,
            genesis_hash,
            data_dir,
            pipeline: 8,
            read_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(15),
        }
    }
}
