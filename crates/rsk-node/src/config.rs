use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rsk-node",
    about = "RSK One — persistent Rootstock light client node"
)]
pub struct NodeConfig {
    /// Data directory for redb databases
    #[arg(long, default_value = "data")]
    pub data_dir: PathBuf,

    /// Electrum server URLs (can specify multiple)
    #[arg(long = "electrum", num_args = 1..)]
    pub electrum_servers: Vec<String>,

    /// RSK JSON-RPC endpoint
    #[arg(long)]
    pub rsk_rpc_url: String,

    /// Bitcoin checkpoint block height (skip syncing before this)
    #[arg(long, default_value_t = 900_000)]
    pub btc_checkpoint_height: u64,

    /// Number of Bitcoin blocks for the difficulty window
    #[arg(long, default_value_t = 100)]
    pub btc_window_size: usize,

    /// RSK safe block margin (reorg safety, from RSKIP555)
    #[arg(long, default_value_t = 6)]
    pub rsk_safe_block_margin: u64,

    /// Batch size for header fetching
    #[arg(long, default_value_t = 100)]
    pub sync_batch_size: usize,
}
