use alloy_primitives::{B256, B512, U256};

/// Configuration for a P2P connection.
///
/// Trimmed from rustock's `NodeConfig`: the fields a light client needs to
/// dial a peer, run the RLPx/devp2p/`rsk` handshake and announce its own tip.
/// The fields that only a full node uses (peer limits, discovery, data dir)
/// are kept so the vendored handshake code compiles unchanged.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub client_id: String,
    pub listen_port: u16,
    pub id: B512,
    pub chain_id: u8,
    pub network_id: u64,
    pub genesis_hash: B256,
    pub best_hash: B256,
    pub best_block_number: u64,
    /// Parent of the best block. The RSK status message is positional: parent
    /// and total difficulty are elements three and four, so without them the
    /// status only has two elements and carries no total difficulty.
    pub best_block_parent_hash: Option<B256>,
    pub total_difficulty: U256,
    /// Lowest block this node can serve (the prune floor), sent as a fifth
    /// status element that rskj ignores.
    pub earliest_block: u64,
    /// Whether to offer the `snap` capability in the handshake.
    pub snap_capability: bool,
    pub bootnodes: Vec<String>,
    pub closed_network: bool,
    pub read_only: bool,
    pub secret_key: [u8; 32],
    pub discovery_port: u16,
    pub data_dir: String,
    pub external_ip: Option<std::net::IpAddr>,
    pub max_outbound_peers: usize,
    pub max_inbound_peers: usize,
    pub max_inbound_per_ip: usize,
    pub max_inbound_per_cidr: usize,
    pub inbound_cidr_prefix: u8,
}
