use ethereum_types::H256;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct RskNetwork {
    pub name: &'static str,
    pub chain_id: u64,
    pub network_id: u64,
    pub genesis_hash: H256,
    pub fork_id: ForkId,
    pub bootstrap_nodes: Vec<BootstrapNode>,
}

#[derive(Debug, Clone)]
pub struct ForkId {
    pub hash: u32,
    pub next: u64,
}

#[derive(Debug, Clone)]
pub struct BootstrapNode {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl RskNetwork {
    pub fn mainnet() -> Self {
        Self {
            name: "RSK Mainnet",
            chain_id: 30,
            network_id: 775,
            genesis_hash: H256([
                0x46, 0x23, 0x95, 0x63, 0x97, 0x9b, 0xb5, 0x4c,
                0x13, 0x63, 0x9f, 0xb4, 0x92, 0xf7, 0x8e, 0x7a,
                0x73, 0xb0, 0x43, 0xb0, 0x23, 0x43, 0x4e, 0x75,
                0x43, 0x64, 0x59, 0x34, 0x25, 0x5e, 0x49, 0x19,
            ]),
            fork_id: ForkId {
                hash: 0xc365d509,
                next: 0,
            },
            bootstrap_nodes: vec![
                BootstrapNode { ip: Ipv4Addr::new(178, 156, 220, 7), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(178, 156, 219, 99), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(178, 156, 223, 98), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(178, 105, 196, 185), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(178, 105, 155, 122), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(178, 105, 213, 138), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(77, 42, 125, 140), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(77, 42, 120, 39), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(5, 78, 221, 102), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(5, 78, 210, 174), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(5, 78, 194, 169), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(91, 98, 175, 212), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(178, 105, 190, 234), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(5, 223, 70, 68), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(5, 223, 72, 83), port: 5050 },
                BootstrapNode { ip: Ipv4Addr::new(5, 223, 79, 181), port: 5050 },
            ],
        }
    }

    pub fn testnet() -> Self {
        Self {
            name: "RSK Testnet",
            chain_id: 31,
            network_id: 8100,
            genesis_hash: H256([
                0x46, 0x23, 0x95, 0x63, 0x97, 0x9b, 0xb5, 0x4c,
                0x13, 0x63, 0x9f, 0xb4, 0x92, 0xf7, 0x8e, 0x7a,
                0x73, 0xb0, 0x43, 0xb0, 0x23, 0x43, 0x4e, 0x75,
                0x43, 0x64, 0x59, 0x34, 0x25, 0x5e, 0x49, 0x19,
            ]),
            fork_id: ForkId {
                hash: 0xc365d509,
                next: 0,
            },
            bootstrap_nodes: vec![
                BootstrapNode { ip: Ipv4Addr::new(178, 105, 196, 185), port: 50505 },
            ],
        }
    }
}
