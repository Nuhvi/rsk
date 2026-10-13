//! Peer discovery: Bitcoin's DNS seeds.
//!
//! Each seed serves A/AAAA records of reachable full nodes. Resolution is
//! best-effort: a seed that fails to resolve is skipped, and the caller works
//! down the candidate list.

use std::net::{SocketAddr, ToSocketAddrs};

/// Default TCP port for the Bitcoin P2P network.
pub const DEFAULT_PORT: u16 = 8333;

/// Bitcoin mainnet DNS seeds.
pub const MAINNET_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
];

/// Resolve the seeds to candidate peer addresses, deduped. Seeds that do not
/// resolve are skipped (they are frequently offline); an empty result means
/// none did, and the caller should say so.
pub fn resolve(seeds: &[&str], port: u16) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for seed in seeds {
        match (*seed, port).to_socket_addrs() {
            Ok(addrs) => out.extend(addrs),
            // Unresolvable seeds are routine; the caller sees the count.
            Err(_) => continue,
        }
    }
    out.sort();
    out.dedup();
    out
}
