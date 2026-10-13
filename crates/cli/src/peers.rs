//! Shared peer-address helpers: seed resolution and candidate ordering.

use std::net::{SocketAddr, ToSocketAddrs};

use btc_p2p::seeds;

/// Resolve seed hosts on `port`, returning the addresses and the hosts that
/// failed (which is routine — seeds come and go).
pub fn resolve(hosts: &[String], port: u16) -> (Vec<SocketAddr>, Vec<String>) {
    let mut addrs = Vec::new();
    let mut failed = Vec::new();
    for host in hosts {
        match (host.as_str(), port).to_socket_addrs() {
            Ok(list) => addrs.extend(list),
            Err(e) => failed.push(format!("{host} ({e})")),
        }
    }
    (addrs, failed)
}

/// Build the candidate list: explicit `--addr` addresses first, then the
/// resolved seeds (defaulting to the mainnet seeds when none were given),
/// deduped while keeping that order.
pub fn candidates(
    addrs: Vec<SocketAddr>,
    given_seeds: &[String],
) -> (Vec<SocketAddr>, Vec<String>) {
    let hosts: Vec<String> = if given_seeds.is_empty() {
        seeds::MAINNET_SEEDS.iter().map(|s| s.to_string()).collect()
    } else {
        given_seeds.to_vec()
    };
    let (resolved, failed) = resolve(&hosts, seeds::DEFAULT_PORT);
    let mut out = addrs;
    for addr in resolved {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    (out, failed)
}
