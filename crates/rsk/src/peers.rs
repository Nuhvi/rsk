//! Bitcoin peer discovery and a small pool of connected peers.
//!
//! A header sync is sequential in *validation* (each batch links to the one
//! before it), but the network fetch is overlapped with it: the sync round-robins
//! across every pooled peer and prefetches the next batch while the current one
//! is validated. Keeping several peers connected also means the driver keeps
//! answering their pings, so they stay alive.
//!
//! Deliberately minimal: real peer management (maintain a target count with a
//! minimum that never blocks progress, ping idle peers, drop unresponsive ones,
//! grow the address table via `getaddr`/`addr`, score peers) is a later slice.

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

use btc_p2p::Handshake;
use btc_p2p::seeds;
use btc_p2p::session::Session;
use tracing::{info, warn};

/// Resolve seed hosts on `port`, returning the addresses and the hosts that
/// failed (which is routine — seeds come and go).
pub(crate) fn resolve(hosts: &[String], port: u16) -> (Vec<SocketAddr>, Vec<String>) {
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

/// Build the candidate list: explicit addresses first, then the resolved seeds
/// (defaulting to the mainnet seeds when none were given), deduped while
/// keeping that order.
pub(crate) fn candidates(
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

/// One connected, handshaken peer.
pub(crate) struct Peer {
    pub(crate) addr: SocketAddr,
    pub(crate) handshake: Handshake,
    pub(crate) session: Session<TcpStream>,
}

/// A small pool of connected peers. It spends a bounded number of connection
/// attempts (shared across refills) so a bad seed list cannot loop forever.
pub(crate) struct Pool {
    peers: Vec<Peer>,
    attempts: usize,
    user_agent: String,
}

impl Pool {
    pub(crate) fn new(user_agent: impl Into<String>) -> Self {
        Self {
            peers: Vec::new(),
            attempts: 0,
            user_agent: user_agent.into(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// A one-line description of every pooled peer, for logging.
    pub(crate) fn summary(&self) -> String {
        self.peers
            .iter()
            .map(|p| {
                format!(
                    "{}@{} ({})",
                    p.handshake.user_agent, p.handshake.start_height, p.addr
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Connect toward `want` peers, spending at most `max_attempts` total
    /// connections over the pool's life. Returns how many are now connected.
    pub(crate) fn fill(
        &mut self,
        candidates: &mut VecDeque<SocketAddr>,
        want: usize,
        max_attempts: usize,
        start_height: i32,
    ) -> usize {
        while self.peers.len() < want && self.attempts < max_attempts {
            let Some(addr) = candidates.pop_front() else {
                break;
            };
            self.attempts += 1;
            match Session::connect(addr, &self.user_agent, start_height) {
                Ok((session, handshake)) => {
                    info!(
                        "  peer {} @ {} — {} height {}",
                        handshake.user_agent, addr, handshake.services, handshake.start_height
                    );
                    self.peers.push(Peer {
                        addr,
                        handshake,
                        session,
                    });
                }
                Err(e) => warn!("  {addr} failed: {e:#}"),
            }
        }
        self.peers.len()
    }

    /// Take every connected peer out; the sync drives them all.
    pub(crate) fn into_peers(self) -> Vec<Peer> {
        self.peers
    }
}
