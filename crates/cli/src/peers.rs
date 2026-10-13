//! Shared peer helpers: candidate discovery, and a small pool of connected
//! peers kept warm for the sync.
//!
//! A Bitcoin header sync is sequential in *validation* (each batch links to the
//! one before it), but the network fetch is overlapped with it: the sync
//! round-robins across every pooled peer and prefetches the next batch while
//! the current one is validated. Keeping several peers connected also means the
//! driver keeps answering their pings, so they stay alive.
//!
//! TODO(peers): this is deliberately minimal. Real peer management — maintain a
//! target count with a minimum that never blocks progress, connect in the
//! background, ping and answer pings on idle peers, drop unresponsive ones,
//! grow the address table via `getaddr`/`addr` gossip and a persisted peer
//! cache, and score peers by validity/latency — is described in
//! `docs/ROADMAP.md` ("Peer management") and not implemented yet.

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

use btc_p2p::Handshake;
use btc_p2p::seeds;
use btc_p2p::session::Session;
use tracing::{info, warn};

use crate::USER_AGENT;

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

/// One connected, handshaken peer.
pub struct Peer {
    pub addr: SocketAddr,
    pub handshake: Handshake,
    pub session: Session<TcpStream>,
}

/// A small pool of connected peers. It spends a bounded number of connection
/// attempts (shared across refills) so a bad seed list cannot loop forever.
pub struct Pool {
    peers: Vec<Peer>,
    attempts: usize,
}

impl Pool {
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            attempts: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// A one-line description of every pooled peer, for logging.
    pub fn summary(&self) -> String {
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
    pub fn fill(
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
            match Session::connect(addr, USER_AGENT, start_height) {
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
    pub fn into_peers(self) -> Vec<Peer> {
        self.peers
    }
}
