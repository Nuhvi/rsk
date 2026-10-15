//! Reach a real Bitcoin peer and prove headers flow: resolve candidates,
//! handshake, and pull one `headers` batch off genesis.

use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use bitcoin::Network;
use bitcoin::block::BlockHash;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use btc_p2p::Handshake;
use btc_p2p::session::Session;
use tracing::{info, warn};

use crate::config::Config;
use crate::peers;

/// What a successful Bitcoin probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// The peer that answered.
    pub addr: SocketAddr,
    /// What the peer advertised in its `version` message.
    pub handshake: Handshake,
    /// Headers returned in one batch after genesis.
    pub headers: usize,
    /// The first (oldest) header in the batch.
    pub first: BlockHash,
    /// The last (newest) header in the batch.
    pub last: BlockHash,
}

/// Try each candidate (explicit addresses, then resolved seeds) until one
/// answers, and return the first successful probe.
pub fn bitcoin(config: &Config) -> Result<ProbeReport> {
    let (candidates, failed) = peers::candidates(config.addrs.clone(), &config.seeds);
    info!(
        "{} candidate peer address(es); {} seed(s) failed to resolve{}",
        candidates.len(),
        failed.len(),
        if failed.is_empty() {
            String::new()
        } else {
            format!(": {}", failed.join(", "))
        }
    );
    if candidates.is_empty() {
        bail!("no candidate peers: every DNS seed failed to resolve");
    }

    for addr in candidates.into_iter().take(config.limit) {
        info!("trying {addr} …");
        match connect_probe(addr, &config.user_agent) {
            Ok(report) => return Ok(report),
            Err(e) => warn!("  {addr} failed: {e:#}"),
        }
    }
    bail!("no peer answered within {} tries", config.limit)
}

/// Connect, handshake, and pull one real `headers` batch off genesis.
fn connect_probe(addr: SocketAddr, user_agent: &str) -> Result<ProbeReport> {
    let (mut session, handshake) =
        Session::connect(addr, user_agent, 0).context("connecting and handshaking")?;

    info!("  user agent:   {}", handshake.user_agent);
    info!("  version:      {}", handshake.version);
    info!("  services:     {}", handshake.services);
    info!("  best height:  {}", handshake.start_height);

    let genesis = genesis_block(Network::Bitcoin).header.block_hash();
    let headers = session
        .get_headers(&[genesis], BlockHash::all_zeros())
        .context("getheaders round trip")?;
    if headers.is_empty() {
        bail!("peer returned no headers after genesis");
    }
    let first = headers[0].block_hash();
    let last = headers
        .last()
        .context("checked non-empty above")?
        .block_hash();
    info!("  getheaders:   {} header(s) in one batch", headers.len());
    info!("  first:        {first}");
    info!("  last:         {last}");
    info!("probe ok: handshake and header flow work against {addr}");

    Ok(ProbeReport {
        addr,
        handshake,
        headers: headers.len(),
        first,
        last,
    })
}
