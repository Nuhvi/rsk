//! `rsk-cli probe` — contact a real Bitcoin P2P peer and prove headers flow.

use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use bitcoin::Network;
use bitcoin::block::BlockHash;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use btc_p2p::session::Session;
use tracing::{info, warn};

use crate::USER_AGENT;
use crate::peers;

#[derive(clap::Args)]
pub struct Args {
    /// Peer address to try first (repeatable), e.g. 1.2.3.4:8333
    #[arg(long, value_name = "IP:PORT")]
    addr: Vec<SocketAddr>,

    /// DNS seed host to resolve (repeatable; defaults to the mainnet seeds)
    #[arg(long, value_name = "HOST")]
    seed: Vec<String>,

    /// Maximum number of candidate peers to try
    #[arg(long, default_value_t = 8)]
    limit: usize,
}

pub fn run(args: Args) -> Result<()> {
    let (candidates, failed) = peers::candidates(args.addr, &args.seed);
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

    for addr in candidates.into_iter().take(args.limit) {
        info!("trying {addr} …");
        match connect_probe(addr) {
            Ok(()) => return Ok(()),
            Err(e) => warn!("  {addr} failed: {e:#}"),
        }
    }
    bail!("no peer answered within {} tries", args.limit)
}

/// Connect, handshake, and pull one real `headers` batch off genesis.
fn connect_probe(addr: SocketAddr) -> Result<()> {
    let (mut session, handshake) =
        Session::connect(addr, USER_AGENT, 0).context("connecting and handshaking")?;

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
    Ok(())
}
