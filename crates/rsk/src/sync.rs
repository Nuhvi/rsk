//! The Bitcoin header sync: download, validate and store the tail above the
//! anchor, overlapping the fetch with validation.
//!
//! Headers come from a small pool of peers, round-robining across all of them
//! with the next batch prefetched while the current one validates. The store is
//! durable, so a re-run resumes from the tip. Every header is validated by
//! [`rsk_core::Core::connect_headers`]; this module only moves bytes.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use bitcoin::block::BlockHash;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash as _;
use bitcoin::pow::Work;
use rsk_core::{Core, DIFFICULTY_PERIOD};
use tracing::{info, warn};

use crate::config::Config;
use crate::peers::{Peer, Pool};

/// What a completed sync did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// Headers newly stored.
    pub headers: usize,
    /// Batches downloaded and validated.
    pub batches: usize,
    /// Canonical tip height after the sync.
    pub tip: u64,
    /// Finalized checkpoint after the sync.
    pub finalized: u64,
    /// Cumulative chain work at the tip.
    pub chainwork: Work,
    /// The greatest height advertised by the peers that drove the sync.
    pub peer_height: u64,
}

/// A locator for our canonical tip: the last few headers (newest first), then
/// genesis as the universal fallback. A peer walks it to find the fork point
/// and serves headers after the first hash it knows.
pub(crate) fn locator(core: &Core) -> Result<Vec<BlockHash>> {
    let Some(tip) = core.tip_height()? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for height in (tip.saturating_sub(9)..=tip).rev() {
        if let Some(header) = core.header_at(height)? {
            out.push(header.block_hash());
        }
    }
    if let Some(genesis) = core.header_at(0)? {
        let hash = genesis.block_hash();
        if out.last() != Some(&hash) {
            out.push(hash);
        }
    }
    Ok(out)
}

fn start_height(core: &Core) -> Result<i32> {
    Ok(core.tip_height()?.unwrap_or(0).min(i32::MAX as u64) as i32)
}

/// Running totals for the sync report.
struct Stats {
    started: Instant,
    total: usize,
    batches: usize,
    works: Vec<Work>,
    /// The greatest advertised height across the peers driving the sync.
    peer_height: u64,
}

/// Download and validate the tail above the current tip, driving the pool of
/// `candidates`. Returns the [`SyncReport`] once every peer is caught up.
pub(crate) fn run(
    core: &Core,
    config: &Config,
    candidates: &mut VecDeque<SocketAddr>,
) -> Result<SyncReport> {
    let want = config.peers.max(1);
    let mut pool = Pool::new(config.user_agent.clone());
    pool.fill(candidates, want, config.limit, start_height(core)?);
    if pool.is_empty() {
        bail!("could not connect to any peer");
    }
    let summary = pool.summary();
    let mut peers = pool.into_peers();
    let n = peers.len();
    info!("{n} peer(s) connected: {summary}");

    let mut stats = Stats {
        started: Instant::now(),
        total: 0,
        batches: 0,
        works: Vec::new(),
        peer_height: peers
            .iter()
            .map(|p| p.handshake.start_height.max(0) as u64)
            .max()
            .unwrap_or(0),
    };

    // Every peer is a worker; `alive[i]` marks those still usable. The sync
    // round-robins across them and prefetches the next batch while the current
    // one validates, so download overlaps the (CPU-bound) validation.
    let mut alive = vec![true; n];
    let mut cur = 0usize;
    peers[cur]
        .session
        .request_headers(&locator(core)?, BlockHash::all_zeros())?;

    loop {
        let server = peers[cur].addr;
        let headers = match peers[cur].session.read_headers() {
            Ok(headers) => headers,
            Err(e) => {
                warn!("  peer {server} dropped: {e:#}");
                alive[cur] = false;
                let Some(next) = next_alive(&alive, cur) else {
                    bail!("all peers dropped");
                };
                cur = next;
                peers[cur]
                    .session
                    .request_headers(&locator(core)?, BlockHash::all_zeros())?;
                continue;
            }
        };
        if headers.is_empty() {
            return report(core, config, &stats);
        }

        // Prefetch the next batch on another peer *before* validating this one.
        let last = headers.last().context("non-empty headers")?.block_hash();
        cur = prefetch(&mut peers, &mut alive, cur, last)?;

        let first = core.tip_height()?.unwrap_or(0) + 1;
        let out = core.connect_headers(&headers)?;
        stats.batches += 1;
        stats.total += out.connected;
        stats
            .works
            .push(core.chainwork()?.context("chainwork after connect")?);
        let tip = core.tip_height()?.context("tip after connect")?;
        let seen = first + out.connected as u64 - 1;
        // Print the first handful, then every 20th batch, so a long run stays
        // readable.
        if stats.batches <= 10 || stats.batches.is_multiple_of(20) {
            let percent = if stats.peer_height > 0 {
                format!(" {:>5.1}%", 100.0 * seen as f64 / stats.peer_height as f64)
            } else {
                String::new()
            };
            let rate = stats.total as f64 / stats.started.elapsed().as_secs_f64().max(0.001);
            let live = alive.iter().filter(|a| **a).count();
            info!(
                "[{:>4}] headers {first}..={seen}  tip {tip}{percent}  {rate:.0} h/s  peer {server} ({live}/{n} up)",
                stats.batches
            );
            if let Some(finalized) = out.finalized {
                info!("         ↳ auto-finalized difficulty period {finalized}");
            }
        }
    }
}

/// The next alive peer after `from`, round-robin.
fn next_alive(alive: &[bool], from: usize) -> Option<usize> {
    let n = alive.len();
    (1..=n).map(|step| (from + step) % n).find(|&p| alive[p])
}

/// Send the next `getheaders` (for the batch after `last`) to an alive peer,
/// round-robin, returning whichever peer now holds the outstanding request. A
/// peer whose send fails is marked dead; if every other peer is gone, the peer
/// we just read from is reused (single-peer fallback).
fn prefetch(peers: &mut [Peer], alive: &mut [bool], from: usize, last: BlockHash) -> Result<usize> {
    let n = peers.len();
    for step in 1..=n {
        let p = (from + step) % n;
        if !alive[p] {
            continue;
        }
        match peers[p]
            .session
            .request_headers(&[last], BlockHash::all_zeros())
        {
            Ok(()) => return Ok(p),
            Err(e) => {
                warn!("  peer {} dropped (request): {e:#}", peers[p].addr);
                alive[p] = false;
            }
        }
    }
    peers[from]
        .session
        .request_headers(&[last], BlockHash::all_zeros())?;
    Ok(from)
}

/// The end-of-run summary and the invariants that say the sync was real.
fn report(core: &Core, config: &Config, stats: &Stats) -> Result<SyncReport> {
    let tip = core.tip_height()?.context("no tip after sync")?;
    let elapsed = stats.started.elapsed().as_secs_f64();
    info!(
        "\nsynced {} headers in {} batches over {elapsed:.1}s ({:.0} headers/s); tip {tip}",
        stats.total,
        stats.batches,
        stats.total as f64 / elapsed.max(0.001)
    );

    // 1. We reached the peer's advertised height.
    if stats.peer_height > 0 {
        anyhow::ensure!(
            tip >= stats.peer_height,
            "tip {tip} is below the peer's advertised height {}",
            stats.peer_height
        );
        info!(
            "peer advertised height {}; our tip is {tip}",
            stats.peer_height
        );
    }

    // 2. Cumulative work grew monotonically with the tip.
    for window in stats.works.windows(2) {
        anyhow::ensure!(
            window[1] > window[0],
            "cumulative work did not increase across a batch"
        );
    }
    let chainwork = core.chainwork()?.context("chainwork after sync")?;
    info!("chainwork: {chainwork} (log2 {:.1})", chainwork.log2());

    // 3. Genesis survived and the canonical (root) chain won.
    let genesis = core.header_at(0)?.context("genesis pruned")?;
    anyhow::ensure!(
        genesis.block_hash() == genesis_block(config.network).header.block_hash(),
        "genesis hash changed"
    );
    anyhow::ensure!(
        core.best_fork()? == Some(0),
        "a fork won the canonical chain"
    );

    // 4. Finality advanced across real difficulty periods.
    let finalized = core.finalized_height()?.unwrap_or(0);
    if tip > 2 * DIFFICULTY_PERIOD {
        let expected = ((tip - DIFFICULTY_PERIOD) / DIFFICULTY_PERIOD) * DIFFICULTY_PERIOD;
        anyhow::ensure!(
            finalized >= expected.saturating_sub(2 * DIFFICULTY_PERIOD),
            "finality floor {finalized} lagged the expected boundary {expected}"
        );
        info!("finality: floor {finalized} (expected boundary ~{expected})");
    }

    Ok(SyncReport {
        headers: stats.total,
        batches: stats.batches,
        tip,
        finalized,
        chainwork,
        peer_height: stats.peer_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    /// A temp store anchored on the first `periods` spine checkpoints
    /// (heights 0, 2016, 4032, …). The temp dir must outlive the store.
    fn anchored(periods: usize) -> (tempfile::TempDir, Core) {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::open(&dir.path().join("chain.redb"), Network::Bitcoin).unwrap();
        let spine = rsk_core::btc::checkpoints::parse().unwrap();
        core.seed_checkpoints(&spine[..periods]).unwrap();
        (dir, core)
    }

    #[test]
    fn locator_is_the_tip_then_genesis() {
        let (_dir, core) = anchored(3); // heights 0, 2016, 4032
        let spine = rsk_core::btc::checkpoints::parse().unwrap();

        // Only the tip boundary (4032) is within the last ten heights; genesis
        // is always appended as the fallback.
        let loc = locator(&core).unwrap();
        assert_eq!(loc.first(), Some(&spine[2].1.block_hash()));
        assert_eq!(loc.last(), Some(&spine[0].1.block_hash()));
        assert_eq!(loc.len(), 2);
    }

    #[test]
    fn locator_is_empty_without_a_tip() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::open(&dir.path().join("chain.redb"), Network::Bitcoin).unwrap();
        assert!(locator(&core).unwrap().is_empty());
    }
}
