//! `rsk-cli sync` — download real Bitcoin headers over P2P into `rsk-core`.
//!
//! By default the node anchors on the **embedded checkpoint spine** (one
//! trusted header per difficulty period, compiled into `rsk-core`). Like
//! Electrum's hardcoded checkpoints, this lets the node skip the whole-history
//! download and sync only the tail above the newest checkpoint, while still
//! PoW-, continuity-, difficulty- and timestamp-validating every header above
//! it. `--cut N` pulls the spine back N periods (trust less, validate more);
//! `--from-genesis` ignores the spine entirely and validates the whole chain
//! from block 1.
//!
//! Headers come from a small pool of peers, round-robining across all of them
//! with the next batch prefetched while the current one validates. The store is
//! durable, so a re-run resumes from the tip.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use bitcoin::Network;
use bitcoin::block::BlockHash;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash as _;
use bitcoin::pow::Work;
use rsk_core::{Chain, DIFFICULTY_PERIOD};
use tracing::{info, warn};

use crate::DEFAULT_DATA_DIR;
use crate::peers::{self, Peer, Pool};

#[derive(clap::Args)]
pub struct Args {
    /// Directory for the chain store
    #[arg(long, value_name = "DIR", default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,

    /// Trust only the first (spine length − N) checkpoints, validating N
    /// periods of real headers above the spine
    #[arg(long, value_name = "N", default_value_t = 0)]
    cut: u64,

    /// Ignore the embedded checkpoint spine and validate the whole chain from
    /// block 1
    #[arg(long)]
    from_genesis: bool,

    /// Number of peers to keep connected
    #[arg(long, value_name = "N", default_value_t = 3)]
    peers: usize,

    /// Peer address to try first (repeatable), e.g. 1.2.3.4:8333
    #[arg(long, value_name = "IP:PORT")]
    addr: Vec<SocketAddr>,

    /// DNS seed host to resolve (repeatable; defaults to the mainnet seeds)
    #[arg(long, value_name = "HOST")]
    seed: Vec<String>,

    /// Maximum number of peer connections to attempt
    #[arg(long, value_name = "N", default_value_t = 8)]
    limit: usize,
}

pub fn run(mut args: Args) -> Result<()> {
    std::fs::create_dir_all(&args.data_dir)
        .with_context(|| format!("creating data dir {}", args.data_dir.display()))?;
    // Make the location unambiguous: log the absolute path, not the relative
    // one the user typed (or the default).
    let data_dir = std::fs::canonicalize(&args.data_dir)
        .with_context(|| format!("resolving data dir {}", args.data_dir.display()))?;
    let store_path = data_dir.join("chain.redb");
    info!("data directory: {}", data_dir.display());
    info!("chain store:    {}", store_path.display());

    let chain = Chain::open(&store_path, Network::Bitcoin)?;

    let from = anchor(&chain, &args)?;
    info!("syncing from height {from} …");

    let (candidates, failed) = peers::candidates(std::mem::take(&mut args.addr), &args.seed);
    if !failed.is_empty() {
        warn!("seed(s) failed to resolve: {}", failed.join(", "));
    }
    if candidates.is_empty() {
        bail!("no candidate peers: every DNS seed failed to resolve");
    }

    let mut candidates: VecDeque<SocketAddr> = candidates.into_iter().collect();
    sync(&chain, &mut candidates, &args)
}

/// Plant the trust anchor once and return the first height to download. On a
/// store that is already anchored this is just the height above the tip.
fn anchor(chain: &Chain, args: &Args) -> Result<u64> {
    if let Some(tip) = chain.tip_height()? {
        info!("resume: store already anchored at tip {tip}; continuing above it");
        return Ok(tip + 1);
    }
    if args.from_genesis {
        let genesis = genesis_block(Network::Bitcoin).header;
        chain.seed_checkpoints(&[(0, genesis)])?;
        info!("anchor: genesis only — validating the whole chain from block 1");
        return Ok(1);
    }

    let spine = rsk_core::checkpoints::parse()?;
    let cut = args.cut as usize;
    anyhow::ensure!(
        cut < spine.len(),
        "--cut {cut} is past the end of the {}-period spine",
        spine.len()
    );
    let prefix = &spine[..spine.len() - cut];
    chain.seed_checkpoints(prefix)?;
    let seed_height = prefix.last().context("non-empty spine")?.0;
    if cut == 0 {
        info!(
            "anchor: {} embedded checkpoints trusted (heights 0..={seed_height}); syncing the tail above them",
            prefix.len()
        );
    } else {
        info!(
            "anchor: {} checkpoints trusted up to {seed_height}; validating {cut} period(s) of real headers above",
            prefix.len()
        );
    }
    Ok(seed_height + 1)
}

/// A locator for our canonical tip: the last few headers (newest first), then
/// genesis as the universal fallback. A peer walks it to find the fork point
/// and serves headers after the first hash it knows.
fn locator(chain: &Chain) -> Result<Vec<BlockHash>> {
    let Some(tip) = chain.tip_height()? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for height in (tip.saturating_sub(9)..=tip).rev() {
        if let Some(header) = chain.header_at(height)? {
            out.push(header.block_hash());
        }
    }
    if let Some(genesis) = chain.header_at(0)? {
        let hash = genesis.block_hash();
        if out.last() != Some(&hash) {
            out.push(hash);
        }
    }
    Ok(out)
}

fn start_height(chain: &Chain) -> Result<i32> {
    Ok(chain.tip_height()?.unwrap_or(0).min(i32::MAX as u64) as i32)
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

fn sync(chain: &Chain, candidates: &mut VecDeque<SocketAddr>, args: &Args) -> Result<()> {
    let want = args.peers.max(1);
    let mut pool = Pool::new();
    pool.fill(candidates, want, args.limit, start_height(chain)?);
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
        .request_headers(&locator(chain)?, BlockHash::all_zeros())?;

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
                    .request_headers(&locator(chain)?, BlockHash::all_zeros())?;
                continue;
            }
        };
        if headers.is_empty() {
            return report(chain, &stats);
        }

        // Prefetch the next batch on another peer *before* validating this one.
        let last = headers.last().context("non-empty headers")?.block_hash();
        cur = prefetch(&mut peers, &mut alive, cur, last)?;

        let first = chain.tip_height()?.unwrap_or(0) + 1;
        let out = chain.connect_headers(&headers)?;
        stats.batches += 1;
        stats.total += out.connected;
        stats
            .works
            .push(chain.chainwork()?.context("chainwork after connect")?);
        let tip = chain.tip_height()?.context("tip after connect")?;
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
fn report(chain: &Chain, stats: &Stats) -> Result<()> {
    let tip = chain.tip_height()?.context("no tip after sync")?;
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
    if let Some(work) = chain.chainwork()? {
        info!("chainwork: {work} (log2 {:.1})", work.log2());
    }

    // 3. Genesis survived and the canonical (root) chain won.
    let genesis = chain.header_at(0)?.context("genesis pruned")?;
    anyhow::ensure!(
        genesis.block_hash() == genesis_block(Network::Bitcoin).header.block_hash(),
        "genesis hash changed"
    );
    anyhow::ensure!(
        chain.best_fork()? == Some(0),
        "a fork won the canonical chain"
    );

    // 4. Finality advanced across real difficulty periods.
    if tip > 2 * DIFFICULTY_PERIOD {
        let finalized = chain.finalized_height()?.unwrap_or(0);
        let expected = ((tip - DIFFICULTY_PERIOD) / DIFFICULTY_PERIOD) * DIFFICULTY_PERIOD;
        anyhow::ensure!(
            finalized >= expected.saturating_sub(2 * DIFFICULTY_PERIOD),
            "finality floor {finalized} lagged the expected boundary {expected}"
        );
        info!("finality: floor {finalized} (expected boundary ~{expected})");
    }
    Ok(())
}
