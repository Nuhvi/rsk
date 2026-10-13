//! `rsk-cli sync` — download real Bitcoin headers over P2P into `rsk-core`.
//!
//! The default mode seeds **genesis only** and pulls the whole chain from the
//! peer: every header is PoW-, continuity-, difficulty- and timestamp-checked
//! by `rsk-core`, which also finalizes difficulty periods (and prunes below
//! the floor) as it goes, so the store stays bounded. `--spine-tail` instead
//! trusts the embedded checkpoint spine and syncs only the recent tail — the
//! ephemeral-sidechain trust model.
//!
//! The store is opened once and reused, so a re-run resumes from the tip.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use bitcoin::Network;
use bitcoin::block::{BlockHash, Header as BitcoinHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash as _;
use bitcoin::pow::Work;
use btc_p2p::session::Session;
use rsk_core::{Chain, DIFFICULTY_PERIOD};

use crate::USER_AGENT;
use crate::peers;

/// The embedded checkpoint spine: one 80-byte hex header per difficulty
/// period, from genesis to near the tip. It is the same file
/// `bitcoin-spv::checkpoints()` embeds; read in directly so the CLI does not
/// pull that crate's network dependencies.
const CHECKPOINTS: &str = include_str!("../../bitcoin-spv/checkpoints.txt");

/// Where the chain store lives by default, relative to the working directory
/// (the repo gitignores `data/`). Product-scoped rather than bitcoin-scoped
/// because the same store will later carry RSK chain state. Keep it simple and
/// predictable; the absolute path is logged at startup so there is never a
/// question of *where*.
const DEFAULT_DATA_DIR: &str = "data/rsk-one";

#[derive(clap::Args)]
pub struct Args {
    /// Directory for the chain store
    #[arg(long, value_name = "DIR", default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,

    /// Trust the embedded checkpoint spine and sync only the recent tail
    /// instead of the whole chain from genesis
    #[arg(long)]
    spine_tail: bool,

    /// Periods of spine tail to leave un-synced when --spine-tail is set
    #[arg(long, value_name = "N", default_value_t = 24)]
    cut: u64,

    /// Peer address to try first (repeatable), e.g. 1.2.3.4:8333
    #[arg(long, value_name = "IP:PORT")]
    addr: Vec<SocketAddr>,

    /// DNS seed host to resolve (repeatable; defaults to the mainnet seeds)
    #[arg(long, value_name = "HOST")]
    seed: Vec<String>,

    /// Maximum number of peer attempts
    #[arg(long, value_name = "N", default_value_t = 8)]
    limit: usize,
}

pub fn run(args: Args) -> Result<()> {
    std::fs::create_dir_all(&args.data_dir)
        .with_context(|| format!("creating data dir {}", args.data_dir.display()))?;
    // Make the location unambiguous for the user: log the absolute path, not
    // the relative one they typed (or the default).
    let data_dir = std::fs::canonicalize(&args.data_dir)
        .with_context(|| format!("resolving data dir {}", args.data_dir.display()))?;
    let store_path = data_dir.join("chain.redb");
    println!("data directory: {}", data_dir.display());
    println!("chain store:    {}", store_path.display());

    let chain = Chain::open(&store_path, Network::Bitcoin)?;

    let from = anchor(&chain, &args)?;
    println!("syncing from height {from} …");

    let (candidates, failed) = peers::candidates(args.addr, &args.seed);
    if !failed.is_empty() {
        println!("seed(s) failed to resolve: {}", failed.join(", "));
    }
    if candidates.is_empty() {
        bail!("no candidate peers: every DNS seed failed to resolve");
    }
    println!("{} candidate peer address(es)", candidates.len());

    let mut queue: VecDeque<SocketAddr> = candidates.into_iter().collect();
    sync(&chain, &mut queue, args.limit)
}

/// Plant the trust anchor once and return the first height to download. On a
/// store that is already anchored this is just the height above the tip.
fn anchor(chain: &Chain, args: &Args) -> Result<u64> {
    if let Some(tip) = chain.tip_height()? {
        println!("resume: store already anchored at tip {tip}; continuing above it");
        return Ok(tip + 1);
    }
    if args.spine_tail {
        let spine = parse_checkpoints()?;
        let cut = args.cut as usize;
        anyhow::ensure!(
            cut + 2 < spine.len(),
            "--cut {cut} leaves nothing to validate above the {}-period spine",
            spine.len()
        );
        let prefix = &spine[..spine.len() - cut];
        chain.seed_checkpoints(prefix)?;
        let seed_height = prefix.last().context("non-empty spine")?.0;
        println!(
            "spine: seeded {} trusted checkpoints (heights 0..={seed_height}); syncing the {cut} period(s) above them",
            prefix.len()
        );
        Ok(seed_height + 1)
    } else {
        let genesis = genesis_block(Network::Bitcoin).header;
        chain.seed_checkpoints(&[(0, genesis)])?;
        println!("spine: seeded genesis only; syncing the whole chain from block 1");
        Ok(1)
    }
}

fn parse_checkpoints() -> Result<Vec<(u64, BitcoinHeader)>> {
    let mut out = Vec::new();
    for (i, line) in CHECKPOINTS
        .lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
    {
        let bytes = hex::decode(line.trim()).with_context(|| format!("checkpoint line {i}"))?;
        anyhow::ensure!(
            bytes.len() == 80,
            "checkpoint line {i} is {} bytes, want 80",
            bytes.len()
        );
        let mut reader = bytes.as_slice();
        out.push((
            i as u64 * DIFFICULTY_PERIOD,
            BitcoinHeader::consensus_decode(&mut reader)
                .with_context(|| format!("checkpoint line {i}"))?,
        ));
    }
    Ok(out)
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

fn sync(chain: &Chain, queue: &mut VecDeque<SocketAddr>, limit: usize) -> Result<()> {
    let started = Instant::now();
    let mut total = 0usize;
    let mut batches = 0usize;
    let mut works: Vec<Work> = Vec::new();
    let mut peer_height: Option<u64> = None;
    let mut attempts = 0usize;
    let mut caught_up = false;

    'peers: while let Some(addr) = queue.pop_front() {
        attempts += 1;
        if attempts > limit {
            bail!("gave up after {limit} peer attempt(s)");
        }
        let start_height = chain.tip_height()?.unwrap_or(0).min(i32::MAX as u64) as i32;
        let (mut session, handshake) = match Session::connect(addr, USER_AGENT, start_height) {
            Ok(pair) => pair,
            Err(e) => {
                println!("  {addr} failed: {e:#}");
                continue;
            }
        };
        peer_height = Some(handshake.start_height.max(0) as u64);
        println!(
            "peer {addr}: {} best height {}",
            handshake.user_agent, handshake.start_height
        );

        loop {
            let locator = locator(chain)?;
            let headers = match session.get_headers(&locator, BlockHash::all_zeros()) {
                Ok(headers) => headers,
                Err(e) => {
                    println!("  peer {addr} dropped: {e:#}");
                    queue.push_back(addr);
                    continue 'peers;
                }
            };
            if headers.is_empty() {
                caught_up = true;
                break 'peers;
            }

            let first = chain.tip_height()?.unwrap_or(0) + 1;
            let out = match chain.connect_headers(&headers) {
                Ok(out) => out,
                Err(e) => {
                    // The transactional store means nothing from this batch
                    // stuck; drop the peer and try another.
                    println!("  peer {addr} sent headers we rejected: {e:#}");
                    queue.push_back(addr);
                    continue 'peers;
                }
            };
            batches += 1;
            total += out.connected;
            works.push(chain.chainwork()?.context("chainwork after connect")?);
            let tip = chain.tip_height()?.context("tip after connect")?;
            let seen = first + out.connected as u64 - 1;
            // Print the first handful, then every 20th batch, so a ~485-batch
            // from-genesis run stays readable.
            if batches <= 10 || batches.is_multiple_of(20) {
                let percent = match peer_height {
                    Some(h) if h > 0 => format!(" {:>5.1}%", 100.0 * seen as f64 / h as f64),
                    _ => String::new(),
                };
                let rate = total as f64 / started.elapsed().as_secs_f64().max(0.001);
                println!(
                    "[{batches:>4}] headers {first}..={seen}  tip {tip}{percent}  {rate:.0} h/s"
                );
                if let Some(finalized) = out.finalized {
                    println!("         ↳ auto-finalized difficulty period {finalized}");
                }
            }
        }
    }

    if !caught_up {
        bail!("did not reach any peer's tip");
    }

    report(chain, total, batches, started, peer_height, &works)
}

/// The end-of-run summary and the invariants that say the sync was real.
fn report(
    chain: &Chain,
    total: usize,
    batches: usize,
    started: Instant,
    peer_height: Option<u64>,
    works: &[Work],
) -> Result<()> {
    let tip = chain.tip_height()?.context("no tip after sync")?;
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "\nsynced {total} headers in {batches} batches over {elapsed:.1}s ({:.0} headers/s); tip {tip}",
        total as f64 / elapsed.max(0.001)
    );

    // 1. We reached the peer's advertised height.
    if let Some(peer_height) = peer_height {
        anyhow::ensure!(
            tip >= peer_height,
            "tip {tip} is below the peer's advertised height {peer_height}"
        );
        println!("peer advertised height {peer_height}; our tip is {tip}");
    }

    // 2. Cumulative work grew monotonically with the tip.
    for window in works.windows(2) {
        anyhow::ensure!(
            window[1] > window[0],
            "cumulative work did not increase across a batch"
        );
    }
    if let Some(work) = chain.chainwork()? {
        println!("chainwork: {work} (log2 {:.1})", work.log2());
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
        println!("finality: floor {finalized} (expected boundary ~{expected})");
    }
    Ok(())
}
