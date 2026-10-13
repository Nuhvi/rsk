//! rsk-cli — run the RSK One node from the command line.
//!
//! This is the user-facing way to run things; the crates below it are
//! libraries (`btc-p2p` protocol, `rsk-core` chain engine) with no CLI of
//! their own, so the node stays embeddable.
//!
//! Commands:
//!
//! ```text
//! rsk-cli probe [--addr <ip:port>] [--seed <host>] [--limit N]
//! ```
//!
//! `probe` reaches a real Bitcoin P2P peer over the mainnet DNS seeds, runs
//! the version/verack handshake, and pulls one real `headers` batch off
//! genesis — the smallest end-to-end proof that the network side works.

use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use bitcoin::Network;
use bitcoin::block::BlockHash;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use btc_p2p::seeds;
use btc_p2p::session::Session;

/// Who we are on the wire (BIP 14).
const USER_AGENT: &str = "/rsk-one:0.1.0/";

/// How many candidate peers to try before giving up.
const DEFAULT_TRY_LIMIT: usize = 8;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    let rest: Vec<String> = args.collect();
    match command.as_deref() {
        Some("probe") => probe(&rest),
        other => {
            eprintln!(
                "rsk-cli — the RSK One node\n\nusage: rsk-cli <command> [flags]\n\ncommands:\n  \
                 probe  contact a real Bitcoin P2P peer and prove headers flow\n\
                 \x20   [--addr <ip:port>] [--seed <host>] [--limit N]\n{}",
                other
                    .map(|c| format!("\nunknown command: {c}\n"))
                    .unwrap_or_default()
            );
            if other.is_some() {
                std::process::exit(2);
            }
            Ok(())
        }
    }
}

struct ProbeArgs {
    addrs: Vec<SocketAddr>,
    seeds: Vec<String>,
    limit: usize,
}

fn parse_probe_args(args: &[String]) -> Result<ProbeArgs> {
    let mut out = ProbeArgs {
        addrs: Vec::new(),
        seeds: Vec::new(),
        limit: DEFAULT_TRY_LIMIT,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                let raw = args.get(i).context("--addr needs a value")?;
                let addr = SocketAddr::from_str(raw).context(format!("bad --addr {raw:?}"))?;
                out.addrs.push(addr);
            }
            "--seed" => {
                i += 1;
                out.seeds
                    .push(args.get(i).context("--seed needs a value")?.clone());
            }
            "--limit" => {
                i += 1;
                out.limit = args.get(i).context("--limit needs a value")?.parse()?;
            }
            other => bail!("unknown flag {other:?} (try --help)"),
        }
        i += 1;
    }
    Ok(out)
}

fn probe(args: &[String]) -> Result<()> {
    let parsed = parse_probe_args(args)?;

    // Manual addresses come first; otherwise (and after them) the DNS seeds.
    let mut candidates = parsed.addrs;
    let seed_hosts: Vec<String> = if parsed.seeds.is_empty() {
        seeds::MAINNET_SEEDS.iter().map(|s| s.to_string()).collect()
    } else {
        parsed.seeds
    };
    let (resolved, failed) = resolve(&seed_hosts, seeds::DEFAULT_PORT);
    candidates.extend(resolved);
    candidates.sort();
    candidates.dedup();

    println!(
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

    for addr in candidates.into_iter().take(parsed.limit) {
        println!("trying {addr} …");
        match connect_probe(addr) {
            Ok(()) => return Ok(()),
            Err(e) => println!("  {addr} failed: {e:#}"),
        }
    }
    bail!("no peer answered within {} tries", parsed.limit)
}

/// Resolve seed hosts, reporting the failures alongside the addresses so the
/// caller can show both.
fn resolve(hosts: &[String], port: u16) -> (Vec<SocketAddr>, Vec<String>) {
    use std::net::ToSocketAddrs;
    let mut addrs = Vec::new();
    let mut failed = Vec::new();
    for host in hosts {
        match (host.as_str(), port).to_socket_addrs() {
            Ok(list) => addrs.extend(list),
            Err(e) => failed.push(format!("{host} ({e})")),
        }
    }
    addrs.sort();
    addrs.dedup();
    (addrs, failed)
}

/// Connect, handshake, and pull one real `headers` batch off genesis.
fn connect_probe(addr: SocketAddr) -> Result<()> {
    let (mut session, handshake) =
        Session::connect(addr, USER_AGENT, 0).context("connecting and handshaking")?;

    println!("  user agent:   {}", handshake.user_agent);
    println!("  version:      {}", handshake.version);
    println!("  services:     {}", handshake.services);
    println!("  best height:  {}", handshake.start_height);

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
    println!("  getheaders:   {} header(s) in one batch", headers.len());
    println!("  first:        {first}");
    println!("  last:         {last}");
    println!("probe ok: handshake and header flow work against {addr}");
    Ok(())
}
