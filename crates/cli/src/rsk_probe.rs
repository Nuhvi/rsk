//! `rsk-cli rsk-probe` — connect to a real Rootstock peer and read its tip.
//!
//! The RSK analogue of `probe`, reusing the vendored `rsk-p2p` stack: resolve a
//! bootnode, learn its node ID over signed UDP discovery (DNS bootnodes carry no
//! public key), run the RLPx + devp2p + `rsk/*` handshake, and print the peer's
//! status — best block number/hash and total difficulty. That is step 1 of the
//! RSK IBD design (find where peers are).

use std::net::SocketAddr;
use std::time::Duration;

use alloy_primitives::{B256, B512, Bytes, U256};
use anyhow::{Context, Result};
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{info, warn};

use rsk_p2p::discovery::{
    DiscoveryEndpoint, DiscoveryPacket, DiscoveryPayload, PingMessage, PongMessage,
};
use rsk_p2p::{Handshake, NodeConfig};

const MAINNET_GENESIS: &str = "0xf88529d4ab262c0f4d042e9d8d3f2472848eaafe1a9b7213f57617eb40a9f9e0";
const TESTNET_GENESIS: &str = "0xcabb7fbe88cd6d922042a32ffc08ce8b1fbb37d650b9d4e7dbfe2a7469adfa42";

#[derive(clap::Args)]
pub struct Args {
    /// Rootstock bootnode `host:port` to dial
    #[arg(long, default_value = "bootstrap01.rsk.co:5050")]
    host: String,

    /// Network: `mainnet` or `testnet`
    #[arg(long, default_value = "mainnet")]
    chain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chain {
    Mainnet,
    Testnet,
}

impl Chain {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "mainnet" => Ok(Chain::Mainnet),
            "testnet" => Ok(Chain::Testnet),
            other => anyhow::bail!("unknown chain {other:?} (mainnet|testnet)"),
        }
    }
    fn default_port(self) -> u16 {
        match self {
            Chain::Mainnet => 5050,
            Chain::Testnet => 50505,
        }
    }
    fn network_id(self) -> u64 {
        match self {
            Chain::Mainnet => 775,
            Chain::Testnet => 8100,
        }
    }
    fn chain_id(self) -> u8 {
        match self {
            Chain::Mainnet => 30,
            Chain::Testnet => 31,
        }
    }
    fn genesis_hash(self) -> B256 {
        match self {
            Chain::Mainnet => MAINNET_GENESIS.parse().expect("valid genesis hash"),
            Chain::Testnet => TESTNET_GENESIS.parse().expect("valid genesis hash"),
        }
    }
}

pub fn run(args: Args) -> Result<()> {
    let chain = Chain::parse(&args.chain)?;
    // The CLI is otherwise synchronous; RSK P2P lives on tokio, so drive just
    // this command on a runtime of its own.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    runtime.block_on(probe(&args.host, chain))
}

async fn probe(host: &str, chain: Chain) -> Result<()> {
    let addr = resolve(host, chain).await?;
    info!("target bootnode: {addr} ({chain:?})");

    let (secret_key, our_id) = make_identity();

    // Step 1: learn the peer's public key over signed UDP discovery.
    let peer_id = discover_node_id(&secret_key, addr).await?;
    info!("discovered node id: 0x{}…", hex(&peer_id.as_slice()[..8]));

    // Step 2: TCP + RLPx + devp2p + rsk status handshake.
    let config = NodeConfig {
        client_id: "rsk-one:0.1.0".to_string(),
        listen_port: 0,
        id: our_id,
        chain_id: chain.chain_id(),
        network_id: chain.network_id(),
        genesis_hash: chain.genesis_hash(),
        best_hash: chain.genesis_hash(),
        best_block_number: 0,
        best_block_parent_hash: None,
        total_difficulty: U256::ZERO,
        earliest_block: 0,
        snap_capability: false,
        bootnodes: vec![],
        closed_network: false,
        read_only: true,
        secret_key,
        discovery_port: 0,
        data_dir: ".".to_string(),
        external_ip: None,
        max_outbound_peers: 8,
        max_inbound_peers: 0,
        max_inbound_per_ip: 0,
        max_inbound_per_cidr: 0,
        inbound_cidr_prefix: 24,
    };

    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("TCP connect to {addr}"))?;
    let handshake = Handshake::new(stream, config, Some(peer_id));
    let (_peer, status, caps, _framed) = timeout(Duration::from_secs(15), handshake.run())
        .await
        .context("RLPx/p2p handshake timed out")??;

    info!(
        "negotiated:    rsk/{} (snap: {})",
        caps.rsk_version, caps.snap
    );
    info!(
        "peer tip:      block {} 0x{}",
        status.best_block_number,
        hex(&status.best_block_hash.as_slice()[..8])
    );
    match status.total_difficulty {
        Some(td) => info!("total difficulty: {td}"),
        None => warn!("peer did not report total difficulty"),
    }
    Ok(())
}

/// Split `host:port` (defaulting the port for the chain) and resolve the host,
/// preferring IPv4.
async fn resolve(host: &str, chain: Chain) -> Result<SocketAddr> {
    let (host, port) = match host.rsplit_once(':') {
        Some((h, p)) => (h, p.parse()?),
        None => (host, chain.default_port()),
    };
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}:{port}"))?;
    addrs
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.next())
        .with_context(|| format!("no address for {host}:{port}"))
}

/// A one-shot node identity: a random secp256k1 key, `id` = its uncompressed
/// public key (what devp2p's `HelloMessage` carries).
fn make_identity() -> ([u8; 32], B512) {
    let sk = SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let encoded = sk.public_key().to_encoded_point(false);
    let mut pk = [0u8; 64];
    pk.copy_from_slice(&encoded.as_bytes()[1..]);
    (sk.to_bytes().into(), B512::from_slice(&pk))
}

/// Send a signed UDP discovery `Ping` and read back the `Pong`, recovering the
/// peer's node ID from the packet signature. Retries, answering any `Ping` we
/// receive with a `Pong` (courtesy, as a real node does).
async fn discover_node_id(secret_key: &[u8; 32], addr: SocketAddr) -> Result<B512> {
    use k256::ecdsa::SigningKey;
    let key = SigningKey::from_slice(&secret_key[..])?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local = socket.local_addr()?;

    for attempt in 1..=5 {
        let message_id = uuid::Uuid::new_v4().to_string();
        let ping = PingMessage {
            from: DiscoveryEndpoint {
                ip: Bytes::from(vec![127, 0, 0, 1]),
                udp_port: local.port(),
                tcp_port: local.port(),
            },
            to: addr_to_endpoint(addr),
            message_id: message_id.clone(),
            network_id: 775,
        };
        let packet = DiscoveryPacket::create(DiscoveryPayload::Ping(ping.clone()), &key)?;
        socket.send_to(&packet.encode(), addr).await?;
        info!("  pinged {addr} (attempt {attempt})…");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        let mut buf = vec![0u8; 4096];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) if from == addr => match DiscoveryPacket::decode(&buf[..len]) {
                    Ok(packet) => match packet.payload {
                        DiscoveryPayload::Pong(_) => {
                            return packet.recover_id().context("recovering node id from pong");
                        }
                        DiscoveryPayload::Ping(_) => {
                            let reply = DiscoveryPacket::create(
                                DiscoveryPayload::Pong(PongMessage {
                                    from: ping.from.clone(),
                                    to: ping.to.clone(),
                                    message_id: message_id.clone(),
                                    network_id: 775,
                                }),
                                &key,
                            )?;
                            let _ = socket.send_to(&reply.encode(), addr).await;
                        }
                        _ => {}
                    },
                    Err(e) => warn!("  discovery decode error: {e}"),
                },
                _ => break,
            }
        }
    }
    anyhow::bail!("could not learn {addr}'s node id over discovery")
}

fn addr_to_endpoint(addr: SocketAddr) -> DiscoveryEndpoint {
    DiscoveryEndpoint {
        ip: match addr {
            SocketAddr::V4(v4) => Bytes::from(v4.ip().octets().to_vec()),
            SocketAddr::V6(v6) => Bytes::from(v6.ip().octets().to_vec()),
        },
        udp_port: addr.port(),
        tcp_port: addr.port(),
    }
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
