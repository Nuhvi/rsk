//! Dial an RSK node from a bare `host:port` bootnode and read its status.
//!
//! Bootnodes in rskj's DNS list carry no node ID, so the node's public key has
//! to be learned first. This example does the two-step dance a real client
//! would:
//!
//! 1. resolve the host to a socket address,
//! 2. send a signed UDP discovery `Ping` and read back the `Pong`, recovering
//!    the peer's node ID from the packet signature,
//! 3. open a TCP connection and run the RLPx + devp2p + `rsk/62` handshake,
//!    which verifies the peer's genesis hash against ours,
//! 4. report the peer's status (`bestBlockNumber`, `bestBlockHash`,
//!    `totalDifficulty`) and exchange a `Ping`/`Pong` to prove the session is
//!    alive end to end.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p rsk-p2p --example connect \
//!   -- --host bootstrap01.rsk.co:5050 --chain mainnet
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use alloy_primitives::{B256, B512, U256};
use futures::{SinkExt, StreamExt};
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use rsk_p2p::discovery::{
    DiscoveryEndpoint, DiscoveryPacket, DiscoveryPayload, PingMessage,
};
use rsk_p2p::protocol::{P2pMessage, RskSubMessage};
use rsk_p2p::{Handshake, NodeConfig};

const MAINNET_GENESIS: &str = "0xf88529d4ab262c0f4d042e9d8d3f2472848eaafe1a9b7213f57617eb40a9f9e0";
const TESTNET_GENESIS: &str = "0xcabb7fbe88cd6d922042a32ffc08ce8b1fbb37d650b9d4e7dbfe2a7469adfa42";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chain {
    Mainnet,
    Testnet,
}

impl Chain {
    fn rpc_port_default(self) -> u16 {
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
    fn genesis_hash(self) -> B256 {
        match self {
            Chain::Mainnet => MAINNET_GENESIS.parse().unwrap(),
            Chain::Testnet => TESTNET_GENESIS.parse().unwrap(),
        }
    }
}

/// A one-shot node identity: a random secp256k1 secret key, with `id` set to
/// its uncompressed public key (what devp2p's `HelloMessage` carries).
fn make_identity() -> ([u8; 32], B512) {
    let sk = SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let encoded = sk.public_key().to_encoded_point(false);
    let mut pk = [0u8; 64];
    pk.copy_from_slice(&encoded.as_bytes()[1..]);
    (sk.to_bytes().into(), B512::from_slice(&pk))
}

/// Split `host:port` (defaulting the port for the chain) and resolve the host
/// to a socket address, preferring IPv4.
async fn resolve(host: &str, chain: Chain) -> Result<SocketAddr> {
    let (host, port) = match host.rsplit_once(':') {
        Some((h, p)) => (h, p.parse()?),
        None => (host, chain.rpc_port_default()),
    };
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    let addr = addrs
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.next())
        .with_context(|| format!("no address for {host}:{port}"))?;
    Ok(addr)
}

/// Send a UDP discovery `Ping` to `addr` and wait for the `Pong`, returning
/// the sender's recovered node ID. Retries because bootnodes are busy and
/// packets are dropped. Answers any `Ping` we receive with a `Pong` (courtesy,
/// same as a real node), and keeps draining the socket for the whole attempt.
async fn discover_node_id(sk_bytes: &[u8; 32], addr: SocketAddr) -> Result<B512> {
    use k256::ecdsa::SigningKey;
    let key = SigningKey::from_slice(&sk_bytes[..])?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local = socket.local_addr()?;

    for attempt in 1..=5 {
        let message_id = uuid::Uuid::new_v4().to_string();
        let ping = PingMessage {
            from: DiscoveryEndpoint {
                ip: alloy_primitives::Bytes::from(vec![127, 0, 0, 1]),
                udp_port: local.port(),
                tcp_port: local.port(),
            },
            to: addr_to_endpoint(addr),
            message_id: message_id.clone(),
            network_id: 775, // RSK discovery carries the chain's network id
        };
        let packet = DiscoveryPacket::create(DiscoveryPayload::Ping(ping.clone()), &key)?;
        socket.send_to(&packet.encode(), addr).await?;
        eprintln!("  pinged {addr} (attempt {attempt})…");

        // Drain the socket for the attempt: the peer may reply with its own
        // Ping (which we answer), an unrelated packet, or finally the Pong we
        // are waiting for.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        let mut buf = vec![0u8; 4096];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) if from == addr => {
                    match DiscoveryPacket::decode(&buf[..len]) {
                        Ok(packet) => match packet.payload {
                            DiscoveryPayload::Pong(_) => {
                                return packet
                                    .recover_id()
                                    .with_context(|| "recovering node id from pong");
                            }
                            DiscoveryPayload::Ping(_) => {
                                let pong = DiscoveryEndpoint {
                                    ip: ping.from.ip.clone(),
                                    udp_port: ping.from.udp_port,
                                    tcp_port: ping.from.tcp_port,
                                };
                                let reply = DiscoveryPacket::create(
                                    DiscoveryPayload::Pong(rsk_p2p::discovery::PongMessage {
                                        from: pong.clone(),
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
                        Err(e) => eprintln!("  discovery decode error: {e}"),
                    }
                }
                _ => break,
            }
        }
    }
    Err(anyhow::anyhow!("could not learn {addr}'s node id over discovery"))
}

fn addr_to_endpoint(addr: SocketAddr) -> DiscoveryEndpoint {
    DiscoveryEndpoint {
        ip: match addr {
            SocketAddr::V4(v4) => alloy_primitives::Bytes::from(v4.ip().octets().to_vec()),
            SocketAddr::V6(v6) => alloy_primitives::Bytes::from(v6.ip().octets().to_vec()),
        },
        udp_port: addr.port(),
        tcp_port: addr.port(),
    }
}

async fn run(host: &str, chain: Chain) -> Result<()> {
    let addr = resolve(host, chain).await?;
    println!("target bootnode: {addr} ({chain:?})");

    let (sk_bytes, our_id) = make_identity();

    // Step 1: learn the peer's public key over UDP discovery.
    println!("pinging discovery…");
    let peer_id = discover_node_id(&sk_bytes, addr).await?;
    println!(
        "discovered node id: 0x{}…",
        hex(&peer_id.as_slice()[..8])
    );

    // Step 2: TCP + RLPx + devp2p + rsk status handshake.
    let config = NodeConfig {
        client_id: "rsk-one-light".to_string(),
        listen_port: 0,
        id: our_id,
        chain_id: match chain {
            Chain::Mainnet => 30,
            Chain::Testnet => 31,
        },
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
        secret_key: sk_bytes,
        discovery_port: 0,
        data_dir: ".".to_string(),
        external_ip: None,
        max_outbound_peers: 8,
        max_inbound_peers: 0,
        max_inbound_per_ip: 0,
        max_inbound_per_cidr: 0,
        inbound_cidr_prefix: 24,
    };

    println!("connecting…");
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("TCP connect to {addr}"))?;

    let handshake = Handshake::new(stream, config, Some(peer_id));
    let (handled_peer, status, caps, mut framed) = timeout(Duration::from_secs(15), handshake.run())
        .await
        .context("RLPx/p2p handshake timed out")??;

    println!("----------------------------------------");
    println!("connected to peer:  0x{}…", hex(&handled_peer.as_slice()[..8]));
    println!("negotiated:         rsk/{} (snap: {})", caps.rsk_version, caps.snap);
    println!(
        "peer status:         block {} 0x{}…",
        status.best_block_number,
        hex(&status.best_block_hash.as_slice()[..8])
    );
    match status.total_difficulty {
        Some(td) => println!("peer total difficulty:  {td}"),
        None => println!("peer total difficulty:  (unset in status)"),
    }
    match status.earliest_block {
        Some(e) => println!("peer served range:     from block {e}"),
        None => println!("peer served range:     everything (rskj peer)"),
    }
    if status.best_block_hash == chain.genesis_hash() {
        println!("peer is at genesis (unlikely for mainnet — check your bootnode)");
    }
    println!("----------------------------------------");

    // Step 3: prove the session is alive. Send Ping, then watch for messages
    // (the peer may send us a Ping, a Pong, or NewBlockHashes) for a moment.
    framed.send(P2pMessage::Ping).await?;
    for _ in 0..4 {
        match timeout(Duration::from_secs(5), framed.next()).await {
            Ok(Some(Ok(P2pMessage::Pong))) => println!("got Pong ✓"),
            Ok(Some(Ok(P2pMessage::Ping))) => {
                framed.send(P2pMessage::Pong).await?;
                println!("peer sent Ping, replied Pong ✓");
            }
            Ok(Some(Ok(P2pMessage::RskMessage(m)))) => match m.sub_message {
                RskSubMessage::NewBlockHashes(ids) => {
                    println!("NewBlockHashes: {} announcements", ids.len());
                    if let Some(top) = ids.last() {
                        println!("  newest: block {} 0x{}…", top.number, hex(&top.hash.as_slice()[..8]));
                    }
                }
                other => println!("rsk message: {other:?}"),
            },
            Ok(Some(Ok(other))) => println!("message: {other:?}"),
            Ok(Some(Err(e))) => {
                eprintln!("session error: {e}");
                break;
            }
            Ok(None) | Err(_) => break,
        }
    }

    println!("done");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut host = String::new();
    let mut chain = Chain::Mainnet;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                i += 1;
                host = args.get(i).cloned().unwrap_or_default();
            }
            "--chain" => {
                i += 1;
                chain = match args.get(i).map(|s| s.as_str()) {
                    Some("testnet") => Chain::Testnet,
                    _ => Chain::Mainnet,
                };
            }
            _ => {}
        }
        i += 1;
    }
    if host.is_empty() {
        eprintln!("usage: connect --host <host:port> [--chain mainnet|testnet]");
        std::process::exit(2);
    }

    match run(&host, chain).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}