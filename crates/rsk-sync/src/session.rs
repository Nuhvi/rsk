//! One peer connection: find the node, handshake, and drive the walk's message
//! pipeline over it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use alloy_primitives::{B256, B512, U256};
use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt};
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use rsk_consensus::checkpoint::{judge, CheckpointVerdict};
use rsk_p2p::discovery::{
    DiscoveryEndpoint, DiscoveryPacket, DiscoveryPayload, PingMessage, PongMessage,
};
use rsk_p2p::protocol::{
    BlockHeadersQuery, BlockHeadersRequest, P2pMessage, RskMessage, RskSubMessage, SkeletonRequest,
};
use rsk_p2p::{Handshake, HandshakeCodec, NodeConfig, PeerCapabilities, RskStatus};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use crate::config::SyncConfig;
use crate::walk::{HeaderWalk, Want};

/// A connected, handshaken, status-gated peer.
pub struct PeerConnection {
    pub framed: Framed<TcpStream, HandshakeCodec>,
    pub peer_id: B512,
    pub caps: PeerCapabilities,
    pub status: RskStatus,
}

/// A one-shot node identity: random secp256k1 key + uncompressed public key.
pub fn make_identity() -> ([u8; 32], B512) {
    let sk = SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let encoded = sk.public_key().to_encoded_point(false);
    let mut pk = [0u8; 64];
    pk.copy_from_slice(&encoded.as_bytes()[1..]);
    (sk.to_bytes().into(), B512::from_slice(&pk))
}

fn chain_p2p_port(chain_id: u8) -> u16 {
    match chain_id {
        30 => 5050,
        31 => 50505,
        _ => 5050,
    }
}

/// Split `host:port`, defaulting the port for the chain, and resolve to a
/// socket address (preferring IPv4).
async fn resolve(host: &str, port_default: u16) -> Result<SocketAddr> {
    let (host, port) = match host.rsplit_once(':') {
        Some((h, p)) => (h, p.parse()?),
        None => (host, port_default),
    };
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.next())
        .with_context(|| format!("no address for {host}:{port}"))
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

/// Learn a bootnode's node ID by sending a signed UDP discovery ping and
/// recovering the signer of the pong. Bootnode DNS entries carry no pubkey, so
/// there is no other way to dial one.
async fn discover_node_id(
    sk: &k256::ecdsa::SigningKey,
    addr: SocketAddr,
    network_id: u32,
) -> Result<B512> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local = socket.local_addr()?;

    for attempt in 1..=6 {
        let message_id = uuid::Uuid::new_v4().to_string();
        let ping = PingMessage {
            from: DiscoveryEndpoint {
                ip: alloy_primitives::Bytes::from(vec![127, 0, 0, 1]),
                udp_port: local.port(),
                tcp_port: local.port(),
            },
            to: addr_to_endpoint(addr),
            message_id: message_id.clone(),
            network_id,
        };
        let packet = DiscoveryPacket::create(DiscoveryPayload::Ping(ping.clone()), sk)?;
        socket.send_to(&packet.encode(), addr).await?;

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
                            return packet
                                .recover_id()
                                .with_context(|| "recovering node id from pong");
                        }
                        DiscoveryPayload::Ping(_) => {
                            let reply = DiscoveryPacket::create(
                                DiscoveryPayload::Pong(PongMessage {
                                    from: ping.from.clone(),
                                    to: ping.to.clone(),
                                    message_id: message_id.clone(),
                                    network_id,
                                }),
                                sk,
                            )?;
                            let _ = socket.send_to(&reply.encode(), addr).await;
                        }
                        _ => {}
                    },
                    Err(e) => debug!("discovery decode error: {e}"),
                },
                _ => break,
            }
        }
        debug!("discovery: no pong from {addr} (attempt {attempt})");
    }
    Err(anyhow!("could not learn {addr}'s node id over discovery"))
}

fn node_config_for(config: &SyncConfig, sk: &[u8; 32], our_id: B512) -> NodeConfig {
    NodeConfig {
        client_id: "rsk-one-light".to_string(),
        listen_port: 0,
        id: our_id,
        chain_id: config.chain.chain_id,
        network_id: config.chain.network_id,
        genesis_hash: config.genesis_hash,
        best_hash: config.genesis_hash,
        best_block_number: 0,
        best_block_parent_hash: None,
        total_difficulty: U256::ZERO,
        earliest_block: 0,
        snap_capability: false,
        bootnodes: vec![],
        closed_network: false,
        read_only: true,
        secret_key: *sk,
        discovery_port: 0,
        data_dir: String::new(),
        external_ip: None,
        max_outbound_peers: 8,
        max_inbound_peers: 0,
        max_inbound_per_ip: 0,
        max_inbound_per_cidr: 0,
        inbound_cidr_prefix: 24,
    }
}

/// Try the configured bootnodes in order until one hands us a handshaken,
/// status-gated connection.
pub async fn dial(config: &SyncConfig) -> Result<PeerConnection> {
    let (sk_bytes, our_id) = make_identity();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&sk_bytes[..])?;
    let network_id = config.chain.network_id as u32;
    let port_default = chain_p2p_port(config.chain.chain_id);

    let mut last_err: Option<anyhow::Error> = None;
    for node in &config.bootnodes {
        let addr = match resolve(node, port_default).await {
            Ok(a) => a,
            Err(e) => {
                warn!(%e, node, "bootnode resolution failed");
                last_err = Some(e);
                continue;
            }
        };

        let peer_id = match discover_node_id(&signing_key, addr, network_id).await {
            Ok(id) => id,
            Err(e) => {
                warn!(%e, node, "discovery failed");
                last_err = Some(e);
                continue;
            }
        };

        let stream = match timeout(config.handshake_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!(%e, node, "TCP connect failed");
                last_err = Some(e.into());
                continue;
            }
            Err(_) => {
                last_err = Some(anyhow!("TCP connect to {node} timed out"));
                continue;
            }
        };

        let nc = node_config_for(config, &sk_bytes, our_id);
        let handshake = Handshake::new(stream, nc, Some(peer_id));
        match timeout(
            config.handshake_timeout + Duration::from_secs(5),
            handshake.run(),
        )
        .await
        {
            Ok(Ok((got_id, status, caps, framed))) => match gate_status(&status, config) {
                Ok(()) => {
                    info!(
                        peer = %hex(&got_id.as_slice()[..6]),
                        best = status.best_block_number,
                        td = ?status.total_difficulty,
                        "connected to peer"
                    );
                    return Ok(PeerConnection {
                        framed,
                        peer_id: got_id,
                        caps,
                        status,
                    });
                }
                Err(e) => {
                    warn!(%e, node, "peer rejected by checkpoint gate");
                    last_err = Some(e);
                }
            },
            Ok(Err(e)) => {
                warn!(%e, node, "handshake failed");
                last_err = Some(e);
            }
            Err(_) => {
                last_err = Some(anyhow!("handshake to {node} timed out"));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("no bootnodes configured")))
}

/// Cheap, sound pre-filter: a peer at/below the checkpoint can't have enough
/// work to matter, and one above it can't claim more than the checkpoint's
/// ceiling allows (loosest bound — no uncle samples yet — which never refuses
/// an honest chain).
fn gate_status(status: &RskStatus, config: &SyncConfig) -> Result<()> {
    let head = status.best_block_number;
    let cp = &config.checkpoint;
    if head < cp.number {
        return Err(anyhow!(
            "peer at block {head}, below our checkpoint {}",
            cp.number
        ));
    }
    let claimed = status.total_difficulty.unwrap_or_default();
    match judge(cp, claimed, &[], head, 400, config.chain.min_difficulty) {
        CheckpointVerdict::Impossible { claimed, ceiling } => Err(anyhow!(
            "peer claims {claimed} work at {head}, over the ceiling {ceiling}"
        )),
        _ => Ok(()),
    }
}

/// A per-connection message loop that keeps a `HeaderWalk` fed.
pub struct SessionLoop<'a> {
    framed: &'a mut Framed<TcpStream, HandshakeCodec>,
    walk: &'a mut HeaderWalk,
    id: u64,
    outstanding: HashMap<u64, Want>,
    pipeline: usize,
    read_timeout: Duration,
    // A peer stuck off our chain answers every request promptly without the
    // walk ever linking — frontier never moves. Count responses since the last
    // move and treat a large run as a stall rather than spinning forever.
    last_frontier: u64,
    no_progress: u32,
    // Progress logging: log every time the frontier has dropped by this much.
    progress_marker: u64,
}

const STALL_LIMIT: u32 = 1500;
const PROGRESS_STEP: u64 = 20_000;

impl<'a> SessionLoop<'a> {
    pub fn new(
        framed: &'a mut Framed<TcpStream, HandshakeCodec>,
        walk: &'a mut HeaderWalk,
        pipeline: usize,
        read_timeout: Duration,
    ) -> Self {
        let last_frontier = walk.frontier();
        Self {
            framed,
            walk,
            id: 0,
            outstanding: HashMap::new(),
            pipeline,
            read_timeout,
            last_frontier,
            no_progress: 0,
            progress_marker: last_frontier,
        }
    }

    /// Refill the pipeline, wait for one response, and feed the walk.
    /// Returns `Ok(true)` once the walk is done.
    pub async fn step(&mut self) -> Result<bool> {
        self.pump().await?;
        if self.walk.is_done() {
            return Ok(true);
        }

        let msg = match timeout(self.read_timeout, self.framed.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => return Err(e.context("session read")),
            Ok(None) => return Err(anyhow!("peer closed the connection")),
            Err(_) => return Err(anyhow!("no response within {:?}", self.read_timeout)),
        };

        self.dispatch(msg).await?;
        let _ = self.walk.advance()?;

        let frontier = self.walk.frontier();
        if frontier == self.last_frontier {
            self.no_progress += 1;
            if self.no_progress > STALL_LIMIT {
                return Err(anyhow!(
                    "no chain progress for {STALL_LIMIT} responses at height {frontier} \
                     (peer may be on a fork)"
                ));
            }
        } else {
            self.no_progress = 0;
            self.last_frontier = frontier;
        }

        if self.progress_marker - frontier >= PROGRESS_STEP {
            self.progress_marker = frontier;
            let remaining = match self.walk.floor_number() {
                Some(floor) => frontier.saturating_sub(floor),
                None => frontier,
            };
            info!(
                frontier,
                remaining_to_floor = remaining,
                in_flight = self.outstanding.len(),
                "header walk progress"
            );
        }

        Ok(self.walk.is_done())
    }

    /// Give up on everything in flight so the same walk can be retried over a
    /// fresh connection.
    pub fn release_all(&mut self) {
        for want in self.outstanding.drain().map(|(_, w)| w) {
            self.walk.release(&want);
        }
    }

    async fn pump(&mut self) -> Result<()> {
        while self.outstanding.len() < self.pipeline {
            let Some(want) = self.walk.wants(1).pop() else {
                break;
            };
            let id = self.next_id();
            let msg = match &want {
                Want::Skeleton { start } => {
                    RskMessage::new(RskSubMessage::SkeletonRequest(SkeletonRequest {
                        id,
                        start_number: *start,
                    }))
                }
                Want::Headers { from, count, .. } => {
                    RskMessage::new(RskSubMessage::BlockHeadersRequest(BlockHeadersRequest {
                        id,
                        query: BlockHeadersQuery {
                            hash: *from,
                            count: *count,
                        },
                    }))
                }
            };
            self.framed
                .send(P2pMessage::RskMessage(msg))
                .await
                .context("send request")?;
            debug!(id, ?want, "request sent");
            self.outstanding.insert(id, want);
        }
        Ok(())
    }

    async fn dispatch(&mut self, msg: P2pMessage) -> Result<()> {
        match msg {
            P2pMessage::Ping => {
                self.framed.send(P2pMessage::Pong).await.ok();
            }
            P2pMessage::Pong | P2pMessage::Hello(_) | P2pMessage::Disconnect(_) => {}
            P2pMessage::RskMessage(m) => match m.sub_message {
                RskSubMessage::SkeletonResponse(r) => {
                    if let Some(Want::Skeleton { .. }) = self.outstanding.remove(&r.id) {
                        debug!(
                            id = r.id,
                            points = r.block_identifiers.len(),
                            "skeleton response"
                        );
                        self.walk.on_skeleton(&r.block_identifiers);
                    }
                }
                RskSubMessage::BlockHeadersResponse(r) => {
                    if let Some(Want::Headers { point, .. }) = self.outstanding.remove(&r.id) {
                        debug!(
                            id = r.id,
                            point,
                            headers = r.headers.len(),
                            "headers response"
                        );
                        let headers: Vec<_> = r
                            .headers
                            .into_iter()
                            .zip(r.raw.into_iter().map(|b| b.to_vec()))
                            .collect();
                        self.walk.on_headers(point, &headers, &HashMap::new())?;
                    }
                }
                RskSubMessage::NewBlockHashes(ids) => {
                    if let Some(top) = ids.last() {
                        debug!(block = top.number, "new block announcement");
                    }
                }
                RskSubMessage::Status(_) | RskSubMessage::Unknown(_) => {}
                other => debug!(?other, "unexpected rsk message"),
            },
            other => debug!(?other, "unexpected p2p message"),
        }
        Ok(())
    }

    fn next_id(&mut self) -> u64 {
        self.id += 1;
        self.id
    }
}

/// Fetch the header at a hash with a single-header request. Used to get the
/// walk's starting `Header` object from the peer's advertised best block.
pub async fn fetch_top_header(
    framed: &mut Framed<TcpStream, HandshakeCodec>,
    hash: B256,
    id: u64,
    read_timeout: Duration,
) -> Result<rsk_consensus::Header> {
    let req = RskMessage::new(RskSubMessage::BlockHeadersRequest(BlockHeadersRequest {
        id,
        query: BlockHeadersQuery { hash, count: 1 },
    }));
    framed
        .send(P2pMessage::RskMessage(req))
        .await
        .context("send top-header request")?;

    loop {
        let msg = timeout(read_timeout, framed.next())
            .await
            .context("waiting for top header")?
            .context("peer closed while fetching top header")??;
        match msg {
            P2pMessage::Ping => {
                framed.send(P2pMessage::Pong).await.ok();
            }
            P2pMessage::RskMessage(m) => match m.sub_message {
                RskSubMessage::BlockHeadersResponse(r) if r.id == id => {
                    let header = r
                        .headers
                        .into_iter()
                        .next()
                        .ok_or_else(|| anyhow!("peer returned no header for {hash:#x}"))?;
                    return Ok(header);
                }
                _ => {}
            },
            _ => {}
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
