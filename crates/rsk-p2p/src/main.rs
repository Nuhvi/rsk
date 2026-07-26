mod codec;
mod config;
mod discv4;
mod ecies;
mod error;
mod hash_mac;
mod handshake;
mod messages;
mod secret;

use config::RskNetwork;
use discv4::{Discovery, DiscoveredNode, lookup};
use futures::{SinkExt, StreamExt};
use log::{error, info, warn};
use secp256k1::SecretKey;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::{
    codec::Codec,
    error::{Error, Result},
    handshake::Handshake,
    messages::{Message, Status},
};

/// RSK P2P Header Sync PoC
///
/// Connects to RSK nodes via Ethereum devp2p/RLPx protocol
/// and fetches block headers using automatic peer discovery.
///
/// Usage: rsk-p2p [enode_url]
/// If no enode URL provided, uses discv4 to discover peers from bootstrap nodes.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        unsafe { std::env::set_var("RUST_LOG", "debug") };
    }

    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let network = RskNetwork::mainnet();
    
    info!(
        "RSK P2P Header Sync - {} (network_id: {})",
        network.name, network.network_id
    );

    // Generate a temporary private key for discovery
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    
    // Create discovery service on a random port
    let discovery = Discovery::new(
        private_key,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    ).await?;
    
    info!("Local node ID: {}", hex::encode(discovery.local_node_id()));
    
    if args.len() >= 2 {
        // Direct connection mode (existing behavior)
        let enode_url = &args[1];
        let (node_id, host, port) = parse_enode_url(enode_url)?;
        
        info!("Connecting to specified node: {}:{}", host, port);
        connect_and_fetch(&node_id, &host, port, &network).await?;
    } else {
        // Discovery mode - find peers via discv4
        info!("Starting peer discovery via discv4...");
        
        let bootstrap_addrs: Vec<(Ipv4Addr, u16)> = network.bootstrap_nodes
            .iter()
            .map(|n| (n.ip, n.port))
            .collect();
        
        info!("Using {} bootstrap nodes", bootstrap_addrs.len());
        
        // First, ping all bootstrap nodes to establish endpoint proof
        info!("Sending Ping to bootstrap nodes...");
        let mut ping_hashes: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        
        for (ip, port) in &bootstrap_addrs {
            let addr = SocketAddr::new((*ip).into(), *port);
            match discovery.send_ping(addr).await {
                Ok(hash) => {
                    info!("Ping sent to {}", addr);
                    ping_hashes.push((addr, hash));
                }
                Err(e) => {
                    warn!("Failed to ping {}: {}", addr, e);
                }
            }
        }
        
        // Wait for Pong responses
        info!("Waiting for Pong responses...");
        let mut all_nodes: Vec<DiscoveredNode> = Vec::new();
        
        for _ in 0..20 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                discovery.recv(),
            ).await {
                Ok(Ok((packet, from, _, ping_hash))) => {
                    match packet {
                        discv4::Packet::Pong(_pong) => {
                            info!("Pong received from {}", from);
                            // Now that we have endpoint proof, send FindNode
                            let local_node_id = *discovery.local_node_id();
                            if let Err(e) = discovery.send_find_node(from, &local_node_id).await {
                                warn!("Failed to send FindNode to {}: {}", from, e);
                            } else {
                                info!("FindNode sent to {}", from);
                            }
                        }
                        discv4::Packet::Neighbors(neighbors) => {
                            info!("Received {} neighbors from {}", neighbors.nodes.len(), from);
                            for node in &neighbors.nodes {
                                if node.ip.len() == 4 {
                                    let ip = Ipv4Addr::new(node.ip[0], node.ip[1], node.ip[2], node.ip[3]);
                                    let mut node_id = [0u8; 64];
                                    let copy_len = node.node_id.len().min(64);
                                    node_id[..copy_len].copy_from_slice(&node.node_id[..copy_len]);
                                    
                                    all_nodes.push(DiscoveredNode {
                                        node_id,
                                        ip,
                                        udp_port: node.udp_port,
                                        tcp_port: node.tcp_port,
                                    });
                                }
                            }
                        }
                        discv4::Packet::Ping(_ping) => {
                            info!("Ping received from {}, sending Pong", from);
                            if let Err(e) = discovery.send_pong(from, &ping_hash).await {
                                warn!("Failed to send Pong: {}", e);
                            }
                        }
                        _ => {
                            info!("Other packet from {}: {:?}", from, std::mem::discriminant(&packet));
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("Error receiving: {}", e);
                }
                Err(_) => {
                    break;
                }
            }
        }
        
        // Also try a lookup with a random target to discover more nodes
        info!("Performing Kademlia lookup...");
        let random_target = [0x01u8; 64]; // Use a simple target for bootstrap
        match lookup(&discovery, &bootstrap_addrs, &random_target).await {
            Ok(nodes) => {
                info!("Lookup returned {} nodes", nodes.len());
                all_nodes.extend(nodes);
            }
            Err(e) => {
                warn!("Lookup failed: {}", e);
            }
        }
        
        info!("Total discovered nodes: {}", all_nodes.len());
        
        // Deduplicate by IP
        let mut seen = std::collections::HashSet::new();
        all_nodes.retain(|n| seen.insert(n.ip));
        
        // Try to connect to discovered nodes
        for node in &all_nodes {
            if node.tcp_port == 0 {
                continue;
            }
            
            info!(
                "Trying to connect to discovered node {}:{}",
                node.ip, node.tcp_port
            );
            
            match connect_and_fetch(&node.node_id, &node.ip.to_string(), node.tcp_port, &network).await {
                Ok(()) => {
                    info!("Successfully connected to {}", node.ip);
                    break;
                }
                Err(e) => {
                    warn!("Failed to connect to {}: {}", node.ip, e);
                }
            }
        }
        
        if all_nodes.is_empty() {
            warn!("No nodes discovered. Bootstrap nodes may not be responding to discv4.");
            warn!("Try running an RSKj node to get an enode URL, then use: rsk-p2p enode://...");
        }
    }

    Ok(())
}

/// Connect to a node and perform RLPx handshake + fetch headers
async fn connect_and_fetch(
    node_id: &[u8; 64],
    host: &str,
    port: u16,
    network: &RskNetwork,
) -> Result<()> {
    let mut public_key_bytes = [4_u8; 65];
    public_key_bytes[1..].copy_from_slice(node_id);
    let public_key = secp256k1::PublicKey::from_slice(&public_key_bytes)
        .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let handshake = Handshake::new(private_key, public_key);
    
    let addr = format!("{}:{}", host, port)
        .to_socket_addrs()
        .map_err(|e| Error::InvalidInput(e.to_string()))?
        .next()
        .ok_or_else(|| Error::InvalidInput("No addresses found".to_string()))?;

    let stream = TcpStream::connect(addr).await?;
    let mut framed = Framed::new(stream, Codec::new(handshake));

    framed.send(Message::Auth).await?;
    info!("Auth message sent to {}", addr);

    while let Some(message) = framed.next().await {
        match message {
            Ok(frame) => match frame {
                Message::Auth => {}
                Message::AuthAck => {
                    info!("AuthAck received, sending Hello");
                    framed.send(Message::Hello).await?;
                }
                Message::Hello => {
                    info!("Hello received, sending Status");
                    framed
                        .send(Message::Status(Status {
                            version: 66,
                            networkid: network.network_id,
                            td: 1,
                            blockhash: network.genesis_hash.into(),
                            genesis: network.genesis_hash.into(),
                            forkid: crate::messages::ForkId {
                                hash: network.fork_id.hash,
                                next: network.fork_id.next,
                            },
                        }))
                        .await?;
                }
                Message::Ping => {
                    info!("Ping received, sending Pong");
                    framed.send(Message::Pong).await?;
                }
                Message::Pong => {
                    info!("Pong received");
                }
                Message::Status(ref msg) => {
                    info!("Status received: {:?}", msg);
                    framed
                        .send(Message::GetBlockHeaders(
                            crate::messages::GetBlockHeaders {
                                request_id: 1,
                                query: crate::messages::BlockHeadersQuery {
                                    block: alloy_rlp::encode(1u64).to_vec(),
                                    skip: 0,
                                    limit: 10,
                                    reverse: false,
                                },
                            },
                        ))
                        .await?;
                    info!("GetBlockHeaders request sent");
                }
                Message::BlockHeaders(ref headers) => {
                    info!(
                        "BlockHeaders received: {} headers",
                        headers.headers.len()
                    );
                    for (i, header) in headers.headers.iter().enumerate() {
                        info!("Header {}: {} bytes", i, header.len());
                    }
                    break;
                }
                Message::BlockBodies(ref bodies) => {
                    info!(
                        "BlockBodies received: {} bodies",
                        bodies.bodies.len()
                    );
                }
                Message::Disconnect(reason) => {
                    info!("Disconnected: {}", reason);
                    break;
                }
                _ => {
                    warn!("Unhandled message: {:?}", frame);
                }
            },
            Err(e) => {
                error!("Error receiving message: {e}");
                break;
            }
        }
    }

    Ok(())
}

/// Parse an enode URL: enode://<hex_node_id>@<host>:<port>
fn parse_enode_url(url: &str) -> Result<([u8; 64], String, u16)> {
    let url = url
        .strip_prefix("enode://")
        .ok_or_else(|| Error::InvalidInput("URL must start with enode://".to_string()))?;

    let (id_part, host_part) = url
        .split_once('@')
        .ok_or_else(|| Error::InvalidInput("URL must contain @".to_string()))?;

    let node_id_hex = id_part
        .strip_prefix("0x")
        .unwrap_or(id_part);

    let node_id_bytes = hex::decode(node_id_hex)
        .map_err(|e| Error::InvalidInput(format!("Invalid hex in node ID: {e}")))?;

    if node_id_bytes.len() != 64 {
        return Err(Error::InvalidInput(format!(
            "Node ID must be 64 bytes (128 hex chars), got {}",
            node_id_bytes.len()
        )));
    }

    let mut node_id = [0u8; 64];
    node_id.copy_from_slice(&node_id_bytes);

    let (host, port_str) = host_part
        .rsplit_once(':')
        .ok_or_else(|| Error::InvalidInput("URL must contain :port".to_string()))?;

    let port: u16 = port_str
        .parse()
        .map_err(|e| Error::InvalidInput(format!("Invalid port: {e}")))?;

    Ok((node_id, host.to_string(), port))
}
