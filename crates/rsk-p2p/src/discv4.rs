use sha3::{Digest, Keccak256};
use secp256k1::{SecretKey, PublicKey, SECP256K1};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};
use rlp::{Rlp, RlpStream, Encodable, Decodable, DecoderError};

use crate::error::{Error, Result};

/// Discv4 packet types
pub const PACKET_PING: u8 = 0x01;
pub const PACKET_PONG: u8 = 0x02;
pub const PACKET_FIND_NODE: u8 = 0x03;
pub const PACKET_NEIGHBORS: u8 = 0x04;
pub const PACKET_ENR_REQUEST: u8 = 0x05;
pub const PACKET_ENR_RESPONSE: u8 = 0x06;

/// Maximum discv4 packet size
pub const MAX_PACKET_SIZE: usize = 1280;

/// A discovered node
#[derive(Debug, Clone)]
pub struct DiscoveredNode {
    pub node_id: [u8; 64],
    pub ip: Ipv4Addr,
    pub udp_port: u16,
    pub tcp_port: u16,
}

/// Endpoint for ping/pong
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub ip: Vec<u8>,
    pub udp_port: u16,
    pub tcp_port: u16,
}

impl Encodable for Endpoint {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.ip);
        s.append(&self.udp_port);
        s.append(&self.tcp_port);
    }
}

impl Decodable for Endpoint {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        Ok(Endpoint {
            ip: rlp.val_at(0)?,
            udp_port: rlp.val_at(1)?,
            tcp_port: rlp.val_at(2)?,
        })
    }
}

/// Discv4 packet
#[derive(Debug)]
pub enum Packet {
    Ping(Ping),
    Pong(Pong),
    FindNode(FindNode),
    Neighbors(Neighbors),
    EnrRequest(EnrRequest),
    EnrResponse(EnrResponse),
}

#[derive(Debug, Clone)]
pub struct Ping {
    pub version: u32,
    pub from: Endpoint,
    pub to: Endpoint,
    pub expiration: u64,
    pub enr_seq: Option<u64>,
}

impl Encodable for Ping {
    fn rlp_append(&self, s: &mut RlpStream) {
        if self.enr_seq.is_some() {
            s.begin_list(5);
            s.append(&self.version);
            s.append(&self.from);
            s.append(&self.to);
            s.append(&self.expiration);
            s.append(&self.enr_seq.unwrap());
        } else {
            s.begin_list(4);
            s.append(&self.version);
            s.append(&self.from);
            s.append(&self.to);
            s.append(&self.expiration);
        }
    }
}

impl Decodable for Ping {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        let version = rlp.val_at(0)?;
        let from = rlp.val_at(1)?;
        let to = rlp.val_at(2)?;
        let expiration = rlp.val_at(3)?;
        let enr_seq = if rlp.item_count()? > 4 {
            Some(rlp.val_at(4)?)
        } else {
            None
        };
        
        Ok(Ping {
            version,
            from,
            to,
            expiration,
            enr_seq,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Pong {
    pub to: Endpoint,
    pub ping_hash: Vec<u8>,
    pub expiration: u64,
    pub enr_seq: Option<u64>,
}

impl Encodable for Pong {
    fn rlp_append(&self, s: &mut RlpStream) {
        if self.enr_seq.is_some() {
            s.begin_list(4);
            s.append(&self.to);
            s.append(&self.ping_hash);
            s.append(&self.expiration);
            s.append(&self.enr_seq.unwrap());
        } else {
            s.begin_list(3);
            s.append(&self.to);
            s.append(&self.ping_hash);
            s.append(&self.expiration);
        }
    }
}

impl Decodable for Pong {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        let to = rlp.val_at(0)?;
        let ping_hash = rlp.val_at(1)?;
        let expiration = rlp.val_at(2)?;
        let enr_seq = if rlp.item_count()? > 3 {
            Some(rlp.val_at(3)?)
        } else {
            None
        };
        
        Ok(Pong {
            to,
            ping_hash,
            expiration,
            enr_seq,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FindNode {
    pub target: Vec<u8>,
    pub expiration: u64,
}

impl Encodable for FindNode {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.target);
        s.append(&self.expiration);
    }
}

impl Decodable for FindNode {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        Ok(FindNode {
            target: rlp.val_at(0)?,
            expiration: rlp.val_at(1)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    pub ip: Vec<u8>,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub node_id: Vec<u8>,
}

impl Encodable for Node {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.ip);
        s.append(&self.udp_port);
        s.append(&self.tcp_port);
        s.append(&self.node_id);
    }
}

impl Decodable for Node {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        Ok(Node {
            ip: rlp.val_at(0)?,
            udp_port: rlp.val_at(1)?,
            tcp_port: rlp.val_at(2)?,
            node_id: rlp.val_at(3)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Neighbors {
    pub nodes: Vec<Node>,
    pub expiration: u64,
}

impl Encodable for Neighbors {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append_list(&self.nodes);
        s.append(&self.expiration);
    }
}

impl Decodable for Neighbors {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        Ok(Neighbors {
            nodes: rlp.list_at(0)?,
            expiration: rlp.val_at(1)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EnrRequest {
    pub expiration: u64,
}

impl Encodable for EnrRequest {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(1);
        s.append(&self.expiration);
    }
}

impl Decodable for EnrRequest {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        Ok(EnrRequest {
            expiration: rlp.val_at(0)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EnrResponse {
    pub request_hash: Vec<u8>,
    pub enr: Vec<u8>,
}

impl Encodable for EnrResponse {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.request_hash);
        s.append(&self.enr);
    }
}

impl Decodable for EnrResponse {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        Ok(EnrResponse {
            request_hash: rlp.val_at(0)?,
            enr: rlp.val_at(1)?,
        })
    }
}

impl Packet {
    /// Encode the packet to bytes with signature
    pub fn encode(&self, private_key: &SecretKey) -> Vec<u8> {
        let (packet_type, mut payload) = match self {
            Packet::Ping(ping) => {
                let mut stream = RlpStream::new();
                ping.rlp_append(&mut stream);
                (PACKET_PING, stream.out().to_vec())
            }
            Packet::Pong(pong) => {
                let mut stream = RlpStream::new();
                pong.rlp_append(&mut stream);
                (PACKET_PONG, stream.out().to_vec())
            }
            Packet::FindNode(find) => {
                let mut stream = RlpStream::new();
                find.rlp_append(&mut stream);
                (PACKET_FIND_NODE, stream.out().to_vec())
            }
            Packet::Neighbors(neighbors) => {
                let mut stream = RlpStream::new();
                neighbors.rlp_append(&mut stream);
                (PACKET_NEIGHBORS, stream.out().to_vec())
            }
            Packet::EnrRequest(req) => {
                let mut stream = RlpStream::new();
                req.rlp_append(&mut stream);
                (PACKET_ENR_REQUEST, stream.out().to_vec())
            }
            Packet::EnrResponse(res) => {
                let mut stream = RlpStream::new();
                res.rlp_append(&mut stream);
                (PACKET_ENR_RESPONSE, stream.out().to_vec())
            }
        };

        // Create the message to sign: packet-type || packet-data
        let mut msg = vec![packet_type];
        msg.extend_from_slice(&payload);

        // Sign the message
        let msg_hash = keccak256(&msg);
        let message = secp256k1::Message::from_slice(&msg_hash).expect("32 bytes");
        let sig = SECP256K1.sign_ecdsa_recoverable(&message, private_key);
        let (rec_id, sig_compact) = sig.serialize_compact();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig_compact);
        sig_bytes[64] = rec_id.to_i32() as u8;

        // Create the full packet: hash || signature || packet-type || packet-data
        let mut packet = Vec::new();
        
        // First, compute hash over signature || packet-type || packet-data
        let mut sign_and_data = Vec::new();
        sign_and_data.extend_from_slice(&sig_bytes);
        sign_and_data.push(packet_type);
        sign_and_data.extend_from_slice(&payload);
        
        let hash = keccak256(&sign_and_data);
        
        packet.extend_from_slice(&hash);
        packet.extend_from_slice(&sig_bytes);
        packet.push(packet_type);
        packet.extend_from_slice(&payload);
        
        packet
    }

    /// Decode a packet from bytes
    pub fn decode(data: &[u8]) -> Result<(Packet, [u8; 64])> {
        if data.len() < 97 {
            return Err(Error::InvalidInput("Packet too short".to_string()));
        }

        let hash = <[u8; 32]>::try_from(&data[..32])
            .map_err(|_| Error::InvalidInput("Invalid hash".to_string()))?;
        let sig = &data[32..97];
        let packet_type = data[97];
        let payload = &data[98..];

        // Verify hash
        let computed_hash = keccak256(&data[32..]);
        if hash != computed_hash.as_slice() {
            return Err(Error::InvalidInput("Hash mismatch".to_string()));
        }

        // Recover public key from signature
        let sig_compact = secp256k1::ecdsa::RecoverableSignature::from_compact(
            &sig[..64],
            secp256k1::ecdsa::RecoveryId::from_i32(sig[64] as i32)
                .map_err(|e| Error::InvalidInput(e.to_string()))?,
        )
        .map_err(|e| Error::InvalidInput(e.to_string()))?;

        let msg_hash = keccak256(&data[32..]);
        let message = secp256k1::Message::from_slice(&msg_hash).expect("32 bytes");
        let public_key = SECP256K1
            .recover_ecdsa(&message, &sig_compact)
            .map_err(|e| Error::InvalidInput(e.to_string()))?;

        // Extract node_id from public key (64 bytes without 04 prefix)
        let pk_bytes = public_key.serialize_uncompressed();
        let mut node_id = [0u8; 64];
        node_id.copy_from_slice(&pk_bytes[1..]);

        let rlp = Rlp::new(payload);
        let packet = match packet_type {
            PACKET_PING => {
                let ping = Ping::decode(&rlp)?;
                Packet::Ping(ping)
            }
            PACKET_PONG => {
                let pong = Pong::decode(&rlp)?;
                Packet::Pong(pong)
            }
            PACKET_FIND_NODE => {
                let find = FindNode::decode(&rlp)?;
                Packet::FindNode(find)
            }
            PACKET_NEIGHBORS => {
                let neighbors = Neighbors::decode(&rlp)?;
                Packet::Neighbors(neighbors)
            }
            PACKET_ENR_REQUEST => {
                let req = EnrRequest::decode(&rlp)?;
                Packet::EnrRequest(req)
            }
            PACKET_ENR_RESPONSE => {
                let res = EnrResponse::decode(&rlp)?;
                Packet::EnrResponse(res)
            }
            _ => return Err(Error::UnsupportedMessageId(packet_type)),
        };

        Ok((packet, node_id))
    }
}

/// Discv4 discovery service
pub struct Discovery {
    socket: UdpSocket,
    private_key: SecretKey,
    local_node_id: [u8; 64],
    local_enr_seq: u64,
}

impl Discovery {
    /// Create a new discovery service
    pub async fn new(private_key: SecretKey, bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        
        let public_key = PublicKey::from_secret_key(&SECP256K1, &private_key);
        let pk_bytes = public_key.serialize_uncompressed();
        let mut local_node_id = [0u8; 64];
        local_node_id.copy_from_slice(&pk_bytes[1..]);
        
        Ok(Discovery {
            socket,
            private_key,
            local_node_id,
            local_enr_seq: 0,
        })
    }

    /// Send a ping to a node
    pub async fn send_ping(&self, target: SocketAddr) -> Result<Vec<u8>> {
        // Detect the actual outgoing IP by creating a temporary connected socket
        let from_ip = match target {
            SocketAddr::V4(_) => {
                let temp = std::net::UdpSocket::bind("0.0.0.0:0")?;
                temp.connect(target)?;
                let local = temp.local_addr()?;
                match local.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                    _ => vec![0, 0, 0, 0],
                }
            }
            SocketAddr::V6(_) => {
                let temp = std::net::UdpSocket::bind("[::]:0")?;
                temp.connect(target)?;
                let local = temp.local_addr()?;
                match local.ip() {
                    std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
                    _ => vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                }
            }
        };
        
        let to_ip = match target.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        
        let ping = Ping {
            version: 4,
            from: Endpoint {
                ip: from_ip,
                udp_port: self.local_addr()?.port(),
                tcp_port: 0,
            },
            to: Endpoint {
                ip: to_ip,
                udp_port: target.port(),
                tcp_port: 0,
            },
            expiration: expiration(),
            enr_seq: Some(self.local_enr_seq),
        };

        let packet = Packet::Ping(ping);
        let encoded = packet.encode(&self.private_key);
        let hash = encoded[..32].to_vec();
        self.socket.send_to(&encoded, target).await?;
        
        Ok(hash)
    }

    /// Send a pong in response to a ping
    pub async fn send_pong(&self, target: SocketAddr, ping_hash: &[u8]) -> Result<()> {
        let to_ip = match target.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        
        let pong = Pong {
            to: Endpoint {
                ip: to_ip,
                udp_port: target.port(),
                tcp_port: 0,
            },
            ping_hash: ping_hash.to_vec(),
            expiration: expiration(),
            enr_seq: Some(self.local_enr_seq),
        };

        let packet = Packet::Pong(pong);
        let encoded = packet.encode(&self.private_key);
        self.socket.send_to(&encoded, target).await?;
        Ok(())
    }

    /// Send a FindNode request
    pub async fn send_find_node(&self, target: SocketAddr, node_id: &[u8]) -> Result<()> {
        let find = FindNode {
            target: node_id.to_vec(),
            expiration: expiration(),
        };

        let packet = Packet::FindNode(find);
        let encoded = packet.encode(&self.private_key);
        self.socket.send_to(&encoded, target).await?;
        Ok(())
    }

    /// Send an ENR request
    pub async fn send_enr_request(&self, target: SocketAddr) -> Result<()> {
        let req = EnrRequest {
            expiration: expiration(),
        };

        let packet = Packet::EnrRequest(req);
        let encoded = packet.encode(&self.private_key);
        self.socket.send_to(&encoded, target).await?;
        Ok(())
    }

    /// Receive a packet, also returning the raw packet hash
    pub async fn recv(&self) -> Result<(Packet, SocketAddr, [u8; 64], [u8; 32])> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let (len, from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        
        let hash = <[u8; 32]>::try_from(&buf[..32])
            .map_err(|_| Error::InvalidInput("Invalid hash".to_string()))?;
        let (packet, node_id) = Packet::decode(&buf)?;
        Ok((packet, from, node_id, hash))
    }

    /// Get the local address
    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(|e| Error::Io(e))
    }

    /// Get the local node ID
    pub fn local_node_id(&self) -> &[u8; 64] {
        &self.local_node_id
    }
}

/// Compute keccak256 hash
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Get current time + 20 seconds as expiration
fn expiration() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() + 20
}

/// Perform a Kademlia lookup for nodes near a target
pub async fn lookup(
    discovery: &Discovery,
    bootstrap_nodes: &[(Ipv4Addr, u16)],
    target_node_id: &[u8; 64],
) -> Result<Vec<DiscoveredNode>> {
    let mut discovered = Vec::new();
    
    // Send Ping to bootstrap nodes to establish endpoint proof
    for (ip, port) in bootstrap_nodes {
        let addr = SocketAddr::new((*ip).into(), *port);
        if let Err(e) = discovery.send_ping(addr).await {
            log::warn!("Failed to send Ping to {}: {}", addr, e);
            continue;
        }
        
        // Wait for Pong response
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            discovery.recv(),
        ).await;
        
        match timeout {
            Ok(Ok((Packet::Pong(_pong), from, _, _ping_hash))) => {
                log::info!("Pong received from {}, sending FindNode", from);
                if let Err(e) = discovery.send_find_node(from, target_node_id).await {
                    log::warn!("Failed to send FindNode to {}: {}", from, e);
                    continue;
                }
                
                // Wait for Neighbors response
                let timeout2 = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    discovery.recv(),
                ).await;
                
                match timeout2 {
                    Ok(Ok((Packet::Neighbors(neighbors), from2, _, _))) => {
                        log::info!("Received {} neighbors from {}", neighbors.nodes.len(), from2);
                        for node in &neighbors.nodes {
                            if node.ip.len() == 4 {
                                let ip = Ipv4Addr::new(node.ip[0], node.ip[1], node.ip[2], node.ip[3]);
                                let mut node_id = [0u8; 64];
                                let copy_len = node.node_id.len().min(64);
                                node_id[..copy_len].copy_from_slice(&node.node_id[..copy_len]);
                                
                                discovered.push(DiscoveredNode {
                                    node_id,
                                    ip,
                                    udp_port: node.udp_port,
                                    tcp_port: node.tcp_port,
                                });
                            }
                        }
                    }
                    Ok(Ok((packet, from2, _, _))) => {
                        log::warn!("Unexpected packet from {}: {:?}", from2, std::mem::discriminant(&packet));
                    }
                    Ok(Err(e)) => {
                        log::warn!("Error receiving neighbors: {}", e);
                    }
                    Err(_) => {
                        log::warn!("Timeout waiting for neighbors from {}", from);
                    }
                }
            }
            Ok(Ok((packet, from, _, _))) => {
                log::warn!("Unexpected packet from {}: {:?}", from, std::mem::discriminant(&packet));
            }
            Ok(Err(e)) => {
                log::warn!("Error receiving pong: {}", e);
            }
            Err(_) => {
                log::warn!("Timeout waiting for pong from {}:{}", ip, port);
            }
        }
    }
    
    Ok(discovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256() {
        let data = b"hello";
        let hash = keccak256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_expiration() {
        let exp = expiration();
        assert!(exp > 0);
    }
}
