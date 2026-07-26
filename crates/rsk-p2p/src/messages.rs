use alloy_rlp::{RlpDecodable, RlpEncodable};
use ethereum_types::H256;

pub type Reason = usize;

#[derive(Debug)]
pub enum Message {
    Auth,
    AuthAck,
    Hello,
    Ping,
    Pong,
    Disconnect(Reason),
    Status(Status),
    GetBlockHeaders(GetBlockHeaders),
    BlockHeaders(BlockHeaders),
    GetBlockBodies(Vec<H256>),
    BlockBodies(BlockBodiesResponse),
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Hello {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<Capability>,
    pub port: u16,
    pub id: [u8; 64],
}

impl Hello {
    pub const ID: u8 = 0x00;
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Disconnect {
    pub reason: usize,
}

impl Disconnect {
    pub const ID: u8 = 0x01;
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Ping {}

impl Ping {
    pub const ID: u8 = 0x02;
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Pong {}

impl Pong {
    pub const ID: u8 = 0x03;
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct ForkId {
    pub hash: u32,
    pub next: u64,
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Status {
    pub version: u8,
    pub networkid: u64,
    pub td: u128,
    pub blockhash: [u8; 32],
    pub genesis: [u8; 32],
    pub forkid: ForkId,
}

impl Status {
    pub const ID: u8 = 0x00; // ETH protocol Status
}

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct GetBlockHeaders {
    pub request_id: u64,
    pub query: BlockHeadersQuery,
}

impl GetBlockHeaders {
    pub const ID: u8 = 0x03; // ETH protocol GetBlockHeaders
}

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct BlockHeadersQuery {
    pub block: Vec<u8>, // Block number or hash
    pub skip: u64,
    pub limit: u64,
    pub reverse: bool,
}

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct BlockHeaders {
    pub request_id: u64,
    pub headers: Vec<Vec<u8>>, // Raw RLP-encoded headers
}

impl BlockHeaders {
    pub const ID: u8 = 0x04; // ETH protocol BlockHeaders
}

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct BlockBody {
    pub transactions: Vec<Vec<u8>>,
    pub uncles: Vec<Vec<u8>>,
}

#[derive(Debug, RlpEncodable, RlpDecodable)]
pub struct BlockBodiesResponse {
    pub request_id: u64,
    pub bodies: Vec<BlockBody>,
}

impl BlockBodiesResponse {
    pub const ID: u8 = 0x06; // ETH protocol BlockBodies
}
