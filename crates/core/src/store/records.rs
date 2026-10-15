//! The stored record types and their redb codecs.
//!
//! Every table value is a type here, so the byte layout lives in one place and
//! a table reads as `TableDefinition<Key, Record>` rather than
//! `TableDefinition<_, &[u8]>`. Decoding is total for data this crate wrote;
//! `from_bytes` cannot fail (redb's `Value` returns a value, not a `Result`),
//! so a malformed row panics rather than silently producing a wrong value.

use alloy_primitives::U256;
use bitcoin::block::BlockHash;
use bitcoin::block::Header as BitcoinHeader;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::pow::Work;
use redb::{TypeName, Value};

/// Sentinel `parent` for a root fork (`ForkMeta::parent == None`).
const NO_PARENT: u64 = u64::MAX;

/// A Bitcoin header row: the header and its cumulative work on its fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BtcRow {
    pub header: BitcoinHeader,
    pub work: Work,
}

impl Value for BtcRow {
    type SelfType<'a> = BtcRow;
    type AsBytes<'a> = [u8; 112];

    fn fixed_width() -> Option<usize> {
        Some(112)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> BtcRow
    where
        Self: 'a,
    {
        let mut reader = &data[..80];
        let header =
            BitcoinHeader::consensus_decode(&mut reader).expect("stored header is always valid");
        let work = Work::from_be_bytes(data[80..112].try_into().expect("32-byte work"));
        BtcRow { header, work }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a BtcRow) -> [u8; 112]
    where
        Self: 'b,
    {
        let mut out = [0u8; 112];
        let mut buf = Vec::with_capacity(80);
        value
            .header
            .consensus_encode(&mut buf)
            .expect("encoding to vec is infallible");
        out[..80].copy_from_slice(&buf);
        out[80..].copy_from_slice(&value.work.to_be_bytes());
        out
    }

    fn type_name() -> TypeName {
        TypeName::new("rsk_core::BtcRow")
    }
}

/// A bare Bitcoin header (the checkpoint spine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BtcHeader(pub BitcoinHeader);

impl Value for BtcHeader {
    type SelfType<'a> = BtcHeader;
    type AsBytes<'a> = [u8; 80];

    fn fixed_width() -> Option<usize> {
        Some(80)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> BtcHeader
    where
        Self: 'a,
    {
        let mut reader = &data[..80];
        BtcHeader(
            BitcoinHeader::consensus_decode(&mut reader).expect("stored header is always valid"),
        )
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a BtcHeader) -> [u8; 80]
    where
        Self: 'b,
    {
        let mut buf = Vec::with_capacity(80);
        value
            .0
            .consensus_encode(&mut buf)
            .expect("encoding to vec is infallible");
        buf.try_into().expect("80-byte header")
    }

    fn type_name() -> TypeName {
        TypeName::new("rsk_core::BtcHeader")
    }
}

/// Metadata for one Bitcoin chain (fork) in the tree. The root chain (id 0)
/// has `forkpoint == 0`, `parent == None`, and is the initial best chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForkMeta {
    /// Height of this fork's first header.
    pub forkpoint: u64,
    /// The chain this one diverged from; `None` for a root fork.
    pub parent: Option<u64>,
    /// Hash of the block at `forkpoint` (this fork's identity).
    pub forkpoint_hash: BlockHash,
    /// Highest connected height on this fork.
    pub tip_height: u64,
    /// Hash of the block at `tip_height`.
    pub tip_hash: BlockHash,
    /// Cumulative work at `tip_height`.
    pub tip_work: Work,
}

impl Value for ForkMeta {
    type SelfType<'a> = ForkMeta;
    type AsBytes<'a> = [u8; 120];

    fn fixed_width() -> Option<usize> {
        Some(120)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> ForkMeta
    where
        Self: 'a,
    {
        let parent = u64::from_be_bytes(data[8..16].try_into().expect("8 bytes"));
        let mut fp_hash = [0u8; 32];
        fp_hash.copy_from_slice(&data[16..48]);
        ForkMeta {
            forkpoint: u64::from_be_bytes(data[0..8].try_into().expect("8 bytes")),
            parent: (parent != NO_PARENT).then_some(parent),
            forkpoint_hash: BlockHash::from_byte_array(fp_hash),
            tip_height: u64::from_be_bytes(data[48..56].try_into().expect("8 bytes")),
            tip_hash: BlockHash::from_byte_array(data[56..88].try_into().expect("32 bytes")),
            tip_work: Work::from_be_bytes(data[80..112].try_into().expect("32 bytes")),
        }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a ForkMeta) -> [u8; 120]
    where
        Self: 'b,
    {
        let mut out = [0u8; 120];
        out[0..8].copy_from_slice(&value.forkpoint.to_be_bytes());
        out[8..16].copy_from_slice(&value.parent.unwrap_or(NO_PARENT).to_be_bytes());
        out[16..48].copy_from_slice(value.forkpoint_hash.as_byte_array());
        out[48..56].copy_from_slice(&value.tip_height.to_be_bytes());
        out[56..88].copy_from_slice(value.tip_hash.as_byte_array());
        out[88..120].copy_from_slice(&value.tip_work.to_be_bytes());
        out
    }

    fn type_name() -> TypeName {
        TypeName::new("rsk_core::ForkMeta")
    }
}

/// A stored RSK block index: its number, its parent, and its own work
/// (`difficulty + Σ included uncle difficulty`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RskBlock {
    pub number: u64,
    pub parent: [u8; 32],
    pub cumulative_difficulty: U256,
}

impl Value for RskBlock {
    type SelfType<'a> = RskBlock;
    type AsBytes<'a> = [u8; 72];

    fn fixed_width() -> Option<usize> {
        Some(72)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> RskBlock
    where
        Self: 'a,
    {
        let mut parent = [0u8; 32];
        parent.copy_from_slice(&data[8..40]);
        RskBlock {
            number: u64::from_be_bytes(data[..8].try_into().expect("8 bytes")),
            parent,
            cumulative_difficulty: U256::from_be_slice(&data[40..72]),
        }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a RskBlock) -> [u8; 72]
    where
        Self: 'b,
    {
        let mut out = [0u8; 72];
        out[..8].copy_from_slice(&value.number.to_be_bytes());
        out[8..40].copy_from_slice(&value.parent);
        out[40..72].copy_from_slice(&value.cumulative_difficulty.to_be_bytes::<32>());
        out
    }

    fn type_name() -> TypeName {
        TypeName::new("rsk_core::RskBlock")
    }
}

/// A list of 32-byte hashes (the GHOST subtree edges).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct HashList(pub Vec<[u8; 32]>);

impl Value for HashList {
    type SelfType<'a> = HashList;
    type AsBytes<'a> = Vec<u8>;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> HashList
    where
        Self: 'a,
    {
        HashList(
            data.chunks(32)
                .filter(|chunk| chunk.len() == 32)
                .map(|chunk| {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(chunk);
                    hash
                })
                .collect(),
        )
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a HashList) -> Vec<u8>
    where
        Self: 'b,
    {
        let mut out = Vec::with_capacity(value.0.len() * 32);
        for hash in &value.0 {
            out.extend_from_slice(hash);
        }
        out
    }

    fn type_name() -> TypeName {
        TypeName::new("rsk_core::HashList")
    }
}

/// A list of opaque byte blobs (raw uncle headers).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct BlobList(pub Vec<Vec<u8>>);

impl Value for BlobList {
    type SelfType<'a> = BlobList;
    type AsBytes<'a> = Vec<u8>;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> BlobList
    where
        Self: 'a,
    {
        if data.len() < 4 {
            return BlobList::default();
        }
        let count = u32::from_be_bytes(data[..4].try_into().expect("4 bytes")) as usize;
        let mut out = Vec::with_capacity(count);
        let mut at = 4;
        for _ in 0..count {
            if at + 4 > data.len() {
                break;
            }
            let len = u32::from_be_bytes(data[at..at + 4].try_into().expect("4 bytes")) as usize;
            at += 4;
            if at + len > data.len() {
                break;
            }
            out.push(data[at..at + len].to_vec());
            at += len;
        }
        BlobList(out)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a BlobList) -> Vec<u8>
    where
        Self: 'b,
    {
        let mut out = Vec::new();
        out.extend_from_slice(&(value.0.len() as u32).to_be_bytes());
        for blob in &value.0 {
            out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            out.extend_from_slice(blob);
        }
        out
    }

    fn type_name() -> TypeName {
        TypeName::new("rsk_core::BlobList")
    }
}

/// A metadata value: a small tagged union so one meta table serves every key,
/// instead of each call site encoding and decoding raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Meta {
    U64(u64),
    Text(String),
}

impl Meta {
    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self {
            Meta::U64(value) => Some(*value),
            Meta::Text(_) => None,
        }
    }

    pub(crate) fn as_text(&self) -> Option<&str> {
        match self {
            Meta::Text(text) => Some(text),
            Meta::U64(_) => None,
        }
    }
}

impl Value for Meta {
    type SelfType<'a> = Meta;
    type AsBytes<'a> = Vec<u8>;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Meta
    where
        Self: 'a,
    {
        match data.first() {
            Some(0) => Meta::U64(u64::from_be_bytes(
                data[1..9].try_into().expect("8-byte meta"),
            )),
            Some(1) => Meta::Text(String::from_utf8_lossy(&data[1..]).into_owned()),
            _ => panic!("stored meta value has an unknown tag"),
        }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Meta) -> Vec<u8>
    where
        Self: 'b,
    {
        let mut out = Vec::new();
        match value {
            Meta::U64(number) => {
                out.push(0);
                out.extend_from_slice(&number.to_be_bytes());
            }
            Meta::Text(text) => {
                out.push(1);
                out.extend_from_slice(text.as_bytes());
            }
        }
        out
    }

    fn type_name() -> TypeName {
        TypeName::new("rsk_core::Meta")
    }
}
