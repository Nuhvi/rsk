use std::path::Path;

use bitcoin::block::Header as BitcoinHeader;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash as _;
use primitive_types::U256;
use redb::{Database, ReadableTable, TableDefinition};

use crate::error::StoreError;

const HEADERS: TableDefinition<u64, &[u8]> = TableDefinition::new("headers");
const HASH_TO_HEIGHT: TableDefinition<&[u8], u64> = TableDefinition::new("hash_to_height");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

pub struct BitcoinHeaderStorage {
    db: Database,
}

impl BitcoinHeaderStorage {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        txn.open_table(HEADERS)?;
        txn.open_table(HASH_TO_HEIGHT)?;
        txn.open_table(META)?;
        txn.commit()?;
        Ok(Self { db })
    }

    pub fn get_tip_height(&self) -> Result<Option<u64>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META)?;
        Ok(table.get("tip_height")?.map(|v| {
            let bytes: &[u8] = v.value();
            u64::from_be_bytes(bytes.try_into().expect("tip_height is 8 bytes"))
        }))
    }

    pub fn get_tip_hash(&self) -> Result<Option<[u8; 32]>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META)?;
        Ok(table.get("tip_hash")?.map(|v| {
            let bytes: &[u8] = v.value();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(bytes);
            hash
        }))
    }

    pub fn get_header_at_height(&self, height: u64) -> Result<Option<BitcoinHeader>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HEADERS)?;
        Ok(table.get(height)?.map(|v| {
            let bytes: &[u8] = v.value();
            let mut reader = &bytes[..];
            BitcoinHeader::consensus_decode(&mut reader).expect("stored header is always valid")
        }))
    }

    pub fn header_exists_on_canonical_chain(&self, hash: &[u8; 32]) -> Result<bool, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HASH_TO_HEIGHT)?;
        Ok(table.get(hash.as_slice())?.is_some())
    }

    /// Append validated headers. Returns the number of headers stored.
    pub fn append_headers(&self, headers: &[(u64, BitcoinHeader)]) -> Result<usize, StoreError> {
        if headers.is_empty() {
            return Ok(0);
        }

        let txn = self.db.begin_write()?;

        let mut current_work = {
            let meta = txn.open_table(META)?;
            meta.get("tip_work")?
                .map(|v| U256::from_big_endian(v.value()))
                .unwrap_or(U256::zero())
        };

        {
            let mut headers_table = txn.open_table(HEADERS)?;
            let mut hash_table = txn.open_table(HASH_TO_HEIGHT)?;
            let mut meta = txn.open_table(META)?;

            for &(height, ref header) in headers {
                let mut header_bytes = Vec::with_capacity(80);
                header
                    .consensus_encode(&mut header_bytes)
                    .expect("encoding to vec is infallible");

                let block_hash = header.block_hash();
                let hash_arr = block_hash.as_byte_array();
                let hash_bytes: &[u8] = hash_arr;

                let work = header_work(header);
                current_work = current_work.checked_add(work).unwrap_or(current_work);

                headers_table.insert(height, header_bytes.as_slice())?;
                hash_table.insert(hash_bytes, height)?;
                meta.insert("tip_height", height.to_be_bytes().as_slice())?;
                meta.insert("tip_hash", hash_bytes)?;
                meta.insert("tip_work", current_work.to_big_endian().as_slice())?;
            }
        }

        txn.commit()?;
        Ok(headers.len())
    }

    /// Truncate chain to height (inclusive). Used for reorgs.
    pub fn truncate_to_height(&self, height: u64) -> Result<(), StoreError> {
        let current_height = {
            let txn = self.db.begin_read()?;
            let meta = txn.open_table(META)?;
            meta.get("tip_height")?
                .map(|v| u64::from_be_bytes(v.value().try_into().expect("8 bytes")))
        };

        let current_height =
            current_height.ok_or_else(|| StoreError::Internal("no chain to truncate".into()))?;

        if height >= current_height {
            return Ok(());
        }

        let txn = self.db.begin_write()?;

        {
            let mut headers_table = txn.open_table(HEADERS)?;
            let mut hash_table = txn.open_table(HASH_TO_HEIGHT)?;

            for h in (height + 1)..=current_height {
                if let Some(header_val) = headers_table.get(h)? {
                    let bytes: &[u8] = header_val.value();
                    let mut reader = &bytes[..];
                    let header = BitcoinHeader::consensus_decode(&mut reader)
                        .expect("stored header is valid");
                    let blk_hash = header.block_hash();
                    let hash_bytes: &[u8] = blk_hash.as_byte_array();
                    hash_table.remove(hash_bytes)?;
                }
                headers_table.remove(h)?;
            }
        }

        {
            let mut meta = txn.open_table(META)?;
            meta.insert("tip_height", height.to_be_bytes().as_slice())?;

            let headers_table = txn.open_table(HEADERS)?;
            if let Some(tip_val) = headers_table.get(height)? {
                let bytes: &[u8] = tip_val.value();
                let mut reader = &bytes[..];
                let tip_header =
                    BitcoinHeader::consensus_decode(&mut reader).expect("stored header is valid");
                let tip_hash = tip_header.block_hash();
                let hash_bytes: &[u8] = tip_hash.as_byte_array();
                meta.insert("tip_hash", hash_bytes)?;
                meta.insert("tip_work", U256::zero().to_big_endian().as_slice())?;
            }
        }

        txn.commit()?;
        Ok(())
    }

    /// Check if hash matches the header stored at given height.
    pub fn hash_at_height_matches(
        &self,
        height: u64,
        expected_hash: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HEADERS)?;
        match table.get(height)? {
            Some(val) => {
                let bytes: &[u8] = val.value();
                let mut reader = &bytes[..];
                let header =
                    BitcoinHeader::consensus_decode(&mut reader).expect("stored header is valid");
                let hdr_hash = header.block_hash();
                let hash: &[u8] = hdr_hash.as_byte_array();
                Ok(hash == expected_hash)
            }
            None => Ok(false),
        }
    }
}

/// Compute work from a Bitcoin header's nBits target.
pub fn header_work(header: &BitcoinHeader) -> U256 {
    let work = header.target().to_work();
    let le_bytes = work.to_le_bytes();
    U256::from_little_endian(&le_bytes)
}
