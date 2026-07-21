use std::path::Path;

use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::error::NodeError;

const HEADERS: TableDefinition<u64, &[u8]> = TableDefinition::new("rsk_headers");
const MERGE_MINING: TableDefinition<u64, &[u8]> = TableDefinition::new("rsk_merge_mining");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("rsk_meta");

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MergeMiningData {
    pub bitcoin_header_hex: String,
    pub compressed_coinbase_hex: String,
    pub merkle_proof_hex: String,
    pub hash_for_merged_mining_hex: String,
}

pub struct RskHeaderStorage {
    db: Database,
}

impl RskHeaderStorage {
    pub fn open(path: &Path) -> Result<Self, NodeError> {
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        txn.open_table(HEADERS)?;
        txn.open_table(MERGE_MINING)?;
        txn.open_table(META)?;
        txn.commit()?;
        Ok(Self { db })
    }

    pub fn get_tip_height(&self) -> Result<Option<u64>, NodeError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META)?;
        Ok(table.get("tip_height")?.map(|v| {
            let bytes: &[u8] = v.value();
            u64::from_be_bytes(bytes.try_into().expect("8 bytes"))
        }))
    }

    pub fn get_lowest_validated_height(&self) -> Result<Option<u64>, NodeError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META)?;
        Ok(table.get("lowest_validated_height")?.map(|v| {
            let bytes: &[u8] = v.value();
            u64::from_be_bytes(bytes.try_into().expect("8 bytes"))
        }))
    }

    pub fn get_header_at_height(&self, height: u64) -> Result<Option<Vec<u8>>, NodeError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HEADERS)?;
        Ok(table.get(height)?.map(|v| v.value().to_vec()))
    }

    pub fn get_merge_mining_at_height(
        &self,
        height: u64,
    ) -> Result<Option<MergeMiningData>, NodeError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(MERGE_MINING)?;
        Ok(table.get(height)?.map(|v| {
            let bytes: &[u8] = v.value();
            serde_json::from_slice(bytes).expect("stored merge-mining data is always valid")
        }))
    }

    /// Store an RSK header with merge-mining data.
    pub fn store_header(
        &self,
        height: u64,
        raw_header: &[u8],
        merge_mining: &MergeMiningData,
    ) -> Result<(), NodeError> {
        let txn = self.db.begin_write()?;

        {
            let mut headers = txn.open_table(HEADERS)?;
            headers.insert(height, raw_header)?;
        }

        {
            let mut mm_table = txn.open_table(MERGE_MINING)?;
            let mm_bytes = serde_json::to_vec(merge_mining)
                .map_err(|e| NodeError::Sync(format!("merge-mining serialize: {e}")))?;
            mm_table.insert(height, mm_bytes.as_slice())?;
        }

        {
            let mut meta = txn.open_table(META)?;
            meta.insert("tip_height", height.to_be_bytes().as_slice())?;
        }

        txn.commit()?;
        Ok(())
    }

    /// Store an RSK header only (no merge-mining data).
    pub fn store_header_only(&self, height: u64, raw_header: &[u8]) -> Result<(), NodeError> {
        let txn = self.db.begin_write()?;

        {
            let mut headers = txn.open_table(HEADERS)?;
            headers.insert(height, raw_header)?;
        }

        {
            let mut meta = txn.open_table(META)?;
            meta.insert("tip_height", height.to_be_bytes().as_slice())?;
        }

        txn.commit()?;
        Ok(())
    }

    /// Update the lowest validated height.
    pub fn set_lowest_validated_height(&self, height: u64) -> Result<(), NodeError> {
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            meta.insert("lowest_validated_height", height.to_be_bytes().as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Get headers in range (inclusive).
    pub fn get_headers_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, NodeError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HEADERS)?;
        let mut result = Vec::new();
        for height in from_height..=to_height {
            if let Some(val) = table.get(height)? {
                result.push((height, val.value().to_vec()));
            }
        }
        Ok(result)
    }

    /// Get merge-mining data in range (inclusive).
    pub fn get_merge_mining_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, MergeMiningData)>, NodeError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(MERGE_MINING)?;
        let mut result = Vec::new();
        for height in from_height..=to_height {
            if let Some(val) = table.get(height)? {
                let bytes: &[u8] = val.value();
                let data: MergeMiningData = serde_json::from_slice(bytes)
                    .map_err(|e| NodeError::Sync(format!("merge-mining deserialize: {e}")))?;
                result.push((height, data));
            }
        }
        Ok(result)
    }
}

/// Decode an RSK header from raw RLP bytes.
pub fn decode_rsk_header(raw: &[u8]) -> Result<rsk::block_header::RskBlockHeader, NodeError> {
    rsk::block_header::RskBlockHeader::decode_rlp(raw)
        .map_err(|e| NodeError::Validation(e.to_string()))
}
