//! How the header walk sees the chain it is building: a tiny store interface
//! and one implementation over `rsk_store::Store` (redb).
//!
//! The walk needs four things from the store: whether a block is already
//! accepted as canonical at a height, a place to put verified headers, and the
//! cumulative difficulty it had already established at the block the walk
//! anchors on. Everything else is derived.

use std::sync::Arc;

use alloy_primitives::{B256, U256};
use anyhow::{Context, Result};
use rsk_consensus::checkpoint::DifficultyCheckpoint;
use rsk_consensus::Header;
use rsk_store::Store;

/// The slice of storage the header walk touches.
pub trait HeaderStore: Send + Sync {
    /// The hash this node considers canonical at `number`, if any.
    ///
    /// Asked of the canonical view, never of "is this header stored": the walk
    /// stores headers as it goes, and a check its own writes could satisfy
    /// would be no check at all.
    fn canonical_hash(&self, number: u64) -> Result<Option<B256>>;

    /// Persist a run of verified headers in one write, keyed by canonical
    /// height.
    fn put_headers(&self, entries: &[(u64, Vec<u8>)]) -> Result<()>;

    /// The cumulative difficulty already established at the block with `hash`.
    fn total_difficulty(&self, hash: B256) -> Result<Option<U256>>;
}

/// `HeaderStore` over the redb `Store`, seeded by a cumulative-difficulty
/// checkpoint.
///
/// The checkpoint is the trust anchor: its hash is reported as canonical at
/// its height (so a walk always stops there at the latest) and its cumulative
/// difficulty is the base every established figure is measured from. Headers
/// this node has already verified and stored report their own hashes.
pub struct RedbHeaderStore {
    store: Arc<Store>,
    checkpoint: DifficultyCheckpoint,
}

impl RedbHeaderStore {
    pub fn new(store: Arc<Store>, checkpoint: DifficultyCheckpoint) -> Self {
        Self { store, checkpoint }
    }

    /// Mark every verified stored header above the checkpoint as canonical.
    ///
    /// Called once a walk has *completed* (linked down to the anchor): until
    /// then the chain rests on a peer's claim, and the walk must not be able
    /// to satisfy its own anchor. This is what lets a later run start from the
    /// previously-verified tip instead of the checkpoint.
    ///
    /// Written in batches: a single 280k-row redb write txn is both slow and a
    /// large in-memory buffered commit.
    pub fn canonicalize_above_checkpoint(&self, tip: u64) -> Result<u64> {
        const BATCH: u64 = 8192;
        let start = self.checkpoint.number + 1;
        if tip < start {
            return Ok(0);
        }
        let mut marked = 0u64;
        let mut entries: Vec<(u64, [u8; 32])> = Vec::with_capacity(BATCH as usize);
        let flush = |entries: &mut Vec<(u64, [u8; 32])>| -> Result<(), anyhow::Error> {
            if !entries.is_empty() {
                self.store.rsk_canonical_set_batch(entries)?;
                entries.clear();
            }
            Ok(())
        };

        for number in start..=tip {
            let Some(raw) = self.store.rsk_get_header_at_height(number)? else {
                continue;
            };
            let mut slice = raw.as_slice();
            let header = Header::decode_with_hash(&mut slice)
                .with_context(|| format!("stored header #{number} failed to decode"))?;
            entries.push((number, header.hash().0));
            marked += 1;
            if entries.len() as u64 >= BATCH {
                flush(&mut entries)?;
            }
        }
        flush(&mut entries)?;
        Ok(marked)
    }
}

impl HeaderStore for RedbHeaderStore {
    fn canonical_hash(&self, number: u64) -> Result<Option<B256>> {
        if number == self.checkpoint.number {
            return Ok(Some(self.checkpoint.hash));
        }
        // The canonical index only, never the header table: the walk writes
        // headers as it goes, so a check its own writes could satisfy would
        // anchor immediately and verify nothing.
        Ok(self.store.rsk_canonical_get(number)?.map(B256::from))
    }

    fn put_headers(&self, entries: &[(u64, Vec<u8>)]) -> Result<()> {
        let refs: Vec<_> = entries.iter().map(|(h, r)| (*h, r.as_slice())).collect();
        self.store.rsk_store_headers_batch(&refs)?;
        Ok(())
    }

    fn total_difficulty(&self, hash: B256) -> Result<Option<U256>> {
        if hash == self.checkpoint.hash {
            return Ok(Some(self.checkpoint.cumulative_difficulty));
        }

        // The walk anchored on a verified header above the checkpoint: its
        // difficulty is the checkpoint's, plus every stored header between the
        // checkpoint and it. Scanning once per run (only on restart) is fine;
        // a fresh first run always anchors at the checkpoint itself.
        let tip = match self.store.rsk_get_tip_height()? {
            Some(t) => t,
            None => return Ok(None),
        };
        let mut cumulative = self.checkpoint.cumulative_difficulty;
        let start = self.checkpoint.number + 1;
        let end = tip.max(start);
        for number in start..=end {
            let Some(raw) = self.store.rsk_get_header_at_height(number)? else {
                continue;
            };
            let mut slice = raw.as_slice();
            let header = Header::decode_with_hash(&mut slice)
                .with_context(|| format!("stored header #{number} failed to decode"))?;
            cumulative = cumulative.saturating_add(header.difficulty);
            if header.hash() == hash {
                return Ok(Some(cumulative));
            }
        }
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, B256};
    use rsk_consensus::checkpoint::DifficultyCheckpoint;

    fn header(number: u64) -> Header {
        Header {
            parent_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            ommers_hash: B256::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(1_000_000u64),
            number,
            gas_limit: U256::from(10_000_000u64),
            gas_used: 0,
            timestamp: 1_600_000_000 + number,
            extra_data: Bytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(1),
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }

    fn raw(h: &Header) -> Vec<u8> {
        let mut buf = Vec::new();
        alloy_rlp::Encodable::encode(h, &mut buf);
        buf
    }

    fn cp() -> DifficultyCheckpoint {
        DifficultyCheckpoint {
            number: 100,
            hash: B256::repeat_byte(0x11),
            cumulative_difficulty: U256::from(50u64),
            difficulty: U256::from(1_000_000u64),
        }
    }

    #[test]
    fn total_difficulty_summed_from_the_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("s.redb")).unwrap());
        let adapter = RedbHeaderStore::new(store.clone(), cp());

        let entries: Vec<(u64, Vec<u8>)> = (101..=104)
            .map(|h| {
                let x = header(h);
                (h, raw(&x))
            })
            .collect();
        adapter.put_headers(&entries).unwrap();

        // total difficulty of a header above the checkpoint = 50 + sum(101..=n)
        let b = &header(103);
        let td = adapter.total_difficulty(b.hash()).unwrap().unwrap();
        assert_eq!(td, U256::from(50u64 + 3 * 1_000_000));
        // The checkpoint hash itself reports the base.
        assert_eq!(
            adapter.total_difficulty(cp().hash).unwrap(),
            Some(cp().cumulative_difficulty)
        );
    }

    #[test]
    fn canonicalize_marks_only_above_the_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("s.redb")).unwrap());
        let adapter = RedbHeaderStore::new(store.clone(), cp());

        let entries: Vec<(u64, Vec<u8>)> = (101..=103)
            .map(|h| {
                let x = header(h);
                (h, raw(&x))
            })
            .collect();
        adapter.put_headers(&entries).unwrap();
        assert_eq!(
            adapter.canonical_hash(101).unwrap(),
            None,
            "nothing canonical before a completed walk"
        );

        adapter.canonicalize_above_checkpoint(103).unwrap();
        assert_eq!(
            adapter.canonical_hash(101).unwrap(),
            Some(header(101).hash())
        );
        assert_eq!(
            adapter.canonical_hash(103).unwrap(),
            Some(header(103).hash())
        );
        // The checkpoint itself is always canonical via seeding.
        assert_eq!(adapter.canonical_hash(100).unwrap(), Some(cp().hash));
    }
}
