//! Walking the header chain down from the top, in parallel.
//!
//! Ported from rustock's `crates/sync/src/snap/headers.rs` (MIT), adapted to
//! this repo's `HeaderStore` trait and raw-byte storage.
//!
//! # Why the obvious way is slow
//!
//! To ask for headers you need a hash, and the only hash you have is the one
//! the last answer gave you. So the natural walk — ask for 192 headers, take
//! the oldest one's parent, ask again — is strictly serial. For a nine-million
//! block chain that is about 48,000 round trips, one at a time. rskj walks this
//! way.
//!
//! # Breaking the dependency
//!
//! A *skeleton* request answers with block identifiers at fixed heights — up to
//! twenty of them, 192 apart — and it is addressed by height, not by hash. So
//! skeletons can all be asked for at once, and each identifier they return is
//! the starting hash for a header request that can also be asked for at once.
//! The requests no longer wait for each other.
//!
//! # What it must not cost
//!
//! A skeleton identifier is a peer's claim about which block sits at a height.
//! It is never believed: it says only *where to ask*, and what makes the answer
//! trustworthy is that the chunks **link** — the oldest of the run from height
//! `p` must be the parent of the newest of the run from `p-192`. A wrong
//! identifier produces a chunk that fails that test and the range is asked of
//! somebody else. Every header still passes the full consensus rules; only the
//! questions are pipelined, never the answers accepted.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use alloy_primitives::{B256, U256};
use rsk_consensus::validation::HeaderVerifier;
use rsk_consensus::Header;

use crate::store::HeaderStore;

/// Headers per request, and so the spacing of skeleton points.
pub const HEADER_CHUNK: u64 = 192;

/// Identifiers one skeleton answer carries.
pub const SKELETON_POINTS: u64 = 20;

/// What the walk wants asked next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    Skeleton { start: u64 },
    Headers { from: B256, count: u32, point: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalkError {
    #[error("header #{number} failed validation: {reason}")]
    InvalidHeader { number: u64, reason: String },
    #[error("the headers for point {point} do not form a chain")]
    BrokenChunk { point: u64 },
    #[error("the chain leads back to a genesis this node has never seen")]
    ForeignGenesis,
}

/// A verified run of headers, remembered by its ends.
#[derive(Debug, Clone)]
struct Run {
    newest: B256,
    oldest_number: u64,
    oldest_parent: B256,
}

pub struct HeaderWalk {
    store: Arc<dyn HeaderStore>,
    verifier: Arc<HeaderVerifier>,

    top: Header,

    skeleton_todo: Vec<u64>,
    skeleton_sent: HashSet<u64>,
    points: BTreeMap<u64, B256>,

    headers_sent: HashSet<u64>,
    runs: BTreeMap<u64, Run>,

    need_number: u64,
    need_hash: B256,
    /// The lowest height the walk may descend to, with the difficulty already
    /// established there. `need_number` moves down the 192-block grid, so an
    /// arbitrary checkpoint height is never visited; the floor is where the
    /// walk anchors instead. `(number, cumulative_difficulty_through_number)`.
    floor: Option<(u64, U256)>,
    done: bool,

    walked_difficulty: U256,
    uncles_omitted: u64,

    anchor_difficulty: Option<U256>,
}

impl HeaderWalk {
    /// Walk down from `top`, stopping at the first block this node already
    /// accepts as canonical (which — via the seeding in
    /// [`HeaderStore`] — is at latest the checkpoint).
    pub fn new(
        top: Header,
        store: Arc<dyn HeaderStore>,
        verifier: Arc<HeaderVerifier>,
        floor: Option<(u64, U256)>,
    ) -> Self {
        let number = top.number;
        let top_hash = top.hash();

        let grid_top = (number / HEADER_CHUNK) * HEADER_CHUNK;

        let mut skeleton_todo = Vec::new();
        let span = HEADER_CHUNK * SKELETON_POINTS;
        let mut start = 0u64;
        while start <= grid_top {
            skeleton_todo.push(start);
            start += span;
        }
        // Popped with `pop()` (from the end), so ascending order means the top
        // skeleton — the one that unblocks the walk — is asked for first. The
        // top finishing is what lets `advance` start linking immediately.

        Self {
            store,
            verifier,
            top,
            skeleton_todo,
            skeleton_sent: HashSet::new(),
            points: BTreeMap::new(),
            headers_sent: HashSet::new(),
            runs: BTreeMap::new(),
            need_number: number,
            need_hash: top_hash,
            floor,
            done: false,
            walked_difficulty: U256::ZERO,
            uncles_omitted: 0,
            anchor_difficulty: None,
        }
    }

    /// Difficulty summed across every header verified so far.
    pub fn walked_difficulty(&self) -> U256 {
        self.walked_difficulty
    }

    /// How many uncles the walk could not account for.
    pub fn uncles_omitted(&self) -> u64 {
        self.uncles_omitted
    }

    /// Cumulative difficulty at the top once the walk anchors: what this node
    /// already had at the anchor, plus every header the walk verified above it.
    pub fn established_difficulty(&self) -> Option<U256> {
        self.anchor_difficulty
            .map(|anchor| anchor.saturating_add(self.walked_difficulty))
    }

    pub fn top_number(&self) -> u64 {
        self.top.number
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// The lowest height the linked chain reaches.
    pub fn frontier(&self) -> u64 {
        self.need_number
    }

    /// The height the walk anchors at, if one was configured.
    pub fn floor_number(&self) -> Option<u64> {
        self.floor.map(|(f, _)| f)
    }

    fn is_ours(&self, number: u64, hash: B256) -> bool {
        self.store.canonical_hash(number).ok().flatten() == Some(hash)
    }

    /// Up to `budget` things to ask for, none of them already outstanding.
    pub fn wants(&mut self, budget: usize) -> Vec<Want> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }

        let floor_number = self.floor.map(|(f, _)| f);
        let points: Vec<u64> = self
            .points
            .keys()
            .rev()
            .copied()
            .filter(|p| {
                if floor_number.is_some_and(|f| *p < f) {
                    return false;
                }
                !self.headers_sent.contains(p) && !self.runs.contains_key(p)
            })
            .take(budget)
            .collect();
        for point in points {
            let Some(hash) = self.points.get(&point).copied() else {
                continue;
            };
            self.headers_sent.insert(point);
            out.push(Want::Headers {
                from: hash,
                count: HEADER_CHUNK as u32,
                point,
            });
            if out.len() >= budget {
                return out;
            }
        }

        let grid_top = (self.top.number / HEADER_CHUNK) * HEADER_CHUNK;
        if self.top.number > grid_top
            && !self.headers_sent.contains(&self.top.number)
            && !self.runs.contains_key(&self.top.number)
        {
            self.headers_sent.insert(self.top.number);
            out.push(Want::Headers {
                from: self.top.hash(),
                count: (self.top.number - grid_top) as u32,
                point: self.top.number,
            });
            if out.len() >= budget {
                return out;
            }
        }

        while out.len() < budget {
            let Some(start) = self.skeleton_todo.pop() else {
                break;
            };
            if self.skeleton_sent.insert(start) {
                out.push(Want::Skeleton { start });
            }
        }
        out
    }

    /// Give up on an outstanding request so it can be asked of someone else.
    pub fn release(&mut self, want: &Want) {
        match want {
            Want::Skeleton { start } => {
                if self.skeleton_sent.remove(start) {
                    self.skeleton_todo.push(*start);
                }
            }
            Want::Headers { point, .. } => {
                self.headers_sent.remove(point);
            }
        }
    }

    /// Skeleton identifiers: where to ask, and nothing more.
    pub fn on_skeleton(&mut self, identifiers: &[rsk_p2p::protocol::BlockIdentifier]) {
        let floor_number = self.floor.map(|(f, _)| f);
        for id in identifiers {
            if id.number == 0 || id.number > self.top.number {
                continue;
            }
            // Nothing below the floor is ever wanted: those blocks are trusted
            // through the anchor, not re-downloaded.
            if let Some(floor) = floor_number {
                if id.number < floor {
                    continue;
                }
            }
            if self.runs.contains_key(&id.number) {
                continue;
            }
            self.points.insert(id.number, id.hash);
        }
    }

    /// A run of headers (newest first, as the protocol delivers them) with the
    /// original wire bytes each arrived in.
    ///
    /// Every header is verified on its own terms here — static rules, adjacent
    /// pairs, the internal chain — and stored. Whether it belongs to *our*
    /// chain is settled by whether it links, which [`Self::advance`] decides.
    pub fn on_headers(
        &mut self,
        point: u64,
        headers: &[(Header, Vec<u8>)],
        proven: &HashMap<B256, U256>,
    ) -> Result<(), WalkError> {
        self.headers_sent.remove(&point);
        if headers.is_empty() {
            return Ok(());
        }

        let newest = &headers[0].0;
        for pair in headers.windows(2) {
            let (child, parent) = (&pair[0].0, &pair[1].0);
            if child.parent_hash != parent.hash() {
                return Err(WalkError::BrokenChunk { point });
            }
            self.verifier
                .verify(parent, None)
                .map_err(|e| WalkError::InvalidHeader {
                    number: parent.number,
                    reason: e.to_string(),
                })?;
            self.verifier
                .verify_against_parent(child, parent)
                .map_err(|e| WalkError::InvalidHeader {
                    number: child.number,
                    reason: e.to_string(),
                })?;
        }
        self.verifier
            .verify(newest, None)
            .map_err(|e| WalkError::InvalidHeader {
                number: newest.number,
                reason: e.to_string(),
            })?;

        let floor_number = self.floor.map(|(f, _)| f);
        for (header, _raw) in headers {
            // Blocks below the floor belong to the trusted anchor, not to the
            // walked chain; they were verified as part of the run's internal
            // consistency but are neither stored nor credited here.
            if floor_number.is_some_and(|f| header.number < f) {
                continue;
            }
            let hash = header.hash();
            match proven.get(&hash) {
                Some(exact) => {
                    self.walked_difficulty = self.walked_difficulty.saturating_add(*exact);
                }
                None => {
                    self.walked_difficulty =
                        self.walked_difficulty.saturating_add(header.difficulty);
                    if header.uncle_count > 0 {
                        self.uncles_omitted += header.uncle_count;
                    }
                }
            }
        }

        // One write per run, not one per header: redb's write txn is the
        // expensive part, and a batch commit turns 192 txns into one.
        let entries: Vec<(u64, Vec<u8>)> = headers
            .iter()
            .filter(|(h, _)| !floor_number.is_some_and(|f| h.number < f))
            .map(|(h, r)| (h.number, r.clone()))
            .collect();
        if entries.is_empty() {
            self.runs.insert(
                point,
                Run {
                    newest: headers[0].0.hash(),
                    oldest_number: headers.last().unwrap().0.number,
                    oldest_parent: headers.last().unwrap().0.parent_hash,
                },
            );
            return Ok(());
        }
        self.store
            .put_headers(&entries)
            .map_err(|e| WalkError::InvalidHeader {
                number: 0,
                reason: e.to_string(),
            })?;

        let oldest = &headers[headers.len() - 1].0;
        self.runs.insert(
            point,
            Run {
                newest: newest.hash(),
                oldest_number: oldest.number,
                oldest_parent: oldest.parent_hash,
            },
        );
        Ok(())
    }

    /// Follow the links as far down as they now reach. Returns how many blocks
    /// the chain grew by (in height from the top).
    pub fn advance(&mut self) -> Result<u64, WalkError> {
        let started_at = self.need_number;

        loop {
            if self.is_ours(self.need_number, self.need_hash) {
                self.anchor_difficulty = Some(
                    self.store
                        .total_difficulty(self.need_hash)
                        .ok()
                        .flatten()
                        .unwrap_or_default(),
                );
                self.done = true;
                break;
            }
            if let Some((floor_number, floor_difficulty)) = self.floor {
                if self.need_number <= floor_number {
                    // Reached the checkpoint floor: everything above it is now
                    // anchored to the difficulty established there.
                    self.anchor_difficulty = Some(floor_difficulty);
                    self.done = true;
                    break;
                }
            }
            if self.need_number == 0 {
                return Err(WalkError::ForeignGenesis);
            }

            let Some(run) = self.runs.get(&self.need_number).cloned() else {
                break;
            };
            if run.newest != self.need_hash {
                self.runs.remove(&self.need_number);
                self.points.remove(&self.need_number);
                break;
            }

            self.runs.remove(&self.need_number);
            self.need_number = run.oldest_number.saturating_sub(1);
            self.need_hash = run.oldest_parent;
        }

        Ok(started_at.saturating_sub(self.need_number))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, B256, U256};
    use std::sync::Mutex;

    /// A canonical index mock: only heights listed are "ours", and their
    /// hashes are the real hashes from the synthetic chain.
    struct MockStore {
        stored: Mutex<Vec<(u64, Vec<u8>)>>,
        canonical: Mutex<std::collections::HashSet<u64>>,
        chain: Vec<Header>,
    }

    impl MockStore {
        fn new(chain: Vec<Header>) -> Self {
            Self {
                stored: Mutex::new(Vec::new()),
                canonical: Mutex::new(HashSet::new()),
                chain,
            }
        }
    }

    impl HeaderStore for MockStore {
        fn canonical_hash(&self, number: u64) -> anyhow::Result<Option<B256>> {
            if self.canonical.lock().unwrap().contains(&number) {
                Ok(Some(self.chain[number as usize].hash()))
            } else {
                Ok(None)
            }
        }
        fn put_headers(&self, entries: &[(u64, Vec<u8>)]) -> anyhow::Result<()> {
            self.stored.lock().unwrap().extend(entries.iter().cloned());
            Ok(())
        }
        fn total_difficulty(&self, _hash: B256) -> anyhow::Result<Option<U256>> {
            Ok(None)
        }
    }

    /// A linked chain of `count` headers (heights `0..count`), oldest first.
    fn chain(count: u64) -> Vec<Header> {
        let mut out = Vec::with_capacity(count as usize);
        for number in 0..count {
            let parent = out.last().map(Header::hash).unwrap_or(B256::ZERO);
            out.push(Header {
                parent_hash: parent,
                beneficiary: Address::ZERO,
                ommers_hash: B256::ZERO,
                state_root: B256::ZERO,
                transactions_root: B256::ZERO,
                receipts_root: B256::ZERO,
                logs_bloom: Default::default(),
                extension_data: None,
                difficulty: U256::from(1_000_000),
                number,
                gas_limit: U256::from(10_000_000),
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
            });
        }
        out
    }

    /// Feed a run: `count` headers newest-first, newest at `newest`, keyed at
    /// `point`. Includes each header's raw RLP bytes.
    fn run_headers(walk: &mut HeaderWalk, point: u64, newest: u64, count: u64) {
        let hdrs = chain(newest + 1);
        let slice: Vec<Header> = hdrs[newest as usize + 1 - count as usize..=newest as usize]
            .iter()
            .rev()
            .cloned()
            .collect();
        let pairs: Vec<(Header, Vec<u8>)> = slice
            .iter()
            .map(|h| {
                let mut buf = Vec::new();
                alloy_rlp::Encodable::encode(h, &mut buf);
                (h.clone(), buf)
            })
            .collect();
        walk.on_headers(point, &pairs, &HashMap::new()).unwrap();
    }

    fn skeleton(num: u64) -> rsk_p2p::protocol::BlockIdentifier {
        rsk_p2p::protocol::BlockIdentifier {
            hash: chain(num + 1)[num as usize].hash(),
            number: num,
        }
    }

    /// The walk descends a canonical-empty store to the floor, filtering
    /// below-floor headers out of both storage and the difficulty sum.
    #[test]
    fn walk_anchors_at_the_floor_and_filters_below_it() {
        let full = chain(600);
        let top = full[599].clone();
        let mock = Arc::new(MockStore::new(full));
        let store: Arc<dyn HeaderStore> = mock.clone();
        let mut walk = HeaderWalk::new(
            top,
            store.clone(),
            Arc::new(HeaderVerifier::new()),
            Some((100, U256::from(7))),
        );

        walk.on_skeleton(&[skeleton(576), skeleton(384), skeleton(192), skeleton(0)]);

        // Wants the top bespoke run and the highest grid points first (top-down).
        let points_wanted: Vec<u64> = walk
            .wants(8)
            .iter()
            .filter_map(|w| match w {
                Want::Headers { point, .. } => Some(*point),
                _ => None,
            })
            .collect();
        let mut sorted = points_wanted.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![192, 384, 576, 599]);

        run_headers(&mut walk, 599, 599, 23); // 599..577
        run_headers(&mut walk, 576, 576, 192); // 576..385
        run_headers(&mut walk, 384, 384, 192); // 384..193
        run_headers(&mut walk, 192, 192, 192); // 192..1 (1..99 below floor)

        walk.advance().unwrap();
        assert!(walk.is_done(), "walk should anchor at the floor");

        // Heights 100..599 are all stored (500 headers); 0..99 are not.
        let stored: Vec<u64> = {
            let s = mock.stored.lock().unwrap();
            s.iter().map(|(h, _)| *h).collect()
        };
        for h in 100..600 {
            assert!(stored.contains(&h), "height {h} should be stored");
        }
        for h in 0..100 {
            assert!(
                !stored.contains(&h),
                "height {h} should have been filtered (below floor)"
            );
        }

        // 500 headers' difficulty (1e6 each) plus the floor base (7).
        assert_eq!(
            walk.established_difficulty(),
            Some(U256::from(500_u64 * 1_000_000 + 7))
        );
        assert_eq!(walk.frontier(), 0);
    }

    /// A canonical store anchors the walk immediately (the resume case).
    #[test]
    fn walk_anchors_at_an_existing_canonical_head() {
        let full = chain(600);
        let top = full[599].clone();
        let mock = Arc::new(MockStore::new(full));
        {
            let mut c = mock.canonical.lock().unwrap();
            for h in 0..400u64 {
                c.insert(h);
            }
        }
        let store: Arc<dyn HeaderStore> = mock.clone();
        let mut walk = HeaderWalk::new(
            top,
            store.clone(),
            Arc::new(HeaderVerifier::new()),
            Some((100, U256::from(7))),
        );

        walk.on_skeleton(&[skeleton(576), skeleton(384), skeleton(192)]);
        run_headers(&mut walk, 599, 599, 23);
        run_headers(&mut walk, 576, 576, 192);
        run_headers(&mut walk, 384, 384, 192);

        walk.advance().unwrap();
        assert!(walk.is_done(), "walk should anchor on the canonical 0..400");
    }
}
