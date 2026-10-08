//! The header sync engine: dial a peer, gate its claim, then run the parallel
//! skeleton walk down to the checkpoint, storing verified headers as it goes.

use std::sync::Arc;

use alloy_primitives::U256;
use anyhow::{anyhow, Result};
use rsk_consensus::checkpoint::{judge, Sample};
use rsk_consensus::validation::HeaderVerifier;
use rsk_store::Store;
use tracing::{info, warn};

use crate::config::SyncConfig;
use crate::session::{dial, fetch_top_header, SessionLoop};
use crate::store::{HeaderStore, RedbHeaderStore};
use crate::walk::HeaderWalk;

/// Maximum times the engine will re-dial a peer mid-walk after a dropped
/// connection before giving up.
const MAX_RECONNECTS: u32 = 20;

pub struct SyncEngine {
    store: Arc<Store>,
    config: SyncConfig,
    verifier: Arc<HeaderVerifier>,
}

pub struct SyncOutcome {
    /// How the peer's claimed total difficulty fared against the checkpoint
    /// ceiling once real headers had been sampled.
    pub gate_report: GateReport,
    /// Stored headers at or below this height are anchored to work this node
    /// trusts (the checkpoint, or a previously verified tip).
    pub anchored_at: u64,
    /// Cumulative difficulty of the walked chain: checkpoint + every header
    /// verified above it.
    pub established_difficulty: U256,
    /// The peer's advertised best height.
    pub peer_best: u64,
    /// The peer's advertised total difficulty.
    pub peer_claimed_td: Option<U256>,
}

pub struct GateReport {
    pub claimed: Option<U256>,
    pub established: U256,
    pub ceiling: U256,
    pub samples: usize,
    pub plausible: bool,
}

impl SyncEngine {
    pub fn new(store: Arc<Store>, config: SyncConfig) -> Self {
        let verifier = Arc::new(HeaderVerifier::default_rsk(Arc::new(config.chain.clone())));
        Self {
            store,
            config,
            verifier,
        }
    }

    /// Sync headers from the network into the store.
    ///
    /// Idempotent: verified headers are persisted as the walk goes, and a
    /// re-run anchors at the highest previously-verified grid boundary instead
    /// of re-downloading the whole chain.
    pub async fn sync(&mut self) -> Result<SyncOutcome> {
        let hstore = Arc::new(RedbHeaderStore::new(
            self.store.clone(),
            self.config.checkpoint,
        ));

        let mut conn = dial(&self.config).await?;
        let peer_best = conn.status.best_block_number;

        let top = fetch_top_header(
            &mut conn.framed,
            conn.status.best_block_hash,
            1,
            self.config.read_timeout,
        )
        .await?;
        info!(top = top.number, hash = %top.hash(), "walk start");

        let hstore_dyn: Arc<dyn HeaderStore> = hstore.clone();
        let floor = Some((
            self.config.checkpoint.number,
            self.config.checkpoint.cumulative_difficulty,
        ));
        let mut walk = HeaderWalk::new(top, hstore_dyn, self.verifier.clone(), floor);

        if !walk.is_done() {
            let mut reconnects = 0u32;
            loop {
                {
                    let mut session = SessionLoop::new(
                        &mut conn.framed,
                        &mut walk,
                        self.config.pipeline,
                        self.config.read_timeout,
                    );
                    loop {
                        match session.step().await {
                            Ok(true) => break,
                            Ok(false) => continue,
                            Err(e) => {
                                warn!(error = %e, "session error");
                                session.release_all();
                                break;
                            }
                        }
                    }
                }
                if walk.is_done() {
                    break;
                }
                info!(
                    frontier = walk.frontier(),
                    "reconnecting to continue the walk"
                );
                drop(conn);
                reconnects += 1;
                if reconnects > MAX_RECONNECTS {
                    return Err(anyhow!(
                        "gave up after {reconnects} reconnects at height {}",
                        walk.frontier()
                    ));
                }
                conn = dial(&self.config).await?;
            }
        }

        let established = walk
            .established_difficulty()
            .ok_or_else(|| anyhow!("walk finished without establishing difficulty"))?;
        let anchored_at = walk.frontier();

        // The chain is now linked down to what we already trusted; promote the
        // verified stretch to canonical so the next run resumes from here.
        let canonicalized = hstore.canonicalize_above_checkpoint(peer_best)?;
        info!(canonicalized, "promoted verified headers to canonical");

        let samples = collect_samples(&self.store, &self.config.checkpoint, peer_best)?;
        let gate = self.audit(&conn.status, established, &samples);

        info!(
            anchored_at,
            established = %established,
            headers_walked = peer_best.saturating_sub(anchored_at),
            uncles_omitted = walk.uncles_omitted(),
            "header walk complete"
        );

        Ok(SyncOutcome {
            gate_report: gate,
            anchored_at,
            established_difficulty: established,
            peer_best,
            peer_claimed_td: conn.status.total_difficulty,
        })
    }

    fn audit(
        &self,
        status: &rsk_p2p::RskStatus,
        established: U256,
        samples: &[Sample],
    ) -> GateReport {
        let cp = &self.config.checkpoint;
        let claimed = status.total_difficulty;
        let head = status.best_block_number;

        let verdict = judge(
            cp,
            claimed.unwrap_or_default(),
            samples,
            head,
            400,
            self.config.chain.min_difficulty,
        );
        let (plausible, ceiling) = match verdict {
            rsk_consensus::checkpoint::CheckpointVerdict::Plausible { ceiling } => (true, ceiling),
            rsk_consensus::checkpoint::CheckpointVerdict::Impossible {
                claimed: _,
                ceiling,
            } => (false, ceiling),
            rsk_consensus::checkpoint::CheckpointVerdict::Contradicted { .. } => {
                (false, U256::ZERO)
            }
        };

        match claimed {
            Some(c) if c < established => {
                // Diagnostic only: `established` mixes the checkpoint's
                // uncle-inclusive base with header-only walked work, so it is
                // not a precise lower bound and a small overstatement is
                // ordinary. The `judge` ceiling below is the real gate.
                info!(
                    %c,
                    established = %established,
                    "peer's total difficulty is below our estimated verified work \
                     (approximate; see checkpoint gate)"
                );
            }
            _ => {}
        }

        info!(
            ?claimed,
            established = %established,
            ceiling = %ceiling,
            samples = samples.len(),
            plausible,
            "checkpoint gate"
        );

        GateReport {
            claimed,
            established,
            ceiling,
            samples: samples.len(),
            plausible,
        }
    }
}

/// Read every `step`-th stored header above the checkpoint as a gate sample.
/// `step` keeps the scan cheap while the empirical-Bernstein uncle allowance
/// only needs a few hundred samples to be tight.
pub fn collect_samples(
    store: &Store,
    checkpoint: &rsk_consensus::checkpoint::DifficultyCheckpoint,
    tip: u64,
) -> Result<Vec<Sample>> {
    const STEP: u64 = 768;
    let mut out = Vec::new();
    let mut number = checkpoint.number + 1;
    while number <= tip {
        let Some(raw) = store.rsk_get_header_at_height(number)? else {
            number += 1;
            continue;
        };
        let mut slice = raw.as_slice();
        let header = rsk_consensus::Header::decode_with_hash(&mut slice)
            .map_err(|e| anyhow::anyhow!("sample #{number}: {e}"))?;
        out.push(Sample {
            number,
            difficulty: header.difficulty,
            uncle_count: header.uncle_count,
        });
        number += STEP;
    }
    Ok(out)
}
