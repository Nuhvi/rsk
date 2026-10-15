//! The [`Node`] handle: owns the chain store and drives the operations an
//! embedder asks for.

use std::collections::VecDeque;

use anyhow::{Context, Result, bail};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::Encodable;
use rsk_core::Core;
use tracing::{info, warn};

use crate::config::{Anchor, Config};
use crate::peers;
use crate::sync::{self, SyncReport};

/// The RSK One node: a chain store plus the configuration it was opened with.
///
/// Nothing runs in the background — call [`Node::sync`] to make progress. The
/// store is durable, so a later [`Node::open`] resumes from the tip.
pub struct Node {
    core: Core,
    config: Config,
}

impl Node {
    /// Open (creating the data directory and store if needed) the node.
    pub fn open(config: Config) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("creating data dir {}", config.data_dir.display()))?;
        // Make the location unambiguous: log the absolute path, not the
        // relative one the caller passed (or the default).
        let data_dir = std::fs::canonicalize(&config.data_dir)
            .with_context(|| format!("resolving data dir {}", config.data_dir.display()))?;
        let store_path = data_dir.join("chain.redb");
        info!("data directory: {}", data_dir.display());
        info!("chain store:    {}", store_path.display());

        let core = Core::open(&store_path, config.network)?;
        Ok(Self { core, config })
    }

    /// The chain store, for reads an embedder wants to do directly.
    pub fn core(&self) -> &Core {
        &self.core
    }

    /// The configuration the node was opened with.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Plant the trust anchor if the store is empty, then download and validate
    /// the Bitcoin tail above it. Overlaps the fetch with validation across the
    /// configured peers.
    pub fn sync(&self) -> Result<SyncReport> {
        let from = plant_anchor(&self.core, &self.config)?;
        info!("syncing from height {from} …");

        let (candidates, failed) = peers::candidates(self.config.addrs.clone(), &self.config.seeds);
        if !failed.is_empty() {
            warn!("seed(s) failed to resolve: {}", failed.join(", "));
        }
        if candidates.is_empty() {
            bail!("no candidate peers: every DNS seed failed to resolve");
        }
        let mut candidates: VecDeque<_> = candidates.into_iter().collect();
        sync::run(&self.core, &self.config, &mut candidates)
    }

    /// The finalized period-boundary headers as `checkpoints.txt` text (one hex
    /// header per line, line `i` at height `i * DIFFICULTY_PERIOD`).
    ///
    /// Only checkpoints at or below the finalized floor are written — those
    /// that have satisfied the finality rule and are safe to treat as
    /// irreversible. The tip's nearest boundary is deliberately excluded.
    pub fn export_checkpoints(&self) -> Result<String> {
        let finalized = self
            .core
            .finalized_height()?
            .context("store is not seeded")?;
        let checkpoints = self.core.finalized_checkpoints()?;
        if checkpoints.is_empty() {
            bail!("no finalized checkpoints at or below {finalized}");
        }

        let mut text = String::new();
        for (_, header) in &checkpoints {
            let mut bytes = Vec::with_capacity(80);
            header
                .consensus_encode(&mut bytes)
                .expect("encoding to vec is infallible");
            text.push_str(&hex::encode(&bytes));
            text.push('\n');
        }
        Ok(text)
    }
}

/// Plant the trust anchor once and return the first height to download. On a
/// store that is already anchored this is just the height above the tip.
fn plant_anchor(core: &Core, config: &Config) -> Result<u64> {
    if let Some(tip) = core.tip_height()? {
        info!("resume: store already anchored at tip {tip}; continuing above it");
        return Ok(tip + 1);
    }

    match config.anchor {
        Anchor::Genesis => {
            let genesis = genesis_block(config.network).header;
            core.seed_checkpoints(&[(0, genesis)])?;
            info!("anchor: genesis only — validating the whole chain from block 1");
            Ok(1)
        }
        Anchor::Spine { cut } => {
            let spine = rsk_core::btc::checkpoints::parse()?;
            let cut = cut as usize;
            anyhow::ensure!(
                cut < spine.len(),
                "--cut {cut} is past the end of the {}-period spine",
                spine.len()
            );
            let prefix = &spine[..spine.len() - cut];
            core.seed_checkpoints(prefix)?;
            let seed_height = prefix.last().context("non-empty spine")?.0;
            if cut == 0 {
                info!(
                    "anchor: {} embedded checkpoints trusted (heights 0..={seed_height}); syncing the tail above them",
                    prefix.len()
                );
            } else {
                info!(
                    "anchor: {} checkpoints trusted up to {seed_height}; validating {cut} period(s) of real headers above",
                    prefix.len()
                );
            }
            Ok(seed_height + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    /// A fresh temp store for one test. The temp dir must outlive the store.
    fn store() -> (tempfile::TempDir, Core) {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::open(&dir.path().join("chain.redb"), Network::Bitcoin).unwrap();
        (dir, core)
    }

    #[test]
    fn anchor_trusts_the_whole_spine_by_default() {
        let (_dir, core) = store();
        let spine = rsk_core::btc::checkpoints::parse().unwrap();
        let from = plant_anchor(&core, &Config::default()).unwrap();
        assert_eq!(from, spine.last().unwrap().0 + 1);
    }

    #[test]
    fn anchor_cut_trusts_fewer_checkpoints() {
        let (_dir, core) = store();
        let spine = rsk_core::btc::checkpoints::parse().unwrap();
        let config = Config {
            anchor: Anchor::Spine { cut: 2 },
            ..Config::default()
        };
        // Trust everything but the last two periods.
        assert_eq!(
            plant_anchor(&core, &config).unwrap(),
            spine[spine.len() - 3].0 + 1
        );
    }

    #[test]
    fn anchor_resumes_above_an_anchored_tip() {
        let (_dir, core) = store();
        let spine = rsk_core::btc::checkpoints::parse().unwrap();
        core.seed_checkpoints(&spine[..3]).unwrap();
        // Already anchored: resume above the tip, ignoring the anchor setting.
        let config = Config {
            anchor: Anchor::Genesis,
            ..Config::default()
        };
        assert_eq!(plant_anchor(&core, &config).unwrap(), spine[2].0 + 1);
    }

    #[test]
    fn anchor_from_genesis_starts_at_one() {
        let (_dir, core) = store();
        let config = Config {
            anchor: Anchor::Genesis,
            ..Config::default()
        };
        assert_eq!(plant_anchor(&core, &config).unwrap(), 1);
        assert_eq!(core.tip_height().unwrap(), Some(0));
    }
}
