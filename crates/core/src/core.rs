//! The [`Core`] handle: one redb-backed store, opened once and shared by the
//! Bitcoin and Rootstock trees.
//!
//! This module owns only the handle and how it is built. The behaviour lives
//! with the domain: [`crate::btc`] for the Bitcoin chain and [`crate::rsk`] for
//! the Rootstock tree, both as `impl Core`.

use std::path::Path;
use std::sync::Arc;

use bitcoin::Network;
use rsk_consensus::config::ChainConfig;

use crate::error::Error;
use crate::rsk;
use crate::store::Store;

/// The side-effect-free core: a thin, deterministic layer over a redb-backed
/// store.
///
/// No concurrency, no network, no clock, no hidden I/O — the caller supplies
/// data and reads back outcomes.
pub struct Core {
    pub(crate) store: Store,
    pub(crate) network: Network,
    /// Rootstock consensus parameters the RSK tree validates against.
    pub(crate) rsk_chain: Arc<ChainConfig>,
}

impl Core {
    /// Open a file-backed store for the given network.
    pub fn open(path: &Path, network: Network) -> Result<Self, Error> {
        Ok(Self {
            store: Store::open(path)?,
            network,
            rsk_chain: rsk::chain_config(network),
        })
    }

    /// Open an in-memory store (tests, no disk I/O) for the given network.
    #[cfg(test)]
    pub fn in_memory(network: Network) -> Result<Self, Error> {
        Ok(Self {
            store: Store::in_memory()?,
            network,
            rsk_chain: rsk::chain_config(network),
        })
    }
}
