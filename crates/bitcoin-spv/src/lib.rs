//! Bitcoin SPV library for RSK One.
//!
//! Intended home for:
//! - Bitcoin block header verification (PoW, chain continuity)
//! - SPV proofs: coinbase transaction fetching and Merkle/merkleblock verification
//! - Esplora clients with multi-host rotation
//! - A storage trait for Bitcoin chain state (headers, proofs, checkpoints)
//!
//! The `checkpoints` binary (see `bin/checkpoints.rs`) downloads the header at
//! the start of every difficulty period (height % 2016 == 0) into
//! `checkpoints.txt` in this crate's directory.

pub const CHECKPOINTS_PATH: &str = "checkpoints.txt";

pub fn checkpoints() -> &'static str {
    include_str!("../checkpoints.txt")
}
