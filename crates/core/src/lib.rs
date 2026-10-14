//! # rsk-core — the side-effect-free core
//!
//! The deterministic heart of RSK One's fast-IBD plan: keep the Bitcoin
//! canonical chain, finalize it at difficulty-period boundaries, and later carry
//! Rootstock headers on the same tree.
//!
//! No concurrency, no network, no clock, no hidden I/O. The only state is a
//! redb-backed store, reached only through a transaction: [`Chain`] opens a read
//! snapshot or the writer at the start of each method.
//!
//! Design is still in flux; see `CONTRIBUTING.md` (repo root) for the plan.

// Tests read/write a deterministic in-memory store and conventionally use
// `unwrap`; keep the strict lint for production code only.
#![cfg_attr(test, allow(clippy::unwrap_used))]
// The error enum deliberately mirrors redb's error types (`thiserror`), which
// makes `Result<_, Error>` larger than clippy's default threshold. That shape
// is intentional (see CONTRIBUTING.md); every fallible method returns it.
#![allow(clippy::result_large_err)]

pub mod chain;
pub mod checkpoints;
pub mod error;
mod store;
pub mod validation;

pub use chain::{Chain, ConnectOutcome, FINALITY_MARGIN_BLOCKS, header_work};
pub use error::Error;
pub use store::DIFFICULTY_PERIOD;
pub use validation::MEDIAN_TIME_PAST;
