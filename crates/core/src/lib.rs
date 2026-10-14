//! # rsk-core — the side-effect-free core
//!
//! The deterministic heart of RSK One's fast-IBD plan (the *ephemeral
//! sidechain* model): find and keep the **Bitcoin canonical chain**, checkpoint
//! it at difficulty-period boundaries, and prune everything below final.
//!
//! ## What "side-effect free" means here
//!
//! This crate has no concurrency, no network, no clock and no hidden I/O. The
//! only state is a redb-backed store; all logic is synchronous and driven
//! entirely by the caller:
//!
//! ```text
//! seed_checkpoints  →  connect_headers  (finalizes automatically; repeat)
//! ```
//!
//! Every read-modify-write — connecting headers, selecting the best chain and
//! advancing the finality floor — happens inside a single redb write
//! transaction, so the store cannot change under a decision. All store access
//! goes through a transaction: read-only methods open a consistent snapshot and
//! mutating methods open the single writer, at the start of every [`Chain`]
//! method.
//!
//! Tests construct the store over redb's **in-memory backend**, so the exact
//! production code path runs with zero disk access and a fully deterministic
//! sequence of inputs → outputs.
//!
//! ## The trust model (Electrum's)
//!
//! - The anchor is a **checkpoint spine**: one header per difficulty period
//!   (2016 blocks), seeded from this crate's embedded `checkpoints.txt` and
//!   trusted wholesale (no ancestor validation). One header per period is
//!   enough to know the *entire* chain's work, because Bitcoin difficulty is
//!   constant within a period.
//! - Headers above the spine are PoW-, continuity-, difficulty- and
//!   timestamp-validated (see [`validation`]) and kept as a **tree of chains**
//!   (forks), each with a forkpoint and a parent. The best chain is the one
//!   with the most cumulative work; a fork that is lighter is kept (not
//!   rejected) and can win later if it becomes heavier. This is Electrum's
//!   `BlockchainManager` model.
//! - Once a difficulty period is a full period below the tip, its boundary is
//!   finalized as the store's **tail start**, and forks cannot cross it (like
//!   Electrum's hardcoded max checkpoint). The Bitcoin headers themselves are
//!   retained until Rootstock reaches FINAL, when they can be pruned.
//!
//! The same tree will later carry Rootstock headers and reorg them with the
//! same machinery. See `CONTRIBUTING.md` (repo root) for the working plan.

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
