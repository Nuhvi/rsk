//! # btc-p2p — the Bitcoin P2P protocol client
//!
//! Transport, the `version`/`verack` handshake, and the small set of requests
//! a headers client needs, against the real Bitcoin network.
//!
//! This crate is deliberately **chain-agnostic protocol mechanics**: it never
//! interprets a header, never stores anything, and has no notion of the chain
//! state. Chain knowledge (the checkpoint spine, what to sync) lives with the
//! caller — `rsk-core` and above — which hands this crate a locator and gets
//! headers back.
//!
//! Deliberately minimal for now: mainnet only, P2P v1 transport (no BIP 324),
//! one blocking connection at a time, no tokio. `ServiceFlags::NONE` is
//! advertised because we serve nothing.

// Tests conventionally assert with `unwrap`-style calls; keep the strict lint
// for production code only.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod codec;
pub mod error;
pub mod seeds;
pub mod session;

#[cfg(test)]
pub(crate) mod mock;

pub use error::Error;
pub use session::{Handshake, Session};
