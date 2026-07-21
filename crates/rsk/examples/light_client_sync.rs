//! RSK Light Client PoC — runnable example
//!
//! Usage:
//!     RSK_RPC_URL=https://rpc.mainnet.rootstock.io/YOUR_KEY cargo run --example light_client_sync
//!
//! This will:
//! 1. Derive Bitcoin work target from the RSK tip's embedded Bitcoin header
//! 2. Walk backwards from the RSK chain tip, verifying merge-mining proofs (Rules 1-7)
//!    for EVERY block using data from the RSK node's JSON-RPC API
//! 3. Report the finalized block once RSK cumulative work >= Bitcoin target work

use rsk::light_client::{self, LightClientConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = LightClientConfig::default();
    let result = light_client::sync_light_client(&config)?;

    println!("\nLight client sync complete!");
    println!(
        "Chain finalized at block {} ({:?})",
        result.finalized_height, result.finalized_block_hash
    );

    Ok(())
}
