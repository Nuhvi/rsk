//! RSK Light Client PoC — runnable example
//!
//! Usage:
//!     cargo run --example light_client_sync
//!
//! This will:
//! 1. Fetch the last 144 Bitcoin headers from blockstream.info
//! 2. Calculate total Bitcoin work over that window
//! 3. Walk backwards from the RSK chain tip, accumulating difficulty
//! 4. Report the finalized block once RSK work >= Bitcoin work

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
