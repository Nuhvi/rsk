use ethers::prelude::*;
use std::convert::TryFrom;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Rootstock Public RPC (Mainnet)
    let rpc_url = "https://public-node.rsk.co";
    let provider = Provider::<Http>::try_from(rpc_url)?;

    // Get the latest block number
    let block_number = provider.get_block_number().await?;
    println!("Latest Rootstock block: {}", block_number);

    // Get the full block header
    if let Some(block) = provider.get_block(block_number).await? {
        println!("Block Hash: {:?}", block.hash);
        println!("Parent Hash: {:?}", block.parent_hash);
    }

    Ok(())
}
