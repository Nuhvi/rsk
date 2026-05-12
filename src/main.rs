use serde_json::Value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let rpc_url = "https://public-node.rsk.co";

    async fn rpc_call(
        client: &reqwest::Client,
        url: &str,
        method: &str,
        params: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let mut resp: Value = client.post(url).json(&body).send().await?.json().await?;
        Ok(resp["result"].take())
    }

    let block_hex = rpc_call(&client, rpc_url, "eth_blockNumber", Value::Null)
        .await?
        .as_str()
        .unwrap()
        .to_string();
    let block_num = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16)?;
    println!("Latest Rootstock block: {}\n", block_num);

    let params = serde_json::json!([format!("{:#x}", block_num), false]);
    let block = rpc_call(&client, rpc_url, "eth_getBlockByNumber", params).await?;
    dbg!(&block);

    Ok(())
}
