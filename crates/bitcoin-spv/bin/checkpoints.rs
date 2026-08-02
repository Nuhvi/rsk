//! Bitcoin Checkpoints
//!
//! Download the 80-byte Bitcoin header at the start of every difficulty
//! period (height % 2016 == 0), starting from genesis, from an Esplora API.
//! Headers are written to `checkpoints.txt` in this crate's directory as one
//! hex line each, in height order.
//!
//! On rerun the file is read back: already-downloaded period starts are
//! skipped and the walk resumes forward from the next multiple of 2016.
//!
//! Usage:
//!   cargo run --bin checkpoints
//!   cargo run --bin checkpoints -- --file /somewhere/else.txt
//!
//! Environment:
//!   ESPLORA_URL (default https://blockstream.info/api; comma-separated
//!   hosts are tried in rotation on failure)

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use reqwest::Client;
use tokio::time::sleep;

const DIFFICULTY_PERIOD: u64 = 2016;
const PAUSE_MS: u64 = 150;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Anchor the output to the crate directory so it lands in the same place
    // no matter which directory the binary is invoked from. CARGO_MANIFEST_DIR
    // is the absolute path to crates/bitcoin-spv, baked in at compile time.
    let default_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("checkpoints.txt");
    let mut file_path = default_file.to_string_lossy().to_string();
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--file" => file_path = args.next().ok_or("--file needs a value")?,
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let hosts: Vec<String> = std::env::var("ESPLORA_URL")
        .unwrap_or_else(|_| "https://blockstream.info/api".to_string())
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("rsk-period-headers/0.1")
        .build()?;
    let esplora = Esplora {
        client,
        hosts,
        current: AtomicUsize::new(0),
    };
    eprintln!("esplora hosts: {}", esplora.hosts.join(", "));

    // Resume state lives in the file: N headers means the first N difficulty
    // periods are done, so the next period start is height N * 2016.
    let existing = if Path::new(&file_path).exists() {
        std::fs::read_to_string(&file_path)?
    } else {
        String::new()
    };
    let existing: Vec<String> = existing
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    for line in &existing {
        validate_header_hex(line)?;
    }
    let next_start = existing.len() as u64 * DIFFICULTY_PERIOD;
    eprintln!(
        "loaded {} headers from {file_path}; resuming at height {next_start}",
        existing.len()
    );

    let tip: u64 = esplora.get("/blocks/tip/height").await?.trim().parse()?;
    eprintln!("bitcoin tip height: {tip}");

    // Ensure the parent directory exists (e.g. for an explicit --file path).
    if let Some(parent) = Path::new(&file_path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut out = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file_path)?;

    let mut height = next_start;
    while height <= tip {
        let hash = esplora
            .get(&format!("/block-height/{height}"))
            .await?
            .trim()
            .to_string();
        let header_hex = esplora
            .get(&format!("/block/{hash}/header"))
            .await?
            .trim()
            .to_string();
        validate_header_hex(&header_hex)?;
        writeln!(out, "{header_hex}")?;
        eprintln!("period start {height}: saved {hash}");
        sleep(Duration::from_millis(PAUSE_MS)).await;
        height += DIFFICULTY_PERIOD;
    }

    eprintln!(
        "done: {} period-start headers in {file_path}",
        tip / DIFFICULTY_PERIOD + 1
    );
    Ok(())
}

/// Check a hex string decodes to an 80-byte Bitcoin block header.
fn validate_header_hex(hex_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex)?;
    if bytes.len() != 80 {
        return Err(format!("expected 80-byte header, got {} bytes", bytes.len()).into());
    }
    Ok(())
}

// Esplora client with host rotation: on any failure (rate limit, outage)
// the next request goes to the next host; the tool only sleeps once every
// host in the pool has failed in the current cycle.
struct Esplora {
    client: Client,
    hosts: Vec<String>,
    current: AtomicUsize,
}

impl Esplora {
    async fn get(&self, path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let host_count = self.hosts.len().max(1);
        let total_attempts = host_count * 8;
        let mut last_error: Option<String> = None;
        for attempt in 0..total_attempts {
            let host = &self.hosts[self.current.load(Ordering::Relaxed) % host_count];
            let url = format!("{host}{path}");
            match self.client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    return Ok(response.text().await?);
                }
                Ok(response) => last_error = Some(format!("GET {url}: HTTP {}", response.status())),
                Err(error) => last_error = Some(format!("GET {url}: {error}")),
            }
            self.current.fetch_add(1, Ordering::Relaxed);
            if (attempt + 1) % host_count == 0 {
                let cycle = ((attempt + 1) / host_count) as u32;
                let wait_seconds = (1u64 << cycle.min(7)).min(120);
                eprintln!("  all esplora hosts failing, backing off {wait_seconds}s");
                sleep(Duration::from_secs(wait_seconds)).await;
            }
        }
        Err(last_error
            .unwrap_or_else(|| format!("GET {path} failed on all hosts"))
            .into())
    }
}
