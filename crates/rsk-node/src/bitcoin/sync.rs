use bitcoin::block::Header as BitcoinHeader;
use electrum_client::{ElectrumApi, GetHeadersRes};
use tracing::{info, warn};

use crate::bitcoin::difficulty::DifficultyTracker;
use crate::bitcoin::storage::{BitcoinHeaderStorage, header_work};
use crate::error::NodeError;

/// Connect to Electrum servers. Returns connected clients.
pub fn connect_electrum(urls: &[String]) -> Result<Vec<electrum_client::Client>, NodeError> {
    let mut clients = Vec::new();
    for url in urls {
        match electrum_client::Client::new(url) {
            Ok(c) => {
                info!(url = %url, "connected to Electrum");
                clients.push(c);
            }
            Err(e) => warn!(url = %url, error = %e, "failed to connect"),
        }
    }
    if clients.is_empty() {
        return Err(NodeError::Electrum("no Electrum servers connected".into()));
    }
    Ok(clients)
}

fn pick_client<'a>(
    clients: &'a [electrum_client::Client],
    idx: &mut usize,
) -> &'a electrum_client::Client {
    let c = &clients[*idx % clients.len()];
    *idx += 1;
    c
}

/// Fetch Bitcoin headers from Electrum starting at `start_height`.
pub fn fetch_headers(
    clients: &[electrum_client::Client],
    idx: &mut usize,
    start_height: u64,
    count: u64,
) -> Result<Vec<BitcoinHeader>, NodeError> {
    let max_per_request = 2016u64;
    let mut all = Vec::with_capacity(count as usize);
    let mut remaining = count;
    let mut current = start_height;

    while remaining > 0 {
        let batch = remaining.min(max_per_request);
        let client = pick_client(clients, idx);
        let res: GetHeadersRes = client
            .block_headers(current as usize, batch as usize)
            .map_err(|e| NodeError::Electrum(e.to_string()))?;

        for header in &res.headers {
            all.push(*header);
        }

        let fetched = res.headers.len() as u64;
        if fetched == 0 {
            break;
        }
        remaining = remaining.saturating_sub(fetched);
        current += fetched;
    }

    Ok(all)
}

/// Get the current tip height from Electrum.
pub fn get_tip_height(
    clients: &[electrum_client::Client],
    idx: &mut usize,
) -> Result<u64, NodeError> {
    let client = pick_client(clients, idx);
    let header = client
        .block_headers_subscribe()
        .map_err(|e| NodeError::Electrum(e.to_string()))?;
    Ok(header.height as u64)
}

/// Sync Bitcoin headers from Electrum into storage (incremental).
pub fn sync_bitcoin_headers(
    storage: &BitcoinHeaderStorage,
    clients: &[electrum_client::Client],
    idx: &mut usize,
    difficulty_tracker: &mut DifficultyTracker,
    checkpoint_height: u64,
) -> Result<u64, NodeError> {
    let start_height = match storage.get_tip_height()? {
        Some(tip) => {
            if tip >= checkpoint_height {
                tip + 1
            } else {
                checkpoint_height
            }
        }
        None => checkpoint_height,
    };

    let tip_height = get_tip_height(clients, idx)?;
    info!(
        start = start_height,
        tip = tip_height,
        "Bitcoin header sync"
    );

    if start_height > tip_height {
        info!("already synced to tip {tip_height}");
        if let Some(tip) = storage.get_tip_height()? {
            difficulty_tracker.rebuild_from_chain(storage, tip)?;
        }
        return Ok(tip_height);
    }

    // Rebuild difficulty tracker from what we have
    if let Some(tip) = storage.get_tip_height()? {
        difficulty_tracker.rebuild_from_chain(storage, tip)?;
    }

    let batch_size = 2016u64;
    let mut current = start_height;

    while current <= tip_height {
        let count = (tip_height + 1 - current).min(batch_size);
        let headers = fetch_headers(clients, idx, current, count)?;

        if headers.is_empty() {
            break;
        }

        let mut validated = Vec::with_capacity(headers.len());
        for (i, header) in headers.iter().enumerate() {
            let height = current + i as u64;

            // Validate chain continuity
            if height > checkpoint_height {
                if let Some(prev) = storage.get_header_at_height(height - 1)? {
                    if header.prev_blockhash != prev.block_hash() {
                        return Err(NodeError::Validation(format!(
                            "Bitcoin header at {height}: prev_blockhash mismatch"
                        )));
                    }
                }
            }

            // Validate PoW
            header
                .validate_pow(header.target())
                .map_err(|e| NodeError::Validation(format!("Bitcoin PoW at {height}: {e}")))?;

            let work = header_work(header);
            difficulty_tracker.add_block(work);
            validated.push((height, *header));
        }

        let stored = storage.append_headers(&validated)?;
        current += stored as u64;

        let pct = ((current - start_height) as f64 / (tip_height + 1 - start_height) as f64 * 100.0)
            as u64;
        info!(height = current - 1, pct = %pct, "Bitcoin sync progress");
    }

    info!(
        tip = tip_height,
        cumulative_work = %difficulty_tracker.cumulative_work(),
        "Bitcoin sync complete"
    );

    Ok(tip_height)
}
