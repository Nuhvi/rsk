// rsk-epoch-tags
//
// Iteratively picks a work-based "tail" of Bitcoin blocks ending at a
// reorg-safe confirmed tip (>= `confirmations` below the live tip), measures
// merge-mining participation and CPV agreement over it, and only stops once the
// combined statistic t = participation x agreement exceeds a threshold T:
//
//   1. Start from the (work-based) epoch tail: walk back epoch by epoch from
//      the confirmed tip while the tail's cumulative work (sum of per-block
//      difficulty) does NOT exceed the single epoch before it (~difficulty
//      * 2016). The tail is everything from the final boundary to the tip.
//   2. Download every block header and the coinbases (to parse the RSKBLOCK
//      tag) for the current tail, concurrently and out of order.
//   3. Compute t = participation x agreement over that tail.
//   4. If t > T (default 0.5, override with --threshold) we succeed and print
//      the full table. Otherwise extend the tail back one full epoch and
//      re-measure, repeating until t > T or the lookback cap is reached.
//
// Agreement is RSKIP110-style: a CPV byte is a property of the shared ancestor
// history, not of the tag, so every tag referencing the same checkpoint height
// MUST claim the same byte; tags that diverge from the majority are flagged.
//
// The 32-byte tag (RSKIP110) is laid out as:
//   [0..20]  PREFIX - 20-byte prefix of hashForMergedMining
//   [20..27] CPV    - LSBs of the Bitcoin ids merge-mined with 7 RSK
//                     "checkpoint" blocks (j = 0..6)
//   [27]     NU     - number of uncles referenced in the last 32 RSK blocks
//   [28..32] BN     - the RSK block height being mined (big endian)
//
// CPV checkpoint j corresponds to the RSK block at height
//   base - j*64,  where base = ((BN - 1) / 64) * 64
// (v(0) is the newest checkpoint). A CPV byte is a property of the shared
// ancestor history (the LSB of the Bitcoin block id that checkpoint was merged
// into), not of the tag, so every tag referencing the same checkpoint MUST claim
// the same byte — which is what the agreement check exploits.
//
// Data comes from Electrum: headers in 2016-block batches and coinbases fetched
// in parallel across many public Electrum servers (each worker thread drives its
// own connection, failing over to the next server on error). Everything is
// persisted to a redb cache so re-runs and interrupted runs cost almost nothing.
//
// Usage:
//   cargo run -p rsk-node --example epoch_tags \
//       [--period-len N] [--confirmations N] [--concurrency N] \
//       [--lookback-epochs N] [--db PATH]
//
// Environment:
//   ELECTRUM_URLS  (comma-separated, comma+space optional; defaults to a
//                   set of well-known public servers)

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::block::Header as BitcoinHeader;
use electrum_client::{Client as ElectrumClient, ConfigBuilder, ElectrumApi};
use redb::{Database, TableDefinition};

const TAG_MAGIC: &[u8] = b"RSKBLOCK:";

// Bitcoin's retarget interval; consensus-fixed at 2016.
const PERIOD_LENGTH: u64 = 2016;
// The top of the epoch must have at least this many blocks above it so the
// epoch can no longer change in a reorg.
const CONFIRMATIONS: u64 = 6;
const ELECTRUM_TIMEOUT: Duration = Duration::from_secs(3);
// Wall-clock cap for any single Electrum operation (across all failover
// attempts), so a couple of dead connections can never stall the run.
const CALL_DEADLINE: Duration = Duration::from_secs(6);

// bitcoin block: height -> [32-byte hash][8-byte BE timestamp][1-byte flags][32-byte tag]
// flags bit 0 = coinbase fetched this run, bit 1 = tag present.
const EPOCH_BLOCK_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("epoch_block");
// raw coinbase transaction: height -> serialized coinbase bytes (cached eagerly).
const COINBASE_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("coinbase");
// epoch difficulty: epoch-start height -> 8-byte BE f64 (constant per epoch).
const EPOCH_DIFF_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("epoch_difficulty");

fn default_servers() -> Vec<String> {
    [
        "ssl://electrum.blockstream.info:50002",
        "tcp://electrum.blockstream.info:50001",
        "ssl://electrum.bitaroo.net:50002",
        "tcp://electrum.bitaroo.net:50001",
        "ssl://electrum.emzy.de:50002",
        "ssl://electrum.vom-stausee.de:50002",
        "ssl://electrum.diynodes.com:50002",
        "ssl://electrums.bitcoin.de:50002",
        "ssl://electrum.anduck.net:50002",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn main() -> Result<()> {
    let mut period_length = PERIOD_LENGTH;
    let mut confirmations = CONFIRMATIONS;
    let mut concurrency = 16usize;
    let mut lookback_epochs = 24u64;
    let mut threshold = 0.5f64;
    let mut print_table_arg = false;
    let mut database_path = "epoch-tags.redb".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--period-len" => {
                period_length = args.next().context("--period-len needs a value")?.parse()?
            }
            "--confirmations" => {
                confirmations = args
                    .next()
                    .context("--confirmations needs a value")?
                    .parse()?
            }
            "--concurrency" => {
                concurrency = args
                    .next()
                    .context("--concurrency needs a value")?
                    .parse()?
            }
            "--lookback-epochs" => {
                lookback_epochs = args
                    .next()
                    .context("--lookback-epochs needs a value")?
                    .parse()?
            }
            "--threshold" => {
                threshold = args.next().context("--threshold needs a value")?.parse()?
            }
            "--print-table" => {
                print_table_arg = args
                    .next()
                    .context("--print-table needs a value")?
                    .parse()?
            }
            "--db" | "--cache" => database_path = args.next().context("--db needs a value")?,
            other => bail!("unknown argument: {other}"),
        }
    }

    let server_urls: Vec<String> = std::env::var("ELECTRUM_URLS")
        .map(|s| {
            s.split(',')
                .map(|part| part.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_else(|_| default_servers());
    if server_urls.is_empty() {
        bail!("no electrum servers configured");
    }

    let mut clients: Vec<ElectrumClient> = Vec::new();
    for url in &server_urls {
        let config = ConfigBuilder::new()
            .timeout(Some(ELECTRUM_TIMEOUT))
            .retry(0)
            .build();
        match ElectrumClient::from_config(url, config) {
            Ok(client) => {
                eprintln!("connected: {url}");
                clients.push(client);
                if clients.len() >= concurrency {
                    break;
                }
            }
            Err(e) => eprintln!("failed to connect {url}: {e}"),
        }
    }
    if clients.is_empty() {
        bail!("no electrum servers connected");
    }
    // One connection per distinct server: replicating the same server into many
    // connections hammers it (resets/EOFs) and only makes failover slower.
    eprintln!(
        "using {} electrum connections (one per server)",
        clients.len()
    );
    let pool = Arc::new(ClientPool {
        clients: Mutex::new(VecDeque::from(clients)),
    });

    let database = Database::create(&database_path)?;
    {
        let transaction = database.begin_write()?;
        transaction.open_table(EPOCH_BLOCK_TABLE)?;
        transaction.open_table(COINBASE_TABLE)?;
        transaction.open_table(EPOCH_DIFF_TABLE)?;
        transaction.commit()?;
    }

    // Tip height from any server.
    let bitcoin_tip = pool.call(|c| c.block_headers_subscribe().map(|h| h.height as u64))?;
    let confirmed_tip = bitcoin_tip.saturating_sub(confirmations);
    eprintln!("bitcoin tip = {bitcoin_tip}, confirmed tip = {confirmed_tip} (-{confirmations})");

    // ---- Work-based epoch tail (initial) ----------------------------------
    // Walk back epoch by epoch from the confirmed tip, fetching one header per
    // epoch to read its difficulty, so the scan is only as wide as the work
    // comparison actually needs (usually 1-3 epochs, not the full lookback).
    let (mut tail_start, tail_work, prev_work) = select_epoch_tail(
        &pool,
        &database,
        period_length,
        confirmed_tip,
        lookback_epochs,
    )?;
    let tail_len = confirmed_tip - tail_start + 1;
    eprintln!(
        "epoch tail (work): [{tail_start}..={confirmed_tip}] = {tail_len} blocks, \
         tail work {tail_work:.6e} vs previous epoch {prev_work:.6e}"
    );

    // Fetch full headers (hash + timestamp) for the initial tail.
    let mut records = load_range(&database, tail_start, confirmed_tip)?;
    fetch_headers(&pool, &mut records, tail_start, confirmed_tip)?;
    store_range(&database, &records)?;

    // ---- Iterative statistical sufficiency ---------------------------------
    // Measure t = participation x agreement over the current tail. If t > T we
    // are done; otherwise extend the tail back one full epoch and re-measure.
    eprintln!(
        "success threshold T = {threshold} (t = participation x agreement); \
         extending back one epoch while t <= T"
    );
    let mut iterations = 0u64;
    let winning = loop {
        iterations += 1;
        // Download coinbases for the current tail, concurrently, out of order.
        fetch_tags_parallel(
            pool.clone(),
            &database,
            &mut records,
            tail_start,
            confirmed_tip,
        )?;

        let agg = compute_agreement(&records, tail_start, confirmed_tip);
        let t = agg.participation * agg.agreement;
        println!(
            "tail t = {t:.3} (P {:.1}% x A {:.1}%)  {}  T = {threshold}",
            agg.participation * 100.0,
            agg.agreement * 100.0,
            if t > threshold {
                "SUCCESS"
            } else {
                "extending..."
            }
        );
        print_summary(
            &agg,
            confirmed_tip - tail_start + 1,
            t,
            iterations,
            threshold,
        );

        if t > threshold {
            break agg;
        }
        if iterations >= lookback_epochs {
            bail!("t = {t:.3} never exceeded T = {threshold} within {lookback_epochs} epochs");
        }
        if tail_start < period_length {
            bail!("reached genesis before achieving t > T");
        }
        let new_start = tail_start - period_length;
        eprintln!("t <= T; extending tail back one epoch -> [{new_start}..={confirmed_tip}]");
        fetch_headers(&pool, &mut records, new_start, tail_start - 1)?;
        store_range(&database, &records)?;
        tail_start = new_start;
    };

    if print_table_arg {
        let mut rows = build_rows(&records, tail_start, confirmed_tip, &winning.status)?;
        print_table(&mut rows);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tail selection (Bitcoin work-based)

// Fetch only the headers in [low..=hi] that are not yet cached, filling
// `records` with hash+timestamp. Missing heights are grouped into contiguous
// runs and fetched as one batch each, so re-runs (where only the tip advanced)
// fetch only the handful of new blocks.
fn fetch_headers(
    pool: &ClientPool,
    records: &mut HashMap<u64, Record>,
    low: u64,
    hi: u64,
) -> Result<()> {
    // Contiguous runs of heights we have no cached header for.
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut height = low;
    while height <= hi {
        if records.contains_key(&height) {
            height += 1;
            continue;
        }
        let run_start = height;
        let mut run_len = 0u64;
        while height <= hi && !records.contains_key(&height) {
            run_len += 1;
            height += 1;
        }
        runs.push((run_start, run_len));
    }

    let mut fetched = 0u64;
    for (run_start, run_len) in &runs {
        let mut start = *run_start;
        let mut remaining = *run_len;
        while remaining > 0 {
            let count = remaining.min(2016) as usize;
            let res = pool.call(|c| c.block_headers(start as usize, count))?;
            if res.headers.len() != count {
                bail!(
                    "electrum returned {} of {count} headers at {start}",
                    res.headers.len()
                );
            }
            for (offset, header) in res.headers.iter().enumerate() {
                let height = start + offset as u64;
                records.entry(height).or_insert_with(|| Record {
                    hash: header.block_hash().to_string(),
                    timestamp: header_time(header) as u64,
                    fetched: false,
                    tag: None,
                });
            }
            fetched += count as u64;
            start += count as u64;
            remaining -= count as u64;
        }
    }
    let cached = (hi - low + 1).saturating_sub(fetched);
    eprintln!("headers: {cached} from cache, {fetched} fetched");
    Ok(())
}

// The earliest epoch boundary such that everything from that boundary to the
// confirmed tip has more work than the single preceding epoch. Difficulty is
// read from the persistent per-epoch cache (one fetch per epoch, never
// repeated across runs), so the scan is no wider than the work comparison needs.
// Returns (tail_start, tail_work, previous_epoch_work).
fn select_epoch_tail(
    pool: &ClientPool,
    database: &Database,
    period_len: u64,
    confirmed_tip: u64,
    max_epochs: u64,
) -> Result<(u64, f64, f64)> {
    // Difficulty of an epoch, read from its first block (constant per epoch),
    // cached in EPOCH_DIFF_TABLE so re-runs fetch nothing.
    let epoch_difficulty = |epoch_start: u64| -> Result<f64> {
        {
            let transaction = database.begin_read()?;
            let table = transaction.open_table(EPOCH_DIFF_TABLE)?;
            if let Some(value) = table.get(epoch_start)? {
                let bytes = value.value();
                if bytes.len() == 8 {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(bytes);
                    return Ok(f64::from_be_bytes(buf));
                }
            }
        }
        let difficulty = pool.call(|c| {
            c.block_header(epoch_start as usize)
                .map(|h| h.difficulty_float())
        })?;
        let transaction = database.begin_write()?;
        {
            let mut table = transaction.open_table(EPOCH_DIFF_TABLE)?;
            table.insert(epoch_start, &difficulty.to_be_bytes()[..])?;
        }
        transaction.commit()?;
        Ok(difficulty)
    };
    let tip_epoch_start = (confirmed_tip / period_len) * period_len;
    let tip_epoch_diff = epoch_difficulty(tip_epoch_start)?;
    // Work of the partial current epoch.
    let mut tail_work = (confirmed_tip - tip_epoch_start + 1) as f64 * tip_epoch_diff;
    let mut tail_start = tip_epoch_start;
    let mut prev_work = 0.0f64;
    for _ in 0..max_epochs {
        if tail_start < period_len {
            break;
        }
        let prev_epoch_start = tail_start - period_len;
        // The previous epoch is a full, completed epoch.
        prev_work = epoch_difficulty(prev_epoch_start)? * period_len as f64;
        if tail_work > prev_work {
            break;
        }
        tail_work += prev_work; // absorb that epoch into the tail
        tail_start = prev_epoch_start;
    }
    Ok((tail_start, tail_work, prev_work))
}

// ---------------------------------------------------------------------------
// Per-tail analysis: participation + CPV agreement.

struct Agreement {
    tagged: u64,
    neutral: u64,
    participation: f64,
    consistent: u64,
    agreement: f64,
    status: HashMap<u64, String>,
    divergent_at: HashMap<u64, Vec<u64>>,
}

fn compute_agreement(records: &HashMap<u64, Record>, start: u64, end: u64) -> Agreement {
    let size = end - start + 1;

    // Collect every decoded tag in the tail.
    let mut tagged: Vec<(u64, Tag)> = Vec::new();
    for height in start..=end {
        if let Some(record) = records.get(&height)
            && let Some(raw) = record.tag
            && let Some(tag) = decode_tag(raw)
        {
            tagged.push((height, tag));
        }
    }
    let tagged_count = tagged.len() as u64;
    let neutral_count = size - tagged_count;
    let participation = tagged_count as f64 / size as f64;

    // Per checkpoint RSK height, count how many tags claim each LSB byte.
    let mut cpv_tally: HashMap<u64, HashMap<u8, u32>> = HashMap::new();
    for (_, tag) in &tagged {
        for (h, b) in &tag.cpv {
            *cpv_tally.entry(*h).or_default().entry(*b).or_insert(0) += 1;
        }
    }
    // The consensus byte at each checkpoint is the one claimed by the most tags.
    let consensus: HashMap<u64, u8> = cpv_tally
        .into_iter()
        .filter_map(|(h, tally)| {
            tally
                .into_iter()
                .max_by_key(|&(_, count)| count)
                .map(|(byte, _)| (h, byte))
        })
        .collect();

    // A tag is CONSISTENT iff it agrees with the consensus byte at every
    // checkpoint it references; otherwise it points at a different history.
    let mut status: HashMap<u64, String> = HashMap::new();
    let mut divergent_at: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut consistent_count = 0u64;
    for (btc_height, tag) in &tagged {
        let mut ok = true;
        for (h, b) in &tag.cpv {
            if let Some(&consensus_byte) = consensus.get(h)
                && consensus_byte != *b
            {
                ok = false;
                divergent_at.entry(*btc_height).or_default().push(*h);
            }
        }
        if ok {
            consistent_count += 1;
            status.insert(*btc_height, "CONSISTENT".to_string());
        } else {
            status.insert(*btc_height, "DIVERGENT".to_string());
        }
    }
    let agreement = if tagged_count > 0 {
        consistent_count as f64 / tagged_count as f64
    } else {
        0.0
    };

    Agreement {
        tagged: tagged_count,
        neutral: neutral_count,
        participation,
        consistent: consistent_count,
        agreement,
        status,
        divergent_at,
    }
}

fn build_rows(
    records: &HashMap<u64, Record>,
    start: u64,
    end: u64,
    status: &HashMap<u64, String>,
) -> Result<Vec<Row>> {
    (start..=end)
        .map(|height| {
            let record = records.get(&height).context("record missing after fetch")?;
            let tag = record.tag.and_then(decode_tag);
            let status = match (&tag, status.get(&height)) {
                (Some(_), Some(s)) => s.clone(),
                (None, _) => "-".to_string(),
                (Some(_), None) => "CONSISTENT".to_string(),
            };
            Ok(Row {
                height,
                timestamp: record.timestamp,
                tag,
                status,
            })
        })
        .collect()
}

// Fetch (and cache) coinbase tags for every not-yet-fetched height in
// [start..=end], in parallel across the electrum client pool.
fn fetch_tags_parallel(
    pool: Arc<ClientPool>,
    database: &Database,
    records: &mut HashMap<u64, Record>,
    start: u64,
    end: u64,
) -> Result<()> {
    let missing: Vec<u64> = (start..=end)
        .filter(|h| records.get(h).map(|r| !r.fetched).unwrap_or(false))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    eprintln!(
        "pass 2: fetching {} coinbases for [{start}..={end}] (concurrency {})",
        missing.len(),
        pool.clients.lock().unwrap_or_else(|p| p.into_inner()).len()
    );

    let next = Arc::new(AtomicU64::new(start));
    let total = end - start + 1;
    let done = Arc::new(AtomicU64::new(0));
    // Extracted tags for already-fetched heights; failures are tracked separately.
    let results: Arc<Mutex<HashMap<u64, Option<[u8; 32]>>>> = Arc::new(Mutex::new(HashMap::new()));
    let failed: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let start_time = std::time::Instant::now();

    let worker_count = missing
        .len()
        .min(pool.clients.lock().map(|g| g.len()).unwrap_or(1));
    // Heights whose coinbases are already cached, shared read-only by workers
    // so they skip anything we already have (re-runs fetch only the new tail).
    let already: Arc<HashSet<u64>> = Arc::new(
        records
            .iter()
            .filter(|(_, r)| r.fetched)
            .map(|(h, _)| *h)
            .collect(),
    );
    // Raw coinbases flow to a single writer that persists them in batches, so
    // even a cancelled run keeps everything flushed so far cached for the next
    // run (up to one final un-flushed batch is lost).
    let (write_tx, write_rx) = std::sync::mpsc::channel::<(u64, Vec<u8>)>();
    const COINBASE_BATCH: usize = 200;
    // Handles moved into the scoped threads; originals stay for use after the
    // scope joins.
    let failed_scope = failed.clone();
    let results_scope = results.clone();

    thread::scope(move |scope| {
        // Progress monitor so the run never looks silently stuck.
        let monitor_done = Arc::clone(&done);
        let monitor_failed = Arc::clone(&failed_scope);
        scope.spawn(move || {
            let mut last_done = u64::MAX;
            let mut stall = 0u64;
            loop {
                let d = monitor_done.load(Ordering::Relaxed);
                if d >= total {
                    break;
                }
                let failed_count = monitor_failed
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .len();
                // Note when no height has finished for a while so the run never
                // looks silently frozen on a failing connection.
                if d == last_done {
                    stall += 1;
                } else {
                    stall = 0;
                    last_done = d;
                }
                let stall_note = if stall >= 1 {
                    format!(
                        "  (no progress for {stall}s — waiting on {}/{} height(s), deadline-bound)",
                        total - d,
                        total
                    )
                } else {
                    String::new()
                };
                eprintln!(
                    "  progress: {d}/{total} heights scanned ({} failed), {}s elapsed{stall_note}",
                    failed_count,
                    start_time.elapsed().as_secs()
                );
                std::thread::sleep(Duration::from_secs(1));
            }
        });

        // Incremental coinbase writer.
        scope.spawn(move || {
            let mut buffer: Vec<(u64, Vec<u8>)> = Vec::with_capacity(COINBASE_BATCH);
            loop {
                let received = write_rx.recv();
                if let Ok(item) = &received {
                    buffer.push(item.clone());
                }
                if buffer.len() >= COINBASE_BATCH || received.is_err() {
                    if let Err(e) = write_coinbases(database, &buffer) {
                        eprintln!("  WARNING: failed to cache coinbase chunk: {e:#}");
                    }
                    buffer.clear();
                }
                if received.is_err() {
                    // All workers done and their senders dropped.
                    break;
                }
            }
        });

        for _ in 0..worker_count {
            let pool = pool.clone();
            let next = next.clone();
            let done = done.clone();
            let results = results_scope.clone();
            let failed = failed_scope.clone();
            let already = already.clone();
            let write_tx = write_tx.clone();
            scope.spawn(move || {
                loop {
                    let height = next.fetch_add(1, Ordering::Relaxed);
                    if height > end {
                        break;
                    }
                    if already.contains(&height) {
                        done.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let outcome = pool
                        .call(|c| {
                            let txid = c.txid_from_pos(height as usize, 0)?;
                            let raw = c.transaction_get_raw(&txid)?;
                            Ok::<Vec<u8>, electrum_client::Error>(raw)
                        })
                        .map(|raw| (extract_tag(&raw), raw));
                    done.fetch_add(1, Ordering::Relaxed);
                    match outcome {
                        Ok((tag, raw)) => {
                            let _ = write_tx.send((height, raw));
                            results
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .insert(height, tag);
                        }
                        Err(e) => {
                            failed
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .push(height);
                            eprintln!("  coinbase {height} failed on all servers: {e:#}");
                        }
                    }
                }
            });
        }
        // Release our own sender so the writer thread sees the channel close
        // once every worker has finished (otherwise the writer parks on recv()
        // forever and the scope never returns: a deadlock).
        drop(write_tx);
    });
    eprintln!(
        "pass 2 complete in {}s",
        start_time.elapsed().as_secs_f64().round() as u64
    );

    let failed_heights = {
        let failed = failed.lock().unwrap_or_else(|p| p.into_inner());
        failed.clone()
    };
    // Fail fast: the parallel pass already tried every server for a height. A
    // height that still failed is usually a tip-region block some servers
    // haven't indexed yet; leave it uncached (a later run retries it) and just
    // warn — it then counts as untagged, only slightly lowering participation.
    let mut changed = false;
    if !failed_heights.is_empty() {
        eprintln!(
            "WARNING: {} coinbase(s) could not be fetched and are EXCLUDED: {}",
            failed_heights.len(),
            failed_heights
                .iter()
                .take(10)
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let results = results.lock().unwrap_or_else(|p| p.into_inner());
    for (height, tag) in results.iter() {
        let record = records.entry(*height).or_insert_with(|| Record {
            hash: String::new(),
            timestamp: 0,
            fetched: false,
            tag: None,
        });
        record.fetched = true;
        record.tag = *tag;
        changed = true;
    }
    drop(results);
    if changed {
        store_range(database, records)?;
    }
    eprintln!("pass 2 done: coinbase txns cached for [{start}..={end}]");
    Ok(())
}

// bitcoin Header.time is a u32 (seconds since epoch).
fn header_time(header: &BitcoinHeader) -> u32 {
    header.time
}

// ---------------------------------------------------------------------------
// Electrum client pool with round-robin failover.

struct ClientPool {
    clients: Mutex<VecDeque<ElectrumClient>>,
}

impl ClientPool {
    // Run `f` against one client. On error, round-robin to the next client and
    // retry (each client once), with a short backoff between attempts and a
    // wall-clock deadline so a run of dead connections can never stall the
    // whole binary long. Each client is held by a single caller at a time (it
    // is removed from the pool for the duration of the call), so concurrent
    // callers never share a socket.
    fn call<T, F>(&self, f: F) -> Result<T>
    where
        F: Fn(&ElectrumClient) -> Result<T, electrum_client::Error>,
    {
        let pool_size = self.clients.lock().unwrap_or_else(|p| p.into_inner()).len();
        if pool_size == 0 {
            bail!("electrum client pool is empty");
        }
        let deadline = std::time::Instant::now() + CALL_DEADLINE;
        let mut errors: Vec<electrum_client::Error> = Vec::new();
        for attempt in 0..pool_size {
            if std::time::Instant::now() >= deadline {
                errors.push(electrum_client::Error::Message(
                    "electrum call deadline exceeded".to_string(),
                ));
                break;
            }
            let client = self
                .clients
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pop_front()
                .context("electrum pool empty")?;
            let outcome = f(&client);
            self.clients
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push_back(client);
            match outcome {
                Ok(value) => return Ok(value),
                Err(e) => errors.push(e),
            }
            if attempt + 1 < pool_size {
                // Short backoff so we don't hammer the servers while failing over.
                let backoff_ms = (1u64 << (attempt % 4).min(3)) * 200;
                std::thread::sleep(Duration::from_millis(backoff_ms));
            }
        }
        Err(anyhow!(
            "electrum call failed on all {pool_size} server(s): {errors:?}"
        ))
    }
}

// ---------------------------------------------------------------------------
// Per-block data

struct Row {
    height: u64,
    timestamp: u64,
    tag: Option<Tag>,
    // CPV-consistency verdict for this bitcoin block: CONSISTENT / DIVERGENT / "-".
    status: String,
}

struct Tag {
    prefix: [u8; 20],
    // (RSK checkpoint block height, claimed LSB byte) for j = 0..=6.
    cpv: Vec<(u64, u8)>,
    // Uncles referenced in the last 32 RSK blocks.
    recent_uncles: u8,
    // RSK block height being mined (bytes 28..32, big endian).
    block_number: u64,
}

fn decode_tag(raw: [u8; 32]) -> Option<Tag> {
    let mut prefix = [0u8; 20];
    prefix.copy_from_slice(&raw[0..20]);
    let block_number = u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]]) as u64;
    let base = ((block_number.saturating_sub(1)) / 64) * 64;
    let mut cpv = Vec::with_capacity(7);
    for j in 0..7u64 {
        // Checkpoint j is the LSB of the bitcoin id merge-mined with the RSK
        // block at height base - j*64 (v(0) newest). Clamp at genesis.
        let checkpoint_height = base.saturating_sub(j * 64);
        cpv.push((checkpoint_height, raw[20 + j as usize]));
    }
    Some(Tag {
        prefix,
        cpv,
        recent_uncles: raw[27],
        block_number,
    })
}

// The merge-mining spec requires the tag in the tail of the serialized
// coinbase, so take the LAST occurrence of the magic bytes.
fn extract_tag(raw: &[u8]) -> Option<[u8; 32]> {
    let mut position = None;
    let mut i = 0usize;
    while i + TAG_MAGIC.len() <= raw.len() {
        if &raw[i..i + TAG_MAGIC.len()] == TAG_MAGIC {
            position = Some(i);
        }
        i += 1;
    }
    let start = position? + TAG_MAGIC.len();
    if start + 32 > raw.len() {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw[start..start + 32]);
    Some(out)
}

// ---------------------------------------------------------------------------
// redb caching

#[derive(Clone)]
struct Record {
    hash: String,
    timestamp: u64,
    fetched: bool,
    tag: Option<[u8; 32]>,
}

fn load_range(database: &Database, start: u64, end: u64) -> Result<HashMap<u64, Record>> {
    let mut out = HashMap::new();
    let transaction = database.begin_read()?;
    let table = transaction.open_table(EPOCH_BLOCK_TABLE)?;
    let coinbases = transaction.open_table(COINBASE_TABLE)?;
    for entry in table.range(start..=end)? {
        let (key, value) = entry?;
        let height = key.value();
        let bytes = value.value();
        if bytes.len() < 41 {
            bail!("corrupt epoch record at {height}");
        }
        let hash = hex::encode(&bytes[0..32]);
        let timestamp = u64::from_be_bytes(bytes[32..40].try_into().context("ts")?);
        // A cached raw coinbase is authoritative: it means we've already fetched
        // this block, so interrupted runs still skip everything that was cached
        // before the crash. The stored flags/tag are only a legacy fallback for
        // rows written by older versions without a COINBASE_TABLE entry.
        let (fetched, tag) = match coinbases.get(height)? {
            Some(raw) => {
                let raw = raw.value();
                (true, extract_tag(raw))
            }
            None => {
                let flags = bytes[40];
                let fetched = flags & 1 != 0;
                let tag = if flags & 2 != 0 {
                    let mut tag = [0u8; 32];
                    tag.copy_from_slice(&bytes[41..73]);
                    Some(tag)
                } else {
                    None
                };
                (fetched, tag)
            }
        };
        if height >= start && height <= end {
            out.insert(
                height,
                Record {
                    hash,
                    timestamp,
                    fetched,
                    tag,
                },
            );
        }
    }
    Ok(out)
}

fn store_range(database: &Database, records: &HashMap<u64, Record>) -> Result<()> {
    let transaction = database.begin_write()?;
    {
        let mut table = transaction.open_table(EPOCH_BLOCK_TABLE)?;
        let mut entries: Vec<(u64, &Record)> = records.iter().map(|(h, r)| (*h, r)).collect();
        entries.sort_unstable_by_key(|(h, _)| *h);
        for (height, record) in entries {
            let hash = hex::decode(&record.hash).context("decoding stored hash")?;
            if hash.len() != 32 {
                // Legacy/unknown hash: store zeros rather than corrupting.
                let mut bytes = Vec::with_capacity(73);
                bytes.extend_from_slice(&[0u8; 32]);
                bytes.extend_from_slice(&record.timestamp.to_be_bytes());
                let mut flags = 0u8;
                if record.fetched {
                    flags |= 1;
                }
                if let Some(tag) = &record.tag {
                    flags |= 2;
                    bytes.push(flags);
                    bytes.extend_from_slice(tag);
                } else {
                    bytes.push(flags);
                    bytes.extend_from_slice(&[0u8; 32]);
                }
                table.insert(height, &bytes[..])?;
                continue;
            }
            let mut bytes = Vec::with_capacity(73);
            bytes.extend_from_slice(&hash);
            bytes.extend_from_slice(&record.timestamp.to_be_bytes());
            let mut flags = 0u8;
            if record.fetched {
                flags |= 1;
            }
            if let Some(tag) = &record.tag {
                flags |= 2;
                bytes.push(flags);
                bytes.extend_from_slice(tag);
            } else {
                bytes.push(flags);
                bytes.extend_from_slice(&[0u8; 32]);
            }
            table.insert(height, &bytes[..])?;
        }
    }
    transaction.commit()?;
    Ok(())
}

// Persist raw coinbase transactions to COINBASE_TABLE in one write transaction.
fn write_coinbases(database: &Database, batch: &[(u64, Vec<u8>)]) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let transaction = database.begin_write()?;
    {
        let mut table = transaction.open_table(COINBASE_TABLE)?;
        for (height, raw) in batch {
            table.insert(*height, raw.as_slice())?;
        }
    }
    transaction.commit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Table output

fn print_summary(agg: &Agreement, tail_size: u64, t: f64, iterations: u64, threshold: f64) {
    println!();
    println!("================ CPV agreement (RSKIP110) [iteration {iterations}] ================");
    println!("blocks in tail        : {tail_size}");
    println!("rsk tagged            : {}", agg.tagged);
    println!("untagged (neutral)    : {}", agg.neutral);
    println!("participation P       : {:.2}%", agg.participation * 100.0);
    println!(
        "cpv-consistent tags   : {} / {}",
        agg.consistent, agg.tagged
    );
    println!("agreement A           : {:.2}%", agg.agreement * 100.0);
    println!(
        "t = P x A             : {t:.3}   (T = {threshold}) {}",
        if t > threshold { "PASS" } else { "FAIL" }
    );
    if agg.divergent_at.is_empty() {
        println!("divergent tags        : none — all CPVs agree on a single chain");
    } else {
        println!("divergent tags        : {}", agg.divergent_at.len());
        let mut rows: Vec<(&u64, &Vec<u64>)> = agg.divergent_at.iter().collect();
        rows.sort_unstable_by_key(|(h, _)| **h);
        for (btc_height, heights) in rows {
            // Deepest disagreeing checkpoint = the smallest (oldest) height.
            let deepest = heights.iter().min().copied().unwrap_or(0);
            let hn: Vec<String> = heights.iter().map(|h| h.to_string()).collect();
            println!(
                "  btc {btc_height}: disagrees at rsk#{} (deepest {deepest})",
                hn.join(", ")
            );
        }
    }
    println!();
}

fn print_table(rows: &mut [Row]) {
    enum Cell {
        Single(String),
        Multi(Vec<String>),
    }

    rows.sort_unstable_by_key(|r| r.height);

    let mut table: Vec<Vec<Cell>> = Vec::with_capacity(rows.len());
    for row in rows {
        let timestamp = format!("{:<10}  {}", row.timestamp, utc(row.timestamp));
        let (bn, prefix, cpv, nu) = match &row.tag {
            None => (
                String::from("-"),
                String::from("-"),
                String::from("-"),
                String::from("-"),
            ),
            Some(tag) => {
                let bn = tag.block_number.to_string();
                let prefix = format!("0x{}", hex::encode(tag.prefix));
                let nu = format!("{}", tag.recent_uncles);
                let cpv: Vec<String> = tag
                    .cpv
                    .iter()
                    .enumerate()
                    .map(|(j, (height, byte))| format!("j{j}: rsk#{height}=0x{byte:02x}"))
                    .collect();
                (bn, prefix, cpv.join(", "), nu)
            }
        };
        table.push(vec![
            Cell::Single(row.height.to_string()),
            Cell::Single(bn),
            Cell::Single(prefix),
            Cell::Single(nu),
            Cell::Multi(cpv.split(", ").map(|s| s.to_string()).collect()),
            Cell::Single(row.status.clone()),
            Cell::Single(timestamp),
        ]);
    }

    let headers = [
        "btc block",
        "RSK BN",
        "RSK prefix (20B)",
        "NU",
        "RSK CPV (rsk#ht=claimed LSB)",
        "CPV agree",
        "btc timestamp",
    ];

    // Widths are the tallest cell or header per column.
    let mut col_widths = [0usize; 7];
    for (col, header) in headers.iter().enumerate() {
        col_widths[col] = header.len();
    }
    for row_cells in &table {
        for (col, cell) in row_cells.iter().enumerate() {
            let text = match cell {
                Cell::Single(s) => vec![s.clone()],
                Cell::Multi(lines) => lines.clone(),
            };
            for line in text {
                col_widths[col] = col_widths[col].max(line.len());
            }
        }
    }

    println!();
    {
        let mut line = String::new();
        for (i, (header, width)) in headers.iter().zip(col_widths.iter()).enumerate() {
            if i > 0 {
                line.push_str("  ");
            }
            line.push_str(&format!("{header:<width$}"));
        }
        println!("{line}");
        let mut sep = String::new();
        for (i, width) in col_widths.iter().enumerate() {
            if i > 0 {
                sep.push_str("  ");
            }
            sep.push_str(&"-".repeat(*width));
        }
        println!("{sep}");
    }

    for row_cells in &table {
        let line_count = row_cells
            .iter()
            .map(|cell| match cell {
                Cell::Single(_) => 1,
                Cell::Multi(lines) => lines.len(),
            })
            .max()
            .unwrap_or(1);
        for line_idx in 0..line_count {
            let mut out = String::new();
            for (col, cell) in row_cells.iter().enumerate() {
                let value = match cell {
                    Cell::Single(s) => {
                        if line_idx == 0 {
                            s.clone()
                        } else {
                            String::new()
                        }
                    }
                    Cell::Multi(lines) => lines.get(line_idx).cloned().unwrap_or_default(),
                };
                if col > 0 {
                    out.push_str("  ");
                }
                if col == 4 {
                    let fill = col_widths[col].saturating_sub(value.len());
                    out.push_str(&value);
                    out.push_str(&" ".repeat(fill));
                } else {
                    out.push_str(&format!("{value:<width$}", width = col_widths[col]));
                }
            }
            println!("{out}");
        }
    }
    println!();
}

fn utc(unix_seconds: u64) -> String {
    chrono::DateTime::from_timestamp(unix_seconds as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "?".to_string())
}
