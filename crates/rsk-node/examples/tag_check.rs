// rsk-tag-check
//
// Local "Armadillo" fork-detection check for the Ephemeral Sidechains sync:
//
//   1. Walk the last N (default 2016) Bitcoin blocks via an Esplora API,
//      fetch each coinbase transaction, and extract the RSKBLOCK: tag.
//   2. Decode each tag per RSKIP110:
//        [0..20]  PREFIX - 20-byte prefix of hashForMergedMining
//        [20..27] CPV    - LSBs of BTC block ids at 7 ancestor checkpoints
//        [27]     NU     - uncles referenced in the last 32 RSK blocks
//        [28..32] BN     - RSK block height being mined (big endian)
//   3. For each tag, check whether the referenced RSK block exists in the
//      canonical Rootstock chain at that height, or as an uncle included in
//      one of the following blocks (consensus window: height+1..=height+6,
//      from rskj uncleGenerationLimit = 7).
//   4. Report supporting vs hiding evidence and compute a subjective SAFE
//      block from it.
//
// All fetched data is persisted in a redb database so interrupted runs and
// re-runs cost almost nothing. Data near either chain tip (last 2 Bitcoin
// blocks, last 64 RSK blocks) is deliberately NOT persisted because it can
// still change in a reorg; it is re-fetched on the next run.
//
// Usage:
//   rsk-tag-check [--blocks N] [--uncle-depth D] [--pause-ms MS] [--db PATH]
//
// Environment:
//   ESPLORA_URL  (default https://blockstream.info/api ; mempool.space/api works too)
//   RSK_RPC_URL  (default https://public-node.rsk.co)

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use redb::{Database, TableDefinition};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const TAG_MAGIC: &[u8] = b"RSKBLOCK:";

// bitcoin coinbase: height -> [32-byte block hash][optional 32-byte tag]
const BITCOIN_COINBASE_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("btc_coinbase");
// rootstock block: height -> RskBlockRecord::to_bytes()
const RSK_BLOCK_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("rsk_block");
// rootstock uncles: height -> repeated [8-byte BE uncle height][32-byte mm hash]
const RSK_UNCLES_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("rsk_uncles");
// rootstock headers kept since the latest FINAL block, WITHOUT merge-mining
// proofs: height -> [32 hash][32 parent hash][32 state root][8-byte BE timestamp]
const RSK_HEADER_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("rsk_header");
// bitcoin coinbase + SPV proof, servable to syncing peers:
// height -> [u32 LE coinbase length][coinbase raw][merkleblock proof raw]
const BITCOIN_PROOF_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("btc_proof");

// Reorg safety margins: never persist data this close to the tip.
const BITCOIN_FINAL_DEPTH: u64 = 2;
const RSK_FINAL_DEPTH: u64 = 64;

// ---- subjective SAFE parameters -------------------------------------------
//
// REQUIRED_CONFIRMATIONS: a block is only SAFE once at least this many
// bitcoin blocks with supporting tags exist above it. One tagged bitcoin
// block is a single miner's attestation (which, in the worst case, could be
// the attacker's own); two independent attestations double the bitcoin-block
// cost of self-attestation and absorb the lumpiness of tag arrival. Roughly
// comparable to FACON's (RSKIP555) 100-RSK-block evidence epoch. A chosen
// parameter, not a derived constant: raise it for higher assurance at the
// cost of SAFE lagging further behind the tip.
const REQUIRED_CONFIRMATIONS: usize = 2;
//
// SAFETY_MARGIN: the work race for SAFE requires supporting work above the
// contested fork root to exceed SAFETY_MARGIN times the hiding work, whereas
// the FINAL-style acceptance rule over the whole window requires only a bare
// majority (S > H). The difference is sample size, not principle: FINAL is a
// one-shot judgment over a closed window of ~2000 tags where one tag of
// noise is irrelevant; the SAFE race near the tip may hinge on 2-3 tags,
// tags are counted rather than difficulty-weighted, CPV checkpoint matches
// are probabilistic (1/256 false-match per byte), and a tag near the tip may
// still resolve into an uncle. The margin absorbs that small-sample noise
// and becomes irrelevant as the sample grows. Also a chosen parameter.
const SAFETY_MARGIN: usize = 2;
//
// MAX_REORG_DEPTH: assumption 2 of the Ephemeral Sidechains proposal — no
// reorg deeper than ~14 days of RSK blocks. Fork evidence is never allowed
// to allege a root deeper than this, which is what defuses free fake tags
// with garbage CPV bytes.
const MAX_REORG_DEPTH: u64 = 40320;
//
// MAX_TIMESTAMP_SKEW_SECONDS: every RSK block's timestamp must lie within
// this bound of the timestamp of the bitcoin block referenced by its
// merge-mining header's prevHash. Combined with the freshness rule this
// binds each block's claimed time to its real mining time: prevHash
// unpredictability proves "mined after", timestamp consistency prevents
// claiming any other time (backdated or forward-dated forks, and timestamp
// games against difficulty). 6h is generous against honest bitcoin
// timestamp drift (~2h future rule, MTP skew, long inter-block gaps).
const MAX_TIMESTAMP_SKEW_SECONDS: u64 = 6 * 3600;

#[derive(Debug, Clone)]
struct Tag {
    tag_bytes: [u8; 32],
    hash_prefix: [u8; 20],
    cpv: [u8; 7],
    recent_uncles: u8,
    block_number: u64,
    bitcoin_height: u64,
    bitcoin_hash: String,
    // difficulty of the bitcoin block's period; 1.0 in fixed-window test mode
    difficulty: f64,
}

// TODO: actually verify the incoming rootsotck block merge mining hash against the json header.

#[derive(Debug)]
enum Verdict {
    SupportingCanonical,
    SupportingUncle { included_at: u64 },
    Hiding { matched_oldest_checkpoints: usize },
    AheadOfTip,
}

fn main() -> Result<()> {
    // 0 = objective mode (default): the scan window is derived from the
    // difficulty-period rule below. Non-zero = fixed window for testing.
    let mut fixed_blocks: u64 = 0;
    // Bitcoin's retarget interval. Consensus-fixed: every node MUST use 2016
    // or checkpoints stop being objective. Overridable ONLY as a test
    // harness (--test-period-len) to exercise the walk on tiny windows.
    let mut period_length: u64 = 2016;
    let mut uncle_scan_depth: u64 = 6;
    let mut pause_ms: u64 = 150;
    let mut database_path = "tag-check.redb".to_string();
    let mut keep_headers = true;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--blocks" => fixed_blocks = args.next().context("--blocks needs a value")?.parse()?,
            "--test-period-len" => {
                period_length = args
                    .next()
                    .context("--test-period-len needs a value")?
                    .parse()?
            }
            "--uncle-depth" => {
                uncle_scan_depth = args
                    .next()
                    .context("--uncle-depth needs a value")?
                    .parse()?
            }
            "--pause-ms" => pause_ms = args.next().context("--pause-ms needs a value")?.parse()?,
            "--db" | "--cache" => database_path = args.next().context("--db needs a value")?,
            "--no-headers" => keep_headers = false,
            other => bail!("unknown argument: {other}"),
        }
    }

    if period_length != 2016 {
        eprintln!("==========================================================");
        eprintln!("WARNING: test period length {period_length} != 2016.");
        eprintln!("Results are NOT objective and NOT comparable across nodes.");
        eprintln!("Never use this outside of testing.");
        eprintln!("==========================================================");
    }

    // Comma-separated list of API-compatible Esplora hosts. On rate limiting
    // the tool rotates to the next host immediately and only backs off when
    // every host in the pool is limited.
    let esplora_hosts: Vec<String> = std::env::var("ESPLORA_URL")
        .unwrap_or_else(|_| "https://blockstream.info/api,https://mempool.space/api".to_string())
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let rsk_rpc =
        std::env::var("RSK_RPC_URL").unwrap_or_else(|_| "https://public-node.rsk.co".to_string());

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("rsk-tag-check/0.2")
        .build()?;
    let esplora = Esplora {
        client: client.clone(),
        hosts: esplora_hosts,
        current: std::cell::Cell::new(0),
    };
    eprintln!("esplora hosts: {}", esplora.hosts.join(", "));

    let database = Database::create(&database_path)?;
    {
        // Ensure all tables exist so read transactions never fail.
        let transaction = database.begin_write()?;
        transaction.open_table(BITCOIN_COINBASE_TABLE)?;
        transaction.open_table(RSK_BLOCK_TABLE)?;
        transaction.open_table(RSK_UNCLES_TABLE)?;
        transaction.open_table(RSK_HEADER_TABLE)?;
        transaction.open_table(BITCOIN_PROOF_TABLE)?;
        transaction.commit()?;
    }

    let bitcoin_tip: u64 = esplora
        .get("/blocks/tip/height")?
        .trim()
        .parse()
        .context("parsing bitcoin tip height")?;
    let rsk_tip = hex_to_u64(
        rsk_call(&client, &rsk_rpc, "eth_blockNumber", json!([]))?
            .as_str()
            .context("eth_blockNumber returned no string")?,
    )?;
    eprintln!("bitcoin tip = {bitcoin_tip}, rootstock tip = {rsk_tip}");

    // ---- pass 1: determine the scan window and collect tags ----------------
    //
    // Objective mode (default), following the Ephemeral Sidechains rule:
    // walk backwards period by period (difficulty periods of `period_length`
    // bitcoin blocks). The tail is accepted once the difficulty-weighted
    // tagged work observed in it exceeds the ENTIRE difficulty of the next
    // older period (period_length * D). The lower the merge-mining
    // participation, the more coinbases must be explored. The first period
    // that the tail outweighs is the Checkpoint Period; it is scanned too
    // (its tags join the audit and its start anchors the freshness rule).
    let mut scan = ScanState::default();
    let mut difficulty_by_period: HashMap<u64, f64> = HashMap::new();
    let scan_start;
    if fixed_blocks > 0 {
        scan_start = bitcoin_tip.saturating_sub(fixed_blocks - 1);
        eprintln!("fixed window: scanning {scan_start}..={bitcoin_tip} ({fixed_blocks} blocks)");
        scan_bitcoin_range(
            &esplora,
            &database,
            &mut scan,
            scan_start,
            bitcoin_tip,
            bitcoin_tip,
            pause_ms,
            1.0,
        )?;
    } else {
        // Step 1 (headers only, no coinbase downloads): walk back period by
        // period accumulating the bitcoin tail's HEADER work until it exceeds
        // the entire work of the next older period. Difficulty is read per
        // period, so this costs two API calls per period and nothing else.
        const MAX_PERIODS_BACK: u64 = 20;
        let mut tail_start = (bitcoin_tip / period_length) * period_length;
        let mut target_work = {
            let difficulty =
                period_difficulty(&esplora, tail_start, &mut difficulty_by_period, pause_ms)?;
            (bitcoin_tip - tail_start + 1) as f64 * difficulty
        };
        let mut walked = 0u64;
        loop {
            if walked >= MAX_PERIODS_BACK || tail_start < period_length {
                bail!("no acceptable bitcoin tail within {MAX_PERIODS_BACK} periods");
            }
            let previous_start = tail_start - period_length;
            let d_previous = period_difficulty(
                &esplora,
                previous_start,
                &mut difficulty_by_period,
                pause_ms,
            )?;
            let full_previous_work = period_length as f64 * d_previous;
            if target_work > full_previous_work {
                break;
            }
            target_work += full_previous_work;
            tail_start = previous_start;
            walked += 1;
        }
        eprintln!(
            "bitcoin tail {tail_start}..={bitcoin_tip} ({} blocks), header work target {target_work:.4e}",
            bitcoin_tip - tail_start + 1
        );
        // Step 2: download coinbases backwards from the tip until the
        // difficulty-weighted TAGGED work matches the tail's header work.
        // Participation self-adjusts the depth: at p participation the tag
        // tail spans ~(tail blocks)/p bitcoin blocks.
        scan_start = scan_tags_until_target(
            &esplora,
            &database,
            &mut scan,
            bitcoin_tip,
            target_work,
            &mut difficulty_by_period,
            period_length,
            pause_ms,
        )?;
        eprintln!(
            "tag tail {scan_start}..={bitcoin_tip} ({} blocks) reached the target",
            bitcoin_tip - scan_start + 1
        );
    }
    let blocks_scanned = bitcoin_tip - scan_start + 1;
    let ScanState {
        tags,
        neutral_count,
        from_cache: bitcoin_from_cache,
        fetched: bitcoin_fetched,
        proofs_stored,
        window_bitcoin,
    } = scan;
    eprintln!(
        "pass 1 done: window {scan_start}..={bitcoin_tip} ({blocks_scanned} blocks), \
         {} tagged, {} untagged; {} from cache, {} fetched, {} proofs stored",
        tags.len(),
        neutral_count,
        bitcoin_from_cache,
        bitcoin_fetched,
        proofs_stored
    );

    // ---- pass 2: match tags against rootstock blocks + uncles --------------
    let mut rsk = RskCache::new(&database, rsk_tip);
    let mut verdicts: Vec<(Tag, Verdict)> = Vec::new();
    // The CPV byte convention (first byte of the double-sha256 digest) is
    // fixed; verified against mainnet. This flag enforces it fail-loud on the
    // first known-supporting tag, in case a future tag version (e.g. RSKIP224
    // CFV) changes the field's meaning.
    let mut cpv_sanity_checked = false;

    for (index, tag) in tags.iter().enumerate() {
        let verdict = if tag.block_number > rsk_tip {
            Verdict::AheadOfTip
        } else if rsk
            .get_block(&client, &rsk_rpc, tag.block_number)?
            .and_then(|block| block.merged_mining_hash)
            .map(|hash| hash == tag.tag_bytes || hash[0..20] == tag.hash_prefix)
            .unwrap_or(false)
        {
            Verdict::SupportingCanonical
        } else if let Some(included_at) =
            find_as_uncle(&client, &rsk_rpc, &mut rsk, tag, uncle_scan_depth, rsk_tip)?
        {
            Verdict::SupportingUncle { included_at }
        } else {
            let matched = cpv_suffix_matches(&client, &rsk_rpc, &mut rsk, tag)?;
            Verdict::Hiding {
                matched_oldest_checkpoints: matched,
            }
        };

        if matches!(verdict, Verdict::SupportingCanonical) && !cpv_sanity_checked {
            let expected = expected_cpv(&client, &rsk_rpc, &mut rsk, tag.block_number)?;
            let available = expected.iter().filter(|e| e.is_some()).count();
            let matched = expected
                .iter()
                .zip(tag.cpv.iter())
                .filter(|(e, t)| e.map(|e| e == **t).unwrap_or(false))
                .count();
            if available > 0 && matched < available {
                bail!(
                    "CPV sanity check FAILED on known-supporting tag at rsk height {} \
                     ({matched}/{available} available checkpoints matched). The CPV \
                     derivation or tag format assumption is wrong; all divergence-depth \
                     output would be invalid.",
                    tag.block_number
                );
            }
            if available > 0 {
                eprintln!(
                    "  CPV sanity check passed ({matched}/{available} on rsk height {})",
                    tag.block_number
                );
                cpv_sanity_checked = true;
            }
        }

        verdicts.push((tag.clone(), verdict));
        if index % 50 == 0 {
            eprintln!("  matched {} / {} tags", index + 1, tags.len());
        }
    }
    eprintln!(
        "pass 2 done: rsk data {} from cache, {} rpc calls",
        rsk.cache_hits, rsk.rpc_calls
    );

    // ---- report -------------------------------------------------------------
    let mut supporting_canonical = 0u64;
    let mut supporting_uncle = 0u64;
    let mut hiding_tags: Vec<&(Tag, Verdict)> = Vec::new();
    let mut ahead_of_tip = 0u64;
    for entry in &verdicts {
        match entry.1 {
            Verdict::SupportingCanonical => supporting_canonical += 1,
            Verdict::SupportingUncle { .. } => supporting_uncle += 1,
            Verdict::Hiding { .. } => hiding_tags.push(entry),
            Verdict::AheadOfTip => ahead_of_tip += 1,
        }
    }
    let tagged_count = tags.len() as u64;
    let supporting_count = supporting_canonical + supporting_uncle;
    let hiding_count = hiding_tags.len() as u64;
    // Difficulty-weighted observed work on each side.
    let supporting_work: f64 = verdicts
        .iter()
        .filter(|(_, verdict)| {
            matches!(
                verdict,
                Verdict::SupportingCanonical | Verdict::SupportingUncle { .. }
            )
        })
        .map(|(tag, _)| tag.difficulty)
        .sum();
    let hiding_work: f64 = hiding_tags.iter().map(|(tag, _)| tag.difficulty).sum();

    println!();
    println!("================ RSK tag audit ================");
    println!("bitcoin blocks scanned : {blocks_scanned} ({scan_start}..={bitcoin_tip})");
    println!("tagged coinbases (n)   : {tagged_count}");
    println!("untagged (neutral)     : {neutral_count}");
    println!(
        "S  supporting          : {supporting_count}   (canonical {supporting_canonical}, uncle {supporting_uncle})"
    );
    println!("H  hiding              : {hiding_count}");
    if ahead_of_tip > 0 {
        println!("ahead of RSK tip       : {ahead_of_tip} (re-run once RSK node catches up)");
    }
    if tagged_count > 0 {
        if hiding_count == 0 {
            println!(
                "no hiding evidence: hidden merge-mining share < {:.3}% (rule of three, 95% conf.)",
                300.0 / tagged_count as f64
            );
        } else {
            println!(
                "observed hiding share  : {:.3}% of tagged blocks",
                100.0 * hiding_count as f64 / tagged_count as f64
            );
        }
        println!("weighted work          : S {supporting_work:.4e} vs H {hiding_work:.4e}");
        println!(
            "acceptance rule S > H  : {}",
            if supporting_work > hiding_work {
                "PASS"
            } else {
                "FAIL"
            }
        );
    }

    let deepest_allowed_fork_root = rsk_tip.saturating_sub(MAX_REORG_DEPTH);
    for (tag, verdict) in &hiding_tags {
        let matched = match verdict {
            Verdict::Hiding {
                matched_oldest_checkpoints,
            } => *matched_oldest_checkpoints,
            _ => 0,
        };
        let (root_lower_bound, root_upper_bound) =
            fork_root_interval(tag, matched, deepest_allowed_fork_root);
        let explanation = if matched >= 7 {
            format!(
                "shares all CPV checkpoints -> root in ({}, {}] (benign sibling territory)",
                root_lower_bound - 1,
                root_upper_bound
            )
        } else if matched == 0 {
            format!(
                "shares no CPV checkpoints -> root at or below {root_upper_bound} (deep fork or fake tag)"
            )
        } else {
            format!(
                "shares oldest {matched}/7 CPV checkpoints -> root in ({}, {}]",
                root_lower_bound - 1,
                root_upper_bound
            )
        };
        println!(
            "  HIDING btc {} ({}) -> rsk bn {} prefix {} nu {} | {}",
            tag.bitcoin_height,
            &tag.bitcoin_hash[tag.bitcoin_hash.len().saturating_sub(16)..],
            tag.block_number,
            hex::encode(&tag.hash_prefix[..8]),
            tag.recent_uncles,
            explanation
        );
    }

    // ---- subjective SAFE ----------------------------------------------------
    // A block X is SAFE when:
    //   (a) at least REQUIRED_CONFIRMATIONS supporting tags exist above X, and
    //   (b) every fork hypothesis with a root at or below X is losing the
    //       work race on the bitcoin record.
    // All unexplained tags are conservatively merged into ONE fork hypothesis
    // rooted at the deepest lower bound any of them implies.
    println!();
    println!("---------------- subjective SAFE ----------------");
    let mut supporting_heights: Vec<u64> = verdicts
        .iter()
        .filter_map(|(tag, verdict)| {
            matches!(
                verdict,
                Verdict::SupportingCanonical | Verdict::SupportingUncle { .. }
            )
            .then_some(tag.block_number)
        })
        .collect();
    supporting_heights.sort_unstable();
    if supporting_heights.len() < REQUIRED_CONFIRMATIONS {
        println!("not enough supporting evidence to declare any block SAFE");
        return Ok(());
    }
    // Highest block that already has REQUIRED_CONFIRMATIONS supporting tags
    // strictly above it.
    let confirmation_ceiling =
        supporting_heights[supporting_heights.len() - REQUIRED_CONFIRMATIONS].saturating_sub(1);

    let safe_block = if hiding_tags.is_empty() {
        println!("no unresolved fork evidence in window");
        confirmation_ceiling
    } else {
        let mut deepest_fork_root = u64::MAX;
        for (tag, verdict) in &hiding_tags {
            let matched = match verdict {
                Verdict::Hiding {
                    matched_oldest_checkpoints,
                } => *matched_oldest_checkpoints,
                _ => 0,
            };
            deepest_fork_root = deepest_fork_root
                .min(fork_root_interval(tag, matched, deepest_allowed_fork_root).0);
        }
        let supporting_work_above_root: f64 = verdicts
            .iter()
            .filter(|(tag, verdict)| {
                matches!(
                    verdict,
                    Verdict::SupportingCanonical | Verdict::SupportingUncle { .. }
                ) && tag.block_number > deepest_fork_root
            })
            .map(|(tag, _)| tag.difficulty)
            .sum();
        println!(
            "unresolved evidence: {} tag(s), deepest possible fork root {deepest_fork_root} (tip - {})",
            hiding_tags.len(),
            rsk_tip.saturating_sub(deepest_fork_root)
        );
        println!(
            "work race above root: S {supporting_work_above_root:.4e} vs H {hiding_work:.4e} (need S > {SAFETY_MARGIN}*H)"
        );
        if supporting_work_above_root > SAFETY_MARGIN as f64 * hiding_work {
            println!("hypothetical fork is losing on the bitcoin record; no retreat");
            confirmation_ceiling
        } else {
            println!("insufficient observed work above the contested root; retreating");
            confirmation_ceiling.min(deepest_fork_root.saturating_sub(1))
        }
    };
    println!(
        "subjective SAFE block  : {safe_block} (tip - {})",
        rsk_tip.saturating_sub(safe_block)
    );

    // ---- FINAL checkpoint, header retention, pruning ------------------------
    // Operational version of the Ephemeral Sidechains rule: the checkpoint
    // block is the earliest RSK block whose merge-mined bitcoin header has a
    // prevHash inside the scanned bitcoin window (proving it was mined after
    // the window started). If the window's acceptance rule (S > H) passed,
    // that checkpoint is FINAL: keep all RSK headers (without merge-mining
    // proofs) from it to the tip, and delete everything older.
    if keep_headers {
        println!();
        println!("---------------- FINAL + headers ----------------");
        if supporting_count <= hiding_count {
            println!("acceptance rule failed; FINAL not advanced, nothing pruned");
        } else {
            let final_block = find_checkpoint_block(
                &client,
                &rsk_rpc,
                &mut rsk,
                &window_bitcoin,
                deepest_allowed_fork_root.max(1),
                rsk_tip,
            )?;
            match final_block {
                None => println!("no checkpoint block found in range; nothing pruned"),
                Some(final_block) => {
                    println!(
                        "FINAL block            : {final_block} (tip - {})",
                        rsk_tip.saturating_sub(final_block)
                    );
                    let report = sync_headers(
                        &client,
                        &rsk_rpc,
                        &database,
                        final_block,
                        rsk_tip,
                        pause_ms,
                        &window_bitcoin,
                    )?;
                    let (stored, fetched, link_breaks) =
                        (report.stored, report.fetched, report.link_breaks);
                    println!(
                        "headers since FINAL    : {stored} stored ({fetched} fetched this run)"
                    );
                    if link_breaks > 0 {
                        println!(
                            "WARNING: {link_breaks} parent-hash link break(s) in stored headers \
                             (possible reorg; delete affected heights and re-run)"
                        );
                    } else {
                        println!("header chain verified  : parent links OK");
                    }
                    if report.timestamp_violations > 0 || report.order_violations > 0 {
                        println!(
                            "WARNING: timestamp check: {} skew violation(s) (> {}h), {} bitcoin-parent order violation(s)",
                            report.timestamp_violations,
                            MAX_TIMESTAMP_SKEW_SECONDS / 3600,
                            report.order_violations
                        );
                    } else if report.fetched > 0 {
                        println!(
                            "timestamp check        : {} fetched headers within {}h of their bitcoin parents ({} unresolved refs)",
                            report.fetched,
                            MAX_TIMESTAMP_SKEW_SECONDS / 3600,
                            report.unresolved_parents
                        );
                    }
                    let pruned_headers = prune_below(&database, RSK_HEADER_TABLE, final_block)?;
                    let pruned_blocks = prune_below(&database, RSK_BLOCK_TABLE, final_block)?;
                    let pruned_uncles = prune_below(&database, RSK_UNCLES_TABLE, final_block)?;
                    // The window slid forward with FINAL: coinbases and SPV
                    // proofs below the current window are no longer needed to
                    // reproduce the checkpoint decision, so drop them too.
                    let pruned_coinbases =
                        prune_below(&database, BITCOIN_COINBASE_TABLE, scan_start)?;
                    let pruned_proofs = prune_below(&database, BITCOIN_PROOF_TABLE, scan_start)?;
                    println!(
                        "pruned below FINAL     : {pruned_headers} headers, {pruned_blocks} block records, {pruned_uncles} uncle lists"
                    );
                    println!(
                        "pruned bitcoin < window: {pruned_coinbases} coinbases, {pruned_proofs} proofs"
                    );
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bitcoin scanning

#[derive(Default)]
struct ScanState {
    tags: Vec<Tag>,
    neutral_count: u64,
    from_cache: u64,
    fetched: u64,
    proofs_stored: u64,
    // Window bitcoin blocks keyed by hash in internal little-endian order
    // (prevHash field order) -> (height, timestamp; 0 = unknown from a
    // legacy cache record). Used by the freshness rule and the RSK-vs-
    // bitcoin timestamp consistency check.
    window_bitcoin: HashMap<[u8; 32], (u64, u32)>,
}

// Scan one contiguous bitcoin height range, filling ScanState. Returns the
// difficulty-weighted tagged work added by this range.
fn scan_bitcoin_range(
    esplora: &Esplora,
    database: &Database,
    scan: &mut ScanState,
    start: u64,
    end: u64,
    bitcoin_tip: u64,
    pause_ms: u64,
    difficulty: f64,
) -> Result<f64> {
    // Prefetch hashes + timestamps for heights missing from the database,
    // 10 per request.
    let mut hints_by_height: HashMap<u64, (String, u32)> = HashMap::new();
    let mut cursor = end;
    loop {
        let batch_needed = (0..10u64).any(|offset| {
            let height = cursor.saturating_sub(offset);
            height >= start
                && height <= end
                && !matches!(
                    database_read(database, BITCOIN_COINBASE_TABLE, height),
                    Ok(Some(_))
                )
        });
        if batch_needed {
            let body = esplora.get(&format!("/blocks/{cursor}"))?;
            let parsed: Value = serde_json::from_str(&body).context("parsing /blocks batch")?;
            for block in parsed.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                if let (Some(height), Some(id)) = (
                    block.get("height").and_then(|x| x.as_u64()),
                    block.get("id").and_then(|x| x.as_str()),
                ) {
                    let timestamp =
                        block.get("timestamp").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                    if height >= start {
                        hints_by_height.insert(height, (id.to_string(), timestamp));
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(pause_ms));
        }
        if cursor.saturating_sub(9) <= start {
            break;
        }
        cursor -= 10;
    }

    let mut added_tag_work = 0.0f64;
    for height in start..=end {
        let (hash_hex, timestamp, tag_bytes) = ensure_bitcoin_block(
            esplora,
            database,
            scan,
            height,
            hints_by_height.get(&height),
            bitcoin_tip,
            pause_ms,
        )?;
        {
            let hash_bytes = hex::decode(&hash_hex).context("decoding block hash hex")?;
            let mut little_endian = [0u8; 32];
            for (i, byte) in hash_bytes.iter().rev().enumerate() {
                little_endian[i] = *byte;
            }
            scan.window_bitcoin
                .insert(little_endian, (height, timestamp.unwrap_or(0)));
        }
        match tag_bytes {
            Some(raw) => {
                let mut hash_prefix = [0u8; 20];
                hash_prefix.copy_from_slice(&raw[0..20]);
                let mut cpv = [0u8; 7];
                cpv.copy_from_slice(&raw[20..27]);
                let block_number = u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]]) as u64;
                scan.tags.push(Tag {
                    tag_bytes: raw,
                    hash_prefix,
                    cpv,
                    recent_uncles: raw[27],
                    block_number,
                    bitcoin_height: height,
                    bitcoin_hash: hash_hex,
                    difficulty,
                });
                added_tag_work += difficulty;
            }
            None => scan.neutral_count += 1,
        }
        if (height - start) % 100 == 0 {
            eprintln!(
                "  scanned {} / {} btc blocks in range, {} tags total",
                height - start + 1,
                end - start + 1,
                scan.tags.len()
            );
        }
    }
    Ok(added_tag_work)
}

// Make sure the coinbase record AND the servable SPV proof for this height
// exist in the database (when reorg-final), fetching whatever is missing.
// Returns (block hash hex, block timestamp if known, tag bytes if any).
#[allow(clippy::too_many_arguments)]
fn ensure_bitcoin_block(
    esplora: &Esplora,
    database: &Database,
    scan: &mut ScanState,
    height: u64,
    hint: Option<&(String, u32)>,
    bitcoin_tip: u64,
    pause_ms: u64,
) -> Result<(String, Option<u32>, Option<[u8; 32]>)> {
    let persistable = height + BITCOIN_FINAL_DEPTH <= bitcoin_tip;
    let cached = database_read(database, BITCOIN_COINBASE_TABLE, height)?;
    let have_proof = database_read(database, BITCOIN_PROOF_TABLE, height)?.is_some();

    if let Some(stored) = &cached {
        let (hash_bytes, timestamp, tag) = decode_bitcoin_record(stored)
            .with_context(|| format!("corrupt bitcoin record at {height}"))?;
        if have_proof || !persistable {
            scan.from_cache += 1;
            return Ok((hex::encode(hash_bytes), timestamp, tag));
        }
    }

    // Something is missing: fetch coinbase (and proof) from the network.
    let (hash_hex, mut timestamp): (String, Option<u32>) = if let Some(stored) = &cached {
        let (hash_bytes, timestamp, _) = decode_bitcoin_record(stored)?;
        (hex::encode(hash_bytes), timestamp)
    } else if let Some((hash, timestamp)) = hint {
        (hash.clone(), (*timestamp != 0).then_some(*timestamp))
    } else {
        let hash = esplora
            .get(&format!("/block-height/{height}"))?
            .trim()
            .to_string();
        (hash, None)
    };
    if timestamp.is_none() {
        let body = esplora.get(&format!("/block/{hash_hex}"))?;
        let parsed: Value = serde_json::from_str(&body).context("parsing block json")?;
        timestamp = parsed
            .get("timestamp")
            .and_then(|v| v.as_u64())
            .map(|t| t as u32);
    }
    let coinbase_txid = esplora
        .get(&format!("/block/{hash_hex}/txid/0"))?
        .trim()
        .to_string();
    let coinbase_hex = esplora
        .get(&format!("/tx/{coinbase_txid}/hex"))?
        .trim()
        .to_string();
    let coinbase_raw = hex::decode(&coinbase_hex).context("decoding coinbase hex")?;
    let tag = extract_tag(&coinbase_raw);

    if persistable {
        if cached.is_none() {
            let hash_bytes = hex::decode(&hash_hex).context("decoding block hash hex")?;
            if hash_bytes.len() != 32 {
                bail!("unexpected block hash length for height {height}");
            }
            let mut record = hash_bytes;
            record.extend_from_slice(&timestamp.unwrap_or(0).to_be_bytes());
            if let Some(tag) = &tag {
                record.extend_from_slice(tag);
            }
            database_write(database, BITCOIN_COINBASE_TABLE, height, &record)?;
        }
        if !have_proof {
            let proof_hex = esplora
                .get(&format!("/tx/{coinbase_txid}/merkleblock-proof"))?
                .trim()
                .to_string();
            let proof_raw = hex::decode(&proof_hex).context("decoding merkleblock proof")?;
            let mut record = Vec::with_capacity(4 + coinbase_raw.len() + proof_raw.len());
            record.extend_from_slice(&(coinbase_raw.len() as u32).to_le_bytes());
            record.extend_from_slice(&coinbase_raw);
            record.extend_from_slice(&proof_raw);
            database_write(database, BITCOIN_PROOF_TABLE, height, &record)?;
            scan.proofs_stored += 1;
        }
    }
    scan.fetched += 1;
    std::thread::sleep(Duration::from_millis(pause_ms));
    Ok((hash_hex, timestamp, tag))
}

// Step 2 of the objective window: walk backwards from the tip downloading
// coinbases until the difficulty-weighted tagged work reaches the header
// work target of the bitcoin tail. Returns the first (lowest) height of the
// tag tail.
fn scan_tags_until_target(
    esplora: &Esplora,
    database: &Database,
    scan: &mut ScanState,
    bitcoin_tip: u64,
    target_work: f64,
    difficulty_by_period: &mut HashMap<u64, f64>,
    period_length: u64,
    pause_ms: u64,
) -> Result<u64> {
    // If participation collapsed, refuse to walk back forever.
    let hard_floor = bitcoin_tip.saturating_sub(8 * period_length);
    let mut tagged_work = 0.0f64;
    let mut hints_by_height: HashMap<u64, (String, u32)> = HashMap::new();
    let mut height = bitcoin_tip;
    loop {
        // Batch-prefetch summaries (hash + timestamp) for this height and the
        // 9 below it, but only when something in that span is missing.
        if !hints_by_height.contains_key(&height)
            && database_read(database, BITCOIN_COINBASE_TABLE, height)?.is_none()
        {
            let body = esplora.get(&format!("/blocks/{height}"))?;
            let parsed: Value = serde_json::from_str(&body).context("parsing /blocks batch")?;
            for block in parsed.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                if let (Some(entry_height), Some(id)) = (
                    block.get("height").and_then(|x| x.as_u64()),
                    block.get("id").and_then(|x| x.as_str()),
                ) {
                    let timestamp =
                        block.get("timestamp").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                    hints_by_height.insert(entry_height, (id.to_string(), timestamp));
                }
            }
            std::thread::sleep(Duration::from_millis(pause_ms));
        }
        let period_start = (height / period_length) * period_length;
        let difficulty = period_difficulty(esplora, period_start, difficulty_by_period, pause_ms)?;
        let (hash_hex, timestamp, tag_bytes) = ensure_bitcoin_block(
            esplora,
            database,
            scan,
            height,
            hints_by_height.get(&height),
            bitcoin_tip,
            pause_ms,
        )?;
        {
            let hash_bytes = hex::decode(&hash_hex).context("decoding block hash hex")?;
            let mut little_endian = [0u8; 32];
            for (i, byte) in hash_bytes.iter().rev().enumerate() {
                little_endian[i] = *byte;
            }
            scan.window_bitcoin
                .insert(little_endian, (height, timestamp.unwrap_or(0)));
        }
        match tag_bytes {
            Some(raw) => {
                let mut hash_prefix = [0u8; 20];
                hash_prefix.copy_from_slice(&raw[0..20]);
                let mut cpv = [0u8; 7];
                cpv.copy_from_slice(&raw[20..27]);
                let block_number = u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]]) as u64;
                scan.tags.push(Tag {
                    tag_bytes: raw,
                    hash_prefix,
                    cpv,
                    recent_uncles: raw[27],
                    block_number,
                    bitcoin_height: height,
                    bitcoin_hash: hash_hex,
                    difficulty,
                });
                tagged_work += difficulty;
            }
            None => scan.neutral_count += 1,
        }
        if (bitcoin_tip - height) % 100 == 0 {
            eprintln!(
                "  scanned {} btc blocks back, tagged work {tagged_work:.4e} / {target_work:.4e}",
                bitcoin_tip - height + 1
            );
        }
        if tagged_work >= target_work {
            return Ok(height);
        }
        if height <= hard_floor {
            bail!(
                "tagged work {tagged_work:.4e} did not reach target {target_work:.4e} \
                 within 8 periods; participation too low"
            );
        }
        height -= 1;
    }
}

// Difficulty of the period starting at the given height, read from that
// period's first block and cached per run.
fn period_difficulty(
    esplora: &Esplora,
    period_start: u64,
    cache: &mut HashMap<u64, f64>,
    pause_ms: u64,
) -> Result<f64> {
    if let Some(difficulty) = cache.get(&period_start) {
        return Ok(*difficulty);
    }
    let hash = esplora
        .get(&format!("/block-height/{period_start}"))?
        .trim()
        .to_string();
    let body = esplora.get(&format!("/block/{hash}"))?;
    let parsed: Value = serde_json::from_str(&body).context("parsing block json")?;
    let difficulty = parsed
        .get("difficulty")
        .and_then(|v| v.as_f64())
        .context("block json missing difficulty")?;
    cache.insert(period_start, difficulty);
    std::thread::sleep(Duration::from_millis(pause_ms));
    Ok(difficulty)
}

// ---------------------------------------------------------------------------
// Tag extraction: the merge-mining spec requires the tag in the tail of the
// serialized coinbase, so take the LAST occurrence of the magic bytes.
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
// redb plumbing

fn database_read(
    database: &Database,
    table: TableDefinition<'static, u64, &'static [u8]>,
    key: u64,
) -> Result<Option<Vec<u8>>> {
    let transaction = database.begin_read()?;
    let table = transaction.open_table(table)?;
    Ok(table.get(key)?.map(|guard| guard.value().to_vec()))
}

fn database_write(
    database: &Database,
    table: TableDefinition<'static, u64, &'static [u8]>,
    key: u64,
    value: &[u8],
) -> Result<()> {
    let transaction = database.begin_write()?;
    {
        let mut table = transaction.open_table(table)?;
        table.insert(key, value)?;
    }
    transaction.commit()?;
    Ok(())
}

// bitcoin record: [32-byte hash][4-byte BE timestamp][optional 32-byte tag].
// Legacy records (32 or 64 bytes, no timestamp) are still readable; their
// timestamp reads as unknown and the consistency check skips them.
fn decode_bitcoin_record(bytes: &[u8]) -> Result<(Vec<u8>, Option<u32>, Option<[u8; 32]>)> {
    let tag_at = |offset: usize| {
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&bytes[offset..offset + 32]);
        tag
    };
    match bytes.len() {
        32 => Ok((bytes.to_vec(), None, None)),
        64 => Ok((bytes[0..32].to_vec(), None, Some(tag_at(32)))),
        36 | 68 => {
            let timestamp = u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
            let timestamp = (timestamp != 0).then_some(timestamp);
            let tag = (bytes.len() == 68).then(|| tag_at(36));
            Ok((bytes[0..32].to_vec(), timestamp, tag))
        }
        length => bail!("bitcoin record has invalid length {length}"),
    }
}

// ---------------------------------------------------------------------------
// Rootstock data: compact per-block record + uncle list, cached in memory and
// persisted in redb (except near the tip, where reorgs can still change it).

#[derive(Debug, Clone)]
struct RskBlockRecord {
    merged_mining_hash: Option<[u8; 32]>, // hashForMergedMining (== the 32-byte tag)
    bitcoin_header: Option<Vec<u8>>,      // bitcoinMergedMiningHeader (80 bytes)
    uncle_count: u8,                      // number of uncles referenced by this block
}

impl RskBlockRecord {
    fn from_json(value: &Value) -> Self {
        let bitcoin_header = value
            .get("bitcoinMergedMiningHeader")
            .and_then(|x| x.as_str())
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok());
        let uncle_count = value
            .get("uncles")
            .and_then(|u| u.as_array())
            .map(|a| a.len().min(255))
            .unwrap_or(0) as u8;
        RskBlockRecord {
            merged_mining_hash: extract_merged_mining_hash(value),
            bitcoin_header,
            uncle_count,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 2 + 80 + 1);
        let mut flags = 0u8;
        if self.merged_mining_hash.is_some() {
            flags |= 1;
        }
        if self.bitcoin_header.is_some() {
            flags |= 2;
        }
        out.push(flags);
        if let Some(hash) = &self.merged_mining_hash {
            out.extend_from_slice(hash);
        }
        if let Some(header) = &self.bitcoin_header {
            out.extend_from_slice(&(header.len() as u16).to_le_bytes());
            out.extend_from_slice(header);
        }
        out.push(self.uncle_count);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let corrupt = || anyhow!("corrupt rsk block record");
        let flags = *bytes.first().ok_or_else(corrupt)?;
        let mut position = 1usize;
        let merged_mining_hash = if flags & 1 != 0 {
            let slice = bytes.get(position..position + 32).ok_or_else(corrupt)?;
            position += 32;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(slice);
            Some(hash)
        } else {
            None
        };
        let bitcoin_header = if flags & 2 != 0 {
            let length_bytes = bytes.get(position..position + 2).ok_or_else(corrupt)?;
            let length = u16::from_le_bytes([length_bytes[0], length_bytes[1]]) as usize;
            position += 2;
            let slice = bytes.get(position..position + length).ok_or_else(corrupt)?;
            position += length;
            Some(slice.to_vec())
        } else {
            None
        };
        let uncle_count = *bytes.get(position).ok_or_else(corrupt)?;
        Ok(RskBlockRecord {
            merged_mining_hash,
            bitcoin_header,
            uncle_count,
        })
    }
}

struct RskCache<'a> {
    database: &'a Database,
    rsk_tip: u64,
    block_records: HashMap<u64, Option<RskBlockRecord>>,
    uncle_lists: HashMap<u64, Vec<(u64, [u8; 32])>>,
    cache_hits: u64,
    rpc_calls: u64,
}

impl<'a> RskCache<'a> {
    fn new(database: &'a Database, rsk_tip: u64) -> Self {
        RskCache {
            database,
            rsk_tip,
            block_records: HashMap::new(),
            uncle_lists: HashMap::new(),
            cache_hits: 0,
            rpc_calls: 0,
        }
    }

    fn persistable(&self, height: u64) -> bool {
        height + RSK_FINAL_DEPTH <= self.rsk_tip
    }

    fn get_block(
        &mut self,
        client: &reqwest::blocking::Client,
        rpc: &str,
        height: u64,
    ) -> Result<Option<&RskBlockRecord>> {
        if !self.block_records.contains_key(&height) {
            let record = if let Some(bytes) = database_read(self.database, RSK_BLOCK_TABLE, height)?
            {
                self.cache_hits += 1;
                Some(RskBlockRecord::from_bytes(&bytes)?)
            } else {
                let response = rsk_call(
                    client,
                    rpc,
                    "eth_getBlockByNumber",
                    json!([to_hex(height), false]),
                )?;
                self.rpc_calls += 1;
                if response.is_null() {
                    None
                } else {
                    let record = RskBlockRecord::from_json(&response);
                    if self.persistable(height) {
                        database_write(self.database, RSK_BLOCK_TABLE, height, &record.to_bytes())?;
                    }
                    Some(record)
                }
            };
            self.block_records.insert(height, record);
        }
        Ok(self.block_records.get(&height).unwrap().as_ref())
    }

    // Uncles referenced by the block at the given height, as
    // (uncle height, merged-mining hash) pairs. Uncles whose height or hash
    // cannot be determined are omitted (they could never match a tag anyway).
    fn get_uncles_included_at(
        &mut self,
        client: &reqwest::blocking::Client,
        rpc: &str,
        height: u64,
    ) -> Result<&[(u64, [u8; 32])]> {
        if !self.uncle_lists.contains_key(&height) {
            let list = if let Some(bytes) = database_read(self.database, RSK_UNCLES_TABLE, height)?
            {
                self.cache_hits += 1;
                decode_uncles(&bytes)?
            } else {
                let count = self
                    .get_block(client, rpc, height)?
                    .map(|block| block.uncle_count as usize)
                    .unwrap_or(0);
                let mut list = Vec::with_capacity(count);
                for index in 0..count {
                    let uncle = rsk_call(
                        client,
                        rpc,
                        "eth_getUncleByBlockNumberAndIndex",
                        json!([to_hex(height), to_hex(index as u64)]),
                    )?;
                    self.rpc_calls += 1;
                    if uncle.is_null() {
                        continue;
                    }
                    let uncle_height = uncle
                        .get("number")
                        .and_then(|v| v.as_str())
                        .and_then(|s| hex_to_u64(s).ok());
                    if let (Some(uncle_height), Some(hash)) =
                        (uncle_height, extract_merged_mining_hash(&uncle))
                    {
                        list.push((uncle_height, hash));
                    }
                }
                if self.persistable(height) {
                    database_write(
                        self.database,
                        RSK_UNCLES_TABLE,
                        height,
                        &encode_uncles(&list),
                    )?;
                }
                list
            };
            self.uncle_lists.insert(height, list);
        }
        Ok(self.uncle_lists.get(&height).unwrap())
    }
}

fn encode_uncles(list: &[(u64, [u8; 32])]) -> Vec<u8> {
    let mut out = Vec::with_capacity(list.len() * 40);
    for (uncle_height, hash) in list {
        out.extend_from_slice(&uncle_height.to_be_bytes());
        out.extend_from_slice(hash);
    }
    out
}

fn decode_uncles(bytes: &[u8]) -> Result<Vec<(u64, [u8; 32])>> {
    if bytes.len() % 40 != 0 {
        bail!("corrupt uncle record");
    }
    let mut out = Vec::with_capacity(bytes.len() / 40);
    for chunk in bytes.chunks_exact(40) {
        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(&chunk[0..8]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&chunk[8..40]);
        out.push((u64::from_be_bytes(height_bytes), hash));
    }
    Ok(out)
}

// The tag committed on Bitcoin IS the RSK block's hashForMergedMining
// (RSKIP110 replaced its format with PREFIX|CPV|NU|BN). RSKj exposes it
// directly on block objects; if the field is absent (e.g. some uncle
// responses), fall back to parsing the block's own embedded coinbase.
fn extract_merged_mining_hash(block: &Value) -> Option<[u8; 32]> {
    if let Some(text) = block.get("hashForMergedMining").and_then(|v| v.as_str()) {
        if let Ok(bytes) = hex::decode(text.trim_start_matches("0x")) {
            if bytes.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                return Some(out);
            }
        }
    }
    if let Some(text) = block
        .get("bitcoinMergedMiningCoinbaseTransaction")
        .and_then(|v| v.as_str())
    {
        if let Ok(bytes) = hex::decode(text.trim_start_matches("0x")) {
            return extract_tag(&bytes);
        }
    }
    None
}

// A tag that doesn't match the canonical block at its height may still be an
// uncle: scan the uncles included in the next `depth` blocks for one at the
// tag's height with the same merged-mining hash prefix. rskj's
// uncleGenerationLimit = 7 means a valid uncle at height N can only be
// referenced by blocks at N+1..=N+6, so the default depth of 6 covers the
// full consensus window.
fn find_as_uncle(
    client: &reqwest::blocking::Client,
    rpc: &str,
    rsk: &mut RskCache,
    tag: &Tag,
    depth: u64,
    rsk_tip: u64,
) -> Result<Option<u64>> {
    for offset in 1..=depth {
        let height = tag.block_number + offset;
        if height > rsk_tip {
            break;
        }
        let matched =
            rsk.get_uncles_included_at(client, rpc, height)?
                .iter()
                .any(|(uncle_height, hash)| {
                    *uncle_height == tag.block_number && hash[0..20] == tag.hash_prefix
                });
        if matched {
            return Ok(Some(height));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// CPV: v(j) = LSB of the Bitcoin block id merge-mined with the RSK block at
// height base - j*64, where base = ((BN-1)/64)*64 and v(0) is the newest
// checkpoint. "LSB" is the first byte of the raw
// double_sha256(bitcoinMergedMiningHeader) digest (the little-endian internal
// form, i.e. the last byte of the displayed block hash). Verified against
// mainnet tags; guarded by the fail-loud sanity check in the matching loop.
fn expected_cpv(
    client: &reqwest::blocking::Client,
    rpc: &str,
    rsk: &mut RskCache,
    block_number: u64,
) -> Result<Vec<Option<u8>>> {
    let base = ((block_number.saturating_sub(1)) / 64) * 64;
    let mut out = Vec::with_capacity(7);
    for j in 0..7u64 {
        if base < j * 64 {
            out.push(None);
            continue;
        }
        let checkpoint_height = base - j * 64;
        let lsb = rsk
            .get_block(client, rpc, checkpoint_height)?
            .and_then(|block| block.bitcoin_header.as_ref())
            .map(|header| double_sha256(header)[0]);
        out.push(lsb);
    }
    Ok(out)
}

// For a non-matching tag: by ancestry, a consistent diverged fork matches a
// contiguous SUFFIX of checkpoints from the oldest up to its divergence
// point, and mismatches everything newer. Returns how many oldest-contiguous
// checkpoints match. 7 means the fork root is within 64 blocks of the tag's
// height; 0 means deeper than base-384 (or a fake tag).
fn cpv_suffix_matches(
    client: &reqwest::blocking::Client,
    rpc: &str,
    rsk: &mut RskCache,
    tag: &Tag,
) -> Result<usize> {
    let expected = expected_cpv(client, rpc, rsk, tag.block_number)?;
    let mut matched = 0usize;
    for j in (0..7usize).rev() {
        match expected[j] {
            Some(byte) if byte == tag.cpv[j] => matched += 1,
            _ => break,
        }
    }
    Ok(matched)
}

// The interval the fork root must lie in, given how many oldest checkpoints
// matched, clamped below by the maximum-reorg assumption. Returns
// (lower bound inclusive, upper bound inclusive).
fn fork_root_interval(tag: &Tag, matched: usize, deepest_allowed_root: u64) -> (u64, u64) {
    let base = ((tag.block_number.saturating_sub(1)) / 64) * 64;
    let (lower, upper) = if matched >= 7 {
        (base + 1, tag.block_number)
    } else {
        let matched = matched as u64;
        (
            base.saturating_sub((7 - matched) * 64) + 1,
            base.saturating_sub((6 - matched) * 64),
        )
    };
    (lower.max(deepest_allowed_root), upper)
}

// ---------------------------------------------------------------------------
// FINAL checkpoint + header retention

// Is this RSK block provably mined after the bitcoin window started? True
// when its merge-mined bitcoin header's prevHash (bytes 4..36, little endian)
// is one of the window's bitcoin blocks.
fn is_fresh(
    client: &reqwest::blocking::Client,
    rpc: &str,
    rsk: &mut RskCache,
    window: &HashMap<[u8; 32], (u64, u32)>,
    height: u64,
) -> Result<bool> {
    Ok(rsk
        .get_block(client, rpc, height)?
        .and_then(|block| block.bitcoin_header.as_ref())
        .and_then(|header| header.get(4..36))
        .map(|prev_hash| {
            let mut key = [0u8; 32];
            key.copy_from_slice(prev_hash);
            window.contains_key(&key)
        })
        .unwrap_or(false))
}

// Earliest RSK block whose merge-mined bitcoin parent is inside the window.
// Bitcoin parent references advance almost monotonically with RSK height, so
// binary search finds the boundary, then a bounded backward walk absorbs the
// non-monotonic fuzz (miners briefly building on stale bitcoin tips).
fn find_checkpoint_block(
    client: &reqwest::blocking::Client,
    rpc: &str,
    rsk: &mut RskCache,
    window: &HashMap<[u8; 32], (u64, u32)>,
    mut low: u64,
    mut high: u64,
) -> Result<Option<u64>> {
    if !is_fresh(client, rpc, rsk, window, high)? {
        return Ok(None);
    }
    if is_fresh(client, rpc, rsk, window, low)? {
        return Ok(Some(low));
    }
    while low < high {
        let middle = low + (high - low) / 2;
        if is_fresh(client, rpc, rsk, window, middle)? {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    // Backward refinement: accept earlier fresh blocks within a short gap.
    let mut checkpoint = high;
    let mut probe = high;
    let mut gap = 0u64;
    while probe > 1 && gap < 32 {
        probe -= 1;
        if is_fresh(client, rpc, rsk, window, probe)? {
            checkpoint = probe;
            gap = 0;
        } else {
            gap += 1;
        }
    }
    Ok(Some(checkpoint))
}

// Header record: [32 hash][32 parent hash][32 state root][8-byte BE timestamp]
fn encode_header(value: &Value) -> Option<Vec<u8>> {
    let field = |name: &str| -> Option<Vec<u8>> {
        let bytes = hex::decode(value.get(name)?.as_str()?.trim_start_matches("0x")).ok()?;
        (bytes.len() == 32).then_some(bytes)
    };
    let mut out = Vec::with_capacity(104);
    out.extend_from_slice(&field("hash")?);
    out.extend_from_slice(&field("parentHash")?);
    out.extend_from_slice(&field("stateRoot")?);
    let timestamp = value
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| hex_to_u64(s).ok())?;
    out.extend_from_slice(&timestamp.to_be_bytes());
    Some(out)
}

struct HeaderSyncReport {
    stored: u64,
    fetched: u64,
    link_breaks: u64,
    // RSK timestamp more than MAX_TIMESTAMP_SKEW_SECONDS away from the
    // timestamp of the bitcoin block its merge-mining header points to.
    timestamp_violations: u64,
    // Referenced bitcoin parent heights must be non-decreasing along the RSK
    // chain (a decrease of 1 is tolerated for miners on briefly stale tips).
    order_violations: u64,
    // prevHash not found among the window's canonical bitcoin blocks
    // (below-window or orphaned bitcoin parents; checked only when fetched).
    unresolved_parents: u64,
}

// Download any missing headers in [final_block, rsk_tip], persist those that
// are reorg-final (height <= tip - RSK_FINAL_DEPTH), verify parent-hash
// links over the stored range, and check RSK-vs-bitcoin timestamp
// consistency on every header fetched this run.
fn sync_headers(
    client: &reqwest::blocking::Client,
    rpc: &str,
    database: &Database,
    final_block: u64,
    rsk_tip: u64,
    pause_ms: u64,
    window: &HashMap<[u8; 32], (u64, u32)>,
) -> Result<HeaderSyncReport> {
    let persist_up_to = rsk_tip.saturating_sub(RSK_FINAL_DEPTH);
    let mut missing: Vec<u64> = Vec::new();
    {
        let transaction = database.begin_read()?;
        let table = transaction.open_table(RSK_HEADER_TABLE)?;
        let mut present = std::collections::HashSet::new();
        for entry in table.range(final_block..=persist_up_to)? {
            present.insert(entry?.0.value());
        }
        for height in final_block..=persist_up_to {
            if !present.contains(&height) {
                missing.push(height);
            }
        }
    }
    let total_missing = missing.len();
    let mut fetched = 0u64;
    let mut timestamp_violations = 0u64;
    let mut order_violations = 0u64;
    let mut unresolved_parents = 0u64;
    let mut previous_bitcoin_parent: Option<(u64, u64)> = None; // (rsk height, btc height)
    const BATCH: usize = 25;
    for (batch_index, chunk) in missing.chunks(BATCH).enumerate() {
        let requests: Vec<(u64, &str, Value)> = chunk
            .iter()
            .map(|height| {
                (
                    *height,
                    "eth_getBlockByNumber",
                    json!([to_hex(*height), false]),
                )
            })
            .collect();
        let results = rsk_batch_call(client, rpc, &requests)?;
        for height in chunk {
            let Some(block) = results.get(height) else {
                continue;
            };
            if block.is_null() {
                continue;
            }
            let Some(record) = encode_header(block) else {
                bail!("block {height} response missing header fields");
            };
            // Timestamp + ordering consistency against the bitcoin parent
            // referenced by this block's merge-mining header.
            let bitcoin_parent = block
                .get("bitcoinMergedMiningHeader")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
                .and_then(|header| {
                    header.get(4..36).map(|prev_hash| {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(prev_hash);
                        key
                    })
                })
                .and_then(|key| window.get(&key).copied());
            match bitcoin_parent {
                Some((bitcoin_height, bitcoin_timestamp)) => {
                    if bitcoin_timestamp != 0 {
                        let rsk_timestamp = block
                            .get("timestamp")
                            .and_then(|v| v.as_str())
                            .and_then(|s| hex_to_u64(s).ok())
                            .unwrap_or(0);
                        if rsk_timestamp.abs_diff(bitcoin_timestamp as u64)
                            > MAX_TIMESTAMP_SKEW_SECONDS
                        {
                            timestamp_violations += 1;
                        }
                    }
                    if let Some((previous_rsk, previous_bitcoin)) = previous_bitcoin_parent {
                        if previous_rsk < *height && bitcoin_height + 1 < previous_bitcoin {
                            order_violations += 1;
                        }
                    }
                    previous_bitcoin_parent = Some((*height, bitcoin_height));
                }
                None => unresolved_parents += 1,
            }
            database_write(database, RSK_HEADER_TABLE, *height, &record)?;
            fetched += 1;
        }
        if batch_index % 20 == 0 {
            eprintln!(
                "  headers: {} / {} fetched",
                (batch_index * BATCH + chunk.len()).min(total_missing),
                total_missing
            );
        }
        std::thread::sleep(Duration::from_millis(pause_ms));
    }

    // Verify parent links and count stored headers.
    let mut stored = 0u64;
    let mut link_breaks = 0u64;
    {
        let transaction = database.begin_read()?;
        let table = transaction.open_table(RSK_HEADER_TABLE)?;
        let mut previous_hash: Option<[u8; 32]> = None;
        let mut previous_height: Option<u64> = None;
        for entry in table.range(final_block..=persist_up_to)? {
            let (key, value) = entry?;
            let height = key.value();
            let bytes = value.value();
            if bytes.len() < 64 {
                link_breaks += 1;
                continue;
            }
            if let (Some(previous_hash), Some(previous_height)) = (previous_hash, previous_height) {
                if previous_height + 1 == height && bytes[32..64] != previous_hash {
                    link_breaks += 1;
                }
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[0..32]);
            previous_hash = Some(hash);
            previous_height = Some(height);
            stored += 1;
        }
    }
    Ok(HeaderSyncReport {
        stored,
        fetched,
        link_breaks,
        timestamp_violations,
        order_violations,
        unresolved_parents,
    })
}

// Delete all entries with key < cutoff. Returns how many were removed.
fn prune_below(
    database: &Database,
    table_definition: TableDefinition<'static, u64, &'static [u8]>,
    cutoff: u64,
) -> Result<u64> {
    let keys: Vec<u64> = {
        let transaction = database.begin_read()?;
        let table = transaction.open_table(table_definition)?;
        let mut keys = Vec::new();
        for entry in table.range(..cutoff)? {
            keys.push(entry?.0.value());
        }
        keys
    };
    if keys.is_empty() {
        return Ok(0);
    }
    let transaction = database.begin_write()?;
    {
        let mut table = transaction.open_table(table_definition)?;
        for key in &keys {
            table.remove(key)?;
        }
    }
    transaction.commit()?;
    Ok(keys.len() as u64)
}

// JSON-RPC batch: one POST carrying many requests, results keyed by id.
fn rsk_batch_call(
    client: &reqwest::blocking::Client,
    rpc: &str,
    requests: &[(u64, &str, Value)],
) -> Result<HashMap<u64, Value>> {
    let body = Value::Array(
        requests
            .iter()
            .map(|(id, method, params)| {
                json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
            })
            .collect(),
    );
    let mut last_error: Option<anyhow::Error> = None;
    for attempt in 0..4 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(500 * (1 << attempt)));
        }
        match client.post(rpc).json(&body).send() {
            Ok(response) if response.status().is_success() => {
                let parsed: Value = response.json()?;
                let mut out = HashMap::new();
                for item in parsed.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                    if let Some(id) = item.get("id").and_then(|v| v.as_u64()) {
                        out.insert(id, item.get("result").cloned().unwrap_or(Value::Null));
                    }
                }
                return Ok(out);
            }
            Ok(response) => last_error = Some(anyhow!("batch call: HTTP {}", response.status())),
            Err(error) => last_error = Some(error.into()),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("batch call failed")))
}

// ---------------------------------------------------------------------------
// network plumbing

// Esplora client with host rotation: on any failure (rate limit, outage)
// the next request goes to the next host; the tool only sleeps once every
// host in the pool has failed in the current cycle. Retry-After is honored
// when present.
struct Esplora {
    client: reqwest::blocking::Client,
    hosts: Vec<String>,
    current: std::cell::Cell<usize>,
}

impl Esplora {
    fn get(&self, path: &str) -> Result<String> {
        let host_count = self.hosts.len().max(1);
        let total_attempts = host_count * 8;
        let mut last_error: Option<anyhow::Error> = None;
        let mut retry_after_hint: u64 = 0;
        for attempt in 0..total_attempts {
            let host = &self.hosts[self.current.get() % host_count];
            let url = format!("{host}{path}");
            match self.client.get(&url).send() {
                Ok(response) if response.status().is_success() => return Ok(response.text()?),
                Ok(response) => {
                    let status = response.status();
                    if status.as_u16() == 429 {
                        let hinted = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);
                        retry_after_hint = retry_after_hint.max(hinted);
                    }
                    last_error = Some(anyhow!("GET {url}: HTTP {status}"));
                }
                Err(error) => last_error = Some(anyhow!("GET {url}: {error}")),
            }
            // This host failed: rotate to the next one immediately.
            self.current.set(self.current.get().wrapping_add(1));
            // Sleep only after a full cycle through every host.
            if (attempt + 1) % host_count == 0 {
                let cycle = ((attempt + 1) / host_count) as u32;
                let wait_seconds = retry_after_hint.max((1u64 << cycle.min(7)).min(120));
                retry_after_hint = 0;
                if wait_seconds > 2 {
                    eprintln!("  all esplora hosts failing, backing off {wait_seconds}s");
                }
                std::thread::sleep(Duration::from_secs(wait_seconds));
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("GET {path} failed on all hosts")))
    }
}

fn rsk_call(
    client: &reqwest::blocking::Client,
    rpc: &str,
    method: &str,
    params: Value,
) -> Result<Value> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    let mut last_error: Option<anyhow::Error> = None;
    for attempt in 0..4 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(500 * (1 << attempt)));
        }
        match client.post(rpc).json(&body).send() {
            Ok(response) if response.status().is_success() => {
                let value: Value = response.json()?;
                if let Some(error) = value.get("error") {
                    if !error.is_null() {
                        bail!("{method}: rpc error {error}");
                    }
                }
                return Ok(value.get("result").cloned().unwrap_or(Value::Null));
            }
            Ok(response) => last_error = Some(anyhow!("{method}: HTTP {}", response.status())),
            Err(error) => last_error = Some(error.into()),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("{method} failed")))
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn to_hex(number: u64) -> String {
    format!("0x{number:x}")
}

fn hex_to_u64(text: &str) -> Result<u64> {
    Ok(u64::from_str_radix(text.trim_start_matches("0x"), 16)?)
}
