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

#[derive(Debug, Clone)]
struct Tag {
    tag_bytes: [u8; 32],
    hash_prefix: [u8; 20],
    cpv: [u8; 7],
    recent_uncles: u8,
    block_number: u64,
    bitcoin_height: u64,
    bitcoin_hash: String,
}

#[derive(Debug)]
enum Verdict {
    SupportingCanonical,
    SupportingUncle { included_at: u64 },
    Hiding { matched_oldest_checkpoints: usize },
    AheadOfTip,
}

fn main() -> Result<()> {
    let mut blocks_to_scan: u64 = 2016;
    let mut uncle_scan_depth: u64 = 6;
    let mut pause_ms: u64 = 150;
    let mut database_path = "tag-check.redb".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--blocks" => {
                blocks_to_scan = args.next().context("--blocks needs a value")?.parse()?
            }
            "--uncle-depth" => {
                uncle_scan_depth = args
                    .next()
                    .context("--uncle-depth needs a value")?
                    .parse()?
            }
            "--pause-ms" => pause_ms = args.next().context("--pause-ms needs a value")?.parse()?,
            "--db" | "--cache" => database_path = args.next().context("--db needs a value")?,
            other => bail!("unknown argument: {other}"),
        }
    }

    let esplora =
        std::env::var("ESPLORA_URL").unwrap_or_else(|_| "https://blockstream.info/api".to_string());
    let rsk_rpc =
        std::env::var("RSK_RPC_URL").unwrap_or_else(|_| "https://public-node.rsk.co".to_string());

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("rsk-tag-check/0.2")
        .build()?;

    let database = Database::create(&database_path)?;
    {
        // Ensure all tables exist so read transactions never fail.
        let transaction = database.begin_write()?;
        transaction.open_table(BITCOIN_COINBASE_TABLE)?;
        transaction.open_table(RSK_BLOCK_TABLE)?;
        transaction.open_table(RSK_UNCLES_TABLE)?;
        transaction.commit()?;
    }

    let bitcoin_tip: u64 = http_get(&client, &format!("{esplora}/blocks/tip/height"))?
        .trim()
        .parse()
        .context("parsing bitcoin tip height")?;
    let scan_start = bitcoin_tip.saturating_sub(blocks_to_scan - 1);
    eprintln!(
        "bitcoin tip = {bitcoin_tip}, scanning heights {scan_start}..={bitcoin_tip} ({blocks_to_scan} blocks)"
    );

    let rsk_tip = hex_to_u64(
        rsk_call(&client, &rsk_rpc, "eth_blockNumber", json!([]))?
            .as_str()
            .context("eth_blockNumber returned no string")?,
    )?;
    eprintln!("rootstock tip = {rsk_tip}");

    // ---- pass 1: collect tags from bitcoin coinbases -----------------------
    // Block hashes for heights missing from the database, 10 per request via
    // the /blocks/{start_height} batch endpoint.
    let mut block_hashes_by_height: HashMap<u64, String> = HashMap::new();
    let mut cursor = bitcoin_tip;
    loop {
        let batch_needed = (0..10u64).any(|offset| {
            let height = cursor.saturating_sub(offset);
            height >= scan_start
                && !matches!(
                    database_read(&database, BITCOIN_COINBASE_TABLE, height),
                    Ok(Some(_))
                )
        });
        if batch_needed {
            let body = http_get(&client, &format!("{esplora}/blocks/{cursor}"))?;
            let parsed: Value = serde_json::from_str(&body).context("parsing /blocks batch")?;
            for block in parsed.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                if let (Some(height), Some(id)) = (
                    block.get("height").and_then(|x| x.as_u64()),
                    block.get("id").and_then(|x| x.as_str()),
                ) {
                    if height >= scan_start {
                        block_hashes_by_height.insert(height, id.to_string());
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(pause_ms));
        }
        if cursor.saturating_sub(9) <= scan_start {
            break;
        }
        cursor -= 10;
    }

    let mut tags: Vec<Tag> = Vec::new();
    let mut neutral_count: u64 = 0;
    let mut bitcoin_from_cache: u64 = 0;
    let mut bitcoin_fetched: u64 = 0;
    for height in scan_start..=bitcoin_tip {
        let (hash_bytes, tag_bytes): (Vec<u8>, Option<[u8; 32]>) =
            if let Some(stored) = database_read(&database, BITCOIN_COINBASE_TABLE, height)? {
                bitcoin_from_cache += 1;
                decode_bitcoin_record(&stored)
                    .with_context(|| format!("corrupt bitcoin record at {height}"))?
            } else {
                let hash = block_hashes_by_height
                    .get(&height)
                    .cloned()
                    .with_context(|| format!("no block hash for height {height}"))?;
                let coinbase_txid = http_get(&client, &format!("{esplora}/block/{hash}/txid/0"))?
                    .trim()
                    .to_string();
                let coinbase_hex = http_get(&client, &format!("{esplora}/tx/{coinbase_txid}/hex"))?
                    .trim()
                    .to_string();
                let coinbase_raw = hex::decode(&coinbase_hex).context("decoding coinbase hex")?;
                let tag = extract_tag(&coinbase_raw);
                let hash_bytes = hex::decode(&hash).context("decoding block hash hex")?;
                if hash_bytes.len() != 32 {
                    bail!("unexpected block hash length for height {height}");
                }
                if height + BITCOIN_FINAL_DEPTH <= bitcoin_tip {
                    let mut record = hash_bytes.clone();
                    if let Some(tag) = &tag {
                        record.extend_from_slice(tag);
                    }
                    database_write(&database, BITCOIN_COINBASE_TABLE, height, &record)?;
                }
                bitcoin_fetched += 1;
                std::thread::sleep(Duration::from_millis(pause_ms));
                (hash_bytes, tag)
            };
        match tag_bytes {
            Some(raw) => {
                let mut hash_prefix = [0u8; 20];
                hash_prefix.copy_from_slice(&raw[0..20]);
                let mut cpv = [0u8; 7];
                cpv.copy_from_slice(&raw[20..27]);
                let block_number = u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]]) as u64;
                tags.push(Tag {
                    tag_bytes: raw,
                    hash_prefix,
                    cpv,
                    recent_uncles: raw[27],
                    block_number,
                    bitcoin_height: height,
                    bitcoin_hash: hex::encode(&hash_bytes),
                });
            }
            None => neutral_count += 1,
        }
        if (height - scan_start) % 100 == 0 {
            eprintln!(
                "  scanned {} / {} btc blocks, {} tags so far",
                height - scan_start + 1,
                blocks_to_scan,
                tags.len()
            );
        }
    }
    eprintln!(
        "pass 1 done: {} tagged, {} untagged (neutral); {} from cache, {} fetched",
        tags.len(),
        neutral_count,
        bitcoin_from_cache,
        bitcoin_fetched
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

    println!();
    println!("================ RSK tag audit ================");
    println!("bitcoin blocks scanned : {blocks_to_scan}");
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
        println!(
            "acceptance rule S > H  : {}",
            if supporting_count > hiding_count {
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
        let hiding_work = hiding_tags.len();
        let supporting_above_root = supporting_heights
            .iter()
            .filter(|height| **height > deepest_fork_root)
            .count();
        println!(
            "unresolved evidence: {hiding_work} tag(s), deepest possible fork root {deepest_fork_root} (tip - {})",
            rsk_tip.saturating_sub(deepest_fork_root)
        );
        println!(
            "work race above root: S {supporting_above_root} vs H {hiding_work} (need S > {SAFETY_MARGIN}*H)"
        );
        if supporting_above_root > SAFETY_MARGIN * hiding_work {
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
    Ok(())
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

// bitcoin record: [32-byte hash][optional 32-byte tag]
fn decode_bitcoin_record(bytes: &[u8]) -> Result<(Vec<u8>, Option<[u8; 32]>)> {
    match bytes.len() {
        32 => Ok((bytes.to_vec(), None)),
        64 => {
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&bytes[32..64]);
            Ok((bytes[0..32].to_vec(), Some(tag)))
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
// network plumbing

fn http_get(client: &reqwest::blocking::Client, url: &str) -> Result<String> {
    let mut last_error: Option<anyhow::Error> = None;
    for attempt in 0..8u32 {
        match client.get(url).send() {
            Ok(response) if response.status().is_success() => return Ok(response.text()?),
            Ok(response) => {
                let status = response.status();
                let wait_seconds = if status.as_u16() == 429 {
                    response
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or_else(|| (1u64 << attempt).min(60))
                } else {
                    (1u64 << attempt).min(30)
                };
                if wait_seconds > 2 {
                    eprintln!("  HTTP {status}, backing off {wait_seconds}s ({url})");
                }
                last_error = Some(anyhow!("GET {url}: HTTP {status}"));
                std::thread::sleep(Duration::from_secs(wait_seconds));
            }
            Err(error) => {
                last_error = Some(error.into());
                std::thread::sleep(Duration::from_secs((1u64 << attempt).min(30)));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("GET {url} failed")))
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
