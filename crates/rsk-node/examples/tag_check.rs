// rsk-tag-check
//
// Local "Armadillo" fork-detection check for the Ephemeral Sidechains sync:
//
//   1. Walk the last N (default 2016) Bitcoin blocks via an Esplora API,
//      fetch each coinbase transaction, and extract the RSKBLOCK: tag.
//   2. Decode each tag per RSKIP110:
//        [0..20]  PREFIX  - 20-byte prefix of hashForMergedMining
//        [20..27] CPV     - LSBs of BTC block ids at 7 ancestor checkpoints
//        [27]     NU      - uncles in the last 32 RSK blocks
//        [28..32] BN      - RSK block height being mined (big endian)
//   3. For each tag, check whether the referenced RSK block exists in the
//      canonical Rootstock chain at height BN, or as an uncle included in
//      one of the following blocks (consensus window: BN+1..=BN+6, from
//      rskj uncleGenerationLimit = 7).
//   4. Report S (supporting), H (hiding) and, for hiding tags, a CPV-based
//      estimate of how deep the divergence is.
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

// btc: height -> [32-byte block hash][optional 32-byte tag]
const T_BTC: TableDefinition<u64, &[u8]> = TableDefinition::new("btc_coinbase");
// rsk block: height -> BlockRec::to_bytes()
const T_BLK: TableDefinition<u64, &[u8]> = TableDefinition::new("rsk_block");
// rsk uncles: height -> repeated [8-byte BE uncle number][32-byte mm hash]
const T_UNC: TableDefinition<u64, &[u8]> = TableDefinition::new("rsk_uncles");

// Reorg safety margins: never persist data this close to the tip.
const BTC_FINAL_DEPTH: u64 = 2;
const RSK_FINAL_DEPTH: u64 = 64;

#[derive(Debug, Clone)]
struct Tag {
    raw: [u8; 32],
    prefix: [u8; 20],
    cpv: [u8; 7],
    nu: u8,
    bn: u64,
    btc_height: u64,
    btc_hash: String,
}

#[derive(Debug)]
enum Verdict {
    SupportingCanonical,
    SupportingUncle { included_at: u64 },
    Hiding { cpv_matches: usize },
    AheadOfTip,
}

fn main() -> Result<()> {
    let mut n_blocks: u64 = 2016;
    let mut uncle_depth: u64 = 6;
    let mut pause_ms: u64 = 150;
    let mut db_path = "tag-check.redb".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--blocks" => n_blocks = args.next().context("--blocks needs a value")?.parse()?,
            "--uncle-depth" => {
                uncle_depth = args
                    .next()
                    .context("--uncle-depth needs a value")?
                    .parse()?
            }
            "--pause-ms" => pause_ms = args.next().context("--pause-ms needs a value")?.parse()?,
            "--db" | "--cache" => db_path = args.next().context("--db needs a value")?,
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

    let db = Database::create(&db_path)?;
    {
        // Ensure all tables exist so read transactions never fail.
        let tx = db.begin_write()?;
        tx.open_table(T_BTC)?;
        tx.open_table(T_BLK)?;
        tx.open_table(T_UNC)?;
        tx.commit()?;
    }

    let btc_tip: u64 = http_get(&client, &format!("{esplora}/blocks/tip/height"))?
        .trim()
        .parse()
        .context("parsing bitcoin tip height")?;
    let start = btc_tip.saturating_sub(n_blocks - 1);
    eprintln!("bitcoin tip = {btc_tip}, scanning heights {start}..={btc_tip} ({n_blocks} blocks)");

    let rsk_tip = hex_to_u64(
        rsk_call(&client, &rsk_rpc, "eth_blockNumber", json!([]))?
            .as_str()
            .context("eth_blockNumber returned no string")?,
    )?;
    eprintln!("rootstock tip = {rsk_tip}");

    // ---- pass 1: collect tags from bitcoin coinbases -----------------------
    // Block hashes for heights missing from the db, 10 per request via the
    // /blocks/{start_height} batch endpoint.
    let mut hashes: HashMap<u64, String> = HashMap::new();
    let mut cursor = btc_tip;
    loop {
        let batch_needed = (0..10u64).any(|i| {
            let h = cursor.saturating_sub(i);
            h >= start && !matches!(db_get(&db, T_BTC, h), Ok(Some(_)))
        });
        if batch_needed {
            let body = http_get(&client, &format!("{esplora}/blocks/{cursor}"))?;
            let v: Value = serde_json::from_str(&body).context("parsing /blocks batch")?;
            for b in v.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                if let (Some(hh), Some(id)) = (
                    b.get("height").and_then(|x| x.as_u64()),
                    b.get("id").and_then(|x| x.as_str()),
                ) {
                    if hh >= start {
                        hashes.insert(hh, id.to_string());
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

    let mut tags: Vec<Tag> = Vec::new();
    let mut untagged: u64 = 0;
    let mut btc_cached: u64 = 0;
    let mut btc_fetched: u64 = 0;
    for h in start..=btc_tip {
        let (hash_bytes, tag_bytes): (Vec<u8>, Option<[u8; 32]>) =
            if let Some(bytes) = db_get(&db, T_BTC, h)? {
                btc_cached += 1;
                decode_btc_rec(&bytes).with_context(|| format!("corrupt btc record at {h}"))?
            } else {
                let hash = hashes
                    .get(&h)
                    .cloned()
                    .with_context(|| format!("no block hash for height {h}"))?;
                let cb_txid = http_get(&client, &format!("{esplora}/block/{hash}/txid/0"))?
                    .trim()
                    .to_string();
                let cb_hex = http_get(&client, &format!("{esplora}/tx/{cb_txid}/hex"))?
                    .trim()
                    .to_string();
                let cb_raw = hex::decode(&cb_hex).context("decoding coinbase hex")?;
                let t = extract_tag(&cb_raw);
                let hash_bytes = hex::decode(&hash).context("decoding block hash hex")?;
                if hash_bytes.len() != 32 {
                    bail!("unexpected block hash length for height {h}");
                }
                if h + BTC_FINAL_DEPTH <= btc_tip {
                    let mut rec = hash_bytes.clone();
                    if let Some(t) = &t {
                        rec.extend_from_slice(t);
                    }
                    db_put(&db, T_BTC, h, &rec)?;
                }
                btc_fetched += 1;
                std::thread::sleep(Duration::from_millis(pause_ms));
                (hash_bytes, t)
            };
        match tag_bytes {
            Some(raw) => {
                let mut prefix = [0u8; 20];
                prefix.copy_from_slice(&raw[0..20]);
                let mut cpv = [0u8; 7];
                cpv.copy_from_slice(&raw[20..27]);
                let bn = u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]]) as u64;
                tags.push(Tag {
                    raw,
                    prefix,
                    cpv,
                    nu: raw[27],
                    bn,
                    btc_height: h,
                    btc_hash: hex::encode(&hash_bytes),
                });
            }
            None => untagged += 1,
        }
        if (h - start) % 100 == 0 {
            eprintln!(
                "  scanned {} / {} btc blocks, {} tags so far",
                h - start + 1,
                n_blocks,
                tags.len()
            );
        }
    }
    eprintln!(
        "pass 1 done: {} tagged, {} untagged (neutral); {} from cache, {} fetched",
        tags.len(),
        untagged,
        btc_cached,
        btc_fetched
    );

    // ---- pass 2: match tags against rootstock blocks + uncles --------------
    let mut cache = RskCache::new(&db, rsk_tip);
    let mut verdicts: Vec<(Tag, Verdict)> = Vec::new();
    // CPV LSB convention (first byte of the double-sha256 digest) is fixed;
    // verified against mainnet. cpv_sanity_checked enforces it fail-loud on
    // the first known-supporting tag in case a future tag version (e.g.
    // RSKIP224 CFV) changes the field's meaning.
    let mut cpv_sanity_checked = false;

    for (i, tag) in tags.iter().enumerate() {
        let verdict = if tag.bn > rsk_tip {
            Verdict::AheadOfTip
        } else if cache
            .block(&client, &rsk_rpc, tag.bn)?
            .and_then(|b| b.mm)
            .map(|h| h == tag.raw || h[0..20] == tag.prefix)
            .unwrap_or(false)
        {
            Verdict::SupportingCanonical
        } else if let Some(at) =
            find_as_uncle(&client, &rsk_rpc, &mut cache, tag, uncle_depth, rsk_tip)?
        {
            Verdict::SupportingUncle { included_at: at }
        } else {
            let m = cpv_suffix_matches(&client, &rsk_rpc, &mut cache, tag)?;
            Verdict::Hiding { cpv_matches: m }
        };

        if matches!(verdict, Verdict::SupportingCanonical) && !cpv_sanity_checked {
            let exp = expected_cpv(&client, &rsk_rpc, &mut cache, tag.bn)?;
            let available = exp.iter().filter(|e| e.is_some()).count();
            let matched = exp
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
                    tag.bn
                );
            }
            if available > 0 {
                eprintln!(
                    "  CPV sanity check passed ({matched}/{available} on rsk height {})",
                    tag.bn
                );
                cpv_sanity_checked = true;
            }
        }

        verdicts.push((tag.clone(), verdict));
        if i % 50 == 0 {
            eprintln!("  matched {} / {} tags", i + 1, tags.len());
        }
    }
    eprintln!(
        "pass 2 done: rsk data {} from cache, {} rpc calls",
        cache.db_hits, cache.rpc_calls
    );

    // ---- report -------------------------------------------------------------
    let mut s_canon = 0u64;
    let mut s_uncle = 0u64;
    let mut hiding: Vec<&(Tag, Verdict)> = Vec::new();
    let mut ahead = 0u64;
    for v in &verdicts {
        match v.1 {
            Verdict::SupportingCanonical => s_canon += 1,
            Verdict::SupportingUncle { .. } => s_uncle += 1,
            Verdict::Hiding { .. } => hiding.push(v),
            Verdict::AheadOfTip => ahead += 1,
        }
    }
    let n = tags.len() as u64;
    let s = s_canon + s_uncle;
    let h = hiding.len() as u64;

    println!();
    println!("================ RSK tag audit ================");
    println!("bitcoin blocks scanned : {n_blocks}");
    println!("tagged coinbases (n)   : {n}");
    println!("untagged (neutral)     : {untagged}");
    println!("S  supporting          : {s}   (canonical {s_canon}, uncle {s_uncle})");
    println!("H  hiding              : {h}");
    if ahead > 0 {
        println!("ahead of RSK tip       : {ahead} (re-run once RSK node catches up)");
    }
    if n > 0 {
        if h == 0 {
            println!(
                "no hiding evidence: hidden merge-mining share < {:.3}% (rule of three, 95% conf.)",
                300.0 / n as f64
            );
        } else {
            println!(
                "observed hiding share  : {:.3}% of tagged blocks",
                100.0 * h as f64 / n as f64
            );
        }
        println!(
            "acceptance rule S > H  : {}",
            if s > h { "PASS" } else { "FAIL" }
        );
    }
    const MAX_REORG: u64 = 40320; // assumption 2: no reorg deeper than ~14 days
    let assumption_floor = rsk_tip.saturating_sub(MAX_REORG);
    for (tag, verdict) in &hiding {
        let m = match verdict {
            Verdict::Hiding { cpv_matches } => *cpv_matches,
            _ => 0,
        };
        let (lb, ub) = fork_root_interval(tag, m, assumption_floor);
        let depth = if m >= 7 {
            format!(
                "shares all CPV checkpoints -> root in ({}, {}] (benign sibling territory)",
                lb - 1,
                ub
            )
        } else if m == 0 {
            format!("shares no CPV checkpoints -> root at or below {ub} (deep fork or fake tag)")
        } else {
            format!(
                "shares oldest {m}/7 CPV checkpoints -> root in ({}, {}]",
                lb - 1,
                ub
            )
        };
        println!(
            "  HIDING btc {} ({}) -> rsk bn {} prefix {} nu {} | {}",
            tag.btc_height,
            &tag.btc_hash[tag.btc_hash.len().saturating_sub(16)..],
            tag.bn,
            hex::encode(&tag.prefix[..8]),
            tag.nu,
            depth
        );
    }

    // ---- subjective SAFE ----------------------------------------------------
    // FACON-style (RSKIP555) but difficulty-period-local and work-based:
    //   1. Union all unresolved non-matching evidence into one conservative
    //      fork hypothesis: root = deepest CPV-implied lower bound (clamped by
    //      the max-reorg assumption), H = its bitcoin-observed work (tag count).
    //   2. Work race: supporting tags above that root form S_race. If
    //      S_race > 2*H the hypothetical fork is provably losing on the
    //      bitcoin record and does not constrain SAFE.
    //   3. Otherwise SAFE retreats to root-1.
    //   4. Confirmation floor: SAFE never exceeds the height with at least
    //      W_CONF bitcoin-observed supporting confirmations above it.
    const W_CONF: usize = 2;
    println!();
    println!("---------------- subjective SAFE ----------------");
    let mut sup_bns: Vec<u64> = verdicts
        .iter()
        .filter_map(|(t, v)| {
            matches!(
                v,
                Verdict::SupportingCanonical | Verdict::SupportingUncle { .. }
            )
            .then_some(t.bn)
        })
        .collect();
    sup_bns.sort_unstable();
    if sup_bns.len() < W_CONF {
        println!("not enough supporting evidence to declare any block SAFE");
        return Ok(());
    }
    let x_conf = sup_bns[sup_bns.len() - W_CONF].saturating_sub(1);
    let safe = if hiding.is_empty() {
        println!("no unresolved fork evidence in window");
        x_conf
    } else {
        let mut root = u64::MAX;
        for (tag, verdict) in &hiding {
            let m = match verdict {
                Verdict::Hiding { cpv_matches } => *cpv_matches,
                _ => 0,
            };
            root = root.min(fork_root_interval(tag, m, assumption_floor).0);
        }
        let h_work = hiding.len();
        let s_race = sup_bns.iter().filter(|b| **b > root).count();
        println!(
            "unresolved evidence: {h_work} tag(s), deepest possible fork root {root} \
             (tip - {})",
            rsk_tip.saturating_sub(root)
        );
        println!("work race above root: S {s_race} vs H {h_work} (need S > 2H)");
        if s_race > 2 * h_work {
            println!("hypothetical fork is losing on the bitcoin record; no retreat");
            x_conf
        } else {
            println!("insufficient observed work above the contested root; retreating");
            x_conf.min(root.saturating_sub(1))
        }
    };
    println!(
        "subjective SAFE block  : {safe} (tip - {})",
        rsk_tip.saturating_sub(safe)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Tag extraction: the merge-mining spec requires the tag in the tail of the
// serialized coinbase, so take the LAST occurrence of the magic bytes.
fn extract_tag(raw: &[u8]) -> Option<[u8; 32]> {
    let mut pos = None;
    let mut i = 0usize;
    while i + TAG_MAGIC.len() <= raw.len() {
        if &raw[i..i + TAG_MAGIC.len()] == TAG_MAGIC {
            pos = Some(i);
        }
        i += 1;
    }
    let p = pos? + TAG_MAGIC.len();
    if p + 32 > raw.len() {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw[p..p + 32]);
    Some(out)
}

// ---------------------------------------------------------------------------
// redb plumbing

fn db_get(
    db: &Database,
    t: TableDefinition<'static, u64, &'static [u8]>,
    k: u64,
) -> Result<Option<Vec<u8>>> {
    let tx = db.begin_read()?;
    let table = tx.open_table(t)?;
    Ok(table.get(k)?.map(|g| g.value().to_vec()))
}

fn db_put(
    db: &Database,
    t: TableDefinition<'static, u64, &'static [u8]>,
    k: u64,
    v: &[u8],
) -> Result<()> {
    let tx = db.begin_write()?;
    {
        let mut table = tx.open_table(t)?;
        table.insert(k, v)?;
    }
    tx.commit()?;
    Ok(())
}

// btc record: [32-byte hash][optional 32-byte tag]
fn decode_btc_rec(bytes: &[u8]) -> Result<(Vec<u8>, Option<[u8; 32]>)> {
    match bytes.len() {
        32 => Ok((bytes.to_vec(), None)),
        64 => {
            let mut t = [0u8; 32];
            t.copy_from_slice(&bytes[32..64]);
            Ok((bytes[0..32].to_vec(), Some(t)))
        }
        n => bail!("btc record has invalid length {n}"),
    }
}

// ---------------------------------------------------------------------------
// Rootstock data: compact per-block record + uncle list, cached in memory and
// persisted in redb (except near the tip, where reorgs can still change it).

#[derive(Debug, Clone)]
struct BlockRec {
    mm: Option<[u8; 32]>, // hashForMergedMining (== the 32-byte tag)
    hdr: Option<Vec<u8>>, // bitcoinMergedMiningHeader (80 bytes)
    uncle_count: u8,      // number of uncles referenced by this block
}

impl BlockRec {
    fn from_json(v: &Value) -> Self {
        let hdr = v
            .get("bitcoinMergedMiningHeader")
            .and_then(|x| x.as_str())
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok());
        let uncle_count = v
            .get("uncles")
            .and_then(|u| u.as_array())
            .map(|a| a.len().min(255))
            .unwrap_or(0) as u8;
        BlockRec {
            mm: merged_mining_hash(v),
            hdr,
            uncle_count,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 2 + 80 + 1);
        let mut flags = 0u8;
        if self.mm.is_some() {
            flags |= 1;
        }
        if self.hdr.is_some() {
            flags |= 2;
        }
        out.push(flags);
        if let Some(mm) = &self.mm {
            out.extend_from_slice(mm);
        }
        if let Some(hdr) = &self.hdr {
            out.extend_from_slice(&(hdr.len() as u16).to_le_bytes());
            out.extend_from_slice(hdr);
        }
        out.push(self.uncle_count);
        out
    }

    fn from_bytes(b: &[u8]) -> Result<Self> {
        let err = || anyhow!("corrupt rsk block record");
        let flags = *b.first().ok_or_else(err)?;
        let mut pos = 1usize;
        let mm = if flags & 1 != 0 {
            let s = b.get(pos..pos + 32).ok_or_else(err)?;
            pos += 32;
            let mut a = [0u8; 32];
            a.copy_from_slice(s);
            Some(a)
        } else {
            None
        };
        let hdr = if flags & 2 != 0 {
            let l = b.get(pos..pos + 2).ok_or_else(err)?;
            let len = u16::from_le_bytes([l[0], l[1]]) as usize;
            pos += 2;
            let s = b.get(pos..pos + len).ok_or_else(err)?;
            pos += len;
            Some(s.to_vec())
        } else {
            None
        };
        let uncle_count = *b.get(pos).ok_or_else(err)?;
        Ok(BlockRec {
            mm,
            hdr,
            uncle_count,
        })
    }
}

struct RskCache<'a> {
    db: &'a Database,
    rsk_tip: u64,
    blocks: HashMap<u64, Option<BlockRec>>,
    uncles: HashMap<u64, Vec<(u64, [u8; 32])>>,
    db_hits: u64,
    rpc_calls: u64,
}

impl<'a> RskCache<'a> {
    fn new(db: &'a Database, rsk_tip: u64) -> Self {
        RskCache {
            db,
            rsk_tip,
            blocks: HashMap::new(),
            uncles: HashMap::new(),
            db_hits: 0,
            rpc_calls: 0,
        }
    }

    fn persistable(&self, h: u64) -> bool {
        h + RSK_FINAL_DEPTH <= self.rsk_tip
    }

    fn block(
        &mut self,
        client: &reqwest::blocking::Client,
        rpc: &str,
        h: u64,
    ) -> Result<Option<&BlockRec>> {
        if !self.blocks.contains_key(&h) {
            let rec = if let Some(bytes) = db_get(self.db, T_BLK, h)? {
                self.db_hits += 1;
                Some(BlockRec::from_bytes(&bytes)?)
            } else {
                let v = rsk_call(
                    client,
                    rpc,
                    "eth_getBlockByNumber",
                    json!([to_hex(h), false]),
                )?;
                self.rpc_calls += 1;
                if v.is_null() {
                    None
                } else {
                    let rec = BlockRec::from_json(&v);
                    if self.persistable(h) {
                        db_put(self.db, T_BLK, h, &rec.to_bytes())?;
                    }
                    Some(rec)
                }
            };
            self.blocks.insert(h, rec);
        }
        Ok(self.blocks.get(&h).unwrap().as_ref())
    }

    // Uncles referenced by the block at height h, as (uncle number, mm hash).
    // Uncles whose number or mm hash cannot be determined are omitted (they
    // could never match a tag anyway).
    fn uncles_at(
        &mut self,
        client: &reqwest::blocking::Client,
        rpc: &str,
        h: u64,
    ) -> Result<&[(u64, [u8; 32])]> {
        if !self.uncles.contains_key(&h) {
            let list = if let Some(bytes) = db_get(self.db, T_UNC, h)? {
                self.db_hits += 1;
                decode_uncles(&bytes)?
            } else {
                let count = self
                    .block(client, rpc, h)?
                    .map(|b| b.uncle_count as usize)
                    .unwrap_or(0);
                let mut list = Vec::with_capacity(count);
                for idx in 0..count {
                    let u = rsk_call(
                        client,
                        rpc,
                        "eth_getUncleByBlockNumberAndIndex",
                        json!([to_hex(h), to_hex(idx as u64)]),
                    )?;
                    self.rpc_calls += 1;
                    if u.is_null() {
                        continue;
                    }
                    let num = u
                        .get("number")
                        .and_then(|v| v.as_str())
                        .and_then(|s| hex_to_u64(s).ok());
                    if let (Some(num), Some(mm)) = (num, merged_mining_hash(&u)) {
                        list.push((num, mm));
                    }
                }
                if self.persistable(h) {
                    db_put(self.db, T_UNC, h, &encode_uncles(&list))?;
                }
                list
            };
            self.uncles.insert(h, list);
        }
        Ok(self.uncles.get(&h).unwrap())
    }
}

fn encode_uncles(list: &[(u64, [u8; 32])]) -> Vec<u8> {
    let mut out = Vec::with_capacity(list.len() * 40);
    for (num, mm) in list {
        out.extend_from_slice(&num.to_be_bytes());
        out.extend_from_slice(mm);
    }
    out
}

fn decode_uncles(bytes: &[u8]) -> Result<Vec<(u64, [u8; 32])>> {
    if bytes.len() % 40 != 0 {
        bail!("corrupt uncle record");
    }
    let mut out = Vec::with_capacity(bytes.len() / 40);
    for chunk in bytes.chunks_exact(40) {
        let mut n = [0u8; 8];
        n.copy_from_slice(&chunk[0..8]);
        let mut mm = [0u8; 32];
        mm.copy_from_slice(&chunk[8..40]);
        out.push((u64::from_be_bytes(n), mm));
    }
    Ok(out)
}

// The tag committed on Bitcoin IS the RSK block's hashForMergedMining
// (RSKIP110 replaced its format with PREFIX|CPV|NU|BN). RSKj exposes it
// directly on block objects; if the field is absent (e.g. some uncle
// responses), fall back to parsing the block's own embedded coinbase.
fn merged_mining_hash(block: &Value) -> Option<[u8; 32]> {
    if let Some(s) = block.get("hashForMergedMining").and_then(|v| v.as_str()) {
        if let Ok(b) = hex::decode(s.trim_start_matches("0x")) {
            if b.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                return Some(out);
            }
        }
    }
    if let Some(s) = block
        .get("bitcoinMergedMiningCoinbaseTransaction")
        .and_then(|v| v.as_str())
    {
        if let Ok(b) = hex::decode(s.trim_start_matches("0x")) {
            return extract_tag(&b);
        }
    }
    None
}

// A tag that doesn't match the canonical block at BN may still be an uncle:
// scan the uncles included in the next `depth` blocks for one at height BN
// with the same merged-mining hash prefix. rskj's uncleGenerationLimit = 7
// means a valid uncle at height BN can only be referenced by blocks at
// BN+1..=BN+6, so the default depth of 6 covers the full consensus window.
fn find_as_uncle(
    client: &reqwest::blocking::Client,
    rpc: &str,
    cache: &mut RskCache,
    tag: &Tag,
    depth: u64,
    rsk_tip: u64,
) -> Result<Option<u64>> {
    for k in 1..=depth {
        let h = tag.bn + k;
        if h > rsk_tip {
            break;
        }
        let matched = cache
            .uncles_at(client, rpc, h)?
            .iter()
            .any(|(num, mm)| *num == tag.bn && mm[0..20] == tag.prefix);
        if matched {
            return Ok(Some(h));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// CPV: v(i) = LSB of the Bitcoin block id merge-mined with the RSK block at
// height ((BN-1)/64)*64 - i*64. "LSB" is the first byte of the raw
// double_sha256(bitcoinMergedMiningHeader) digest (the little-endian internal
// form, i.e. the last byte of the displayed block hash). Verified against
// mainnet tags; guarded by the fail-loud sanity check in the matching loop.
fn expected_cpv(
    client: &reqwest::blocking::Client,
    rpc: &str,
    cache: &mut RskCache,
    bn: u64,
) -> Result<Vec<Option<u8>>> {
    let base = ((bn.saturating_sub(1)) / 64) * 64;
    let mut out = Vec::with_capacity(7);
    for i in 0..7u64 {
        if base < i * 64 {
            out.push(None);
            continue;
        }
        let h = base - i * 64;
        let lsb = cache
            .block(client, rpc, h)?
            .and_then(|b| b.hdr.as_ref())
            .map(|hdr| double_sha256(hdr)[0]);
        out.push(lsb);
    }
    Ok(out)
}

// For a non-matching tag: CPV checkpoints sit at heights base - j*64
// (j = 0..6, base = ((BN-1)/64)*64), v(0) newest. By ancestry, a consistent
// diverged fork matches a contiguous SUFFIX from the oldest checkpoint up to
// its divergence point and mismatches everything newer. Returns m = number of
// oldest-contiguous matches; the fork root then lies in
// (base - (7-m)*64, base - (6-m)*64], with m=7 meaning root within 64 of BN
// and m=0 meaning deeper than base-384 (or a fake tag).
fn cpv_suffix_matches(
    client: &reqwest::blocking::Client,
    rpc: &str,
    cache: &mut RskCache,
    tag: &Tag,
) -> Result<usize> {
    let exp = expected_cpv(client, rpc, cache, tag.bn)?;
    let mut m = 0usize;
    for j in (0..7usize).rev() {
        match exp[j] {
            Some(e) if e == tag.cpv[j] => m += 1,
            _ => break,
        }
    }
    Ok(m)
}

// Lower bound (exclusive -> we return inclusive lb) and upper bound of the
// fork root implied by a non-matching tag, clamped by the maximum-reorg
// assumption.
fn fork_root_interval(tag: &Tag, m: usize, assumption_floor: u64) -> (u64, u64) {
    let base = ((tag.bn.saturating_sub(1)) / 64) * 64;
    let (lb, ub) = if m >= 7 {
        (base + 1, tag.bn)
    } else {
        let m = m as u64;
        (
            base.saturating_sub((7 - m) * 64) + 1,
            base.saturating_sub((6 - m) * 64),
        )
    };
    (lb.max(assumption_floor), ub)
}

// ---------------------------------------------------------------------------
// network plumbing

fn http_get(client: &reqwest::blocking::Client, url: &str) -> Result<String> {
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..8u32 {
        match client.get(url).send() {
            Ok(r) if r.status().is_success() => return Ok(r.text()?),
            Ok(r) => {
                let status = r.status();
                let wait = if status.as_u16() == 429 {
                    r.headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or_else(|| (1u64 << attempt).min(60))
                } else {
                    (1u64 << attempt).min(30)
                };
                if wait > 2 {
                    eprintln!("  HTTP {status}, backing off {wait}s ({url})");
                }
                last = Some(anyhow!("GET {url}: HTTP {status}"));
                std::thread::sleep(Duration::from_secs(wait));
            }
            Err(e) => {
                last = Some(e.into());
                std::thread::sleep(Duration::from_secs((1u64 << attempt).min(30)));
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("GET {url} failed")))
}

fn rsk_call(
    client: &reqwest::blocking::Client,
    rpc: &str,
    method: &str,
    params: Value,
) -> Result<Value> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..4 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(500 * (1 << attempt)));
        }
        match client.post(rpc).json(&body).send() {
            Ok(r) if r.status().is_success() => {
                let v: Value = r.json()?;
                if let Some(err) = v.get("error") {
                    if !err.is_null() {
                        bail!("{method}: rpc error {err}");
                    }
                }
                return Ok(v.get("result").cloned().unwrap_or(Value::Null));
            }
            Ok(r) => last = Some(anyhow!("{method}: HTTP {}", r.status())),
            Err(e) => last = Some(e.into()),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("{method} failed")))
}

fn double_sha256(b: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(b);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn to_hex(n: u64) -> String {
    format!("0x{n:x}")
}

fn hex_to_u64(s: &str) -> Result<u64> {
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}
