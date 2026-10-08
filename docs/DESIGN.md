# RSK One — Design

A persistent Rootstock **light client** built to sync Bitcoin and Rootstock
headers **faster than rskj or rustock**, using the *ephemeral sidechain* model:
RSK headers are anchored, block-for-block, into Bitcoin via merge mining, so a
client that trusts Bitcoin headers can validate RSK headers almost entirely off
the headers themselves.

The design behind the security model is described in
[Ephemeral Sidechains](https://research.rsk.dev/t/ephemeral-sidechains/536) on
the RSK research forum.

## 1. Goal and scope

1.  Sync Rootstock (RSK) **block headers** over P2P, verifying every one of them
    under the full consensus rule set.
2.  Do the Bitcoin side of the proof-of-work anchor using **Electrum** today
    (RSK nodes do not expose Bitcoin block sharing, and none of our peers serve
    it), with a path to fetch Bitcoin blocks over P2P from e.g.
    [floresta](https://github.com/romanz/floresta) later.
3.  Reuse the consensus and networking code that
    [rustock](https://github.com/SergioDemianLerner/rustock) already has written
    and tested, vendored into this repository, rather than reinventing it.
4.  Headers first; **state sync is a later problem**. Once headers are flowing,
    and only then, worry about state/trie and bodies.

The measure of success is speed: an initial header download ("IBD") that
completes in minutes, not the hours that a serial per-block walk costs rskj and
(ordinarily) rustock.

## 2. Why header sync from scratch is slow, and how this gets around it

To ask for RSK headers you must name a block hash, and the only hash you have is
the one the last answer gave you. The obvious walk — ask for 192 headers, take
the oldest one's parent, ask again — is strictly **serial**. For a ~9.3M block
chain that is ~48,000 round trips before a single header is verified, and it is
exactly how rskj walks (and how rustock's snapshot walk is bounded when it
cannot use skeletons).

The wire cannot express "give me headers *forward* from this height": the
request is `{hash, count}` and servers walk *backward* from the hash. But two
RSK protocol messages break the serial dependency:

- **`SkeletonRequest`** (id 16): asks, by *height*, for up to 20 block
  identifiers spaced **192 blocks** apart.
- **`BlockHeadersRequest`** (id 9): asks, by *hash*, for up to 192 headers.

Skeletons can all be asked at once, and each returned identifier is the starting
hash for a header request that can also be asked at once — the requests no
longer wait for each other. Chunks are verified by **linking**: the oldest of
the run from height `p` must be the parent of the newest of the run from
`p-192`, and a run is trusted only when an unbroken chain of links reaches from
the top down to a block this node already holds. A wrong identifier produces a
chunk that fails the link test and is simply asked of somebody else.

This is rustock's `HeaderWalk` (`sync/src/snap/headers.rs`), which we port into
this repo. Every header still passes the *full* consensus rule set including the
merge-mining proof of work — pipelining changes *when* questions are asked, not
*which* answers are accepted.

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ rsk-node  (binary; existing, gains a P2P sync phase)             │
│   loop { election of peers → walk headers → store → cross-link } │
├──────────────────────────────────────────────────────────────────┤
│ rsk-p2p        (NEW; vendored+trimmed from rustock-networking)   │
│   RLPx: ECIES auth, AES-256-CTR frames, Keccak MACs              │
│   devp2p: Hello/Ping/Pong/GetPeers/Peers                         │
│   rsk subprotocol: Status, BlockHash, Skeleton, BlockHeaders     │
│   (later: bodies, NewBlockHashes, BlockHeadersWithUncles)        │
├──────────────────────────────────────────────────────────────────┤
│ rsk-consensus  (NEW; vendored from rustock-core, no trie dep)    │
│   Header (decode_with_hash, hashing)                             │
│   HeaderVerifier::default_rsk (full consensus rules incl.        │
│     MergedMining, Difficulty, gas, timestamp, linkage)           │
│   ChainConfig (genesis, activations, bootnodes)                  │
│   DifficultyCheckpoint + cumulative-difficulty gate              │
├──────────────────────────────────────────────────────────────────┤
│ rsk-sync       (NEW; port of rustock HeaderWalk engine)          │
│   skeleton grid → parallel descending chunks → redb Store        │
├──────────────────────────────────────────────────────────────────┤
│ rsk-store / rsk (existing)                                       │
│   Store: btc_headers, rsk_headers, rsk_merge_mining, meta        │
│   Electrum BTC sync + bitcoin-spv checkpoints (trust anchor)     │
└──────────────────────────────────────────────────────────────────┘
```

### The P2P layer (`rsk-p2p`)

RSK's P2P protocol is inherited from Ethereum: **RLPx** over TCP — an ECIES
handshake, AES-256-CTR frames with Keccak MACs, multi-frame chunking — carrying
a devp2p `Hello` for capability negotiation and then an **`rsk` subprotocol**
(double-wrapped RLP like devp2p's `eth`). Full details live in rustock's
`docs/wire-protocol.md`.

The message set a light client needs is small:

| id | message | use |
|---|---|---|
| 1 | `Status` | handshake: best block number/hash, total difficulty |
| 8/18 | `BlockHashRequest` / `BlockHashResponse` | connection point at a height |
| 16/13 | `SkeletonRequest` / `SkeletonResponse` | block identifiers every 192 blocks |
| 9/10 | `BlockHeadersRequest` / `BlockHeadersResponse` | up to 192 headers, delivered newest-first |
| 6 | `NewBlockHashes` | follow mode near the tip |
| 2/3 | `Ping` / `Pong` | keepalive |

Bootstrap uses the same DNS seeds as rskj: `bootstrap01..16.rsk.co:5050`
(mainnet), `bootstrap01..08.testnet.rsk.co:50505` (testnet), then UDP discovery
and/or `GetPeers`/`Peers` to grow the peer set.

### Trust and verification (`rsk-consensus`)

Every header that arrives is checked against the full consensus rule set
(vendored from rustock-core's `HeaderVerifier::default_rsk`):

- **static rules**: gas used, gas limit bounds, merged-mining proof (the
  `RSKBLOCK:` tag commitment and the RSKIP-92 Merkle proof to the embedded
  Bitcoin header, plus the RSK PoW check `hash ≤ 2^256 / difficulty`),
  extra-data;
- **parent rules**: block number linkage, timestamp (≤15 s future drift),
  parent gas limit, minimum gas price (relative to the previous block),
  difficulty (the ±1/400 retarget family of rules).

A **cumulative-difficulty checkpoint** (`DifficultyCheckpoint`, mainnet #9,020,000
as of this writing) bounds what a peer may claim in `Status.total_difficulty`
before we spend any bandwidth on it: the work below the checkpoint is exact, and
the work above it is bounded by the retarget rule plus an uncle allowance
estimated from sampled headers. A claim above the ceiling is `Impossible` and
the peer is dropped. See rustock's `docs/difficulty-gate.md`.

### The Bitcoin anchor (`rsk-store` + `bitcoin-spv`)

Bitcoin headers are synced from **Electrum** servers, PoW- and
chain-continuity-validated, starting from a **difficulty-period checkpoint**
(`crates/bitcoin-spv/checkpoints.txt` — one 80-byte header per 2016-block
period, downloaded from Esplora). This gives a trusted Bitcoin chain cheaply
without a full Bitcoin node.

The ephemeral-sidechain security argument then does the rest: each RSK header
embeds the 80-byte Bitcoin header it was merge-mined on. Consecutive RSK headers
therefore carry a **Bitcoin-side linkage** — embedded header `prevHash` chains
tracking real Bitcoin blocks — which a light client can cross-check against the
Electrum-synced chain. Combined with a BTC work window (RSK cumulative
difficulty must match or exceed the Bitcoin work spanning the same period), a
reorg past the finalized checkpoint would have to out-mine real Bitcoin. This is
the "freshness / checkpoint block" logic prototyped in `tag_check.rs`.

## 4. The sync phases

1. **Bitcoin first.** Sync and persist BTC headers from Electrum from the last
   trusted checkpoint. Maintain a sliding-window difficulty tracker.
2. **RSK headers.** Connect P2P, take the peer's best block under the
   difficulty gate, and run the skeleton walk *backward* (or from the stored
   tip forward) to a block already held or to the checkpoint. Verify every
   header; persist raw header bytes keyed by height.
3. **Cross-link.** For stored RSK headers, validate their embedded BTC headers
   lie on the trusted Bitcoin chain (`prevHash` linkage). This is what makes
   header-only data *probative*, not just self-consistent.
4. **Follow.** Near the tip, react to `NewBlockHashes`; reorgs are handled by
   storing the chain as a linked spine and truncating to the last common
   ancestor.
5. **Later: state.** Reuse the verified header spine to fetch bodies and account
   state, either over P2P or (today's fallback) RSK JSON-RPC for merge-mining
   proof components (`eth_getBlockByNumber`, `rsk_getRawBlockHeaderByNumber`).

## 5. Speed expectations

The parallel skeleton walk downloads ~9.3M headers in a handful of pipelined
round trips per 3,840-block grid, then verifies each header in-process
(keccak, difficulty, merged-mining PoW). Header verification is the only cost
that does not parallelise away **per block**, and it is cheap — milliseconds.
The bottleneck becomes the peers and the network, which is why the design keeps
many reconciliation-free requests in flight at once and never lets a chunk wait
on a previous chunk.

For reference: rustock measured ~21 GB / ~7,000 s on mainnet for the *full*
sync's header phase; a headers-only light client doing only the walk and skipping
bodies/state avoids most of that cost entirely.

## 6. What we vendor and from where

This project copies (and where necessary trims) code from
[rustock](https://github.com/SergioDemianLerner/rustock), MIT-licensed. We keep
the source attribution. The alternative — cargo-depending on rustock — was
rejected: it drags in `rustock-trie`, RocksDB storage, and the execution engine,
and couples this repo's build to upstream churn. An independent client should
be able to build out of this repository alone.

The validation types (`Header`, `HeaderVerifier`, `ChainConfig`,
`DifficultyCheckpoint`) are taken wholesale, not re-derived from this repo's
older `RskBlockHeader` SDK type; a copy that diverges from the tested
implementation is worse than no copy. The `rsk` SDK crate remains for its
RPC/SPV helpers.

## 7. Open questions / deferred

- **Bitcoin blocks**: keep Electrum, or add floresta P2P (or the Bitcoin SPV
  crate already started in `crates/bitcoin-spv`)? Not needed for headers.
- **Merge-mining proofs over P2P**: heads-up, headers carry the embedded BTC
  header but not the coinbase/Merkle proof (bodies). Today proofs come from
  JSON-RPC where required; `rsk/63`'s `BlockHeadersWithUncles` (RSKIP-698) may
  close part of the gap later.
- **Replacement of `light_client.rs`**: the RPC-driven backward walk becomes
  the fallback/oracle path once P2P sync works, and can be retired.
- **Finality**: RSKIP-110 checkpoint tags (Armadillo/CPV) and the
  tag-based finality logic in `tag_check.rs`/`epoch_tags.rs` integrate when the
  P2P spine is complete.