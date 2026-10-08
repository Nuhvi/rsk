# RSK One — Roadmap & notes for next steps

A running document capturing the direction discussed so far. When in doubt, this
is the source of truth for *what we decided and why*, and `DESIGN.md` holds the
architecture.

## What we are building

A Rootstock **independent client** (independent of rskj). The main goal, in
order of priority:

1.  **Sync RSK block headers — at the very least — and do it faster than rskj or
    rustock.**
2.  Only once headers sync, worry about syncing the **state**.

## Decisions made (keep these)

- **Headers over P2P, not RPC.** Get RSK headers from the RSK P2P network.
  The protocol already exists and *works* in
  [rustock](https://github.com/SergioDemianLerner/rustock) (a Rust Rootstock
  client by SergioDemianLerner) — clone it next to this repo (`../rustock`),
  read its `docs/` (especially `wire-protocol.md`, `header-first-sync.md`,
  `snapshot-sync.md`, `difficulty-gate.md`).
- **Use the *same code* as rustock to verify headers.** Vendored into this repo
  as `rsk-consensus`; do not re-derive a parallel rule set.
- **Bitcoin blocks are a separate problem.** RSK peers don't serve/share
  Bitcoin blocks over their P2P protocol, so:
  - **Now**: get Bitcoin headers via **Electrum** (already implemented in
    `rsk-node`), plus the difficulty-period checkpoints from `bitcoin-spv`.
  - **Later**: optionally copy Bitcoin blocks over P2P from
    **[floresta](https://github.com/romanz/floresta)**.
- **Docs first.** Design and roadmap are written before the code lands.

## Why faster (the short version)

rskj's header sync is a *serial* walk: servers return headers descending from a
hash you supply, so you fetch 192, take the oldest parent, repeat — ~48,000
round trips for mainnet. RSK's `SkeletonRequest`(by height, returns identifiers
every 192 blocks) lets you fire off all the anchors at once and then parallelise
the descendant downloads; the chunks are trusted only because they **link**
(oldest of run `p` == parent of newest of run `p-192`). rustock implements this
(`sync/src/snap/headers.rs`, `HeaderWalk`). We port it.

## Milestones

### M0 — Docs ✅ (this repo, current)
- [x] `docs/DESIGN.md` — architecture, wire flow, security model, vendoring.
- [x] `docs/ROADMAP.md` — this file.
- [x] README updated to point at the new direction.

### M1 — Vendored P2P + connect example (done ✅)
- [x] `crates/rsk-consensus` — vendored rustock-core subset (`Header`,
  `HeaderVerifier` + all rules, `ChainConfig`, `DifficultyCheckpoint` gate,
  `Block`/`Transaction`), `trie` dep dropped. 88 vendored tests pass
  (genesis hashes, RSKIP92 header hashing vs real mainnet blocks, merged-mining
  PoW, checkpoint ceiling/refusal on real sampled chain).
- [x] `crates/rsk-p2p` — vendored rustock-networking subset: RLPx
  (`ecies`/`frame`/`handshake`/`codec`, EIP-8, multi-frame chunking), devp2p
  `Hello`/`Ping`/`Pong`, `eth`+`rsk` subprotocol messages, and the UDP
  discovery `Ping`/`Pong`/`FindNode`/`Neighbors` packets. Trimmed to a light
  client (no tx relay, no body/snap serving, no scoring). 80 vendored tests
  pass, incl. a full local RLPx initiator↔responder handshake.
- [x] Example: `crates/rsk-p2p/examples/connect.rs` — resolves a bootnode,
  learns its node ID via a signed UDP discovery ping (bootnode DNS entries
  carry no pubkey), then does RLPx + `rsk/62` handshake, verifies the peer's
  genesis hash against mainnet, prints
  `{best_block_number, best_block_hash, total_difficulty}` and proves the
  session with a Ping/Pong and `NewBlockHashes`.

  Verified against live mainnet (bootnode 12):
  ```text
  discovered node id: 0x81471846e79afde2…
  connected to peer:  0x81471846e79afde2…
  negotiated:         rsk/62 (snap: false)
  peer status:        block 9307795 0x237c0f22f7ec1e24…
  peer total difficulty:  61329131479833386325493975807
  got Pong ✓
  NewBlockHashes: …  block 9307796
  ```

  Note: not every bootnode answers UDP discovery (several were silent on a
  first try); `bootstrap12.rsk.co` responded reliably. A real client should
  try the whole bootnode list and rotate.
- [ ] Wire as a `--p2p` mode or probe command in `rsk-node`.

### M2 — Parallel header walk into redb (done ✅)
- [x] `crates/rsk-sync` — port of rustock's `HeaderWalk` (`walk.rs`): skeleton
  grid → parallel descending `BlockHeadersRequest` pipeline → full
  `HeaderVerifier` rules on every header → redb via a `HeaderStore` trait
  (`store.rs`, adapter over `rsk-store`).
- [x] Trust model: the walk seeds the store's **canonical index** with the
  checkpoint (#9,020,000) and takes a **floor** there, so it anchors at the
  checkpoint (or at a previously-verified grid boundary on resume) instead of
  re-downloading genesis. The canonical index is deliberately separate from the
  raw header table so a walk can never satisfy its own anchor. Verified
  stretches are promoted to canonical only after the walk links (`canonicalize_above_checkpoint`).
- [x] Checkpoint gate: peer's claimed total difficulty is bounded against the
  checkpoint before download (loose no-sample ceiling) and audited again after
  the walk with real sampled headers (`judge`, ~376 samples). Refuses
  impossible claims.
- [x] Resume: a second run against the same store connected, walked only the
  `9308100 − 9308030 = 132`-header delta and re-anchored on the canonical tip.
- [x] Verified live on mainnet: **288,062 headers walked/verified/stored**
  (top 9,308,030 → anchor 9,019,968), canonicalized 288,030, gate `plausible`
  (established 6.142e28 vs peer-claimed 6.133e28, ceiling 7.08e28). Debug
  build, single peer, ~10 min; a release build with several peers is far faster
  than rskj's serial walk (48k sequential round trips).
- [x] Offline regression tests: walk floor-anchor + below-floor filtering,
  resume-anchor on an existing canonical head, `total_difficulty` summation,
  canonicalization (4 tests).
- Streams ahead of the completed M2 fix: batched redb header writes (one write
  txn per 192-header run), top-down skeleton ordering ("the top unblocks the
  walk"), correct `tip_height` maintenance across descending batches.

### M3 — Bitcoin cross-link, follow mode, proofs
- [ ] Follow new blocks near the tip: status polls + `NewBlockHashes`, reorgs
  via last-common-ancestor truncation.
- [ ] Bitcoin cross-link: validate each stored RSK header's embedded 80-byte BTC
  header lies on the Electrum-synced chain (`prevHash` linkage) — makes
  header-only RSK data probative (ephemeral sidechains).
- [ ] Merge-mining proof components (coinbase + Merkle proof): from JSON-RPC
  today, RSKIP-698 `BlockHeadersWithUncles` (`rsk/63`) later.

### Later
- [ ] State/trie sync on top of the verified header spine.
- [ ] Floresta P2P for Bitcoin blocks; retire `light_client.rs` RPC walk as the
  oracle once P2P covers it.
- [ ] RSKIP-110 checkpoint tags (Armadillo/CPV) and tag-based finality from
  `tag_check.rs` / `epoch_tags.rs` integrated with the spine.

## Useful reference facts

- Mainnet genesis hash `0xf88529d4ab262c0f4d042e9d8d3f2472848eaafe1a9b7213f57617eb40a9f9e0`; testnet `0xcabb7fbe88cd6d922042a32ffc08ce8b1fbb37d650b9d4e7dbfe2a7469adfa42`.
- Bootnodes: mainnet `bootstrap01..16.rsk.co:5050`, testnet `bootstrap01..08.testnet.rsk.co:50505`.
- Cumulative-difficulty checkpoint: mainnet **#9,020,000** (refreshed per release, see rustock `core/src/checkpoint.rs`).
- Skeleton grid: 20 points × 192 blocks (`HEADER_CHUNK = 192`, `SKELETON_POINTS = 20`).
- Headers arrive **descending** (newest first); reverse before validation.