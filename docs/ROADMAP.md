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

### M1 — Vendored P2P + connect example (next)
- [ ] `crates/rsk-consensus` — vendor rustock-core subset (Header,
  HeaderVerifier, ChainConfig, checkpoint), drop the `trie` dep. Port its tests.
- [ ] `crates/rsk-p2p` — vendor rustock-networking subset (RLPx ecies/frame/
  handshake, devp2p Hello, rsk subprotocol messages), trimmed for a light client
  (no tx relay, no body/snap serving, no scoring at first).
- [ ] Example/phase: **connect** — resolve a mainnet bootnode
  (`bootstrap01.rsk.co:5050`), RLPx handshake, `Hello` with `rsk/62`, exchange
  `Status`, verify the peer's genesis hash is mainnet
  (`0xf88529d4ab262c0f4d042e9d8d3f2472848eaafe1a9b7213f57617eb40a9f9e0`),
  ping/pong for a while, print `{best_block_number, best_block_hash,
  total_difficulty}`.
- [ ] Wire as a `--p2p` mode or probe command in `rsk-node`.

### M2 — Parallel header walk into redb
- [ ] Port `HeaderWalk` as `rsk-sync`, storing verified headers in
  `rsk-store::Store` (raw RLP bytes keyed by height + embedded BTC header hash).
- [ ] Validate every header with `HeaderVerifier`; sum difficulty; honour the
  checkpoint gate against the peer's claimed TD.
- [ ] `BlockHashRequest` connection-point logic when starting from a height we
  don't hold.

### M3 — Bitcoin cross-link, follow mode, proofs
- [ ] Cross-check each stored RSK header's embedded 80-byte BTC header lies on
  the Electrum-synced Bitcoin chain (`prevHash` linkage) — this is what makes
  header-only RSK data probative (the *ephemeral sidechain* argument).
- [ ] Follow mode: `NewBlockHashes` + status polls near the tip; reorgs via
  last-common-ancestor truncation.
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