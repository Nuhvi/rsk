# RSK One

A persistent Rootstock (RSK) light client that syncs Bitcoin and Rootstock
headers to disk, and whose stated goal is to download and verify RSK block
headers **faster than rskj or rustock** — by pulling headers over the RSK P2P
network with a parallel skeleton walk, anchored to Bitcoin via merge mining.

Start with the docs: [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and
security model, [`docs/ROADMAP.md`](docs/ROADMAP.md) for the working plan and
notes on next steps.

## Current status

- Bitcoin headers sync from **Electrum** servers (PoW + chain continuity
  validated), starting from a difficulty-period checkpoint.
- RSK headers + merge-mining data sync from an RSK **JSON-RPC** endpoint
  (backward/forward walk) into redb.
- **Next milestone (M1):** vendored `rsk-consensus` + `rsk-p2p` crates (from
  rustock, MIT) and a working example that connects to a mainnet bootnode,
  completes the RLPx / `rsk/62` handshake, and reads the peer's status — the
  first step toward P2P header sync.

## Project Structure

```
crates/
  rsk/           — Rust SDK library (header model, merge-mining verification, RPC light-client logic)
  rsk-store/     — Persistent storage for Bitcoin and RSK headers (redb). Shared between node and client.
  rsk-node/      — Binary crate (header sync orchestration, Electrum + RSK RPC)
  bitcoin-spv/   — Bitcoin SPV helpers + difficulty-period checkpoint dump
  rsk-consensus/ — [planned] vendored rustock consensus: Header, HeaderVerifier, ChainConfig, checkpoint
  rsk-p2p/       — [planned] vendored rustock RLPx networking + rsk subprotocol
```

### `rsk-store` (library, usable by both node and client)

| Type | Description |
|---|---|
| `Store` | redb persistence for Bitcoin headers, RSK headers, and merge-mining data |
| `DifficultyTracker` | Sliding-window cumulative Bitcoin work tracker |
| `MergeMiningData` | Merge-mining proof components (hex strings) |
| `header_work()` | Compute work from a Bitcoin header's nBits target |
| `decode_rsk_header()` | Decode an RSK header from raw RLP bytes |
| `StoreError` | Error type for storage operations |

The client can use `get_tip_height()` and header range queries to tell the node
which blocks it already has, so the node only sends what's missing.

### `rsk-node` (binary)

Phase 1: Connects to Electrum servers, syncs Bitcoin headers from a checkpoint
(default block 900,000), validates PoW and chain continuity.

Phase 2: Syncs RSK headers and merge-mining data from an RSK JSON-RPC endpoint,
accumulating RSK difficulty until it covers the Bitcoin window work.

Both phases skip already-stored data on restart. The P2P path will replace the
RPC fetch in Phase 2.

## Usage

```bash
cargo run -p rsk-node -- \
  --electrum ssl://blockstream.info:993 \
  --electrum ssl://electrum.blockstream.info:993 \
  --rsk-rpc-url https://public-node.rsk.co \
  --data-dir ./data
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--data-dir` | `data` | Directory for `store.redb` |
| `--electrum` | *(required)* | Electrum server URL(s), repeatable |
| `--rsk-rpc-url` | *(required)* | RSK JSON-RPC endpoint |
| `--btc-checkpoint-height` | `900000` | Skip Bitcoin headers before this block |
| `--btc-window-size` | `100` | Number of blocks in the difficulty window |
| `--rsk-safe-block-margin` | `6` | How far below the RSK tip to start (reorg safety) |
| `--sync-batch-size` | `100` | Block headers per RPC batch |

## Acknowledgment

Bootstrapped from the great work at `check-fork` for the [Union bridge
client](https://github.com/rsksmart/union-bridge-client), and reuses consensus and
P2P code from [rustock](https://github.com/SergioDemianLerner/rustock) (MIT).