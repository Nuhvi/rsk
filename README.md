# RSK One

A persistent Rootstock light client node.

RSK One syncs and stores Bitcoin and Rootstock headers to disk on startup so algorithm iteration doesn't require re-downloading data from RPCs. On restart it picks up where it left off.

## Project Structure

```
crates/
  rsk/        — Rust SDK library (block validation, merge-mining verification, light client logic)
  rsk-store/  — Persistent storage for Bitcoin and RSK headers (redb). Shared between node and client.
  rsk-node/   — Binary crate (header sync orchestration, Electrum + RSK RPC)
```

### `rsk-store` (library, usable by both node and client)

| Type | Description |
|---|---|
| `BitcoinHeaderStorage` | redb persistence for Bitcoin block headers |
| `RskHeaderStorage` | redb persistence for RSK headers + merge-mining data |
| `DifficultyTracker` | Sliding-window cumulative Bitcoin work tracker |
| `MergeMiningData` | Merge-mining proof components (hex strings) |
| `header_work()` | Compute work from a Bitcoin header's nBits target |
| `decode_rsk_header()` | Decode an RSK header from raw RLP bytes |
| `StoreError` | Error type for storage operations |

The client can use `get_tip_height()` and header range queries to tell the node which blocks it already has, so the node only sends what's missing.

### `rsk-node` (binary)

Phase 1: Connects to Electrum servers, syncs Bitcoin headers from a checkpoint (default block 900,000), validates PoW and chain continuity.

Phase 2: Walks backwards from the RSK tip, fetches block headers and merge-mining data from an RSK JSON-RPC endpoint, accumulates RSK difficulty until it meets or exceeds the Bitcoin window work.

Both phases skip already-stored data on restart.

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

## Status

Persistence-only first commit. No HTTP API, no merge-mining verification in the sync path yet, no Bitcoin reorg handling.

## Acknowledgment

This implementation was bootstrapped by copying the great work at `check-fork` for the [Union bridge client](https://github.com/rsksmart/union-bridge-client).
