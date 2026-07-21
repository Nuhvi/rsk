# RSK One

A persistent Rootstock light client node.

RSK One syncs and stores Bitcoin and Rootstock headers to disk on startup so algorithm iteration doesn't require re-downloading data from RPCs. On restart it picks up where it left off.

## Project Structure

```
crates/
  rsk/        — Rust SDK library (block validation, merge-mining verification, light client logic)
  rsk-node/   — Binary crate (header sync, persistence, future API)
```

## What It Does

1. **Bitcoin headers** — Connects to Electrum servers, fetches Bitcoin headers from a checkpoint (default block 900,000), and persists them to a redb database. Maintains a sliding-window cumulative difficulty tracker.
2. **RSK headers** — Walks backwards from the RSK tip, fetches block headers and merge-mining data from an RSK JSON-RPC endpoint, and stores everything to a second redb database. Accumulates RSK difficulty until it meets or exceeds the Bitcoin window work.

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
| `--data-dir` | `data` | Directory for `btc_headers.redb` and `rsk_headers.redb` |
| `--electrum` | *(required)* | Electrum server URL(s), repeatable |
| `--rsk-rpc-url` | *(required)* | RSK JSON-RPC endpoint |
| `--btc-checkpoint-height` | `900000` | Skip Bitcoin headers before this block |
| `--btc-window-size` | `100` | Number of blocks in the difficulty window |
| `--rsk-safe-block-margin` | `6` | How far below the RSK tip to start (reorg safety) |
| `--sync-batch-size` | `100` | Block headers per RPC batch |

## Status

Persistence-only first commit. No HTTP API, no merge-mining verification in the sync path yet, no Bitcoin reorg handling.
