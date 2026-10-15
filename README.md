# RSK One

A persistent Rootstock (RSK) light client that syncs Bitcoin and Rootstock
headers to disk, and whose stated goal is to download and verify RSK block
headers **faster than rskj or rustock** — by pulling headers over the RSK P2P
network with a parallel skeleton walk, anchored to Bitcoin via merge mining.

## Current status

- `rsk-core` — the side-effect-free chain state (redb): the Bitcoin fork tree
  with a **checkpoint spine** (one header per difficulty period, so whole-chain
  work is known without holding every block), header validation (PoW,
  difficulty, median-time-past), automatic period finalization, and the
  Rootstock header **forest** with GHOST weighting and the ephemeral-chain
  checkpoint rules.
- `rsk` — the node **as a library**: Bitcoin header sync over P2P (a small peer
  pool, prefetch overlapped with validation) and checkpoint export. Embeddable
  in any app.
- `rsk-cli` — a thin command-line wrapper over the `rsk` library.
- `rsk-consensus` / `rsk-p2p` — vendored from rustock (consensus types + rules;
  RLPx + devp2p + `rsk/*` + UDP discovery).

Not yet: RSK header sync over P2P (the checkpoint/tree logic in `rsk-core` is
ready), follow mode near the tip, and state.

## Project Structure

```
crates/
  rsk-core/      — side-effect-free Bitcoin + Rootstock chain state (redb): checkpoint spine, fork tree, RSK header forest, checkpoint rules
  rsk/           — the RSK One node as a library: Bitcoin header sync, peer pool, checkpoint export
  cli/           — rsk-cli: a thin command-line wrapper over the `rsk` library
  btc-p2p/       — Bitcoin P2P protocol client: framed transport, version/verack handshake, headers
  rsk-consensus/ — vendored rustock consensus: Header, HeaderVerifier, ChainConfig, checkpoint (88 tests)
  rsk-p2p/       — vendored rustock RLPx networking + rsk subprotocol + discovery (80 tests)
```

## Usage

```bash
# sync Bitcoin headers into ./data/rsk-one/chain.redb (validates every header)
cargo run -p rsk-cli -- sync

# write the store's finalized period boundaries as a checkpoints.txt
cargo run -p rsk-cli -- export-checkpoints > checkpoints.txt
```

See `cargo run -p rsk-cli -- <command> --help` for the flags of each command.

## Acknowledgment

Bootstrapped from the great work at `check-fork` for the [Union bridge
client](https://github.com/rsksmart/union-bridge-client), and reuses consensus and
P2P code from [rustock](https://github.com/SergioDemianLerner/rustock) (MIT).
