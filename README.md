# RSK One

A persistent Rootstock (RSK) light node that syncs Bitcoin and Rootstock
headers to disk, and whose stated goal is to download and verify RSK block
headers **faster than rskj or rustock** — by pulling headers over the RSK P2P
network with a parallel skeleton walk, anchored to Bitcoin via merge mining.

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

Reuses consensus and P2P code from [rustock](https://github.com/SergioDemianLerner/rustock) (MIT).
