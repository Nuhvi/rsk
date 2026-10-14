# rsk-core — TODO

Next steps, roughly in order. The crate is the side-effect-free core; network
I/O and orchestration live outside it (p2p / sync layers).

## Rootstock tail sync

- [ ] **`UncleGuard` window.** `Core::connect_rsk_headers` currently requires a
  batch in ascending order with each parent already stored, so the uncle rule's
  `AncestorSource` can walk the ancestry. Port rustock's `UncleGuard` (a bounded
  window of the uncle lists a header-only client has seen) so out-of-order or
  partial batches still validate, and credit no uncle work when the ancestry is
  incomplete.
- [ ] **`rsk_is_final` glue.** One method combining `rsk::Core::rsk_subtree_work`
  with `rootstock::bitcoin_tail_work` and `rootstock::is_final`, so a caller gets
  a verdict without wiring the pieces.
- [ ] **Tree ↔ `find_f` integration.** `rootstock::find_f` works on a provided
  descending run; wire it to the stored tree / the p2p bisect.
- [ ] **Pruning.** RSK headers below `F`; Bitcoin headers below the tail start
  (keep the previous finalized boundary so the finality condition stays
  re-derivable). Opt-in.
- [ ] **Merge-mining proof pruning.** Stored RSK headers carry the merged-mining
  merkle proof and coinbase (~600 B each). After validation, decide whether to
  keep them (to re-serve) or drop them.

## Validation

- [ ] **Vetiver.** Every block we validate is newer than `VETIVER-731b9d8`
  (`F` is always newer given >67% participation), so pre-Vetiver rules and the
  activation-height branches that only apply to older blocks can be dropped.
- [ ] **Real-header tests.** `connect_rsk_headers` is exercised only on synthetic
  headers today; add a fixture with real mainnet Rootstock headers (with uncles)
  to cover the full validation path.

## p2p (outside rsk-core)

- [ ] **Fetch with uncles.** `rsk/63` `BlockHeadersWithUncles` (27/28), else
  headers + bodies for uncles.
- [ ] **Bisect for `F`.** Per peer/fork, bisect canonical heights for the deepest
  in-tail anchor, then download `[F..tip]`.
- [ ] **Status work-at-F.** Advertise the cumulative work at `F` (a sixth status
  field) so a peer's `[F..tip]` work can be previewed before downloading.
