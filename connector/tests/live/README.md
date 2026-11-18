# Live tests against a local Blokli

`chain.sh` starts Anvil, deploys the HOPR contracts and starts a Blokli (`bloklid`) on top, then runs until interrupted. It prints the
`BLOKLI_URL` and `ANVIL_URL` to use. The logs are in `DATA_DIR`.

```shell
BLOKLID_BIN=<bloklid> DEPLOYER_BIN=<blokli-contract-deployer> ANVIL_BIN=<anvil> DATA_DIR=/tmp/blokli-chain \
  connector/tests/live/chain.sh
```

`ANVIL_PORT` (default 18545) and `BLOKLI_PORT` (default 18080) move the ports. `UNMINED_TIMEOUT` (default `15s`) is passed to Blokli as
`BLOKLI_API_TRANSACTIONS_UNMINED_TIMEOUT`, so that an unmined transaction is diagnosed within seconds instead of the default 300 s. Blokli
0.14.5 has no such setting and ignores it.

## Nonce gap after a fee spike

`connector/src/connector/sequencer_live_tests.rs` raises the base fee above the fee cap Blokli handed out, lets the sequencer's approvals go
unmined, and measures how far the sequencer's nonce stays ahead of the chain while it keeps sending. It is meant to be run against several
Blokli builds to compare them. `BLOKLI_LABEL` is `0.14.5` or `main`, and selects the expected outcome. Any other label only prints the
series.

Run the matrix with one chain per build, one after the other (or on different ports):

```shell
for build in 0.14.5 main; do
  BLOKLID_BIN=<dir>/bloklid-$build/bin/bloklid DEPLOYER_BIN=<dir>/bloklid-$build/bin/blokli-contract-deployer \
    ANVIL_BIN=<anvil> DATA_DIR=/tmp/blokli-chain-$build connector/tests/live/chain.sh &
  chain=$!
  until curl -sf -X POST http://127.0.0.1:18080/graphql -H 'content-type: application/json' \
    --data '{"query":"{chainInfo{... on ChainInfo{chainId}}}"}' | grep -q chainId; do sleep 2; done
  BLOKLI_URL=http://127.0.0.1:18080 ANVIL_URL=http://127.0.0.1:18545 BLOKLI_LABEL=$build \
    cargo test -p hopr-chain-connector --lib sequencer_live_tests -- --ignored --nocapture --test-threads=1
  kill $chain
done
```

The two tests share the chain and the signer, so run them with `--test-threads=1`. Each test ramps the base fee block by block (12.5% per
block, as under EIP-1559 with full blocks) to a multiple of the baseline, holds it for 5 blocks, then decays it the same way. Blocks come
every second instead of every 5 s on Gnosis Chain, so the scenario is time-compressed. The sequencer receives an approval every 2 s
throughout. The moderate test (3x) takes about a minute and the large one (100x) about two and a half minutes (`NONCE_GAP_WINDOW_SECS` sets
the measuring window counted from the start of the ramp, default 60 s and 150 s). Keep the window below the sequencer's 5 minute nonce gap
tolerance: past it, even Blokli 0.14.5 resyncs the cached nonce and the gap closes. `NONCE_GAP_BASELINE_BASE_FEE` (wei, default 100000000)
sets the baseline base fee, which is far above the idle base fee of the real chain. The approvals signed before the ramp are mined in its
first blocks, so only approvals sent during the ramp can strand. The test mines 12 blocks at the baseline first, as Blokli's fee estimate
depends on the last blocks. With a ramp, neither build keeps a hole in the nonces: 0.14.5 hands out about twice the current base fee, which
outpaces a rise of 12.5% per block, while main hands out a coarser estimate (1 Gwei while the base fee climbs from 0.16 to about 1 Gwei,
then 10 Gwei) and in the large test an approval signed with the stale 1 Gwei is evicted by Anvil once the base fee passes it. The gap opens
to about 9 for 20 s until Blokli diagnoses the lost approval and the sequencer re-reads the nonce. The output shows the base fee next to
Blokli's max fee, the peak gap and the final gap.
