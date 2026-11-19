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

## Nonce gap under congestion on a real execution client

`chain-geth.sh` is `chain.sh` on go-ethereum in dev mode (tested with 1.17.10): chain id 31337, 15M gas limit, 1 s blocks, accounts #0 and
#1 funded, base fee following EIP-1559. Same environment as `chain.sh` with `GETH_BIN` instead of `ANVIL_BIN`, and `GETH_PORT` instead of
`ANVIL_PORT`. Unlike Anvil, geth keeps a transaction whose fee cap is below the base fee pending and mines it once the base fee falls.

`connector/src/connector/sequencer_live_geth_tests.rs` crowds the sequencer's approvals out with a filler. Account #0 deploys a burner
contract (`JUMPDEST PUSH0 JUMP`) and sends a transaction to it with a gas limit of 14.98M, so that a block holds one filler transaction and
leaves less than an approval needs. The filler's tip starts at 5 Gwei and grows by 10 Mwei per transaction (Blokli 0.14.5 follows the tips
of the last blocks, a constant tip would be matched by its approvals). Every block is full, the base fee rises by 12.5% per block from the
idle 7 wei, and the sequencer sends an approval every 2 s. The phase ends at `GETH_PEAK_BASE_FEE` (default 4 Gwei, about 170 blocks, as
Blokli hands out a max fee of 0.5 to 5 Gwei at an idle base fee); `GETH_MAX_FILL_BLOCKS` (260) bounds it. Then the filler stops and the base
fee decays by 12.5% per empty block until the approvals are mined (`GETH_RELIEF_SECS`, default 120). The scenario takes about 4 minutes,
below the sequencer's 5 minute nonce gap tolerance.

```shell
for build in 0.14.5 main; do
  BLOKLID_BIN=<dir>/bloklid-$build/bin/bloklid DEPLOYER_BIN=<dir>/bloklid-$build/bin/blokli-contract-deployer \
    GETH_BIN=<geth> DATA_DIR=/tmp/blokli-geth-$build connector/tests/live/chain-geth.sh &
  chain=$!
  until curl -sf -X POST http://127.0.0.1:18080/graphql -H 'content-type: application/json' \
    --data '{"query":"{chainInfo{... on ChainInfo{chainId}}}"}' | grep -q chainId; do sleep 2; done
  BLOKLI_URL=http://127.0.0.1:18080 GETH_URL=http://127.0.0.1:18545 BLOKLI_LABEL=$build RUST_LOG=hopr_chain_connector=debug \
    cargo test -p hopr-chain-connector --all-features --lib sequencer_live_geth_tests -- --ignored --nocapture --test-threads=1
  kill $chain
done
```

The output has a row every 5 s (block number, base fee, Blokli's max fee, gas used, mined approvals, approvals in the pool, how many of them
cannot pay the base fee, nonce gap), the diagnoses Blokli reported on timeouts, the stuck approvals when the filler stops, the peak gap and
the time the gap needs to close. Only two qualitative claims are asserted, for any `BLOKLI_LABEL`: the gap is closed after relief and every
approval is mined. The difference between the builds is printed, not asserted. The debug log shows whether the sequencer reused a nonce
(`nonce incremented`, `unknown whether the nonce was consumed`).

Observed on geth 1.17.10 (two runs per build, same outcome): approvals are crowded out from the first congested block and wait in the pool,
Blokli accepts them, and geth mines them all after the filler stops. Main hands out 0.5 Gwei at an idle base fee, 1 Gwei from about 0.4 Gwei
of base fee and 10 Gwei from about 2 Gwei. 0.14.5 hands out about 5 Gwei plus twice the base fee, the 5 Gwei being the tip it copies from
the recent blocks. Main diagnoses the stuck approvals (`Queued`, then `Underpriced` once the base fee passes the cap), 0.14.5 gives none.
0.14.5 stops accepting approvals once 64 are tracked (`SUBMISSION_CAPACITY_EXCEEDED`, which is not a nonce error: the sequencer keeps its
nonce), main accepted 93. After the filler stops, the gap closes in about 5 s on 0.14.5 and about 23 s on main, because the approvals signed
early on main carry a cap of 0.5 Gwei and wait for the base fee to fall below it. At this ramp (about 3 minutes) neither build produces an
approval that geth cannot mine again once the base fee has fallen, so no build difference is asserted.
