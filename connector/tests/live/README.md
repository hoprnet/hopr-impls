This branch carries connector 0.28.0 (hopr-impls commit 840cc20), with the live tests ported to it.

# Live tests against a local Blokli

The tests in `connector/src/connector/sequencer_live_tests.rs` (Anvil) and `sequencer_live_geth_tests.rs` (go-ethereum) drive the
connector's transaction sequencer against a real Blokli on a local chain during a fee spike. They measure how far the sequencer's nonce
stays ahead of the chain (the nonce gap) and whether the gap closes after the congestion is over. They are meant to be run against several
Blokli builds (0.14.5 and main) to compare them, and they are all `#[ignore]`d: they need the setup below and are never run by `cargo test`
alone.

The reference scenario is `redemption_retry_loop`, which exists for Anvil and for geth. It replays the fee profile and the retry behaviour
of the production incident. The other tests are earlier, more synthetic scenarios.

## Prerequisites

Build the two Blokli versions and Foundry with Nix, into one directory (`<dir>`) that holds
`bloklid-<build>/bin/{bloklid,blokli-contract-deployer}`:

```shell
nix build -L 'github:hoprnet/blokli/v0.14.5#bloklid' --out-link <dir>/bloklid-0.14.5
nix build -L --refresh 'github:hoprnet/blokli/main#bloklid' --out-link <dir>/bloklid-main
nix build 'nixpkgs#foundry' --out-link <dir>/foundry
```

`main` moves, so `--refresh` fetches its current head. Note the commit you tested.

Anvil is `<dir>/foundry/bin/anvil`. The geth scenarios need go-ethereum 1.17.x (tested with 1.17.10) in dev mode. The geth derivation is not
pinned by this repository: build or install a 1.17.x release and point `GETH_BIN` at it.

Also needed: `curl`, and `cargo` on the `PATH` (the scripts fall back to `nix develop -c cargo` when it is missing).

## Run one cell

A cell is one Blokli build and one scenario. `run-cell.sh` starts the chain, waits until Blokli answers on GraphQL, runs
`redemption_retry_loop`, writes the output and stops every process it started, also on failure or interruption.

```shell
export BLOKLI_BUILDS_DIR=<dir>
export ANVIL_BIN=<dir>/foundry/bin/anvil
export GETH_BIN=<path to geth>
export OUT_DIR=./live-results   # default
connector/tests/live/run-cell.sh 0.14.5 anvil-redemption
```

The arguments are the Blokli build (`0.14.5` or `main`) and the scenario (`anvil-redemption` or `geth-redemption`). The script fails with a
message if a variable or binary is missing. It writes `$OUT_DIR/<scenario>-<build>.txt`, the same without colour codes as `.clean`, and the
chain logs as `chain-<scenario>-<build>.log`. Anvil cells use ports 18545 and 18080, geth cells 28545 and 28080. Any variable listed under
Parameters is passed through to the chain scripts and the test.

## Run the matrix

`run-matrix.sh` calls `run-cell.sh` for every build and scenario, one at a time, and prints a start and an end line with the time of each
cell. `BUILDS` (default `0.14.5 main`) and `SCENARIOS` (default `anvil-redemption geth-redemption`) restrict it. A full cell takes several
minutes, the matrix of four cells about half an hour.

```shell
connector/tests/live/run-matrix.sh
BUILDS=main SCENARIOS=anvil-redemption connector/tests/live/run-matrix.sh
connector/tests/live/summarize.sh "$OUT_DIR"
```

`summarize.sh` prints the result lines of every cell: the base fee at the start and at the peak, when the relief starts, the peak and final
gap, the time the gap needs to close, the approvals enqueued, the confirmed channels and the errors.

## Run by hand

`chain.sh` starts Anvil, deploys the HOPR contracts and starts a Blokli on top, then runs until interrupted. `chain-geth.sh` does the same
on geth in dev mode (chain id 31337, 15M gas limit, 1 s blocks, accounts #0 and #1 funded, EIP-1559 base fee). Both print the URLs to use
and write their logs to `DATA_DIR`.

```shell
BLOKLID_BIN=<dir>/bloklid-main/bin/bloklid DEPLOYER_BIN=<dir>/bloklid-main/bin/blokli-contract-deployer \
  ANVIL_BIN=<dir>/foundry/bin/anvil DATA_DIR=/tmp/blokli-chain connector/tests/live/chain.sh
```

Use `GETH_BIN` instead of `ANVIL_BIN` and `GETH_PORT` instead of `ANVIL_PORT` for `chain-geth.sh`. `ANVIL_PORT` and `GETH_PORT` default to
18545, `BLOKLI_PORT` to 18080. When Blokli answers on GraphQL (`{chainInfo{... on ChainInfo{chainId}}}`), run the test in another shell:

```shell
BLOKLI_URL=http://127.0.0.1:18080 ANVIL_URL=http://127.0.0.1:18545 BLOKLI_LABEL=main RUST_LOG=hopr_chain_connector=debug \
  cargo test -p hopr-chain-connector --all-features --lib sequencer_live_tests::redemption_retry_loop -- --ignored --nocapture --test-threads=1
```

For geth use `GETH_URL` instead of `ANVIL_URL` and `sequencer_live_geth_tests::redemption_retry_loop`. Drop the test name to run every test
of the module. The tests share the chain and the signer, so always use `--test-threads=1`. `BLOKLI_LABEL` is `0.14.5` or `main`; the older
tests use it to select the expected outcome, any other label only prints the series.

## Parameters

Chain scripts:

| Variable           | Default | Meaning                                                                                                                                                                                                                       |
| ------------------ | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UNMINED_TIMEOUT`  | `15s`   | bloklid's unmined transaction timeout (`BLOKLI_API_TRANSACTIONS_UNMINED_TIMEOUT`), so that an unmined transaction is diagnosed within seconds instead of the default 300 s. Blokli 0.14.5 has no such setting and ignores it. |
| `GENESIS_BASE_FEE` | `15`    | `chain-geth.sh` only: base fee of the genesis block in wei. Geth dev mode floors the idle base fee at 7.                                                                                                                      |
| `GETH_EXTRA_ARGS`  | empty   | `chain-geth.sh` only: extra geth flags, for example `--txpool.globalslots 64 --txpool.globalqueue 64` for a small pool.                                                                                                       |
| `BLOCK_TIME`       | `1`     | `chain-geth.sh` only: seconds between blocks.                                                                                                                                                                                 |

`redemption_retry_loop`, both chains:

| Variable                       | Default     | Meaning                                             |
| ------------------------------ | ----------- | --------------------------------------------------- |
| `REDEMPTION_CHANNELS`          | `12`        | simulated channels, each redeeming one ticket       |
| `REDEMPTION_TICK_SECS`         | `5`         | wait between a failed attempt and the next one      |
| `REDEMPTION_TRACKING_SECS`     | `12`        | tracking timeout of every attempt                   |
| `REDEMPTION_STAGGER_SECS`      | `2`         | delay between the first attempts of two channels    |
| `REDEMPTION_START_BASE_FEE`    | `2000000`   | base fee (wei) at which the channels start          |
| `REDEMPTION_PEAK_BASE_FEE`     | `100000000` | base fee (wei) at which the ramp ends               |
| `REDEMPTION_HOLD_BLOCKS`       | `30`        | blocks held near the peak before the relief         |
| `REDEMPTION_WINDOW_SECS`       | `900`       | total wall time of the observation                  |
| `REDEMPTION_STOP_ON_CLOSE`     | `1`         | stop as soon as the gap has closed after the relief |
| `REDEMPTION_BASELINE_BASE_FEE` | `15`        | Anvil only: base fee (wei) before the ramp          |
| `GETH_MAX_FILL_BLOCKS`         | `400`       | geth only: bound on the blocks of the filling phase |

Earlier tests: `NONCE_GAP_WINDOW_SECS` (default 60 for the moderate test, 150 for the large one) and `NONCE_GAP_BASELINE_BASE_FEE`
(default 100000000) for the Anvil ramp tests, and `GETH_PEAK_BASE_FEE` (default 4000000000), `GETH_MAX_FILL_BLOCKS` (default 260) and
`GETH_RELIEF_SECS` (default 120) for the geth congestion test.

## Production fee profile of the redemption loop

`redemption_retry_loop` replays the base fee of the production incident and the redemption strategy's retry behaviour:

- The base fee starts at 15 wei and rises by 12.5% per block (full blocks under EIP-1559) to about 1e8 wei.
- It is held near the peak for 30 blocks, then decays by halving every 24 blocks until it is below 1e6 wei. On Anvil the test sets the base
  fee directly. On geth a filler transaction fills the blocks during the ramp and the hold and burns part of the block gas during the decay,
  so the base fee follows the same curve on a real execution client.
- 12 channels each enqueue one approval, starting when the base fee passes 2e6 wei and 2 s apart. After every failure a channel waits 5 s
  and enqueues the approval again, as the next strategy tick does.
- Every attempt has a tracking timeout of 12 s. The finality is 3 blocks. Blokli runs with its default parameters, except for the unmined
  timeout of the chain scripts.
- The test samples the gap, Blokli's transaction count of the signer minus the mined count, every second until it has closed after the
  relief and every channel is confirmed, or until the window has passed.

Blocks come every second instead of every 5 s on Gnosis Chain, so the scenario is time-compressed. The test asserts nothing about the
difference between the builds. It prints it.

## Reading the output

Every line starts with `[<BLOKLI_LABEL>]`. The result lines of the redemption loop are:

- `start base fee ... Blokli max fee ...`: the chain and the fee cap Blokli hands out before the spike.
- `channels start`, `peak reached` (geth), `relief starts`: when each phase begins, with the block and the base fee.
- `peak gap`, `final gap`, `approvals enqueued`, `confirmed channels`: the worst gap seen, the gap at the end, the approvals sent including
  retries, and how many channels got a confirmed approval out of the total. Fewer confirmed channels than channels, or a final gap above 0,
  means the sequencer did not recover within the window.
- `base fee at start`, `peak base fee reached`, `Blokli max fee at start`, `distinct transactions seen underpriced in the pool`: the fee
  context.
- `diagnosis reasons`: the reasons Blokli gave for transactions that were not mined, counted.
- `the gap closed at t=...s, ...s after the relief started` or `the gap never closed`: the time to close.
- `errors`: the tally of the errors the attempts failed with.
- `test exit`: the exit code of cargo and the seconds the cell took, added by `run-cell.sh`.

The debug log (`RUST_LOG=hopr_chain_connector=debug`) shows whether the sequencer reused a nonce (`nonce incremented`,
`unknown whether the nonce was consumed`).

## Earlier scenarios

Nonce gap after a fee spike (Anvil, `sequencer_live_tests`, two tests): the base fee is raised above the fee cap Blokli handed out, the
sequencer's approvals go unmined, and the test measures how far its nonce stays ahead of the chain. Each test ramps the base fee by 12.5%
per block to a multiple of the baseline (3x and 100x), holds it for 5 blocks and decays it the same way. The sequencer sends an approval
every 2 s. The moderate test takes about a minute, the large one about two and a half minutes. Keep `NONCE_GAP_WINDOW_SECS` below the
sequencer's 5 minute nonce gap tolerance: past it, even Blokli 0.14.5 resyncs the cached nonce and the gap closes. Anvil evicts a
transaction whose fee cap is below the base fee, so on the large ramp an approval signed with a stale fee cap is lost until Blokli diagnoses
it and the sequencer re-reads the nonce.

Nonce gap under congestion on geth (`sequencer_live_geth_tests`, `nonce_gap_under_congestion`): an account deploys a burner contract and
sends transactions to it with a gas limit of 14.98M, so that a block holds one filler transaction and less than an approval needs. The
filler's tip grows by 10 Mwei per transaction, as Blokli 0.14.5 follows the tips of the last blocks. Every block is full, the base fee rises
by 12.5% per block until `GETH_PEAK_BASE_FEE`, then the filler stops and the base fee decays until the approvals are mined. Unlike Anvil,
geth keeps a transaction whose fee cap is below the base fee pending and mines it once the base fee falls. The scenario takes about 4
minutes. `burst_under_rising_base_fee` runs the same rise with bursts of 5 approvals every 10 s instead of one approval every 2 s. Only two
claims are asserted, for any label: the gap is closed after the relief and every approval is mined.

These scenarios do not reproduce the production profile: the base fee starts at the idle value, the tips are large, and the ramp is slower
and lower than the incident's. Use `redemption_retry_loop` as the reference.
