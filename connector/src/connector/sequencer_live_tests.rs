//! Measures how far the sequencer's nonce runs ahead of the chain after a gas fee spike, against a real Blokli
//! and Anvil.
//!
//! The scenario, for a spike of `factor` times the baseline base fee:
//!
//! 1. Anvil stops mining. The sequencer signs and submits a few approvals, which wait in Anvil's pool.
//! 2. The base fee ramps up as under EIP-1559 on a chain with full blocks: each block is mined with a base fee 12.5%
//!    above the previous one, until `factor` times the baseline is reached, driven by `anvil_setNextBlockBaseFeePerGas`
//!    and `anvil_mine`. The first blocks may still mine the approvals, until the base fee passes their fee cap. The
//!    sequencer keeps receiving approvals during the whole scenario, so its fee refresh runs against the rising fee.
//! 3. After a few blocks at the peak, the approvals Anvil still lists although they cannot pay the base fee are
//!    dropped, which emulates an RPC node that forgot them. Approvals that can pay it are kept, they only wait for the
//!    next block. Anvil usually evicts the underpriced ones on its own, so this is often a no-op. A real node would
//!    keep them pending.
//! 4. The base fee decays by 12.5% per block back to the baseline and Anvil keeps mining.
//!
//! Blocks come every second instead of every 5 s on Gnosis Chain, so the scenario is time-compressed. The baseline
//! is `NONCE_GAP_BASELINE_BASE_FEE` wei, 100 Mwei by default.
//!
//! The gap is the nonce the sequencer signs next minus the account's mined transaction count. It is read from
//! Anvil's pool, as the sequencer's nonce cache is private. An approval that waits for the next block counts as a gap
//! of one for a moment, so the series keeps the smallest gap within each second and the final gap is the smallest over
//! the last three seconds. The series is printed, and only the qualitative claim of `BLOKLI_LABEL` is asserted.
//!
//! These tests are ignored by default. `tests/live/chain.sh` starts a matching Anvil and Blokli, see
//! `tests/live/README.md`. Run them one at a time, as they share the chain:
//!
//! ```shell
//! BLOKLI_URL=http://127.0.0.1:18080 ANVIL_URL=http://127.0.0.1:18545 BLOKLI_LABEL=main \
//!   cargo test -p hopr-chain-connector --lib sequencer_live_tests -- --ignored --nocapture --test-threads=1
//! ```

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use blokli_client::{BlokliClient, BlokliClientConfig, api::BlokliQueryClient, exports::Url};
use futures::{StreamExt, stream::FuturesUnordered};
use hopr_api::types::{
    chain::prelude::{BasicPayloadGenerator, GasEstimation},
    crypto::prelude::*,
    primitive::prelude::*,
};
use serde_json::json;

use super::live_support::{
    ANVIL_ACCOUNT_1_KEY, Enqueuer, Outcome, RetryConfig, RetryState, Rpc, Seq, run_channels, sample_gap,
    wait_for_chain_info,
};
use crate::{connector::sequencer::TransactionSequencer, utils::model_to_chain_info};

/// Default base fee the scenario starts from, in wei. `NONCE_GAP_BASELINE_BASE_FEE` overrides it.
const DEFAULT_BASELINE_BASE_FEE: u128 = 100_000_000;
/// Blocks the base fee stays at its peak, as it does on a chain whose blocks stay full.
const HOLD_BLOCKS: usize = 5;
/// Blocks mined at the baseline base fee before the scenario starts.
const SETTLE_BLOCKS: usize = 12;
/// Time between two blocks of the ramp. The real chain mines every 5 s and takes about 2 minutes to ramp up; the test
/// is time-compressed to 1 s per block, with the same 12.5% change per block.
const BLOCK_INTERVAL: Duration = Duration::from_secs(1);
/// Approvals sent before the spike.
const BEFORE_SPIKE: usize = 3;
/// Spacing of the approvals sent after the spike.
const SEND_INTERVAL: Duration = Duration::from_secs(2);

/// Base fees of the blocks to mine: up by 12.5% per block until `peak`, held for `HOLD_BLOCKS`, then down by 12.5% per
/// block until `baseline`. Returns the fees, the index of the first decay block and the number of ramp blocks.
fn ramp_schedule(baseline: u128, peak: u128) -> (Vec<u128>, usize, usize) {
    let mut fees = Vec::new();
    let mut fee = baseline;
    while fee < peak {
        fee = (fee * 1125 / 1000).min(peak);
        fees.push(fee);
    }
    let ramp_blocks = fees.len();
    fees.extend(std::iter::repeat_n(peak, HOLD_BLOCKS));
    let drop_after = fees.len();
    while fee > baseline {
        fee = (fee * 1000 / 1125).max(baseline);
        fees.push(fee);
    }
    (fees, drop_after, ramp_blocks)
}

impl Rpc {
    async fn set_next_base_fee(&self, fee: u128) -> anyhow::Result<()> {
        self.call("anvil_setNextBlockBaseFeePerGas", json!([format!("{fee:#x}")]))
            .await
            .map(drop)
    }

    async fn mine(&self) -> anyhow::Result<()> {
        self.call("anvil_mine", json!(["0x1"])).await.map(drop)
    }

    async fn stop_mining(&self) -> anyhow::Result<()> {
        self.call("anvil_setIntervalMining", json!([0])).await?;
        self.call("anvil_setAutomine", json!([false])).await.map(drop)
    }

    async fn mine_every_second(&self) -> anyhow::Result<()> {
        self.call("anvil_setIntervalMining", json!([1])).await.map(drop)
    }
}

async fn run_scenario(spike_factor: u128, default_window_secs: u64) -> anyhow::Result<()> {
    let blokli_url: Url = std::env::var("BLOKLI_URL")?.parse()?;
    let label = std::env::var("BLOKLI_LABEL").unwrap_or_else(|_| "unlabeled".into());
    let window = Duration::from_secs(
        std::env::var("NONCE_GAP_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_window_secs),
    );
    let anvil = Rpc::new(std::env::var("ANVIL_URL")?);

    let signer = ChainKeypair::from_secret(&ANVIL_ACCOUNT_1_KEY)?;
    let account = signer.public().to_address().to_string();
    let client = Arc::new(BlokliClient::new(blokli_url, BlokliClientConfig::default()));

    // Settle at the baseline base fee and let Blokli's estimate follow it.
    anvil.stop_mining().await?;
    // Leftovers of an earlier scenario on the same account would otherwise fill the nonce gap.
    anvil.call("anvil_dropAllTransactions", json!([])).await?;
    let baseline = std::env::var("NONCE_GAP_BASELINE_BASE_FEE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BASELINE_BASE_FEE);
    // Fee estimates are derived from the last blocks, so a whole window at the baseline makes them reproducible.
    for _ in 0..SETTLE_BLOCKS {
        anvil.set_next_base_fee(baseline).await?;
        anvil.mine().await?;
        // One block per second, as Blokli's indexer reports itself as not ready when it lags behind by too many blocks.
        tokio::time::sleep(BLOCK_INTERVAL).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let base_fee = anvil.base_fee().await?;

    let chain_info = wait_for_chain_info(&client, &label).await?;
    let gas = GasEstimation::from(chain_info.clone());
    let spike_fee = base_fee * spike_factor;
    let payloads = BasicPayloadGenerator::new(signer.public().to_address(), chain_info.info.contract_addresses);
    println!(
        "[{label}] base fee {base_fee} wei, Blokli max fee {} wei ({:.1}x), spike {spike_factor}x = {spike_fee} wei \
         ({})",
        gas.max_fee_per_gas,
        gas.max_fee_per_gas as f64 / base_fee as f64,
        if spike_fee > gas.max_fee_per_gas {
            "above the max fee"
        } else {
            "within the max fee"
        }
    );

    let spender = Address::try_from(chain_info.info.contract_addresses.channels.as_slice())?;
    let sequencer: Seq = TransactionSequencer::new(signer.clone(), client.clone());
    let started = Instant::now();
    let ctx = Enqueuer {
        sequencer: &sequencer,
        payloads: &payloads,
        spender,
        started,
    };
    let mut outcomes: FuturesUnordered<Outcome<'_>> = FuturesUnordered::new();
    let mut sent = 0usize;

    // 1. approvals waiting in the pool
    let first_nonce = anvil.nonce(&account).await?;
    for _ in 0..BEFORE_SPIKE {
        sent += 1;
        ctx.enqueue(sent, &outcomes).await?;
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while anvil.pooled(&account).await?.len() < BEFORE_SPIKE {
        anyhow::ensure!(Instant::now() < deadline, "approvals did not reach Anvil's pool");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // 2. the ramp, then the decay. The schedule holds the base fee of every block to mine, one per `BLOCK_INTERVAL`.
    let (mut schedule, drop_after, ramp_blocks) = ramp_schedule(base_fee, spike_fee);
    println!(
        "[{label}] ramp of {ramp_blocks} blocks to {spike_fee} wei, held {HOLD_BLOCKS} blocks, {} blocks in total",
        schedule.len()
    );
    let mut blocks_mined = 0usize;
    let mut mined_before_drop: Option<u64> = None;
    let mut mined_of_initial: Option<u64> = None;
    let mut stranded_at_drop = 0usize;
    let mut nonce_at_drop: Option<u64> = None;
    let mut fee_series: Vec<(u64, u128, u128)> = Vec::new();

    let ramp_start = Instant::now();
    let mut highest_signed_next = first_nonce;
    let mut series: Vec<(u64, u64, u64)> = Vec::new();
    let mut last_second = u64::MAX;
    let mut second_min_gap = u64::MAX;
    let mut second_mined = 0u64;
    let mut first_mined_at: Option<u64> = None;
    let mut next_send = Instant::now();
    let mut next_block = Instant::now();
    let mut ramp_done = false;
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    while ramp_start.elapsed() < window {
        tokio::select! {
            _ = ticker.tick() => {
                if Instant::now() >= next_send {
                    sent += 1;
                    ctx.enqueue(sent, &outcomes).await?;
                    next_send += SEND_INTERVAL;
                }
                if !ramp_done && Instant::now() >= next_block {
                    next_block += BLOCK_INTERVAL;
                    if blocks_mined == drop_after {
                        // 3. the RPC node forgets the transactions it still lists
                        let nonce = anvil.nonce(&account).await?;
                        let stranded = anvil.pooled(&account).await?;
                        let base_fee_now = anvil.base_fee().await?;
                        // Only approvals that cannot pay the base fee: those are what a node that prunes its pool
                        // forgets. An approval merely waiting for the next block is kept.
                        let mut dropped = 0;
                        for (nonce, hash) in &stranded {
                            let tx = anvil.call("eth_getTransactionByHash", json!([hash])).await?;
                            let max_fee = tx["maxFeePerGas"]
                                .as_str()
                                .and_then(|v| u128::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                                .unwrap_or(0);
                            println!("[{label}] pooled nonce {nonce}, max fee {max_fee}, base fee {base_fee_now}");
                            if max_fee < base_fee_now {
                                anvil.call("anvil_dropTransaction", json!([hash])).await?;
                                dropped += 1;
                            }
                        }
                        stranded_at_drop = dropped;
                        mined_before_drop = Some(nonce - first_nonce);
                        mined_of_initial = Some((nonce - first_nonce).min(BEFORE_SPIKE as u64));
                        nonce_at_drop = Some(nonce);
                    }
                    if schedule.is_empty() {
                        // 4. base fee back at the baseline, regular mining resumes
                        anvil.set_next_base_fee(base_fee).await?;
                        anvil.mine_every_second().await?;
                        ramp_done = true;
                    } else {
                        let fee = schedule.remove(0);
                        anvil.set_next_base_fee(fee).await?;
                        anvil.mine().await?;
                        blocks_mined += 1;
                        let estimate = GasEstimation::from(model_to_chain_info(client.query_chain_info().await?)?).max_fee_per_gas;
                        fee_series.push((ramp_start.elapsed().as_secs(), anvil.base_fee().await?, estimate));
                    }
                }
                let latest = anvil.nonce(&account).await?;
                if nonce_at_drop.is_some_and(|at_drop| latest > at_drop) && first_mined_at.is_none() {
                    first_mined_at = Some(ramp_start.elapsed().as_secs());
                }
                for (nonce, _) in anvil.pooled(&account).await? {
                    highest_signed_next = highest_signed_next.max(nonce + 1);
                }
                let signed_next = highest_signed_next.max(latest);
                let second = ramp_start.elapsed().as_secs();
                if second != last_second {
                    if last_second != u64::MAX {
                        series.push((last_second, second_mined, second_min_gap));
                    }
                    last_second = second;
                    second_min_gap = u64::MAX;
                }
                // The smallest gap seen during the second: an approval that waits for the next block only shows up
                // briefly, a hole in the nonces stays.
                second_min_gap = second_min_gap.min(signed_next - latest);
                second_mined = latest - first_nonce;
            }
            Some((index, at, result)) = outcomes.next() => {
                println!("[{label}] t={:.1}s approval #{index}: {result}", at.as_secs_f64());
            }
        }
    }

    println!(
        "[{label}] base fee / Blokli max fee, seconds since the ramp start: {}",
        fee_series
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 3 == 0 || *i + 1 == fee_series.len())
            .map(|(_, (second, fee, cap))| format!("t={second}s {fee}/{cap}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "[{label}] before the drop: {} of {BEFORE_SPIKE} pre-signed approvals mined, {} mined in total, \
         {stranded_at_drop} dropped from the pool",
        mined_of_initial.unwrap_or(0),
        mined_before_drop.unwrap_or(0)
    );
    println!(
        "[{label}] spike {spike_factor}x, seconds since the ramp start: mined since the ramp start / smallest nonce \
         gap within the second"
    );
    for (second, mined, gap) in &series {
        // Every fifth second, to keep the output short.
        if second % 5 != 0 {
            continue;
        }
        println!("[{label}]   t={second:>2}s mined={mined:>2} gap={gap}");
    }
    // Over the last three seconds, so that an approval waiting for the next block is not mistaken for a hole.
    let final_gap = series.iter().rev().take(3).map(|(_, _, gap)| *gap).min().unwrap_or(0);
    let peak_gap = series.iter().map(|(_, _, gap)| *gap).max().unwrap_or(0);
    println!("[{label}] peak gap: {peak_gap}, final gap: {final_gap}");
    match first_mined_at {
        Some(second) => println!("[{label}] first approval mined after the drop at t={second}s (ramp start based)"),
        None => println!("[{label}] no approval was mined after the drop"),
    }

    // With a gradual ramp neither build is expected to keep a hole in the nonces: 0.14.5 hands out about twice the
    // current base fee, which outpaces a rise of 12.5% per block, and main closes the hole its coarser fee estimate may
    // open once Blokli diagnoses the lost transaction. The peak gap tells the two apart.
    match label.as_str() {
        "0.14.5" | "main" => assert_eq!(
            final_gap, 0,
            "the gap is expected to be closed at the end of the window"
        ),
        _ => println!("[{label}] no expectation for this label, series printed only"),
    }
    Ok(())
}

#[test_log::test(tokio::test)]
#[ignore = "requires a running Blokli and Anvil"]
async fn nonce_gap_after_a_moderate_fee_spike() -> anyhow::Result<()> {
    run_scenario(3, 60).await
}

#[test_log::test(tokio::test)]
#[ignore = "requires a running Blokli and Anvil"]
async fn nonce_gap_after_a_large_fee_spike() -> anyhow::Result<()> {
    run_scenario(100, 150).await
}

/// Base fees of the blocks of the production-like profile: up by 12.5% per block from `baseline` to `peak`, `hold`
/// blocks at the peak, then a decay that halves the fee every 24 blocks until it is below `floor`. Returns the fees,
/// the index of the first block of the hold phase's end (the relief) and the number of ramp blocks.
fn incident_schedule(baseline: u128, peak: u128, hold: u64, floor: u128) -> (Vec<u128>, usize, usize) {
    let mut fees = Vec::new();
    let mut fee = baseline;
    while fee < peak {
        fee = (fee * 1125 / 1000 + 1).min(peak);
        fees.push(fee);
    }
    let ramp_blocks = fees.len();
    fees.extend(std::iter::repeat_n(peak, hold as usize));
    let relief = fees.len();
    while fee > floor {
        // 0.5^(1/24)
        fee = fee * 97153 / 100_000;
        fees.push(fee);
    }
    (fees, relief, ramp_blocks)
}

/// Models the redemption strategy under a fee spike like the production incident: the base fee starts at
/// `REDEMPTION_BASELINE_BASE_FEE` (15 wei), ramps up by 12.5% per block to `REDEMPTION_PEAK_BASE_FEE` (100 Mwei), is
/// held for `REDEMPTION_HOLD_BLOCKS` (30) blocks, then halves every 24 blocks until it is below 1 Mwei, after which
/// Anvil mines on its own. `REDEMPTION_CHANNELS` channels (12 by default) each enqueue one approval, from the moment
/// the base fee passes `REDEMPTION_START_BASE_FEE` (2 Mwei), `REDEMPTION_STAGGER_SECS` (2) apart, and enqueue it again
/// `REDEMPTION_TICK_SECS` (5) after every failure, with a tracking timeout of `REDEMPTION_TRACKING_SECS` (12). The gap,
/// Blokli's transaction count of the signer minus the mined count, is sampled every second until it has closed after
/// the relief and every channel is confirmed, or `REDEMPTION_WINDOW_SECS` (900) have passed.
async fn run_redemption_loop() -> anyhow::Result<()> {
    let blokli_url: Url = std::env::var("BLOKLI_URL")?.parse()?;
    let label = std::env::var("BLOKLI_LABEL").unwrap_or_else(|_| "unlabeled".into());
    let config = RetryConfig::from_env(900, true);
    let anvil = Rpc::new(std::env::var("ANVIL_URL")?);
    let signer = ChainKeypair::from_secret(&ANVIL_ACCOUNT_1_KEY)?;
    let client = Arc::new(BlokliClient::new(blokli_url, BlokliClientConfig::default()));

    anvil.stop_mining().await?;
    anvil.call("anvil_dropAllTransactions", json!([])).await?;
    let baseline: u128 = std::env::var("REDEMPTION_BASELINE_BASE_FEE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);
    for _ in 0..SETTLE_BLOCKS {
        anvil.set_next_base_fee(baseline).await?;
        anvil.mine().await?;
        tokio::time::sleep(BLOCK_INTERVAL).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let base_fee = anvil.base_fee().await?;
    let chain_info = wait_for_chain_info(&client, &label).await?;
    println!(
        "[{label}] start base fee {base_fee} wei, Blokli max fee {}",
        super::live_support::blokli_fee_cap(&client)
            .await
            .map_or_else(|| "n/a".into(), |fee| fee.to_string())
    );
    let payloads = BasicPayloadGenerator::new(signer.public().to_address(), chain_info.info.contract_addresses);
    let spender = Address::try_from(chain_info.info.contract_addresses.channels.as_slice())?;
    let sequencer: Seq = TransactionSequencer::new(signer.clone(), client.clone());
    let state = RetryState::new();
    let ctx = Enqueuer {
        sequencer: &sequencer,
        payloads: &payloads,
        spender,
        started: state.started,
    };
    let (schedule, relief, ramp_blocks) =
        incident_schedule(base_fee, config.peak_base_fee, config.hold_blocks, 1_000_000);
    println!(
        "[{label}] base fee {base_fee} wei, ramp of {ramp_blocks} blocks to {} wei, hold {} blocks, {} blocks in total",
        config.peak_base_fee,
        config.hold_blocks,
        schedule.len()
    );

    let drive = async {
        for (blocks_mined, fee) in schedule.iter().enumerate() {
            if state.stopped() {
                return anyhow::Ok(());
            }
            if blocks_mined == relief {
                state.start_relief();
                println!(
                    "[{label}] relief starts at t={}s, block {blocks_mined}",
                    state.started.elapsed().as_secs()
                );
            }
            if *fee >= config.start_base_fee && !state.go.load(std::sync::atomic::Ordering::SeqCst) {
                println!(
                    "[{label}] channels start at t={}s, block {blocks_mined}, base fee {fee}",
                    state.started.elapsed().as_secs()
                );
                state.begin();
            }
            anvil.set_next_base_fee(*fee).await?;
            anvil.mine().await?;
            state.observe_base_fee(*fee);
            tokio::time::sleep(BLOCK_INTERVAL).await;
        }
        anvil.mine_every_second().await?;
        Ok(())
    };
    let (_, report, driven) = tokio::join!(
        run_channels(&ctx, &state, &config),
        sample_gap(&client, &anvil, signer.public().to_address(), &config, &state, &label),
        drive
    );
    driven?;
    let report = report?;
    report.print(&label, &config, &state);
    Ok(())
}

#[test_log::test(tokio::test)]
#[ignore = "requires a running Blokli and Anvil"]
async fn redemption_retry_loop() -> anyhow::Result<()> {
    run_redemption_loop().await
}
