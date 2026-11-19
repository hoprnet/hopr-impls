//! Measures the sequencer's nonce gap under congestion against a real Blokli on a real execution client (geth in dev
//! mode), whose transaction pool keeps a transaction that cannot pay the base fee pending and mines it once the base
//! fee falls. Anvil evicts such transactions and cannot crowd transactions out, see `sequencer_live_tests`.
//!
//! The scenario, with account #0 as the filler and account #1 as the sequencer's signer:
//!
//! 1. Settle: the base fee sits at the floor of the chain (a few wei), the sequencer sends approvals that mine.
//! 2. Congestion: the filler sends transactions to a burner contract with a gas limit that leaves less than an approval
//!    needs in a block, and a tip far above the approvals' tip. Every block holds one filler transaction and no
//!    approval, so the base fee rises by 12.5% per block. The sequencer keeps sending an approval every 2 s; they wait
//!    in the pool, and fall below the base fee once it passes their fee cap. The phase ends when the base fee reaches
//!    `GETH_PEAK_BASE_FEE` (4 Gwei by default, above the max fee Blokli hands out at an idle base fee: 1 Gwei on
//!    0.14.5, 0.5 Gwei on main).
//! 3. Relief: the filler stops, the base fee decays by 12.5% per empty block, the approvals mine again.
//!
//! The nonce gap is the highest nonce the sequencer signed plus one minus the account's mined transaction count,
//! read from geth's pool. Only qualitative claims are asserted: after relief the gap is closed and every approval
//! Blokli accepted is mined. The base fee path, Blokli's max fee, the stuck approvals at the peak, the time the gap
//! needs to close and the diagnoses Blokli reports on timeouts are printed.
//!
//! These tests are ignored by default. `tests/live/chain-geth.sh` starts a matching geth and Blokli, see
//! `tests/live/README.md`:
//!
//! ```shell
//! BLOKLI_URL=http://127.0.0.1:18080 GETH_URL=http://127.0.0.1:18545 BLOKLI_LABEL=main \
//!   cargo test -p hopr-chain-connector --lib sequencer_live_geth_tests -- --ignored --nocapture --test-threads=1
//! ```

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use blokli_client::{BlokliClient, BlokliClientConfig, api::BlokliQueryClient, exports::Url};
use futures::{StreamExt, stream::FuturesUnordered};
use hopr_api::types::{
    chain::{
        exports::alloy::primitives::TxKind,
        prelude::{BasicPayloadGenerator, GasEstimation, SignableTransaction, TransactionRequest},
    },
    crypto::prelude::*,
    primitive::prelude::*,
};
use serde_json::{Value, json};

use super::live_support::{ANVIL_ACCOUNT_1_KEY, Enqueuer, Outcome, Rpc, Seq, parse_quantity, wait_for_chain_info};
use crate::{connector::sequencer::TransactionSequencer, utils::model_to_chain_info};

/// Secret key of the well-known, public Anvil development account #0 (the filler). It holds no real funds.
const ANVIL_ACCOUNT_0_KEY: [u8; 32] =
    hex_literal::hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
/// Burner contract: `JUMPDEST PUSH0 JUMP`, loops until the gas is exhausted.
const BURNER_INITCODE: [u8; 12] = hex_literal::hex!("60038060095f395ff35b5f56");
/// Block gas limit of `chain-geth.sh`.
const BLOCK_GAS_LIMIT: u64 = 15_000_000;
/// Gas limit of a filler transaction. The 20 000 gas left in a block are less than an approval needs.
const FILLER_GAS_LIMIT: u64 = 14_980_000;
/// The filler's tip starts far above the approvals' tip and grows with every filler transaction. Blokli 0.14.5 follows
/// the tips of the last blocks, so a constant filler tip would be matched by the approvals, which would then mine
/// next to the filler's transactions in the order of arrival instead of being crowded out.
const FILLER_MAX_FEE: u128 = 20_000_000_000;
const FILLER_TIP: u128 = 5_000_000_000;
const FILLER_TIP_STEP: u128 = 10_000_000;
/// Filler transactions kept in the pool ahead of the chain.
const FILLER_AHEAD: u64 = 3;
const DEFAULT_PEAK_BASE_FEE: u128 = 4_000_000_000;
/// Safety bound on the congestion phase, in blocks.
const DEFAULT_MAX_FILL_BLOCKS: u64 = 260;
/// Safety bound on the relief phase.
const DEFAULT_RELIEF_SECS: u64 = 120;
/// Approvals sent and mined before the congestion.
const SETTLE_APPROVALS: usize = 3;
const SEND_INTERVAL: Duration = Duration::from_secs(2);
/// The sequencer's nonce gap tolerance, as in the default connector configuration.
const NONCE_GAP_TOLERANCE: Duration = Duration::from_mins(5);

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Sends the filler's transactions from account #0.
struct Filler<'a> {
    rpc: &'a Rpc,
    keypair: ChainKeypair,
    chain_id: u64,
    address: String,
    burner: [u8; 20],
    next_nonce: u64,
    /// Nonce of the first filler transaction, which sets its tip.
    first_nonce: u64,
}

impl Filler<'_> {
    /// Sends the signed transaction and returns its hash.
    async fn send_raw(&self, tx: TransactionRequest, nonce: u64, gas: GasEstimation) -> anyhow::Result<Value> {
        let raw = tx
            .sign_and_encode_to_eip2718(nonce, self.chain_id, Some(gas), &self.keypair)
            .await?;
        self.rpc
            .call("eth_sendRawTransaction", json!([const_hex::encode_prefixed(&raw)]))
            .await
    }

    /// Deploys the burner contract and returns its address.
    async fn deploy_burner(rpc: &Rpc, chain_id: u64) -> anyhow::Result<Filler<'_>> {
        let keypair = ChainKeypair::from_secret(&ANVIL_ACCOUNT_0_KEY)?;
        let address = keypair.public().to_address().to_string();
        let nonce = rpc
            .quantity("eth_getTransactionCount", json!([address, "pending"]))
            .await? as u64;
        let mut filler = Filler {
            rpc,
            keypair,
            chain_id,
            address,
            burner: [0; 20],
            next_nonce: nonce + 1,
            first_nonce: nonce + 1,
        };
        let deploy = TransactionRequest {
            to: Some(TxKind::Create),
            input: BURNER_INITCODE.to_vec().into(),
            ..Default::default()
        };
        let gas = GasEstimation {
            gas_limit: 200_000,
            max_fee_per_gas: FILLER_MAX_FEE,
            max_priority_fee_per_gas: FILLER_TIP,
        };
        let hash = filler.send_raw(deploy, nonce, gas).await?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let contract = loop {
            let receipt = rpc.call("eth_getTransactionReceipt", json!([hash])).await?;
            if let Some(address) = receipt["contractAddress"].as_str() {
                break address.to_owned();
            }
            anyhow::ensure!(Instant::now() < deadline, "burner deployment was not mined");
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        filler.burner = const_hex::decode(contract)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("burner address has the wrong length"))?;
        Ok(filler)
    }

    /// Keeps `FILLER_AHEAD` filler transactions ahead of the chain.
    async fn top_up(&mut self) -> anyhow::Result<()> {
        let mined = self.rpc.nonce(&self.address).await?;
        while self.next_nonce < mined + FILLER_AHEAD {
            let tx = TransactionRequest {
                to: Some(TxKind::Call(self.burner.into())),
                ..Default::default()
            };
            let gas = GasEstimation {
                gas_limit: FILLER_GAS_LIMIT,
                max_fee_per_gas: FILLER_MAX_FEE,
                max_priority_fee_per_gas: FILLER_TIP + (self.next_nonce - self.first_nonce) as u128 * FILLER_TIP_STEP,
            };
            self.send_raw(tx, self.next_nonce, gas).await?;
            self.next_nonce += 1;
        }
        Ok(())
    }
}

/// The latest block: number, base fee and gas used.
async fn latest_block(rpc: &Rpc) -> anyhow::Result<(u64, u128, u64)> {
    let block = rpc.call("eth_getBlockByNumber", json!(["latest", false])).await?;
    Ok((
        parse_quantity(&block["number"]).unwrap_or(0) as u64,
        parse_quantity(&block["baseFeePerGas"]).unwrap_or(0),
        parse_quantity(&block["gasUsed"]).unwrap_or(0) as u64,
    ))
}

async fn blokli_max_fee(client: &BlokliClient) -> Option<u128> {
    let info = model_to_chain_info(client.query_chain_info().await.ok()?).ok()?;
    Some(GasEstimation::from(info).max_fee_per_gas)
}

fn show(value: Option<u128>) -> String {
    value.map_or_else(|| "n/a".into(), |v| v.to_string())
}

async fn run_scenario() -> anyhow::Result<()> {
    let blokli_url: Url = std::env::var("BLOKLI_URL")?.parse()?;
    let label = std::env::var("BLOKLI_LABEL").unwrap_or_else(|_| "unlabeled".into());
    let peak_base_fee: u128 = env_or("GETH_PEAK_BASE_FEE", DEFAULT_PEAK_BASE_FEE);
    anyhow::ensure!(
        peak_base_fee < FILLER_MAX_FEE,
        "the peak must stay below the filler's max fee"
    );
    let max_fill_blocks: u64 = env_or("GETH_MAX_FILL_BLOCKS", DEFAULT_MAX_FILL_BLOCKS);
    let relief_window = Duration::from_secs(env_or("GETH_RELIEF_SECS", DEFAULT_RELIEF_SECS));
    let rpc = Rpc::new(std::env::var("GETH_URL")?);

    let signer = ChainKeypair::from_secret(&ANVIL_ACCOUNT_1_KEY)?;
    let account = signer.public().to_address().to_string();
    let client = Arc::new(BlokliClient::new(blokli_url, BlokliClientConfig::default()));
    let chain_id = rpc.quantity("eth_chainId", json!([])).await? as u64;
    let mut filler = Filler::deploy_burner(&rpc, chain_id).await?;
    println!("[{label}] burner at {}", const_hex::encode_prefixed(filler.burner));

    let chain_info = wait_for_chain_info(&client, &label).await?;
    let payloads = BasicPayloadGenerator::new(signer.public().to_address(), chain_info.info.contract_addresses);
    let spender = Address::try_from(chain_info.info.contract_addresses.channels.as_slice())?;
    let sequencer: Seq = TransactionSequencer::new(signer.clone(), client.clone(), NONCE_GAP_TOLERANCE);
    let started = Instant::now();
    let ctx = Enqueuer {
        sequencer: &sequencer,
        payloads: &payloads,
        spender,
        started,
    };
    let mut outcomes: FuturesUnordered<Outcome<'_>> = FuturesUnordered::new();
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    // Approvals Blokli refused (for example when its submission capacity is exhausted) never got a nonce.
    let refused = std::cell::Cell::new(0usize);
    let mut record = |index: usize, at: Duration, result: String| {
        println!("[{label}] t={:.1}s approval #{index}: {result}", at.as_secs_f64());
        if result.starts_with("remote blokli error") {
            refused.set(refused.get() + 1);
        }
        let (error, diagnosis) = result.split_once("; diagnosis ").unwrap_or(("confirmed", ""));
        let error: String = error.chars().take(70).collect();
        *tally
            .entry(format!("{error} {diagnosis}").trim().to_owned())
            .or_default() += 1;
    };

    // 1. settle: approvals mine at the floor base fee
    let (_, idle_base_fee, _) = latest_block(&rpc).await?;
    println!(
        "[{label}] idle base fee {idle_base_fee} wei, Blokli max fee {}",
        show(blokli_max_fee(&client).await)
    );
    let first_nonce = rpc.nonce(&account).await?;
    let mut sent = 0usize;
    for _ in 0..SETTLE_APPROVALS {
        sent += 1;
        ctx.enqueue(sent, &outcomes).await?;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while rpc.nonce(&account).await? < first_nonce + SETTLE_APPROVALS as u64 {
        anyhow::ensure!(Instant::now() < deadline, "the settle approvals were not mined");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 2. congestion, then 3. relief
    println!(
        "[{label}] seconds since the congestion start: block base fee / Blokli max fee / gas used, mined approvals, \
         pooled approvals (stuck: max fee below the base fee), gap"
    );
    let phase_start = Instant::now();
    let mut relief_start: Option<Instant> = None;
    let mut closed_after: Option<Duration> = None;
    let mut highest_signed_next = first_nonce + SETTLE_APPROVALS as u64;
    let mut max_stuck = 0usize;
    let mut peak_stuck = (0usize, 0u128, 0usize);
    let mut peak_seen = false;
    let mut peak_gap = 0u64;
    let mut peak_base_seen = 0u128;
    let mut last_second = u64::MAX;
    let mut second_min_gap = u64::MAX;
    let mut first_block: Option<u64> = None;
    let mut blocks_full = 0u64;
    let mut next_send = Instant::now();
    let mut next_row = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    let mut final_mined: u64;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let (block, base_fee, gas_used) = latest_block(&rpc).await?;
                let first = *first_block.get_or_insert(block);
                if gas_used > BLOCK_GAS_LIMIT - 100_000 && relief_start.is_none() && block > first {
                    blocks_full = blocks_full.max(block - first);
                }
                peak_base_seen = peak_base_seen.max(base_fee);
                if relief_start.is_none() {
                    if base_fee >= peak_base_fee || block - first >= max_fill_blocks {
                        relief_start = Some(Instant::now());
                        println!("[{label}] relief starts at t={}s, block {}, base fee {base_fee}", phase_start.elapsed().as_secs(), block - first);
                    } else {
                        filler.top_up().await?;
                        if Instant::now() >= next_send {
                            sent += 1;
                            ctx.enqueue(sent, &outcomes).await?;
                            next_send += SEND_INTERVAL;
                        }
                    }
                }

                let latest = rpc.nonce(&account).await?;
                let pooled = rpc.pool_entries(&account).await?;
                for tx in &pooled {
                    highest_signed_next = highest_signed_next.max(tx.nonce + 1);
                }
                let stuck = pooled.iter().filter(|tx| tx.max_fee < base_fee).count();
                max_stuck = max_stuck.max(stuck);
                let gap = highest_signed_next.max(latest) - latest;
                final_mined = latest - first_nonce;
                let second = phase_start.elapsed().as_secs();
                if second != last_second {
                    if last_second != u64::MAX {
                        peak_gap = peak_gap.max(second_min_gap);
                    }
                    last_second = second;
                    second_min_gap = u64::MAX;
                }
                // The smallest gap within the second: an approval that waits for the next block only shows up briefly.
                second_min_gap = second_min_gap.min(gap);
                if relief_start.is_some() && !peak_seen {
                    peak_seen = true;
                    peak_stuck = (stuck, base_fee, pooled.len());
                }
                if Instant::now() >= next_row {
                    next_row += Duration::from_secs(5);
                    let cap = blokli_max_fee(&client).await;
                    println!(
                        "[{label}]   t={second:>3}s block {:>3} {base_fee}/{}/{gas_used} mined={} pooled={} stuck={stuck} gap={gap}",
                        block - first,
                        show(cap),
                        latest - first_nonce,
                        pooled.len()
                    );
                }
                if let Some(start) = relief_start {
                    if gap == 0 && pooled.is_empty() && latest - first_nonce + refused.get() as u64 >= sent as u64 {
                        closed_after.get_or_insert(start.elapsed());
                        break;
                    }
                    if start.elapsed() > relief_window {
                        break;
                    }
                }
            }
            Some((index, at, result)) = outcomes.next() => record(index, at, result),
        }
    }
    // Late outcomes of approvals that were still tracked.
    while let Ok(Some((index, at, result))) = tokio::time::timeout(Duration::from_secs(1), outcomes.next()).await {
        record(index, at, result);
    }

    println!(
        "[{label}] congestion: peak base fee {peak_base_seen} wei (Blokli max fee floor about 5000000), {blocks_full} \
         blocks, {sent} approvals sent, {final_mined} mined"
    );
    println!(
        "[{label}] stuck below the base fee: {} approvals of {} pooled when relief started (base fee {}), {max_stuck} \
         at most",
        peak_stuck.0, peak_stuck.2, peak_stuck.1
    );
    println!("[{label}] peak gap: {peak_gap}");
    match closed_after {
        Some(after) => println!(
            "[{label}] the gap closed {:.1}s after the filler stopped",
            after.as_secs_f64()
        ),
        None => println!("[{label}] the gap did not close within the relief window"),
    }
    println!(
        "[{label}] {} approvals refused by Blokli, outcomes: {tally:?}",
        refused.get()
    );

    anyhow::ensure!(
        closed_after.is_some(),
        "the gap is expected to close after relief: {final_mined} of {sent} approvals mined"
    );
    anyhow::ensure!(
        final_mined + refused.get() as u64 == sent as u64,
        "every approval Blokli accepted is expected to be mined"
    );
    Ok(())
}

#[test_log::test(tokio::test)]
#[ignore = "requires a running Blokli and geth"]
async fn nonce_gap_under_congestion() -> anyhow::Result<()> {
    run_scenario().await
}
