//! Helpers shared by the live sequencer tests (`sequencer_live_tests` against Anvil, `sequencer_live_geth_tests`
//! against geth): a minimal JSON-RPC client, the sequencer enqueuing and the wait for Blokli's indexer.

use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use blokli_client::{BlokliClient, api::BlokliQueryClient};
use futures::stream::FuturesUnordered;
use hopr_api::types::{
    chain::prelude::{BasicPayloadGenerator, GasEstimation, PayloadGenerator, TransactionRequest},
    primitive::prelude::*,
};
use serde_json::{Value, json};

use crate::{
    connector::sequencer::TransactionSequencer,
    utils::{ParsedChainInfo, model_to_chain_info},
};

/// Diagnosis reasons of the unmined attempts, as read from the connector's errors. Stays empty for connectors that do
/// not expose a diagnosis.
pub(super) static DIAGNOSES: Mutex<BTreeMap<String, usize>> = Mutex::new(BTreeMap::new());

/// Blokli's current max fee estimate.
pub(super) async fn blokli_fee_cap(client: &BlokliClient) -> Option<u128> {
    let info = model_to_chain_info(client.query_chain_info().await.ok()?).ok()?;
    Some(GasEstimation::from(info).max_fee_per_gas)
}

/// Secret key of the well-known, public Anvil development account #1. It holds no real funds.
pub(super) const ANVIL_ACCOUNT_1_KEY: [u8; 32] =
    hex_literal::hex!("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

/// Tracking timeout of every approval: longer than Blokli's unmined timeout set by `chain.sh`.
pub(super) const TRACKING_TIMEOUT: Duration = Duration::from_secs(45);

/// A transaction held in the pool of the node.
pub(super) struct PoolTx {
    pub nonce: u64,
    pub hash: String,
    pub max_fee: u128,
}

pub(super) fn parse_quantity(value: &Value) -> Option<u128> {
    u128::from_str_radix(value.as_str()?.trim_start_matches("0x"), 16).ok()
}

/// JSON-RPC client of the execution client (Anvil or geth).
pub(super) struct Rpc {
    pub http: reqwest::Client,
    pub url: String,
}

impl Rpc {
    pub fn new(url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            url,
        }
    }

    pub async fn call(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let response: Value = serde_json::from_slice(
            &self
                .http
                .post(&self.url)
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .await?
                .bytes()
                .await?,
        )?;
        match response.get("error") {
            Some(error) => anyhow::bail!("{method} failed: {error}"),
            None => Ok(response["result"].clone()),
        }
    }

    pub async fn quantity(&self, method: &str, params: Value) -> anyhow::Result<u128> {
        let result = self.call(method, params).await?;
        parse_quantity(&result).ok_or_else(|| anyhow::anyhow!("{method} returned no quantity"))
    }

    /// Mined transaction count of `account`.
    pub async fn nonce(&self, account: &str) -> anyhow::Result<u64> {
        Ok(self
            .quantity("eth_getTransactionCount", json!([account, "latest"]))
            .await? as u64)
    }

    pub async fn base_fee(&self) -> anyhow::Result<u128> {
        let block = self.call("eth_getBlockByNumber", json!(["latest", false])).await?;
        Ok(parse_quantity(&block["baseFeePerGas"]).unwrap_or(0))
    }

    /// Transactions of `account` held in the pool, pending and queued.
    pub async fn pool_entries(&self, account: &str) -> anyhow::Result<Vec<PoolTx>> {
        let content = self.call("txpool_content", json!([])).await?;
        let mut found = Vec::new();
        for section in ["pending", "queued"] {
            let Some(senders) = content[section].as_object() else {
                continue;
            };
            for (sender, by_nonce) in senders {
                if !sender.eq_ignore_ascii_case(account) {
                    continue;
                }
                for (nonce, tx) in by_nonce.as_object().into_iter().flatten() {
                    if let (Ok(nonce), Some(hash)) = (nonce.parse(), tx["hash"].as_str()) {
                        found.push(PoolTx {
                            nonce,
                            hash: hash.to_owned(),
                            max_fee: parse_quantity(&tx["maxFeePerGas"]).unwrap_or(0),
                        });
                    }
                }
            }
        }
        Ok(found)
    }

    /// Transactions of `account` held in the pool, as `(nonce, hash)`.
    pub async fn pooled(&self, account: &str) -> anyhow::Result<Vec<(u64, String)>> {
        Ok(self
            .pool_entries(account)
            .await?
            .into_iter()
            .map(|tx| (tx.nonce, tx.hash))
            .collect())
    }
}

pub(super) type Seq = TransactionSequencer<BlokliClient, TransactionRequest>;

pub(super) struct Enqueuer<'a> {
    pub sequencer: &'a Seq,
    pub payloads: &'a BasicPayloadGenerator,
    pub spender: Address,
    pub started: Instant,
}

impl<'a> Enqueuer<'a> {
    pub async fn enqueue(&self, index: usize, outcomes: &FuturesUnordered<Outcome<'a>>) -> anyhow::Result<()> {
        // A distinct amount per approval, so that none is mistaken for a retry of another.
        let tx = self.payloads.approve(self.spender, HoprBalance::from(index as u64))?;
        let tracked = self.sequencer.enqueue_transaction(tx, TRACKING_TIMEOUT, None).await?;
        let started = self.started;
        outcomes.push(Box::pin(async move {
            let result = match tracked.await {
                Ok(tx) => format!("confirmed ({:?})", tx.status),
                // This client version has no unmined diagnosis
                Err(error) => format!("{error}; diagnosis n/a"),
            };
            (index, started.elapsed(), result)
        }));
        Ok(())
    }
}

impl Enqueuer<'_> {
    /// Enqueues one approval with the given tracking timeout and waits for its outcome.
    pub async fn attempt(&self, index: usize, timeout: Duration) -> Result<String, String> {
        let tx = self
            .payloads
            .approve(self.spender, HoprBalance::from(index as u64))
            .map_err(|error| error.to_string())?;
        let tracked = self
            .sequencer
            .enqueue_transaction(tx, timeout, None)
            .await
            .map_err(|error| error.to_string())?;
        match tracked.await {
            Ok(tx) => Ok(format!("{:?}", tx.status)),
            Err(error) => Err(error.to_string()),
        }
    }
}

pub(super) type Outcome<'a> = Pin<Box<dyn Future<Output = (usize, Duration, String)> + 'a>>;

/// Blokli refuses queries while its indexer lags behind the blocks mined so far: waits until it answers.
pub(super) async fn wait_for_chain_info(client: &BlokliClient, label: &str) -> anyhow::Result<ParsedChainInfo> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match client.query_chain_info().await {
            Ok(info) => return Ok(model_to_chain_info(info)?),
            Err(error) if Instant::now() < deadline => {
                println!("[{label}] waiting for Blokli's indexer: {error}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Parameters of the `redemption_retry_loop` scenario.
pub(super) struct RetryConfig {
    /// Simulated channels, each redeeming one ticket.
    pub channels: usize,
    /// Wait between a failed attempt and the next one, as the strategy tick.
    pub tick: Duration,
    /// Tracking timeout of every attempt.
    pub tracking_timeout: Duration,
    /// Delay between the first attempts of two consecutive channels.
    pub stagger: Duration,
    /// Base fee at which the channels may start, just below the max fee cap of 0.14.5 (5 Mwei) so that the first
    /// approvals are signed before the spike.
    pub start_base_fee: u128,
    /// Base fee at which the ramp ends.
    pub peak_base_fee: u128,
    /// Blocks held near the peak before the relief.
    pub hold_blocks: u64,
    /// Total wall time of the observation.
    pub window: Duration,
    /// Stops the observation as soon as the gap has closed after the relief.
    pub stop_on_close: bool,
}

impl RetryConfig {
    pub fn from_env(default_window_secs: u64, stop_on_close: bool) -> Self {
        fn var<T: std::str::FromStr>(name: &str, default: T) -> T {
            std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
        }
        Self {
            channels: var("REDEMPTION_CHANNELS", 12),
            tick: Duration::from_secs(var("REDEMPTION_TICK_SECS", 5)),
            tracking_timeout: Duration::from_secs(var("REDEMPTION_TRACKING_SECS", 12)),
            stagger: Duration::from_secs(var("REDEMPTION_STAGGER_SECS", 2)),
            start_base_fee: var("REDEMPTION_START_BASE_FEE", 2_000_000),
            peak_base_fee: var("REDEMPTION_PEAK_BASE_FEE", 100_000_000),
            hold_blocks: var("REDEMPTION_HOLD_BLOCKS", 30),
            window: Duration::from_secs(var("REDEMPTION_WINDOW_SECS", default_window_secs)),
            stop_on_close: stop_on_close && var("REDEMPTION_STOP_ON_CLOSE", 1u8) == 1,
        }
    }
}

/// State shared by the channels, the sampler and the chain driver of the scenario.
pub(super) struct RetryState {
    /// Approvals enqueued so far, retries included.
    pub submitted: AtomicUsize,
    /// Channels whose approval was confirmed.
    pub confirmed: AtomicUsize,
    /// Second (since the start) at which the congestion relief starts, `u64::MAX` before.
    pub relief_at: AtomicU64,
    pub stop: AtomicBool,
    /// Highest base fee observed, in wei.
    pub peak_base_fee: AtomicU64,
    /// Set when the channels may start, so that the scenario starts from a reproducible chain state.
    pub go: AtomicBool,
    pub errors: Mutex<BTreeMap<String, usize>>,
    pub started: Instant,
}

impl RetryState {
    pub fn new() -> Self {
        Self {
            submitted: AtomicUsize::new(0),
            confirmed: AtomicUsize::new(0),
            relief_at: AtomicU64::new(u64::MAX),
            stop: AtomicBool::new(false),
            peak_base_fee: AtomicU64::new(0),
            go: AtomicBool::new(false),
            errors: Mutex::new(BTreeMap::new()),
            started: Instant::now(),
        }
    }

    /// Called by the chain driver when the fee pressure ends.
    pub fn start_relief(&self) {
        self.relief_at.store(self.started.elapsed().as_secs(), Ordering::SeqCst);
    }

    pub fn observe_base_fee(&self, fee: u128) {
        self.peak_base_fee.fetch_max(fee as u64, Ordering::SeqCst);
    }

    pub fn begin(&self) {
        self.go.store(true, Ordering::SeqCst);
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// Models the redemption strategy: every channel enqueues one approval and waits for the outcome. On an error it waits
/// one tick and enqueues the approval again, as the next strategy tick starts a new redemption of the ticket at the
/// head of the queue. A confirmed approval ends the channel.
pub(super) async fn run_channels(ctx: &Enqueuer<'_>, state: &RetryState, config: &RetryConfig) {
    let channel = |id: usize| async move {
        while !state.go.load(Ordering::SeqCst) && !state.stopped() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(config.stagger * id as u32).await;
        loop {
            if state.stopped() {
                return;
            }
            // A distinct amount per attempt, across channels too.
            let index = state.submitted.fetch_add(1, Ordering::SeqCst) + 1;
            match ctx.attempt(index, config.tracking_timeout).await {
                Ok(_) => {
                    state.confirmed.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                Err(error) => {
                    println!(
                        "t={:.1}s channel {id} approval #{index} failed: {}",
                        state.started.elapsed().as_secs_f64(),
                        error.chars().take(100).collect::<String>()
                    );
                    *state
                        .errors
                        .lock()
                        .expect("error tally lock")
                        .entry(error.chars().take(70).collect())
                        .or_default() += 1;
                    tokio::time::sleep(config.tick).await;
                }
            }
        }
    };
    futures::future::join_all((0..config.channels).map(channel)).await;
}

/// Result of the observation of the Blokli pending count against the mined count.
pub(super) struct RetryReport {
    /// Highest nonce signed (seen in the node's pool, or the pending count) plus one, minus the mined count.
    pub peak_gap: u64,
    pub final_gap: u64,
    /// The same gap measured as Blokli's transaction count minus the mined count only. A transaction queued behind a
    /// missing nonce is not counted by every node.
    pub peak_blokli_gap: u64,
    /// Seconds since the start at which the gap was first zero for 3 seconds after the relief started.
    pub closed_at: Option<u64>,
    pub relief_at: Option<u64>,
    pub submitted: usize,
    pub confirmed: usize,
    /// Highest base fee observed, in wei.
    pub peak_base_fee: u64,
    /// Blokli's max fee estimate when the observation started.
    pub fee_cap_at_start: Option<u128>,
    /// Base fee of the first sample.
    pub base_fee_at_start: u128,
    /// Distinct transactions seen in the node's pool with a max fee below the base fee of the moment. A transaction
    /// evicted between two samples is not seen.
    pub signed_below_peak: usize,
}

/// Samples every second the gap between Blokli's transaction count of the signer and the mined count, until the
/// window ends, or the gap has closed when `stop_on_close` is set. Sets `state.stop` at the end.
pub(super) async fn sample_gap(
    client: &BlokliClient,
    rpc: &Rpc,
    signer: Address,
    config: &RetryConfig,
    state: &RetryState,
    label: &str,
) -> anyhow::Result<RetryReport> {
    let account = signer.to_string();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let (mut peak_gap, mut final_gap, mut peak_blokli_gap) = (0u64, 0u64, 0u64);
    let mut highest_next = 0u64;
    let mut underpriced: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut fee_cap_at_start = None;
    let mut base_fee_at_start = None;
    let mut zero_run = 0u32;
    let mut closed_at: Option<u64> = None;
    println!(
        "[{label}] per second: base fee, Blokli max fee, Blokli pending count, highest signed nonce + 1, mined count, \
         gap, approvals enqueued, confirmed"
    );
    while state.started.elapsed() < config.window {
        ticker.tick().await;
        let second = state.started.elapsed().as_secs();
        let pending = match client.query_transaction_count(&signer.into()).await {
            Ok(pending) => pending,
            Err(error) => {
                println!("[{label}] t={second}s pending count unavailable: {error}");
                continue;
            }
        };
        let mined = rpc.nonce(&account).await?;
        let base_fee = rpc.base_fee().await?;
        state.observe_base_fee(base_fee);
        let fee_cap = blokli_fee_cap(client).await;
        fee_cap_at_start = fee_cap_at_start.or(fee_cap);
        base_fee_at_start.get_or_insert(base_fee);
        for tx in rpc.pool_entries(&account).await? {
            highest_next = highest_next.max(tx.nonce + 1);
            if tx.max_fee < base_fee {
                underpriced.insert(tx.hash);
            }
        }
        peak_blokli_gap = peak_blokli_gap.max(pending.saturating_sub(mined));
        let gap = highest_next.max(pending).saturating_sub(mined);
        (peak_gap, final_gap) = (peak_gap.max(gap), gap);
        let relief = state.relief_at.load(Ordering::SeqCst);
        zero_run = if gap == 0 { zero_run + 1 } else { 0 };
        if zero_run >= 3 && second >= relief && closed_at.is_none() {
            closed_at = Some(second);
            println!("[{label}] t={second}s the gap is closed");
        }
        {
            println!(
                "[{label}]   t={second:>3}s base_fee={base_fee} blokli_max_fee={} pending={pending} \
                 highest_signed_next={highest_next} mined={mined} gap={gap} enqueued={} confirmed={}",
                fee_cap.map_or_else(|| "n/a".into(), |fee| fee.to_string()),
                state.submitted.load(Ordering::SeqCst),
                state.confirmed.load(Ordering::SeqCst)
            );
        }
        if config.stop_on_close && closed_at.is_some() && state.confirmed.load(Ordering::SeqCst) == config.channels {
            break;
        }
    }
    state.stop.store(true, Ordering::SeqCst);
    let peak_base_fee = state.peak_base_fee.load(Ordering::SeqCst);
    Ok(RetryReport {
        peak_base_fee,
        fee_cap_at_start,
        base_fee_at_start: base_fee_at_start.unwrap_or(0),
        signed_below_peak: underpriced.len(),
        peak_gap,
        final_gap,
        peak_blokli_gap,
        closed_at,
        relief_at: Some(state.relief_at.load(Ordering::SeqCst)).filter(|at| *at != u64::MAX),
        submitted: state.submitted.load(Ordering::SeqCst),
        confirmed: state.confirmed.load(Ordering::SeqCst),
    })
}

impl RetryReport {
    pub fn print(&self, label: &str, config: &RetryConfig, state: &RetryState) {
        println!(
            "[{label}] redemption retry loop: {} channels, tick {:?}, tracking timeout {:?}, window {:?}",
            config.channels, config.tick, config.tracking_timeout, config.window
        );
        println!(
            "[{label}] peak gap: {} (Blokli count only: {}), final gap: {}, approvals enqueued: {}, confirmed \
             channels: {}/{}",
            self.peak_gap, self.peak_blokli_gap, self.final_gap, self.submitted, self.confirmed, config.channels
        );
        println!(
            "[{label}] base fee at start: {}, peak base fee reached: {}, Blokli max fee at start: {}, distinct \
             transactions seen underpriced in the pool: {}",
            self.base_fee_at_start,
            self.peak_base_fee,
            self.fee_cap_at_start
                .map_or_else(|| "n/a".into(), |fee| fee.to_string()),
            self.signed_below_peak
        );
        println!(
            "[{label}] diagnosis reasons: {:?}",
            DIAGNOSES.lock().expect("diagnosis tally lock")
        );
        match (self.closed_at, self.relief_at) {
            (Some(closed), Some(relief)) => println!(
                "[{label}] the gap closed at t={closed}s, {}s after the relief started (t={relief}s)",
                closed.saturating_sub(relief)
            ),
            _ => println!("[{label}] the gap never closed"),
        }
        println!("[{label}] errors: {:?}", state.errors.lock().expect("error tally lock"));
    }
}
