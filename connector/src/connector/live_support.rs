//! Helpers shared by the live sequencer tests (`sequencer_live_tests` against Anvil, `sequencer_live_geth_tests`
//! against geth): a minimal JSON-RPC client, the sequencer enqueuing and the wait for Blokli's indexer.

use std::{
    pin::Pin,
    time::{Duration, Instant},
};

use blokli_client::{BlokliClient, api::BlokliQueryClient};
use futures::stream::FuturesUnordered;
use hopr_api::types::{
    chain::prelude::{BasicPayloadGenerator, PayloadGenerator, TransactionRequest},
    primitive::prelude::*,
};
use serde_json::{Value, json};

use crate::{
    connector::sequencer::TransactionSequencer,
    utils::{ParsedChainInfo, model_to_chain_info},
};

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
        let tracked = self
            .sequencer
            .enqueue_transaction(tx, TRACKING_TIMEOUT, None, "live_test")
            .await?;
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
