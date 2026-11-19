//! A scripted Blokli client for driving the transaction sequencer queue in unit tests.
//!
//! It models the one thing the sequencer relies on: the chain's pending transaction count. A submission is signed
//! with a nonce the fake encodes in the raw bytes, and answered from a script of refusals. Accepted submissions
//! move the pending count the way a mempool does, and every attempt is recorded.

use std::{collections::VecDeque, time::Duration};

use blokli_client::{
    BlokliTestState,
    api::{
        AccountSelector, BlokliQueryClient, BlokliTransactionClient, ChainAddress, ChannelSelector,
        ModulePredictionInput, RedeemedStatsSelector, SafeSelector, ServiceSelector, ServiceTypeId,
        TransactionTrackingOutcome, TxId, TxReceipt,
        types::{self, ChainInfo, Transaction, TransactionStatus},
    },
    errors::{BlokliClientError, ErrorKind},
};
use hopr_api::types::{
    chain::prelude::{GasEstimation, SignableTransaction},
    crypto::prelude::ChainKeypair,
};

type Result<T> = std::result::Result<T, BlokliClientError>;

/// A transaction request whose signature only carries the nonce and the max fee.
#[derive(Clone, Debug)]
pub(super) struct FakeTx;

#[async_trait::async_trait]
impl SignableTransaction for FakeTx {
    async fn sign_and_encode_to_eip2718(
        self,
        nonce: u64,
        _chain_id: u64,
        max_gas: Option<GasEstimation>,
        _chain_keypair: &ChainKeypair,
    ) -> hopr_api::types::chain::errors::Result<Box<[u8]>> {
        let mut raw = nonce.to_be_bytes().to_vec();
        raw.extend(max_gas.map_or(0, |gas| gas.max_fee_per_gas).to_be_bytes());
        Ok(raw.into())
    }
}

/// What the chain does with one submission.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Step {
    /// RPC refusal code, `None` accepts the transaction into the mempool.
    pub refusal: Option<&'static str>,
    /// Sets the chain's pending count after the refusal, e.g. a dropped transaction leaving the mempool.
    pub pending_after: Option<u64>,
}

impl Step {
    pub fn refuse(code: &'static str) -> Self {
        Self {
            refusal: Some(code),
            pending_after: None,
        }
    }
}

/// One submission the chain received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Attempt {
    pub nonce: u64,
    pub max_fee: u128,
    pub pending_before: u64,
    pub accepted: bool,
}

#[derive(Default)]
struct Chain {
    pending: u64,
    script: VecDeque<Step>,
    attempts: Vec<Attempt>,
    /// Max fee returned by the next gas estimate, raised by `fee_step` after every read.
    max_fee: u128,
    fee_step: u128,
    /// Tracking error of the transaction submitted at this nonce.
    track_errors: Vec<(u64, TrackError)>,
    /// Whether an accepted transaction raises the pending count (a mempool that counts underpriced ones).
    count_mempool: bool,
}

/// How tracking of a submitted transaction ends.
#[derive(Clone, Copy, Debug)]
pub(super) enum TrackError {
    UnderpricedTimeout,
}

pub(super) struct ScriptedClient {
    chain: parking_lot::Mutex<Chain>,
    chain_info: ChainInfo,
}

impl ScriptedClient {
    pub fn new(pending: u64, script: Vec<Step>) -> Self {
        Self {
            chain: parking_lot::Mutex::new(Chain {
                pending,
                script: script.into(),
                max_fee: 3_000_000_000,
                count_mempool: true,
                ..Chain::default()
            }),
            chain_info: BlokliTestState::default().chain_info,
        }
    }

    /// Raises the estimated max fee by `step` on every read of the chain info.
    pub fn with_rising_fees(self, step: u128) -> Self {
        self.chain.lock().fee_step = step;
        self
    }

    /// The transaction submitted at `nonce` times out underpriced when tracked.
    pub fn with_underpriced_timeout(self, nonce: u64) -> Self {
        self.chain
            .lock()
            .track_errors
            .push((nonce, TrackError::UnderpricedTimeout));
        self
    }

    /// Underpriced transactions are not part of the chain's pending count.
    pub fn without_mempool_count(self) -> Self {
        self.chain.lock().count_mempool = false;
        self
    }

    pub fn pending(&self) -> u64 {
        self.chain.lock().pending
    }

    pub fn attempts(&self) -> Vec<Attempt> {
        self.chain.lock().attempts.clone()
    }
}

#[allow(unused_variables)]
#[async_trait::async_trait]
impl BlokliQueryClient for ScriptedClient {
    async fn query_chain_info(&self) -> Result<ChainInfo> {
        let mut chain = self.chain.lock();
        let mut info = self.chain_info.clone();
        info.max_fee_per_gas = Some(chain.max_fee.to_string());
        chain.max_fee += chain.fee_step;
        Ok(info)
    }

    async fn query_transaction_count(&self, address: &ChainAddress) -> Result<u64> {
        Ok(self.chain.lock().pending)
    }

    async fn count_accounts(&self, selector: AccountSelector) -> Result<u32> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_accounts(&self, selector: AccountSelector) -> Result<Vec<types::Account>> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_native_balance(&self, address: &ChainAddress) -> Result<types::NativeBalance> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_token_balance(&self, address: &ChainAddress, token: types::Token) -> Result<types::HoprBalance> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_safe_allowance(&self, address: &ChainAddress) -> Result<types::SafeHoprAllowance> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_redeemed_stats(&self, selector: RedeemedStatsSelector) -> Result<types::RedeemedStats> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_safe(&self, selector: SafeSelector) -> Result<Vec<types::Safe>> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_module_address_prediction(&self, input: ModulePredictionInput) -> Result<ChainAddress> {
        unimplemented!("not used by the sequencer")
    }
    async fn count_channels(&self, selector: ChannelSelector) -> Result<u32> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_channel_stats(&self, selector: ChannelSelector) -> Result<types::ChannelStats> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_channels(&self, selector: ChannelSelector) -> Result<types::ChannelsList> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_safes_balance(&self, owner_address: Option<ChainAddress>) -> Result<types::SafesBalance> {
        unimplemented!("not used by the sequencer")
    }
    async fn count_services(&self, selector: ServiceSelector) -> Result<u32> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_services(&self, selector: ServiceSelector) -> Result<Vec<types::ServiceEntry>> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_live_services(&self, selector: ServiceSelector) -> Result<Vec<types::ServiceEntry>> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_service_types(&self, service_type: Option<ServiceTypeId>) -> Result<Vec<types::ServiceTypeInfo>> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_service_registry_config(&self) -> Result<types::ServiceRegistryConfig> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_transaction_status(&self, tx_id: TxId) -> Result<types::Transaction> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_version(&self) -> Result<String> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_health(&self) -> Result<String> {
        unimplemented!("not used by the sequencer")
    }
    async fn query_compatibility(&self) -> Result<types::Compatibility> {
        unimplemented!("not used by the sequencer")
    }
}

#[async_trait::async_trait]
impl BlokliTransactionClient for ScriptedClient {
    async fn submit_transaction(&self, _signed_tx: &[u8]) -> Result<TxReceipt> {
        unimplemented!("not used by the sequencer")
    }

    async fn submit_and_track_transaction(&self, signed_tx: &[u8]) -> Result<TxId> {
        let nonce = u64::from_be_bytes(signed_tx[..8].try_into().expect("nonce"));
        let max_fee = u128::from_be_bytes(signed_tx[8..24].try_into().expect("max fee"));
        let mut chain = self.chain.lock();
        let step = chain.script.pop_front().unwrap_or_default();
        let pending_before = chain.pending;

        let refusal = step
            .refusal
            .or_else(|| (nonce < chain.pending).then_some("NONCE_TOO_LOW"));
        let accepted = refusal.is_none();
        chain.attempts.push(Attempt {
            nonce,
            max_fee,
            pending_before,
            accepted,
        });
        if let Some(pending) = step.pending_after {
            chain.pending = pending;
        }
        if let Some(code) = refusal {
            return Err(ErrorKind::BlokliError {
                kind: "rpc error",
                code: code.into(),
                message: "refused by the rpc node".into(),
            }
            .into());
        }
        // A transaction that does not follow the pending count waits in the queue of the mempool
        if nonce == chain.pending && chain.count_mempool {
            chain.pending += 1;
        }
        Ok(format!("tx-{nonce}-{}", chain.attempts.len()))
    }

    async fn submit_and_confirm_transaction(&self, _signed_tx: &[u8], _num_confirmations: usize) -> Result<TxReceipt> {
        unimplemented!("not used by the sequencer")
    }

    async fn track_transaction(&self, tx_id: TxId, _client_timeout: Duration) -> Result<TransactionTrackingOutcome> {
        let nonce: u64 = tx_id
            .split('-')
            .nth(1)
            .and_then(|n| n.parse().ok())
            .expect("fake tx id");
        if self.chain.lock().track_errors.iter().any(|(n, _)| *n == nonce) {
            let crate::errors::ConnectorError::ClientError(error) =
                crate::errors::test_support::timed_out_error(types::UnminedReason::Underpriced, 0).await
            else {
                unreachable!("a tracking timeout is a client error")
            };
            return Err(error);
        }
        Ok(TransactionTrackingOutcome::Confirmed(Transaction {
            id: tx_id.into(),
            status: TransactionStatus::Confirmed,
            submitted_at: types::DateTime(String::new()),
            transaction_hash: types::Hex32(String::new()),
            safe_execution: None,
        }))
    }
}
