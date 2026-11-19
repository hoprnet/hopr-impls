use std::{
    sync::atomic::AtomicU64,
    time::{Duration, Instant},
};

use blokli_client::{
    api::{BlokliQueryClient, BlokliTransactionClient, TransactionTrackingOutcome},
    errors::{RefusalCode, TrackingErrorKind},
};
use futures::{FutureExt, SinkExt, StreamExt, TryFutureExt};
use hopr_api::{
    Address,
    types::{
        chain::prelude::{GasEstimation, SignableTransaction},
        crypto::prelude::*,
    },
};
use tracing::Instrument;

use crate::{
    errors::{self, ConnectorError},
    utils::model_to_chain_info,
};

type TxRequest<T> = (
    T,
    Option<ChainKeypair>,
    futures::channel::oneshot::Sender<errors::Result<blokli_client::api::TxId>>,
);

/// Takes care of sequencing transactions, nonce management, and submitting the transactions to the blockchain in-order.
///
/// This object is meant to be a singleton and cannot be cloned.
pub struct TransactionSequencer<C, R> {
    sender: futures::channel::mpsc::Sender<TxRequest<R>>,
    client: std::sync::Arc<C>,
    // Shared with the queue task, to drop the nonce of a signer whose transaction was found dropped
    current_nonce: moka::sync::Cache<Address, std::sync::Arc<AtomicU64>>,
    own_signer: Address,
}

const TX_QUEUE_CAPACITY: usize = 2048;

// How long until nonces for other signers (than node's own) expire
const OTHER_SIGNER_NONCE_EXPIRATION: Duration = Duration::from_mins(5);

// How long a tracking id handed out by Blokli is remembered to detect deduplicated submissions.
// Must outlive the time a transaction can stay in flight, i.e. the longest tracking timeout.
const ISSUED_TX_ID_RETENTION: Duration = Duration::from_mins(5);

struct FixedTti {
    fixed: Address,
    tti: std::time::Duration,
}

impl FixedTti {
    #[inline]
    fn duration_for(&self, key: &Address) -> Option<Duration> {
        if key == &self.fixed {
            None // expiration cleared => never expires by time
        } else {
            Some(self.tti) // standard time-to-idle
        }
    }
}

impl moka::Expiry<Address, std::sync::Arc<AtomicU64>> for FixedTti {
    fn expire_after_create(&self, key: &Address, _: &std::sync::Arc<AtomicU64>, _: Instant) -> Option<Duration> {
        self.duration_for(key)
    }

    fn expire_after_read(
        &self,
        key: &Address,
        _: &std::sync::Arc<AtomicU64>,
        _: Instant,
        _: Option<Duration>,
        _: Instant,
    ) -> Option<Duration> {
        self.duration_for(key)
    }

    fn expire_after_update(
        &self,
        key: &Address,
        _: &std::sync::Arc<AtomicU64>,
        _: Instant,
        _: Option<Duration>,
    ) -> Option<Duration> {
        self.duration_for(key)
    }
}

impl<C, R> TransactionSequencer<C, R>
where
    C: BlokliQueryClient + BlokliTransactionClient + Send + Sync + 'static,
    R: SignableTransaction + Clone + Send + Sync + 'static,
{
    pub fn new(signer: ChainKeypair, client: std::sync::Arc<C>, nonce_gap_tolerance: Duration) -> Self {
        tracing::debug!(signer = %signer.public().to_address(), "starting transaction sequencer");

        let client_clone = client.clone();
        let signer_addr_own = signer.public().to_address();
        let (sender, receiver) = futures::channel::mpsc::channel::<TxRequest<R>>(TX_QUEUE_CAPACITY);

        // Nonce of our node signer never expires, all other signers expire after a few minutes
        let current_nonce = moka::sync::CacheBuilder::new(1024)
            .expire_after(FixedTti {
                fixed: signer.public().to_address(),
                tti: OTHER_SIGNER_NONCE_EXPIRATION,
            })
            .build();

        let current_nonce_handle = current_nonce.clone();

        // Tracking ids Blokli has already handed out to this sequencer.
        //
        // When Blokli recognizes a submission as a retry of a HOPR action that is still in flight,
        // it does not broadcast it and returns the id of the transaction already tracking that
        // action instead. The client reports this as an ordinary success, but the nonce the retry
        // was signed with was never used: incrementing the local nonce would open a gap that
        // stalls every later transaction of that signer. Since the in-flight transaction was
        // submitted through this sequencer, its id has been seen before, which identifies the
        // deduplication.
        let issued_tx_ids = moka::sync::CacheBuilder::new(4 * TX_QUEUE_CAPACITY as u64)
            .time_to_live(ISSUED_TX_ID_RETENTION)
            .build();

        let nonce_gaps = moka::sync::Cache::new(1024);

        hopr_utils::runtime::prelude::spawn(
            receiver
                .for_each(move |(tx, tx_signer, notifier): (R, Option<ChainKeypair>, _)| {
                    let client = client_clone.clone();
                    let signer = tx_signer.unwrap_or_else(|| signer.clone());
                    let signer_addr = signer.public().to_address();
                    let current_nonce = current_nonce.clone();
                    let nonce_gaps = nonce_gaps.clone();
                    let issued_tx_ids = issued_tx_ids.clone();
                    async move {
                        // Outer `Err`: the transaction never reached Blokli, inner: Blokli's outcome
                        let submission = async {
                            let (chain_id, gas_estimation) = read_gas_estimation(&*client).await?;

                            let pending = client
                                .query_transaction_count(&signer_addr.into())
                                .map_err(ConnectorError::from)
                                .await?;
                            let local_nonce = current_nonce.entry(signer_addr).or_default().into_value();
                            let nonce =
                                sync_nonce(&local_nonce, &nonce_gaps, signer_addr, pending, nonce_gap_tolerance);

                            submit_with_retry(
                                nonce,
                                gas_estimation,
                                pending,
                                &local_nonce,
                                |nonce, gas_estimation| {
                                    tracing::Span::current().record("nonce", nonce);
                                    let tx = tx.clone();
                                    let client = &client;
                                    let signer = &signer;
                                    async move {
                                        let tx = tx
                                            .sign_and_encode_to_eip2718(nonce, chain_id, gas_estimation.into(), signer)
                                            .await?;
                                        tracing::debug!("submitting transaction");
                                        Ok(client
                                            .submit_and_track_transaction(&tx)
                                            .map_err(ConnectorError::from)
                                            .await)
                                    }
                                },
                                || async {
                                    client
                                        .query_transaction_count(&signer_addr.into())
                                        .map_err(ConnectorError::from)
                                        .await
                                },
                                || async { read_gas_estimation(&*client).await.map(|(_, gas)| gas) },
                            )
                            .await
                        }
                        .await;

                        let deduplicated = matches!(
                            &submission,
                            Ok(Ok(tx_id)) if !record_issued_tx_id(&issued_tx_ids, tx_id)
                        );
                        match nonce_consumed(&submission, deduplicated) {
                            Some(true) => {
                                let prev_nonce = current_nonce
                                    .entry(signer_addr)
                                    .or_default()
                                    .value()
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                                tracing::debug!(
                                    prev_nonce,
                                    ?submission,
                                    "nonce incremented due to tx success or rejection"
                                );
                            }
                            Some(false) => tracing::debug!(deduplicated, ?submission, "nonce not consumed"),
                            None => {
                                current_nonce.invalidate(&signer_addr);
                                tracing::warn!(
                                    ?submission,
                                    "unknown whether the nonce was consumed, re-reading it from the chain"
                                );
                            }
                        }
                        submission.and_then(|res| res)
                    }
                    .instrument(tracing::debug_span!(
                        "sequence_transaction",
                        signer = %signer_addr,
                        nonce = tracing::field::Empty
                    ))
                    .map(move |res| {
                        if notifier.send(res).is_err() {
                            tracing::debug!(
                                "failed to notify transaction result - the caller may not want to await the result \
                                 anymore."
                            );
                        }
                    })
                })
                .inspect(|_| tracing::warn!("transaction sequencer queue stopped")),
        );

        Self {
            sender,
            client,
            current_nonce: current_nonce_handle,
            own_signer: signer_addr_own,
        }
    }
}

type Submission = errors::Result<errors::Result<blokli_client::api::TxId>>;

/// Reads the chain id and the fees to sign with from Blokli.
async fn read_gas_estimation<C: BlokliQueryClient + Sync>(client: &C) -> errors::Result<(u64, GasEstimation)> {
    let chain_info = client.query_chain_info().map_err(ConnectorError::from).await?;
    tracing::debug!(chain_id = chain_info.chain_id, "chain info retrieved for tx");

    let parsed_chain_info = model_to_chain_info(chain_info)?;
    let chain_id = parsed_chain_info.info.chain_id;
    let gas_estimation = GasEstimation::from(parsed_chain_info);
    tracing::debug!(?gas_estimation, "gas estimation used for tx");
    Ok((chain_id, gas_estimation))
}

/// Signs and submits a transaction with `nonce` and `gas` through `attempt`, and corrects it once
/// when Blokli's refusal says what was wrong with it.
///
/// - `NONCE_TOO_HIGH`: the nonce was not consumed and the local nonce is ahead of what the chain expects. The chain's
///   pending count is re-read through `read_pending` and adopted as the local nonce. The pending count never goes below
///   `first_pending`, the one read at the start of the submission, and one that does not lie below the refused nonce is
///   not worth a retry.
/// - `NONCE_TOO_LOW`: the nonce was already used and the local nonce is behind. The pending count is re-read and
///   adopted the same way, but only if it lies above the refused nonce.
/// - `FEE_TOO_LOW`: the nonce was not consumed. The fees are read again through `read_gas`, and the transaction is
///   signed at the same nonce only if they are higher than the ones just refused. Blokli caches its estimate for a
///   block, so an unchanged estimate would be refused again.
///
/// The correction happens at most once per submission, whatever the refusal: a second refusal is
/// returned as is. Failing to read the corrected value returns the first refusal.
async fn submit_with_retry<A, AFut, P, PFut, G, GFut>(
    nonce: u64,
    gas: GasEstimation,
    first_pending: u64,
    local: &AtomicU64,
    mut attempt: A,
    read_pending: P,
    read_gas: G,
) -> Submission
where
    A: FnMut(u64, GasEstimation) -> AFut,
    AFut: Future<Output = Submission>,
    P: FnOnce() -> PFut,
    PFut: Future<Output = errors::Result<u64>>,
    G: FnOnce() -> GFut,
    GFut: Future<Output = errors::Result<GasEstimation>>,
{
    let first = attempt(nonce, gas).await;
    let Ok(Err(error)) = &first else {
        return first;
    };

    match error.refusal_code() {
        Some(code @ (RefusalCode::NonceTooHigh | RefusalCode::NonceTooLow)) => match read_pending().await {
            Ok(re_read) => {
                let pending = re_read.max(first_pending);
                let usable = if code == RefusalCode::NonceTooHigh {
                    pending < nonce
                } else {
                    pending > nonce
                };
                if !usable {
                    tracing::warn!(
                        nonce,
                        pending,
                        ?code,
                        "pending count does not correct the refused nonce"
                    );
                    return first;
                }
                tracing::warn!(
                    nonce,
                    pending,
                    ?code,
                    "nonce refused, retrying once with the chain's pending count"
                );
                local.store(pending, std::sync::atomic::Ordering::Relaxed);
                attempt(pending, gas).await
            }
            Err(error) => {
                tracing::warn!(%error, ?code, "failed to re-read the pending count after a refused nonce");
                first
            }
        },
        Some(RefusalCode::FeeTooLow) => match read_gas().await {
            Ok(new_gas)
                if new_gas.max_fee_per_gas > gas.max_fee_per_gas
                    || new_gas.max_priority_fee_per_gas > gas.max_priority_fee_per_gas =>
            {
                tracing::warn!(
                    nonce,
                    old_max_fee = gas.max_fee_per_gas,
                    new_max_fee = new_gas.max_fee_per_gas,
                    "fees refused as too low, retrying once with Blokli's current estimate"
                );
                attempt(nonce, new_gas).await
            }
            Ok(_) => {
                tracing::warn!(nonce, "fees refused as too low, but Blokli's estimate did not increase");
                first
            }
            Err(error) => {
                tracing::warn!(%error, "failed to re-read the fees after they were refused as too low");
                first
            }
        },
        _ => first,
    }
}

/// Whether Blokli found a timed out transaction to leave its nonce unused, so that the local nonce is ahead.
///
/// This is the case when the RPC node dropped the transaction, or an earlier nonce of the signer is missing
/// altogether. Every later transaction of the signer then waits for a nonce that is never mined, until the
/// local nonce is read from the chain again. A transaction that is merely underpriced or queued behind pending
/// ones keeps its nonce, and a replaced one lost it to another transaction.
fn nonce_is_free(error: &ConnectorError) -> bool {
    error
        .unmined_diagnosis()
        .is_some_and(|diagnosis| reason_leaves_nonce_free(&diagnosis.reason))
}

fn reason_leaves_nonce_free(reason: &blokli_client::api::types::UnminedReason) -> bool {
    use blokli_client::api::types::UnminedReason;

    matches!(reason, UnminedReason::Dropped | UnminedReason::NonceGap)
}

/// Records a tracking id returned by Blokli.
///
/// Returns `false` if the id had already been issued before, meaning Blokli deduplicated the
/// submission to a transaction that is already in flight.
fn record_issued_tx_id(
    issued: &moka::sync::Cache<blokli_client::api::TxId, ()>,
    tx_id: &blokli_client::api::TxId,
) -> bool {
    if issued.contains_key(tx_id) {
        false
    } else {
        issued.insert(tx_id.clone(), ());
        true
    }
}

/// Raises `local` to the chain's `pending` count, or lowers it there once it stayed ahead of an
/// unchanging count for `tolerance`: the missing nonce would otherwise block the signer for good.
fn sync_nonce(
    local: &AtomicU64,
    gaps: &moka::sync::Cache<Address, (u64, Instant)>,
    signer: Address,
    pending: u64,
    tolerance: Duration,
) -> u64 {
    let prev_nonce = local.load(std::sync::atomic::Ordering::Relaxed);
    if let Some(gap_age) = nonce_gap_age(gaps, signer, prev_nonce, pending).filter(|age| *age >= tolerance) {
        tracing::warn!(
            prev_nonce,
            pending,
            ?gap_age,
            %signer,
            "local nonce stayed ahead of the chain's pending count, resyncing it"
        );
        local.store(pending, std::sync::atomic::Ordering::Relaxed);
        gaps.invalidate(&signer);
    }
    tracing::debug!(prev_nonce, tx_count = pending, "transaction count retrieved");
    local
        .fetch_max(pending, std::sync::atomic::Ordering::Relaxed)
        .max(pending)
}

/// How long `signer`'s local nonce has stayed ahead of the same pending count, `None` if it is not ahead.
///
/// A pending count that moves means transactions are still being mined, so the gap starts over.
fn nonce_gap_age(
    gaps: &moka::sync::Cache<Address, (u64, Instant)>,
    signer: Address,
    local: u64,
    pending: u64,
) -> Option<Duration> {
    if local <= pending {
        gaps.invalidate(&signer);
        return None;
    }
    match gaps.get(&signer) {
        Some((gap_pending, since)) if gap_pending == pending => Some(since.elapsed()),
        _ => {
            gaps.insert(signer, (pending, Instant::now()));
            Some(Duration::ZERO)
        }
    }
}

/// Whether the nonce the transaction was signed with is now used up, by it or by another
/// transaction. `None` when the result does not tell.
fn nonce_consumed(
    submission: &errors::Result<errors::Result<blokli_client::api::TxId>>,
    deduplicated: bool,
) -> Option<bool> {
    let error = match submission {
        Err(_) => return Some(false),
        Ok(Ok(_)) => return Some(!deduplicated),
        Ok(Err(error)) => error,
    };
    if error.is_refused_before_broadcast() {
        return Some(false);
    }
    match error.refusal_code() {
        // a transaction already holds this nonce, mined or pending: it is consumed whatever the cache says
        Some(RefusalCode::ReplacementUnderpriced) => Some(true),
        Some(RefusalCode::FeeTooLow | RefusalCode::InsufficientFunds) => Some(false),
        // NONCE_TOO_LOW or NONCE_TOO_HIGH refused again after their correction, unverified ALREADY_KNOWN,
        // unclassified RPC errors, transport failures
        _ => None,
    }
}

impl<C, R> TransactionSequencer<C, R>
where
    C: BlokliTransactionClient + Send + Sync + 'static,
{
    /// Adds the transaction to the [`TransactionSequencer`] queue.
    ///
    /// The `timeout_until_finalized` is a total time until the TX is submitted and either confirmed or rejected.
    pub async fn enqueue_transaction(
        &self,
        transaction: R,
        timeout_until_finalized: std::time::Duration,
        custom_signer: Option<ChainKeypair>,
    ) -> errors::Result<impl Future<Output = errors::Result<blokli_client::api::types::Transaction>>> {
        let (notifier_tx, notifier_rx) = futures::channel::oneshot::channel();
        let signer_addr = custom_signer
            .as_ref()
            .map_or(self.own_signer, |signer| signer.public().to_address());
        let current_nonce = self.current_nonce.clone();

        self.sender
            .clone()
            .send((transaction, custom_signer, notifier_tx))
            .await
            .map_err(|_| ConnectorError::InvalidState("transaction queue dropped"))?;

        Ok(notifier_rx
            .inspect_ok(|res| tracing::debug!(?res, "transaction tracking id received"))
            .map(move |result| {
                result
                    .map_err(|_| ConnectorError::InvalidState("transaction notifier dropped"))
                    .and_then(|tx_res| tx_res.map(|id| (id, timeout_until_finalized)))
            })
            .and_then(move |(tx_id, timeout)| {
                self.client
                    .track_transaction(tx_id, timeout)
                    .map_err(ConnectorError::from)
                    .inspect(|res| tracing::debug!(?res, "transaction tracking done"))
                    .inspect_err(move |error| {
                        if nonce_is_free(error) {
                            tracing::warn!(
                                %signer_addr,
                                diagnosis = ?error.unmined_diagnosis(),
                                "transaction left unmined with its nonce unused, re-reading the nonce from the chain"
                            );
                            current_nonce.invalidate(&signer_addr);
                        }
                    })
                    .and_then(|outcome| async move {
                        match outcome {
                            TransactionTrackingOutcome::Confirmed(tx) => Ok(tx),
                            // The client deadline elapsed without a terminal status. This was reported as a
                            // timeout before the client distinguished the two, and is kept that way here.
                            TransactionTrackingOutcome::StatusUnknown { .. } => {
                                Err(ConnectorError::from(blokli_client::errors::BlokliClientError::from(
                                    blokli_client::errors::ErrorKind::TrackingError(TrackingErrorKind::Timeout),
                                )))
                            }
                        }
                    })
            }))
    }
}

impl<C, R> Drop for TransactionSequencer<C, R> {
    fn drop(&mut self) {
        // Causes the internally spawned task that drives the queue to terminate
        self.sender.close_channel();
    }
}

#[cfg(test)]
mod tests {
    use blokli_client::errors::ErrorKind;

    use super::*;

    fn failed(kind: ErrorKind) -> errors::Result<errors::Result<blokli_client::api::TxId>> {
        Ok(Err(errors::test_support::client_error(kind)))
    }

    fn rpc_refusal(code: &str) -> errors::Result<errors::Result<blokli_client::api::TxId>> {
        failed(ErrorKind::BlokliError {
            kind: "rpc error",
            code: code.into(),
            message: "refused by the rpc node".into(),
        })
    }

    #[test]
    fn nonce_is_consumed_by_a_broadcast_tx_or_a_competing_one() {
        assert_eq!(Some(true), nonce_consumed(&Ok(Ok("tx-1".into())), false));
        assert_eq!(
            Some(true),
            nonce_consumed(&rpc_refusal("REPLACEMENT_UNDERPRICED"), false)
        );
    }

    #[test]
    fn nonce_is_not_consumed_when_nothing_got_into_the_mempool() {
        assert_eq!(
            Some(false),
            nonce_consumed(&Ok(Ok("tx-1".into())), true),
            "deduplicated"
        );
        assert_eq!(
            Some(false),
            nonce_consumed(&Err(ConnectorError::ServerNotHealthy), false),
            "failed before submission"
        );
        assert_eq!(Some(false), nonce_consumed(&rpc_refusal("FEE_TOO_LOW"), false));
        assert_eq!(Some(false), nonce_consumed(&rpc_refusal("INSUFFICIENT_FUNDS"), false));
        let overloaded = failed(ErrorKind::BlokliError {
            kind: "overloaded",
            code: "OVERLOADED".into(),
            message: "too many tracked transactions".into(),
        });
        assert_eq!(Some(false), nonce_consumed(&overloaded, false));
    }

    #[test]
    fn nonce_consumption_is_unknown_when_the_result_does_not_tell() {
        // the nonce codes reach here only after their single correction was refused as well
        for code in ["NONCE_TOO_HIGH", "NONCE_TOO_LOW", "ALREADY_KNOWN", "RPC_ERROR"] {
            assert_eq!(None, nonce_consumed(&rpc_refusal(code), false), "{code}");
        }
        assert_eq!(None, nonce_consumed(&failed(ErrorKind::Timeout), false), "transport");
    }

    const LOW_FEE: u128 = 1_000;
    const HIGH_FEE: u128 = 5_000;

    fn gas(max_fee_per_gas: u128) -> GasEstimation {
        GasEstimation {
            max_fee_per_gas,
            ..GasEstimation::default()
        }
    }

    /// What a run of [`submit_with_retry`] did.
    struct Run {
        /// Nonce and max fee of every attempt, in order.
        attempts: Vec<(u64, u128)>,
        /// The local nonce after the run.
        local: u64,
        result: Submission,
        pending_reads: usize,
        gas_reads: usize,
    }

    /// Setup of a run: the nonce, the pending counts and the fees Blokli returns, and the attempt results.
    struct Setup {
        nonce: u64,
        first_pending: u64,
        pending: errors::Result<u64>,
        new_gas: errors::Result<GasEstimation>,
        outcomes: Vec<Submission>,
    }

    impl Setup {
        fn new(nonce: u64, pending: u64, outcomes: Vec<Submission>) -> Self {
            Self {
                nonce,
                first_pending: pending,
                pending: Ok(pending),
                new_gas: Ok(gas(HIGH_FEE)),
                outcomes,
            }
        }

        async fn run(self) -> Run {
            let attempts = std::sync::Mutex::new(Vec::new());
            let outcomes = std::sync::Mutex::new(self.outcomes.into_iter());
            let local = AtomicU64::new(self.nonce);
            let reads = std::sync::Mutex::new((0usize, 0usize));
            let result = submit_with_retry(
                self.nonce,
                gas(LOW_FEE),
                self.first_pending,
                &local,
                |nonce, gas| {
                    attempts.lock().unwrap().push((nonce, gas.max_fee_per_gas));
                    let outcome = outcomes.lock().unwrap().next().expect("unexpected extra attempt");
                    async move { outcome }
                },
                || {
                    reads.lock().unwrap().0 += 1;
                    async { self.pending }
                },
                || {
                    reads.lock().unwrap().1 += 1;
                    async { self.new_gas }
                },
            )
            .await;
            let (pending_reads, gas_reads) = reads.into_inner().unwrap();
            Run {
                attempts: attempts.into_inner().unwrap(),
                local: local.load(std::sync::atomic::Ordering::Relaxed),
                result,
                pending_reads,
                gas_reads,
            }
        }
    }

    fn ok() -> Submission {
        Ok(Ok("tx-1".into()))
    }

    #[tokio::test]
    async fn too_high_nonce_is_resubmitted_once_with_the_pending_count() {
        let run = Setup::new(9, 5, vec![rpc_refusal("NONCE_TOO_HIGH"), ok()]).run().await;

        assert_eq!(
            vec![(9, LOW_FEE), (5, LOW_FEE)],
            run.attempts,
            "re-signed with the re-read nonce"
        );
        assert_eq!(5, run.local, "pending count adopted as the local nonce");
        assert_eq!(Some(true), nonce_consumed(&run.result, false));
        assert_eq!(0, run.gas_reads, "the fees are not read for a nonce refusal");
    }

    #[tokio::test]
    async fn too_high_nonce_never_retries_below_the_first_pending_count() {
        let mut setup = Setup::new(9, 7, vec![rpc_refusal("NONCE_TOO_HIGH"), ok()]);
        setup.pending = Ok(5);
        let run = setup.run().await;

        assert_eq!(vec![9, 7], run.attempts.iter().map(|a| a.0).collect::<Vec<_>>());
        assert_eq!(7, run.local, "the lower re-read count is not adopted");
    }

    #[tokio::test]
    async fn too_high_nonce_is_not_resigned_when_pending_reaches_it() {
        let mut setup = Setup::new(9, 9, vec![rpc_refusal("NONCE_TOO_HIGH")]);
        setup.pending = Ok(5);
        let run = setup.run().await;

        assert_eq!(1, run.attempts.len(), "same nonce is not signed again");
        assert_eq!(9, run.local);
        assert_eq!(None, nonce_consumed(&run.result, false));
    }

    #[tokio::test]
    async fn too_low_nonce_is_resubmitted_once_with_the_pending_count() {
        let mut setup = Setup::new(5, 5, vec![rpc_refusal("NONCE_TOO_LOW"), ok()]);
        setup.pending = Ok(8);
        let run = setup.run().await;

        assert_eq!(vec![(5, LOW_FEE), (8, LOW_FEE)], run.attempts);
        assert_eq!(8, run.local, "pending count adopted as the local nonce");
        assert_eq!(Some(true), nonce_consumed(&run.result, false));
        assert_eq!(0, run.gas_reads);
    }

    #[tokio::test]
    async fn too_low_nonce_is_not_resigned_when_pending_does_not_pass_it() {
        let run = Setup::new(5, 5, vec![rpc_refusal("NONCE_TOO_LOW")]).run().await;

        assert_eq!(1, run.attempts.len());
        assert_eq!(5, run.local);
        assert_eq!(None, nonce_consumed(&run.result, false), "left for a re-read");
    }

    #[tokio::test]
    async fn nonce_refusals_are_not_retried_twice() {
        for (code, pending) in [("NONCE_TOO_HIGH", 5), ("NONCE_TOO_LOW", 12)] {
            let mut setup = Setup::new(9, 5, vec![rpc_refusal(code), rpc_refusal(code)]);
            setup.pending = Ok(pending);
            let run = setup.run().await;

            assert_eq!(2, run.attempts.len(), "{code}");
            assert_eq!(None, nonce_consumed(&run.result, false), "{code}: left for a re-read");
        }
    }

    #[tokio::test]
    async fn nonce_refusals_are_returned_when_the_pending_count_cannot_be_read() {
        for code in ["NONCE_TOO_HIGH", "NONCE_TOO_LOW"] {
            let mut setup = Setup::new(9, 5, vec![rpc_refusal(code)]);
            setup.pending = Err(ConnectorError::ServerNotHealthy);
            let run = setup.run().await;

            assert_eq!(1, run.attempts.len(), "{code}");
            assert_eq!(9, run.local, "{code}");
            assert_eq!(None, nonce_consumed(&run.result, false), "{code}");
        }
    }

    #[tokio::test]
    async fn too_low_fees_are_resubmitted_once_at_the_same_nonce_with_the_current_estimate() {
        let run = Setup::new(9, 5, vec![rpc_refusal("FEE_TOO_LOW"), ok()]).run().await;

        assert_eq!(
            vec![(9, LOW_FEE), (9, HIGH_FEE)],
            run.attempts,
            "same nonce, higher fees"
        );
        assert_eq!(9, run.local, "the nonce did not move");
        assert_eq!(Some(true), nonce_consumed(&run.result, false));
        assert_eq!(0, run.pending_reads, "the pending count is not read for a fee refusal");
    }

    #[tokio::test]
    async fn too_low_fees_are_not_resigned_when_the_estimate_did_not_increase() {
        for new_gas in [gas(LOW_FEE), gas(LOW_FEE - 1)] {
            let mut setup = Setup::new(9, 5, vec![rpc_refusal("FEE_TOO_LOW")]);
            setup.new_gas = Ok(new_gas);
            let run = setup.run().await;

            assert_eq!(1, run.attempts.len());
            assert_eq!(Some(false), nonce_consumed(&run.result, false), "nonce stays free");
        }
    }

    #[tokio::test]
    async fn too_low_fees_are_returned_when_the_estimate_cannot_be_read() {
        let mut setup = Setup::new(9, 5, vec![rpc_refusal("FEE_TOO_LOW")]);
        setup.new_gas = Err(ConnectorError::ServerNotHealthy);
        let run = setup.run().await;

        assert_eq!(1, run.attempts.len());
        assert_eq!(Some(false), nonce_consumed(&run.result, false));
    }

    #[tokio::test]
    async fn too_low_fees_are_not_retried_twice() {
        let run = Setup::new(9, 5, vec![rpc_refusal("FEE_TOO_LOW"), rpc_refusal("FEE_TOO_LOW")])
            .run()
            .await;

        assert_eq!(2, run.attempts.len());
        assert_eq!(1, run.gas_reads);
        assert_eq!(Some(false), nonce_consumed(&run.result, false));
    }

    #[tokio::test]
    async fn other_refusals_and_successes_are_not_resubmitted() {
        for code in [
            "REPLACEMENT_UNDERPRICED",
            "INSUFFICIENT_FUNDS",
            "ALREADY_KNOWN",
            "RPC_ERROR",
        ] {
            let run = Setup::new(9, 5, vec![rpc_refusal(code)]).run().await;
            assert_eq!(vec![(9, LOW_FEE)], run.attempts, "{code}");
            assert_eq!(9, run.local, "{code}");
            assert_eq!((0, 0), (run.pending_reads, run.gas_reads), "{code}: nothing is read");
        }
        let run = Setup::new(9, 5, vec![ok()]).run().await;
        assert_eq!((vec![(9, LOW_FEE)], 9), (run.attempts, run.local));
    }

    #[test]
    fn nonce_is_free_only_for_a_dropped_transaction_or_a_missing_earlier_nonce() {
        use blokli_client::api::types::UnminedReason;

        for (reason, free) in [
            (UnminedReason::Dropped, true),
            (UnminedReason::NonceGap, true),
            (UnminedReason::Underpriced, false),
            (UnminedReason::Queued, false),
            (UnminedReason::Replaced, false),
            (UnminedReason::Undetermined, false),
            (UnminedReason::Unknown("FUTURE".into()), false),
        ] {
            assert_eq!(free, reason_leaves_nonce_free(&reason), "{reason:?}");
        }
    }

    #[tokio::test]
    async fn a_diagnosed_dropped_timeout_frees_the_nonce_and_a_plain_timeout_does_not() {
        use blokli_client::api::types::UnminedReason;

        let dropped = errors::test_support::timed_out_error(UnminedReason::Dropped, 0).await;
        let underpriced = errors::test_support::timed_out_error(UnminedReason::Underpriced, 0).await;
        let plain = errors::test_support::client_error(ErrorKind::TrackingError(TrackingErrorKind::Timeout));

        assert!(nonce_is_free(&dropped));
        assert!(!nonce_is_free(&underpriced));
        assert!(!nonce_is_free(&plain));
    }

    #[test]
    fn nonce_follows_pending_up_but_drops_to_it_only_after_the_tolerance() {
        let gaps = moka::sync::Cache::new(16);
        let signer: Address = [1u8; 20].into();
        let local = AtomicU64::new(3);

        assert_eq!(5, sync_nonce(&local, &gaps, signer, 5, Duration::from_mins(5)));

        local.store(8, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            8,
            sync_nonce(&local, &gaps, signer, 5, Duration::from_mins(5)),
            "gap tolerated"
        );
        assert_eq!(5, sync_nonce(&local, &gaps, signer, 5, Duration::ZERO), "gap outlived");
        assert_eq!(5, local.load(std::sync::atomic::Ordering::Relaxed));
        assert!(gaps.get(&signer).is_none());
    }

    #[test]
    fn nonce_gaps_of_signers_age_independently() {
        let gaps = moka::sync::Cache::new(16);
        let (a, b): (Address, Address) = ([1u8; 20].into(), [2u8; 20].into());

        assert_eq!(Some(Duration::ZERO), nonce_gap_age(&gaps, a, 8, 7));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(Some(Duration::ZERO), nonce_gap_age(&gaps, b, 8, 7));
        assert!(nonce_gap_age(&gaps, a, 8, 7).is_some_and(|age| age >= Duration::from_millis(20)));
    }

    #[test]
    fn already_issued_tx_id_is_detected_as_deduplicated() {
        let issued = moka::sync::Cache::new(16);

        assert!(record_issued_tx_id(&issued, &"tx-1".to_string()));
        assert!(record_issued_tx_id(&issued, &"tx-2".to_string()));
        assert!(!record_issued_tx_id(&issued, &"tx-1".to_string()));
    }

    #[test]
    fn nonce_gap_ages_only_while_the_pending_count_stays_put() {
        let gaps = moka::sync::Cache::new(16);
        let signer: Address = [1u8; 20].into();

        assert_eq!(Some(Duration::ZERO), nonce_gap_age(&gaps, signer, 8, 7));
        std::thread::sleep(Duration::from_millis(20));
        assert!(nonce_gap_age(&gaps, signer, 9, 7).is_some_and(|age| age >= Duration::from_millis(20)));

        assert_eq!(
            Some(Duration::ZERO),
            nonce_gap_age(&gaps, signer, 9, 8),
            "pending moved"
        );
        assert_eq!(None, nonce_gap_age(&gaps, signer, 8, 8), "caught up");
        assert!(gaps.get(&signer).is_none());
    }

    mod burst {
        use futures::future::join_all;

        use super::*;
        use crate::connector::sequencer_test_client::{FakeTx, ScriptedClient, Step};

        const BURST: usize = 5;

        /// Enqueues [`BURST`] transactions at once and waits for all their results.
        async fn burst(
            client: ScriptedClient,
        ) -> (
            std::sync::Arc<ScriptedClient>,
            TransactionSequencer<ScriptedClient, FakeTx>,
            Vec<errors::Result<blokli_client::api::types::Transaction>>,
        ) {
            let client = std::sync::Arc::new(client);
            let sequencer = TransactionSequencer::new(ChainKeypair::random(), client.clone(), Duration::from_mins(5));
            let mut pending = Vec::new();
            for _ in 0..BURST {
                pending.push(
                    sequencer
                        .enqueue_transaction(FakeTx, Duration::from_secs(5), None)
                        .await
                        .expect("enqueued"),
                );
            }
            let results = join_all(pending).await;
            (client, sequencer, results)
        }

        /// Nonces of the attempts, in order, and the nonces that were accepted.
        fn nonces(client: &ScriptedClient) -> (Vec<u64>, Vec<u64>) {
            let attempts = client.attempts();
            (
                attempts.iter().map(|a| a.nonce).collect(),
                attempts.iter().filter(|a| a.accepted).map(|a| a.nonce).collect(),
            )
        }

        /// The local nonce must end at the chain's pending count: not ahead of it, not behind.
        fn assert_local_nonce_at_pending(
            client: &ScriptedClient,
            sequencer: &TransactionSequencer<ScriptedClient, FakeTx>,
        ) {
            let local = sequencer
                .current_nonce
                .get(&sequencer.own_signer)
                .map_or(0, |n| n.load(std::sync::atomic::Ordering::Relaxed));
            assert_eq!(
                client.pending(),
                local,
                "the local nonce must end at the chain's pending count"
            );
        }

        /// No accepted submission is ahead of the chain's pending count, and none reuses a nonce.
        fn assert_no_gap(client: &ScriptedClient) {
            let attempts = client.attempts();
            for attempt in attempts.iter().filter(|a| a.accepted) {
                assert_eq!(
                    attempt.nonce, attempt.pending_before,
                    "nonce signed ahead of the chain's pending count: {attempts:?}"
                );
            }
            let (_, mut accepted) = nonces(client);
            let n = accepted.len();
            accepted.dedup();
            assert_eq!(n, accepted.len(), "a nonce was accepted twice");
        }

        #[tokio::test]
        async fn fee_refused_first_tx_leaves_its_nonce_for_the_next_ones() {
            // The estimate does not rise, so the refused transaction is not resigned
            let (client, s, results) = burst(ScriptedClient::new(7, vec![Step::refuse("FEE_TOO_LOW")])).await;

            assert!(results[0].is_err());
            assert!(results[1..].iter().all(Result::is_ok));
            let (all, accepted) = nonces(&client);
            assert_eq!(vec![7, 7, 8, 9, 10], all, "the second tx reuses the unconsumed nonce");
            assert_eq!(vec![7, 8, 9, 10], accepted);
            assert_eq!(11, client.pending());
            assert_no_gap(&client);
            assert_local_nonce_at_pending(&client, &s);
        }

        #[tokio::test]
        async fn fee_refused_first_tx_resigned_once_at_the_same_nonce_when_fees_rise() {
            let (client, s, results) =
                burst(ScriptedClient::new(7, vec![Step::refuse("FEE_TOO_LOW")]).with_rising_fees(1)).await;

            assert!(results.iter().all(Result::is_ok));
            let (all, accepted) = nonces(&client);
            assert_eq!(
                vec![7, 7, 8, 9, 10, 11],
                all,
                "only the refused nonce is submitted twice"
            );
            assert_eq!(vec![7, 8, 9, 10, 11], accepted);
            assert_no_gap(&client);
            assert_local_nonce_at_pending(&client, &s);
        }

        #[tokio::test]
        async fn nonce_too_high_first_tx_does_not_make_the_next_ones_skip_a_nonce() {
            // The chain still expects 7: nothing changed the pending count, so there is nothing to correct
            let (client, s, results) = burst(ScriptedClient::new(7, vec![Step::refuse("NONCE_TOO_HIGH")])).await;

            assert!(results[0].is_err());
            assert!(results[1..].iter().all(Result::is_ok));
            let (all, accepted) = nonces(&client);
            assert_eq!(vec![7, 7, 8, 9, 10], all);
            assert_eq!(vec![7, 8, 9, 10], accepted);
            assert_no_gap(&client);
            assert_local_nonce_at_pending(&client, &s);
        }

        #[tokio::test]
        async fn nonce_too_high_after_the_pending_count_dropped_is_not_resigned_below_the_first_read() {
            // A mempool eviction brings the pending count from 9 to 7 after the refusal. The correction never
            // goes below the pending count read at the start, so the refused tx fails and the next ones start
            // from the lowered count, re-read from the chain.
            let step = Step {
                refusal: Some("NONCE_TOO_HIGH"),
                pending_after: Some(7),
            };
            let (client, s, results) = burst(ScriptedClient::new(9, vec![step])).await;

            assert!(results[0].is_err());
            assert!(results[1..].iter().all(Result::is_ok));
            let (all, accepted) = nonces(&client);
            assert_eq!(vec![9, 7, 8, 9, 10], all);
            assert_eq!(vec![7, 8, 9, 10], accepted);
            assert_no_gap(&client);
            assert_local_nonce_at_pending(&client, &s);
        }

        #[tokio::test]
        async fn underpriced_first_tx_keeps_its_nonce_and_the_next_ones_follow() {
            // The first transaction sits in the mempool underpriced and times out while tracked
            let (client, s, results) = burst(ScriptedClient::new(7, vec![]).with_underpriced_timeout(7)).await;

            assert!(results[0].is_err());
            assert!(results[1..].iter().all(Result::is_ok));
            let (all, accepted) = nonces(&client);
            assert_eq!(vec![7, 8, 9, 10, 11], all);
            assert_eq!(all, accepted);
            assert_no_gap(&client);
            assert_local_nonce_at_pending(&client, &s);
        }

        #[tokio::test]
        async fn underpriced_txs_missing_from_the_pending_count_are_signed_ahead_of_it() {
            // A node that does not count its underpriced transactions in the pending count: the cached
            // nonce runs ahead of what the chain knows and stays there until the gap tolerance elapses
            let (client, sequencer, _results) = burst(
                ScriptedClient::new(7, vec![])
                    .without_mempool_count()
                    .with_underpriced_timeout(7),
            )
            .await;

            let (all, _) = nonces(&client);
            assert_eq!(vec![7, 8, 9, 10, 11], all);
            assert_eq!(7, client.pending());
            assert_eq!(
                12,
                sequencer
                    .current_nonce
                    .get(&sequencer.own_signer)
                    .expect("cached")
                    .load(std::sync::atomic::Ordering::Relaxed)
            );
        }
    }
}
