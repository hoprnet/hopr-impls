use std::{
    sync::atomic::AtomicU64,
    time::{Duration, Instant},
};

use blokli_client::api::{BlokliQueryClient, BlokliTransactionClient};
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
        let (sender, receiver) = futures::channel::mpsc::channel::<TxRequest<R>>(TX_QUEUE_CAPACITY);

        // Nonce of our node signer never expires, all other signers expire after a few minutes
        let current_nonce = moka::sync::CacheBuilder::new(1024)
            .expire_after(FixedTti {
                fixed: signer.public().to_address(),
                tti: OTHER_SIGNER_NONCE_EXPIRATION,
            })
            .build();

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
                            let chain_info = client.query_chain_info().map_err(ConnectorError::from).await?;
                            tracing::debug!(chain_id = chain_info.chain_id, "chain info retrieved for tx");

                            let parsed_chain_info = model_to_chain_info(chain_info)?;
                            let chain_id = parsed_chain_info.info.chain_id;
                            let gas_estimation = GasEstimation::from(parsed_chain_info);
                            tracing::debug!(?gas_estimation, "gas estimation used for tx");

                            let pending = client
                                .query_transaction_count(&signer_addr.into())
                                .map_err(ConnectorError::from)
                                .await?;
                            let local_nonce = current_nonce.entry(signer_addr).or_default().into_value();
                            let nonce =
                                sync_nonce(&local_nonce, &nonce_gaps, signer_addr, pending, nonce_gap_tolerance);

                            submit_with_nonce_retry(
                                nonce,
                                pending,
                                &local_nonce,
                                |nonce| {
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

        Self { sender, client }
    }
}

type Submission = errors::Result<errors::Result<blokli_client::api::TxId>>;

/// Signs and submits a transaction with `nonce` through `attempt`.
///
/// When Blokli refuses it as `NONCE_TOO_HIGH`, the nonce is not consumed and the local nonce is
/// ahead of what the chain expects. The chain's pending count is then re-read through
/// `read_pending`, adopted as the local nonce, and the transaction is signed and submitted once
/// more with it. The pending count never goes below `first_pending`, the one read at the start of
/// the submission, and a count that does not lie below the refused nonce is not worth a retry.
/// The retry happens at most once per submission: a second refusal is returned as is.
async fn submit_with_nonce_retry<A, AFut, P, PFut>(
    nonce: u64,
    first_pending: u64,
    local: &AtomicU64,
    mut attempt: A,
    read_pending: P,
) -> Submission
where
    A: FnMut(u64) -> AFut,
    AFut: Future<Output = Submission>,
    P: FnOnce() -> PFut,
    PFut: Future<Output = errors::Result<u64>>,
{
    let first = attempt(nonce).await;
    if !matches!(&first, Ok(Err(error)) if error.rpc_rejection_code() == Some("NONCE_TOO_HIGH")) {
        return first;
    }

    match read_pending().await {
        Ok(re_read) => {
            let pending = re_read.max(first_pending);
            if pending >= nonce {
                tracing::warn!(
                    nonce,
                    pending,
                    "nonce refused as too high, but not above the pending count"
                );
                return first;
            }
            tracing::warn!(
                nonce,
                pending,
                "nonce refused as too high, retrying once with the chain's pending count"
            );
            local.store(pending, std::sync::atomic::Ordering::Relaxed);
            attempt(pending).await
        }
        Err(error) => {
            tracing::warn!(%error, "failed to re-read the pending count after a too high nonce");
            first
        }
    }
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
    match error.rpc_rejection_code() {
        Some("NONCE_TOO_LOW" | "REPLACEMENT_UNDERPRICED") => Some(true),
        Some("FEE_TOO_LOW" | "INSUFFICIENT_FUNDS") => Some(false),
        // NONCE_TOO_HIGH refused twice, unverified ALREADY_KNOWN, unclassified RPC errors, transport failures
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
            .and_then(|(tx_id, timeout)| {
                self.client
                    .track_transaction(tx_id, timeout)
                    .map_err(ConnectorError::from)
                    .inspect(|res| tracing::debug!(?res, "transaction tracking done"))
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
        Ok(Err(ConnectorError::ClientError(kind.into())))
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
        assert_eq!(Some(true), nonce_consumed(&rpc_refusal("NONCE_TOO_LOW"), false));
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
        // NONCE_TOO_HIGH reaches here only after its single retry was refused as well
        for code in ["NONCE_TOO_HIGH", "ALREADY_KNOWN", "RPC_ERROR"] {
            assert_eq!(None, nonce_consumed(&rpc_refusal(code), false), "{code}");
        }
        assert_eq!(None, nonce_consumed(&failed(ErrorKind::Timeout), false), "transport");
    }

    /// Runs [`submit_with_nonce_retry`] with `outcomes` as the results of successive attempts.
    ///
    /// Returns the nonces the attempts were signed with, the final local nonce and the result.
    async fn run_retry(first_nonce: u64, pending: u64, outcomes: Vec<Submission>) -> (Vec<u64>, u64, Submission) {
        run_retry_from(first_nonce, pending, pending, outcomes).await
    }

    /// Like [`run_retry`], with `first_pending` read at the start and `pending` re-read after the refusal.
    async fn run_retry_from(
        first_nonce: u64,
        first_pending: u64,
        pending: u64,
        outcomes: Vec<Submission>,
    ) -> (Vec<u64>, u64, Submission) {
        let used = std::sync::Mutex::new(Vec::new());
        let outcomes = std::sync::Mutex::new(outcomes.into_iter());
        let local = AtomicU64::new(first_nonce);
        let result = submit_with_nonce_retry(
            first_nonce,
            first_pending,
            &local,
            |nonce| {
                used.lock().unwrap().push(nonce);
                let outcome = outcomes.lock().unwrap().next().expect("unexpected extra attempt");
                async move { outcome }
            },
            || async move { Ok(pending) },
        )
        .await;
        let used = used.into_inner().unwrap();
        (used, local.load(std::sync::atomic::Ordering::Relaxed), result)
    }

    #[tokio::test]
    async fn too_high_nonce_is_resubmitted_once_with_the_pending_count() {
        let (used, local, result) = run_retry(9, 5, vec![rpc_refusal("NONCE_TOO_HIGH"), Ok(Ok("tx-1".into()))]).await;

        assert_eq!(vec![9, 5], used, "re-signed with the re-read nonce");
        assert_eq!(5, local, "pending count adopted as the local nonce");
        assert_eq!(Some(true), nonce_consumed(&result, false));
    }

    #[tokio::test]
    async fn too_high_nonce_never_retries_below_the_first_pending_count() {
        let (used, local, _) =
            run_retry_from(9, 7, 5, vec![rpc_refusal("NONCE_TOO_HIGH"), Ok(Ok("tx-1".into()))]).await;

        assert_eq!(vec![9, 7], used, "re-signed with the larger pending count");
        assert_eq!(7, local, "the lower re-read count is not adopted");
    }

    #[tokio::test]
    async fn too_high_nonce_is_not_resigned_when_pending_reaches_it() {
        let (used, local, result) = run_retry_from(9, 9, 5, vec![rpc_refusal("NONCE_TOO_HIGH")]).await;

        assert_eq!(vec![9], used, "same nonce is not signed again");
        assert_eq!(9, local);
        assert_eq!(None, nonce_consumed(&result, false));
    }

    #[tokio::test]
    async fn too_high_nonce_is_not_retried_twice() {
        let (used, local, result) =
            run_retry(9, 5, vec![rpc_refusal("NONCE_TOO_HIGH"), rpc_refusal("NONCE_TOO_HIGH")]).await;

        assert_eq!(vec![9, 5], used);
        assert_eq!(5, local);
        assert_eq!(None, nonce_consumed(&result, false), "left for a re-read");
    }

    #[tokio::test]
    async fn other_refusals_and_successes_are_not_resubmitted() {
        for code in [
            "NONCE_TOO_LOW",
            "REPLACEMENT_UNDERPRICED",
            "FEE_TOO_LOW",
            "INSUFFICIENT_FUNDS",
            "ALREADY_KNOWN",
        ] {
            let (used, local, _) = run_retry(9, 5, vec![rpc_refusal(code)]).await;
            assert_eq!(vec![9], used, "{code}");
            assert_eq!(9, local, "{code}");
        }
        let (used, local, _) = run_retry(9, 5, vec![Ok(Ok("tx-1".into()))]).await;
        assert_eq!((vec![9], 9), (used, local));
    }

    #[tokio::test]
    async fn too_high_nonce_is_returned_when_the_pending_count_cannot_be_read() {
        let used = std::sync::Mutex::new(Vec::new());
        let local = AtomicU64::new(9);
        let result = submit_with_nonce_retry(
            9,
            5,
            &local,
            |nonce| {
                used.lock().unwrap().push(nonce);
                async { rpc_refusal("NONCE_TOO_HIGH") }
            },
            || async { Err(ConnectorError::ServerNotHealthy) },
        )
        .await;

        assert_eq!(vec![9], used.into_inner().unwrap());
        assert_eq!(9, local.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(None, nonce_consumed(&result, false));
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
}
