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

use crate::{
    errors::{self, ConnectorError},
    utils::model_to_chain_info,
};

type TxRequest<T> = (
    T,
    Option<ChainKeypair>,
    futures::channel::oneshot::Sender<errors::Result<blokli_client::api::TxId>>,
);

/// A processed [`TxRequest`], carrying what the nonce bookkeeping needs after the submission.
struct SequencedTx {
    res: errors::Result<blokli_client::api::TxId>,
    /// `false` if it failed before reaching Blokli, so its nonce cannot have been used.
    submitted: bool,
    signer_addr: Address,
    notifier: futures::channel::oneshot::Sender<errors::Result<blokli_client::api::TxId>>,
}

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

// How long the local nonce may stay ahead of an unchanging pending count before it is resynced.
// Matches Blokli's tracking timeout, after which Blokli has given up on the transaction too.
const NONCE_GAP_TOLERANCE: Duration = Duration::from_mins(5);

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
    R: SignableTransaction + Send + Sync + 'static,
{
    pub fn new(signer: ChainKeypair, client: std::sync::Arc<C>) -> Self {
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

        let current_nonce_clone = current_nonce.clone();
        hopr_utils::runtime::prelude::spawn(
            receiver
                .then(move |(tx, tx_signer, notifier): (R, _, _)| {
                    let client = client_clone.clone();
                    let signer = tx_signer.unwrap_or_else(|| signer.clone());
                    let signer_addr = signer.public().to_address();
                    let current_nonce = current_nonce.clone();
                    let nonce_gaps = nonce_gaps.clone();
                    async move {
                        let signed_tx = async {
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
                                sync_nonce(&local_nonce, &nonce_gaps, signer_addr, pending, NONCE_GAP_TOLERANCE);
                            tracing::debug!(nonce, signer = %signer_addr, "nonce used for the tx");

                            let tx = tx
                                .sign_and_encode_to_eip2718(nonce, chain_id, gas_estimation.into(), &signer)
                                .await?;
                            tracing::debug!(nonce, signer = %signer_addr, "submitting transaction");
                            Ok::<_, ConnectorError>(tx)
                        }
                        .await;

                        let (res, submitted) = match signed_tx {
                            Ok(tx) => (
                                client.submit_and_track_transaction(&tx).map_err(ConnectorError::from).await,
                                true,
                            ),
                            Err(e) => (Err(e), false),
                        };
                        SequencedTx {
                            res,
                            submitted,
                            signer_addr,
                            notifier,
                        }
                    }
                })
                .for_each(move |SequencedTx { res, submitted, signer_addr, notifier }| {
                    let deduplicated = res
                        .as_ref()
                        .is_ok_and(|tx_id| !record_issued_tx_id(&issued_tx_ids, tx_id));
                    match nonce_consumed(&res, submitted, deduplicated) {
                        Some(true) => {
                            let prev_nonce = current_nonce_clone
                                .entry(signer_addr)
                                .or_default()
                                .value()
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                            tracing::debug!(prev_nonce, signer = %signer_addr, ?res, "nonce incremented due to tx success or rejection");
                        }
                        Some(false) => tracing::debug!(signer = %signer_addr, deduplicated, ?res, "nonce not consumed"),
                        None => {
                            current_nonce_clone.invalidate(&signer_addr);
                            tracing::warn!(
                                signer = %signer_addr,
                                ?res,
                                "unknown whether the nonce was consumed, re-reading it from the chain"
                            );
                        }
                    }
                    if notifier.send(res).is_err() {
                        tracing::debug!(
                            "failed to notify transaction result - the caller may not want to await the result \
                             anymore."
                        );
                    }
                    futures::future::ready(())
                })
                .inspect(|_| tracing::warn!("transaction sequencer queue stopped")),
        );

        Self { sender, client }
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
fn nonce_consumed(res: &errors::Result<blokli_client::api::TxId>, submitted: bool, deduplicated: bool) -> Option<bool> {
    let error = match res {
        Ok(_) => return Some(!deduplicated),
        Err(_) if !submitted => return Some(false),
        Err(error) => error,
    };
    if error.is_refused_before_broadcast() {
        return Some(false);
    }
    match error.rpc_rejection_code() {
        Some("NONCE_TOO_LOW" | "REPLACEMENT_UNDERPRICED") => Some(true),
        Some("FEE_TOO_LOW" | "INSUFFICIENT_FUNDS") => Some(false),
        // NONCE_TOO_HIGH, unverified ALREADY_KNOWN, unclassified RPC errors, transport failures
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

    fn failed(kind: ErrorKind) -> errors::Result<blokli_client::api::TxId> {
        Err(ConnectorError::ClientError(kind.into()))
    }

    fn rpc_refusal(code: &str) -> errors::Result<blokli_client::api::TxId> {
        failed(ErrorKind::BlokliError {
            kind: "rpc error",
            code: code.into(),
            message: "refused by the rpc node".into(),
        })
    }

    #[test]
    fn nonce_is_consumed_by_a_broadcast_tx_or_a_competing_one() {
        assert_eq!(Some(true), nonce_consumed(&Ok("tx-1".into()), true, false));
        assert_eq!(Some(true), nonce_consumed(&rpc_refusal("NONCE_TOO_LOW"), true, false));
        assert_eq!(
            Some(true),
            nonce_consumed(&rpc_refusal("REPLACEMENT_UNDERPRICED"), true, false)
        );
    }

    #[test]
    fn nonce_is_not_consumed_when_nothing_got_into_the_mempool() {
        assert_eq!(
            Some(false),
            nonce_consumed(&Ok("tx-1".into()), true, true),
            "deduplicated"
        );
        assert_eq!(
            Some(false),
            nonce_consumed(&Err(ConnectorError::ServerNotHealthy), false, false),
            "failed before submission"
        );
        assert_eq!(Some(false), nonce_consumed(&rpc_refusal("FEE_TOO_LOW"), true, false));
        assert_eq!(
            Some(false),
            nonce_consumed(&rpc_refusal("INSUFFICIENT_FUNDS"), true, false)
        );
        let overloaded = failed(ErrorKind::BlokliError {
            kind: "overloaded",
            code: "OVERLOADED".into(),
            message: "too many tracked transactions".into(),
        });
        assert_eq!(Some(false), nonce_consumed(&overloaded, true, false));
    }

    #[test]
    fn nonce_consumption_is_unknown_when_the_result_does_not_tell() {
        for code in ["NONCE_TOO_HIGH", "ALREADY_KNOWN", "RPC_ERROR"] {
            assert_eq!(None, nonce_consumed(&rpc_refusal(code), true, false), "{code}");
        }
        assert_eq!(
            None,
            nonce_consumed(&failed(ErrorKind::Timeout), true, false),
            "transport"
        );
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
