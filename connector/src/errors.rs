use blokli_client::{
    api::types::TransactionDiagnosis,
    errors::{BlokliClientError, ErrorKind, RefusalCode, TrackingErrorKind},
};
use hopr_api::types::{internal::prelude::ChannelId, primitive::prelude::Address};
use thiserror::Error;

/// Back-off suggested when Blokli reports it is overloaded, as it gives no explicit delay.
pub const BLOKLI_OVERLOADED_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("invalid arguments: {0}")]
    InvalidArguments(&'static str),

    #[error("invalid state: {0}")]
    InvalidState(&'static str),

    #[error("blokli server is not healthy")]
    ServerNotHealthy,

    #[error("account {0} does not exist")]
    AccountDoesNotExist(String),

    #[error("safe {0} does not exist")]
    SafeDoesNotExist(Address),

    #[error("channel {0} does not exist")]
    ChannelDoesNotExist(ChannelId),

    #[error("ticket is invalid or does not match the channel")]
    InvalidTicket,

    #[error("channel {0} is closed")]
    ChannelClosed(ChannelId),

    #[error("inner safe transaction failed: {0}")]
    InnerTxFailed(String),

    #[error("type conversion error: {0}")]
    TypeConversion(String),

    #[error("timeout while waiting for the graph to be synced")]
    ConnectionTimeout,

    #[error("backend error: {0}")]
    BackendError(#[source] anyhow::Error),

    #[error(transparent)]
    CacheError(#[from] std::sync::Arc<Self>),

    #[error(transparent)]
    ClientError(#[from] blokli_client::errors::BlokliClientError),

    #[error(transparent)]
    GeneralError(#[from] hopr_api::types::primitive::errors::GeneralError),

    #[error(transparent)]
    ChainTypesError(#[from] hopr_api::types::chain::errors::ChainTypesError),

    #[error(transparent)]
    CoreTypesError(#[from] hopr_api::types::internal::errors::CoreTypesError),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error("undefined error: {0}")]
    OtherError(#[source] anyhow::Error),
}

impl ConnectorError {
    /// Indicates whether this error was caused by the transaction actually being rejected
    /// by the target blockchain and returns the errors.
    pub fn as_transaction_rejection_error(&self) -> Option<&TrackingErrorKind> {
        match self.client_error_kind()? {
            ErrorKind::TrackingError(e @ TrackingErrorKind::Reverted)
            | ErrorKind::TrackingError(e @ TrackingErrorKind::ValidationFailed) => Some(e),
            _ => None,
        }
    }

    /// Returns the decoded `(operation, reason)` if Blokli refused a HOPR action before
    /// broadcasting it, because the indexed chain state contradicts one of its preconditions.
    ///
    /// Such a refusal is permanent: submitting the same action again is futile until the
    /// on-chain state changes. Nothing was broadcast, so no nonce was consumed.
    pub fn as_hopr_action_rejection(&self) -> Option<(&str, &str)> {
        match self.client_error_kind()? {
            ErrorKind::HoprActionRejected { operation, reason, .. } => Some((operation.as_str(), reason.as_str())),
            _ => None,
        }
    }

    /// Returns how long to back off before resubmitting, if Blokli temporarily refused the
    /// transaction without broadcasting it.
    ///
    /// This covers both a throttled HOPR action (repeated invalid submissions from this signer)
    /// and an overloaded Blokli. The latter carries no explicit delay, so
    /// [`BLOKLI_OVERLOADED_RETRY_AFTER`] is returned for it.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        match self.client_error_kind()? {
            ErrorKind::HoprActionThrottled { retry_after, .. } => Some(*retry_after),
            ErrorKind::BlokliError { kind: "overloaded", .. } => Some(BLOKLI_OVERLOADED_RETRY_AFTER),
            _ => None,
        }
    }

    /// Indicates whether Blokli refused the transaction *before* broadcasting it, so that it
    /// did not consume a nonce.
    pub fn is_refused_before_broadcast(&self) -> bool {
        self.as_hopr_action_rejection().is_some()
            || self.retry_after().is_some()
            || matches!(
                self.client_error_kind(),
                Some(ErrorKind::BlokliError {
                    kind: "contract not allowed" | "function not allowed",
                    ..
                })
            )
    }

    /// Returns Blokli's classification of the RPC node's refusal to broadcast, such as
    /// [`RefusalCode::NonceTooLow`].
    ///
    /// A code this client version does not know is returned as [`RefusalCode::Unknown`].
    pub fn rpc_rejection_code(&self) -> Option<RefusalCode> {
        match self.client_error_kind()? {
            ErrorKind::BlokliError {
                kind: "rpc error",
                code,
                ..
            } => Some(RefusalCode::from(code.as_str())),
            _ => None,
        }
    }

    /// Returns Blokli's explanation of why a timed out transaction was not mined, if it gave one.
    ///
    /// Only the timeout of a tracked transaction can carry one, and only when Blokli serves diagnoses.
    /// The transaction was broadcast: this is no refusal, and the nonce it used is not free. See
    /// [`ConnectorError::unmined_retry_after`] for the delay Blokli suggests.
    pub fn unmined_diagnosis(&self) -> Option<&TransactionDiagnosis> {
        self.blokli_client_error()?.unmined_diagnosis()
    }

    /// Returns how long Blokli suggests to wait before checking or retrying a timed out, unmined transaction.
    ///
    /// `None` when Blokli gave no diagnosis or a hint of zero seconds: no hint means no back-off.
    ///
    /// This is deliberately not part of [`ConnectorError::retry_after`]. That one describes a refusal before
    /// broadcast, from which [`ConnectorError::is_refused_before_broadcast`] concludes that the nonce was not
    /// consumed. A timed out transaction was broadcast and may still be mined.
    pub fn unmined_retry_after(&self) -> Option<std::time::Duration> {
        let seconds = self.unmined_diagnosis()?.retry_after_seconds;
        (seconds > 0).then(|| std::time::Duration::from_secs(u64::from(seconds)))
    }

    /// The underlying Blokli client error, looking through cached errors.
    fn blokli_client_error(&self) -> Option<&BlokliClientError> {
        match self {
            ConnectorError::ClientError(client_error) => Some(client_error),
            ConnectorError::CacheError(inner) => inner.blokli_client_error(),
            _ => None,
        }
    }

    /// The underlying Blokli client error kind, looking through cached errors.
    fn client_error_kind(&self) -> Option<&ErrorKind> {
        self.blokli_client_error().map(BlokliClientError::kind)
    }

    pub fn other(e: impl Into<anyhow::Error>) -> Self {
        Self::OtherError(e.into())
    }

    pub fn backend(e: impl Into<anyhow::Error>) -> Self {
        Self::BackendError(e.into())
    }

    pub fn io(e: impl Into<std::io::Error>) -> Self {
        Self::IoError(e.into())
    }
}

pub type Result<T> = std::result::Result<T, ConnectorError>;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn client_error(kind: ErrorKind) -> ConnectorError {
        ConnectorError::ClientError(kind.into())
    }

    #[test]
    fn hopr_action_rejection_is_permanent_and_not_broadcast() {
        let error = client_error(ErrorKind::HoprActionRejected {
            operation: "finalize_channel_closure".into(),
            reason: "closure_time_not_elapsed".into(),
            message: "too early".into(),
        });

        assert_eq!(
            Some(("finalize_channel_closure", "closure_time_not_elapsed")),
            error.as_hopr_action_rejection()
        );
        assert_eq!(None, error.retry_after());
        assert!(error.is_refused_before_broadcast());
        assert!(error.as_transaction_rejection_error().is_none());
    }

    #[test]
    fn hopr_action_throttle_is_transient_and_not_broadcast() {
        let error = client_error(ErrorKind::HoprActionThrottled {
            operation: "finalize_channel_closure".into(),
            reason: "closure_time_not_elapsed".into(),
            retry_after: Duration::from_secs(42),
            message: "slow down".into(),
        });

        assert_eq!(Some(Duration::from_secs(42)), error.retry_after());
        assert!(error.as_hopr_action_rejection().is_none());
        assert!(error.is_refused_before_broadcast());
        assert!(error.as_transaction_rejection_error().is_none());
    }

    #[test]
    fn blokli_overload_is_transient_and_not_broadcast() {
        let error = client_error(ErrorKind::BlokliError {
            kind: "overloaded",
            code: "OVERLOADED".into(),
            message: "too many tracked transactions".into(),
        });

        assert_eq!(Some(BLOKLI_OVERLOADED_RETRY_AFTER), error.retry_after());
        assert!(error.is_refused_before_broadcast());
    }

    #[test]
    fn other_errors_are_not_policy_refusals() {
        let error = client_error(ErrorKind::TrackingError(TrackingErrorKind::Reverted));

        assert!(!error.is_refused_before_broadcast());
        assert!(error.as_transaction_rejection_error().is_some());
        assert!(!ConnectorError::InvalidTicket.is_refused_before_broadcast());
    }

    #[test]
    fn contract_and_function_policy_refusals_are_not_broadcast() {
        for kind in ["contract not allowed", "function not allowed"] {
            let error = client_error(ErrorKind::BlokliError {
                kind,
                code: "NOT_ALLOWED".into(),
                message: "not allowed".into(),
            });

            assert!(error.is_refused_before_broadcast(), "{kind}");
            assert_eq!(None, error.rpc_rejection_code(), "{kind}");
        }
    }

    #[test]
    fn rpc_refusal_code_is_seen_through_cached_errors() {
        let error = ConnectorError::CacheError(std::sync::Arc::new(client_error(ErrorKind::BlokliError {
            kind: "rpc error",
            code: "NONCE_TOO_HIGH".into(),
            message: "nonce too high".into(),
        })));

        assert_eq!(Some(RefusalCode::NonceTooHigh), error.rpc_rejection_code());
        assert!(!error.is_refused_before_broadcast());
        assert_eq!(None, client_error(ErrorKind::Timeout).rpc_rejection_code());
    }

    #[test]
    fn policy_refusals_are_seen_through_cached_errors() {
        let error = ConnectorError::CacheError(std::sync::Arc::new(client_error(ErrorKind::HoprActionRejected {
            operation: "redeem_ticket".into(),
            reason: "ticket_index_already_redeemed".into(),
            message: "already redeemed".into(),
        })));

        assert!(error.as_hopr_action_rejection().is_some());
    }

    async fn timed_out_error(retry_after_seconds: u32) -> ConnectorError {
        use blokli_client::{
            BlokliTestClient, BlokliTestState, NopStateMutator,
            api::{
                BlokliTransactionClient,
                types::{TransactionStatus, UnminedReason},
            },
        };

        let client = BlokliTestClient::new(BlokliTestState::default(), NopStateMutator)
            .with_tx_simulation_delay(Duration::from_millis(1));
        let tx_id = client.submit_and_track_transaction(&[0x02]).await.unwrap();
        let client = client.with_unmined_diagnosis(
            tx_id.clone(),
            TransactionDiagnosis {
                reason: UnminedReason::Underpriced,
                signed_fees: None,
                recommended_fees: None,
                min_replacement_fees: None,
                retry_after_seconds,
            },
        );
        client.hidden_state_update(|state| {
            state.active_txs.get_mut(&tx_id).expect("tracked").status = TransactionStatus::Timeout;
        });

        ConnectorError::from(
            client
                .track_transaction(tx_id, Duration::from_secs(1))
                .await
                .expect_err("the transaction timed out"),
        )
    }

    #[tokio::test]
    async fn diagnosed_timeout_exposes_its_hint_but_is_not_a_refusal() {
        let error = timed_out_error(30).await;

        assert_eq!(Some(Duration::from_secs(30)), error.unmined_retry_after());
        assert!(error.unmined_diagnosis().is_some());
        // the transaction was broadcast: its nonce is consumed and no refusal back-off applies
        assert!(!error.is_refused_before_broadcast());
        assert_eq!(None, error.retry_after());
        assert!(error.as_transaction_rejection_error().is_none());
    }

    #[tokio::test]
    async fn diagnosis_is_seen_through_cached_errors() {
        let error = ConnectorError::CacheError(std::sync::Arc::new(timed_out_error(12).await));

        assert_eq!(Some(Duration::from_secs(12)), error.unmined_retry_after());
        assert!(!error.is_refused_before_broadcast());
    }

    #[tokio::test]
    async fn zero_second_hint_means_no_back_off() {
        let error = timed_out_error(0).await;

        assert!(error.unmined_diagnosis().is_some());
        assert_eq!(None, error.unmined_retry_after());
    }

    #[test]
    fn timeout_without_diagnosis_has_no_back_off() {
        let error = client_error(ErrorKind::TrackingError(TrackingErrorKind::Timeout));

        assert!(error.unmined_diagnosis().is_none());
        assert_eq!(None, error.unmined_retry_after());
        assert!(!ConnectorError::InvalidTicket.unmined_diagnosis().is_some());
    }
}
