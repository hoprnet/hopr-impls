use blokli_client::errors::{ErrorKind, TrackingErrorKind};
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
        self.as_hopr_action_rejection().is_some() || self.retry_after().is_some()
    }

    /// The underlying Blokli client error kind, looking through cached errors.
    fn client_error_kind(&self) -> Option<&ErrorKind> {
        match self {
            ConnectorError::ClientError(client_error) => Some(client_error.kind()),
            ConnectorError::CacheError(inner) => inner.client_error_kind(),
            _ => None,
        }
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
    fn policy_refusals_are_seen_through_cached_errors() {
        let error = ConnectorError::CacheError(std::sync::Arc::new(client_error(ErrorKind::HoprActionRejected {
            operation: "redeem_ticket".into(),
            reason: "ticket_index_already_redeemed".into(),
            message: "already redeemed".into(),
        })));

        assert!(error.as_hopr_action_rejection().is_some());
    }
}
