//! A graph subscription that starts over from a full snapshot when it cannot be trusted any more.
//!
//! The graph subscription resumes after the last cursor it delivered, so a reconnect inside blokli-client never
//! resends an entry that was already handed out. Two situations therefore need a new subscription, which begins with
//! a full snapshot:
//!
//! - an entry fails conversion: it was handed out and is gone, so the channel stays unknown or keeps an old state;
//! - the stream ends: nothing feeds the channel view any more.
//!
//! Starts are paced by [`resync_delay`], so a stream that keeps ending does not turn into a busy loop. A restart
//! replays the state of every subscription that shares the client's connection, not just the graph. So an entry
//! causes at most one restart: if it fails again after that, Blokli serves malformed data for it, a restart cannot fix
//! that, and it is only logged until the entry converts.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use blokli_client::{
    BlokliClientError, SubscriptionHealthHandle,
    api::{BlokliSubscriptionClient, types::OpenedChannelsGraphEntry},
};
use futures::{Stream, StreamExt, stream::BoxStream};
use hopr_api::chain::{AccountEntry, ChannelEntry};

use crate::{errors::ConnectorError, utils::model_to_graph_entry};

/// Delay before the second start in a row, doubled for every further one.
const RESYNC_BACKOFF_INITIAL: Duration = Duration::from_secs(5);

/// Longest delay between two starts.
const RESYNC_BACKOFF_MAX: Duration = Duration::from_mins(5);

/// A subscription that lived this long without needing a restart counts as healthy, which resets the pacing.
const RESYNC_HEALTHY_AFTER: Duration = Duration::from_mins(5);

/// How long to wait before starting the graph subscription again.
///
/// `restarts` is the number of restarts in a row, including the one being scheduled. The first restart is immediate,
/// because a single lost entry should heal as soon as possible; a subscription that keeps needing restarts is paced.
pub(crate) fn resync_delay(restarts: u32) -> Duration {
    match restarts {
        0 | 1 => Duration::ZERO,
        n => RESYNC_BACKOFF_INITIAL
            .saturating_mul(1u32 << (n - 2).min(16))
            .min(RESYNC_BACKOFF_MAX),
    }
}

/// Whether a failed conversion of the channel `id` is worth a restart of the subscription.
///
/// A restart is worth it the first time an entry fails: the failure may come from an entry that is not served this
/// way any more. If the same channel fails again after a restart, restarting again would change nothing. The channel
/// stays on the list until it converts, which [`conversion_succeeded`] records.
fn restart_after_failed_conversion(failed: &mut HashSet<String>, id: &str) -> bool {
    failed.insert(id.to_owned())
}

/// Takes a channel off the list of failed conversions, so a later failure restarts the subscription once more.
fn conversion_succeeded(failed: &mut HashSet<String>, id: &str) {
    failed.remove(id);
}

/// An entry of the graph subscription, converted.
pub(crate) type GraphItem = (AccountEntry, AccountEntry, ChannelEntry);

type RawGraphStream<'a> = BoxStream<'a, Result<OpenedChannelsGraphEntry, BlokliClientError>>;

struct State<'a, C> {
    client: &'a C,
    /// The health of the subscription that is running now, shared with the connector's health checks.
    health: Arc<parking_lot::Mutex<SubscriptionHealthHandle>>,
    stream: Option<RawGraphStream<'a>>,
    started: Instant,
    restarts: u32,
    /// Channels whose entry failed conversion and caused a restart, and that have not converted since.
    failed_conversions: HashSet<String>,
}

impl<C> State<'_, C> {
    /// Drops the running subscription so the next poll starts a new one, and updates the pacing.
    fn restart(&mut self) {
        self.stream = None;
        self.restarts = if self.started.elapsed() >= RESYNC_HEALTHY_AFTER {
            1
        } else {
            self.restarts.saturating_add(1)
        };
    }
}

/// Wraps a graph subscription so that it is started again whenever an entry fails conversion or the stream ends.
///
/// `first` is the subscription the caller already opened, so that a failure to subscribe is reported to the caller.
/// The failing entry is still yielded as an error, so it is logged by the consumer. Errors from the stream itself are
/// passed through: blokli-client reconnects on its own for those.
///
/// The returned stream never ends. `health` always holds the handle of the subscription that is running.
pub(crate) fn resyncing_graph_stream<'a, C, S>(
    client: &'a C,
    first: S,
    health: Arc<parking_lot::Mutex<SubscriptionHealthHandle>>,
) -> impl Stream<Item = Result<GraphItem, ConnectorError>> + Send + 'a
where
    C: BlokliSubscriptionClient + Send + Sync,
    S: Stream<Item = Result<OpenedChannelsGraphEntry, BlokliClientError>> + Send + 'a,
{
    let state = State {
        client,
        health,
        stream: Some(first.boxed()),
        started: Instant::now(),
        restarts: 0,
        failed_conversions: HashSet::new(),
    };

    futures::stream::unfold(state, |mut state| async move {
        loop {
            let Some(stream) = state.stream.as_mut() else {
                let delay = resync_delay(state.restarts);
                if !delay.is_zero() {
                    tracing::warn!(
                        ?delay,
                        restarts = state.restarts,
                        "delaying the restart of the graph subscription"
                    );
                    futures_time::task::sleep(futures_time::time::Duration::from(delay)).await;
                }
                match state.client.subscribe_graph_with_health() {
                    Ok((stream, health)) => {
                        tracing::info!("graph subscription restarted from a full snapshot");
                        *state.health.lock() = health;
                        state.stream = Some(stream.boxed());
                        state.started = Instant::now();
                    }
                    Err(error) => {
                        state.restart();
                        return Some((Err(ConnectorError::from(error)), state));
                    }
                }
                continue;
            };

            match stream.next().await {
                Some(Ok(entry)) => {
                    tracing::trace!(?entry, "new graph event");
                    let channel_id = entry.channel.concrete_channel_id.clone();
                    match model_to_graph_entry(entry) {
                        Ok(item) => {
                            conversion_succeeded(&mut state.failed_conversions, &channel_id);
                            return Some((Ok(item), state));
                        }
                        Err(error) => {
                            if restart_after_failed_conversion(&mut state.failed_conversions, &channel_id) {
                                tracing::warn!(%error, %channel_id, "graph entry failed conversion, restarting the graph subscription");
                                state.restart();
                            } else {
                                tracing::error!(
                                    %error, %channel_id,
                                    "graph entry fails conversion again after a restart, blokli serves it malformed"
                                );
                            }
                            return Some((Err(error), state));
                        }
                    }
                }
                Some(Err(error)) => return Some((Err(ConnectorError::from(error)), state)),
                None => {
                    tracing::warn!("graph subscription ended, restarting it");
                    state.restart();
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_restart_is_immediate_and_later_ones_back_off() {
        assert_eq!(Duration::ZERO, resync_delay(0));
        assert_eq!(Duration::ZERO, resync_delay(1));
        assert_eq!(Duration::from_secs(5), resync_delay(2));
        assert_eq!(Duration::from_secs(10), resync_delay(3));
        assert_eq!(Duration::from_secs(20), resync_delay(4));
    }

    #[test]
    fn a_channel_that_fails_again_after_a_restart_does_not_restart_the_subscription_again() {
        let mut failed = HashSet::new();
        assert!(restart_after_failed_conversion(&mut failed, "0xaa"));
        assert!(!restart_after_failed_conversion(&mut failed, "0xaa"));
        // another channel still gets its restart
        assert!(restart_after_failed_conversion(&mut failed, "0xbb"));
    }

    #[test]
    fn a_channel_that_converted_in_between_gets_a_restart_again() {
        let mut failed = HashSet::new();
        assert!(restart_after_failed_conversion(&mut failed, "0xaa"));
        conversion_succeeded(&mut failed, "0xaa");
        assert!(restart_after_failed_conversion(&mut failed, "0xaa"));
    }

    #[test]
    fn the_delay_is_capped() {
        assert_eq!(RESYNC_BACKOFF_MAX, resync_delay(30));
        assert_eq!(RESYNC_BACKOFF_MAX, resync_delay(u32::MAX));
    }
}
