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
//!
//! A snapshot holds only channels that are not closed, so a channel that closed while no update was received is
//! missing from it and nothing says so. Blokli sets the cursor on the last entry of a snapshot and on no other entry
//! of it, which marks where the snapshot ends. The stream reports that point together with the channels the snapshot
//! held, so the channels that the connector knows but the snapshot did not hold can be checked.

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
use hopr_api::{
    chain::{AccountEntry, ChannelEntry},
    types::internal::prelude::ChannelId,
};

use crate::{errors::ConnectorError, utils::model_to_graph_entry};

/// Delay before the second restart in a row, doubled for every further one.
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

/// What the graph subscription yields.
#[allow(clippy::large_enum_variant)]
pub(crate) enum GraphUpdate {
    /// A converted entry.
    Entry(GraphItem),
    /// The snapshot a subscription started with has been delivered completely. Holds the ids of its channels.
    ///
    /// It is never sent for a snapshot that was cut short by a failing entry or the end of the stream, and not for a
    /// snapshot without entries, which has no last entry to carry the cursor.
    SnapshotComplete(HashSet<ChannelId>),
}

type RawGraphStream<'a> = BoxStream<'a, Result<OpenedChannelsGraphEntry, BlokliClientError>>;

struct State<'a, C> {
    client: &'a C,
    /// The health of the subscription that is running now, shared with the connector's health checks.
    health: Arc<parking_lot::Mutex<SubscriptionHealthHandle>>,
    stream: Option<RawGraphStream<'a>>,
    started: Instant,
    restarts: u32,
    /// Whether the entries arriving now belong to the snapshot a subscription starts with.
    in_snapshot: bool,
    /// The channels of that snapshot so far.
    snapshot: HashSet<ChannelId>,
    /// Whether the snapshot held an entry that could be neither converted nor identified, so its channels are not
    /// all known.
    snapshot_incomplete: bool,
    /// An update that is yielded before the next entry is read.
    queued: Option<GraphUpdate>,
    /// Channels whose entry failed conversion and caused a restart, and that have not converted since.
    failed_conversions: HashSet<String>,
}

impl<C> State<'_, C> {
    /// Starts collecting the channels of a snapshot.
    fn begin_snapshot(&mut self) {
        self.in_snapshot = true;
        self.snapshot.clear();
        self.snapshot_incomplete = false;
    }

    /// Records an entry of the snapshot in progress, and ends the snapshot when the entry is its last.
    ///
    /// `id` is the channel of the entry, or `None` when it could not be identified. A snapshot with such an entry
    /// cannot tell which channels it holds, so it is not reported.
    fn observe_snapshot_entry(&mut self, id: Option<ChannelId>, ends_snapshot: bool) {
        if !self.in_snapshot {
            return;
        }
        match id {
            Some(id) => {
                self.snapshot.insert(id);
            }
            None => self.snapshot_incomplete = true,
        }
        if ends_snapshot {
            self.in_snapshot = false;
            let snapshot = std::mem::take(&mut self.snapshot);
            if std::mem::take(&mut self.snapshot_incomplete) {
                tracing::warn!("graph snapshot held an unidentifiable entry, so it is not used to close channels");
            } else {
                self.queued = Some(GraphUpdate::SnapshotComplete(snapshot));
            }
        }
    }

    /// Drops the running subscription so the next poll starts a new one, and updates the pacing.
    fn restart(&mut self) {
        // Dropping the stream makes blokli-client mark its handle as ended. That is not a failure of the
        // subscription, so the health checks must not see it: they get an untracked handle until the new
        // subscription has one.
        {
            let mut health = self.health.lock();
            *health = SubscriptionHealthHandle::untracked(health.subscription().name());
        }
        self.stream = None;
        self.begin_snapshot();
        self.restarts = if self.started.elapsed() >= RESYNC_HEALTHY_AFTER {
            1
        } else {
            self.restarts.saturating_add(1)
        };
    }

    /// Like [`restart`](Self::restart), after the start of a new subscription failed. The failed start counts as a
    /// short-lived subscription, so that repeated failures keep backing off.
    fn restart_after_failed_start(&mut self) {
        self.started = Instant::now();
        self.restart();
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
) -> impl Stream<Item = Result<GraphUpdate, ConnectorError>> + Send + 'a
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
        in_snapshot: true,
        snapshot: HashSet::new(),
        snapshot_incomplete: false,
        queued: None,
        failed_conversions: HashSet::new(),
    };

    futures::stream::unfold(state, |mut state| async move {
        loop {
            if let Some(update) = state.queued.take() {
                return Some((Ok(update), state));
            }
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
                        state.begin_snapshot();
                    }
                    Err(error) => {
                        state.restart_after_failed_start();
                        return Some((Err(ConnectorError::from(error)), state));
                    }
                }
                continue;
            };

            match stream.next().await {
                Some(Ok(entry)) => {
                    tracing::trace!(?entry, "new graph event");
                    let ends_snapshot = entry.cursor.is_some();
                    // Updates, resumed entries and the last entry of a snapshot carry a cursor, the other entries
                    // of a snapshot do not. So an entry without one, while no snapshot is in progress, is the start
                    // of a snapshot that blokli-client began on its own, after it lost or rejected its position.
                    if !state.in_snapshot && !ends_snapshot {
                        tracing::debug!("graph snapshot started by the client");
                        state.begin_snapshot();
                    }
                    let channel_id = entry.channel.concrete_channel_id.clone();
                    match model_to_graph_entry(entry) {
                        Ok(item) => {
                            conversion_succeeded(&mut state.failed_conversions, &channel_id);
                            state.observe_snapshot_entry(Some(*item.2.get_id()), ends_snapshot);
                            return Some((Ok(GraphUpdate::Entry(item)), state));
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
                                // The channel is in the snapshot even though it cannot be converted.
                                state.observe_snapshot_entry(channel_id.parse().ok(), ends_snapshot);
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

    fn state_with<'a>(
        client: &'a (),
        stream: Option<RawGraphStream<'a>>,
        health: SubscriptionHealthHandle,
    ) -> State<'a, ()> {
        State {
            client,
            health: Arc::new(parking_lot::Mutex::new(health)),
            stream,
            started: Instant::now(),
            restarts: 0,
            in_snapshot: true,
            snapshot: HashSet::new(),
            snapshot_incomplete: false,
            queued: None,
            failed_conversions: HashSet::new(),
        }
    }

    #[test]
    fn restarting_does_not_leave_an_ended_handle_for_the_health_check() {
        use blokli_client::{
            BlokliClient, BlokliClientConfig, SubscriptionEnd, SubscriptionStatus, api::BlokliSubscriptionClient,
        };

        let client = BlokliClient::new("http://localhost:1".parse().unwrap(), BlokliClientConfig::default());
        let (stream, health) = client.subscribe_graph_with_health().unwrap();
        let name = health.subscription().name();
        let observer = health.clone();
        let mut state = state_with(&(), Some(stream.boxed()), health);

        state.restart();

        // the dropped stream ended its own handle, which nobody observes any more
        assert_eq!(
            SubscriptionStatus::Ended(SubscriptionEnd::Cancelled),
            observer.get().status
        );
        let shared = state.health.lock().clone();
        assert_eq!(name, shared.subscription().name());
        assert_eq!(SubscriptionStatus::Untracked, shared.get().status);
    }

    #[test]
    fn failed_starts_keep_backing_off_after_a_long_lived_subscription() {
        let mut state = state_with(&(), None, SubscriptionHealthHandle::untracked("graph"));
        state.started = Instant::now() - RESYNC_HEALTHY_AFTER - Duration::from_secs(1);
        state.restarts = 0;

        state.restart();
        assert_eq!(Duration::ZERO, resync_delay(state.restarts));

        // the immediate restart failed to subscribe
        state.restart_after_failed_start();
        assert_eq!(Duration::from_secs(5), resync_delay(state.restarts));
        state.restart_after_failed_start();
        assert_eq!(Duration::from_secs(10), resync_delay(state.restarts));
    }

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

    fn state() -> State<'static, ()> {
        State {
            client: &(),
            health: Arc::new(parking_lot::Mutex::new(SubscriptionHealthHandle::untracked("graph"))),
            stream: None,
            started: Instant::now(),
            restarts: 0,
            in_snapshot: true,
            snapshot: HashSet::new(),
            snapshot_incomplete: false,
            queued: None,
            failed_conversions: HashSet::new(),
        }
    }

    fn id(n: u8) -> ChannelId {
        ChannelId::from(hopr_api::types::crypto::prelude::Hash::from([n; 32]))
    }

    #[test]
    fn a_snapshot_is_reported_with_its_channels_when_its_last_entry_arrives() {
        let mut state = state();
        state.observe_snapshot_entry(Some(id(1)), false);
        state.observe_snapshot_entry(Some(id(2)), false);
        assert!(state.queued.is_none());

        state.observe_snapshot_entry(Some(id(3)), true);

        match state.queued.take() {
            Some(GraphUpdate::SnapshotComplete(seen)) => assert_eq!(HashSet::from([id(1), id(2), id(3)]), seen),
            _ => panic!("the snapshot was not reported"),
        }
        assert!(!state.in_snapshot);
    }

    #[test]
    fn entries_after_a_snapshot_are_not_part_of_it() {
        let mut state = state();
        state.observe_snapshot_entry(Some(id(1)), true);
        state.queued = None;

        state.observe_snapshot_entry(Some(id(2)), true);

        assert!(state.queued.is_none());
    }

    #[test]
    fn a_snapshot_with_an_unidentifiable_entry_is_not_reported() {
        let mut state = state();
        state.observe_snapshot_entry(Some(id(1)), false);
        state.observe_snapshot_entry(None, false);
        state.observe_snapshot_entry(Some(id(2)), true);

        assert!(state.queued.is_none());
        assert!(!state.in_snapshot);

        // the next snapshot starts clean
        state.begin_snapshot();
        state.observe_snapshot_entry(Some(id(1)), true);
        assert!(matches!(state.queued, Some(GraphUpdate::SnapshotComplete(_))));
    }

    #[test]
    fn a_channel_id_survives_the_round_trip_through_its_text() {
        let original = id(7);
        assert_eq!(Ok(original), original.to_string().parse::<ChannelId>());
    }

    #[test]
    fn the_delay_is_capped() {
        assert_eq!(RESYNC_BACKOFF_MAX, resync_delay(30));
        assert_eq!(RESYNC_BACKOFF_MAX, resync_delay(u32::MAX));
    }
}
