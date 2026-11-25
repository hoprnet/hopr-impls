//! Tests for how the connector keeps its channel view correct when the graph subscription drops an entry or ends.
//!
//! The tests assert that the connector recovers from lost updates by restarting the graph subscription, notices a
//! finished graph stream, and emits an event for every channel status change.
#![cfg(feature = "testing")]

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use blokli_client::{
    AccountSelector, BlokliClientError, BlokliQueryClient, BlokliSubscriptionClient, BlokliTransactionClient,
    ChainAddress, ChannelFilter, ChannelSelector, ModulePredictionInput, RedeemedStatsSelector, SafeSelector,
    ServiceSelector, ServiceTypeId, TicketSelector, TransactionTrackingOutcome, TxId, TxReceipt,
    types::{self, ChannelStatus as ModelChannelStatus, OpenedChannelsGraphEntry},
};
use futures::{StreamExt, stream::BoxStream};
use hopr_api::{
    chain::{ChainEvent, ChainEvents, ChainReadChannelOperations},
    types::{
        crypto::prelude::{ChainKeypair, Keypair, OffchainKeypair},
        internal::{
            channels::ChannelStatus,
            prelude::{AccountEntry, AccountType, ChannelEntry},
        },
        primitive::prelude::{Address, BytesRepresentable, HoprBalance, XDaiBalance},
    },
};
use hopr_chain_connector::{
    BlockchainConnectorConfig, create_trustful_hopr_blokli_connector, testing::BlokliTestStateBuilder,
};

type GraphResult = Result<OpenedChannelsGraphEntry, BlokliClientError>;

/// A client that serves everything from an inner test client, except the graph subscription.
///
/// The graph subscription is fed by the test through a channel, so a test chooses which entries arrive, in which
/// order, and when the stream ends (by dropping the sender).
struct ScriptedGraphClient<T> {
    inner: T,
    graph: Mutex<Option<futures::channel::mpsc::UnboundedReceiver<GraphResult>>>,
    graph_subscriptions: Arc<AtomicUsize>,
    /// What every later subscription replays first: the full, valid snapshot, as a fresh blokli subscription would.
    replay: Vec<OpenedChannelsGraphEntry>,
    /// Accounts that blokli reports and delivers on top of the inner client's, as the node receives them raw.
    extra_accounts: Vec<types::Account>,
}

#[async_trait::async_trait]
impl<T: BlokliQueryClient + Send + Sync> BlokliQueryClient for ScriptedGraphClient<T> {
    async fn count_accounts(&self, selector: AccountSelector) -> Result<u32, BlokliClientError> {
        Ok(self.inner.count_accounts(selector).await? + self.extra_accounts.len() as u32)
    }

    async fn query_accounts(&self, selector: AccountSelector) -> Result<Vec<types::Account>, BlokliClientError> {
        self.inner.query_accounts(selector).await
    }

    async fn query_native_balance(&self, address: &ChainAddress) -> Result<types::NativeBalance, BlokliClientError> {
        self.inner.query_native_balance(address).await
    }

    async fn query_token_balance(
        &self,
        address: &ChainAddress,
        token: types::Token,
    ) -> Result<types::HoprBalance, BlokliClientError> {
        self.inner.query_token_balance(address, token).await
    }

    async fn query_transaction_count(&self, address: &ChainAddress) -> Result<u64, BlokliClientError> {
        self.inner.query_transaction_count(address).await
    }

    async fn query_safe_allowance(
        &self,
        address: &ChainAddress,
    ) -> Result<types::SafeHoprAllowance, BlokliClientError> {
        self.inner.query_safe_allowance(address).await
    }

    async fn query_redeemed_stats(
        &self,
        selector: RedeemedStatsSelector,
    ) -> Result<types::RedeemedStats, BlokliClientError> {
        self.inner.query_redeemed_stats(selector).await
    }

    async fn query_safe(&self, selector: SafeSelector) -> Result<Vec<types::Safe>, BlokliClientError> {
        self.inner.query_safe(selector).await
    }

    async fn query_module_address_prediction(
        &self,
        input: ModulePredictionInput,
    ) -> Result<ChainAddress, BlokliClientError> {
        self.inner.query_module_address_prediction(input).await
    }

    #[allow(deprecated)]
    async fn count_channels(&self, selector: ChannelSelector) -> Result<u32, BlokliClientError> {
        self.inner.count_channels(selector).await
    }

    async fn query_channel_stats(&self, selector: ChannelSelector) -> Result<types::ChannelStats, BlokliClientError> {
        self.inner.query_channel_stats(selector).await
    }

    async fn query_channels(&self, selector: ChannelSelector) -> Result<types::ChannelsList, BlokliClientError> {
        self.inner.query_channels(selector).await
    }

    async fn query_safes_balance(
        &self,
        owner_address: Option<ChainAddress>,
    ) -> Result<types::SafesBalance, BlokliClientError> {
        self.inner.query_safes_balance(owner_address).await
    }

    async fn count_services(&self, selector: ServiceSelector) -> Result<u32, BlokliClientError> {
        self.inner.count_services(selector).await
    }

    async fn query_services(&self, selector: ServiceSelector) -> Result<Vec<types::ServiceEntry>, BlokliClientError> {
        self.inner.query_services(selector).await
    }

    async fn query_live_services(
        &self,
        selector: ServiceSelector,
    ) -> Result<Vec<types::ServiceEntry>, BlokliClientError> {
        self.inner.query_live_services(selector).await
    }

    async fn query_service_types(
        &self,
        service_type: Option<ServiceTypeId>,
    ) -> Result<Vec<types::ServiceTypeInfo>, BlokliClientError> {
        self.inner.query_service_types(service_type).await
    }

    async fn query_service_registry_config(&self) -> Result<types::ServiceRegistryConfig, BlokliClientError> {
        self.inner.query_service_registry_config().await
    }

    async fn query_transaction_status(&self, tx_id: TxId) -> Result<types::Transaction, BlokliClientError> {
        self.inner.query_transaction_status(tx_id).await
    }

    async fn query_chain_info(&self) -> Result<types::ChainInfo, BlokliClientError> {
        self.inner.query_chain_info().await
    }

    async fn query_version(&self) -> Result<String, BlokliClientError> {
        self.inner.query_version().await
    }

    async fn query_health(&self) -> Result<String, BlokliClientError> {
        self.inner.query_health().await
    }

    async fn query_compatibility(&self) -> Result<types::Compatibility, BlokliClientError> {
        self.inner.query_compatibility().await
    }
}

#[async_trait::async_trait]
impl<T: BlokliTransactionClient + Send + Sync> BlokliTransactionClient for ScriptedGraphClient<T> {
    async fn submit_transaction(&self, signed_tx: &[u8]) -> Result<TxReceipt, BlokliClientError> {
        self.inner.submit_transaction(signed_tx).await
    }

    async fn submit_and_track_transaction(&self, signed_tx: &[u8]) -> Result<TxId, BlokliClientError> {
        self.inner.submit_and_track_transaction(signed_tx).await
    }

    async fn submit_and_confirm_transaction(
        &self,
        signed_tx: &[u8],
        num_confirmations: usize,
    ) -> Result<TxReceipt, BlokliClientError> {
        self.inner
            .submit_and_confirm_transaction(signed_tx, num_confirmations)
            .await
    }

    async fn track_transaction(
        &self,
        tx_id: TxId,
        client_timeout: Duration,
    ) -> Result<TransactionTrackingOutcome, BlokliClientError> {
        self.inner.track_transaction(tx_id, client_timeout).await
    }
}

impl<T: BlokliSubscriptionClient + Send + Sync> BlokliSubscriptionClient for ScriptedGraphClient<T> {
    fn subscribe_channels(
        &self,
        selector: ChannelSelector,
    ) -> Result<impl futures::Stream<Item = Result<types::Channel, BlokliClientError>> + Send, BlokliClientError> {
        self.inner.subscribe_channels(selector)
    }

    fn subscribe_accounts(
        &self,
        selector: AccountSelector,
    ) -> Result<impl futures::Stream<Item = Result<types::Account, BlokliClientError>> + Send, BlokliClientError> {
        let extra = self.extra_accounts.clone();
        // merged, because the inner stream may stay open once it has delivered its accounts
        Ok(futures::stream::select(
            self.inner.subscribe_accounts(selector)?,
            futures::stream::iter(extra.into_iter().map(Ok)),
        ))
    }

    fn subscribe_graph(&self) -> Result<impl futures::Stream<Item = GraphResult> + Send, BlokliClientError> {
        self.graph_subscriptions.fetch_add(1, Ordering::SeqCst);
        let stream: BoxStream<'static, GraphResult> = match self.graph.lock().unwrap().take() {
            Some(receiver) => receiver.boxed(),
            // Later subscriptions replay the full snapshot and then stay quiet.
            None => futures::stream::iter(self.replay.clone().into_iter().map(Ok))
                .chain(futures::stream::pending())
                .boxed(),
        };
        Ok(stream)
    }

    fn subscribe_ticket_params(
        &self,
    ) -> Result<impl futures::Stream<Item = Result<types::TicketParameters, BlokliClientError>> + Send, BlokliClientError>
    {
        self.inner.subscribe_ticket_params()
    }

    fn subscribe_health(
        &self,
    ) -> Result<impl futures::Stream<Item = Result<types::ReadinessState, BlokliClientError>> + Send, BlokliClientError>
    {
        self.inner.subscribe_health()
    }

    fn subscribe_safe_deployments(
        &self,
    ) -> Result<impl futures::Stream<Item = Result<types::Safe, BlokliClientError>> + Send, BlokliClientError> {
        self.inner.subscribe_safe_deployments()
    }

    fn subscribe_services(
        &self,
        selector: ServiceSelector,
    ) -> Result<impl futures::Stream<Item = Result<types::ServiceUpdate, BlokliClientError>> + Send, BlokliClientError>
    {
        self.inner.subscribe_services(selector)
    }

    fn subscribe_service_types(
        &self,
        service_type: Option<ServiceTypeId>,
    ) -> Result<
        impl futures::Stream<Item = Result<types::ServiceTypeUpdate, BlokliClientError>> + Send,
        BlokliClientError,
    > {
        self.inner.subscribe_service_types(service_type)
    }

    fn subscribe_service_registry_config(
        &self,
    ) -> Result<
        impl futures::Stream<Item = Result<types::ServiceRegistryConfig, BlokliClientError>> + Send + 'static,
        BlokliClientError,
    > {
        self.inner.subscribe_service_registry_config()
    }

    fn subscribe_track_transaction(
        &self,
        tx_id: TxId,
    ) -> Result<impl futures::Stream<Item = Result<types::Transaction, BlokliClientError>> + Send, BlokliClientError>
    {
        self.inner.subscribe_track_transaction(tx_id)
    }

    fn subscribe_ticket_redeemed(
        &self,
        selector: TicketSelector,
    ) -> Result<
        impl futures::Stream<Item = Result<types::RedeemTicketDetails, BlokliClientError>> + Send,
        BlokliClientError,
    > {
        self.inner.subscribe_ticket_redeemed(selector)
    }
}

lazy_static::lazy_static! {
    static ref CHAIN_KEYS: Vec<ChainKeypair> = (0..3).map(|_| ChainKeypair::random()).collect();
    static ref OFFCHAIN_KEYS: Vec<OffchainKeypair> = (0..3).map(|_| OffchainKeypair::random()).collect();
}

fn accounts() -> Vec<AccountEntry> {
    (0..3)
        .map(|i| AccountEntry {
            public_key: *OFFCHAIN_KEYS[i].public(),
            chain_addr: CHAIN_KEYS[i].public().to_address(),
            entry_type: AccountType::NotAnnounced,
            safe_address: None,
            key_id: (i as u32 + 1).into(),
        })
        .collect()
}

/// Two open channels, 0 -> 1 and 1 -> 2, that the in-process chain knows about.
fn channels() -> [ChannelEntry; 2] {
    let open = |a: usize, b: usize| {
        ChannelEntry::builder()
            .between(&CHAIN_KEYS[a], &CHAIN_KEYS[b])
            .amount(100)
            .ticket_index(1)
            .status(ChannelStatus::Open)
            .epoch(1)
            .build()
            .unwrap()
    };
    [open(0, 1), open(1, 2)]
}

type TestConnector = hopr_chain_connector::HoprBlockchainSafeConnector<
    ScriptedGraphClient<hopr_chain_connector::testing::BlokliTestClient<hopr_chain_connector::testing::StaticState>>,
>;

struct Harness {
    connector: TestConnector,
    graph_tx: futures::channel::mpsc::UnboundedSender<GraphResult>,
    graph_subscriptions: Arc<AtomicUsize>,
    /// The graph entries of the channels returned by [`channels`], as blokli would deliver them.
    entries: [OpenedChannelsGraphEntry; 2],
}

impl Harness {
    /// Builds a connector over a chain that holds both channels, but whose graph subscription only delivers what
    /// the test sends. The sync tolerance is lowered so that a single delivered channel is enough to connect.
    async fn new() -> Self {
        Self::with_node_key(ChainKeypair::random()).await
    }

    /// Like [`Harness::new`], with the connector running as the given node. Channels with that node as an endpoint
    /// are its own channels, which the connector also reconciles against blokli.
    async fn with_node_key(node_key: ChainKeypair) -> Self {
        Self::build(node_key, channels(), |entries| entries.to_vec()).await
    }

    /// Builds the connector over a chain that holds `chain_channels`. `replay` chooses the snapshot that a later
    /// subscription starts with, from the graph entries of the chain's channels.
    async fn build(
        node_key: ChainKeypair,
        chain_channels: [ChannelEntry; 2],
        replay: impl FnOnce(&[OpenedChannelsGraphEntry; 2]) -> Vec<OpenedChannelsGraphEntry>,
    ) -> Self {
        Self::build_with(node_key, chain_channels, replay, 50, vec![]).await
    }

    /// Like [`Harness::build`], with the given sync tolerance and raw accounts that the account subscription
    /// delivers (and the account count includes) in addition to the chain's own.
    async fn build_with(
        node_key: ChainKeypair,
        chain_channels: [ChannelEntry; 2],
        replay: impl FnOnce(&[OpenedChannelsGraphEntry; 2]) -> Vec<OpenedChannelsGraphEntry>,
        sync_tolerance: usize,
        extra_accounts: Vec<types::Account>,
    ) -> Self {
        let state_client = BlokliTestStateBuilder::default()
            .with_hopr_network_chain_info("anvil-localhost")
            .with_accounts(
                accounts()
                    .into_iter()
                    .map(|a| (a, HoprBalance::zero(), XDaiBalance::zero())),
            )
            .with_channels(chain_channels)
            .build_static_client();

        let entries: [OpenedChannelsGraphEntry; 2] = state_client
            .subscribe_graph()
            .unwrap()
            .take(2)
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>()
            .await
            .try_into()
            .unwrap();

        let (graph_tx, graph_rx) = futures::channel::mpsc::unbounded();
        let graph_subscriptions = Arc::new(AtomicUsize::new(0));
        let client = ScriptedGraphClient {
            inner: state_client,
            graph: Mutex::new(Some(graph_rx)),
            graph_subscriptions: graph_subscriptions.clone(),
            replay: replay(&entries),
            extra_accounts,
        };

        let cfg = BlockchainConnectorConfig {
            sync_tolerance,
            ..Default::default()
        };
        let connector =
            create_trustful_hopr_blokli_connector(&node_key, cfg, client, Address::new(&[2u8; Address::SIZE]))
                .await
                .unwrap();

        Self {
            connector,
            graph_tx,
            graph_subscriptions,
            entries,
        }
    }

    fn send(&self, entry: OpenedChannelsGraphEntry) {
        self.graph_tx.unbounded_send(Ok(entry)).unwrap();
    }

    async fn connect(&mut self) {
        self.connector.connect().await.unwrap();
    }

    /// Waits until the channel is visible through the connector.
    async fn wait_for_channel(&self, channel: &ChannelEntry) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.connector.channel_by_id(channel.get_id()).unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the channel never became visible");
    }

    /// Waits until the channel is visible and satisfies the predicate.
    async fn wait_for_channel_state(&self, channel: &ChannelEntry, pred: impl Fn(&ChannelEntry) -> bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !self
                .connector
                .channel_by_id(channel.get_id())
                .unwrap()
                .is_some_and(|c| pred(&c))
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the channel never reached the expected state");
    }
}

/// How long the connector gets to recover before a test calls it lost.
const RECOVERY_WAIT: Duration = Duration::from_secs(3);

/// Waits for the channel to become visible by id and by parties, failing with a clear message otherwise.
async fn expect_channel_to_be_recovered(harness: &Harness, channel: &ChannelEntry, why: &str) {
    let visible = tokio::time::timeout(RECOVERY_WAIT, async {
        loop {
            let by_id = harness.connector.channel_by_id(channel.get_id()).unwrap();
            let by_parties = harness
                .connector
                .channel_by_parties(&channel.source, &channel.destination)
                .unwrap();
            if by_id == Some(*channel) && by_parties == Some(*channel) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        visible.is_ok(),
        "{why}: the channel is still unknown to the connector after {RECOVERY_WAIT:?}"
    );
}

/// A channel whose graph entry fails conversion must not stay lost: a later snapshot or query delivers it.
async fn assert_a_failing_entry_is_recovered(break_entry: impl Fn(&mut OpenedChannelsGraphEntry)) {
    let mut harness = Harness::new().await;
    let [first, second] = channels();

    let mut broken = harness.entries[0].clone();
    break_entry(&mut broken);
    harness.send(broken);
    harness.send(harness.entries[1].clone());
    harness.connect().await;
    harness.wait_for_channel(&second).await;

    expect_channel_to_be_recovered(&harness, &first, "an entry that failed conversion was dropped").await;
}

#[tokio::test]
async fn an_entry_without_closure_time_is_recovered() {
    assert_a_failing_entry_is_recovered(|entry| {
        entry.channel.status = ModelChannelStatus::PendingToClose;
        entry.channel.closure_time = None;
    })
    .await;
}

#[tokio::test]
async fn an_entry_with_an_unknown_status_is_recovered() {
    assert_a_failing_entry_is_recovered(|entry| {
        entry.channel.status = ModelChannelStatus::Unknown;
    })
    .await;
}

#[tokio::test]
async fn a_channel_missing_from_the_graph_subscription_is_backfilled_from_blokli() {
    // The missing channel is one of the node's own channels, the ones the connector reconciles against blokli.
    let mut harness = Harness::with_node_key(CHAIN_KEYS[0].clone()).await;
    let [missing, delivered] = channels();

    harness.send(harness.entries[1].clone());
    harness.connect().await;
    harness.wait_for_channel(&delivered).await;

    // Blokli itself knows the channel.
    let listed = harness
        .connector
        .client()
        .query_channels(ChannelSelector {
            filter: Some(ChannelFilter::ChannelId(missing.get_id().as_ref().try_into().unwrap())),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(1, listed.channels.len());

    let visible = tokio::time::timeout(RECOVERY_WAIT, async {
        while harness
            .connector
            .channel_by_parties(&missing.source, &missing.destination)
            .unwrap()
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        visible.is_ok(),
        "a channel known to blokli but absent from the graph subscription was not backfilled within {RECOVERY_WAIT:?}"
    );
}

#[tokio::test]
async fn an_ended_graph_subscription_is_not_left_as_a_silently_frozen_connection() {
    let mut harness = Harness::new().await;
    let [first, _] = channels();

    harness.send(harness.entries[0].clone());
    harness.connect().await;
    harness.wait_for_channel(&first).await;

    let Harness {
        connector,
        graph_tx,
        graph_subscriptions,
        ..
    } = harness;
    drop(graph_tx);

    // Either the connector resubscribes, or it stops claiming to be connected.
    let handled = tokio::time::timeout(RECOVERY_WAIT, async {
        while graph_subscriptions.load(Ordering::SeqCst) < 2 && connector.is_connected() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        handled.is_ok(),
        "the graph subscription ended, yet after {RECOVERY_WAIT:?} the connector neither resubscribed ({} \
         subscription(s)) nor stopped reporting itself as connected (is_connected = {})",
        graph_subscriptions.load(Ordering::SeqCst),
        connector.is_connected()
    );
}

#[tokio::test]
async fn an_open_channel_that_closes_directly_emits_a_closed_event() {
    let mut harness = Harness::new().await;
    let [first, second] = channels();

    harness.send(harness.entries[0].clone());
    harness.send(harness.entries[1].clone());
    harness.connect().await;
    harness.wait_for_channel(&first).await;
    harness.wait_for_channel(&second).await;

    let mut events = Box::pin(harness.connector.subscribe().unwrap());

    let mut closed = harness.entries[0].clone();
    closed.channel.status = ModelChannelStatus::Closed;
    harness.send(closed);
    harness
        .wait_for_channel_state(&first, |c| c.status == ChannelStatus::Closed)
        .await;

    // The initial sync can still have its `ChannelOpened` events queued, so skip everything up to the close.
    let mut seen = Vec::new();
    let closed_event = tokio::time::timeout(RECOVERY_WAIT, async {
        while let Some(event) = events.next().await {
            if matches!(&event, ChainEvent::ChannelClosed(channel) if channel.get_id() == first.get_id()) {
                return true;
            }
            seen.push(event);
        }
        false
    })
    .await;
    assert!(
        matches!(closed_event, Ok(true)),
        "an Open channel became Closed directly and expected a ChannelClosed event, got {seen:?}"
    );
}

/// A channel that closed while the connector received no updates is missing from the snapshot a new subscription
/// starts with, and nothing says it closed. The connector must notice and close it.
#[tokio::test]
async fn a_channel_that_closed_during_a_gap_is_closed_after_the_snapshot_replay() {
    let [_, second] = channels();
    let closed_first = ChannelEntry::builder()
        .between(&CHAIN_KEYS[0], &CHAIN_KEYS[1])
        .amount(100)
        .ticket_index(1)
        .status(ChannelStatus::Closed)
        .epoch(1)
        .build()
        .unwrap();

    // Blokli sets the cursor on the last entry of a snapshot, which is how the end of one is recognized.
    let snapshot_end = types::ChannelStatePosition {
        block: types::Uint64("10".into()),
        transaction_index: types::Uint64("0".into()),
        log_index: types::Uint64("0".into()),
    };
    let mut harness = Harness::build(ChainKeypair::random(), [closed_first, second], |entries| {
        // the snapshot holds only the channel that is still open
        let mut last = entries[1].clone();
        last.cursor = Some(snapshot_end);
        vec![last]
    })
    .await;

    // The connector learns both channels as open from the live stream.
    let mut open_first = harness.entries[0].clone();
    open_first.channel.status = ModelChannelStatus::Open;
    harness.send(open_first);
    harness.send(harness.entries[1].clone());
    harness.connect().await;
    harness
        .wait_for_channel_state(&closed_first, |c| c.status == ChannelStatus::Open)
        .await;

    // The stream ends and the connector subscribes again, which starts with the snapshot.
    harness.graph_tx.close_channel();

    harness
        .wait_for_channel_state(&closed_first, |c| c.status == ChannelStatus::Closed)
        .await;
    assert_eq!(2, harness.graph_subscriptions.load(Ordering::SeqCst));
}

/// Blokli-client starts a snapshot on its own when it loses its position. The connector sees it as entries without a
/// cursor after entries that had one, and a channel the snapshot lacks has closed.
#[tokio::test]
async fn a_snapshot_started_by_the_client_closes_the_channels_it_lacks() {
    let [first, second] = channels();
    let position = |n: u64| types::ChannelStatePosition {
        block: types::Uint64(n.to_string()),
        transaction_index: types::Uint64("0".into()),
        log_index: types::Uint64("0".into()),
    };
    let mut harness = Harness::new().await;

    // Both channels arrive with a cursor, like live updates.
    for (entry, block) in harness.entries.clone().into_iter().zip([1, 2]) {
        let mut entry = entry;
        entry.cursor = Some(position(block));
        harness.send(entry);
    }
    harness.connect().await;
    harness
        .wait_for_channel_state(&first, |c| c.status == ChannelStatus::Open)
        .await;
    harness
        .wait_for_channel_state(&second, |c| c.status == ChannelStatus::Open)
        .await;

    // A snapshot that holds only the second channel: its entries carry no cursor but the last one's.
    let mut replayed = harness.entries[1].clone();
    replayed.cursor = None;
    harness.send(replayed);
    let mut last = harness.entries[1].clone();
    last.cursor = Some(position(3));
    harness.send(last);

    harness
        .wait_for_channel_state(&first, |c| c.status == ChannelStatus::Closed)
        .await;
    assert!(
        harness
            .connector
            .channel_by_id(second.get_id())
            .unwrap()
            .is_some_and(|c| c.status == ChannelStatus::Open)
    );
    // no new subscription was needed for it
    assert_eq!(1, harness.graph_subscriptions.load(Ordering::SeqCst));
}

/// An account whose packet key is not a point on the curve is rejected, but it still counts in the total that
/// blokli reports. It must count as received, or `connect()` can never finish at a sync tolerance of 100.
#[tokio::test]
async fn a_rejected_account_does_not_keep_connect_from_finishing_at_full_tolerance() {
    let invalid = types::Account {
        chain_key: Address::new(&[9u8; Address::SIZE]).to_string(),
        keyid: 99,
        multi_addresses: vec![],
        // 32 bytes that are not a valid curve point
        packet_key: "02".repeat(32),
        safe_address: None,
    };
    let mut harness = Harness::build_with(
        ChainKeypair::random(),
        channels(),
        |entries| entries.to_vec(),
        100,
        vec![invalid],
    )
    .await;

    for entry in harness.entries.clone() {
        harness.send(entry);
    }

    tokio::time::timeout(RECOVERY_WAIT, harness.connect())
        .await
        .expect("connect never finished");
}

/// A channel that closed between the open channels being counted and the graph snapshot is counted in the total but
/// not delivered. The delivered snapshot says that nothing more is coming, so `connect()` must finish at 100.
#[tokio::test]
async fn a_channel_closed_in_the_setup_gap_does_not_keep_connect_from_finishing_at_full_tolerance() {
    let [_, second] = channels();
    let mut harness = Harness::build_with(
        ChainKeypair::random(),
        channels(),
        |entries| entries.to_vec(),
        100,
        vec![],
    )
    .await;

    // The snapshot only holds the second channel; its last entry carries the cursor.
    let mut last = harness.entries[1].clone();
    last.cursor = Some(types::ChannelStatePosition {
        block: types::Uint64("10".into()),
        transaction_index: types::Uint64("0".into()),
        log_index: types::Uint64("0".into()),
    });
    harness.send(last);

    tokio::time::timeout(RECOVERY_WAIT, harness.connect())
        .await
        .expect("connect never finished");
    harness
        .wait_for_channel_state(&second, |c| c.status == ChannelStatus::Open)
        .await;
}
