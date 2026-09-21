// This integration test requires the `runtime-tokio` and `transport-quic` features.
#![cfg(all(feature = "runtime-tokio", feature = "transport-quic"))]

//! Transport-level throughput test for the raw libp2p stream transport exposed by
//! [`HoprNetwork`]. It drives the network purely through the `hopr-api`
//! [`NetworkStreamControl`] trait (`open`/`accept`) plus a minimal, self-contained
//! length-delimited message framing — no dependency on the concrete HOPR message
//! protocol / codec crates.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    str::FromStr,
};

use anyhow::Context;
use bytes::Bytes;
use futures::{
    AsyncReadExt, AsyncWriteExt, SinkExt, StreamExt,
    channel::mpsc::{Receiver, Sender},
};
use hopr_api::{
    network::{NetworkView, traits::NetworkStreamControl},
    types::crypto::{keypairs::Keypair, prelude::OffchainKeypair},
};
use hopr_transport_p2p::{HoprLibp2pNetworkBuilder, HoprNetwork, PeerDiscovery};
use libp2p::{Multiaddr, PeerId};
use more_asserts::assert_gt;
use tokio::{
    task::{JoinHandle, spawn},
    time::{Instant, sleep, timeout},
};

/// Message-protocol identifier used by this test. Both peers must agree on it;
/// the value itself is arbitrary (replaces the production `CURRENT_HOPR_MSG_PROTOCOL`).
const TEST_MSG_PROTOCOL: &str = "/hopr/p2p-test/msg/1.0.0";

/// Representative HOPR SPHINX packet payload size, used to shape the workload
/// (replaces the `HoprPacket::SIZE` constant from the crypto crate).
const TRANSPORT_PAYLOAD_SIZE: usize = 1028;

type MsgSender = Sender<(PeerId, Bytes)>;
type MsgReceiver = Receiver<(PeerId, Bytes)>;

pub fn random_free_local_ipv4_port() -> Option<u16> {
    let socket = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    TcpListener::bind(socket)
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .ok()
}

pub(crate) struct Interface {
    pub me: PeerId,
    pub address: Multiaddr,
    pub update_from_announcements: futures::channel::mpsc::UnboundedSender<PeerDiscovery>,
    pub send_msg: MsgSender,
    pub recv_msg: MsgReceiver,
}

#[allow(clippy::upper_case_acronyms)]
pub(crate) enum Announcement {
    QUIC,
}

pub(crate) type TestSwarm = HoprNetwork;

/// A minimal length-delimited (`u32` big-endian length prefix) message layer over the
/// raw libp2p streams from [`HoprNetwork`], exposed to the test as `(sender, receiver)`
/// channels. This stands in for the production stream protocol.
///
/// * Incoming: `accept()` yields per-peer substreams; each is drained frame-by-frame into the receiver channel.
/// * Outgoing: the first message to a peer lazily `open()`s a stream and spawns a dedicated writer task fed by a
///   per-peer channel; subsequent messages reuse it.
fn spawn_stream_protocol(network: HoprNetwork, channel_capacity: usize) -> anyhow::Result<(MsgSender, MsgReceiver)> {
    let (out_tx, mut out_rx) = futures::channel::mpsc::channel::<(PeerId, Bytes)>(channel_capacity);
    let (in_tx, in_rx) = futures::channel::mpsc::channel::<(PeerId, Bytes)>(channel_capacity);

    // Accept incoming streams and drain each into the receiver channel.
    let accept_stream = network
        .clone()
        .accept()
        .map_err(|e| anyhow::anyhow!("failed to accept on the test protocol: {e}"))?;
    spawn(async move {
        futures::pin_mut!(accept_stream);
        while let Some((peer, substream)) = accept_stream.next().await {
            let mut in_tx = in_tx.clone();
            spawn(async move {
                let mut reader = Box::pin(substream);
                loop {
                    let mut len_buf = [0u8; 4];
                    if reader.read_exact(&mut len_buf).await.is_err() {
                        break;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut payload = vec![0u8; len];
                    if reader.read_exact(&mut payload).await.is_err() {
                        break;
                    }
                    if in_tx.send((peer, Bytes::from(payload))).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // Route outgoing messages to a per-peer writer task that owns the opened stream.
    spawn(async move {
        let mut peers: HashMap<PeerId, futures::channel::mpsc::Sender<Bytes>> = HashMap::new();
        while let Some((peer, bytes)) = out_rx.next().await {
            let peer_tx = match peers.get_mut(&peer) {
                Some(peer_tx) => peer_tx,
                None => {
                    let stream = match network.clone().open(peer).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!(%peer, error = %e, "failed to open test stream");
                            continue;
                        }
                    };
                    let (peer_tx, mut peer_rx) = futures::channel::mpsc::channel::<Bytes>(channel_capacity);
                    spawn(async move {
                        let mut writer = Box::pin(stream);
                        // Coalesce each burst of already-queued frames into a single flush: write the
                        // received frame plus any others waiting in the channel, then flush. Bulk sends
                        // stay batched for throughput, while a lone priming frame is flushed immediately
                        // instead of waiting for a fixed-size batch to fill.
                        'outer: while let Some(first) = peer_rx.next().await {
                            let mut next = Some(first);
                            while let Some(b) = next {
                                // Length-delimited frame written as a single buffer (4-byte BE length + payload).
                                let mut frame = Vec::with_capacity(4 + b.len());
                                frame.extend_from_slice(&(b.len() as u32).to_be_bytes());
                                frame.extend_from_slice(&b);
                                if writer.write_all(&frame).await.is_err() {
                                    break 'outer;
                                }
                                next = peer_rx.try_recv().ok();
                            }
                            if writer.flush().await.is_err() {
                                break;
                            }
                        }
                        let _ = writer.close().await;
                    });
                    peers.entry(peer).or_insert(peer_tx)
                }
            };

            if peer_tx.send(bytes).await.is_err() {
                peers.remove(&peer);
            }
        }
    });

    Ok((out_tx, in_rx))
}

async fn build_p2p_swarm(
    announcement: Announcement,
    per_peer_channel_capacity: usize,
) -> anyhow::Result<(Interface, (TestSwarm, hopr_api::network::BoxedProcessFn))> {
    let random_port = random_free_local_ipv4_port().context("could not find a free port")?;
    let random_keypair = OffchainKeypair::random();

    let multiaddress = match announcement {
        Announcement::QUIC => quic_addr(random_port),
    };

    let (peer_id, transport_updates_tx, network, process) =
        build_node(&random_keypair, vec![multiaddress.clone()]).await?;

    let (send_msg, recv_msg) = spawn_stream_protocol(network.clone(), per_peer_channel_capacity)?;

    let api = Interface {
        me: peer_id,
        address: multiaddress,
        update_from_announcements: transport_updates_tx,
        send_msg,
        recv_msg,
    };

    Ok((api, (network, process)))
}

lazy_static::lazy_static! {
    pub static ref RANDOM_GIBBERISH: Bytes =
        Bytes::copy_from_slice(&hopr_api::types::crypto_random::random_bytes::<TRANSPORT_PAYLOAD_SIZE>());
}

pub struct SelfClosingJoinHandle {
    handle: Option<JoinHandle<()>>,
}

impl SelfClosingJoinHandle {
    pub fn new<F>(f: F) -> Self
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        Self { handle: Some(spawn(f)) }
    }
}

impl Drop for SelfClosingJoinHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn addressless_peer_connects_after_announcement() -> anyhow::Result<()> {
    let (api1, (network1, process1)) = build_p2p_swarm(Announcement::QUIC, 1).await?;
    let (mut api2, (_network2, process2)) = build_p2p_swarm(Announcement::QUIC, 1).await?;

    let _sjh1 = SelfClosingJoinHandle::new(process1());
    let _sjh2 = SelfClosingJoinHandle::new(process2());

    let initial_open = timeout(std::time::Duration::from_secs(2), network1.clone().open(api2.me))
        .await
        .context("addressless stream open timed out")?;
    assert!(initial_open.is_err(), "opening a stream without an address must fail");

    api1.update_from_announcements
        .unbounded_send(PeerDiscovery::Announce(api2.me, vec![api2.address.clone()]))
        .context("failed to send announcement")?;

    let mut stream = timeout(std::time::Duration::from_secs(10), async {
        loop {
            match network1.clone().open(api2.me).await {
                Ok(stream) => break stream,
                Err(_) => sleep(std::time::Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .context("announced peer did not become dialable")?;

    let payload = Bytes::from_static(b"connected after announcement");
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    stream
        .write_all(&frame)
        .await
        .context("failed to write after announcement")?;
    stream.flush().await.context("failed to flush after announcement")?;

    let (_, received) = timeout(std::time::Duration::from_secs(5), api2.recv_msg.next())
        .await
        .context("receive after announcement timed out")?
        .context("receive channel closed after announcement")?;

    assert_eq!(received, payload);

    Ok(())
}

fn quic_addr(port: u16) -> Multiaddr {
    Multiaddr::from_str(&format!("/ip4/127.0.0.1/udp/{port}/quic-v1")).expect("valid quic multiaddress")
}

/// Block until `127.0.0.1:<port>` (UDP) can be bound again, i.e. the previous
/// owner has released it, so a peer can be rebuilt on the same port.
async fn wait_udp_port_free(port: u16) -> anyhow::Result<()> {
    for _ in 0..200 {
        if std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return Ok(());
        }
        sleep(std::time::Duration::from_millis(50)).await;
    }
    anyhow::bail!("udp port {port} was not released in time")
}

/// Build a swarm on a fixed keypair and port, announcing `announced` addresses.
/// `allow_private_addresses` is enabled so loopback addresses are exercised.
async fn build_node(
    keypair: &OffchainKeypair,
    announced: Vec<Multiaddr>,
) -> anyhow::Result<(
    PeerId,
    futures::channel::mpsc::UnboundedSender<PeerDiscovery>,
    HoprNetwork,
    hopr_api::network::BoxedProcessFn,
)> {
    let peer_id: PeerId = libp2p::identity::Keypair::from(keypair).public().into();
    let (tx, rx) = futures::channel::mpsc::unbounded::<PeerDiscovery>();
    let (network, process) = HoprLibp2pNetworkBuilder::new(rx)
        .build(keypair, announced, TEST_MSG_PROTOCOL, true)
        .await
        .map_err(|e| anyhow::anyhow!("failed to build network: {e}"))?;
    Ok((peer_id, tx, network, process))
}

/// Poll `network` until `peer` reaches `connected`, or `deadline` elapses.
async fn wait_until_connected_is(
    network: &HoprNetwork,
    peer: PeerId,
    connected: bool,
    deadline: std::time::Duration,
) -> anyhow::Result<()> {
    timeout(deadline, async {
        while network.is_connected(&peer) != connected {
            sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .with_context(|| format!("timed out waiting for peer connected={connected}"))?;
    Ok(())
}

async fn wait_until_connected(net: &HoprNetwork, peer: PeerId, deadline: std::time::Duration) -> anyhow::Result<()> {
    wait_until_connected_is(net, peer, true, deadline).await
}

async fn wait_until_disconnected(net: &HoprNetwork, peer: PeerId, deadline: std::time::Duration) -> anyhow::Result<()> {
    wait_until_connected_is(net, peer, false, deadline).await
}

/// Regression for #31 ("Expected"): a disconnected peer reconnects through its
/// announced address.
///
/// The fix makes discovery dial only the announced address (`bootstrap_peers`)
/// with behaviour-contributed addresses disabled, and disables identify's
/// passive address cache. This test exercises that dial path end-to-end over
/// real QUIC: two nodes connect, one is torn down and brought back on the same
/// port and peer id, and the dialer must re-establish the connection.
///
/// Note: the *permanent* undialability in the wild requires a peer sharing the
/// local node's UDP port across hosts (a loopback dial to self, failing
/// `WrongPeerId` and never evicted). That collision cannot be reproduced on a
/// single host — two processes cannot bind one UDP port — and the distinguishing
/// dial state (`DialOpts` addresses / `extend_addresses_through_behaviour`) is
/// not observable from a test, so there is no in-process test that fails under
/// the pre-fix behaviour. This test guards that the fix does not regress the
/// reconnection path; the exclusion itself rests on libp2p's documented flag
/// semantics.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_peer_reconnects_via_announced_address() -> anyhow::Result<()> {
    // Generous deadlines: connection setup waits on discovery's exponential backoff
    // (min 3s), and each phase competes with backoff growth, so keep CI margin.
    let connect_timeout = std::time::Duration::from_secs(30);

    let kp_a = OffchainKeypair::random();
    let port_a = random_free_local_ipv4_port().context("no free port for A")?;
    let (_a_id, a_tx, a_net, a_proc) = build_node(&kp_a, vec![quic_addr(port_a)]).await?;

    let kp_b = OffchainKeypair::random();
    let port_b = random_free_local_ipv4_port().context("no free port for B")?;
    let b_announced = vec![quic_addr(port_b)];
    let (b_id, _b_tx, b_net, b_proc) = build_node(&kp_b, b_announced.clone()).await?;

    let _a_handle = SelfClosingJoinHandle::new(a_proc());
    let b_handle = SelfClosingJoinHandle::new(b_proc());

    // Announce B to A only, so A is the sole dialer (B accepts inbound). A
    // mutual announcement would make both sides dial simultaneously and collide
    // on the loopback QUIC handshake, which is a libp2p artefact unrelated to
    // this fix.
    //
    // Re-announce on a ticker: in production HOPR's network graph pushes
    // announcements continuously, which wakes discovery to fire its backed-off
    // dial attempts. A quiet test has no such wakeups, so a scheduled dial would
    // otherwise wait for an unrelated swarm event. The re-announce is idempotent
    // (discovery de-duplicates a peer already queued/connected).
    let announce_b = PeerDiscovery::Announce(b_id, b_announced.clone());
    let _nudge = {
        let a_tx = a_tx.clone();
        let announce_b = announce_b.clone();
        SelfClosingJoinHandle::new(async move {
            loop {
                if a_tx.unbounded_send(announce_b.clone()).is_err() {
                    break;
                }
                sleep(std::time::Duration::from_millis(500)).await;
            }
        })
    };

    wait_until_connected(&a_net, b_id, connect_timeout)
        .await
        .context("A must connect to B initially")?;

    // Tear B down and wait for A to notice.
    drop(b_handle);
    drop(b_net);
    wait_until_disconnected(&a_net, b_id, connect_timeout)
        .await
        .context("A must observe B disconnecting")?;

    // Bring B back up on the same port and peer id.
    wait_udp_port_free(port_b).await?;
    let (b_id2, _b_tx2, b_net2, b_proc2) = build_node(&kp_b, b_announced).await?;
    anyhow::ensure!(b_id2 == b_id, "rebuilt B must keep its peer id");
    let _b_handle2 = SelfClosingJoinHandle::new(b_proc2());
    let _b_net2 = b_net2;

    // A must reconnect via B's announced address.
    wait_until_connected(&a_net, b_id, std::time::Duration::from_secs(60))
        .await
        .context("A must reconnect to B after it returns")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_only_communication_quic() -> anyhow::Result<()> {
    let packet_count: usize = 2 * 1024 * 10; // ~10 MB
    let (mut api1, (_swarm1, process1)) = build_p2p_swarm(Announcement::QUIC, packet_count).await?;
    let (mut api2, (_swarm2, process2)) = build_p2p_swarm(Announcement::QUIC, packet_count).await?;

    let _sjh1 = SelfClosingJoinHandle::new(process1());
    let _sjh2 = SelfClosingJoinHandle::new(process2());

    // Announce nodes to each other
    api1.update_from_announcements
        .unbounded_send(PeerDiscovery::Announce(api2.me, vec![api2.address.clone()]))
        .context("failed to send announcement")?;
    api2.update_from_announcements
        .unbounded_send(PeerDiscovery::Announce(api1.me, vec![api1.address.clone()]))
        .context("failed to send announcement")?;

    // Wait for node listen_on and announcements
    sleep(std::time::Duration::from_secs(3)).await;

    // Pre-prime: send one packet and wait for it on the receiver side so the
    // per-peer QUIC stream is established before the bulk send.
    api1.send_msg
        .send((api2.me, RANDOM_GIBBERISH.clone()))
        .await
        .context("priming send failed")?;
    timeout(std::time::Duration::from_secs(5), api2.recv_msg.next())
        .await
        .context("priming receive timed out")?
        .context("priming receive: channel closed")?;

    // Bulk send over the (reliable, ordered) QUIC stream.
    let target_bytes = RANDOM_GIBBERISH.len() * packet_count;

    let start = Instant::now();

    let peer = api2.me;
    let mut bulk_sender = api1.send_msg.clone();
    let _sender = SelfClosingJoinHandle::new(async move {
        for _ in 0..packet_count {
            if bulk_sender.send((peer, RANDOM_GIBBERISH.clone())).await.is_err() {
                break;
            }
        }
    });

    // Receive until the target byte count is seen or no packet arrives for 2 s.
    let mut received_bytes = 0usize;
    let mut last_received = start;
    while received_bytes < target_bytes {
        match timeout(std::time::Duration::from_secs(2), api2.recv_msg.next()).await {
            Ok(Some((_, pkt))) => {
                received_bytes += pkt.len();
                last_received = Instant::now();
            }
            _ => break,
        }
    }

    let elapsed = last_received.duration_since(start);
    let speed_in_mbytes_s = received_bytes as f64 / elapsed.as_secs_f64() / 1_000_000.0;

    println!(
        "p2p raw-stream throughput: {speed_in_mbytes_s:.1} MB/s ({received_bytes}/{target_bytes} bytes, \
         {TRANSPORT_PAYLOAD_SIZE}-byte frames, {elapsed:?})"
    );

    // Primary assertion: the raw QUIC stream is reliable and ordered, so every byte must arrive.
    assert_eq!(
        received_bytes, target_bytes,
        "expected all {target_bytes} bytes to be delivered over the reliable stream, got {received_bytes}",
    );

    // Throughput expectation for the raw stream transport driven through the minimal test framing.
    assert_gt!(
        speed_in_mbytes_s,
        50.0f64,
        "The measured speed for data transfer is ~{speed_in_mbytes_s:.1}MB/s on {received_bytes} bytes received, \
         which is less than the expected 50MB/s",
    );

    Ok(())
}
