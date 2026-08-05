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
    network::traits::NetworkStreamControl,
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
                        // Flush in batches rather than per-frame to keep throughput high while still
                        // pushing data out promptly for the receiver.
                        const FLUSH_EVERY: usize = 64;
                        let mut writer = Box::pin(stream);
                        let mut since_flush = 0usize;
                        'outer: while let Some(b) = peer_rx.next().await {
                            // Length-delimited frame written as a single buffer (4-byte BE length + payload).
                            let mut frame = Vec::with_capacity(4 + b.len());
                            frame.extend_from_slice(&(b.len() as u32).to_be_bytes());
                            frame.extend_from_slice(&b);
                            if writer.write_all(&frame).await.is_err() {
                                break;
                            }
                            since_flush += 1;
                            if since_flush >= FLUSH_EVERY {
                                since_flush = 0;
                                if writer.flush().await.is_err() {
                                    break 'outer;
                                }
                            }
                        }
                        let _ = writer.flush().await;
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
    let peer_id: PeerId = libp2p::identity::Keypair::from(&random_keypair).public().into();

    let (transport_updates_tx, transport_updates_rx) = futures::channel::mpsc::unbounded::<PeerDiscovery>();

    let multiaddress = match announcement {
        Announcement::QUIC => format!("/ip4/127.0.0.1/udp/{random_port}/quic-v1"),
    };
    let multiaddress = Multiaddr::from_str(&multiaddress).context("failed to create a valid multiaddress")?;

    let network_builder = HoprLibp2pNetworkBuilder::new(transport_updates_rx);
    let (network, process) = network_builder
        .build(&random_keypair, vec![multiaddress.clone()], TEST_MSG_PROTOCOL, true)
        .await
        .map_err(|e| anyhow::anyhow!("failed to build network: {e}"))?;

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
