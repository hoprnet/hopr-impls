//! HOPR session server that bridges TCP/UDP sockets from the Session Exit node to a destination.

mod allow_list;
pub mod config;
pub mod target_pattern;

use std::{marker::PhantomData, net::SocketAddr};

use hopr_api::{
    node::{IncomingSession, SessionAdmissionDecision, SessionAdmissionRequest},
    types::crypto::prelude::OffchainKeypair,
};
use hopr_utils::{
    network_types::{
        prelude::{ForeignDataMode, IpOrHost, IpOrHostExt, ServiceId, SessionTarget},
        udp::{ConnectedUdpStream, UdpStreamParallelism},
        utils::{transfer_session, transfer_session_datagram},
    },
    parallelize::cpu::spawn_blocking,
};

use crate::{config::SessionIpForwardingConfig, target_pattern::UnsealedTarget};

#[cfg(all(feature = "telemetry", not(test)))]
lazy_static::lazy_static! {
    static ref METRIC_ACTIVE_TARGETS: hopr_api::types::telemetry::MultiGauge = hopr_api::types::telemetry::MultiGauge::new(
        "hopr_session_hoprd_target_connections",
        "Number of currently active HOPR session target connections on this Exit node",
        &["type"]
    ).unwrap();
}

/// Size of the buffer for forwarding data to/from a TCP stream.
pub const HOPR_TCP_BUFFER_SIZE: usize = 4096;

/// Size of the buffer for forwarding data to/from a UDP stream.
pub const HOPR_UDP_BUFFER_SIZE: usize = 16384;

/// Size of the queue (back-pressure) for data incoming from a UDP stream.
pub const HOPR_UDP_QUEUE_SIZE: usize = 8192;

/// Ingress queue depth (in datagrams) for the datagram-preserving UDP relay.
///
/// This bounds how long a datagram can sit queued while the session egress is back-pressured before
/// it is dropped: once the queue is full the UDP receiver stops draining the socket, the kernel
/// socket buffer fills, and the kernel drops. A real-time UDP transport (WireGuard) wants *bounded
/// delay then loss*, not unbounded buffering — at a real-time rate of ~200 datagrams/s, 256 is about
/// one second. The larger [`HOPR_UDP_QUEUE_SIZE`] (~40 s at that rate) is a latency bubble that
/// makes the tunnel unusable under sustained overload. See hoprnet#8421.
pub const HOPR_UDP_DATAGRAM_QUEUE_SIZE: usize = 256;

/// Error type for [`HoprServerIpForwardingReactor`].
#[derive(Debug, thiserror::Error)]
pub enum ForwarderError {
    #[error("{0}")]
    General(String),
    /// The target was refused by policy rather than failing technically.
    ///
    /// Separate from [`General`](Self::General) because the two want opposite responses: a refusal
    /// is the configuration working, and repeating the request will not help.
    #[error("target not admitted: {0}")]
    Denied(String),
}

impl ForwarderError {
    fn general(s: impl std::fmt::Display) -> Self {
        Self::General(s.to_string())
    }

    fn denied(s: impl std::fmt::Display) -> Self {
        Self::Denied(s.to_string())
    }
}

/// Implementation of `HoprSessionServer` that facilitates
/// bridging of TCP or UDP sockets from the Session Exit node to a destination.
///
/// Generic over the incoming session byte-stream `S`, which is supplied by the caller
/// (e.g. hopr-lib) as `HoprSession`; this crate does not depend on the concrete type.
pub struct HoprServerIpForwardingReactor<S> {
    keypair: OffchainKeypair,
    cfg: SessionIpForwardingConfig,
    _marker: PhantomData<fn() -> S>,
}

impl<S> Clone for HoprServerIpForwardingReactor<S> {
    fn clone(&self) -> Self {
        Self {
            keypair: self.keypair.clone(),
            cfg: self.cfg.clone(),
            _marker: PhantomData,
        }
    }
}

impl<S> std::fmt::Debug for HoprServerIpForwardingReactor<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoprServerIpForwardingReactor")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl<S> HoprServerIpForwardingReactor<S> {
    pub fn new(keypair: OffchainKeypair, cfg: SessionIpForwardingConfig) -> Self {
        Self {
            keypair,
            cfg,
            _marker: PhantomData,
        }
    }

    /// Whether the target allow list admits `target`, which `process` has already resolved to `resolved`.
    async fn target_allowed(&self, target: &IpOrHost, resolved: &[SocketAddr]) -> bool {
        allow_list::is_allowed(&self.cfg, target, resolved, |name| name.resolve_tokio()).await
    }
}

pub const SERVICE_ID_LOOPBACK: ServiceId = 0;

#[async_trait::async_trait]
impl<S> hopr_api::node::HoprSessionServer for HoprServerIpForwardingReactor<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    type Error = ForwarderError;
    type Session = IncomingSession<S>;

    // `skip_all` rather than `skip(self)`: the remaining argument would otherwise be formatted with
    // `Debug` into every span, and for a `SealedHost::Plain` target that puts the host the peer asked
    // for next to its session id in the log. This is an exit node in a privacy network, and that
    // association is the linkage the network exists to avoid — the node has to learn the target to
    // forward to it, but it need not persist the pair into whatever sink is configured.
    #[tracing::instrument(level = "debug", skip_all, fields(session_id = ?request.session_id))]
    async fn admit(&self, request: SessionAdmissionRequest) -> Result<SessionAdmissionDecision, ForwarderError> {
        // Nothing to say about any target, so skip the unsealing entirely: with no rules configured
        // this hook costs a match and a return.
        if self.cfg.session_admission_rules.is_empty() {
            return Ok(SessionAdmissionDecision::default());
        }

        // Rules are written against the host the peer asked for, so the target has to be opened
        // before it can be matched. Failing here denies the Session, which is the same outcome it
        // would reach a moment later: `process` unseals with this key too, and cannot forward what
        // it cannot read.
        let kp = self.keypair.clone();
        let target = request.target.clone();
        let target = spawn_blocking(move || UnsealedTarget::new(&target, &kp), "admission_unseal")
            .await
            .map_err(|e| ForwarderError::general(format!("failed to spawn unseal task: {e}")))?
            .map_err(|e| ForwarderError::denied(format!("cannot unseal target: {e}")))?;

        // First match wins, so a specific rule placed above a general one overrides it.
        let Some(rule) = self
            .cfg
            .session_admission_rules
            .iter()
            .find(|rule| rule.target.matches(&target))
        else {
            tracing::debug!(
                session_id = ?request.session_id,
                "no admission rule matches the target, admitting on the node's own terms"
            );
            return Ok(SessionAdmissionDecision::default());
        };

        let mut decision = SessionAdmissionDecision::default();
        if let Some(enforce_pix) = rule.enforce_pix {
            decision = decision.with_enforce_pix(enforce_pix);
        }
        // A bound left unset does not narrow that end, so it is carried over from the node's own
        // range by the saturating value rather than by inventing one here.
        if rule.quota_range_min.is_some() || rule.quota_range_max.is_some() {
            decision = decision.with_pix_quota_range(
                rule.quota_range_min.unwrap_or(u64::MIN)..=rule.quota_range_max.unwrap_or(u64::MAX),
            );
        }

        tracing::debug!(
            session_id = ?request.session_id,
            rule = %rule.target,
            capabilities = format!("{:#010b}", request.capabilities),
            // What the peer asked for, beside what it is being given: an operator tuning a rule
            // needs both, and the offer is the only half that is not already in the config file.
            offered_quota_per_ssa = ?request.offered.as_ref().map(|offer| offer.quota_per_ssa),
            offered_dimensions = ?request
                .offered
                .as_ref()
                .map(|offer| (offer.parts_per_ssa, offer.shares_per_part, offer.surplus_shares)),
            enforce_pix = ?decision.enforce_pix,
            quota_range = ?decision.pix_quota_range,
            "admitting session on the matched rule's terms"
        );

        Ok(decision)
    }

    #[tracing::instrument(level = "debug", skip(self, session))]
    async fn process(&self, mut session: IncomingSession<S>) -> Result<(), ForwarderError> {
        let session_id = session.id;
        match session.target {
            SessionTarget::UdpStream(udp_target) => {
                let kp = self.keypair.clone();
                let udp_target = spawn_blocking(move || udp_target.unseal(&kp), "udp_unseal")
                    .await
                    .map_err(|e| ForwarderError::general(format!("failed to spawn unseal task: {e}")))?
                    .map_err(|e| ForwarderError::general(format!("cannot unseal target: {e}")))?;

                tracing::debug!(
                    session_id = ?session_id,
                    %udp_target,
                    "binding socket to the UDP server"
                );

                // In UDP, it is impossible to determine if the target is viable,
                // so we just take the first resolved address.
                let resolved_udp_target = udp_target
                    .clone()
                    .resolve_tokio()
                    .await
                    .map_err(|e| ForwarderError::general(format!("failed to resolve DNS name {udp_target}: {e}")))?
                    .first()
                    .ok_or_else(|| ForwarderError::general(format!("failed to resolve DNS name {udp_target}")))?
                    .to_owned();
                tracing::debug!(
                    ?session_id,
                    %udp_target,
                    resolution = ?resolved_udp_target,
                    "UDP target resolved"
                );

                if !self.target_allowed(&udp_target, &[resolved_udp_target]).await {
                    return Err(ForwarderError::denied(format!(
                        "{resolved_udp_target} is not allowed by the target allow list"
                    )));
                }

                let mut udp_bridge = ConnectedUdpStream::builder()
                    .with_buffer_size(HOPR_UDP_BUFFER_SIZE)
                    .with_counterparty(resolved_udp_target)
                    .with_foreign_data_mode(ForeignDataMode::Error)
                    .with_queue_size(HOPR_UDP_DATAGRAM_QUEUE_SIZE)
                    .with_receiver_parallelism(
                        self.cfg
                            .udp_rx_parallelism
                            .map(UdpStreamParallelism::Specific)
                            .unwrap_or(UdpStreamParallelism::Auto),
                    )
                    .build(("0.0.0.0", 0))
                    .map_err(|e| {
                        ForwarderError::general(format!("could not bridge the incoming session to {udp_target}: {e}"))
                    })?;

                tracing::debug!(
                    ?session_id,
                    %udp_target,
                    "bridging the session to the UDP server"
                );

                tokio::task::spawn(async move {
                    #[cfg(all(feature = "telemetry", not(test)))]
                    let _g = hopr_api::types::telemetry::MultiGaugeGuard::new(&METRIC_ACTIVE_TARGETS, &["udp"], 1.0);

                    // The Session forwards the termination to the udp_bridge, terminating
                    // the UDP socket.
                    //
                    // Datagram-aware transfer: each UDP datagram received from the target is written
                    // to the session as its own write, so the segmenter emits one frame per datagram
                    // instead of coalescing several return-path datagrams under write backpressure
                    // (which WireGuard-over-Session cannot decode). See hoprnet#8421.
                    match transfer_session_datagram(&mut session.session, &mut udp_bridge, HOPR_UDP_BUFFER_SIZE, None)
                        .await
                    {
                        Ok((session_to_stream_bytes, stream_to_session_bytes)) => tracing::info!(
                            ?session_id,
                            session_to_stream_bytes,
                            stream_to_session_bytes,
                            %udp_target,
                            "server bridged session to UDP ended"
                        ),
                        Err(e) => tracing::error!(
                            ?session_id,
                            %udp_target,
                            error = %e,
                            "UDP server stream is closed"
                        ),
                    }
                });

                Ok(())
            }
            SessionTarget::TcpStream(tcp_target) => {
                let kp = self.keypair.clone();
                let tcp_target = spawn_blocking(move || tcp_target.unseal(&kp), "tcp_unseal")
                    .await
                    .map_err(|e| ForwarderError::general(format!("failed to spawn unseal task: {e}")))?
                    .map_err(|e| ForwarderError::general(format!("cannot unseal target: {e}")))?;

                tracing::debug!(?session_id, %tcp_target, "creating a connection to the TCP server");

                // TCP is able to determine which of the resolved multiple addresses is viable,
                // and therefore we can pass all of them.
                let resolved_tcp_targets =
                    tcp_target.clone().resolve_tokio().await.map_err(|e| {
                        ForwarderError::general(format!("failed to resolve DNS name {tcp_target}: {e}"))
                    })?;
                tracing::debug!(
                    ?session_id,
                    %tcp_target,
                    resolution = ?resolved_tcp_targets,
                    "TCP target resolved"
                );

                if !self.target_allowed(&tcp_target, &resolved_tcp_targets).await {
                    return Err(ForwarderError::denied(format!(
                        "not all of {resolved_tcp_targets:?} are allowed by the target allow list"
                    )));
                }

                let strategy = tokio_retry::strategy::FixedInterval::new(self.cfg.tcp_target_retry_delay)
                    .take(self.cfg.max_tcp_target_retries as usize);

                let mut tcp_bridge = tokio_retry::Retry::start(strategy, || {
                    tokio::net::TcpStream::connect(resolved_tcp_targets.as_slice())
                })
                .await
                .map_err(|e| {
                    ForwarderError::general(format!("could not bridge the incoming session to {tcp_target}: {e}"))
                })?;

                tcp_bridge.set_nodelay(true).map_err(|e| {
                    ForwarderError::general(format!(
                        "could not set the TCP_NODELAY option for the bridged session to {tcp_target}: {e}",
                    ))
                })?;

                tracing::debug!(
                    ?session_id,
                    %tcp_target,
                    "bridging the session to the TCP server"
                );

                tokio::task::spawn(async move {
                    #[cfg(all(feature = "telemetry", not(test)))]
                    let _g = hopr_api::types::telemetry::MultiGaugeGuard::new(&METRIC_ACTIVE_TARGETS, &["tcp"], 1.0);

                    match transfer_session(&mut session.session, &mut tcp_bridge, HOPR_TCP_BUFFER_SIZE, None).await {
                        Ok((session_to_stream_bytes, stream_to_session_bytes)) => tracing::info!(
                            ?session_id,
                            session_to_stream_bytes,
                            stream_to_session_bytes,
                            %tcp_target,
                            "server bridged session to TCP ended"
                        ),
                        Err(error) => tracing::error!(
                            ?session_id,
                            %tcp_target,
                            %error,
                            "TCP server stream is closed"
                        ),
                    }
                });

                Ok(())
            }
            SessionTarget::ExitNode(SERVICE_ID_LOOPBACK) => {
                tracing::debug!(?session_id, "bridging the session to the loopback service");
                let (mut reader, mut writer) = tokio::io::split(session.session);

                #[cfg(all(feature = "telemetry", not(test)))]
                let _g = hopr_api::types::telemetry::MultiGaugeGuard::new(&METRIC_ACTIVE_TARGETS, &["loopback"], 1.0);

                // Use an unbounded channel so the reader always drains EXIT's incoming
                // forward-channel at full network speed, regardless of how long the writer
                // stalls waiting for SURBs.  A bounded pipe would fill when the writer
                // retries (no SURB available), which would block the reader, fill the
                // forward-channel, saturate ENTRY's TCP send buffer, and prevent ENTRY
                // from delivering new SURBs — creating a permanent deadlock.  With an
                // unbounded pipe ENTRY's TCP is never blocked by a SURB stall, so fresh
                // SURBs always reach EXIT and the writer eventually unblocks.
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

                let reader_session_id = session_id;
                let read_task = tokio::spawn(async move {
                    use tokio::io::AsyncReadExt as _;
                    let mut buf = vec![0u8; HOPR_TCP_BUFFER_SIZE];
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if tx.send(buf[..n].to_vec()).is_err() {
                                    break;
                                }
                            }
                            Err(error) => {
                                tracing::debug!(?reader_session_id, %error, "loopback reader error");
                                break;
                            }
                        }
                    }
                });

                let writer_session_id = session_id;
                let write_task = tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt as _;
                    while let Some(data) = rx.recv().await {
                        if let Err(error) = writer.write_all(&data).await {
                            tracing::debug!(?writer_session_id, %error, "loopback writer error");
                            break;
                        }
                    }
                });

                let (read_res, write_res) = tokio::join!(read_task, write_task);
                if let Err(error) = read_res {
                    tracing::warn!(?session_id, %error, "loopback read task terminated abnormally");
                }
                if let Err(error) = write_res {
                    tracing::warn!(?session_id, %error, "loopback write task terminated abnormally");
                }
                tracing::info!(?session_id, "server loopback session service ended");
                Ok(())
            }
            SessionTarget::ExitNode(_) => Err(ForwarderError::General(
                "server does not support internal session processing".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use anyhow::Context;
    use hopr_api::{
        node::HoprSessionServer,
        types::{crypto::keypairs::Keypair, crypto_random::Randomizable, network::SessionId},
    };
    use hopr_utils::network_types::prelude::{IpOrHost, SealedHost};
    use validator::Validate;

    use super::*;
    use crate::config::SessionAdmissionRule;

    /// The reactor never touches the byte-stream during admission, so a placeholder suffices.
    type Reactor = HoprServerIpForwardingReactor<tokio::io::DuplexStream>;

    fn reactor_with(rules: Vec<SessionAdmissionRule>) -> Reactor {
        HoprServerIpForwardingReactor::new(
            OffchainKeypair::random(),
            SessionIpForwardingConfig {
                session_admission_rules: rules,
                ..Default::default()
            },
        )
    }

    fn rule(target: &str) -> anyhow::Result<SessionAdmissionRule> {
        Ok(SessionAdmissionRule {
            target: target.parse().context("parsing rule target")?,
            ..Default::default()
        })
    }

    fn tcp(host: &str) -> anyhow::Result<SessionAdmissionRequest> {
        // Rules match on the target, so the capability bits are immaterial to these tests.
        Ok(SessionAdmissionRequest::new(
            SessionId::random(),
            SessionTarget::TcpStream(SealedHost::Plain(
                IpOrHost::from_str(host).context("parsing target host")?,
            )),
            0,
        ))
    }

    fn udp(host: &str) -> anyhow::Result<SessionAdmissionRequest> {
        Ok(SessionAdmissionRequest::new(
            SessionId::random(),
            SessionTarget::UdpStream(SealedHost::Plain(
                IpOrHost::from_str(host).context("parsing target host")?,
            )),
            0,
        ))
    }

    fn service(id: ServiceId) -> SessionAdmissionRequest {
        SessionAdmissionRequest::new(SessionId::random(), SessionTarget::ExitNode(id), 0)
    }

    fn allow_list_config(entries: &[&str]) -> anyhow::Result<SessionIpForwardingConfig> {
        Ok(SessionIpForwardingConfig {
            target_allow_list: entries
                .iter()
                .map(|entry| IpOrHost::from_str(entry).with_context(|| format!("parsing allow list entry {entry}")))
                .collect::<anyhow::Result<_>>()?,
            ..Default::default()
        })
    }

    /// A reactor enforcing exactly the given allow list.
    fn reactor_allowing(entries: &[&str]) -> anyhow::Result<Reactor> {
        Ok(HoprServerIpForwardingReactor::new(
            OffchainKeypair::random(),
            allow_list_config(entries)?,
        ))
    }

    fn plain(host: &str) -> anyhow::Result<SealedHost> {
        Ok(SealedHost::Plain(
            IpOrHost::from_str(host).context("parsing target host")?,
        ))
    }

    /// A Session arriving for `target`. The far end of its byte-stream is returned so that the caller
    /// decides how long it stays open.
    fn incoming(target: SessionTarget) -> (IncomingSession<tokio::io::DuplexStream>, tokio::io::DuplexStream) {
        let (session, far_end) = tokio::io::duplex(1024);
        (
            IncomingSession {
                id: SessionId::random(),
                session,
                target,
            },
            far_end,
        )
    }

    #[tokio::test]
    async fn a_reactor_with_no_rules_imposes_no_terms() -> anyhow::Result<()> {
        let decision = reactor_with(vec![]).admit(tcp("example.com:443")?).await?;

        assert_eq!(decision, SessionAdmissionDecision::default());
        Ok(())
    }

    /// `UnsealedTarget::new` is the only place the wire's two stream variants become an
    /// [`IpProtocol`](hopr_utils::network_types::prelude::IpProtocol), and the pattern tests build
    /// `UnsealedTarget` directly — so nothing else would notice the two arms being transposed, and a
    /// transposition misprices every UDP Session.
    #[tokio::test]
    async fn a_protocol_rule_tells_the_two_stream_kinds_apart() -> anyhow::Result<()> {
        let udp_only = reactor_with(vec![SessionAdmissionRule {
            enforce_pix: Some(true),
            ..rule("udp:*:*")?
        }]);

        assert_eq!(
            udp_only.admit(udp("example.com:53")?).await?.enforce_pix,
            Some(true),
            "a UDP rule must catch a UDP target"
        );
        assert_eq!(
            udp_only.admit(tcp("example.com:53")?).await?,
            SessionAdmissionDecision::default(),
            "and must not catch the TCP target at the same host and port"
        );

        // The other direction, so that a transposition cannot pass by being wrong both ways.
        let tcp_only = reactor_with(vec![SessionAdmissionRule {
            enforce_pix: Some(true),
            ..rule("tcp:*:*")?
        }]);

        assert_eq!(tcp_only.admit(tcp("example.com:53")?).await?.enforce_pix, Some(true));
        assert_eq!(
            tcp_only.admit(udp("example.com:53")?).await?,
            SessionAdmissionDecision::default()
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_target_matching_no_rule_falls_through_to_the_nodes_own_terms() -> anyhow::Result<()> {
        let reactor = reactor_with(vec![SessionAdmissionRule {
            enforce_pix: Some(true),
            ..rule("tcp:*:443")?
        }]);

        let decision = reactor.admit(tcp("example.com:8080")?).await?;

        assert_eq!(decision, SessionAdmissionDecision::default());
        Ok(())
    }

    #[tokio::test]
    async fn the_first_matching_rule_wins_over_a_later_broader_one() -> anyhow::Result<()> {
        let reactor = reactor_with(vec![
            SessionAdmissionRule {
                enforce_pix: Some(false),
                ..rule("tcp:free.example.com:*")?
            },
            SessionAdmissionRule {
                enforce_pix: Some(true),
                ..rule("*")?
            },
        ]);

        assert_eq!(
            reactor.admit(tcp("free.example.com:443")?).await?.enforce_pix,
            Some(false),
            "the specific rule listed first must win"
        );
        assert_eq!(
            reactor.admit(tcp("paid.example.com:443")?).await?.enforce_pix,
            Some(true),
            "anything it does not cover falls to the catch-all"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_rule_states_only_the_terms_it_sets() -> anyhow::Result<()> {
        let enforce_only = reactor_with(vec![SessionAdmissionRule {
            enforce_pix: Some(true),
            ..rule("*")?
        }])
        .admit(tcp("example.com:443")?)
        .await?;
        assert_eq!(enforce_only.enforce_pix, Some(true));
        assert!(
            enforce_only.pix_quota_range.is_none(),
            "an unset quota must not be invented"
        );

        let quota_only = reactor_with(vec![SessionAdmissionRule {
            quota_range_min: Some(10),
            quota_range_max: Some(20),
            ..rule("*")?
        }])
        .admit(tcp("example.com:443")?)
        .await?;
        assert!(quota_only.enforce_pix.is_none());
        assert_eq!(quota_only.pix_quota_range, Some(10..=20));
        Ok(())
    }

    #[tokio::test]
    async fn one_open_quota_bound_narrows_only_the_other_end() -> anyhow::Result<()> {
        let floor_only = reactor_with(vec![SessionAdmissionRule {
            quota_range_min: Some(10),
            ..rule("*")?
        }])
        .admit(tcp("example.com:443")?)
        .await?;
        // The open end saturates, so intersecting it with the node's range leaves that end alone.
        assert_eq!(floor_only.pix_quota_range, Some(10..=u64::MAX));

        let ceiling_only = reactor_with(vec![SessionAdmissionRule {
            quota_range_max: Some(20),
            ..rule("*")?
        }])
        .admit(tcp("example.com:443")?)
        .await?;
        assert_eq!(ceiling_only.pix_quota_range, Some(u64::MIN..=20));
        Ok(())
    }

    #[tokio::test]
    async fn a_service_rule_applies_to_services_and_not_to_streams() -> anyhow::Result<()> {
        let reactor = reactor_with(vec![SessionAdmissionRule {
            enforce_pix: Some(false),
            ..rule("service:0")?
        }]);

        assert_eq!(
            reactor.admit(service(SERVICE_ID_LOOPBACK)).await?.enforce_pix,
            Some(false)
        );
        assert_eq!(reactor.admit(service(1)).await?.enforce_pix, None);
        assert_eq!(reactor.admit(tcp("example.com:443")?).await?.enforce_pix, None);
        Ok(())
    }

    #[tokio::test]
    async fn a_target_that_cannot_be_unsealed_is_denied_rather_than_defaulted() -> anyhow::Result<()> {
        let reactor = reactor_with(vec![SessionAdmissionRule {
            enforce_pix: Some(true),
            ..rule("*")?
        }]);

        // Sealed to a key that is not this node's, so unsealing cannot succeed. Falling through to
        // the node's terms here would let a peer skip a rule simply by sealing its target.
        let request = SessionAdmissionRequest::new(
            SessionId::random(),
            SessionTarget::TcpStream(SealedHost::Sealed(vec![1, 2, 3].into_boxed_slice())),
            0,
        );

        assert!(matches!(reactor.admit(request).await, Err(ForwarderError::Denied(_))));
        Ok(())
    }

    #[test]
    fn rules_deserialize_from_configuration() -> anyhow::Result<()> {
        let cfg: SessionIpForwardingConfig = serde_json::from_str(
            r#"{
                "session_admission_rules": [
                    { "target": "service:0", "enforce_pix": false },
                    { "target": "tcp:*.example.com:443", "quota_range_min": 340000000 },
                    { "target": "*", "enforce_pix": true, "quota_range_max": 650000000 }
                ]
            }"#,
        )
        .context("deserializing forwarding config")?;

        assert_eq!(cfg.session_admission_rules.len(), 3);
        assert_eq!(cfg.session_admission_rules[0].target.to_string(), "service:0");
        assert_eq!(cfg.session_admission_rules[1].quota_range_min, Some(340000000));
        assert_eq!(cfg.session_admission_rules[2].enforce_pix, Some(true));
        // Absent stanza means no rules, so an existing config keeps its behaviour.
        assert!(
            serde_json::from_str::<SessionIpForwardingConfig>("{}")
                .context("deserializing empty config")?
                .session_admission_rules
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn a_rule_whose_quota_bounds_cross_is_rejected_at_load() -> anyhow::Result<()> {
        let cfg = SessionIpForwardingConfig {
            session_admission_rules: vec![SessionAdmissionRule {
                quota_range_min: Some(20),
                quota_range_max: Some(10),
                ..rule("*")?
            }],
            ..Default::default()
        };

        assert!(
            cfg.validate().is_err(),
            "a range admitting nothing is a typo, not a policy"
        );
        Ok(())
    }

    #[test]
    fn an_allow_list_of_addresses_and_names_deserializes_and_is_written_back_unchanged() -> anyhow::Result<()> {
        let entries = [
            "10.0.0.1:8000",
            "[fd00::1]:443",
            "gnosisvpnserver:8000",
            "wgserver:52820",
        ];
        let cfg: SessionIpForwardingConfig =
            serde_json::from_value(serde_json::json!({ "target_allow_list": entries }))
                .context("deserializing forwarding config")?;

        assert_eq!(cfg.target_allow_list.len(), entries.len());
        assert!(
            cfg.target_allow_list.contains(&IpOrHost::Ip("10.0.0.1:8000".parse()?)),
            "an address keeps meaning that address"
        );
        assert!(
            cfg.target_allow_list
                .contains(&IpOrHost::Dns("gnosisvpnserver".into(), 8000))
        );
        cfg.validate().context("validating forwarding config")?;

        // What is written back is what was written in, so a config that predates names round-trips.
        let mut written: Vec<String> = serde_json::from_value(
            serde_json::to_value(&cfg).context("serializing forwarding config")?["target_allow_list"].clone(),
        )
        .context("reading the written list")?;
        written.sort();
        let mut expected = entries.map(String::from);
        expected.sort();
        assert_eq!(written, expected);
        Ok(())
    }

    #[test]
    fn an_allow_list_entry_without_a_port_is_rejected_at_deserialization() {
        for entry in ["gnosisvpnserver", "gnosisvpnserver:http", "10.0.0.1"] {
            assert!(
                serde_json::from_value::<SessionIpForwardingConfig>(
                    serde_json::json!({ "target_allow_list": [entry] })
                )
                .is_err(),
                "{entry} names no port"
            );
        }
    }

    #[test]
    fn an_allow_list_name_that_no_host_can_have_is_rejected_at_load() -> anyhow::Result<()> {
        for entry in [
            ":80",
            "exa mple.com:80",
            "*.example.com:80",
            "172.30.0:8000",
            "127.1:80",
            "a..b:80",
            ".example.com:80",
        ] {
            assert!(
                allow_list_config(&[entry])?.validate().is_err(),
                "{entry} can never match a host"
            );
        }

        for entry in [
            "gnosisvpnserver:8000",
            "wgserver:52820",
            "Mixed.Case.example:443",
            "root.dot.:80",
            "_sip._tcp.example:5060",
            "1.example.com:80",
            "10.0.0.1:8000",
            "[2001:db8::1]:443",
        ] {
            allow_list_config(&[entry])?
                .validate()
                .with_context(|| format!("{entry} is a usable entry"))?;
        }
        Ok(())
    }

    #[test]
    fn a_rejected_allow_list_entry_is_named_in_the_error() -> anyhow::Result<()> {
        let message = allow_list_config(&["gnosisvpnserver:8000", "172.30.0:8000"])?
            .validate()
            .expect_err("a mistyped address is rejected")
            .to_string();

        assert!(message.contains("172.30.0:8000"), "{message}");
        assert!(
            !message.contains("gnosisvpnserver"),
            "only the entry at fault is named: {message}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_target_off_the_allow_list_is_refused_over_either_protocol() -> anyhow::Result<()> {
        let reactor = reactor_allowing(&["10.0.0.5:8000"])?;

        for target in [
            SessionTarget::TcpStream(plain("10.0.0.6:8000")?),
            SessionTarget::UdpStream(plain("10.0.0.6:8000")?),
        ] {
            let (session, _far_end) = incoming(target);
            let result = reactor.process(session).await;
            assert!(matches!(result, Err(ForwarderError::Denied(_))), "{result:?}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_tcp_target_on_the_allow_list_is_forwarded_to() -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("binding the target")?;
        let target = listener
            .local_addr()
            .context("reading the target's address")?
            .to_string();

        let (session, _far_end) = incoming(SessionTarget::TcpStream(plain(&target)?));
        reactor_allowing(&[&target])?.process(session).await?;

        tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .context("nothing connected to the target")?
            .context("accepting the connection")?;
        Ok(())
    }

    #[tokio::test]
    async fn a_udp_target_on_the_allow_list_is_forwarded_to() -> anyhow::Result<()> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .context("binding the target")?;
        let target = socket.local_addr().context("reading the target's address")?.to_string();

        let (session, _far_end) = incoming(SessionTarget::UdpStream(plain(&target)?));
        reactor_allowing(&[&target])?.process(session).await?;
        Ok(())
    }

    #[tokio::test]
    async fn the_allow_list_does_not_stand_in_the_way_when_it_is_off() -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("binding the target")?;
        let target = listener
            .local_addr()
            .context("reading the target's address")?
            .to_string();
        let reactor = HoprServerIpForwardingReactor::new(
            OffchainKeypair::random(),
            SessionIpForwardingConfig {
                use_target_allow_list: false,
                ..allow_list_config(&["10.0.0.5:8000"])?
            },
        );

        let (session, _far_end) = incoming(SessionTarget::TcpStream(plain(&target)?));
        reactor.process(session).await?;

        tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .context("nothing connected to the target")?
            .context("accepting the connection")?;
        Ok(())
    }
}
