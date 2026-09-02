//! HOPR session server that bridges TCP/UDP sockets from the Session Exit node to a destination.

pub mod config;
pub mod target_pattern;

use std::{marker::PhantomData, net::SocketAddr};

use hopr_api::{
    node::{IncomingSession, SessionAdmissionDecision, SessionAdmissionRequest},
    types::crypto::prelude::OffchainKeypair,
};
use hopr_utils::{
    network_types::{
        prelude::{ForeignDataMode, IpOrHostExt, ServiceId, SessionTarget},
        udp::{ConnectedUdpStream, UdpStreamParallelism},
        utils::transfer_session,
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

    fn all_ips_allowed(&self, addrs: &[SocketAddr]) -> bool {
        if self.cfg.use_target_allow_list {
            for addr in addrs {
                if !self.cfg.target_allow_list.contains(addr) {
                    tracing::error!(%addr, "address not allowed by the target allow list, denying the target");
                    return false;
                }
                tracing::debug!(%addr, "address allowed by the target allow list, accepting the target");
            }
        }
        true
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

    #[tracing::instrument(level = "debug", skip(self))]
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

                if !self.all_ips_allowed(&[resolved_udp_target]) {
                    return Err(ForwarderError::general(format!(
                        "denied target address {resolved_udp_target}"
                    )));
                }

                let mut udp_bridge = ConnectedUdpStream::builder()
                    .with_buffer_size(HOPR_UDP_BUFFER_SIZE)
                    .with_counterparty(resolved_udp_target)
                    .with_foreign_data_mode(ForeignDataMode::Error)
                    .with_queue_size(HOPR_UDP_QUEUE_SIZE)
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
                    match transfer_session(&mut session.session, &mut udp_bridge, HOPR_UDP_BUFFER_SIZE, None).await {
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

                if !self.all_ips_allowed(&resolved_tcp_targets) {
                    return Err(ForwarderError::general(format!(
                        "denied target address {resolved_tcp_targets:?}"
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
    use std::str::FromStr;

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
        Ok(SessionAdmissionRequest::new(
            SessionId::random(),
            SessionTarget::TcpStream(SealedHost::Plain(
                IpOrHost::from_str(host).context("parsing target host")?,
            )),
        ))
    }

    fn service(id: ServiceId) -> SessionAdmissionRequest {
        SessionAdmissionRequest::new(SessionId::random(), SessionTarget::ExitNode(id))
    }

    #[tokio::test]
    async fn a_reactor_with_no_rules_imposes_no_terms() -> anyhow::Result<()> {
        let decision = reactor_with(vec![]).admit(tcp("example.com:443")?).await?;

        assert_eq!(decision, SessionAdmissionDecision::default());
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
}
