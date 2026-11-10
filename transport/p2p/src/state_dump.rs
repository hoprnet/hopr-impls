//! Transport-owned observations, independent of chain or graph topology.
use crate::HoprNetwork;
use hopr_api::network::{Health, NetworkView};
use hopr_state_dump::{Dump, Signal, StateDump};
use serde::Serialize;

/// Counts only: no network-sized list is allocated for reporting.
#[derive(Debug, Serialize)]
pub struct NetworkState {
    pub peer_id: String,
    pub connected_peers: usize,
    pub discovered_peers: usize,
    /// The transport's own `NetworkView::health` classification, not a graph QoS inference.
    pub health: String,
}
impl StateDump for HoprNetwork {
    type State = NetworkState;
    async fn state_dump(&self) -> Result<Dump<Self::State>, String> {
        let health = self.health();
        let (signal, reason) = match health {
            Health::Unknown => (Signal::Unknown, "transport_health_unknown"),
            Health::Red | Health::Orange => (Signal::NeedsAnalysis, "transport_connectivity_degraded"),
            Health::Yellow | Health::Green => (Signal::Healthy, "transport_connectivity_ok"),
        };
        Ok(Dump {
            signal,
            reason,
            state: NetworkState {
                peer_id: self.store.me().to_string(),
                connected_peers: self.tracker.len(),
                discovered_peers: self.store.iter_keys().count(),
                health: health.to_string(),
            },
        })
    }
}

#[cfg(all(test, feature = "runtime-tokio"))]
mod tests {
    use super::*;
    use hopr_api::types::crypto::prelude::{Keypair, OffchainKeypair};
    use hopr_state_dump::{Config, Reporter};
    #[tokio::test]
    async fn actual_transport_reports_degradation_and_recovery_independently() {
        let key = OffchainKeypair::from_secret(&[1; 32]).unwrap();
        let (network, _process) = crate::HoprLibp2pNetworkBuilder::new(futures::stream::empty())
            .build(&key, vec![], "/hopr/state-dump-test/1", true)
            .await
            .unwrap();
        let reporter = Reporter::new("transport", "node", network.clone(), Config::default());
        let disconnected = reporter.collect().await;
        assert!(disconnected.analysis_required);
        assert_eq!(disconnected.state.value().unwrap().connected_peers, 0);
        for i in 2..6u8 {
            let key = OffchainKeypair::from_secret(&[i; 32]).unwrap();
            network.tracker.insert((*key.public()).into());
        }
        let recovered = reporter.collect().await;
        assert!(!recovered.analysis_required);
        assert_eq!(recovered.signal, Signal::Healthy);
        assert_eq!(recovered.state.value().unwrap().connected_peers, 4);
    }
}
