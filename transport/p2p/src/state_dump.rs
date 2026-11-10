//! Transport-owned observations, independent of chain or graph topology.
use hopr_api::network::{Health, NetworkView};
use serde::Serialize;

use crate::{HoprNetwork, state_reporting::Dump};

/// Counts only: no network-sized list is allocated for reporting.
#[derive(Debug, Serialize)]
pub struct NetworkState {
    pub peer_id: String,
    pub connected_peers: usize,
    pub discovered_peers: usize,
    /// The transport's own `NetworkView::health` classification, not a graph QoS inference.
    pub health: String,
}
impl HoprNetwork {
    async fn collect_dump(&self) -> Result<Dump<NetworkState>, String> {
        let health = self.health();
        let (analysis_required, reason) = match health {
            Health::Unknown => (true, "transport_health_unknown"),
            Health::Red | Health::Orange => (true, "transport_connectivity_degraded"),
            Health::Yellow | Health::Green => (false, "transport_connectivity_ok"),
        };
        Ok(Dump {
            analysis_required,
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

impl HoprNetwork {
    /// Collect transport diagnostics without exposing the internal snapshot schema.
    pub async fn state(&self) -> Result<impl serde::Serialize + serde::de::DeserializeOwned + Send, String> {
        hopr_api::StateDump::state_dump(self)
            .await
            .map_err(|error| error.to_string())
    }

    /// Emit independent periodic diagnostics until the host cancels this future.
    /// HOPR_STATE_DUMP_INTERVAL controls the interval; zero disables collection.
    pub async fn run_state_reporting(&self, instance: &str) -> Result<(), String> {
        let config = crate::state_reporting::Config::from_env().map_err(|e| e.to_string())?;
        crate::state_reporting::Reporter::new("transport", instance, config)
            .run(|| self.collect_dump())
            .await;
        Ok(())
    }
}

impl hopr_api::StateDump for HoprNetwork {
    type Error = std::io::Error;

    async fn state_dump(
        &self,
    ) -> Result<impl serde::Serialize + serde::de::DeserializeOwned + Send + 'static, Self::Error> {
        let dump = self.collect_dump().await.map_err(std::io::Error::other)?;
        serde_json::to_value(dump).map_err(std::io::Error::other)
    }
}

#[cfg(all(test, feature = "runtime-tokio"))]
mod tests {
    use hopr_api::types::crypto::prelude::{Keypair, OffchainKeypair};

    use crate::state_reporting::{Config, Reporter};

    #[tokio::test]
    async fn actual_transport_reports_degradation_and_recovery_independently() {
        let key = OffchainKeypair::from_secret(&[1; 32]).unwrap();
        let (network, _process) = crate::HoprLibp2pNetworkBuilder::new(futures::stream::empty())
            .build(&key, vec![], "/hopr/state-dump-test/1", true)
            .await
            .unwrap();
        let shared = std::sync::Arc::new(network.clone());
        let snapshot = hopr_api::StateDump::state_dump(&shared).await.unwrap();
        let value = serde_json::to_value(snapshot).unwrap();
        assert_eq!(value["state"]["connected_peers"], 0);
        let reporter = Reporter::new("transport", "node", Config::default());
        let disconnected = reporter.collect(network.collect_dump()).await;
        assert!(disconnected.analysis_required);
        assert_eq!(disconnected.state.value().unwrap().connected_peers, 0);
        for i in 2..6u8 {
            let key = OffchainKeypair::from_secret(&[i; 32]).unwrap();
            network.tracker.insert((*key.public()).into());
        }
        let recovered = reporter.collect(network.collect_dump()).await;
        assert!(!recovered.analysis_required);
        assert_eq!(recovered.state.value().unwrap().connected_peers, 4);
    }
}
