use std::sync::Arc;

use crate::adapters::{InMemoryPeerDirectory, SimAttestationAdapter, SystemClock};
use crate::application::{GetHealth, PingPeer};
use crate::bootstrap::VaultConfig;
use crate::domain::{DomainError, Measurement, PeerEndpoint, PeerInfo};

pub struct VaultRuntime {
    pub config: VaultConfig,
    pub get_health: GetHealth,
    pub ping_peer: PingPeer,
    pub peers: Arc<InMemoryPeerDirectory>,
}

impl VaultRuntime {
    pub fn build(config: VaultConfig) -> Result<Self, DomainError> {
        config.validate_attestation_policy()?;

        let peers = Arc::new(InMemoryPeerDirectory::new());
        for (id, addr) in &config.seed_peers {
            peers.upsert_sync(PeerInfo {
                id: crate::domain::NodeId::new(id.clone())?,
                endpoint: PeerEndpoint {
                    address: addr.clone(),
                },
            })?;
        }

        let attestation: Arc<dyn crate::application::AttestationPort> =
            match config.attestation_mode {
                crate::domain::AttestationMode::Sim => {
                    Arc::new(SimAttestationAdapter::new(config.lab_root.as_bytes()))
                }
                crate::domain::AttestationMode::Sev | crate::domain::AttestationMode::Sgx => {
                    return Err(DomainError::AttestationRejected(
                        "SEV/SGX adapters not implemented yet (F1 skeleton uses sim only)".into(),
                    ));
                }
            };

        let measurement = Measurement::from_bytes(b"kerosene-vault-f1-skeleton");
        let clock: Arc<dyn crate::application::ClockPort> = Arc::new(SystemClock);
        let peers_port: Arc<dyn crate::application::PeerDirectoryPort> = peers.clone();

        let get_health = GetHealth::new(
            config.node_id.clone(),
            peers_port.clone(),
            attestation.clone(),
        );
        let ping_peer = PingPeer::new(peers_port, attestation, clock, measurement);

        Ok(Self {
            config,
            get_health,
            ping_peer,
            peers,
        })
    }
}
