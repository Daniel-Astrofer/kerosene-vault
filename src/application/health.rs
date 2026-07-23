use std::sync::Arc;

use crate::application::ports::{AttestationPort, PeerDirectoryPort};
use crate::domain::{DomainError, HealthStatus, NodeHealth, NodeId, VaultNodeTier};

pub struct GetHealth {
    node_id: NodeId,
    peers: Arc<dyn PeerDirectoryPort>,
    attestation: Arc<dyn AttestationPort>,
    node_tier: VaultNodeTier,
    tee_available: bool,
    genesis_roster: Vec<String>,
}

impl GetHealth {
    pub fn new(
        node_id: NodeId,
        peers: Arc<dyn PeerDirectoryPort>,
        attestation: Arc<dyn AttestationPort>,
        node_tier: VaultNodeTier,
        tee_available: bool,
    ) -> Self {
        Self::with_roster(node_id, peers, attestation, node_tier, tee_available, vec![])
    }

    pub fn with_roster(
        node_id: NodeId,
        peers: Arc<dyn PeerDirectoryPort>,
        attestation: Arc<dyn AttestationPort>,
        node_tier: VaultNodeTier,
        tee_available: bool,
        genesis_roster: Vec<String>,
    ) -> Self {
        Self {
            node_id,
            peers,
            attestation,
            node_tier,
            tee_available,
            genesis_roster,
        }
    }

    pub fn execute(&self) -> Result<NodeHealth, DomainError> {
        let peers = self.peers.list_peers()?;
        let status = if peers.is_empty() {
            HealthStatus::Starting
        } else {
            HealthStatus::Ready
        };
        Ok(NodeHealth {
            node_id: self.node_id.clone(),
            status,
            node_tier: self.node_tier.as_str().to_string(),
            attestation_mode: self.attestation.mode().as_str().to_string(),
            tee_available: self.tee_available,
            peer_count: peers.len(),
            genesis_roster: self.genesis_roster.clone(),
        })
    }
}
