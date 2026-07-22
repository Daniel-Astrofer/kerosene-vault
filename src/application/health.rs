use std::sync::Arc;

use crate::application::ports::{AttestationPort, PeerDirectoryPort};
use crate::domain::{DomainError, HealthStatus, NodeHealth, NodeId};

pub struct GetHealth {
    node_id: NodeId,
    peers: Arc<dyn PeerDirectoryPort>,
    attestation: Arc<dyn AttestationPort>,
}

impl GetHealth {
    pub fn new(
        node_id: NodeId,
        peers: Arc<dyn PeerDirectoryPort>,
        attestation: Arc<dyn AttestationPort>,
    ) -> Self {
        Self {
            node_id,
            peers,
            attestation,
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
            attestation_mode: self.attestation.mode().as_str().to_string(),
            peer_count: peers.len(),
        })
    }
}
