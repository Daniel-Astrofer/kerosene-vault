use std::sync::Arc;

use crate::adapters::{InMemoryLedger, InMemoryPeerDirectory, SimAttestationAdapter, SystemClock};
use crate::application::{
    GetHealth, GetLedgerSnapshot, PingPeer, ProposeEpochAdvance, VoteEpochAdvance,
};
use crate::bootstrap::VaultConfig;
use crate::domain::{Constitution, DomainError, Measurement, NodeId, PeerEndpoint, PeerInfo};

pub struct VaultRuntime {
    pub config: VaultConfig,
    pub get_health: GetHealth,
    pub ping_peer: PingPeer,
    pub get_ledger: GetLedgerSnapshot,
    pub propose_epoch: ProposeEpochAdvance,
    pub vote_epoch: VoteEpochAdvance,
    pub peers: Arc<InMemoryPeerDirectory>,
    pub ledger: Arc<InMemoryLedger>,
}

impl VaultRuntime {
    pub fn build(config: VaultConfig) -> Result<Self, DomainError> {
        config.validate_attestation_policy()?;

        let peers = Arc::new(InMemoryPeerDirectory::new());
        for (id, addr) in &config.seed_peers {
            peers.upsert_sync(PeerInfo {
                id: NodeId::new(id.clone())?,
                endpoint: PeerEndpoint {
                    address: addr.clone(),
                },
            })?;
        }

        let mut active_set = vec![config.node_id.clone()];
        for (id, _) in &config.seed_peers {
            active_set.push(NodeId::new(id.clone())?);
        }
        active_set.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        active_set.dedup();

        let n = config.genesis_n.unwrap_or(active_set.len().max(2));
        // Pad or trim active set to n for lab genesis consistency.
        while active_set.len() < n {
            active_set.push(NodeId::new(format!("vault-pad-{}", active_set.len()))?);
        }
        active_set.truncate(n);

        let constitution = Constitution::v1_lab(n)?;
        let ledger = Arc::new(InMemoryLedger::genesis(
            constitution,
            active_set,
            config.node_id.clone(),
        )?);

        let attestation: Arc<dyn crate::application::AttestationPort> =
            match config.attestation_mode {
                crate::domain::AttestationMode::Sim => {
                    Arc::new(SimAttestationAdapter::new(config.lab_root.as_bytes()))
                }
                crate::domain::AttestationMode::Sev | crate::domain::AttestationMode::Sgx => {
                    return Err(DomainError::AttestationRejected(
                        "SEV/SGX adapters not implemented yet (F2 uses sim only)".into(),
                    ));
                }
            };

        let measurement = Measurement::from_bytes(b"kerosene-vault-f2-ledger");
        let clock: Arc<dyn crate::application::ClockPort> = Arc::new(SystemClock);
        let peers_port: Arc<dyn crate::application::PeerDirectoryPort> = peers.clone();
        let ledger_port: Arc<dyn crate::application::LedgerPort> = ledger.clone();

        let get_health = GetHealth::new(
            config.node_id.clone(),
            peers_port.clone(),
            attestation.clone(),
        );
        let ping_peer = PingPeer::new(peers_port, attestation, clock, measurement);
        let get_ledger = GetLedgerSnapshot::new(ledger_port.clone());
        let propose_epoch = ProposeEpochAdvance::new(ledger_port.clone(), config.node_id.clone());
        let vote_epoch = VoteEpochAdvance::new(ledger_port, config.node_id.clone());

        Ok(Self {
            config,
            get_health,
            ping_peer,
            get_ledger,
            propose_epoch,
            vote_epoch,
            peers,
            ledger,
        })
    }
}
