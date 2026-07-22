use std::sync::Arc;

use crate::adapters::{
    InMemoryLedger, InMemoryPeerDirectory, SimAttestationAdapter, SystemClock, ThresholdVaultState,
};
use crate::application::{
    GetHealth, GetLedgerSnapshot, PingPeer, ProposeEpochAdvance, SignMessage, StaticOnlineCount,
    VoteEpochAdvance,
};
use crate::bootstrap::VaultConfig;
use crate::domain::{
    run_dkg, Constitution, DomainError, Measurement, NodeId, PeerEndpoint, PeerInfo,
};

pub struct VaultRuntime {
    pub config: VaultConfig,
    pub get_health: GetHealth,
    pub ping_peer: PingPeer,
    pub get_ledger: GetLedgerSnapshot,
    pub propose_epoch: ProposeEpochAdvance,
    pub vote_epoch: VoteEpochAdvance,
    pub sign_message: SignMessage,
    pub peers: Arc<InMemoryPeerDirectory>,
    pub ledger: Arc<InMemoryLedger>,
    pub threshold: Arc<ThresholdVaultState>,
    pub online: Arc<StaticOnlineCount>,
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
        while active_set.len() < n {
            active_set.push(NodeId::new(format!("vault-pad-{}", active_set.len()))?);
        }
        active_set.truncate(n);

        let constitution = Constitution::v1_lab(n)?;
        let t = constitution.signing_t;
        let dkg_set = active_set.clone();
        let ledger = Arc::new(InMemoryLedger::genesis(
            constitution,
            active_set,
            config.node_id.clone(),
        )?);

        let entropy = format!(
            "genesis|{}|{}",
            config.lab_root,
            dkg_set
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        let (group, shares) = run_dkg(&dkg_set, t, entropy.as_bytes())?;
        let local_share = shares
            .iter()
            .find(|s| s.node_id == config.node_id)
            .cloned()
            .ok_or_else(|| DomainError::ThresholdError("local share missing after DKG".into()))?;
        let online = Arc::new(StaticOnlineCount {
            count: config.online_count.unwrap_or(n),
        });
        let threshold = Arc::new(ThresholdVaultState::new(group, local_share, shares));
        let sign_message = SignMessage::new(threshold.clone(), online.clone());

        let attestation: Arc<dyn crate::application::AttestationPort> =
            match config.attestation_mode {
                crate::domain::AttestationMode::Sim => {
                    Arc::new(SimAttestationAdapter::new(config.lab_root.as_bytes()))
                }
                crate::domain::AttestationMode::Sev | crate::domain::AttestationMode::Sgx => {
                    return Err(DomainError::AttestationRejected(
                        "SEV/SGX adapters not implemented yet (F3 uses sim only)".into(),
                    ));
                }
            };

        let measurement = Measurement::from_bytes(b"kerosene-vault-f3-threshold");
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
            sign_message,
            peers,
            ledger,
            threshold,
            online,
        })
    }
}
