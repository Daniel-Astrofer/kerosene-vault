use std::sync::Arc;

use crate::adapters::{
    AeadDiskShareStore, DistributedDkgAdapter, InMemoryBucketLedger, InMemoryEconomy,
    InMemoryLedger, InMemoryPeerDirectory, InMemoryReleaseMesh, LedgerDayEpochStub,
    MutualTlsAuthAdapter, PersistedAntiNonce, SimAttestationAdapter, StaticTokenAuthAdapter,
    SystemClock, TeeAttestationAdapter, TeeSealShareStore, ThresholdVaultState,
};
#[cfg(feature = "dealer_lab")]
use crate::adapters::{dealer_fatal_banner, DealerLabAdapter, FrostSignOrchestrator};
use crate::application::{
    AccrueMinerRewards, AllocateProfit, AntiNoncePort, CosignRelease, DailyRotationPort, DkgPort,
    GateIntent, GetAllowlist, GetEconomyStatus, GetHealth, GetLedgerSnapshot, PingPeer,
    ProposeEpochAdvance, ProposeMinerPayouts, ProposeRelease, RebuildRelease, ShareStorePort,
    SignMessage, StaticOnlineCount, UpsertMiner, VaultAuthPort, VoteEpochAdvance, ActivateRelease,
};
use crate::bootstrap::{AuthMode, CeremonyMode, ShareStoreMode, VaultConfig};
use crate::domain::{
    run_dkg, Constitution, DomainError, EconomyState, Measurement, NodeId, PeerEndpoint, PeerInfo,
    ReleasePolicy,
};

pub struct VaultRuntime {
    pub config: VaultConfig,
    pub get_health: GetHealth,
    pub ping_peer: PingPeer,
    pub get_ledger: GetLedgerSnapshot,
    pub propose_epoch: ProposeEpochAdvance,
    pub vote_epoch: VoteEpochAdvance,
    pub sign_message: SignMessage,
    pub propose_release: ProposeRelease,
    pub rebuild_release: RebuildRelease,
    pub cosign_release: CosignRelease,
    pub activate_release: ActivateRelease,
    pub get_allowlist: GetAllowlist,
    pub gate_intent: GateIntent,
    pub allocate_profit: AllocateProfit,
    pub get_economy: GetEconomyStatus,
    pub upsert_miner: UpsertMiner,
    pub accrue_rewards: AccrueMinerRewards,
    pub propose_miner_payouts: ProposeMinerPayouts,
    pub peers: Arc<InMemoryPeerDirectory>,
    pub ledger: Arc<InMemoryLedger>,
    pub threshold: Arc<ThresholdVaultState>,
    pub online: Arc<StaticOnlineCount>,
    pub release_mesh: Arc<InMemoryReleaseMesh>,
    pub buckets: Arc<InMemoryBucketLedger>,
    pub economy: Arc<InMemoryEconomy>,
    pub auth: Arc<dyn VaultAuthPort>,
    pub share_store: Arc<dyn ShareStorePort>,
    pub dkg: Arc<dyn DkgPort>,
    pub daily_rotation: Arc<dyn DailyRotationPort>,
    pub anti_nonce: Arc<dyn AntiNoncePort>,
    #[cfg(feature = "dealer_lab")]
    pub frost: Option<Arc<FrostSignOrchestrator>>,
}

impl VaultRuntime {
    pub fn build(config: VaultConfig) -> Result<Self, DomainError> {
        config.validate_attestation_policy()?;
        config.validate_hygiene()?;

        if matches!(
            config.ceremony_mode,
            CeremonyMode::Staging | CeremonyMode::Production
        ) && config.dealer_requested
        {
            return Err(DomainError::DealerForbidden(
                "dealer DKG refused in staging/production".into(),
            ));
        }

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

        let constitution = if config.open_economy {
            Constitution::v1_open(n)?
        } else {
            Constitution::v1_lab(n)?
        };
        let max_tx = constitution.max_withdraw_per_tx_sats;
        let max_day = constitution.max_withdraw_per_day_sats;
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
                    Arc::new(TeeAttestationAdapter::new(
                        config.attestation_mode,
                        config.attestation_staging_stub,
                        config.lab_root.as_bytes(),
                    )?)
                }
            };

        let measurement = Measurement::from_bytes(b"kerosene-vault-lab-p0");
        let clock: Arc<dyn crate::application::ClockPort> = Arc::new(SystemClock);
        let peers_port: Arc<dyn crate::application::PeerDirectoryPort> = peers.clone();
        let ledger_port: Arc<dyn crate::application::LedgerPort> = ledger.clone();

        let mut release_policy = ReleasePolicy::lab_default(n);
        release_policy.lab_timelock_scale = config.effective_lab_timelock_scale();
        release_policy.council_n = config.lab_council_n.max(2);
        release_policy.min_rebuilds = config.lab_min_rebuilds.max(1);
        let release_mesh = Arc::new(InMemoryReleaseMesh::new(release_policy));
        let release_port: Arc<dyn crate::application::ReleaseStorePort> = release_mesh.clone();
        let blob_port: Arc<dyn crate::application::BlobStorePort> = release_mesh.clone();

        let buckets = Arc::new(InMemoryBucketLedger::from_constitution_caps(max_tx, max_day));
        let bucket_port: Arc<dyn crate::application::BucketLedgerPort> = buckets.clone();

        let economy = Arc::new(InMemoryEconomy::new(EconomyState::new_open()));
        let economy_port: Arc<dyn crate::application::EconomyPort> = economy.clone();

        let auth: Arc<dyn VaultAuthPort> = match config.auth_mode {
            AuthMode::StaticToken => {
                let token = config
                    .effective_vault_token()
                    .ok_or_else(|| {
                        DomainError::AuthRejected(
                            "VAULT_API_TOKEN (or VAULT_TOKEN) required for static auth".into(),
                        )
                    })?
                    .to_string();
                Arc::new(StaticTokenAuthAdapter::new(token))
            }
            AuthMode::MutualTls => Arc::new(MutualTlsAuthAdapter::new()),
        };

        let data_root = config.effective_data_dir();
        let share_store: Arc<dyn ShareStorePort> = match config.share_store_mode {
            ShareStoreMode::AeadDisk => {
                let pass = config
                    .share_passphrase
                    .clone()
                    .unwrap_or_else(|| "kerosene-vault-lab-passphrase".into());
                Arc::new(AeadDiskShareStore::new(
                    data_root.join("shares"),
                    pass,
                ))
            }
            ShareStoreMode::TeeSeal => Arc::new(TeeSealShareStore::new()),
        };

        let anti_nonce: Arc<dyn AntiNoncePort> = Arc::new(PersistedAntiNonce::open(
            data_root.join("used_sessions.log"),
        )?);
        let daily_rotation: Arc<dyn DailyRotationPort> =
            Arc::new(LedgerDayEpochStub::new(clock.clone()));

        #[cfg(feature = "dealer_lab")]
        let (dkg, frost): (Arc<dyn DkgPort>, Option<Arc<FrostSignOrchestrator>>) = {
            if config.dealer_requested
                && matches!(config.ceremony_mode, CeremonyMode::Lab)
                && !config.hardened
            {
                dealer_fatal_banner();
                let adapter = DealerLabAdapter::new();
                let max = n.min(u16::MAX as usize) as u16;
                let min = t.min(u16::MAX as usize) as u16;
                let bundle = DealerLabAdapter::generate(max.max(2), min.max(2).min(max))?;
                // Seal local share bytes (serialized verifying key + identifier index) for lab store smoke.
                if let Some((id, kp)) = bundle.key_packages.iter().next() {
                    let blob = format!("frost-lab-share:{id:?}");
                    let _ = share_store.put_share(config.node_id.as_str(), blob.as_bytes());
                    let _ = kp;
                }
                let orch = FrostSignOrchestrator::new(
                    bundle.key_packages,
                    bundle.pubkey_package,
                    t,
                    Box::new(PersistedAntiNonce::open(
                        data_root.join("frost_sessions.log"),
                    )?),
                    Box::new(LedgerDayEpochStub::new(clock.clone())),
                );
                (Arc::new(adapter), Some(Arc::new(orch)))
            } else {
                (Arc::new(DistributedDkgAdapter::new()), None)
            }
        };

        #[cfg(not(feature = "dealer_lab"))]
        let dkg: Arc<dyn DkgPort> = {
            if config.dealer_requested {
                return Err(DomainError::DealerForbidden(
                    "dealer DKG not compiled (build without dealer_lab)".into(),
                ));
            }
            Arc::new(DistributedDkgAdapter::new())
        };

        let get_health = GetHealth::new(
            config.node_id.clone(),
            peers_port.clone(),
            attestation.clone(),
        );
        let ping_peer = PingPeer::new(peers_port, attestation, clock.clone(), measurement);
        let get_ledger = GetLedgerSnapshot::new(ledger_port.clone());
        let propose_epoch = ProposeEpochAdvance::new(ledger_port.clone(), config.node_id.clone());
        let vote_epoch = VoteEpochAdvance::new(ledger_port.clone(), config.node_id.clone());
        let propose_release = ProposeRelease::new(
            release_port.clone(),
            blob_port.clone(),
            ledger_port.clone(),
            clock.clone(),
        );
        let rebuild_release = RebuildRelease::new(release_port.clone(), blob_port);
        let cosign_release = CosignRelease::new(
            release_port.clone(),
            ledger_port.clone(),
            clock.clone(),
            config.node_id.clone(),
        );
        let activate_release =
            ActivateRelease::new(release_port.clone(), ledger_port.clone(), clock);
        let get_allowlist = GetAllowlist::new(release_port);
        let gate_intent = GateIntent::new(bucket_port, ledger_port.clone(), economy_port.clone());
        let allocate_profit = AllocateProfit::new(ledger_port.clone());
        let get_economy = GetEconomyStatus::new(economy_port.clone(), ledger_port.clone());
        let upsert_miner = UpsertMiner::new(economy_port.clone());
        let accrue_rewards = AccrueMinerRewards::new(economy_port.clone(), ledger_port.clone());
        let propose_miner_payouts = ProposeMinerPayouts::new(economy_port, ledger_port);

        let mode = if config.hardened {
            "production-refuse"
        } else {
            "lab-visualize"
        };
        eprintln!(
            "MODE={mode} auth={} share_store={} dkg={} bitcoin={}",
            auth.mode_name(),
            share_store.store_kind(),
            dkg.mode_name(),
            config.bitcoin_network.as_str()
        );

        Ok(Self {
            config,
            get_health,
            ping_peer,
            get_ledger,
            propose_epoch,
            vote_epoch,
            sign_message,
            propose_release,
            rebuild_release,
            cosign_release,
            activate_release,
            get_allowlist,
            gate_intent,
            allocate_profit,
            get_economy,
            upsert_miner,
            accrue_rewards,
            propose_miner_payouts,
            peers,
            ledger,
            threshold,
            online,
            release_mesh,
            buckets,
            economy,
            auth,
            share_store,
            dkg,
            daily_rotation,
            anti_nonce,
            #[cfg(feature = "dealer_lab")]
            frost,
        })
    }
}
