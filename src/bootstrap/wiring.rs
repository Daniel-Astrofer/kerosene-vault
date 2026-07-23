use std::collections::BTreeMap;
use std::sync::Arc;

use crate::adapters::{
    AeadDiskShareStore, DistributedDkgAdapter, DistributedWireDkgPort, FrostShareSlot,
    FrostShareState, FrostSignOrchestrator, FrostTrBitcoinOrchestrator, FrostTrShareSlot,
    HttpAntiNonceTransport, InMemoryBucketLedger, InMemoryEconomy, InMemoryLedger,
    InMemoryPeerDirectory, InMemoryReleaseMesh, MutualTlsAuthAdapter, PolicyReshareHook,
    QuorumAntiNonce, QuorumDailyRotation, SharedAntiNonce, SimAttestationAdapter,
    StaticTokenAuthAdapter, SystemClock, TeeAttestationAdapter, TeeSealAdapter,
    ThresholdVaultState, WireDkgHub, WireDkgPeerAuth,
};
#[cfg(feature = "dealer_lab")]
use crate::adapters::{
    dealer_fatal_banner, generate_tr_dealer, load_tr_shares, persist_tr_shares, DealerLabAdapter,
};
use crate::application::{
    AccrueGovernanceWork, AccrueMinerRewards, AllocateProfit, AntiNoncePort, CosignRelease,
    DailyRotationPort, DkgPort, GateIntent, GetAllowlist, GetEconomyStatus, GetHealth,
    GetLedgerSnapshot, PingPeer, ProposeEpochAdvance, ProposeMinerPayouts, ProposeRelease,
    RebuildRelease, ReshareHookPort, ShareStorePort, SignMessage, StaticOnlineCount, UpsertMiner,
    VaultAuthPort, VoteEpochAdvance, ActivateRelease,
};
use crate::bootstrap::{AuthMode, CeremonyMode, DkgMode, ShareStoreMode, VaultConfig};
use crate::domain::{
    run_dkg, Constitution, DomainError, EconomyState, Measurement, NodeId, PeerEndpoint, PeerInfo,
    ReleasePolicy,
};

pub struct VaultRuntime {
    pub config: VaultConfig,
    /// Genesis / wire-DKG roster after SEV-priority seating (§3.1).
    pub genesis_roster: Vec<NodeId>,
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
    pub reshare_hook: Arc<dyn ReshareHookPort>,
    pub frost_shares: Arc<FrostShareSlot>,
    pub anti_nonce: Arc<dyn AntiNoncePort>,
    /// Present after dealer_lab or distributed FROST DKG keygen.
    pub frost: Option<Arc<FrostSignOrchestrator>>,
    /// Taproot BIP-340 FROST keyset for on-chain PSBT / sighash signing.
    pub frost_tr: Option<Arc<FrostTrBitcoinOrchestrator>>,
    pub frost_tr_shares: Arc<FrostTrShareSlot>,
    /// Over-wire DKG hub (HTTP round exchange between peers).
    pub wire_dkg: Arc<WireDkgHub>,
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

        // Genesis seating: prefer SEV > SGX > domestic when filling signing_n.
        // Same roster drives ledger active_set and over-wire FROST DKG start.
        let active_set = config.seat_genesis()?;
        let n = active_set.len();
        if !active_set.iter().any(|id| id == &config.node_id) {
            return Err(DomainError::ThresholdError(format!(
                "local node {} not seated in genesis roster (SEV/SGX peers filled VAULT_GENESIS_N seats; this node is waiting-set only)",
                config.node_id
            )));
        }

        let mut constitution = if config.open_economy {
            Constitution::v1_open(n)?
        } else {
            Constitution::v1_lab(n)?
        };
        if let Some(hex) = config.measurement_pin_hex.as_deref() {
            constitution = constitution.with_measurement_pin(Measurement::from_hex(hex)?);
        } else {
            constitution.ensure_measurement_pin();
        }
        let measurement = constitution.measurement_pin_or_hash();
        let max_tx = constitution.max_withdraw_per_tx_sats;
        let max_day = constitution.max_withdraw_per_day_sats;
        let t = constitution.signing_t;
        let rotation_quorum = constitution.governance_t.max(1);
        let dkg_set = active_set.clone();
        let ledger = Arc::new(InMemoryLedger::genesis(
            constitution,
            active_set.clone(),
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
                crate::domain::AttestationMode::Software => {
                    Arc::new(SimAttestationAdapter::software(config.lab_root.as_bytes()))
                }
                crate::domain::AttestationMode::Sev | crate::domain::AttestationMode::Sgx => {
                    let refuse_stub = matches!(config.ceremony_mode, CeremonyMode::Production)
                        || cfg!(feature = "production");
                    Arc::new(TeeAttestationAdapter::with_policy(
                        config.attestation_mode,
                        config.attestation_staging_stub,
                        refuse_stub,
                        config.lab_root.as_bytes(),
                        measurement.clone(),
                        Vec::new(),
                    )?)
                }
            };

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
        let governance_reward = config.governance_reward_config();
        let accrue_governance = Arc::new(AccrueGovernanceWork::new(
            economy_port.clone(),
            ledger_port.clone(),
            config.node_id.clone(),
            governance_reward,
        ));

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
            ShareStoreMode::TeeSeal => {
                #[cfg(feature = "production")]
                {
                    // Production feature: never wire staging stub.
                    #[cfg(feature = "tee_hw")]
                    {
                        if matches!(
                            config.attestation_mode,
                            crate::domain::AttestationMode::Sev
                                | crate::domain::AttestationMode::Sgx
                        ) {
                            Arc::new(TeeSealAdapter::hw(
                                data_root.join("tee-shares"),
                                config.attestation_mode,
                                measurement.clone(),
                                attestation.clone(),
                            )?)
                        } else {
                            Arc::new(TeeSealAdapter::fail_closed(measurement.clone()))
                        }
                    }
                    #[cfg(not(feature = "tee_hw"))]
                    {
                        let _ = &attestation;
                        Arc::new(TeeSealAdapter::fail_closed(measurement.clone()))
                    }
                }
                #[cfg(not(feature = "production"))]
                {
                    if config.attestation_staging_stub
                        && !matches!(config.ceremony_mode, CeremonyMode::Production)
                    {
                        let pass = config
                            .share_passphrase
                            .clone()
                            .unwrap_or_else(|| "kerosene-vault-lab-passphrase".into());
                        Arc::new(
                            TeeSealAdapter::staging_stub(
                                data_root.join("tee-shares"),
                                pass,
                                measurement.clone(),
                            )
                            .with_attestation(attestation.clone()),
                        )
                    } else {
                        #[cfg(feature = "tee_hw")]
                        {
                            if matches!(
                                config.attestation_mode,
                                crate::domain::AttestationMode::Sev
                                    | crate::domain::AttestationMode::Sgx
                            ) {
                                Arc::new(TeeSealAdapter::hw(
                                    data_root.join("tee-shares"),
                                    config.attestation_mode,
                                    measurement.clone(),
                                    attestation.clone(),
                                )?)
                            } else {
                                Arc::new(TeeSealAdapter::fail_closed(measurement.clone()))
                            }
                        }
                        #[cfg(not(feature = "tee_hw"))]
                        {
                            let _ = &attestation;
                            Arc::new(TeeSealAdapter::fail_closed(measurement.clone()))
                        }
                    }
                }
            }
        };

        let wire_token = config
            .effective_vault_token()
            .unwrap_or("kerosene-vault-lab-only")
            .to_string();
        let mut peer_prepare = Vec::new();
        for (_, addr) in &config.seed_peers {
            let base = if addr.starts_with("http://") || addr.starts_with("https://") {
                addr.clone()
            } else {
                format!("http://{addr}")
            };
            peer_prepare.push(format!("{base}/v1/anti-nonce/prepare"));
        }
        // Lab static_token: send X-Vault-Token. mTLS mode: omit token (peer identity is TLS).
        let peer_auth_token = match config.auth_mode {
            AuthMode::StaticToken => Some(wire_token.clone()),
            AuthMode::MutualTls => None,
        };
        let peer_count = peer_prepare.len();
        let anti_transport = Arc::new(HttpAntiNonceTransport::with_peer_http(
            peer_prepare,
            peer_auth_token,
            config.peer_http.clone(),
        ));
        let anti_nonce: Arc<dyn AntiNoncePort> = Arc::new(QuorumAntiNonce::open(
            data_root.join("used_sessions.log"),
            anti_transport,
            peer_count,
        )?);
        let frost_shares = Arc::new(FrostShareSlot::new());
        let frost_tr_shares = Arc::new(FrostTrShareSlot::new());
        let reshare_hook: Arc<dyn ReshareHookPort> = Arc::new(
            PolicyReshareHook::new(
                config.reshare_policy,
                ledger_port.clone(),
                config.node_id.clone(),
                frost_shares.clone(),
                frost_tr_shares.clone(),
            )
            .with_share_store(share_store.clone())
            .with_governance(accrue_governance.clone()),
        );
        let daily_rotation: Arc<dyn DailyRotationPort> = Arc::new(QuorumDailyRotation::with_persist(
            clock.clone(),
            rotation_quorum,
            config.node_id.as_str(),
            reshare_hook.clone(),
            data_root.join("day_epoch"),
        ));

        // Wire DKG fan-out only to seated peers (not waiting-set seeds cut by tier).
        let mut peer_addrs = BTreeMap::new();
        for (id, addr) in &config.seed_peers {
            if active_set.iter().any(|s| s.as_str() == id.as_str()) {
                peer_addrs.insert(id.clone(), addr.clone());
            }
        }
        let peer_auth = match config.auth_mode {
            AuthMode::StaticToken => WireDkgPeerAuth::StaticToken(wire_token),
            AuthMode::MutualTls => {
                let (cert, key, ca) = config.require_mtls_client_identity()?;
                WireDkgPeerAuth::MutualTls {
                    client_cert_path: std::path::PathBuf::from(cert),
                    client_key_path: std::path::PathBuf::from(key),
                    ca_path: std::path::PathBuf::from(ca),
                }
            }
        };
        let wire_dkg = Arc::new(WireDkgHub::with_peer_http(
            config.node_id.as_str().to_string(),
            peer_addrs,
            peer_auth,
            config.peer_http.clone(),
        )?);

        #[cfg(feature = "dealer_lab")]
        let (dkg, frost, frost_tr): (
            Arc<dyn DkgPort>,
            Option<Arc<FrostSignOrchestrator>>,
            Option<Arc<FrostTrBitcoinOrchestrator>>,
        ) = {
            if config.dealer_requested
                && matches!(config.ceremony_mode, CeremonyMode::Lab)
                && !config.hardened
            {
                dealer_fatal_banner();
                let adapter = DealerLabAdapter::new();
                let max = n.min(u16::MAX as usize) as u16;
                let min = t.min(u16::MAX as usize) as u16;
                let max = max.max(2);
                let min = min.max(2).min(max);
                let bundle = DealerLabAdapter::generate(max, min)?;
                // Seal local share bytes (serialized verifying key + identifier index) for lab store smoke.
                if let Some((id, kp)) = bundle.key_packages.iter().next() {
                    let blob = format!("frost-lab-share:{id:?}");
                    let _ = share_store.put_share(config.node_id.as_str(), blob.as_bytes());
                    let _ = kp;
                }
                frost_shares.install(FrostShareState {
                    key_packages: bundle.key_packages,
                    pubkey_package: bundle.pubkey_package,
                    min_signers: t,
                });
                let orch = FrostSignOrchestrator::from_share_slot(
                    frost_shares.clone(),
                    Box::new(SharedAntiNonce(anti_nonce.clone())),
                    daily_rotation.clone(),
                );
                // Prefer sealed Taproot material in VAULT_DATA_DIR; dealer only if missing.
                let tr_state = match load_tr_shares(share_store.as_ref()) {
                    Ok(existing) => existing,
                    Err(_) => {
                        let fresh = generate_tr_dealer(max, min)?;
                        persist_tr_shares(&fresh, share_store.as_ref())?;
                        fresh
                    }
                };
                frost_tr_shares.install(tr_state);
                let tr_orch = FrostTrBitcoinOrchestrator::new(
                    frost_tr_shares.clone(),
                    Box::new(SharedAntiNonce(anti_nonce.clone())),
                    daily_rotation.clone(),
                    config.bitcoin_network,
                );
                (
                    Arc::new(adapter),
                    Some(Arc::new(orch)),
                    Some(Arc::new(tr_orch)),
                )
            } else if matches!(config.dkg_mode, DkgMode::DistributedWire) {
                // Over-wire ceremony via /v1/dkg/round{1,2,3}; no in-process dealer/sim.
                (Arc::new(DistributedWireDkgPort), None, None)
            } else if matches!(config.dkg_mode, DkgMode::Distributed) {
                let (dkg, frost) = wire_distributed_dkg(
                    n,
                    t,
                    &share_store,
                    daily_rotation.clone(),
                    frost_shares.clone(),
                    anti_nonce.clone(),
                )?;
                (dkg, frost, None)
            } else {
                (Arc::new(DistributedDkgAdapter::new()), None, None)
            }
        };

        #[cfg(not(feature = "dealer_lab"))]
        let (dkg, frost, frost_tr): (
            Arc<dyn DkgPort>,
            Option<Arc<FrostSignOrchestrator>>,
            Option<Arc<FrostTrBitcoinOrchestrator>>,
        ) = {
            if config.dealer_requested || matches!(config.dkg_mode, DkgMode::DealerLab) {
                return Err(DomainError::DealerForbidden(
                    "dealer DKG not compiled (build without dealer_lab)".into(),
                ));
            }
            if matches!(config.dkg_mode, DkgMode::DistributedWire) {
                (Arc::new(DistributedWireDkgPort), None, None)
            } else {
                let (dkg, frost) = wire_distributed_dkg(
                    n,
                    t,
                    &share_store,
                    daily_rotation.clone(),
                    frost_shares.clone(),
                    anti_nonce.clone(),
                )?;
                (dkg, frost, None)
            }
        };

        let get_health = GetHealth::with_roster(
            config.node_id.clone(),
            peers_port.clone(),
            attestation.clone(),
            config.node_tier,
            config.tee_available,
            dkg_set
                .iter()
                .map(|n| n.as_str().to_string())
                .collect(),
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
        )
        .with_governance(accrue_governance.clone());
        let activate_release =
            ActivateRelease::new(release_port.clone(), ledger_port.clone(), clock)
                .with_governance(accrue_governance.clone());
        let get_allowlist = GetAllowlist::new(release_port);
        let gate_intent = GateIntent::new(bucket_port, ledger_port.clone(), economy_port.clone());
        let allocate_profit = AllocateProfit::new(ledger_port.clone());
        let get_economy = GetEconomyStatus::new(
            economy_port.clone(),
            ledger_port.clone(),
            governance_reward,
            config.node_tier,
            config.attestation_mode,
            config.tee_available,
        );
        let upsert_miner = UpsertMiner::new(economy_port.clone());
        let accrue_rewards = AccrueMinerRewards::new(economy_port.clone(), ledger_port.clone());
        let propose_miner_payouts = ProposeMinerPayouts::new(economy_port, ledger_port);

        let mode = if config.hardened {
            "production-refuse"
        } else {
            "lab-visualize"
        };
        eprintln!(
            "MODE={mode} tier={} tee_available={} auth={} share_store={} dkg={} reshare={} bitcoin={}",
            config.node_tier.as_str(),
            config.tee_available,
            auth.mode_name(),
            share_store.store_kind(),
            dkg.mode_name(),
            config.reshare_policy.as_str(),
            config.bitcoin_network.as_str()
        );

        Ok(Self {
            config,
            genesis_roster: dkg_set,
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
            reshare_hook,
            frost_shares,
            anti_nonce,
            frost,
            frost_tr,
            frost_tr_shares,
            wire_dkg,
        })
    }
}

fn wire_distributed_dkg(
    n: usize,
    t: usize,
    share_store: &Arc<dyn ShareStorePort>,
    rotation: Arc<dyn DailyRotationPort>,
    shares: Arc<FrostShareSlot>,
    anti_nonce: Arc<dyn AntiNoncePort>,
) -> Result<(Arc<dyn DkgPort>, Option<Arc<FrostSignOrchestrator>>), DomainError> {
    let max = n.min(u16::MAX as usize) as u16;
    let min = t.min(u16::MAX as usize) as u16;
    let max = max.max(2);
    let min = min.max(2).min(max);
    let bundle = DistributedDkgAdapter::run_in_process(max, min)?;
    // Persist via ShareStorePort only (AEAD lab; TEE refuses in prod until Gate seal).
    DistributedDkgAdapter::persist_shares(&bundle, share_store.as_ref())?;
    shares.install(FrostShareState {
        key_packages: bundle.key_packages,
        pubkey_package: bundle.pubkey_package,
        min_signers: min as usize,
    });
    let orch = FrostSignOrchestrator::from_share_slot(
        shares,
        Box::new(SharedAntiNonce(anti_nonce)),
        rotation,
    );
    Ok((
        Arc::new(DistributedDkgAdapter::new()),
        Some(Arc::new(orch)),
    ))
}
