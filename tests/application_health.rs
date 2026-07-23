use std::sync::Arc;

use kerosene_vault::adapters::{InMemoryPeerDirectory, SimAttestationAdapter, SystemClock};
use kerosene_vault::application::{GetHealth, PingPeer};
use kerosene_vault::domain::{AttestationMode, HealthStatus, Measurement, NodeId, PeerEndpoint, PeerInfo};

#[test]
fn health_ready_when_peers_present() {
    let peers = Arc::new(InMemoryPeerDirectory::new());
    peers
        .upsert_sync(PeerInfo {
            id: NodeId::new("vault-2").unwrap(),
            endpoint: PeerEndpoint {
                address: "vault-2:7701".into(),
            },
        })
        .unwrap();
    let attestation = Arc::new(SimAttestationAdapter::new(b"lab"));
    let uc = GetHealth::new(
        NodeId::new("vault-1").unwrap(),
        peers,
        attestation,
        kerosene_vault::domain::VaultNodeTier::Domestic,
        false,
    );
    let health = uc.execute().unwrap();
    assert_eq!(health.peer_count, 1);
    assert_eq!(health.status, HealthStatus::Ready);
    assert_eq!(health.attestation_mode, AttestationMode::Sim.as_str());
    assert!(health.genesis_roster.is_empty());
    assert_eq!(
        health.peer_reachability,
        kerosene_vault::domain::PeerReachability::DirectoryOnly
    );
    assert!(health.peers_reachable.is_none());
}

#[test]
fn ping_peer_verifies_sim_quote() {
    let peers = Arc::new(InMemoryPeerDirectory::new());
    let peer_id = NodeId::new("vault-2").unwrap();
    peers
        .upsert_sync(PeerInfo {
            id: peer_id.clone(),
            endpoint: PeerEndpoint {
                address: "vault-2:7701".into(),
            },
        })
        .unwrap();
    let attestation = Arc::new(SimAttestationAdapter::new(b"lab"));
    let clock = Arc::new(SystemClock);
    let measurement = Measurement::from_bytes(b"bin");
    let uc = PingPeer::new(peers, attestation, clock, measurement);
    let report = uc.execute(&peer_id).unwrap();
    assert!(report.ok);
    assert!(report.verified_attestation);
}

#[test]
fn refuse_sim_policy_domain_flag() {
    assert!(AttestationMode::Sim.is_lab_only());
    assert!(!AttestationMode::Software.is_lab_only());
    assert!(!AttestationMode::Sev.is_lab_only());
}

#[test]
fn sim_forbidden_when_refuse_sim() {
    use kerosene_vault::bootstrap::VaultConfig;
    use kerosene_vault::domain::DomainError;

    let mut cfg = VaultConfig {
        node_id: NodeId::new("v1").unwrap(),
        node_tier: kerosene_vault::domain::VaultNodeTier::Domestic,
        tee_available: false,
        attestation_mode: AttestationMode::Sim,
        listen_addr: "127.0.0.1:0".into(),
        lab_root: "x".into(),
        seed_peers: vec![],
        peer_tiers: std::collections::BTreeMap::new(),
        refuse_sim: true,
        genesis_n: None,
        online_count: None,
        lab_timelock_scale: 0,
        lab_timelock_env_set: false,
        lab_council_n: 3,
        lab_min_rebuilds: 3,
        hardened: true,
        attestation_staging_stub: false,
        ceremony_mode: kerosene_vault::bootstrap::CeremonyMode::Lab,
        open_economy: false,
        bitcoin_network: kerosene_vault::domain::BitcoinNetwork::Testnet3,
        auth_mode: kerosene_vault::bootstrap::AuthMode::MutualTls,
        vault_token: None,
        tls_cert_path: Some("/lab/certs/vault-server.crt".into()),
        tls_key_path: Some("/lab/certs/vault-server.key".into()),
        tls_client_ca_path: Some("/lab/certs/ca.crt".into()),
        tls_client_cert_path: Some("/lab/certs/vault-client.crt".into()),
        tls_client_key_path: Some("/lab/certs/vault-client.key".into()),
        tls_verify_policy: kerosene_vault::adapters::TlsPeerVerifyPolicy::Hostname,
        share_store_mode: kerosene_vault::bootstrap::ShareStoreMode::TeeSeal,
        share_passphrase: None,
        share_tpm_seal: false,
        share_tpm_stub: false,
        share_tpm_clear_fallback: false,
        data_dir: None,
        anti_nonce_shared_dir: None,
        measurement_pin_hex: None,
        dealer_requested: false,
        dkg_mode: kerosene_vault::bootstrap::DkgMode::Distributed,
        reshare_policy: kerosene_vault::domain::ResharePolicy::Manual,
        governance_reward_sats: 0,
        governance_reward_bps: 0,
        transport: kerosene_vault::adapters::VaultTransport::Clearnet,
        peer_http: kerosene_vault::adapters::PeerHttpSettings::clearnet_defaults(),
        clearnet_publish: false,
    };
    assert_eq!(
        cfg.validate_attestation_policy(),
        Err(DomainError::SimAttestationForbidden)
    );
    cfg.refuse_sim = false;
    cfg.hardened = false;
    assert!(cfg.validate_attestation_policy().is_ok());
}
