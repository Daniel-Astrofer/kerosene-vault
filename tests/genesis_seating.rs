//! Genesis seating wired into runtime ledger + DKG roster (production-native path).

use kerosene_vault::bootstrap::{AuthMode, CeremonyMode, DkgMode, ShareStoreMode, VaultConfig, VaultRuntime};
use kerosene_vault::domain::{AttestationMode, BitcoinNetwork, NodeId, ResharePolicy, VaultNodeTier};
use std::collections::BTreeMap;

fn base_lab() -> VaultConfig {
    VaultConfig {
        node_id: NodeId::new("vault-home").unwrap(),
        node_tier: VaultNodeTier::Domestic,
        tee_available: false,
        attestation_mode: AttestationMode::Sim,
        listen_addr: "127.0.0.1:0".into(),
        lab_root: format!("lab-seat-{}", std::process::id()),
        seed_peers: vec![
            ("vault-epyc".into(), "127.0.0.1:7702".into()),
            ("vault-home-2".into(), "127.0.0.1:7703".into()),
        ],
        peer_tiers: BTreeMap::from([("vault-epyc".into(), VaultNodeTier::Sev)]),
        refuse_sim: false,
        genesis_n: Some(2),
        online_count: Some(2),
        lab_timelock_scale: 0,
        lab_timelock_env_set: false,
        lab_council_n: 2,
        lab_min_rebuilds: 1,
        hardened: false,
        attestation_staging_stub: false,
        ceremony_mode: CeremonyMode::Lab,
        open_economy: false,
        bitcoin_network: BitcoinNetwork::Testnet3,
        auth_mode: AuthMode::StaticToken,
        vault_token: Some("t".into()),
        tls_cert_path: None,
        tls_key_path: None,
        tls_client_ca_path: None,
        tls_client_cert_path: None,
        tls_client_key_path: None,
        share_store_mode: ShareStoreMode::AeadDisk,
        share_passphrase: Some("pass".into()),
        share_tpm_seal: false,
        share_tpm_stub: false,
        share_tpm_clear_fallback: false,
        data_dir: None,
        anti_nonce_shared_dir: None,
        measurement_pin_hex: None,
        dealer_requested: false,
        dkg_mode: DkgMode::DistributedWire,
        reshare_policy: ResharePolicy::Manual,
        governance_reward_sats: 0,
        governance_reward_bps: 0,
        transport: kerosene_vault::adapters::VaultTransport::Clearnet,
        peer_http: kerosene_vault::adapters::PeerHttpSettings::clearnet_defaults(),
        clearnet_publish: false,
    }
}

#[test]
fn runtime_seats_sev_before_domestic_for_genesis_roster() {
    let rt = VaultRuntime::build(base_lab()).expect("build");
    let ids: Vec<_> = rt.genesis_roster.iter().map(|n| n.as_str()).collect();
    assert_eq!(ids, vec!["vault-epyc", "vault-home"]);
    let health = rt.get_health.execute().unwrap();
    assert_eq!(health.node_tier, "domestic");
    assert!(!health.tee_available);
    assert_eq!(health.genesis_roster, vec!["vault-epyc", "vault-home"]);
}

#[test]
fn all_domestic_genesis_seats_normally() {
    let mut cfg = base_lab();
    cfg.node_id = NodeId::new("vault-1").unwrap();
    cfg.seed_peers = vec![
        ("vault-2".into(), "127.0.0.1:7702".into()),
        ("vault-3".into(), "127.0.0.1:7703".into()),
    ];
    cfg.peer_tiers.clear();
    cfg.genesis_n = Some(3);
    cfg.online_count = Some(3);
    let rt = VaultRuntime::build(cfg).unwrap();
    assert_eq!(rt.genesis_roster.len(), 3);
    assert_eq!(rt.genesis_roster[0].as_str(), "vault-1");
}

#[test]
fn unseated_local_node_fails_closed() {
    let mut cfg = base_lab();
    // Local is lowest priority domestic; SEV + another domestic fill n=2.
    cfg.node_id = NodeId::new("vault-zzz").unwrap();
    cfg.seed_peers = vec![
        ("vault-epyc".into(), "127.0.0.1:7702".into()),
        ("vault-aaa".into(), "127.0.0.1:7703".into()),
    ];
    cfg.peer_tiers = BTreeMap::from([("vault-epyc".into(), VaultNodeTier::Sev)]);
    cfg.genesis_n = Some(2);
    let err = match VaultRuntime::build(cfg) {
        Ok(_) => panic!("expected seating fail-closed"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("not seated"),
        "expected seating fail-closed, got {msg}"
    );
}
