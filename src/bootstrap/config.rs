use crate::domain::{AttestationMode, BitcoinNetwork, DomainError, NodeId, ResharePolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyMode {
    Lab,
    Staging,
    Production,
}

impl CeremonyMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "lab" => Some(Self::Lab),
            "staging" => Some(Self::Staging),
            "production" | "prod" => Some(Self::Production),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lab => "lab",
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    StaticToken,
    MutualTls,
}

impl AuthMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "static" | "token" | "static_token" => Some(Self::StaticToken),
            "mtls" | "mutual_tls" => Some(Self::MutualTls),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaticToken => "static_token",
            Self::MutualTls => "mtls",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareStoreMode {
    AeadDisk,
    TeeSeal,
}

/// DKG path selection. Dealer is lab-only (`dealer_lab` feature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgMode {
    /// Trusted-dealer single-process (lab visualize only).
    DealerLab,
    /// Multi-round FROST DKG without dealer — in-process N-party sim (lab/single-node).
    Distributed,
    /// Multi-round FROST DKG over HTTP between vault peers (no dealer).
    DistributedWire,
}

impl DkgMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "dealer" | "dealer_lab" => Some(Self::DealerLab),
            "distributed" | "dkg_distributed" => Some(Self::Distributed),
            "distributed_wire" | "wire" | "over_wire" => Some(Self::DistributedWire),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DealerLab => "dealer_lab",
            Self::Distributed => "distributed",
            Self::DistributedWire => "distributed_wire",
        }
    }

    pub fn is_distributed(self) -> bool {
        matches!(self, Self::Distributed | Self::DistributedWire)
    }
}

impl ShareStoreMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "aead" | "disk" | "aead_disk" => Some(Self::AeadDisk),
            "tee" | "tee_seal" => Some(Self::TeeSeal),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AeadDisk => "aead_disk",
            Self::TeeSeal => "tee_seal",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub node_id: NodeId,
    pub attestation_mode: AttestationMode,
    pub listen_addr: String,
    pub lab_root: String,
    pub seed_peers: Vec<(String, String)>,
    pub refuse_sim: bool,
    /// Explicit genesis n; defaults to len(local+seeds) when unset.
    pub genesis_n: Option<usize>,
    /// Online vaults for fail-stop (lab). Defaults to genesis_n.
    pub online_count: Option<usize>,
    /// Lab: scales NORMAL release timelock (`0` = immediate).
    pub lab_timelock_scale: u64,
    /// True when `LAB_TIMELOCK_SCALE` env was present (forbidden in hardened builds).
    pub lab_timelock_env_set: bool,
    /// Lab council size for release personal quorum.
    pub lab_council_n: usize,
    /// Minimum independent rebuilds before cosign.
    pub lab_min_rebuilds: usize,
    /// Production / staging / refuse-sim: lock lab-only HTTP and flags (§13.5 / F8).
    pub hardened: bool,
    /// Staging-only TEE stub quotes (never for production ceremony).
    pub attestation_staging_stub: bool,
    pub ceremony_mode: CeremonyMode,
    /// `VAULT_ECONOMY=open` enables live p%=1% miner splits (F9); default lab dry-run.
    pub open_economy: bool,
    pub bitcoin_network: BitcoinNetwork,
    pub auth_mode: AuthMode,
    pub vault_token: Option<String>,
    /// PEM server certificate (`VAULT_TLS_CERT_PATH`) — required when `auth_mode=mtls`.
    pub tls_cert_path: Option<String>,
    /// PEM server private key (`VAULT_TLS_KEY_PATH`) — required when `auth_mode=mtls`.
    pub tls_key_path: Option<String>,
    /// PEM client CA bundle (`VAULT_TLS_CLIENT_CA_PATH`) — required when `auth_mode=mtls`.
    pub tls_client_ca_path: Option<String>,
    /// PEM client certificate for outbound peer calls (`VAULT_TLS_CLIENT_CERT_PATH`) — mTLS peer DKG.
    pub tls_client_cert_path: Option<String>,
    /// PEM client private key for outbound peer calls (`VAULT_TLS_CLIENT_KEY_PATH`) — mTLS peer DKG.
    pub tls_client_key_path: Option<String>,
    pub share_store_mode: ShareStoreMode,
    pub share_passphrase: Option<String>,
    /// Share / anti-nonce disk root (`VAULT_DATA_DIR`); lab default under `lab_root`.
    pub data_dir: Option<String>,
    /// Deprecated/ignored: anti-nonce uses quorum HTTP prepare among `VAULT_SEED_PEERS`
    /// (`VAULT_ANTI_NONCE_SHARED_DIR` kept for env back-compat only).
    pub anti_nonce_shared_dir: Option<String>,
    /// Optional hex measurement pin (`VAULT_MEASUREMENT_PIN`); else constitution hash pin.
    pub measurement_pin_hex: Option<String>,
    /// Request dealer DKG (only honored when `dealer_lab` feature is compiled).
    pub dealer_requested: bool,
    /// Explicit DKG mode (`VAULT_DKG_MODE`).
    pub dkg_mode: DkgMode,
    /// FROST reshare cadence (`VAULT_RESHARE_POLICY=daily|manual`).
    pub reshare_policy: ResharePolicy,
}

impl VaultConfig {
    pub fn from_env() -> Result<Self, DomainError> {
        let node_id = NodeId::new(
            std::env::var("VAULT_NODE_ID").unwrap_or_else(|_| "vault-local-1".into()),
        )?;
        let mode_raw = std::env::var("ATTESTATION_MODE").unwrap_or_else(|_| "sim".into());
        let attestation_mode = AttestationMode::parse(&mode_raw).ok_or_else(|| {
            DomainError::AttestationRejected(format!("unknown ATTESTATION_MODE={mode_raw}"))
        })?;
        let listen_addr =
            std::env::var("VAULT_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:7701".into());
        let lab_root =
            std::env::var("LAB_ATTESTATION_ROOT").unwrap_or_else(|_| "kerosene-lab-root".into());

        let kerosene_env = std::env::var("KEROSENE_ENV").unwrap_or_else(|_| "lab".into());
        let is_production =
            cfg!(feature = "production") || kerosene_env.eq_ignore_ascii_case("production");
        let is_staging = kerosene_env.eq_ignore_ascii_case("staging");
        let refuse_sim = env_flag("KEROSENE_VAULT_REFUSE_SIM") || is_production || is_staging;
        let hardened = refuse_sim;
        let attestation_staging_stub = env_flag("ATTESTATION_STAGING_STUB");

        let ceremony_raw =
            std::env::var("VAULT_CEREMONY_MODE").unwrap_or_else(|_| kerosene_env.clone());
        let ceremony_mode = CeremonyMode::parse(&ceremony_raw).ok_or_else(|| {
            DomainError::AttestationRejected(format!("unknown VAULT_CEREMONY_MODE={ceremony_raw}"))
        })?;

        let mut seed_peers = Vec::new();
        if let Ok(raw) = std::env::var("VAULT_SEED_PEERS") {
            for part in raw.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (id, addr) = part.split_once('=').ok_or_else(|| {
                    DomainError::AttestationRejected(format!("bad VAULT_SEED_PEERS entry: {part}"))
                })?;
                seed_peers.push((id.trim().to_string(), addr.trim().to_string()));
            }
        }

        let genesis_n = std::env::var("VAULT_GENESIS_N")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let online_count = std::env::var("VAULT_ONLINE_COUNT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let lab_timelock_env_set = std::env::var_os("LAB_TIMELOCK_SCALE").is_some();
        let lab_timelock_scale = std::env::var("LAB_TIMELOCK_SCALE")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let lab_council_n = std::env::var("LAB_COUNCIL_N")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(3);
        let lab_min_rebuilds = std::env::var("LAB_MIN_REBUILDS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(3);
        let open_economy = matches!(
            std::env::var("VAULT_ECONOMY").as_deref(),
            Ok("open" | "OPEN" | "v1_open")
        );

        let btc_raw = std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "testnet3".into());
        let bitcoin_network = BitcoinNetwork::parse(&btc_raw).ok_or_else(|| {
            DomainError::BitcoinNetworkMismatch(format!("unknown BITCOIN_NETWORK={btc_raw}"))
        })?;

        let auth_raw = std::env::var("VAULT_AUTH_MODE").unwrap_or_else(|_| {
            if hardened {
                "mtls".into()
            } else {
                "static_token".into()
            }
        });
        let auth_mode = AuthMode::parse(&auth_raw).ok_or_else(|| {
            DomainError::AuthRejected(format!("unknown VAULT_AUTH_MODE={auth_raw}"))
        })?;
        // Lab P0 contract: VAULT_API_TOKEN (preferred) ↔ X-Vault-Token; VAULT_TOKEN legacy alias.
        let vault_token = env_nonempty_first(&["VAULT_API_TOKEN", "VAULT_TOKEN"]);
        let tls_cert_path = env_nonempty_first(&["VAULT_TLS_CERT_PATH"]);
        let tls_key_path = env_nonempty_first(&["VAULT_TLS_KEY_PATH"]);
        let tls_client_ca_path = env_nonempty_first(&["VAULT_TLS_CLIENT_CA_PATH"]);
        let tls_client_cert_path = env_nonempty_first(&["VAULT_TLS_CLIENT_CERT_PATH"]);
        let tls_client_key_path = env_nonempty_first(&["VAULT_TLS_CLIENT_KEY_PATH"]);

        let store_raw = std::env::var("VAULT_SHARE_STORE").unwrap_or_else(|_| {
            if hardened {
                "tee_seal".into()
            } else {
                "aead_disk".into()
            }
        });
        let share_store_mode = ShareStoreMode::parse(&store_raw).ok_or_else(|| {
            DomainError::ShareStoreForbidden(format!("unknown VAULT_SHARE_STORE={store_raw}"))
        })?;
        // Lab P0: VAULT_DATA_PASSPHRASE (preferred); VAULT_SHARE_PASSPHRASE legacy alias.
        let share_passphrase =
            env_nonempty_first(&["VAULT_DATA_PASSPHRASE", "VAULT_SHARE_PASSPHRASE"]);
        let data_dir = env_nonempty_first(&["VAULT_DATA_DIR"]);
        let anti_nonce_shared_dir = env_nonempty_first(&["VAULT_ANTI_NONCE_SHARED_DIR"]);
        let measurement_pin_hex = env_nonempty_first(&["VAULT_MEASUREMENT_PIN"]);

        // Lab P0 / Gate: VAULT_DKG_MODE (preferred); VAULT_DKG legacy alias.
        // `distributed` wins over the lab dealer default. Dealer never default in hardened.
        let dkg_raw = std::env::var("VAULT_DKG_MODE")
            .or_else(|_| std::env::var("VAULT_DKG"))
            .ok();
        let dkg_mode = match dkg_raw.as_deref() {
            Some(raw) => DkgMode::parse(raw).ok_or_else(|| {
                DomainError::AttestationRejected(format!("unknown VAULT_DKG_MODE={raw}"))
            })?,
            None if hardened => DkgMode::Distributed,
            None if cfg!(feature = "dealer_lab") => DkgMode::DealerLab,
            None => DkgMode::Distributed,
        };
        let dealer_requested = matches!(dkg_mode, DkgMode::DealerLab);
        let reshare_policy = ResharePolicy::from_env_or_default()?;

        let cfg = Self {
            node_id,
            attestation_mode,
            listen_addr,
            lab_root,
            seed_peers,
            refuse_sim,
            genesis_n,
            online_count,
            lab_timelock_scale,
            lab_timelock_env_set,
            lab_council_n,
            lab_min_rebuilds,
            hardened,
            attestation_staging_stub,
            ceremony_mode,
            open_economy,
            bitcoin_network,
            auth_mode,
            vault_token,
            tls_cert_path,
            tls_key_path,
            tls_client_ca_path,
            tls_client_cert_path,
            tls_client_key_path,
            share_store_mode,
            share_passphrase,
            data_dir,
            anti_nonce_shared_dir,
            measurement_pin_hex,
            dealer_requested,
            dkg_mode,
            reshare_policy,
        };
        cfg.validate_hygiene()?;
        Ok(cfg)
    }

    pub fn validate_attestation_policy(&self) -> Result<(), DomainError> {
        if self.refuse_sim && self.attestation_mode.is_lab_only() {
            return Err(DomainError::SimAttestationForbidden);
        }
        Ok(())
    }

    /// Prod/staging refuse: sim, lab timelock env, dealer, static token, host-disk share without TEE.
    pub fn validate_hygiene(&self) -> Result<(), DomainError> {
        self.validate_attestation_policy()?;
        if self.hardened {
            if self.attestation_mode.is_lab_only() {
                return Err(DomainError::LabFlagForbidden(
                    "ATTESTATION_MODE=sim".into(),
                ));
            }
            if self.lab_timelock_env_set {
                return Err(DomainError::LabFlagForbidden(
                    "LAB_TIMELOCK_SCALE".into(),
                ));
            }
        }
        if self.ceremony_mode == CeremonyMode::Production && self.attestation_staging_stub {
            return Err(DomainError::LabFlagForbidden(
                "ATTESTATION_STAGING_STUB in production ceremony".into(),
            ));
        }
        if cfg!(feature = "production") && self.attestation_staging_stub {
            return Err(DomainError::LabFlagForbidden(
                "ATTESTATION_STAGING_STUB refused under production feature".into(),
            ));
        }
        if matches!(
            self.ceremony_mode,
            CeremonyMode::Staging | CeremonyMode::Production
        ) && self.attestation_mode.is_lab_only()
        {
            return Err(DomainError::LabFlagForbidden(
                "ATTESTATION_MODE=sim".into(),
            ));
        }
        if matches!(
            self.ceremony_mode,
            CeremonyMode::Staging | CeremonyMode::Production
        ) {
            if self.dealer_requested {
                return Err(DomainError::DealerForbidden(
                    "dealer DKG refused in staging/production (ToB 2024)".into(),
                ));
            }
            if self.auth_mode == AuthMode::StaticToken {
                return Err(DomainError::AuthRejected(
                    "static token refused in staging/production; use mTLS".into(),
                ));
            }
            if self.share_store_mode == ShareStoreMode::AeadDisk {
                return Err(DomainError::TeeRequired(
                    "host disk AEAD share store refused without TEE in staging/production".into(),
                ));
            }
        }
        if self.auth_mode == AuthMode::MutualTls {
            self.require_mtls_paths()?;
            self.require_mtls_client_identity()?;
        }
        Ok(())
    }

    /// Paths for rustls mTLS serve (`VAULT_TLS_*`).
    pub fn require_mtls_paths(&self) -> Result<(&str, &str, &str), DomainError> {
        let cert = self.tls_cert_path.as_deref().filter(|s| !s.is_empty());
        let key = self.tls_key_path.as_deref().filter(|s| !s.is_empty());
        let ca = self.tls_client_ca_path.as_deref().filter(|s| !s.is_empty());
        match (cert, key, ca) {
            (Some(c), Some(k), Some(a)) => Ok((c, k, a)),
            _ => Err(DomainError::AuthRejected(
                "mTLS requires VAULT_TLS_CERT_PATH, VAULT_TLS_KEY_PATH, and VAULT_TLS_CLIENT_CA_PATH"
                    .into(),
            )),
        }
    }

    /// Outbound peer client identity (`VAULT_TLS_CLIENT_CERT_PATH` / `VAULT_TLS_CLIENT_KEY_PATH`).
    pub fn require_mtls_client_identity(&self) -> Result<(&str, &str, &str), DomainError> {
        let cert = self
            .tls_client_cert_path
            .as_deref()
            .filter(|s| !s.is_empty());
        let key = self.tls_client_key_path.as_deref().filter(|s| !s.is_empty());
        let ca = self.tls_client_ca_path.as_deref().filter(|s| !s.is_empty());
        match (cert, key, ca) {
            (Some(c), Some(k), Some(a)) => Ok((c, k, a)),
            _ => Err(DomainError::AuthRejected(
                "mTLS peer auth requires VAULT_TLS_CLIENT_CERT_PATH, VAULT_TLS_CLIENT_KEY_PATH, and VAULT_TLS_CLIENT_CA_PATH"
                    .into(),
            )),
        }
    }

    pub fn effective_lab_timelock_scale(&self) -> u64 {
        if self.hardened {
            1
        } else {
            self.lab_timelock_scale
        }
    }

    pub fn lab_endpoints_enabled(&self) -> bool {
        !self.hardened
    }

    pub fn effective_vault_token(&self) -> Option<&str> {
        self.vault_token.as_deref().or(if self.hardened {
            None
        } else {
            // Matches vault-mesh-lab.compose.yaml + kfe-service-vaultmesh-testnet3.properties.
            Some("kerosene-vault-lab-only")
        })
    }

    pub fn effective_data_dir(&self) -> std::path::PathBuf {
        if let Some(dir) = self.data_dir.as_deref() {
            std::path::PathBuf::from(dir)
        } else {
            std::path::PathBuf::from(&self.lab_root).join("vault-data")
        }
    }

    pub fn effective_anti_nonce_shared_dir(&self) -> Option<std::path::PathBuf> {
        self.anti_nonce_shared_dir
            .as_deref()
            .map(std::path::PathBuf::from)
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

fn env_nonempty_first(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(v) = std::env::var(name) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> VaultConfig {
        VaultConfig {
            node_id: NodeId::new("v1").unwrap(),
            attestation_mode: AttestationMode::Sim,
            listen_addr: "127.0.0.1:0".into(),
            lab_root: "x".into(),
            seed_peers: vec![],
            refuse_sim: false,
            genesis_n: None,
            online_count: None,
            lab_timelock_scale: 0,
            lab_timelock_env_set: false,
            lab_council_n: 3,
            lab_min_rebuilds: 3,
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
            data_dir: None,
            anti_nonce_shared_dir: None,
            measurement_pin_hex: None,
            dealer_requested: true,
            dkg_mode: DkgMode::DealerLab,
            reshare_policy: ResharePolicy::Manual,
        }
    }

    fn with_mtls_paths(mut cfg: VaultConfig) -> VaultConfig {
        cfg.tls_cert_path = Some("/lab/certs/vault-server.crt".into());
        cfg.tls_key_path = Some("/lab/certs/vault-server.key".into());
        cfg.tls_client_ca_path = Some("/lab/certs/ca.crt".into());
        cfg.tls_client_cert_path = Some("/lab/certs/vault-client.crt".into());
        cfg.tls_client_key_path = Some("/lab/certs/vault-client.key".into());
        cfg
    }

    #[test]
    fn hardened_rejects_sim() {
        let mut cfg = base();
        cfg.hardened = true;
        cfg.refuse_sim = true;
        cfg.attestation_mode = AttestationMode::Sim;
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::SimAttestationForbidden)
                | Err(DomainError::LabFlagForbidden(_))
        ));
    }

    #[test]
    fn hardened_rejects_lab_timelock_env() {
        let mut cfg = base();
        cfg.hardened = true;
        cfg.refuse_sim = true;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.lab_timelock_env_set = true;
        cfg.ceremony_mode = CeremonyMode::Lab;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::Distributed;
        assert_eq!(
            cfg.validate_hygiene(),
            Err(DomainError::LabFlagForbidden("LAB_TIMELOCK_SCALE".into()))
        );
    }

    #[test]
    fn lab_allows_sim_and_zero_timelock() {
        let cfg = base();
        assert!(cfg.validate_hygiene().is_ok());
        assert_eq!(cfg.effective_lab_timelock_scale(), 0);
        assert!(cfg.lab_endpoints_enabled());
    }

    #[test]
    fn production_ceremony_rejects_staging_stub() {
        let mut cfg = base();
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.attestation_staging_stub = true;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::Distributed;
        assert_eq!(
            cfg.validate_hygiene(),
            Err(DomainError::LabFlagForbidden(
                "ATTESTATION_STAGING_STUB in production ceremony".into()
            ))
        );
    }

    #[test]
    fn staging_allows_sev_with_stub() {
        let mut cfg = base();
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.ceremony_mode = CeremonyMode::Staging;
        cfg.attestation_staging_stub = true;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::Distributed;
        assert!(cfg.validate_hygiene().is_ok());
    }

    #[test]
    fn production_refuses_static_token_and_disk_share() {
        let mut cfg = base();
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::StaticToken;
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::Distributed;
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::AuthRejected(_))
        ));
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::TeeRequired(_))
        ));
    }

    #[test]
    fn mtls_requires_tls_paths() {
        let mut cfg = base();
        cfg.auth_mode = AuthMode::MutualTls;
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::AuthRejected(_))
        ));
        cfg = with_mtls_paths(cfg);
        assert!(cfg.validate_hygiene().is_ok());
    }

    #[test]
    fn staging_and_production_still_refuse_static_token() {
        for mode in [CeremonyMode::Staging, CeremonyMode::Production] {
            let mut cfg = base();
            cfg.attestation_mode = AttestationMode::Sev;
            cfg.ceremony_mode = mode;
            cfg.refuse_sim = true;
            cfg.hardened = true;
            cfg.auth_mode = AuthMode::StaticToken;
            cfg.share_store_mode = ShareStoreMode::TeeSeal;
            cfg.dealer_requested = false;
            cfg.dkg_mode = DkgMode::Distributed;
            assert!(
                matches!(cfg.validate_hygiene(), Err(DomainError::AuthRejected(_))),
                "static_token must be refused in {:?}",
                mode
            );
        }
    }
}
