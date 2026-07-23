use std::collections::BTreeMap;

use crate::adapters::{peer_addr_is_onion, PeerHttpSettings, TlsPeerVerifyPolicy, VaultTransport};
use crate::domain::{
    resolve_node_tier, seat_genesis_by_tier, AttestationMode, BitcoinNetwork, DomainError,
    GovernanceRewardConfig, NodeId, ResharePolicy, SeatingCandidate, VaultNodeTier,
};
use std::time::Duration;

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
    /// Honest hardware tier (`domestic` | `sev` | `sgx`).
    pub node_tier: VaultNodeTier,
    /// True when a TEE guest/enclave device node is present (not the same as TPM).
    pub tee_available: bool,
    pub attestation_mode: AttestationMode,
    pub listen_addr: String,
    pub lab_root: String,
    pub seed_peers: Vec<(String, String)>,
    /// Optional per-peer tier overlay (`VAULT_PEER_TIERS=id=sev,...`); default domestic.
    pub peer_tiers: BTreeMap<String, VaultNodeTier>,
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
    /// Explicit USERS withdraw destinations (`VAULT_USERS_DESTINATION_ALLOWLIST`, comma-separated).
    /// Soft "any parseable address" is refused — destinations must be listed here and/or lab defaults.
    pub users_destination_allowlist: Vec<String>,
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
    /// Outbound peer server-cert verify (`VAULT_TLS_VERIFY_MODE`): hostname | spiffe | onion_or_spiffe.
    pub tls_verify_policy: TlsPeerVerifyPolicy,
    pub share_store_mode: ShareStoreMode,
    pub share_passphrase: Option<String>,
    /// Wrap AEAD passphrase with TPM seal (`VAULT_SHARE_TPM_SEAL=1`). Off by default.
    pub share_tpm_seal: bool,
    /// Lab mock TPM seal (`VAULT_SHARE_TPM_STUB=1`); refused when hardened/production.
    pub share_tpm_stub: bool,
    /// Lab-only clear passphrase if TPM unavailable (`VAULT_SHARE_TPM_CLEAR_FALLBACK=1`).
    pub share_tpm_clear_fallback: bool,
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
    /// Fixed sats bounty per governance job (`VAULT_GOVERNANCE_REWARD_SATS`).
    pub governance_reward_sats: u64,
    /// Optional bps of current miner pool added to job bounty (`VAULT_GOVERNANCE_REWARD_BPS`).
    pub governance_reward_bps: u32,
    /// Mesh transport: `clearnet` (lab LAN) or `tor` (SOCKS → onion peers).
    pub transport: VaultTransport,
    /// Outbound HTTP settings for peer DKG / anti-nonce (SOCKS, timeouts, retries).
    pub peer_http: PeerHttpSettings,
    /// Explicit clearnet publish flag — refused for production ceremony over Tor.
    pub clearnet_publish: bool,
}

impl VaultConfig {
    pub fn from_env() -> Result<Self, DomainError> {
        let node_id = NodeId::new(
            std::env::var("VAULT_NODE_ID").unwrap_or_else(|_| "vault-local-1".into()),
        )?;

        let tier_raw = std::env::var("VAULT_NODE_TIER").ok();
        let (node_tier, tee_available) = resolve_node_tier(tier_raw.as_deref())?;

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

        let mode_default = match node_tier {
            VaultNodeTier::Domestic if matches!(ceremony_mode, CeremonyMode::Lab) && !hardened => {
                "sim"
            }
            VaultNodeTier::Domestic => "software",
            VaultNodeTier::Sev => "sev",
            VaultNodeTier::Sgx => "sgx",
        };
        let mode_raw =
            std::env::var("ATTESTATION_MODE").unwrap_or_else(|_| mode_default.to_string());
        let attestation_mode = AttestationMode::parse(&mode_raw).ok_or_else(|| {
            DomainError::AttestationRejected(format!("unknown ATTESTATION_MODE={mode_raw}"))
        })?;

        let listen_addr =
            std::env::var("VAULT_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:7701".into());
        let lab_root =
            std::env::var("LAB_ATTESTATION_ROOT").unwrap_or_else(|_| "kerosene-lab-root".into());

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

        let mut peer_tiers = BTreeMap::new();
        if let Ok(raw) = std::env::var("VAULT_PEER_TIERS") {
            for part in raw.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (id, tier_s) = part.split_once('=').ok_or_else(|| {
                    DomainError::AttestationRejected(format!("bad VAULT_PEER_TIERS entry: {part}"))
                })?;
                let tier = VaultNodeTier::parse(tier_s).ok_or_else(|| {
                    DomainError::AttestationRejected(format!(
                        "unknown tier in VAULT_PEER_TIERS: {tier_s}"
                    ))
                })?;
                peer_tiers.insert(id.trim().to_string(), tier);
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

        let users_destination_allowlist = std::env::var("VAULT_USERS_DESTINATION_ALLOWLIST")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

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
            match node_tier {
                VaultNodeTier::Domestic => "aead_disk".into(),
                VaultNodeTier::Sev | VaultNodeTier::Sgx if hardened => "tee_seal".into(),
                VaultNodeTier::Sev | VaultNodeTier::Sgx => "aead_disk".into(),
            }
        });
        let share_store_mode = ShareStoreMode::parse(&store_raw).ok_or_else(|| {
            DomainError::ShareStoreForbidden(format!("unknown VAULT_SHARE_STORE={store_raw}"))
        })?;
        // Lab P0: VAULT_DATA_PASSPHRASE (preferred); VAULT_SHARE_PASSPHRASE legacy alias.
        let share_passphrase =
            env_nonempty_first(&["VAULT_DATA_PASSPHRASE", "VAULT_SHARE_PASSPHRASE"]);
        let share_tpm_seal = env_flag("VAULT_SHARE_TPM_SEAL");
        let share_tpm_stub = env_flag("VAULT_SHARE_TPM_STUB");
        let share_tpm_clear_fallback = env_flag("VAULT_SHARE_TPM_CLEAR_FALLBACK");
        let data_dir = env_nonempty_first(&["VAULT_DATA_DIR"]);
        let anti_nonce_shared_dir = env_nonempty_first(&["VAULT_ANTI_NONCE_SHARED_DIR"]);
        let measurement_pin_hex = env_nonempty_first(&["VAULT_MEASUREMENT_PIN"]);

        // Lab P0 / Gate: VAULT_DKG_MODE (preferred); VAULT_DKG legacy alias.
        // Production/staging default = over-wire FROST (same path as lab distributed_wire).
        // In-process `distributed` is lab/single-node only. Dealer never default in hardened.
        let dkg_raw = std::env::var("VAULT_DKG_MODE")
            .or_else(|_| std::env::var("VAULT_DKG"))
            .ok();
        let dkg_mode = match dkg_raw.as_deref() {
            Some(raw) => DkgMode::parse(raw).ok_or_else(|| {
                DomainError::AttestationRejected(format!("unknown VAULT_DKG_MODE={raw}"))
            })?,
            None if hardened => DkgMode::DistributedWire,
            None if cfg!(feature = "dealer_lab") => DkgMode::DealerLab,
            None => DkgMode::Distributed,
        };
        let dealer_requested = matches!(dkg_mode, DkgMode::DealerLab);
        let reshare_policy = ResharePolicy::from_env_or_default()?;
        let governance_reward_sats = std::env::var("VAULT_GOVERNANCE_REWARD_SATS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let governance_reward_bps = std::env::var("VAULT_GOVERNANCE_REWARD_BPS")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let transport_raw = std::env::var("VAULT_TRANSPORT").unwrap_or_else(|_| {
            // Production ceremony defaults to Tor; lab/staging stay clearnet unless set.
            if matches!(ceremony_mode, CeremonyMode::Production) {
                "tor".into()
            } else {
                "clearnet".into()
            }
        });
        let transport = VaultTransport::parse(&transport_raw).ok_or_else(|| {
            DomainError::AttestationRejected(format!("unknown VAULT_TRANSPORT={transport_raw}"))
        })?;

        let mut peer_http = if transport.is_tor() {
            PeerHttpSettings::tor_defaults()
        } else {
            PeerHttpSettings::clearnet_defaults()
        };
        peer_http.transport = transport;
        if let Some(socks) = env_nonempty_first(&["VAULT_SOCKS_PROXY", "VAULT_TOR_SOCKS"]) {
            peer_http.socks_proxy = Some(PeerHttpSettings::normalize_socks_proxy(&socks));
        } else if !transport.is_tor() {
            peer_http.socks_proxy = None;
        }
        if let Ok(s) = std::env::var("VAULT_HTTP_TIMEOUT_SECS") {
            if let Ok(secs) = s.parse::<u64>() {
                peer_http.timeout = Duration::from_secs(secs.max(1));
            }
        }
        if let Ok(s) = std::env::var("VAULT_HTTP_CONNECT_TIMEOUT_SECS") {
            if let Ok(secs) = s.parse::<u64>() {
                peer_http.connect_timeout = Duration::from_secs(secs.max(1));
            }
        }
        if let Ok(s) = std::env::var("VAULT_HTTP_MAX_RETRIES") {
            if let Ok(n) = s.parse::<u32>() {
                peer_http.max_retries = n.max(1);
            }
        }
        if let Ok(s) = std::env::var("VAULT_HTTP_RETRY_BASE_MS") {
            if let Ok(ms) = s.parse::<u64>() {
                peer_http.retry_base_ms = ms;
            }
        }
        if let Ok(s) = std::env::var("VAULT_HTTP_RETRY_JITTER_MS") {
            if let Ok(ms) = s.parse::<u64>() {
                peer_http.retry_jitter_ms = ms;
            }
        }
        let clearnet_publish = env_flag("VAULT_CLEARNET_PUBLISH");
        let tls_verify_policy = resolve_tls_verify_policy(transport)?;

        let cfg = Self {
            node_id,
            node_tier,
            tee_available,
            attestation_mode,
            listen_addr,
            lab_root,
            seed_peers,
            peer_tiers,
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
            users_destination_allowlist,
            tls_cert_path,
            tls_key_path,
            tls_client_ca_path,
            tls_client_cert_path,
            tls_client_key_path,
            tls_verify_policy,
            share_store_mode,
            share_passphrase,
            share_tpm_seal,
            share_tpm_stub,
            share_tpm_clear_fallback,
            data_dir,
            anti_nonce_shared_dir,
            measurement_pin_hex,
            dealer_requested,
            dkg_mode,
            reshare_policy,
            governance_reward_sats,
            governance_reward_bps,
            transport,
            peer_http,
            clearnet_publish,
        };
        cfg.validate_hygiene()?;
        Ok(cfg)
    }

    pub fn governance_reward_config(&self) -> GovernanceRewardConfig {
        GovernanceRewardConfig {
            reward_sats: self.governance_reward_sats,
            reward_bps_of_pool: self.governance_reward_bps,
        }
    }

    pub fn validate_attestation_policy(&self) -> Result<(), DomainError> {
        if self.refuse_sim && self.attestation_mode.is_lab_only() {
            return Err(DomainError::SimAttestationForbidden);
        }
        Ok(())
    }

    /// Prod/staging refuse: sim, lab timelock env, dealer, static token, fake TEE claims.
    /// Domestic AEAD + software attestation is allowed; staging stub and sev-without-HW are not.
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

        // Honest tier / mode: refuse advertising SEV/SGX without HW (stub is staging-only).
        self.validate_tee_claims()?;

        if matches!(
            self.ceremony_mode,
            CeremonyMode::Staging | CeremonyMode::Production
        ) {
            if self.dealer_requested {
                return Err(DomainError::DealerForbidden(
                    "dealer DKG refused in staging/production (ToB 2024)".into(),
                ));
            }
            if !matches!(self.dkg_mode, DkgMode::DistributedWire) {
                return Err(DomainError::DealerForbidden(
                    "staging/production ceremony requires VAULT_DKG_MODE=distributed_wire (real FROST over-wire; not dealer or in-process sim)".into(),
                ));
            }
            if self.auth_mode == AuthMode::StaticToken {
                return Err(DomainError::AuthRejected(
                    "static token refused in staging/production; use mTLS".into(),
                ));
            }
            if self.share_store_mode == ShareStoreMode::AeadDisk && self.node_tier.is_tee() {
                return Err(DomainError::TeeRequired(
                    "TEE-tier node requires VAULT_SHARE_STORE=tee_seal (not host AEAD)".into(),
                ));
            }
        }
        if self.auth_mode == AuthMode::MutualTls {
            self.require_mtls_paths()?;
            self.require_mtls_client_identity()?;
        }
        self.validate_tpm_seal_hygiene()?;
        self.validate_transport_hygiene()?;
        Ok(())
    }

    /// TPM seal optional for domestic AEAD. Stub/clear-fallback lab-only. TPM ≠ SEV.
    pub fn validate_tpm_seal_hygiene(&self) -> Result<(), DomainError> {
        if self.share_tpm_clear_fallback {
            if self.hardened
                || matches!(self.ceremony_mode, CeremonyMode::Production)
                || cfg!(feature = "production")
            {
                return Err(DomainError::LabFlagForbidden(
                    "VAULT_SHARE_TPM_CLEAR_FALLBACK".into(),
                ));
            }
            if !self.share_tpm_seal {
                return Err(DomainError::ShareStoreForbidden(
                    "VAULT_SHARE_TPM_CLEAR_FALLBACK requires VAULT_SHARE_TPM_SEAL=1".into(),
                ));
            }
        }
        if self.share_tpm_stub {
            if matches!(self.ceremony_mode, CeremonyMode::Production) || cfg!(feature = "production")
            {
                return Err(DomainError::LabFlagForbidden(
                    "VAULT_SHARE_TPM_STUB in production ceremony".into(),
                ));
            }
            if self.hardened {
                return Err(DomainError::LabFlagForbidden("VAULT_SHARE_TPM_STUB".into()));
            }
            if !self.share_tpm_seal {
                return Err(DomainError::ShareStoreForbidden(
                    "VAULT_SHARE_TPM_STUB requires VAULT_SHARE_TPM_SEAL=1".into(),
                ));
            }
        }
        if self.share_tpm_seal && self.share_store_mode != ShareStoreMode::AeadDisk {
            return Err(DomainError::ShareStoreForbidden(
                "VAULT_SHARE_TPM_SEAL applies only to VAULT_SHARE_STORE=aead_disk (TEE uses tee_seal; TPM ≠ SEV)"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Production ceremony requires private Tor mesh (onion peers + SOCKS); refuse clearnet publish.
    /// Staging/production Tor also requires mTLS (lab Tor smoke may keep static_token).
    pub fn validate_transport_hygiene(&self) -> Result<(), DomainError> {
        if self.transport.is_tor() {
            let socks = self.peer_http.socks_proxy.as_deref().unwrap_or("");
            if socks.is_empty() {
                return Err(DomainError::LabFlagForbidden(
                    "VAULT_TRANSPORT=tor requires VAULT_SOCKS_PROXY (e.g. socks5h://127.0.0.1:9050)"
                        .into(),
                ));
            }
            for (id, addr) in &self.seed_peers {
                if !peer_addr_is_onion(addr) {
                    return Err(DomainError::AttestationRejected(format!(
                        "VAULT_TRANSPORT=tor requires onion VAULT_SEED_PEERS (peer {id}={addr})"
                    )));
                }
            }
            if matches!(
                self.ceremony_mode,
                CeremonyMode::Staging | CeremonyMode::Production
            ) && self.auth_mode != AuthMode::MutualTls
            {
                return Err(DomainError::AuthRejected(
                    "VAULT_TRANSPORT=tor under staging/production requires VAULT_AUTH_MODE=mtls (static_token refused)"
                        .into(),
                ));
            }
            if self.auth_mode == AuthMode::MutualTls
                && matches!(self.tls_verify_policy, TlsPeerVerifyPolicy::Hostname)
            {
                return Err(DomainError::AuthRejected(
                    "VAULT_TRANSPORT=tor with mTLS requires VAULT_TLS_VERIFY_MODE=onion_or_spiffe|spiffe (not hostname-only)"
                        .into(),
                ));
            }
        }

        if self.ceremony_mode == CeremonyMode::Production {
            if !self.transport.is_tor() {
                return Err(DomainError::LabFlagForbidden(
                    "production ceremony requires VAULT_TRANSPORT=tor (private Tor mesh; not clearnet LAN)"
                        .into(),
                ));
            }
            if self.auth_mode != AuthMode::MutualTls {
                return Err(DomainError::AuthRejected(
                    "production ceremony requires VAULT_AUTH_MODE=mtls".into(),
                ));
            }
            if self.clearnet_publish {
                return Err(DomainError::LabFlagForbidden(
                    "VAULT_CLEARNET_PUBLISH refused in production ceremony (do not expose vault ports on clearnet)"
                        .into(),
                ));
            }
            if self.seed_peers.is_empty() {
                return Err(DomainError::AttestationRejected(
                    "production ceremony requires VAULT_SEED_PEERS (onion addresses)".into(),
                ));
            }
        }
        Ok(())
    }

    /// Refuse fake SEV/SGX claims: no device and no staging stub (stub never in production).
    pub fn validate_tee_claims(&self) -> Result<(), DomainError> {
        if self.node_tier.is_domestic() && self.attestation_mode.is_tee() {
            return Err(DomainError::AttestationRejected(
                "domestic tier cannot advertise ATTESTATION_MODE=sev|sgx (use software)".into(),
            ));
        }
        let claims_tee = self.node_tier.is_tee() || self.attestation_mode.is_tee();
        if !claims_tee {
            return Ok(());
        }
        if self.attestation_staging_stub {
            if matches!(self.ceremony_mode, CeremonyMode::Production) || cfg!(feature = "production")
            {
                return Err(DomainError::LabFlagForbidden(
                    "ATTESTATION_STAGING_STUB cannot back a TEE claim in production".into(),
                ));
            }
            return Ok(());
        }
        if !self.tee_available {
            return Err(DomainError::AttestationRejected(
                "TEE claim (VAULT_NODE_TIER or ATTESTATION_MODE=sev|sgx) without HW device; use domestic/software or set ATTESTATION_STAGING_STUB=1 for staging only".into(),
            ));
        }
        if cfg!(feature = "production") && !cfg!(feature = "tee_hw") {
            return Err(DomainError::AttestationRejected(
                "production TEE claim requires --features tee_hw (or run domestic/software ceremony)".into(),
            ));
        }
        Ok(())
    }

    pub fn peer_tier(&self, peer_id: &str) -> VaultNodeTier {
        self.peer_tiers
            .get(peer_id)
            .copied()
            .unwrap_or(VaultNodeTier::Domestic)
    }

    /// Candidates for genesis seating: local + seed peers (pads added by caller if needed).
    pub fn seating_candidates(&self) -> Result<Vec<SeatingCandidate>, DomainError> {
        let mut candidates = vec![SeatingCandidate {
            id: self.node_id.clone(),
            tier: self.node_tier,
        }];
        for (id, _) in &self.seed_peers {
            candidates.push(SeatingCandidate {
                id: NodeId::new(id.clone())?,
                tier: self.peer_tier(id),
            });
        }
        Ok(candidates)
    }

    /// Target genesis size (`VAULT_GENESIS_N` or local+seeds, min 2).
    pub fn effective_genesis_n(&self) -> usize {
        self.genesis_n
            .unwrap_or_else(|| self.seed_peers.len().saturating_add(1).max(2))
    }

    /// SEV-priority seating for genesis / wire DKG roster (§3.1).
    pub fn seat_genesis(&self) -> Result<Vec<NodeId>, DomainError> {
        let mut candidates = self.seating_candidates()?;
        let n = self.effective_genesis_n();
        while candidates.len() < n {
            candidates.push(SeatingCandidate {
                id: NodeId::new(format!("vault-pad-{}", candidates.len()))?,
                tier: VaultNodeTier::Domestic,
            });
        }
        Ok(seat_genesis_by_tier(&candidates, n))
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

fn resolve_tls_verify_policy(transport: VaultTransport) -> Result<TlsPeerVerifyPolicy, DomainError> {
    let expected = env_nonempty_first(&["VAULT_TLS_PEER_SPIFFE_ID", "VAULT_MTLS_SPIFFE_VAULT"])
        .unwrap_or_else(|| "spiffe://kerosene.lab/vault/server".into());
    let default_mode = if transport.is_tor() {
        "onion_or_spiffe"
    } else {
        "hostname"
    };
    let raw = std::env::var("VAULT_TLS_VERIFY_MODE").unwrap_or_else(|_| default_mode.into());
    TlsPeerVerifyPolicy::parse(&raw, &expected).ok_or_else(|| {
        DomainError::AuthRejected(format!("unknown VAULT_TLS_VERIFY_MODE={raw}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> VaultConfig {
        VaultConfig {
            node_id: NodeId::new("v1").unwrap(),
            node_tier: VaultNodeTier::Domestic,
            tee_available: false,
            attestation_mode: AttestationMode::Sim,
            listen_addr: "127.0.0.1:0".into(),
            lab_root: "x".into(),
            seed_peers: vec![],
            peer_tiers: BTreeMap::new(),
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
            users_destination_allowlist: vec![],
            tls_cert_path: None,
            tls_key_path: None,
            tls_client_ca_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            tls_verify_policy: TlsPeerVerifyPolicy::Hostname,
            share_store_mode: ShareStoreMode::AeadDisk,
            share_passphrase: Some("pass".into()),
            share_tpm_seal: false,
            share_tpm_stub: false,
            share_tpm_clear_fallback: false,
            data_dir: None,
            anti_nonce_shared_dir: None,
            measurement_pin_hex: None,
            dealer_requested: true,
            dkg_mode: DkgMode::DealerLab,
            reshare_policy: ResharePolicy::Manual,
            governance_reward_sats: 0,
            governance_reward_bps: 0,
            transport: VaultTransport::Clearnet,
            peer_http: PeerHttpSettings::clearnet_defaults(),
            clearnet_publish: false,
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

    fn with_tor_mesh(mut cfg: VaultConfig) -> VaultConfig {
        cfg.transport = VaultTransport::Tor;
        cfg.peer_http = PeerHttpSettings::tor_defaults();
        cfg.clearnet_publish = false;
        cfg.tls_verify_policy = TlsPeerVerifyPolicy::OnionOrSpiffe {
            expected: "spiffe://kerosene.lab/vault/server".into(),
        };
        cfg.seed_peers = vec![
            (
                "vault-2".into(),
                "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:7701".into(),
            ),
            (
                "vault-3".into(),
                "http://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion:7701".into(),
            ),
        ];
        cfg.genesis_n = Some(3);
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
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = true;
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
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = true;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.attestation_staging_stub = true;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
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
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = false;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.ceremony_mode = CeremonyMode::Staging;
        cfg.attestation_staging_stub = true;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        assert!(cfg.validate_hygiene().is_ok());
    }

    #[test]
    fn production_refuses_static_token_and_tee_disk_share() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = true;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::StaticToken;
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
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
    fn production_allows_domestic_software_and_aead() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.tee_available = false;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg = with_tor_mesh(cfg);
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        assert!(cfg.validate_hygiene().is_ok());
    }

    #[test]
    fn production_refuses_clearnet_transport() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        cfg.transport = VaultTransport::Clearnet;
        cfg.peer_http = PeerHttpSettings::clearnet_defaults();
        cfg.seed_peers = vec![("vault-2".into(), "vault-2:7701".into())];
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::LabFlagForbidden(_))
        ));
    }

    #[test]
    fn production_refuses_clearnet_publish_flag() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg = with_tor_mesh(cfg);
        cfg.clearnet_publish = true;
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::LabFlagForbidden(_))
        ));
    }

    #[test]
    fn tor_transport_refuses_non_onion_peers() {
        let mut cfg = base();
        cfg.transport = VaultTransport::Tor;
        cfg.peer_http = PeerHttpSettings::tor_defaults();
        cfg.seed_peers = vec![("vault-2".into(), "vault-2:7701".into())];
        assert!(matches!(
            cfg.validate_transport_hygiene(),
            Err(DomainError::AttestationRejected(_))
        ));
    }

    #[test]
    fn production_refuses_in_process_distributed_dkg() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::AeadDisk;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::Distributed;
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::DealerForbidden(_))
        ));
    }

    #[test]
    fn seat_genesis_prefers_sev_peers() {
        let mut cfg = base();
        cfg.node_id = NodeId::new("vault-home").unwrap();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.seed_peers = vec![
            ("vault-epyc".into(), "epyc:7701".into()),
            ("vault-home-2".into(), "h2:7701".into()),
        ];
        cfg.peer_tiers
            .insert("vault-epyc".into(), VaultNodeTier::Sev);
        cfg.genesis_n = Some(2);
        let seats = cfg.seat_genesis().unwrap();
        assert_eq!(seats.len(), 2);
        assert_eq!(seats[0].as_str(), "vault-epyc");
        assert_eq!(seats[1].as_str(), "vault-home");
    }

    #[test]
    fn production_rejects_sev_claim_without_hw() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = false;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.attestation_staging_stub = false;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::AttestationRejected(_))
        ));
    }

    #[test]
    fn production_rejects_stub_as_sev() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Sev;
        cfg.tee_available = false;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.attestation_staging_stub = true;
        cfg.ceremony_mode = CeremonyMode::Production;
        cfg.refuse_sim = true;
        cfg.hardened = true;
        cfg.auth_mode = AuthMode::MutualTls;
        cfg = with_mtls_paths(cfg);
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.dealer_requested = false;
        cfg.dkg_mode = DkgMode::DistributedWire;
        assert!(matches!(
            cfg.validate_hygiene(),
            Err(DomainError::LabFlagForbidden(_))
        ));
    }

    #[test]
    fn domestic_cannot_advertise_sev_mode() {
        let mut cfg = base();
        cfg.node_tier = VaultNodeTier::Domestic;
        cfg.attestation_mode = AttestationMode::Sev;
        cfg.tee_available = true;
        assert!(matches!(
            cfg.validate_tee_claims(),
            Err(DomainError::AttestationRejected(_))
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
            cfg.node_tier = VaultNodeTier::Domestic;
            cfg.attestation_mode = AttestationMode::Software;
            cfg.ceremony_mode = mode;
            cfg.refuse_sim = true;
            cfg.hardened = true;
            cfg.auth_mode = AuthMode::StaticToken;
            cfg.share_store_mode = ShareStoreMode::AeadDisk;
            cfg.dealer_requested = false;
            cfg.dkg_mode = DkgMode::DistributedWire;
            assert!(
                matches!(cfg.validate_hygiene(), Err(DomainError::AuthRejected(_))),
                "static_token must be refused in {:?}",
                mode
            );
        }
    }

    #[test]
    fn lab_allows_tpm_seal_stub() {
        let mut cfg = base();
        cfg.share_tpm_seal = true;
        cfg.share_tpm_stub = true;
        assert!(cfg.validate_tpm_seal_hygiene().is_ok());
        assert!(cfg.validate_hygiene().is_ok());
    }

    #[test]
    fn hardened_rejects_tpm_clear_fallback() {
        let mut cfg = base();
        cfg.hardened = true;
        cfg.refuse_sim = true;
        cfg.attestation_mode = AttestationMode::Software;
        cfg.share_tpm_seal = true;
        cfg.share_tpm_clear_fallback = true;
        assert!(matches!(
            cfg.validate_tpm_seal_hygiene(),
            Err(DomainError::LabFlagForbidden(_))
        ));
    }

    #[test]
    fn tpm_seal_refused_for_tee_store() {
        let mut cfg = base();
        cfg.share_store_mode = ShareStoreMode::TeeSeal;
        cfg.share_tpm_seal = true;
        assert!(matches!(
            cfg.validate_tpm_seal_hygiene(),
            Err(DomainError::ShareStoreForbidden(_))
        ));
    }
}
