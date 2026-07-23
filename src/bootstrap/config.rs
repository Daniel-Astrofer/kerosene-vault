use crate::domain::{AttestationMode, DomainError, NodeId};

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
        let is_production = cfg!(feature = "production")
            || kerosene_env.eq_ignore_ascii_case("production");
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

    /// §13.5 + F8: prod/staging must not boot with sim or LAB_TIMELOCK_SCALE;
    /// production ceremony forbids staging TEE stubs.
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
        if matches!(
            self.ceremony_mode,
            CeremonyMode::Staging | CeremonyMode::Production
        ) && self.attestation_mode.is_lab_only()
        {
            return Err(DomainError::LabFlagForbidden(
                "ATTESTATION_MODE=sim".into(),
            ));
        }
        Ok(())
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
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES")
    )
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
        }
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
        assert!(cfg.validate_hygiene().is_ok());
    }
}
