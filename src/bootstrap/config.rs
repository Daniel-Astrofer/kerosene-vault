use crate::domain::{AttestationMode, DomainError, NodeId};

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub node_id: NodeId,
    pub attestation_mode: AttestationMode,
    pub listen_addr: String,
    pub lab_root: String,
    pub seed_peers: Vec<(String, String)>,
    pub refuse_sim: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct AttestationPolicy {
    pub refuse_sim: bool,
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
        let refuse_sim = env_flag("KEROSENE_VAULT_REFUSE_SIM")
            || cfg!(feature = "production")
            || std::env::var("KEROSENE_ENV").as_deref() == Ok("production");

        let mut seed_peers = Vec::new();
        if let Ok(raw) = std::env::var("VAULT_SEED_PEERS") {
            // format: id=host:port,id2=host2:port
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

        Ok(Self {
            node_id,
            attestation_mode,
            listen_addr,
            lab_root,
            seed_peers,
            refuse_sim,
        })
    }

    pub fn validate_attestation_policy(&self) -> Result<(), DomainError> {
        if self.refuse_sim && self.attestation_mode.is_lab_only() {
            return Err(DomainError::SimAttestationForbidden);
        }
        Ok(())
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES")
    )
}
