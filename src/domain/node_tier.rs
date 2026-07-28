//! Vault node tiers: domestic (home PC / TPM) vs SEV/SGX (preferred TEE).
//!
//! Honest labeling: TPM ≠ SEV. Domestic is first-class; TEE gets seating priority.

use crate::domain::{DomainError, NodeId};

/// Hardware / trust tier of a vault node.
///
/// - [`Domestic`](Self::Domestic): home/miner PC; software measurement (+ optional TPM seal).
/// - [`Sev`](Self::Sev) / [`Sgx`](Self::Sgx): real confidential-compute upgrade when HW is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VaultNodeTier {
    Domestic,
    Sgx,
    Sev,
}

impl VaultNodeTier {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "domestic" | "home" | "tpm" => Some(Self::Domestic),
            "sgx" => Some(Self::Sgx),
            "sev" | "sev-snp" | "sev_snp" => Some(Self::Sev),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domestic => "domestic",
            Self::Sgx => "sgx",
            Self::Sev => "sev",
        }
    }

    /// Seating / admission rank: higher fills genesis seats first (`sev` > `sgx` > `domestic`).
    pub fn seating_priority(self) -> u8 {
        match self {
            Self::Sev => 3,
            Self::Sgx => 2,
            Self::Domestic => 1,
        }
    }

    /// Soft governance weight (basis points of a 1.0x domestic baseline).
    /// Hard policy for genesis is seating priority; weight is for docs / future accrual.
    pub fn governance_weight_bps(self) -> u32 {
        match self {
            Self::Sev => 15_000,
            Self::Sgx => 12_500,
            Self::Domestic => 10_000,
        }
    }

    pub fn is_tee(self) -> bool {
        matches!(self, Self::Sev | Self::Sgx)
    }

    pub fn is_domestic(self) -> bool {
        matches!(self, Self::Domestic)
    }
}

/// Candidate for genesis / signing seating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatingCandidate {
    pub id: NodeId,
    pub tier: VaultNodeTier,
}

/// Fill up to `n` seats preferring highest tier, then stable `node_id` order.
///
/// Algorithm:
/// 1. Deduplicate by `node_id` (first occurrence wins).
/// 2. Sort by `tier.seating_priority()` descending, then `node_id` ascending.
/// 3. Take the first `n` ids.
///
/// A mixed roster (domestic + SEV) therefore seats SEV/SGX first; an all-domestic
/// set of size `n` seats normally. Pads are **not** invented here — callers add
/// lab pads before calling if desired.
pub fn seat_genesis_by_tier(candidates: &[SeatingCandidate], n: usize) -> Vec<NodeId> {
    let mut seen = std::collections::BTreeSet::new();
    let mut unique: Vec<SeatingCandidate> = Vec::new();
    for c in candidates {
        if seen.insert(c.id.as_str().to_string()) {
            unique.push(c.clone());
        }
    }
    unique.sort_by(|a, b| {
        b.tier
            .seating_priority()
            .cmp(&a.tier.seating_priority())
            .then_with(|| a.id.as_str().cmp(b.id.as_str()))
    });
    unique.into_iter().map(|c| c.id).take(n).collect()
}

/// Probe common Linux TEE device nodes. Returns `(tee_available, preferred_tier)`.
pub fn detect_tee_devices() -> (bool, Option<VaultNodeTier>) {
    detect_tee_at_paths(&[
        std::path::Path::new("/dev/sev-guest"),
        std::path::Path::new("/dev/sev"),
        std::path::Path::new("/dev/sgx_enclave"),
        std::path::Path::new("/dev/sgx/enclave"),
        std::path::Path::new("/dev/isgx"),
    ])
}

/// Testable TEE probe: SEV paths win over SGX when both exist.
pub fn detect_tee_at_paths(paths: &[&std::path::Path]) -> (bool, Option<VaultNodeTier>) {
    let mut sev = false;
    let mut sgx = false;
    for p in paths {
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let parent = p
            .parent()
            .and_then(|s| s.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let exists = p.exists();
        if !exists {
            continue;
        }
        if name.contains("sev") {
            sev = true;
        } else if name.contains("sgx") || name == "isgx" || parent == "sgx" {
            sgx = true;
        }
    }
    if sev {
        (true, Some(VaultNodeTier::Sev))
    } else if sgx {
        (true, Some(VaultNodeTier::Sgx))
    } else {
        (false, None)
    }
}

/// Resolve `VAULT_NODE_TIER` (`auto` → detect TEE else domestic).
pub fn resolve_node_tier(raw: Option<&str>) -> Result<(VaultNodeTier, bool), DomainError> {
    let (tee_available, detected) = detect_tee_devices();
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("auto") => Ok((detected.unwrap_or(VaultNodeTier::Domestic), tee_available)),
        Some(other) => {
            let tier = VaultNodeTier::parse(other).ok_or_else(|| {
                DomainError::AttestationRejected(format!("unknown VAULT_NODE_TIER={other}"))
            })?;
            Ok((tier, tee_available))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_parse_and_priority() {
        assert_eq!(VaultNodeTier::parse("domestic"), Some(VaultNodeTier::Domestic));
        assert_eq!(VaultNodeTier::parse("SEV"), Some(VaultNodeTier::Sev));
        assert_eq!(VaultNodeTier::parse("sgx"), Some(VaultNodeTier::Sgx));
        assert!(VaultNodeTier::parse("epyc").is_none());
        assert!(VaultNodeTier::Sev.seating_priority() > VaultNodeTier::Sgx.seating_priority());
        assert!(VaultNodeTier::Sgx.seating_priority() > VaultNodeTier::Domestic.seating_priority());
    }

    #[test]
    fn seating_prefers_sev_then_sgx_then_domestic() {
        let cands = vec![
            SeatingCandidate {
                id: NodeId::new("vault-d2").unwrap(),
                tier: VaultNodeTier::Domestic,
            },
            SeatingCandidate {
                id: NodeId::new("vault-s1").unwrap(),
                tier: VaultNodeTier::Sgx,
            },
            SeatingCandidate {
                id: NodeId::new("vault-e1").unwrap(),
                tier: VaultNodeTier::Sev,
            },
            SeatingCandidate {
                id: NodeId::new("vault-d1").unwrap(),
                tier: VaultNodeTier::Domestic,
            },
        ];
        let seats = seat_genesis_by_tier(&cands, 3);
        assert_eq!(
            seats
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>(),
            vec!["vault-e1", "vault-s1", "vault-d1"]
        );
    }

    #[test]
    fn seating_all_domestic_ok() {
        let cands: Vec<_> = (1..=3)
            .map(|i| SeatingCandidate {
                id: NodeId::new(format!("vault-{i}")).unwrap(),
                tier: VaultNodeTier::Domestic,
            })
            .collect();
        let seats = seat_genesis_by_tier(&cands, 3);
        assert_eq!(seats.len(), 3);
        assert_eq!(seats[0].as_str(), "vault-1");
    }

    #[test]
    fn detect_fallback_when_no_devices() {
        let tmp = std::env::temp_dir().join(format!(
            "kerosene-tee-detect-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let missing = tmp.join("no-such-sev");
        let (avail, tier) = detect_tee_at_paths(&[&missing]);
        assert!(!avail);
        assert!(tier.is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn detect_sev_path_when_present() {
        let tmp = std::env::temp_dir().join(format!(
            "kerosene-tee-sev-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let sev = tmp.join("sev-guest");
        std::fs::write(&sev, b"").unwrap();
        let (avail, tier) = detect_tee_at_paths(&[&sev]);
        assert!(avail);
        assert_eq!(tier, Some(VaultNodeTier::Sev));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

/// Post-genesis admission seating for a new vault node.
///
/// Priority: SEV > SGX > domestic (same as `seating_priority`).
/// Timeout: if TEE node does not complete admission within `timeout_hours`,
/// a domestic node may be admitted as fallback.
///
/// Returns `(target_tier, timeout_secs)` for the admission window.
pub fn admission_seating(
    tier: VaultNodeTier,
    attested_at_secs: Option<u64>,
    now_secs: u64,
    timeout_hours: u64,
) -> Result<VaultNodeTier, DomainError> {
    match tier {
        VaultNodeTier::Domestic => Ok(VaultNodeTier::Domestic),
        VaultNodeTier::Sgx | VaultNodeTier::Sev => {
            if let Some(attested) = attested_at_secs {
                let elapsed = now_secs.saturating_sub(attested);
                let timeout = timeout_hours * 3600;
                if elapsed > timeout {
                    return Ok(VaultNodeTier::Domestic);
                }
            }
            Ok(tier)
        }
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn domestic_admitted_immediately() {
        assert_eq!(
            admission_seating(VaultNodeTier::Domestic, None, 1000, 24).unwrap(),
            VaultNodeTier::Domestic
        );
    }

    #[test]
    fn sev_admitted_within_timeout() {
        assert_eq!(
            admission_seating(VaultNodeTier::Sev, Some(100), 500, 24).unwrap(),
            VaultNodeTier::Sev
        );
    }

    #[test]
    fn sev_falls_back_to_domestic_after_timeout() {
        assert_eq!(
            admission_seating(VaultNodeTier::Sev, Some(100), 100 + 25 * 3600, 24).unwrap(),
            VaultNodeTier::Domestic
        );
    }

    #[test]
    fn sev_no_attestation_yet_admitted() {
        assert_eq!(
            admission_seating(VaultNodeTier::Sev, None, 1000, 24).unwrap(),
            VaultNodeTier::Sev
        );
    }
}
