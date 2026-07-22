use std::collections::BTreeSet;
use std::sync::Arc;

use crate::application::ports::{BlobStorePort, ClockPort, LedgerPort, ReleaseStorePort};
use crate::domain::{
    lab_rebuild_binary_hash, AllowlistEntry, ContentHash, DomainError, NodeId, ReleaseCandidate,
    ReleasePhase,
};

pub struct ProposeRelease {
    releases: Arc<dyn ReleaseStorePort>,
    blobs: Arc<dyn BlobStorePort>,
    ledger: Arc<dyn LedgerPort>,
    clock: Arc<dyn ClockPort>,
}

impl ProposeRelease {
    pub fn new(
        releases: Arc<dyn ReleaseStorePort>,
        blobs: Arc<dyn BlobStorePort>,
        ledger: Arc<dyn LedgerPort>,
        clock: Arc<dyn ClockPort>,
    ) -> Self {
        Self {
            releases,
            blobs,
            ledger,
            clock,
        }
    }

    /// Lab: publish source bytes → Hs, derive Hb via lab rebuild, store both blobs + candidate.
    pub fn execute(
        &self,
        release_id: &str,
        source: &[u8],
        council_sigs: BTreeSet<String>,
    ) -> Result<ReleaseCandidate, DomainError> {
        let hs = ContentHash::from_bytes(source);
        let hb = lab_rebuild_binary_hash(source);
        self.blobs.put(&hs, source)?;
        let binary = format!("lab-bin|{}", hs.as_str());
        self.blobs.put(&hb, binary.as_bytes())?;

        let constitution = self.ledger.constitution()?;
        let policy = self.releases.policy()?;
        if council_sigs.len() < policy.council_quorum() {
            return Err(DomainError::QuorumNotMet {
                have: council_sigs.len(),
                need: policy.council_quorum(),
            });
        }
        let candidate = ReleaseCandidate::new(
            release_id.to_string(),
            hs,
            hb,
            constitution.hash,
            council_sigs,
            self.clock.unix_now_secs(),
        )?;
        self.releases.put_candidate(candidate.clone())?;
        Ok(candidate)
    }

    /// Propose with explicit Hs/Hb (tamper tests). Source blob for `hs` must already exist.
    pub fn execute_with_hashes(
        &self,
        release_id: &str,
        hs: ContentHash,
        hb: ContentHash,
        council_sigs: BTreeSet<String>,
    ) -> Result<ReleaseCandidate, DomainError> {
        let _ = self.blobs.get(&hs)?;
        let constitution = self.ledger.constitution()?;
        let policy = self.releases.policy()?;
        if council_sigs.len() < policy.council_quorum() {
            return Err(DomainError::QuorumNotMet {
                have: council_sigs.len(),
                need: policy.council_quorum(),
            });
        }
        let candidate = ReleaseCandidate::new(
            release_id.to_string(),
            hs,
            hb,
            constitution.hash,
            council_sigs,
            self.clock.unix_now_secs(),
        )?;
        self.releases.put_candidate(candidate.clone())?;
        Ok(candidate)
    }
}

pub struct RebuildRelease {
    releases: Arc<dyn ReleaseStorePort>,
    blobs: Arc<dyn BlobStorePort>,
}

impl RebuildRelease {
    pub fn new(releases: Arc<dyn ReleaseStorePort>, blobs: Arc<dyn BlobStorePort>) -> Self {
        Self { releases, blobs }
    }

    pub fn execute(
        &self,
        release_id: &str,
        vault_id: &NodeId,
    ) -> Result<ReleaseCandidate, DomainError> {
        let mut candidate = self.releases.get_candidate(release_id)?;
        let source = self.blobs.get(&candidate.hs)?;
        let recomputed_hs = ContentHash::from_bytes(&source);
        if recomputed_hs != candidate.hs {
            return Err(DomainError::MeasurementMismatch);
        }
        let rebuilt_hb = lab_rebuild_binary_hash(&source);
        candidate.record_rebuild(vault_id, rebuilt_hb)?;
        self.releases.save_candidate(candidate.clone())?;
        Ok(candidate)
    }
}

pub struct CosignRelease {
    releases: Arc<dyn ReleaseStorePort>,
    ledger: Arc<dyn LedgerPort>,
    clock: Arc<dyn ClockPort>,
    local_node: NodeId,
}

impl CosignRelease {
    pub fn new(
        releases: Arc<dyn ReleaseStorePort>,
        ledger: Arc<dyn LedgerPort>,
        clock: Arc<dyn ClockPort>,
        local_node: NodeId,
    ) -> Self {
        Self {
            releases,
            ledger,
            clock,
            local_node,
        }
    }

    pub fn execute(&self, release_id: &str) -> Result<ReleaseCandidate, DomainError> {
        let mut candidate = self.releases.get_candidate(release_id)?;
        let policy = self.releases.policy()?;
        let constitution = self.ledger.constitution()?;
        candidate.predicates_ok(&policy, self.clock.unix_now_secs(), &constitution.hash)?;
        candidate.add_cosign(&self.local_node)?;
        self.releases.save_candidate(candidate.clone())?;
        Ok(candidate)
    }
}

pub struct ActivateRelease {
    releases: Arc<dyn ReleaseStorePort>,
    ledger: Arc<dyn LedgerPort>,
    clock: Arc<dyn ClockPort>,
}

impl ActivateRelease {
    pub fn new(
        releases: Arc<dyn ReleaseStorePort>,
        ledger: Arc<dyn LedgerPort>,
        clock: Arc<dyn ClockPort>,
    ) -> Self {
        Self {
            releases,
            ledger,
            clock,
        }
    }

    pub fn execute(&self, release_id: &str) -> Result<AllowlistEntry, DomainError> {
        let mut candidate = self.releases.get_candidate(release_id)?;
        let policy = self.releases.policy()?;
        let constitution = self.ledger.constitution()?;
        candidate.predicates_ok(&policy, self.clock.unix_now_secs(), &constitution.hash)?;
        if candidate.cosigns.len() < policy.vault_cosign_quorum() {
            return Err(DomainError::QuorumNotMet {
                have: candidate.cosigns.len(),
                need: policy.vault_cosign_quorum(),
            });
        }
        let entry = AllowlistEntry {
            release_id: candidate.id.clone(),
            hs: candidate.hs.clone(),
            hb: candidate.hb.clone(),
            activated_at_secs: self.clock.unix_now_secs(),
            constitution_hash: constitution.hash,
        };
        candidate.phase = ReleasePhase::Allowlisted;
        self.releases.save_candidate(candidate)?;
        self.releases.put_allowlist(entry.clone())?;
        Ok(entry)
    }
}

pub struct GetAllowlist {
    releases: Arc<dyn ReleaseStorePort>,
}

impl GetAllowlist {
    pub fn new(releases: Arc<dyn ReleaseStorePort>) -> Self {
        Self { releases }
    }

    pub fn execute(&self) -> Result<Vec<AllowlistEntry>, DomainError> {
        self.releases.allowlist()
    }

    pub fn require_hb(&self, hb: &ContentHash) -> Result<(), DomainError> {
        if self.releases.is_allowlisted_hb(hb)? {
            Ok(())
        } else {
            Err(DomainError::NotAllowlisted(hb.as_str().to_string()))
        }
    }
}
