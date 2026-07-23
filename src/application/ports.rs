use crate::domain::{
    AttestationMode, AttestationQuote, AllowlistEntry, BucketKind, BucketPolicy, Constitution,
    ContentHash, DayEpoch, DomainError, EconomyState, Epoch, EpochAdvanceProposal, LedgerEntry,
    Measurement, MinerOperator, MinerPayoutShare, NodeId, PeerInfo, ReleaseCandidate,
    ReleasePolicy,
};

pub trait PeerDirectoryPort: Send + Sync {
    fn list_peers(&self) -> Result<Vec<PeerInfo>, DomainError>;
    fn upsert_peer(&self, peer: PeerInfo) -> Result<(), DomainError>;
    fn ping(&self, peer_id: &NodeId) -> Result<(), DomainError>;
}

pub trait AttestationPort: Send + Sync {
    fn mode(&self) -> AttestationMode;
    fn issue_quote(&self, measurement: &Measurement) -> Result<AttestationQuote, DomainError>;
    fn verify_quote(&self, quote: &AttestationQuote) -> Result<(), DomainError>;
}

pub trait ClockPort: Send + Sync {
    fn unix_now_secs(&self) -> u64;
}

/// Permissioned append-only governance ledger.
pub trait LedgerPort: Send + Sync {
    fn constitution(&self) -> Result<Constitution, DomainError>;
    fn epoch(&self) -> Result<Epoch, DomainError>;
    fn set_epoch(&self, epoch: Epoch) -> Result<(), DomainError>;
    fn head(&self) -> Result<Option<LedgerEntry>, DomainError>;
    fn entries(&self) -> Result<Vec<LedgerEntry>, DomainError>;
    fn append(&self, entry: LedgerEntry) -> Result<(), DomainError>;
    fn put_proposal(&self, proposal: EpochAdvanceProposal) -> Result<(), DomainError>;
    fn get_proposal(&self, id: &str) -> Result<EpochAdvanceProposal, DomainError>;
    fn save_proposal(&self, proposal: EpochAdvanceProposal) -> Result<(), DomainError>;
}

/// Content-addressed blob store for Hs/Hb artifacts.
pub trait BlobStorePort: Send + Sync {
    fn put(&self, hash: &ContentHash, bytes: &[u8]) -> Result<(), DomainError>;
    fn get(&self, hash: &ContentHash) -> Result<Vec<u8>, DomainError>;
}

/// Release candidate + allowlist state shared across vaults in the lab mesh.
pub trait ReleaseStorePort: Send + Sync {
    fn policy(&self) -> Result<ReleasePolicy, DomainError>;
    fn put_candidate(&self, candidate: ReleaseCandidate) -> Result<(), DomainError>;
    fn get_candidate(&self, id: &str) -> Result<ReleaseCandidate, DomainError>;
    fn save_candidate(&self, candidate: ReleaseCandidate) -> Result<(), DomainError>;
    fn put_allowlist(&self, entry: AllowlistEntry) -> Result<(), DomainError>;
    fn allowlist(&self) -> Result<Vec<AllowlistEntry>, DomainError>;
    fn is_allowlisted_hb(&self, hb: &ContentHash) -> Result<bool, DomainError>;
}

/// Per-bucket spend tracking + destination policies (enclave side).
pub trait BucketLedgerPort: Send + Sync {
    fn policy(&self, kind: BucketKind) -> Result<BucketPolicy, DomainError>;
    fn spent_today(&self, kind: BucketKind) -> Result<u64, DomainError>;
    fn record_spend(&self, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError>;
    fn is_consumed(&self, intent_id: &str) -> Result<bool, DomainError>;
    fn mark_consumed(&self, intent_id: &str) -> Result<(), DomainError>;
}

/// Miner reward pool + eligibility (F9). Vaults never invent payout destinations.
pub trait EconomyPort: Send + Sync {
    fn snapshot(&self) -> Result<EconomyState, DomainError>;
    fn upsert_operator(&self, op: MinerOperator) -> Result<(), DomainError>;
    fn accrue_from_profit(&self, profit_sats: u64, p_reward_bps: u32) -> Result<u64, DomainError>;
    fn propose_equal_payouts(&self, amount: u64) -> Result<Vec<MinerPayoutShare>, DomainError>;
    fn debit_pool(&self, amount: u64) -> Result<(), DomainError>;
}

/// DKG / keygen port. Lab may use dealer behind `dealer_lab`; prod uses distributed (Gate).
pub trait DkgPort: Send + Sync {
    fn mode_name(&self) -> &'static str;
    fn is_dealer(&self) -> bool;
}

/// Persist / load sealed FROST share material.
pub trait ShareStorePort: Send + Sync {
    fn store_kind(&self) -> &'static str;
    fn put_share(&self, share_id: &str, plaintext: &[u8]) -> Result<(), DomainError>;
    fn get_share(&self, share_id: &str) -> Result<Vec<u8>, DomainError>;
}

/// Auth between kfe ↔ vault (lab static token vs prod mTLS).
pub trait VaultAuthPort: Send + Sync {
    fn mode_name(&self) -> &'static str;
    fn is_static_token(&self) -> bool;
    fn authorize(&self, token_header: Option<&str>) -> Result<(), DomainError>;
}

/// Anti-nonce session ledger: one signing_session_id → at most one nonce package, survives restart.
pub trait AntiNoncePort: Send + Sync {
    fn claim_session(&self, session_id: &str) -> Result<(), DomainError>;
    fn is_consumed(&self, session_id: &str) -> Result<bool, DomainError>;
}

/// Daily rotation stub: advance/bind day_epoch (full reshare is Production Gate).
pub trait DailyRotationPort: Send + Sync {
    fn current_day_epoch(&self) -> Result<DayEpoch, DomainError>;
    fn advance(&self) -> Result<DayEpoch, DomainError>;
    fn require_epoch(&self, bound: &DayEpoch) -> Result<(), DomainError>;
}
