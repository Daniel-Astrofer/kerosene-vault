use crate::domain::{
    AttestationMode, AttestationQuote, Constitution, DomainError, Epoch, EpochAdvanceProposal,
    LedgerEntry, Measurement, NodeId, PeerInfo,
};

pub trait PeerDirectoryPort {
    fn list_peers(&self) -> Result<Vec<PeerInfo>, DomainError>;
    fn upsert_peer(&self, peer: PeerInfo) -> Result<(), DomainError>;
    fn ping(&self, peer_id: &NodeId) -> Result<(), DomainError>;
}

pub trait AttestationPort {
    fn mode(&self) -> AttestationMode;
    fn issue_quote(&self, measurement: &Measurement) -> Result<AttestationQuote, DomainError>;
    fn verify_quote(&self, quote: &AttestationQuote) -> Result<(), DomainError>;
}

pub trait ClockPort {
    fn unix_now_secs(&self) -> u64;
}

/// Permissioned append-only governance ledger.
pub trait LedgerPort {
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
