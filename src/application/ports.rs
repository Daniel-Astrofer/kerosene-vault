use crate::domain::{
    AttestationMode, AttestationQuote, DomainError, Measurement, NodeId, PeerInfo,
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
