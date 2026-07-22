use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    InvalidNodeId,
    PeerNotFound(String),
    SimAttestationForbidden,
    AttestationRejected(String),
    MeasurementMismatch,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNodeId => write!(f, "invalid node id"),
            Self::PeerNotFound(id) => write!(f, "peer not found: {id}"),
            Self::SimAttestationForbidden => {
                write!(f, "attestation mode sim is forbidden in production builds")
            }
            Self::AttestationRejected(reason) => write!(f, "attestation quote rejected: {reason}"),
            Self::MeasurementMismatch => write!(f, "measurement mismatch"),
        }
    }
}

impl std::error::Error for DomainError {}
