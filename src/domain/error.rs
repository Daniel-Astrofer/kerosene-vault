use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    InvalidNodeId,
    PeerNotFound(String),
    SimAttestationForbidden,
    AttestationRejected(String),
    MeasurementMismatch,
    InvalidConstitution(String),
    LedgerConflict(String),
    UnauthorizedWriter(String),
    QuorumNotMet { have: usize, need: usize },
    UnknownProposal(String),
    EpochMismatch { expected: u64, got: u64 },
    ProposalClosed(String),
    InvalidShare(String),
    ThresholdError(String),
    NonceReuse(String),
    FailStop { online: usize, need: usize },
    SessionConsumed(String),
    BadSigningPhase { session_id: String, phase: String },
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
            Self::InvalidConstitution(r) => write!(f, "invalid constitution: {r}"),
            Self::LedgerConflict(r) => write!(f, "ledger conflict: {r}"),
            Self::UnauthorizedWriter(id) => write!(f, "unauthorized ledger writer: {id}"),
            Self::QuorumNotMet { have, need } => {
                write!(f, "quorum not met: have {have}, need {need}")
            }
            Self::UnknownProposal(id) => write!(f, "unknown proposal: {id}"),
            Self::EpochMismatch { expected, got } => {
                write!(f, "epoch mismatch: expected {expected}, got {got}")
            }
            Self::ProposalClosed(id) => write!(f, "proposal already closed: {id}"),
            Self::InvalidShare(r) => write!(f, "invalid share: {r}"),
            Self::ThresholdError(r) => write!(f, "threshold error: {r}"),
            Self::NonceReuse(r) => write!(f, "nonce reuse: {r}"),
            Self::FailStop { online, need } => {
                write!(f, "fail-stop: online {online} < need {need}")
            }
            Self::SessionConsumed(id) => write!(f, "signing session consumed: {id}"),
            Self::BadSigningPhase { session_id, phase } => {
                write!(f, "bad signing phase for {session_id}: {phase}")
            }
        }
    }
}

impl std::error::Error for DomainError {}
