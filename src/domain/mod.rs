//! Domain layer: entities and pure policy. No Tor, disk, or network.

mod attestation;
mod constitution;
mod error;
mod health;
mod ledger;
mod peer;

pub use attestation::{AttestationMode, AttestationQuote, Measurement};
pub use constitution::{quorum_two_thirds, Constitution};
pub use error::DomainError;
pub use health::{HealthStatus, NodeHealth};
pub use ledger::{Epoch, EpochAdvanceProposal, LedgerEntry, LedgerEventKind};
pub use peer::{NodeId, PeerEndpoint, PeerInfo};
