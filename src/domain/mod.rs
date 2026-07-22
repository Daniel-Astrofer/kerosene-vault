//! Domain layer: entities and pure policy. No Tor, disk, or network.

mod attestation;
mod error;
mod health;
mod peer;

pub use attestation::{AttestationMode, AttestationQuote, Measurement};
pub use error::DomainError;
pub use health::{HealthStatus, NodeHealth};
pub use peer::{NodeId, PeerEndpoint, PeerInfo};
