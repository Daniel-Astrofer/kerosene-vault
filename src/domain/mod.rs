//! Domain layer: entities and pure policy. No Tor, disk, or network.

mod attestation;
mod bucket;
mod constitution;
mod dkg;
mod error;
mod health;
mod ledger;
mod peer;
mod release;
mod threshold;

pub use attestation::{AttestationMode, AttestationQuote, Measurement};
pub use bucket::{
    evaluate_intent, BucketKind, BucketPolicy, ProfitSplits, SettlementIntent,
};
pub use constitution::{quorum_two_thirds, Constitution};
pub use dkg::run_dkg;
pub use error::DomainError;
pub use health::{HealthStatus, NodeHealth};
pub use ledger::{Epoch, EpochAdvanceProposal, LedgerEntry, LedgerEventKind};
pub use peer::{NodeId, PeerEndpoint, PeerInfo};
pub use release::{
    lab_rebuild_binary_hash, AllowlistEntry, ContentHash, ReleaseCandidate, ReleasePhase,
    ReleasePolicy,
};
pub use threshold::{
    derive_nonce, eval_poly, field_add, field_mul, interpolate_secret, lab_random_u64,
    nonce_commitment, CombinedSignature, GroupKey, KeyShare, PartialSignature, ShareIndex,
    SigningPhase, SigningSession, LAB_PRIME,
};
