//! Domain layer: entities and pure policy. No Tor, disk, or network.

mod attestation;
mod bitcoin_net;
mod bucket;
mod constitution;
mod day_epoch;
mod dkg;
mod error;
mod health;
mod ledger;
mod peer;
mod release;
mod reshare_policy;
mod reward;
mod threshold;

pub use attestation::{
    admits_attestation_measurement, AttestationMode, AttestationQuote, Measurement,
};
pub use bitcoin_net::{validate_destination, BitcoinNetwork};
pub use bucket::{
    evaluate_intent, BucketKind, BucketPolicy, ProfitSplits, SettlementIntent,
};
pub use constitution::{quorum_two_thirds, Constitution};
pub use day_epoch::DayEpoch;
pub use dkg::run_dkg;
pub use error::DomainError;
pub use health::{HealthStatus, NodeHealth};
pub use ledger::{Epoch, EpochAdvanceProposal, LedgerEntry, LedgerEventKind};
pub use peer::{NodeId, PeerEndpoint, PeerInfo};
pub use release::{
    lab_rebuild_binary_hash, AllowlistEntry, ContentHash, ReleaseCandidate, ReleasePhase,
    ReleasePolicy,
};
pub use reshare_policy::ResharePolicy;
pub use reward::{
    assert_bank_issued_miner_payout, EconomyState, GovernanceAccrual, GovernanceJobKind,
    GovernanceRewardConfig, MinerOperator, MinerPayoutShare, RewardPolicy,
};
pub use threshold::{
    derive_nonce, eval_poly, field_add, field_mul, interpolate_secret, lab_random_u64,
    nonce_commitment, CombinedSignature, GroupKey, KeyShare, PartialSignature, ShareIndex,
    SigningPhase, SigningSession, LAB_PRIME,
};
