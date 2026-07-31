//! Domain layer: entities and pure policy. No Tor, disk, or network.

mod attestation;
mod bitcoin_net;
mod bucket;
mod constitution;
mod day_epoch;
mod dkg;
mod error;
mod health;
mod hybrid_envelope;
mod intent_bind;
mod ledger;
mod node_tier;
mod peer;
mod psbt_policy;
mod quantum_state;
mod release;
mod reshare_policy;
mod reward;
mod threshold;

pub use attestation::{admits_attestation_measurement, AttestationMode, AttestationQuote, Measurement};
pub use bitcoin_net::{destination_script_pubkey, validate_destination, BitcoinNetwork};
pub use bucket::{
    assert_channels_taproot_bucket, assert_shared_taproot_bucket, evaluate_intent, BucketKind, BucketPolicy,
    ProfitSplits, SettlementIntent,
};
pub use constitution::{quorum_two_thirds, Constitution, DowngradePolicy, FormatVersions};
pub use day_epoch::DayEpoch;
pub use dkg::run_dkg;
pub use error::DomainError;
pub use health::{HealthStatus, NodeHealth, PeerReachability};
pub use hybrid_envelope::{HybridContext, HybridEnvelope, HybridKeyMaterial};
pub use intent_bind::{assert_outputs_match_intent, IntentSignature};
pub use ledger::{Epoch, EpochAdvanceProposal, LedgerEntry, LedgerEventKind};
pub use node_tier::{
    admission_seating, detect_tee_at_paths, detect_tee_devices, resolve_node_tier, seat_genesis_by_tier,
    SeatingCandidate, VaultNodeTier,
};
pub use peer::{NodeId, PeerEndpoint, PeerIdentity, PeerInfo};
pub use psbt_policy::{PsbtPolicy, RbfPolicy};
pub use quantum_state::{DrillReport, QuantumMigrationConfig, QuantumState, SweepReport, TransitionAuth, UtxoRecord};
pub use release::{
    lab_rebuild_binary_hash, AllowlistEntry, ContentHash, ReleaseCandidate, ReleasePhase, ReleasePolicy,
};
pub use reshare_policy::ResharePolicy;
pub use reward::{
    assert_bank_issued_miner_payout, EconomyState, GovernanceAccrual, GovernanceJobKind, GovernanceRewardConfig,
    MinerOperator, MinerPayoutCadence, MinerPayoutShare, ProfitSplitAccrual, RewardPolicy,
};
pub use threshold::{
    derive_nonce, eval_poly, field_add, field_mul, interpolate_secret, lab_random_u64, nonce_commitment,
    CombinedSignature, GroupKey, KeyShare, PartialSignature, ShareIndex, SigningPhase, SigningSession, LAB_PRIME,
};
