//! Application layer: use cases depend on ports (DIP).

mod economy_ops;
mod health;
mod intent_ops;
mod key_lifecycle;
mod ledger_ops;
mod metrics;
mod online_probe;
mod ping_peer;
pub mod ports;
mod quantum_migration;
mod release_ops;
mod share_migration;
mod sign;

pub use economy_ops::{
    economy_snapshot_json, is_payout_epoch, AccrueGovernanceWork, AccrueMinerRewards, AccrueReceipt, EconomyStatusView,
    GetEconomyStatus, PayoutProposal, ProposeMinerPayouts, UpsertMiner,
};
pub use health::GetHealth;
pub use intent_ops::{AllocateProfit, GateIntent, GateReceipt, ProfitAllocation};
pub use key_lifecycle::{KeyDomain, KeyLifecycle, KeyLifecycleEvent, KeyMetadata};
pub use ledger_ops::{GetLedgerSnapshot, LedgerSnapshot, ProposeEpochAdvance, VoteEpochAdvance};
pub use metrics::GetMetrics;
pub use online_probe::ProbedOnlineCount;
pub use ping_peer::{PingPeer, PingReport};
pub use ports::{
    bind_session_to_intent, AntiNoncePort, AttestationPort, BlobStorePort, BucketLedgerPort, ClockPort,
    DailyRotationPort, DkgPort, EconomyPort, HybridEnvelopePort, KeyLifecyclePort, LedgerPort, PeerDirectoryPort,
    ReleaseStorePort, ReshareHookPort, ShareStorePort, VaultAuthPort,
};
pub use quantum_migration::{
    validate_emergency_ready, PsbtSkeleton, QuantumMigrationPort, StubQuantumMigrationController,
};
pub use release_ops::{ActivateRelease, CosignRelease, GetAllowlist, ProposeRelease, RebuildRelease};
pub use share_migration::{NoopShareMigration, ShareMigrationPort};
pub use sign::{MutableOnlineCount, OnlineStatusPort, SignMessage, StaticOnlineCount};
