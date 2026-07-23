//! Lab P0 adapters: FROST dealer/sign, share store, auth, day rotation, HTTP.

mod attestation_sim;
mod attestation_tee;
mod auth_mtls;
mod auth_static;
mod bucket_memory;
mod clock;
mod daily_rotation;
mod dkg_distributed;
mod economy_memory;
#[cfg(feature = "dealer_lab")]
mod frost_dealer;
mod frost_sign;
mod http;
mod ledger_memory;
mod peer_memory;
mod release_memory;
mod session_persist;
mod share_aead;
mod share_tee;
mod threshold_state;

pub use attestation_sim::SimAttestationAdapter;
pub use attestation_tee::TeeAttestationAdapter;
pub use auth_mtls::MutualTlsAuthAdapter;
pub use auth_static::StaticTokenAuthAdapter;
pub use bucket_memory::InMemoryBucketLedger;
pub use clock::SystemClock;
pub use daily_rotation::LedgerDayEpochStub;
pub use dkg_distributed::{DistributedDkgAdapter, FrostDistributedBundle};
pub use economy_memory::InMemoryEconomy;
#[cfg(feature = "dealer_lab")]
pub use frost_dealer::{dealer_fatal_banner, DealerLabAdapter, FrostDealerBundle};
pub use frost_sign::{FrostAggregateResult, FrostSignOrchestrator};
pub use http::{build_router, AppState};
pub use ledger_memory::InMemoryLedger;
pub use peer_memory::InMemoryPeerDirectory;
pub use release_memory::InMemoryReleaseMesh;
pub use session_persist::PersistedAntiNonce;
pub use share_aead::AeadDiskShareStore;
pub use share_tee::TeeSealShareStore;
pub use threshold_state::ThresholdVaultState;
