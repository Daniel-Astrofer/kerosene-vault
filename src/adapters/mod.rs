//! Adapters: I/O and vendor details. Domain/application must not import these internals.

mod attestation_sim;
mod clock;
mod ledger_memory;
mod peer_memory;
mod release_memory;
mod threshold_state;

pub use attestation_sim::SimAttestationAdapter;
pub use clock::SystemClock;
pub use ledger_memory::InMemoryLedger;
pub use peer_memory::InMemoryPeerDirectory;
pub use release_memory::InMemoryReleaseMesh;
pub use threshold_state::ThresholdVaultState;
