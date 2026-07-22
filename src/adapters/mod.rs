//! Adapters: I/O and vendor details. Domain/application must not import these internals.

mod attestation_sim;
mod clock;
mod peer_memory;

pub use attestation_sim::SimAttestationAdapter;
pub use clock::SystemClock;
pub use peer_memory::InMemoryPeerDirectory;
