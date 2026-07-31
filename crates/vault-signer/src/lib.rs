//! vault-signer — FROST signing daemon library.
//!
//! Provides a FROST (Flexible Round-Optimized Schnorr Threshold) signing
//! state machine with distributed key generation (DKG), key reshare,
//! and session management. Communicates via Unix socket IPC only — no
//! TCP or network dependencies.

pub mod dkg;
pub mod ipc;
pub mod reshare;
pub mod session;
pub mod signer;

pub use dkg::DistributedKeyGeneration;
pub use ipc::SignerIpc;
pub use reshare::KeyReshare;
pub use session::SigningSessionManager;
pub use signer::FrostSigner;
