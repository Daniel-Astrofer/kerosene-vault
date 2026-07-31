//! Re-export `vault_core` for backward compatibility with existing tests
//! and the thin `src/main.rs` binary wrapper.
//!
//! All implementation code now lives in `crates/vault-core/`.

pub use vault_core::*;
