//! Kerosene vault mesh node — Core Library.
//!
//! Layering (Clean Architecture — see `VAULT_MESH_PLAN.md` §2.1):
//! - `domain` — pure types and rules (no I/O)
//! - `application` — use cases + ports (traits)
//! - `adapters` — Tor/TEE/store implementations (later); lab doubles here
//! - `bootstrap` — config, DI, process entry wiring

pub mod adapters;
pub mod application;
pub mod bootstrap;
pub mod domain;
