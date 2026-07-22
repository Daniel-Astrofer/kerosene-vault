//! Process bootstrap: config + DI. Lab flags stay here — never in domain.

mod config;
mod wiring;

pub use config::{CeremonyMode, VaultConfig};
pub use wiring::VaultRuntime;
