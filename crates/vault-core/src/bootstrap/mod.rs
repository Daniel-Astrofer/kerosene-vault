//! Process bootstrap: config + DI. Lab flags stay here — never in domain.

#[cfg(all(feature = "production", feature = "dealer_lab"))]
compile_error!(
    "features `production` and `dealer_lab` are mutually exclusive; build with --no-default-features --features production"
);

mod config;
mod wiring;

pub use config::{AuthMode, CeremonyMode, DkgMode, ShareStoreMode, VaultConfig};
pub use wiring::VaultRuntime;
