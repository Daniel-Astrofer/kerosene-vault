//! Distributed DKG adapter — fail-closed until Production Gate wiring.

use crate::application::DkgPort;
use crate::domain::DomainError;

pub struct DistributedDkgAdapter;

impl DistributedDkgAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn refuse_dealer_attempt() -> Result<(), DomainError> {
        Err(DomainError::DealerForbidden(
            "distributed DKG only; dealer single-process is lab-only (ToB 2024)".into(),
        ))
    }
}

impl Default for DistributedDkgAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl DkgPort for DistributedDkgAdapter {
    fn mode_name(&self) -> &'static str {
        "distributed_fail_closed"
    }

    fn is_dealer(&self) -> bool {
        false
    }
}
