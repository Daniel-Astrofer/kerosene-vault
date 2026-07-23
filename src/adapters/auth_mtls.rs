//! mTLS auth stub — Production Gate. Lab static tokens are refused here.

use crate::application::VaultAuthPort;
use crate::domain::DomainError;

pub struct MutualTlsAuthAdapter;

impl MutualTlsAuthAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MutualTlsAuthAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultAuthPort for MutualTlsAuthAdapter {
    fn mode_name(&self) -> &'static str {
        "mtls"
    }

    fn is_static_token(&self) -> bool {
        false
    }

    fn authorize(&self, _token_header: Option<&str>) -> Result<(), DomainError> {
        Err(DomainError::ProductionGate(
            "mTLS adapter stub: peer certificate verification not wired (Production Gate)".into(),
        ))
    }
}
