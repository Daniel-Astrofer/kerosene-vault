//! Static vault token auth (lab only). Production must use mTLS.

use crate::application::VaultAuthPort;
use crate::domain::DomainError;

pub struct StaticTokenAuthAdapter {
    expected: String,
}

impl StaticTokenAuthAdapter {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            expected: token.into(),
        }
    }
}

impl VaultAuthPort for StaticTokenAuthAdapter {
    fn mode_name(&self) -> &'static str {
        "static_token"
    }

    fn is_static_token(&self) -> bool {
        true
    }

    fn authorize(&self, token_header: Option<&str>) -> Result<(), DomainError> {
        let Some(provided) = token_header.filter(|t| !t.is_empty()) else {
            return Err(DomainError::AuthRejected("missing X-Vault-Token".into()));
        };
        if provided != self.expected {
            return Err(DomainError::AuthRejected("invalid X-Vault-Token".into()));
        }
        Ok(())
    }
}
