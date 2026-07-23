//! Static vault token auth (lab only). Production must use mTLS.
//! Even if mis-wired, static token never authorizes treasury signing when
//! `treasury_signing_allowed` is false (staging/prod).

use crate::application::VaultAuthPort;
use crate::domain::DomainError;

pub struct StaticTokenAuthAdapter {
    expected: String,
    /// When false (staging/production), `authorize_treasury_sign` fails closed.
    treasury_signing_allowed: bool,
}

impl StaticTokenAuthAdapter {
    /// Lab visualize: token may authorize treasury signing.
    pub fn new(token: impl Into<String>) -> Self {
        Self::with_treasury_signing(token, true)
    }

    pub fn with_treasury_signing(token: impl Into<String>, treasury_signing_allowed: bool) -> Self {
        Self {
            expected: token.into(),
            treasury_signing_allowed,
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

    fn authorize_treasury_sign(&self) -> Result<(), DomainError> {
        if !self.treasury_signing_allowed {
            return Err(DomainError::AuthRejected(
                "static lab token cannot authorize treasury signing outside lab; use mTLS"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_token_may_sign_in_lab() {
        let a = StaticTokenAuthAdapter::with_treasury_signing("tok", true);
        assert!(a.authorize(Some("tok")).is_ok());
        assert!(a.authorize_treasury_sign().is_ok());
    }

    #[test]
    fn lab_token_cannot_sign_when_disabled() {
        let a = StaticTokenAuthAdapter::with_treasury_signing("tok", false);
        assert!(a.authorize(Some("tok")).is_ok());
        assert!(a.authorize_treasury_sign().is_err());
    }
}
