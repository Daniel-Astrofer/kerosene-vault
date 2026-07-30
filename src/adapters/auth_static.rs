//! Static vault token auth (lab only). Production must use mTLS.
//! Even if mis-wired, static token never authorizes treasury signing when
//! `treasury_signing_allowed` is false (staging/prod).

use subtle::ConstantTimeEq;

use crate::application::VaultAuthPort;
use crate::domain::DomainError;

pub struct StaticTokenAuthAdapter {
    expected: String,
    /// When false (staging/production), `authorize_treasury_sign` fails closed.
    treasury_signing_allowed: bool,
    /// Manual reshare only in lab unless ops sets allow flag at wiring (#30).
    reshare_trigger_allowed: bool,
}

impl StaticTokenAuthAdapter {
    /// Lab visualize: token may authorize treasury signing.
    pub fn new(token: impl Into<String>) -> Self {
        Self::with_treasury_signing(token, true)
    }

    pub fn with_treasury_signing(token: impl Into<String>, treasury_signing_allowed: bool) -> Self {
        Self { expected: token.into(), treasury_signing_allowed, reshare_trigger_allowed: treasury_signing_allowed }
    }

    pub fn with_ops(token: impl Into<String>, treasury_signing_allowed: bool, reshare_trigger_allowed: bool) -> Self {
        Self { expected: token.into(), treasury_signing_allowed, reshare_trigger_allowed }
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    // Length mismatch: still compare against expected to avoid short-circuit leak of length.
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        let _ = a.ct_eq(a);
        return false;
    }
    bool::from(a.ct_eq(b))
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
        if !constant_time_eq(provided, &self.expected) {
            return Err(DomainError::AuthRejected("invalid X-Vault-Token".into()));
        }
        Ok(())
    }

    fn authorize_treasury_sign(&self) -> Result<(), DomainError> {
        if !self.treasury_signing_allowed {
            return Err(DomainError::AuthRejected(
                "static lab token cannot authorize treasury signing outside lab; use mTLS".into(),
            ));
        }
        Ok(())
    }

    fn authorize_reshare_trigger(&self) -> Result<(), DomainError> {
        if !self.reshare_trigger_allowed {
            return Err(DomainError::AuthRejected(
                "manual reshare trigger refused; lab ceremony or VAULT_ALLOW_MANUAL_RESHARE=1".into(),
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
        assert!(a.authorize_reshare_trigger().is_ok());
    }

    #[test]
    fn lab_token_cannot_sign_when_disabled() {
        let a = StaticTokenAuthAdapter::with_treasury_signing("tok", false);
        assert!(a.authorize(Some("tok")).is_ok());
        assert!(a.authorize_treasury_sign().is_err());
        assert!(a.authorize_reshare_trigger().is_err());
    }

    #[test]
    fn rejects_wrong_token() {
        let a = StaticTokenAuthAdapter::new("expected-token");
        assert!(a.authorize(Some("wrong-token!!")).is_err());
    }
}
