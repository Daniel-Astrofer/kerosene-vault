//! Reshare cadence policy (Gate): daily auto-refresh vs manual trigger.

use crate::domain::DomainError;

/// Cadence for FROST share refresh after day-epoch advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResharePolicy {
    /// Run multi-round FROST refresh DKG on every quorum day advance.
    Daily,
    /// Day advance only records constitution ledger events; reshare is explicit.
    Manual,
}

impl ResharePolicy {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "daily" | "auto" => Some(Self::Daily),
            "manual" | "on_demand" | "ondemand" => Some(Self::Manual),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Manual => "manual",
        }
    }

    pub fn from_env_or_default() -> Result<Self, DomainError> {
        match std::env::var("VAULT_RESHARE_POLICY") {
            Ok(raw) => Self::parse(&raw).ok_or_else(|| {
                DomainError::InvalidConstitution(format!("unknown VAULT_RESHARE_POLICY={raw} (want daily|manual)"))
            }),
            Err(_) => Ok(Self::Manual),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_daily_and_manual() {
        assert_eq!(ResharePolicy::parse("daily"), Some(ResharePolicy::Daily));
        assert_eq!(ResharePolicy::parse("MANUAL"), Some(ResharePolicy::Manual));
        assert!(ResharePolicy::parse("weekly").is_none());
    }
}
