use crate::domain::{DomainError, ProfitSplits};

/// Active security/economic constitution anchored on the vault ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constitution {
    pub version: u32,
    pub max_withdraw_per_day_sats: u64,
    pub max_withdraw_per_tx_sats: u64,
    pub signing_n: usize,
    pub signing_t: usize,
    pub governance_t: usize,
    pub p_reward_bps: u32,
    pub p_reward_max_bps: u32,
    pub profit_splits: ProfitSplits,
    pub crypto_suite_id: String,
    pub hash: String,
}

impl Constitution {
    pub fn v1_lab(n: usize) -> Result<Self, DomainError> {
        if n < 2 {
            return Err(DomainError::InvalidConstitution(
                "signing_n must be >= 2".into(),
            ));
        }
        let signing_t = quorum_two_thirds(n);
        let governance_t = (signing_t + 1).min(n);
        let profit_splits = ProfitSplits::lab_dry_run();
        profit_splits.validate()?;
        let mut c = Self {
            version: 1,
            max_withdraw_per_day_sats: 1_000_000,
            max_withdraw_per_tx_sats: 250_000,
            signing_n: n,
            signing_t,
            governance_t,
            p_reward_bps: 100, // 1% target; lab dry-run uses profit_splits.miners_bps=0
            p_reward_max_bps: 800,
            profit_splits,
            crypto_suite_id: "hybrid-v1-placeholder".into(),
            hash: String::new(),
        };
        c.hash = c.compute_hash();
        Ok(c)
    }

    pub fn compute_hash(&self) -> String {
        let material = format!(
            "v{}|day{}|tx{}|n{}|t{}|gt{}|p{}|max{}|m{}|ch{}|inf{}|{}",
            self.version,
            self.max_withdraw_per_day_sats,
            self.max_withdraw_per_tx_sats,
            self.signing_n,
            self.signing_t,
            self.governance_t,
            self.p_reward_bps,
            self.p_reward_max_bps,
            self.profit_splits.miners_bps,
            self.profit_splits.channels_bps,
            self.profit_splits.infra_bps,
            self.crypto_suite_id
        );
        crate::domain::attestation::Measurement::from_bytes(material.as_bytes())
            .as_hex()
            .to_string()
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.signing_n < 2 {
            return Err(DomainError::InvalidConstitution("n < 2".into()));
        }
        if self.signing_t == 0 || self.signing_t > self.signing_n {
            return Err(DomainError::InvalidConstitution("bad signing_t".into()));
        }
        if self.governance_t < self.signing_t || self.governance_t > self.signing_n {
            return Err(DomainError::InvalidConstitution("bad governance_t".into()));
        }
        if self.p_reward_bps > self.p_reward_max_bps {
            return Err(DomainError::InvalidConstitution(
                "p_reward exceeds max".into(),
            ));
        }
        self.profit_splits.validate()?;
        if self.hash != self.compute_hash() {
            return Err(DomainError::InvalidConstitution(
                "constitution hash mismatch".into(),
            ));
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            r#"{{"version":{},"max_withdraw_per_day_sats":{},"max_withdraw_per_tx_sats":{},"signing_n":{},"signing_t":{},"governance_t":{},"p_reward_bps":{},"p_reward_max_bps":{},"profit_splits":{{"miners_bps":{},"channels_bps":{},"infra_bps":{}}},"crypto_suite_id":"{}","hash":"{}"}}"#,
            self.version,
            self.max_withdraw_per_day_sats,
            self.max_withdraw_per_tx_sats,
            self.signing_n,
            self.signing_t,
            self.governance_t,
            self.p_reward_bps,
            self.p_reward_max_bps,
            self.profit_splits.miners_bps,
            self.profit_splits.channels_bps,
            self.profit_splits.infra_bps,
            self.crypto_suite_id,
            self.hash
        )
    }
}

/// `t = ceil(2n/3)` for transaction signing quorum.
pub fn quorum_two_thirds(n: usize) -> usize {
    (2 * n).div_ceil(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_thirds_examples() {
        assert_eq!(quorum_two_thirds(3), 2);
        assert_eq!(quorum_two_thirds(6), 4);
        assert_eq!(quorum_two_thirds(7), 5);
    }
}
