//! In-memory miner economy state (F9).
//!
//! # Persistence honesty (#18)
//! State is **process-local**. Restart loses pool / operators / accruals.
//! Not an authenticated append-only mesh ledger — do not claim durability.
//! Residual until a durable economy store lands.

use std::sync::Mutex;

use super::sync_util::lock_mutex;

use crate::application::ports::EconomyPort;
use crate::domain::{
    DomainError, EconomyState, GovernanceAccrual, GovernanceJobKind, GovernanceRewardConfig,
    MinerOperator,
};

pub struct InMemoryEconomy {
    inner: Mutex<EconomyState>,
}

impl InMemoryEconomy {
    pub fn new(state: EconomyState) -> Self {
        Self {
            inner: Mutex::new(state),
        }
    }

    pub fn open() -> Self {
        Self::new(EconomyState::new_open())
    }
}

impl EconomyPort for InMemoryEconomy {
    fn snapshot(&self) -> Result<EconomyState, DomainError> {
        Ok(lock_mutex(&self.inner, "economy")?.clone())
    }

    fn upsert_operator(&self, op: MinerOperator) -> Result<(), DomainError> {
        lock_mutex(&self.inner, "economy")?.upsert_operator(op)
    }

    fn accrue_from_profit(&self, profit_sats: u64, p_reward_bps: u32) -> Result<u64, DomainError> {
        Ok(lock_mutex(&self.inner, "economy")?.accrue_from_profit(profit_sats, p_reward_bps))
    }

    fn accrue_governance_job(
        &self,
        job: GovernanceJobKind,
        participants: &[crate::domain::NodeId],
        config: &GovernanceRewardConfig,
    ) -> Result<GovernanceAccrual, DomainError> {
        Ok(lock_mutex(&self.inner, "economy")?
            .accrue_governance_job(job, participants, config))
    }

    fn propose_equal_payouts(
        &self,
        amount: u64,
    ) -> Result<Vec<crate::domain::MinerPayoutShare>, DomainError> {
        lock_mutex(&self.inner, "economy")?.propose_equal_payouts(amount)
    }

    fn debit_pool(&self, amount: u64) -> Result<(), DomainError> {
        lock_mutex(&self.inner, "economy")?.debit_pool(amount)
    }
}
