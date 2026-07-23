//! In-memory miner economy state (F9).

use std::sync::Mutex;

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
        Ok(self.inner.lock().expect("economy lock").clone())
    }

    fn upsert_operator(&self, op: MinerOperator) -> Result<(), DomainError> {
        self.inner
            .lock()
            .expect("economy lock")
            .upsert_operator(op)
    }

    fn accrue_from_profit(&self, profit_sats: u64, p_reward_bps: u32) -> Result<u64, DomainError> {
        Ok(self
            .inner
            .lock()
            .expect("economy lock")
            .accrue_from_profit(profit_sats, p_reward_bps))
    }

    fn accrue_governance_job(
        &self,
        job: GovernanceJobKind,
        participants: &[crate::domain::NodeId],
        config: &GovernanceRewardConfig,
    ) -> Result<GovernanceAccrual, DomainError> {
        Ok(self
            .inner
            .lock()
            .expect("economy lock")
            .accrue_governance_job(job, participants, config))
    }

    fn propose_equal_payouts(
        &self,
        amount: u64,
    ) -> Result<Vec<crate::domain::MinerPayoutShare>, DomainError> {
        self.inner
            .lock()
            .expect("economy lock")
            .propose_equal_payouts(amount)
    }

    fn debit_pool(&self, amount: u64) -> Result<(), DomainError> {
        self.inner.lock().expect("economy lock").debit_pool(amount)
    }
}
