//! Miner economy use cases (F9): accrue p%, propose bank-issued MINERS Intents.

use std::sync::Arc;

use crate::application::ports::{EconomyPort, LedgerPort};
use crate::domain::{
    assert_bank_issued_miner_payout, DomainError, EconomyState, MinerOperator, MinerPayoutShare,
    SettlementIntent,
};

pub struct GetEconomyStatus {
    economy: Arc<dyn EconomyPort>,
    ledger: Arc<dyn LedgerPort>,
}

impl GetEconomyStatus {
    pub fn new(economy: Arc<dyn EconomyPort>, ledger: Arc<dyn LedgerPort>) -> Self {
        Self { economy, ledger }
    }

    pub fn execute(&self) -> Result<EconomyStatusView, DomainError> {
        let constitution = self.ledger.constitution()?;
        let eco = self.economy.snapshot()?;
        let eligible = eco.eligible_active().len();
        let waiting = eco.operators.values().filter(|o| o.waiting).count();
        let online = constitution.signing_n; // lab: assume genesis set size
        let survivability_ok = eco.survivability_ok(online, constitution.signing_t);
        Ok(EconomyStatusView {
            miner_pool_sats: eco.miner_pool_sats,
            accrued_profit_sats: eco.accrued_profit_sats,
            p_reward_bps: constitution.p_reward_bps,
            eligible_miners: eligible,
            waiting_miners: waiting,
            crypto_suite_id: constitution.crypto_suite_id,
            crypto_suite_id_pq: eco.crypto_suite_id_pq,
            survivability_ok,
            open_economy: constitution.profit_splits.miners_bps > 0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomyStatusView {
    pub miner_pool_sats: u64,
    pub accrued_profit_sats: u64,
    pub p_reward_bps: u32,
    pub eligible_miners: usize,
    pub waiting_miners: usize,
    pub crypto_suite_id: String,
    pub crypto_suite_id_pq: String,
    pub survivability_ok: bool,
    pub open_economy: bool,
}

impl EconomyStatusView {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"miner_pool_sats":{},"accrued_profit_sats":{},"p_reward_bps":{},"eligible_miners":{},"waiting_miners":{},"crypto_suite_id":"{}","crypto_suite_id_pq":"{}","survivability_ok":{},"open_economy":{}}}"#,
            self.miner_pool_sats,
            self.accrued_profit_sats,
            self.p_reward_bps,
            self.eligible_miners,
            self.waiting_miners,
            self.crypto_suite_id,
            self.crypto_suite_id_pq,
            self.survivability_ok,
            self.open_economy
        )
    }
}

pub struct UpsertMiner {
    economy: Arc<dyn EconomyPort>,
}

impl UpsertMiner {
    pub fn new(economy: Arc<dyn EconomyPort>) -> Self {
        Self { economy }
    }

    pub fn execute(&self, op: MinerOperator) -> Result<(), DomainError> {
        self.economy.upsert_operator(op)
    }
}

pub struct AccrueMinerRewards {
    economy: Arc<dyn EconomyPort>,
    ledger: Arc<dyn LedgerPort>,
}

impl AccrueMinerRewards {
    pub fn new(economy: Arc<dyn EconomyPort>, ledger: Arc<dyn LedgerPort>) -> Self {
        Self { economy, ledger }
    }

    pub fn execute(&self, profit_sats: u64) -> Result<AccrueReceipt, DomainError> {
        let constitution = self.ledger.constitution()?;
        let accrued = self
            .economy
            .accrue_from_profit(profit_sats, constitution.p_reward_bps)?;
        let eco = self.economy.snapshot()?;
        Ok(AccrueReceipt {
            profit_sats,
            accrued_to_pool_sats: accrued,
            miner_pool_sats: eco.miner_pool_sats,
            p_reward_bps: constitution.p_reward_bps,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccrueReceipt {
    pub profit_sats: u64,
    pub accrued_to_pool_sats: u64,
    pub miner_pool_sats: u64,
    pub p_reward_bps: u32,
}

impl AccrueReceipt {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"profit_sats":{},"accrued_to_pool_sats":{},"miner_pool_sats":{},"p_reward_bps":{}}}"#,
            self.profit_sats,
            self.accrued_to_pool_sats,
            self.miner_pool_sats,
            self.p_reward_bps
        )
    }
}

/// Propose equal MINERS Intents for the bank to submit — vaults do not broadcast payouts.
pub struct ProposeMinerPayouts {
    economy: Arc<dyn EconomyPort>,
    ledger: Arc<dyn LedgerPort>,
}

impl ProposeMinerPayouts {
    pub fn new(economy: Arc<dyn EconomyPort>, ledger: Arc<dyn LedgerPort>) -> Self {
        Self { economy, ledger }
    }

    pub fn execute(&self, amount: u64, intent_prefix: &str) -> Result<PayoutProposal, DomainError> {
        let constitution = self.ledger.constitution()?;
        let shares = self.economy.propose_equal_payouts(amount)?;
        let mut intents = Vec::with_capacity(shares.len());
        for (i, share) in shares.iter().enumerate() {
            let id = format!("{intent_prefix}-{i}-{}", share.node_id.as_str());
            let intent = share.to_intent(id, constitution.hash.clone())?;
            assert_bank_issued_miner_payout(&self.economy.snapshot()?, &intent)?;
            intents.push(intent);
        }
        self.economy.debit_pool(amount)?;
        Ok(PayoutProposal {
            total_sats: amount,
            shares,
            intents,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutProposal {
    pub total_sats: u64,
    pub shares: Vec<MinerPayoutShare>,
    pub intents: Vec<SettlementIntent>,
}

impl PayoutProposal {
    pub fn to_json(&self) -> String {
        let parts: Vec<String> = self
            .intents
            .iter()
            .map(|i| {
                format!(
                    r#"{{"intent_id":"{}","destination":"{}","amount_sats":{}}}"#,
                    i.intent_id, i.destination, i.amount_sats
                )
            })
            .collect();
        format!(
            r#"{{"total_sats":{},"intent_count":{},"intents":[{}]}}"#,
            self.total_sats,
            self.intents.len(),
            parts.join(",")
        )
    }
}

pub fn economy_snapshot_json(eco: &EconomyState) -> String {
    let ops: Vec<String> = eco
        .operators
        .values()
        .map(|o| {
            format!(
                r#"{{"node_id":"{}","waiting":{},"eligible":{},"uptime_bps_30d":{},"streak":{}}}"#,
                o.node_id.as_str(),
                o.waiting,
                o.is_eligible(&eco.policy),
                o.uptime_bps_30d,
                o.attestation_streak_days
            )
        })
        .collect();
    format!(
        r#"{{"miner_pool_sats":{},"operators":[{}],"crypto_suite_id_pq":"{}"}}"#,
        eco.miner_pool_sats,
        ops.join(","),
        eco.crypto_suite_id_pq
    )
}
