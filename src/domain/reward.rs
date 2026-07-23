//! Miner rewards, waiting set, and eligibility (F9).
//! Payouts are bank-issued Intents from MINERS — vaults never self-pay.

use std::collections::BTreeMap;

use crate::domain::{BucketKind, DomainError, NodeId, SettlementIntent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardPolicy {
    /// Minimum 30d uptime in bps (9500 = 95%).
    pub min_uptime_bps_30d: u32,
    /// Minimum consecutive daily attestation days.
    pub min_attestation_streak_days: u32,
    /// Minimum bond (sats) to leave waiting set / stay eligible.
    pub min_bond_sats: u64,
    /// Waiting-set share of pool (0 = waiting does not dilute active pool).
    pub waiting_pool_share_bps: u32,
}

impl RewardPolicy {
    pub fn v1_open() -> Self {
        Self {
            min_uptime_bps_30d: 9_500,
            min_attestation_streak_days: 1,
            min_bond_sats: 0, // permissioned early; raise when opening set
            waiting_pool_share_bps: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinerOperator {
    pub node_id: NodeId,
    pub payout_destination: String,
    pub uptime_bps_30d: u32,
    pub attestation_streak_days: u32,
    pub bond_sats: u64,
    pub waiting: bool,
}

impl MinerOperator {
    pub fn is_eligible(&self, policy: &RewardPolicy) -> bool {
        if self.waiting {
            return false;
        }
        self.uptime_bps_30d >= policy.min_uptime_bps_30d
            && self.attestation_streak_days >= policy.min_attestation_streak_days
            && self.bond_sats >= policy.min_bond_sats
            && !self.payout_destination.trim().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomyState {
    pub policy: RewardPolicy,
    pub operators: BTreeMap<String, MinerOperator>,
    pub miner_pool_sats: u64,
    pub accrued_profit_sats: u64,
    /// Optional PQ suite alongside classical (dual-stack placeholder).
    pub crypto_suite_id_pq: String,
}

impl EconomyState {
    pub fn new_open() -> Self {
        Self {
            policy: RewardPolicy::v1_open(),
            operators: BTreeMap::new(),
            miner_pool_sats: 0,
            accrued_profit_sats: 0,
            crypto_suite_id_pq: "ml-dsa-65-placeholder".into(),
        }
    }

    pub fn upsert_operator(&mut self, op: MinerOperator) -> Result<(), DomainError> {
        if op.payout_destination.contains("..")
            || op.payout_destination.contains('/')
            || op.payout_destination.contains('\\')
        {
            return Err(DomainError::InvalidIntent(
                "miner payout destination illegal".into(),
            ));
        }
        self.operators
            .insert(op.node_id.as_str().to_string(), op);
        Ok(())
    }

    pub fn eligible_active(&self) -> Vec<&MinerOperator> {
        self.operators
            .values()
            .filter(|o| o.is_eligible(&self.policy))
            .collect()
    }

    /// Accrue `p_reward_bps` of profit into the MINERS pool. Waiting set does not dilute.
    pub fn accrue_from_profit(&mut self, profit_sats: u64, p_reward_bps: u32) -> u64 {
        let miners = profit_sats.saturating_mul(p_reward_bps as u64) / 10_000;
        self.miner_pool_sats = self.miner_pool_sats.saturating_add(miners);
        self.accrued_profit_sats = self.accrued_profit_sats.saturating_add(profit_sats);
        miners
    }

    /// Equal split of `amount` among eligible active miners (bank will issue Intents).
    pub fn propose_equal_payouts(&self, amount: u64) -> Result<Vec<MinerPayoutShare>, DomainError> {
        let eligible = self.eligible_active();
        if eligible.is_empty() {
            return Err(DomainError::NoEligibleMiners);
        }
        if amount == 0 || amount > self.miner_pool_sats {
            return Err(DomainError::InsufficientMinerPool {
                have: self.miner_pool_sats,
                want: amount,
            });
        }
        let n = eligible.len() as u64;
        let each = amount / n;
        let mut rem = amount - each * n;
        let mut out = Vec::with_capacity(eligible.len());
        for op in eligible {
            let mut share = each;
            if rem > 0 {
                share += 1;
                rem -= 1;
            }
            out.push(MinerPayoutShare {
                node_id: op.node_id.clone(),
                destination: op.payout_destination.clone(),
                amount_sats: share,
            });
        }
        Ok(out)
    }

    pub fn debit_pool(&mut self, amount: u64) -> Result<(), DomainError> {
        if amount > self.miner_pool_sats {
            return Err(DomainError::InsufficientMinerPool {
                have: self.miner_pool_sats,
                want: amount,
            });
        }
        self.miner_pool_sats -= amount;
        Ok(())
    }

    /// Survivability note: losing one vault must not unlock USERS omnibus or full key.
    pub fn survivability_ok(&self, online_vaults: usize, signing_t: usize) -> bool {
        // Bank ledger survives independently; cofre only fails closed when online < t.
        online_vaults >= signing_t || online_vaults == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinerPayoutShare {
    pub node_id: NodeId,
    pub destination: String,
    pub amount_sats: u64,
}

impl MinerPayoutShare {
    pub fn to_intent(
        &self,
        intent_id: impl Into<String>,
        policy_hash: impl Into<String>,
    ) -> Result<SettlementIntent, DomainError> {
        SettlementIntent::new(
            intent_id,
            BucketKind::Miners,
            self.destination.clone(),
            self.amount_sats,
            policy_hash,
        )
    }
}

/// Reject vault self-payment: payout destination must match registered operator, not invented.
pub fn assert_bank_issued_miner_payout(
    economy: &EconomyState,
    intent: &SettlementIntent,
) -> Result<(), DomainError> {
    if intent.bucket != BucketKind::Miners {
        return Ok(());
    }
    let matched = economy.operators.values().any(|op| {
        op.is_eligible(&economy.policy) && op.payout_destination == intent.destination
    });
    if !matched {
        return Err(DomainError::MinerSelfPayForbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiting_miner_not_eligible() {
        let policy = RewardPolicy::v1_open();
        let op = MinerOperator {
            node_id: NodeId::new("m1").unwrap(),
            payout_destination: "bc1q-miner-payout".into(),
            uptime_bps_30d: 9_900,
            attestation_streak_days: 10,
            bond_sats: 0,
            waiting: true,
        };
        assert!(!op.is_eligible(&policy));
    }

    #[test]
    fn accrue_one_percent() {
        let mut eco = EconomyState::new_open();
        let got = eco.accrue_from_profit(1_000_000, 100);
        assert_eq!(got, 10_000);
        assert_eq!(eco.miner_pool_sats, 10_000);
    }
}
