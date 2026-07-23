use std::sync::Arc;

use crate::application::ports::{BucketLedgerPort, EconomyPort, LedgerPort};
use crate::domain::{
    assert_bank_issued_miner_payout, evaluate_intent, BucketKind, DomainError, SettlementIntent,
};

pub struct GateIntent {
    buckets: Arc<dyn BucketLedgerPort>,
    ledger: Arc<dyn LedgerPort>,
    economy: Arc<dyn EconomyPort>,
}

impl GateIntent {
    pub fn new(
        buckets: Arc<dyn BucketLedgerPort>,
        ledger: Arc<dyn LedgerPort>,
        economy: Arc<dyn EconomyPort>,
    ) -> Self {
        Self {
            buckets,
            ledger,
            economy,
        }
    }

    /// Evaluate + consume intent id (atomic + durable when backed by persisted ledger).
    /// Does not sign.
    pub fn execute(&self, intent: SettlementIntent) -> Result<GateReceipt, DomainError> {
        let constitution = self.ledger.constitution()?;
        let miners_open =
            constitution.profit_splits.miners_bps > 0 && intent.bucket == BucketKind::Miners;
        if miners_open {
            assert_bank_issued_miner_payout(&self.economy.snapshot()?, &intent)?;
        }
        let policy_hash = constitution.hash.clone();
        let intent_id = intent.intent_id.clone();
        let bucket = intent.bucket;
        let amount_sats = intent.amount_sats;

        self.buckets.authorize_spend_and_consume(
            &intent_id,
            bucket,
            amount_sats,
            &|policy, spent| {
                let mut policy = policy.clone();
                // F9: open MINERS — destination must be an eligible registered operator
                // (bank Intent; vaults never invent self-pay). Admit registered dest for check.
                if miners_open {
                    policy
                        .destination_allowlist
                        .insert(intent.destination.clone());
                }
                evaluate_intent(&intent, &policy, spent, &policy_hash)
            },
        )?;
        Ok(GateReceipt {
            intent_id,
            bucket,
            amount_sats,
            status: "ACCEPTED",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateReceipt {
    pub intent_id: String,
    pub bucket: BucketKind,
    pub amount_sats: u64,
    pub status: &'static str,
}

impl GateReceipt {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"intent_id":"{}","bucket":"{}","amount_sats":{},"status":"{}"}}"#,
            self.intent_id,
            self.bucket.as_str(),
            self.amount_sats,
            self.status
        )
    }
}

pub struct AllocateProfit {
    ledger: Arc<dyn LedgerPort>,
}

impl AllocateProfit {
    pub fn new(ledger: Arc<dyn LedgerPort>) -> Self {
        Self { ledger }
    }

    pub fn execute(&self, profit_sats: u64) -> Result<ProfitAllocation, DomainError> {
        let constitution = self.ledger.constitution()?;
        let (miners, channels, infra) = constitution.profit_splits.allocate(profit_sats);
        Ok(ProfitAllocation {
            profit_sats,
            miners_sats: miners,
            channels_sats: channels,
            infra_sats: infra,
            dry_run_miners: constitution.profit_splits.miners_bps == 0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfitAllocation {
    pub profit_sats: u64,
    pub miners_sats: u64,
    pub channels_sats: u64,
    pub infra_sats: u64,
    pub dry_run_miners: bool,
}

impl ProfitAllocation {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"profit_sats":{},"miners_sats":{},"channels_sats":{},"infra_sats":{},"dry_run_miners":{}}}"#,
            self.profit_sats,
            self.miners_sats,
            self.channels_sats,
            self.infra_sats,
            self.dry_run_miners
        )
    }
}
