use std::sync::Arc;

use crate::application::ports::{BucketLedgerPort, LedgerPort};
use crate::domain::{
    evaluate_intent, BucketKind, DomainError, SettlementIntent,
};

pub struct GateIntent {
    buckets: Arc<dyn BucketLedgerPort>,
    ledger: Arc<dyn LedgerPort>,
}

impl GateIntent {
    pub fn new(buckets: Arc<dyn BucketLedgerPort>, ledger: Arc<dyn LedgerPort>) -> Self {
        Self { buckets, ledger }
    }

    /// Evaluate + consume intent id (replay-safe). Does not sign.
    pub fn execute(&self, intent: SettlementIntent) -> Result<GateReceipt, DomainError> {
        if self.buckets.is_consumed(&intent.intent_id)? {
            return Err(DomainError::IntentReplay(intent.intent_id));
        }
        let constitution = self.ledger.constitution()?;
        let policy = self.buckets.policy(intent.bucket)?;
        let spent = self.buckets.spent_today(intent.bucket)?;
        evaluate_intent(&intent, &policy, spent, &constitution.hash)?;
        self.buckets.record_spend(intent.bucket, intent.amount_sats)?;
        self.buckets.mark_consumed(&intent.intent_id)?;
        Ok(GateReceipt {
            intent_id: intent.intent_id,
            bucket: intent.bucket,
            amount_sats: intent.amount_sats,
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
