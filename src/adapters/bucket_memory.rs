use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::application::ports::BucketLedgerPort;
use crate::domain::{BucketKind, BucketPolicy, DomainError};

/// In-memory per-bucket spend + policies (lab).
pub struct InMemoryBucketLedger {
    inner: Mutex<BucketState>,
}

struct BucketState {
    policies: HashMap<BucketKind, BucketPolicy>,
    spent_today: HashMap<BucketKind, u64>,
    consumed: HashSet<String>,
}

impl InMemoryBucketLedger {
    pub fn from_constitution_caps(max_tx: u64, max_day: u64) -> Self {
        let mut policies = HashMap::new();
        for kind in [
            BucketKind::Users,
            BucketKind::Profit,
            BucketKind::Miners,
            BucketKind::Channels,
            BucketKind::Infra,
        ] {
            let (tx, day) = match kind {
                BucketKind::Users => (max_tx, max_day),
                BucketKind::Profit => (max_tx, max_day),
                BucketKind::Miners => (max_tx / 10, max_day / 10),
                BucketKind::Channels => (max_tx, max_day),
                BucketKind::Infra => (max_tx / 5, max_day / 5),
            };
            policies.insert(kind, BucketPolicy::lab_defaults(kind, tx.max(1), day.max(1)));
        }
        Self {
            inner: Mutex::new(BucketState {
                policies,
                spent_today: HashMap::new(),
                consumed: HashSet::new(),
            }),
        }
    }
}

impl BucketLedgerPort for InMemoryBucketLedger {
    fn policy(&self, kind: BucketKind) -> Result<BucketPolicy, DomainError> {
        let g = self.inner.lock().expect("bucket lock");
        g.policies
            .get(&kind)
            .cloned()
            .ok_or_else(|| DomainError::InvalidBucket(kind.as_str().into()))
    }

    fn spent_today(&self, kind: BucketKind) -> Result<u64, DomainError> {
        let g = self.inner.lock().expect("bucket lock");
        Ok(*g.spent_today.get(&kind).unwrap_or(&0))
    }

    fn record_spend(&self, kind: BucketKind, amount_sats: u64) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        let e = g.spent_today.entry(kind).or_insert(0);
        *e = e.saturating_add(amount_sats);
        Ok(())
    }

    fn is_consumed(&self, intent_id: &str) -> Result<bool, DomainError> {
        let g = self.inner.lock().expect("bucket lock");
        Ok(g.consumed.contains(intent_id))
    }

    fn mark_consumed(&self, intent_id: &str) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("bucket lock");
        g.consumed.insert(intent_id.to_string());
        Ok(())
    }
}
