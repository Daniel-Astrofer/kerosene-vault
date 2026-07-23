//! Daily rotation: quorum-gated day_epoch advance + reshare hook (Gate).
//!
//! Lab may still bind signing to the active day. Calendar ahead of the ledger day
//! without a quorum `advance` → stale rejection (no silent auto-roll).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::application::{ClockPort, DailyRotationPort, ReshareHookPort};
use crate::domain::{DayEpoch, DomainError};

/// No-op reshare hook (tests / until real reshare policy lands).
pub struct NoopReshareHook;

impl ReshareHookPort for NoopReshareHook {
    fn on_day_advance(&self, _from: &DayEpoch, _to: &DayEpoch) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Records day advances for tests / lab observability.
pub struct RecordingReshareHook {
    pub advances: Mutex<Vec<(String, String)>>,
}

impl RecordingReshareHook {
    pub fn new() -> Self {
        Self {
            advances: Mutex::new(Vec::new()),
        }
    }
}

impl Default for RecordingReshareHook {
    fn default() -> Self {
        Self::new()
    }
}

impl ReshareHookPort for RecordingReshareHook {
    fn on_day_advance(&self, from: &DayEpoch, to: &DayEpoch) -> Result<(), DomainError> {
        self.advances
            .lock()
            .expect("reshare log")
            .push((from.as_str().to_string(), to.as_str().to_string()));
        Ok(())
    }
}

/// Quorum-gated daily rotation (Gate path beyond the pure calendar stub).
pub struct QuorumDailyRotation {
    clock: Arc<dyn ClockPort>,
    current: Mutex<DayEpoch>,
    votes: Mutex<HashMap<String, DayEpoch>>,
    quorum_t: usize,
    local_voter: String,
    reshare: Arc<dyn ReshareHookPort>,
}

impl QuorumDailyRotation {
    pub fn new(
        clock: Arc<dyn ClockPort>,
        quorum_t: usize,
        local_voter: impl Into<String>,
        reshare: Arc<dyn ReshareHookPort>,
    ) -> Self {
        let current = DayEpoch::from_unix_secs(clock.unix_now_secs());
        Self {
            clock,
            current: Mutex::new(current),
            votes: Mutex::new(HashMap::new()),
            quorum_t: quorum_t.max(1),
            local_voter: local_voter.into(),
            reshare,
        }
    }
}

impl DailyRotationPort for QuorumDailyRotation {
    fn current_day_epoch(&self) -> Result<DayEpoch, DomainError> {
        let live = DayEpoch::from_unix_secs(self.clock.unix_now_secs());
        let g = self.current.lock().expect("day_epoch");
        if live > *g {
            return Err(DomainError::DayEpochStale {
                have: g.as_str().to_string(),
                need: live.as_str().to_string(),
            });
        }
        Ok(g.clone())
    }

    fn record_vote(&self, voter: &str, target: &DayEpoch) -> Result<(), DomainError> {
        let mut votes = self.votes.lock().expect("day votes");
        votes.insert(voter.to_string(), target.clone());
        Ok(())
    }

    fn advance(&self) -> Result<DayEpoch, DomainError> {
        let live = DayEpoch::from_unix_secs(self.clock.unix_now_secs());
        self.record_vote(&self.local_voter, &live)?;

        let have = {
            let votes = self.votes.lock().expect("day votes");
            votes.values().filter(|e| *e == &live).count()
        };
        if have < self.quorum_t {
            return Err(DomainError::QuorumNotMet {
                have,
                need: self.quorum_t,
            });
        }

        let mut g = self.current.lock().expect("day_epoch");
        let from = g.clone();
        if live == from {
            return Ok(from);
        }
        if live < from {
            return Err(DomainError::DayEpochStale {
                have: live.as_str().to_string(),
                need: from.as_str().to_string(),
            });
        }
        *g = live.clone();
        drop(g);
        self.reshare.on_day_advance(&from, &live)?;
        Ok(live)
    }

    fn require_epoch(&self, bound: &DayEpoch) -> Result<(), DomainError> {
        let cur = {
            let g = self.current.lock().expect("day_epoch");
            g.clone()
        };
        if bound != &cur {
            return Err(DomainError::DayEpochStale {
                have: bound.as_str().to_string(),
                need: cur.as_str().to_string(),
            });
        }
        // Also reject if calendar has moved past the ledger day (stale session window).
        let live = DayEpoch::from_unix_secs(self.clock.unix_now_secs());
        if live > cur {
            return Err(DomainError::DayEpochStale {
                have: cur.as_str().to_string(),
                need: live.as_str().to_string(),
            });
        }
        Ok(())
    }
}

/// Backward-compatible name: quorum rotation with t=1 (local self-vote advances).
pub struct LedgerDayEpochStub {
    inner: QuorumDailyRotation,
}

impl LedgerDayEpochStub {
    pub fn new(clock: Arc<dyn ClockPort>) -> Self {
        Self {
            inner: QuorumDailyRotation::new(clock, 1, "local", Arc::new(NoopReshareHook)),
        }
    }

    pub fn with_reshare(clock: Arc<dyn ClockPort>, reshare: Arc<dyn ReshareHookPort>) -> Self {
        Self {
            inner: QuorumDailyRotation::new(clock, 1, "local", reshare),
        }
    }
}

impl DailyRotationPort for LedgerDayEpochStub {
    fn current_day_epoch(&self) -> Result<DayEpoch, DomainError> {
        self.inner.current_day_epoch()
    }

    fn advance(&self) -> Result<DayEpoch, DomainError> {
        self.inner.advance()
    }

    fn require_epoch(&self, bound: &DayEpoch) -> Result<(), DomainError> {
        self.inner.require_epoch(bound)
    }

    fn record_vote(&self, voter: &str, target: &DayEpoch) -> Result<(), DomainError> {
        self.inner.record_vote(voter, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ClockPort;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FakeClock(AtomicU64);
    impl ClockPort for FakeClock {
        fn unix_now_secs(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn quorum_advance_invokes_reshare_and_rejects_stale() {
        // 2024-01-01 00:00 UTC
        let clock = Arc::new(FakeClock(AtomicU64::new(1_704_067_200)));
        let hook = Arc::new(RecordingReshareHook::new());
        let rot = QuorumDailyRotation::new(clock.clone(), 2, "v1", hook.clone());

        assert_eq!(rot.current_day_epoch().unwrap().as_str(), "2024-01-01");

        // Roll calendar to next day without advance → stale.
        clock.0.store(1_704_067_200 + 86_400, Ordering::SeqCst);
        assert!(matches!(
            rot.current_day_epoch(),
            Err(DomainError::DayEpochStale { .. })
        ));

        // One vote insufficient.
        assert!(matches!(
            rot.advance(),
            Err(DomainError::QuorumNotMet { have: 1, need: 2 })
        ));

        rot.record_vote("v2", &DayEpoch::from_unix_secs(1_704_067_200 + 86_400))
            .unwrap();
        let next = rot.advance().unwrap();
        assert_eq!(next.as_str(), "2024-01-02");
        assert_eq!(rot.current_day_epoch().unwrap().as_str(), "2024-01-02");

        let log = hook.advances.lock().unwrap().clone();
        assert_eq!(log, vec![("2024-01-01".into(), "2024-01-02".into())]);

        // Stale bound rejected.
        let stale = DayEpoch::parse("2024-01-01").unwrap();
        assert!(matches!(
            rot.require_epoch(&stale),
            Err(DomainError::DayEpochStale { .. })
        ));
    }
}
