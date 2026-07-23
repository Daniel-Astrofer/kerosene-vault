//! Daily rotation stub: bind signing to UTC day_epoch (full reshare = Gate).

use std::sync::{Arc, Mutex};

use crate::application::{ClockPort, DailyRotationPort};
use crate::domain::{DayEpoch, DomainError};

pub struct LedgerDayEpochStub {
    clock: Arc<dyn ClockPort>,
    current: Mutex<DayEpoch>,
}

impl LedgerDayEpochStub {
    pub fn new(clock: Arc<dyn ClockPort>) -> Self {
        let current = DayEpoch::from_unix_secs(clock.unix_now_secs());
        Self {
            clock,
            current: Mutex::new(current),
        }
    }
}

impl DailyRotationPort for LedgerDayEpochStub {
    fn current_day_epoch(&self) -> Result<DayEpoch, DomainError> {
        let live = DayEpoch::from_unix_secs(self.clock.unix_now_secs());
        let mut g = self.current.lock().expect("day_epoch");
        if live > *g {
            // Auto-observe calendar rollover; advance still required for explicit quorum stub.
            *g = live.clone();
        }
        Ok(g.clone())
    }

    fn advance(&self) -> Result<DayEpoch, DomainError> {
        let live = DayEpoch::from_unix_secs(self.clock.unix_now_secs());
        let mut g = self.current.lock().expect("day_epoch");
        *g = live.clone();
        Ok(live)
    }

    fn require_epoch(&self, bound: &DayEpoch) -> Result<(), DomainError> {
        let cur = self.current_day_epoch()?;
        if bound != &cur {
            return Err(DomainError::DayEpochStale {
                have: bound.as_str().to_string(),
                need: cur.as_str().to_string(),
            });
        }
        Ok(())
    }
}
