use std::sync::Arc;

use crate::adapters::ThresholdVaultState;
use crate::domain::{CombinedSignature, DomainError, SigningSession};

/// Reports how many vaults are considered online for fail-stop checks.
pub trait OnlineStatusPort: Send + Sync {
    fn online_count(&self) -> usize;
}

pub struct SignMessage {
    threshold: Arc<ThresholdVaultState>,
    online: Arc<dyn OnlineStatusPort>,
}

impl SignMessage {
    pub fn new(threshold: Arc<ThresholdVaultState>, online: Arc<dyn OnlineStatusPort>) -> Self {
        Self { threshold, online }
    }

    pub fn begin(&self, session_id: &str, message_hash: &str) -> Result<SigningSession, DomainError> {
        self.threshold.begin_session(session_id, message_hash, self.online.online_count())
    }

    pub fn run_lab_quorum_sign(&self, session_id: &str, message_hash: &str) -> Result<CombinedSignature, DomainError> {
        let online = self.online.online_count();
        self.threshold.begin_session(session_id, message_hash, online)?;
        self.threshold.lab_collect_partials_from_all(session_id, online)?;
        self.threshold.combine(session_id, online)
    }
}

pub struct StaticOnlineCount {
    pub count: usize,
}

impl OnlineStatusPort for StaticOnlineCount {
    fn online_count(&self) -> usize {
        self.count
    }
}

/// Lab partition / fail-stop harness: online count can change at runtime.
pub struct MutableOnlineCount {
    count: std::sync::Mutex<usize>,
}

impl MutableOnlineCount {
    pub fn new(count: usize) -> Self {
        Self { count: std::sync::Mutex::new(count) }
    }

    pub fn set(&self, count: usize) {
        *self.count.lock().expect("online lock") = count;
    }
}

impl OnlineStatusPort for MutableOnlineCount {
    fn online_count(&self) -> usize {
        *self.count.lock().expect("online lock")
    }
}
