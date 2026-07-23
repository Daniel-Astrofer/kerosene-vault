//! Persistent anti-nonce session ledger (survives restart).

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::application::AntiNoncePort;
use crate::domain::DomainError;

pub struct PersistedAntiNonce {
    path: PathBuf,
    inner: Mutex<HashSet<String>>,
}

impl PersistedAntiNonce {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DomainError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                DomainError::ThresholdError(format!("anti-nonce mkdir: {e}"))
            })?;
        }
        let mut set = HashSet::new();
        if path.exists() {
            let file = fs::File::open(&path).map_err(|e| {
                DomainError::ThresholdError(format!("anti-nonce open: {e}"))
            })?;
            for line in BufReader::new(file).lines() {
                let line = line.map_err(|e| {
                    DomainError::ThresholdError(format!("anti-nonce read: {e}"))
                })?;
                let id = line.trim();
                if !id.is_empty() {
                    set.insert(id.to_string());
                }
            }
        }
        Ok(Self {
            path,
            inner: Mutex::new(set),
        })
    }
}

impl AntiNoncePort for PersistedAntiNonce {
    fn claim_session(&self, session_id: &str) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("anti-nonce");
        if g.contains(session_id) {
            return Err(DomainError::NonceReuse(format!(
                "session_id already used: {session_id}"
            )));
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| DomainError::ThresholdError(format!("anti-nonce append: {e}")))?;
        writeln!(file, "{session_id}")
            .map_err(|e| DomainError::ThresholdError(format!("anti-nonce write: {e}")))?;
        file.sync_all()
            .map_err(|e| DomainError::ThresholdError(format!("anti-nonce sync: {e}")))?;
        g.insert(session_id.to_string());
        Ok(())
    }

    fn is_consumed(&self, session_id: &str) -> Result<bool, DomainError> {
        let g = self.inner.lock().expect("anti-nonce");
        Ok(g.contains(session_id))
    }
}
