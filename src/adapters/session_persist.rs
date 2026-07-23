//! Persistent anti-nonce session ledger (local + best-effort replication).

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
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
            load_ids_into(&path, &mut set)?;
        }
        Ok(Self {
            path,
            inner: Mutex::new(set),
        })
    }

    fn append_id(&self, session_id: &str) -> Result<(), DomainError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| DomainError::ThresholdError(format!("anti-nonce append: {e}")))?;
        writeln!(file, "{session_id}")
            .map_err(|e| DomainError::ThresholdError(format!("anti-nonce write: {e}")))?;
        file.sync_all()
            .map_err(|e| DomainError::ThresholdError(format!("anti-nonce sync: {e}")))?;
        Ok(())
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
        self.append_id(session_id)?;
        g.insert(session_id.to_string());
        Ok(())
    }

    fn is_consumed(&self, session_id: &str) -> Result<bool, DomainError> {
        let g = self.inner.lock().expect("anti-nonce");
        Ok(g.contains(session_id))
    }

    fn observe_remote(&self, session_id: &str) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("anti-nonce");
        if g.contains(session_id) {
            return Ok(());
        }
        self.append_id(session_id)?;
        g.insert(session_id.to_string());
        Ok(())
    }
}

/// Best-effort replicated anti-nonce: local log + shared lab volume (+ optional peer gossip).
///
/// Not a consensus log — peers may race; goal is to reduce cross-node `session_id` reuse
/// in lab/staging before a stronger gossip ledger lands.
pub struct ReplicatedAntiNonce {
    local: PersistedAntiNonce,
    shared_dir: Option<PathBuf>,
    node_id: String,
    peer_ingest_urls: Vec<String>,
    auth_token: String,
}

impl ReplicatedAntiNonce {
    pub fn open(
        local_path: impl Into<PathBuf>,
        shared_dir: Option<PathBuf>,
        node_id: impl Into<String>,
        peer_ingest_urls: Vec<String>,
        auth_token: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let node_id = node_id.into();
        if let Some(dir) = shared_dir.as_ref() {
            fs::create_dir_all(dir).map_err(|e| {
                DomainError::ThresholdError(format!("anti-nonce shared mkdir: {e}"))
            })?;
        }
        let local = PersistedAntiNonce::open(local_path)?;
        let this = Self {
            local,
            shared_dir,
            node_id,
            peer_ingest_urls,
            auth_token: auth_token.into(),
        };
        this.reload_shared()?;
        Ok(this)
    }

    fn shared_path(&self) -> Option<PathBuf> {
        self.shared_dir
            .as_ref()
            .map(|d| d.join(format!("used-{}.log", self.node_id)))
    }

    fn reload_shared(&self) -> Result<(), DomainError> {
        let Some(dir) = self.shared_dir.as_ref() else {
            return Ok(());
        };
        if !dir.exists() {
            return Ok(());
        }
        let mut g = self.local.inner.lock().expect("anti-nonce");
        for entry in fs::read_dir(dir).map_err(|e| {
            DomainError::ThresholdError(format!("anti-nonce shared read_dir: {e}"))
        })? {
            let entry = entry.map_err(|e| {
                DomainError::ThresholdError(format!("anti-nonce shared entry: {e}"))
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("log") {
                continue;
            }
            load_ids_into(&path, &mut g)?;
        }
        Ok(())
    }

    fn append_shared(&self, session_id: &str) -> Result<(), DomainError> {
        let Some(path) = self.shared_path() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                DomainError::ThresholdError(format!("anti-nonce shared mkdir: {e}"))
            })?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| DomainError::ThresholdError(format!("anti-nonce shared append: {e}")))?;
        writeln!(file, "{session_id}")
            .map_err(|e| DomainError::ThresholdError(format!("anti-nonce shared write: {e}")))?;
        let _ = file.sync_all();
        Ok(())
    }

    fn gossip_best_effort(&self, session_id: &str) {
        if self.peer_ingest_urls.is_empty() {
            return;
        }
        let body = format!(r#"{{"session_id":"{session_id}"}}"#);
        let token = self.auth_token.clone();
        let urls = self.peer_ingest_urls.clone();
        // Detached best-effort; failures must not block local claim.
        std::thread::spawn(move || {
            for url in urls {
                let client = match reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_millis(800))
                    .build()
                {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let _ = client
                    .post(&url)
                    .header("X-Vault-Token", &token)
                    .header("Content-Type", "application/json")
                    .body(body.clone())
                    .send();
            }
        });
    }
}

impl AntiNoncePort for ReplicatedAntiNonce {
    fn claim_session(&self, session_id: &str) -> Result<(), DomainError> {
        let _ = self.reload_shared();
        self.local.claim_session(session_id)?;
        let _ = self.append_shared(session_id);
        self.gossip_best_effort(session_id);
        Ok(())
    }

    fn is_consumed(&self, session_id: &str) -> Result<bool, DomainError> {
        let _ = self.reload_shared();
        self.local.is_consumed(session_id)
    }

    fn observe_remote(&self, session_id: &str) -> Result<(), DomainError> {
        self.local.observe_remote(session_id)?;
        let _ = self.append_shared(session_id);
        Ok(())
    }
}

fn load_ids_into(path: &Path, set: &mut HashSet<String>) -> Result<(), DomainError> {
    let file = fs::File::open(path).map_err(|e| {
        DomainError::ThresholdError(format!("anti-nonce open {}: {e}", path.display()))
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "kv-anti-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn shared_volume_propagates_session_ids() {
        let tmp = TempDir::new("shared");
        let shared = tmp.0.join("shared");
        let a = ReplicatedAntiNonce::open(
            tmp.0.join("a.log"),
            Some(shared.clone()),
            "vault-1",
            vec![],
            "tok",
        )
        .unwrap();
        a.claim_session("sess-shared-1").unwrap();

        let b = ReplicatedAntiNonce::open(
            tmp.0.join("b.log"),
            Some(shared),
            "vault-2",
            vec![],
            "tok",
        )
        .unwrap();
        assert!(b.is_consumed("sess-shared-1").unwrap());
        assert!(matches!(
            b.claim_session("sess-shared-1"),
            Err(DomainError::NonceReuse(_))
        ));
    }
}
