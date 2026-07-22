use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use crate::application::ports::{BlobStorePort, ReleaseStorePort};
use crate::domain::{AllowlistEntry, ContentHash, DomainError, ReleaseCandidate, ReleasePolicy};

/// Lab content-addressed blob + release/allowlist store.
pub struct InMemoryReleaseMesh {
    inner: Mutex<ReleaseMeshState>,
}

struct ReleaseMeshState {
    policy: ReleasePolicy,
    blobs: HashMap<String, Vec<u8>>,
    candidates: BTreeMap<String, ReleaseCandidate>,
    allowlist: Vec<AllowlistEntry>,
}

impl InMemoryReleaseMesh {
    pub fn new(policy: ReleasePolicy) -> Self {
        Self {
            inner: Mutex::new(ReleaseMeshState {
                policy,
                blobs: HashMap::new(),
                candidates: BTreeMap::new(),
                allowlist: Vec::new(),
            }),
        }
    }
}

impl BlobStorePort for InMemoryReleaseMesh {
    fn put(&self, hash: &ContentHash, bytes: &[u8]) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("release mesh lock");
        g.blobs.insert(hash.as_str().to_string(), bytes.to_vec());
        Ok(())
    }

    fn get(&self, hash: &ContentHash) -> Result<Vec<u8>, DomainError> {
        let g = self.inner.lock().expect("release mesh lock");
        g.blobs
            .get(hash.as_str())
            .cloned()
            .ok_or_else(|| DomainError::UnknownBlob(hash.as_str().to_string()))
    }
}

impl ReleaseStorePort for InMemoryReleaseMesh {
    fn policy(&self) -> Result<ReleasePolicy, DomainError> {
        Ok(self.inner.lock().expect("release mesh lock").policy.clone())
    }

    fn put_candidate(&self, candidate: ReleaseCandidate) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("release mesh lock");
        if g.candidates.contains_key(&candidate.id) {
            return Err(DomainError::InvalidRelease(format!(
                "release already exists: {}",
                candidate.id
            )));
        }
        g.candidates.insert(candidate.id.clone(), candidate);
        Ok(())
    }

    fn get_candidate(&self, id: &str) -> Result<ReleaseCandidate, DomainError> {
        let g = self.inner.lock().expect("release mesh lock");
        g.candidates
            .get(id)
            .cloned()
            .ok_or_else(|| DomainError::UnknownRelease(id.to_string()))
    }

    fn save_candidate(&self, candidate: ReleaseCandidate) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("release mesh lock");
        if !g.candidates.contains_key(&candidate.id) {
            return Err(DomainError::UnknownRelease(candidate.id));
        }
        g.candidates.insert(candidate.id.clone(), candidate);
        Ok(())
    }

    fn put_allowlist(&self, entry: AllowlistEntry) -> Result<(), DomainError> {
        let mut g = self.inner.lock().expect("release mesh lock");
        g.allowlist.retain(|e| e.release_id != entry.release_id);
        g.allowlist.push(entry);
        Ok(())
    }

    fn allowlist(&self) -> Result<Vec<AllowlistEntry>, DomainError> {
        Ok(self
            .inner
            .lock()
            .expect("release mesh lock")
            .allowlist
            .clone())
    }

    fn is_allowlisted_hb(&self, hb: &ContentHash) -> Result<bool, DomainError> {
        let g = self.inner.lock().expect("release mesh lock");
        Ok(g.allowlist.iter().any(|e| e.hb == *hb))
    }
}
