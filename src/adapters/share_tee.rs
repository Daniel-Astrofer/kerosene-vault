//! TEE seal share store — fail-closed until Production Gate enclave sealing.

use crate::application::ShareStorePort;
use crate::domain::DomainError;

pub struct TeeSealShareStore;

impl TeeSealShareStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TeeSealShareStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ShareStorePort for TeeSealShareStore {
    fn store_kind(&self) -> &'static str {
        "tee_seal"
    }

    fn put_share(&self, _share_id: &str, _plaintext: &[u8]) -> Result<(), DomainError> {
        Err(DomainError::TeeRequired(
            "TEE seal path not available; host disk AEAD is lab-only".into(),
        ))
    }

    fn get_share(&self, _share_id: &str) -> Result<Vec<u8>, DomainError> {
        Err(DomainError::TeeRequired(
            "TEE unseal path not available; host disk AEAD is lab-only".into(),
        ))
    }
}
