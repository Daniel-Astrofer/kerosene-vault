//! AEAD disk share store (domestic / lab). Argon2id + ChaCha20-Poly1305.
//!
//! # Honest tier note
//! Disk AEAD ≠ TEE. Domestic production may use this path; SEV/SGX nodes should use
//! `VAULT_SHARE_STORE=tee_seal` when a real enclave seal is available.
//!
//! # Optional TPM 2.0 seal (`VAULT_SHARE_TPM_SEAL=1`)
//! Off by default. When enabled, wiring seals the AEAD passphrase under a TPM-bound
//! envelope (see [`super::share_tpm`]) **before** constructing this store.
//! TPM ≠ SEV: disk-at-rest only; clear fallback is lab-only (`VAULT_SHARE_TPM_CLEAR_FALLBACK=1`).
//! See `VAULT_MESH_PLAN.md` §3.1.

use std::fs;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::application::ShareStorePort;
use crate::domain::DomainError;

pub struct AeadDiskShareStore {
    root: PathBuf,
    passphrase: SecretString,
    tpm_sealed_passphrase: bool,
}

impl AeadDiskShareStore {
    pub fn new(root: impl Into<PathBuf>, passphrase: impl Into<String>) -> Self {
        Self::with_tpm_seal(root, passphrase, false)
    }

    pub fn with_tpm_seal(
        root: impl Into<PathBuf>,
        passphrase: impl Into<String>,
        tpm_sealed_passphrase: bool,
    ) -> Self {
        Self {
            root: root.into(),
            passphrase: SecretString::from(passphrase.into()),
            tpm_sealed_passphrase,
        }
    }

    fn path_for(&self, share_id: &str) -> PathBuf {
        let id_hash = hex::encode(Sha256::digest(share_id.as_bytes()));
        self.root.join(format!("share-{id_hash}.bin"))
    }

    fn derive_key(&self, salt: &[u8; 16]) -> Result<[u8; 32], DomainError> {
        let params = Params::new(19_456, 2, 1, Some(32)).map_err(|e| {
            DomainError::ShareStoreForbidden(format!("argon2 params: {e}"))
        })?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(self.passphrase.expose_secret().as_bytes(), salt, &mut key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("argon2: {e}")))?;
        Ok(key)
    }
}

impl ShareStorePort for AeadDiskShareStore {
    fn store_kind(&self) -> &'static str {
        if self.tpm_sealed_passphrase { "aead_disk_tpm" } else { "aead_disk" }
    }

    fn put_share(&self, share_id: &str, plaintext: &[u8]) -> Result<(), DomainError> {
        fs::create_dir_all(&self.root).map_err(|e| {
            DomainError::ShareStoreForbidden(format!("mkdir: {e}"))
        })?;
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut key = self.derive_key(&salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("cipher: {e}")))?;
        key.zeroize();
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| DomainError::ShareStoreForbidden("encrypt failed".into()))?;
        let mut out = Vec::with_capacity(16 + 12 + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        atomic_write(&self.path_for(share_id), &out)
    }

    fn get_share(&self, share_id: &str) -> Result<Vec<u8>, DomainError> {
        let bytes = fs::read(&self.path_for(share_id)).map_err(|e| {
            DomainError::ShareStoreForbidden(format!("read share: {e}"))
        })?;
        if bytes.len() < 16 + 12 + 16 {
            return Err(DomainError::ShareStoreForbidden("share blob too short".into()));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[..16]);
        let nonce_bytes = &bytes[16..28];
        let ciphertext = &bytes[28..];
        let mut key = self.derive_key(&salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("cipher: {e}")))?;
        key.zeroize();
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| DomainError::ShareStoreForbidden("decrypt failed".into()))
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), DomainError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data).map_err(|e| DomainError::ShareStoreForbidden(format!("write: {e}")))?;
    fs::rename(&tmp, path).map_err(|e| DomainError::ShareStoreForbidden(format!("rename: {e}")))?;
    Ok(())
}
