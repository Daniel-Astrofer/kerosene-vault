//! AEAD disk share store (lab). Argon2id + ChaCha20-Poly1305. Disk ≠ TEE.

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
}

impl AeadDiskShareStore {
    pub fn new(root: impl Into<PathBuf>, passphrase: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            passphrase: SecretString::from(passphrase.into()),
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
        "aead_disk"
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
        let path = self.path_for(share_id);
        atomic_write(&path, &out)?;
        Ok(())
    }

    fn get_share(&self, share_id: &str) -> Result<Vec<u8>, DomainError> {
        let path = self.path_for(share_id);
        let bytes = fs::read(&path).map_err(|e| {
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
