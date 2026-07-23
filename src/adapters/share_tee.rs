//! TEE seal share store — versioned sealed envelope.
//!
//! - Staging / lab (`ATTESTATION_STAGING_STUB`): seal with measurement-bound AEAD envelope
//!   compatible with a future HW seal layout (`KVSEAL01`).
//! - Production / ceremonial without real TEE: fail-closed (no host-disk plaintext path).

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
use crate::domain::{DomainError, Measurement};

const MAGIC: &[u8; 8] = b"KVSEAL01";
const ENVELOPE_VERSION: u8 = 1;
const MODE_STAGING_STUB: u8 = 1;
const MODE_HW_PLACEHOLDER: u8 = 2;

/// Versioned TEE seal adapter (`ShareStorePort`).
///
/// Prefer this name in Gate docs; `TeeSealShareStore` remains a type alias.
pub struct TeeSealAdapter {
    root: PathBuf,
    /// When true, lab/staging may seal with stub-compatible envelope.
    staging_stub: bool,
    passphrase: Option<SecretString>,
    measurement: Measurement,
}

/// Historical name used in wiring / Gate table.
pub type TeeSealShareStore = TeeSealAdapter;

impl TeeSealAdapter {
    /// Production-style constructor: refuse seal/unseal until real TEE lands.
    pub fn fail_closed(measurement: Measurement) -> Self {
        Self {
            root: PathBuf::from("/dev/null"),
            staging_stub: false,
            passphrase: None,
            measurement,
        }
    }

    /// Staging-stub seal path (lab / `ATTESTATION_STAGING_STUB=1` only).
    pub fn staging_stub(
        root: impl Into<PathBuf>,
        passphrase: impl Into<String>,
        measurement: Measurement,
    ) -> Self {
        Self {
            root: root.into(),
            staging_stub: true,
            passphrase: Some(SecretString::from(passphrase.into())),
            measurement,
        }
    }

    pub fn new() -> Self {
        Self::fail_closed(Measurement::from_bytes(b"kerosene-vault-tee-unconfigured"))
    }

    fn path_for(&self, share_id: &str) -> PathBuf {
        let id_hash = hex::encode(Sha256::digest(share_id.as_bytes()));
        self.root.join(format!("tee-share-{id_hash}.seal"))
    }

    fn derive_key(&self, salt: &[u8; 16]) -> Result<[u8; 32], DomainError> {
        let pass = self.passphrase.as_ref().ok_or_else(|| {
            DomainError::TeeRequired("staging seal passphrase missing".into())
        })?;
        let params = Params::new(19_456, 2, 1, Some(32)).map_err(|e| {
            DomainError::ShareStoreForbidden(format!("argon2 params: {e}"))
        })?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        // Bind seal key to measurement so a wrong binary pin cannot open the envelope.
        let mut material = Vec::with_capacity(pass.expose_secret().len() + 64);
        material.extend_from_slice(pass.expose_secret().as_bytes());
        material.extend_from_slice(self.measurement.as_hex().as_bytes());
        let mut key = [0u8; 32];
        argon
            .hash_password_into(&material, salt, &mut key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("argon2: {e}")))?;
        material.zeroize();
        Ok(key)
    }

    fn seal_envelope(&self, plaintext: &[u8]) -> Result<Vec<u8>, DomainError> {
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
            .map_err(|_| DomainError::ShareStoreForbidden("tee stub encrypt failed".into()))?;

        let mut out = Vec::with_capacity(8 + 1 + 1 + 16 + 12 + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.push(ENVELOPE_VERSION);
        out.push(MODE_STAGING_STUB);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn unseal_envelope(&self, blob: &[u8]) -> Result<Vec<u8>, DomainError> {
        if blob.len() < 8 + 1 + 1 + 16 + 12 + 16 {
            return Err(DomainError::ShareStoreForbidden(
                "tee seal envelope too short".into(),
            ));
        }
        if &blob[..8] != MAGIC {
            return Err(DomainError::ShareStoreForbidden(
                "tee seal magic mismatch".into(),
            ));
        }
        let version = blob[8];
        if version != ENVELOPE_VERSION {
            return Err(DomainError::ShareStoreForbidden(format!(
                "unsupported tee seal version {version}"
            )));
        }
        let mode = blob[9];
        if mode == MODE_HW_PLACEHOLDER {
            return Err(DomainError::TeeRequired(
                "HW TEE unseal not available".into(),
            ));
        }
        if mode != MODE_STAGING_STUB {
            return Err(DomainError::ShareStoreForbidden(format!(
                "unknown tee seal mode {mode}"
            )));
        }
        if !self.staging_stub {
            return Err(DomainError::TeeRequired(
                "staging-stub envelope refused without ATTESTATION_STAGING_STUB".into(),
            ));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&blob[10..26]);
        let nonce_bytes = &blob[26..38];
        let ciphertext = &blob[38..];
        let mut key = self.derive_key(&salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| DomainError::ShareStoreForbidden(format!("cipher: {e}")))?;
        key.zeroize();
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| DomainError::ShareStoreForbidden("tee stub decrypt failed".into()))
    }
}

impl Default for TeeSealAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ShareStorePort for TeeSealAdapter {
    fn store_kind(&self) -> &'static str {
        if self.staging_stub {
            "tee_seal_staging_stub"
        } else {
            "tee_seal"
        }
    }

    fn put_share(&self, share_id: &str, plaintext: &[u8]) -> Result<(), DomainError> {
        if !self.staging_stub {
            return Err(DomainError::TeeRequired(
                "TEE seal path not available; host disk AEAD is lab-only (production fail-closed)"
                    .into(),
            ));
        }
        fs::create_dir_all(&self.root).map_err(|e| {
            DomainError::ShareStoreForbidden(format!("tee seal mkdir: {e}"))
        })?;
        let sealed = self.seal_envelope(plaintext)?;
        atomic_write(&self.path_for(share_id), &sealed)
    }

    fn get_share(&self, share_id: &str) -> Result<Vec<u8>, DomainError> {
        if !self.staging_stub {
            return Err(DomainError::TeeRequired(
                "TEE unseal path not available; host disk AEAD is lab-only (production fail-closed)"
                    .into(),
            ));
        }
        let bytes = fs::read(self.path_for(share_id)).map_err(|e| {
            DomainError::ShareStoreForbidden(format!("tee seal read: {e}"))
        })?;
        self.unseal_envelope(&bytes)
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), DomainError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data).map_err(|e| DomainError::ShareStoreForbidden(format!("write: {e}")))?;
    fs::rename(&tmp, path).map_err(|e| DomainError::ShareStoreForbidden(format!("rename: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "kv-tee-{name}-{}",
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
    fn staging_stub_roundtrip_envelope() {
        let tmp = TempDir::new("round");
        let m = Measurement::from_bytes(b"pin-v1");
        let store = TeeSealAdapter::staging_stub(&tmp.0, "lab-pass", m);
        store.put_share("s1", b"frost-share-bytes").unwrap();
        let got = store.get_share("s1").unwrap();
        assert_eq!(got, b"frost-share-bytes");
        let raw = std::fs::read(store.path_for("s1")).unwrap();
        assert_eq!(&raw[..8], MAGIC);
        assert_eq!(raw[8], ENVELOPE_VERSION);
        assert_eq!(raw[9], MODE_STAGING_STUB);
    }

    #[test]
    fn production_fail_closed_without_stub() {
        let store = TeeSealAdapter::fail_closed(Measurement::from_bytes(b"x"));
        assert!(matches!(
            store.put_share("s", b"x"),
            Err(DomainError::TeeRequired(_))
        ));
        assert!(matches!(
            store.get_share("s"),
            Err(DomainError::TeeRequired(_))
        ));
        assert_eq!(store.store_kind(), "tee_seal");
    }

    #[test]
    fn wrong_measurement_cannot_unseal() {
        let tmp = TempDir::new("meas");
        let a = TeeSealAdapter::staging_stub(
            &tmp.0,
            "lab-pass",
            Measurement::from_bytes(b"pin-a"),
        );
        a.put_share("s1", b"secret").unwrap();
        let b = TeeSealAdapter::staging_stub(
            &tmp.0,
            "lab-pass",
            Measurement::from_bytes(b"pin-b"),
        );
        assert!(b.get_share("s1").is_err());
    }
}
