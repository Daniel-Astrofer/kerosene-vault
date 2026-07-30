//! ML-DSA-65 identity implementation using ml-dsa crate.
//!
//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is the
//! FIPS 204 post-quantum signing standard. ML-DSA-65 targets NIST
//! security level 3 (AES-192 equivalent).

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::IdentityError;
use crate::VaultIdentity;

/// ML-DSA-65 identity keypair (post-quantum signing).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65Identity {
    /// Serialized secret key.
    secret_key: Vec<u8>,
    /// Serialized public key.
    public_key: Vec<u8>,
}

// ML-DSA-65 fixed sizes per FIPS 204
const ML_DSA_65_SECRET_KEY_LEN: usize = 4032;
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

impl MlDsa65Identity {
    /// Create from raw key material.
    pub fn from_raw(secret: &[u8], public: &[u8]) -> Result<Self, IdentityError> {
        if secret.len() != ML_DSA_65_SECRET_KEY_LEN {
            return Err(IdentityError::InvalidKeyMaterial(format!(
                "ML-DSA-65 secret key: expected {ML_DSA_65_SECRET_KEY_LEN} bytes, got {}",
                secret.len()
            )));
        }
        if public.len() != ML_DSA_65_PUBLIC_KEY_LEN {
            return Err(IdentityError::InvalidKeyMaterial(format!(
                "ML-DSA-65 public key: expected {ML_DSA_65_PUBLIC_KEY_LEN} bytes, got {}",
                public.len()
            )));
        }
        Ok(Self {
            secret_key: secret.to_vec(),
            public_key: public.to_vec(),
        })
    }
}

impl VaultIdentity for MlDsa65Identity {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type Signature = Vec<u8>;

    fn generate() -> Result<Self, IdentityError> {
        // Use ml-dsa crate for key generation
        let mut rng = rand::rngs::OsRng;
        let (secret, public) = ml_dsa::generate_keypair::<ml_dsa::MlDsa65>(&mut rng)
            .map_err(|e| IdentityError::KeyGenerationFailed(format!("ML-DSA-65 keygen: {e}")))?;

        Ok(Self {
            secret_key: secret.as_ref().to_vec(),
            public_key: public.as_ref().to_vec(),
        })
    }

    fn from_secret(secret: &Self::SecretKey) -> Result<Self, IdentityError> {
        if secret.len() != ML_DSA_65_SECRET_KEY_LEN {
            return Err(IdentityError::InvalidKeyMaterial(format!(
                "ML-DSA-65 from_secret: expected {ML_DSA_65_SECRET_KEY_LEN} bytes, got {}",
                secret.len()
            )));
        }
        // Recover public key from secret
        let (_, public) = ml_dsa::Keypair::from_secret(&ml_dsa::MlDsa65, secret)
            .map_err(|e| IdentityError::InvalidKeyMaterial(format!("ML-DSA-65 key recovery: {e}")))?;

        Ok(Self {
            secret_key: secret.clone(),
            public_key: public.as_ref().to_vec(),
        })
    }

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn secret_key(&self) -> &Self::SecretKey {
        &self.secret_key
    }

    fn sign(&self, message: &[u8]) -> Result<Self::Signature, IdentityError> {
        let mut rng = rand::rngs::OsRng;
        let signature = ml_dsa::sign(message, &self.secret_key, &mut rng)
            .map_err(|e| IdentityError::SigningFailed(format!("ML-DSA-65 sign: {e}")))?;
        Ok(signature)
    }

    fn verify(public: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> Result<bool, IdentityError> {
        if public.len() != ML_DSA_65_PUBLIC_KEY_LEN {
            return Err(IdentityError::InvalidKeyMaterial(format!(
                "ML-DSA-65 verify: expected {ML_DSA_65_PUBLIC_KEY_LEN} byte public key, got {}",
                public.len()
            )));
        }
        match ml_dsa::verify(message, signature, public) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.secret_key.len() + self.public_key.len());
        bytes.extend_from_slice(&self.secret_key);
        bytes.extend_from_slice(&self.public_key);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let expected = ML_DSA_65_SECRET_KEY_LEN + ML_DSA_65_PUBLIC_KEY_LEN;
        if bytes.len() < expected {
            return Err(IdentityError::InvalidKeyMaterial(format!(
                "ML-DSA-65 from_bytes: expected {expected} bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self {
            secret_key: bytes[..ML_DSA_65_SECRET_KEY_LEN].to_vec(),
            public_key: bytes[ML_DSA_65_SECRET_KEY_LEN..ML_DSA_65_SECRET_KEY_LEN + ML_DSA_65_PUBLIC_KEY_LEN].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VaultIdentity;

    fn is_zeroed(bytes: &[u8]) -> bool {
        bytes.iter().all(|&b| b == 0)
    }

    #[test]
    fn generate_ml_dsa_identity() {
        let id = MlDsa65Identity::generate().unwrap();
        assert_eq!(id.public_key.len(), ML_DSA_65_PUBLIC_KEY_LEN);
        assert_eq!(id.secret_key.len(), ML_DSA_65_SECRET_KEY_LEN);
        assert!(!is_zeroed(&id.public_key));
        assert!(!is_zeroed(&id.secret_key));
    }

    #[test]
    fn sign_and_verify_ml_dsa() {
        let id = MlDsa65Identity::generate().unwrap();
        let msg = b"hello vault identity (PQ secure)";
        let sig = id.sign(msg).unwrap();
        assert!(MlDsa65Identity::verify(&id.public_key, msg, &sig).unwrap());
        assert!(!MlDsa65Identity::verify(&id.public_key, b"wrong message", &sig).unwrap());
    }

    #[test]
    fn from_secret_roundtrip() {
        let id = MlDsa65Identity::generate().unwrap();
        let pk = id.public_key.clone();
        let restored = MlDsa65Identity::from_secret(&id.secret_key).unwrap();
        assert_eq!(restored.public_key, pk);
        let sig = restored.sign(b"from_secret roundtrip").unwrap();
        assert!(MlDsa65Identity::verify(&pk, b"from_secret roundtrip", &sig).unwrap());
    }

    #[test]
    fn to_from_bytes_roundtrip() {
        let id = MlDsa65Identity::generate().unwrap();
        let pk = id.public_key.clone();
        let bytes = id.to_bytes();
        let restored = MlDsa65Identity::from_bytes(&bytes).unwrap();
        assert_eq!(restored.public_key, pk);
    }

    #[test]
    fn from_raw_validates_sizes() {
        let id = MlDsa65Identity::generate().unwrap();
        let valid = MlDsa65Identity::from_raw(&id.secret_key, &id.public_key);
        assert!(valid.is_ok());
        let bad_secret = MlDsa65Identity::from_raw(&[0u8; 10], &id.public_key);
        assert!(bad_secret.is_err());
        let bad_public = MlDsa65Identity::from_raw(&id.secret_key, &[0u8; 10]);
        assert!(bad_public.is_err());
    }
}
