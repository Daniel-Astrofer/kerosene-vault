//! FROST signing state machine.
//!
//! Manages the lifecycle of FROST signing operations including key material,
//! signing rounds, and quorum verification.

use std::collections::BTreeMap;

use frost_secp256k1::keys::KeyPackage;
use frost_secp256k1::round1::{SigningCommitments, SigningNonces};
use frost_secp256k1::round2::SignatureShare;
use frost_secp256k1::{self as frost, Identifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::session::{SessionId, SessionState};

/// Errors that can occur during FROST signing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    /// Not enough signing participants.
    InsufficientShares { have: usize, need: usize },
    /// Invalid key package.
    InvalidKeyPackage(String),
    /// Signing round error.
    RoundError(String),
    /// Session not found.
    SessionNotFound,
    /// Session already completed.
    SessionAlreadyCompleted,
    /// Duplicate commitment.
    DuplicateCommitment,
    /// Signature verification failed.
    SignatureVerificationFailed,
    /// Internal error.
    Internal(String),
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientShares { have, need } => {
                write!(f, "insufficient shares: have {have}, need {need}")
            }
            Self::InvalidKeyPackage(msg) => write!(f, "invalid key package: {msg}"),
            Self::RoundError(msg) => write!(f, "round error: {msg}"),
            Self::SessionNotFound => write!(f, "session not found"),
            Self::SessionAlreadyCompleted => write!(f, "session already completed"),
            Self::DuplicateCommitment => write!(f, "duplicate commitment"),
            Self::SignatureVerificationFailed => write!(f, "signature verification failed"),
            Self::Internal(msg) => write!(f, "internal: {msg}"),
        }
    }
}

impl std::error::Error for SignerError {}

/// Serialized form of signing commitments for IPC transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedCommitments {
    pub identifier: Vec<u8>,
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}

/// Serialized signature share for IPC transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedSignatureShare {
    pub identifier: Vec<u8>,
    pub share: Vec<u8>,
}

/// Round 1 output: commitments and nonces.
pub struct Round1Output {
    pub commitments: SigningCommitments,
    pub nonces: SigningNonces,
}

/// FROST signing state machine.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FrostSigner {
    /// Our key package (secret share).
    key_package: KeyPackage,
    /// Minimum signers required (threshold).
    min_signers: u16,
    /// Total number of participants.
    total_participants: u16,
    /// Our identifier index.
    identifier: Identifier,
}

impl FrostSigner {
    /// Create a new FROST signer from a key package.
    pub fn new(key_package: KeyPackage, min_signers: u16, total_participants: u16) -> Result<Self, SignerError> {
        let identifier = *key_package.identifier();
        Ok(Self {
            key_package,
            min_signers,
            total_participants,
            identifier,
        })
    }

    /// Get our identifier.
    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// Get the minimum number of signers required.
    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Get the total number of participants.
    pub fn total_participants(&self) -> u16 {
        self.total_participants
    }

    /// Preprocess: generate signing nonces and commitments (Round 1).
    ///
    /// These are generated ahead of time and stored for the signing session.
    pub fn preprocess(&self) -> Result<Round1Output, SignerError> {
        let mut rng = OsRng;
        let (nonces, commitments) = frost::round1::commit(
            self.key_package.secret_share(),
            &mut rng,
        );
        Ok(Round1Output {
            commitments,
            nonces,
        })
    }

    /// Sign the message (Round 2).
    ///
    /// Takes the message, our nonces, and all commitments from participants
    /// to produce our signature share.
    pub fn sign(
        &self,
        message: &[u8],
        nonces: &SigningNonces,
        commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SignatureShare, SignerError> {
        let signer_nonces = frost::round2::sign(
            &self.key_package,
            nonces,
            commitments,
            message,
        )
        .map_err(|e| SignerError::RoundError(format!("round2 sign: {e}")))?;

        Ok(signer_nonces)
    }

    /// Aggregate signature shares into a final signature.
    pub fn aggregate(
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        shares: &BTreeMap<Identifier, SignatureShare>,
        pubkey_package: &frost_secp256k1::keys::PublicKeyPackage,
        message: &[u8],
    ) -> Result<frost_secp256k1::Signature, SignerError> {
        let group_signature = frost::aggregate(
            commitments,
            shares,
            pubkey_package,
            message,
        )
        .map_err(|e| SignerError::RoundError(format!("aggregate: {e}")))?;

        Ok(group_signature)
    }

    /// Verify the final aggregated signature.
    pub fn verify(
        signature: &frost_secp256k1::Signature,
        pubkey_package: &frost_secp256k1::keys::PublicKeyPackage,
        message: &[u8],
    ) -> Result<bool, SignerError> {
        Ok(pubkey_package
            .group_public()
            .verify(message, signature)
            .is_ok())
    }
}

/// Taproot (BIP-340) variant of the FROST signer.
pub mod taproot {
    use std::collections::BTreeMap;

    use frost_secp256k1_tr as frost_tr;
    use frost_secp256k1_tr::keys::KeyPackage;
    use rand::rngs::OsRng;

    use super::SignerError;

    /// Taproot FROST signer state machine.
    pub struct TaprootSigner {
        key_package: KeyPackage,
        min_signers: u16,
        total_participants: u16,
    }

    impl TaprootSigner {
        pub fn new(key_package: KeyPackage, min_signers: u16, total_participants: u16) -> Result<Self, SignerError> {
            Ok(Self {
                key_package,
                min_signers,
                total_participants,
            })
        }

        pub fn preprocess(&self) -> Result<(frost_tr::round1::SigningNonces, frost_tr::round1::SigningCommitments), SignerError> {
            let mut rng = OsRng;
            let (nonces, commitments) = frost_tr::round1::commit(
                self.key_package.secret_share(),
                &mut rng,
            );
            Ok((nonces, commitments))
        }

        pub fn sign(
            &self,
            message: &[u8],
            nonces: &frost_tr::round1::SigningNonces,
            commitments: &BTreeMap<frost_secp256k1::Identifier, frost_tr::round1::SigningCommitments>,
        ) -> Result<frost_tr::round2::SignatureShare, SignerError> {
            frost_tr::round2::sign(
                &self.key_package,
                nonces,
                commitments,
                message,
            )
            .map_err(|e| SignerError::RoundError(format!("taproot round2 sign: {e}")))
        }

        pub fn aggregate(
            commitments: &BTreeMap<frost_secp256k1::Identifier, frost_tr::round1::SigningCommitments>,
            shares: &BTreeMap<frost_secp256k1::Identifier, frost_tr::round2::SignatureShare>,
            pubkey_package: &frost_tr::keys::PublicKeyPackage,
            message: &[u8],
        ) -> Result<frost_tr::Signature, SignerError> {
            frost_tr::aggregate(commitments, shares, pubkey_package, message)
                .map_err(|e| SignerError::RoundError(format!("taproot aggregate: {e}")))
        }

        pub fn verify(
            signature: &frost_tr::Signature,
            pubkey_package: &frost_tr::keys::PublicKeyPackage,
            message: &[u8],
        ) -> Result<bool, SignerError> {
            Ok(pubkey_package.group_public().verify(message, signature).is_ok())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage, SecretShare};
    use frost_secp256k1::Identifier;

    /// Minimal test using trusted dealer keygen (in-process N-party simulation).
    fn setup_test_signers(
        n: u16,
        t: u16,
    ) -> Result<(Vec<FrostSigner>, PublicKeyPackage), SignerError> {
        let mut rng = OsRng;
        let (shares, pubkey_package) = frost_secp256k1::keys::generate_with_dealer(
            n,
            t,
            &mut rng,
        )
        .map_err(|e| SignerError::InvalidKeyPackage(format!("dealer keygen: {e}")))?;

        let signers: Result<Vec<_>, _> = shares
            .into_iter()
            .map(|share| FrostSigner::new(share, t, n))
            .collect();

        Ok((signers?, pubkey_package))
    }

    #[test]
    fn basic_threshold_sign_roundtrip() {
        let (signers, pubkey_package) = setup_test_signers(3, 2).unwrap();

        // Each signer preprocesses
        let round1_outputs: Vec<_> = signers.iter().map(|s| s.preprocess().unwrap()).collect();

        // Every signer receives all commitments
        let mut all_commitments = BTreeMap::new();
        for (i, output) in round1_outputs.iter().enumerate() {
            all_commitments.insert(Identifier::try_from((i + 1) as u16).unwrap(), output.commitments);
        }

        // Each signer produces their signature share
        let message = b"test threshold message";
        let mut all_shares = BTreeMap::new();
        for (i, signer) in signers.iter().enumerate() {
            let share = signer
                .sign(message, &round1_outputs[i].nonces, &all_commitments)
                .unwrap();
            all_shares.insert(Identifier::try_from((i + 1) as u16).unwrap(), share);
        }

        // Aggregate with only threshold (t=2) shares
        let mut t_commitments = BTreeMap::new();
        let mut t_shares = BTreeMap::new();
        let id1 = Identifier::try_from(1u16).unwrap();
        let id2 = Identifier::try_from(2u16).unwrap();
        t_commitments.insert(id1, all_commitments[&id1]);
        t_commitments.insert(id2, all_commitments[&id2]);
        t_shares.insert(id1, all_shares[&id1]);
        t_shares.insert(id2, all_shares[&id2]);

        let signature = FrostSigner::aggregate(&t_commitments, &t_shares, &pubkey_package, message).unwrap();

        // Verify
        assert!(FrostSigner::verify(&signature, &pubkey_package, message).unwrap());
        assert!(!FrostSigner::verify(&signature, &pubkey_package, b"wrong message").unwrap());
    }
}
