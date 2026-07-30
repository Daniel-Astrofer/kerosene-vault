//! Distributed Key Generation (DKG) for FROST signing.
//!
//! Implements the FROST DKG protocol for generating keys without a trusted dealer.
//! This is the foundation for the vault mesh's distributed signing capability.

use std::collections::BTreeMap;

use frost_secp256k1 as frost;
use frost_secp256k1::Identifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::signer::SignerError;

/// DKG round 1 output for a single participant.
pub struct DkgRound1Output {
    pub secret_package: frost::keys::dkg::round1::SecretPackage,
    pub public_package: frost::keys::dkg::round1::PublicPackage,
}

/// DKG round 2 output for a single participant.
pub struct DkgRound2Output {
    pub secret_package: frost::keys::dkg::round2::SecretPackage,
    pub proof: frost::keys::dkg::Proof,
}

/// Result of a completed DKG: key package and public key package.
pub struct DkgResult {
    pub key_package: frost::keys::KeyPackage,
    pub pubkey_package: frost::keys::PublicKeyPackage,
}

/// Serialized DKG message for IPC transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgMessage {
    pub round: u8,
    pub sender: Vec<u8>,
    pub payload: Vec<u8>,
}

/// State for a single DKG participant.
pub struct DkgParticipant {
    identifier: Identifier,
    min_signers: u16,
    max_signers: u16,
    round1_secret: Option<frost::keys::dkg::round1::SecretPackage>,
}

impl DkgParticipant {
    /// Create a new DKG participant.
    pub fn new(identifier: Identifier, min_signers: u16, max_signers: u16) -> Self {
        Self {
            identifier,
            min_signers,
            max_signers,
            round1_secret: None,
        }
    }

    /// Execute DKG round 1.
    pub fn round1(&mut self) -> Result<DkgRound1Output, SignerError> {
        let mut rng = OsRng;
        let (secret, public) = frost::keys::dkg::round1::part1(
            self.identifier,
            self.max_signers,
            self.min_signers,
            &mut rng,
        )
        .map_err(|e| SignerError::RoundError(format!("dkg round1 part1: {e}")))?;

        self.round1_secret = Some(secret.clone());

        Ok(DkgRound1Output {
            secret_package: secret,
            public_package: public,
        })
    }

    /// Execute DKG round 2.
    pub fn round2(
        &self,
        all_public_packages: &BTreeMap<Identifier, frost::keys::dkg::round1::PublicPackage>,
    ) -> Result<DkgRound2Output, SignerError> {
        let secret = self
            .round1_secret
            .as_ref()
            .ok_or_else(|| SignerError::Internal("round1 not executed".into()))?;

        let (round2_secret, proof) = frost::keys::dkg::part2(
            secret,
            all_public_packages,
        )
        .map_err(|e| SignerError::RoundError(format!("dkg round2 part2: {e}")))?;

        Ok(DkgRound2Output {
            secret_package: round2_secret,
            proof,
        })
    }

    /// Finalize DKG, producing the key package and public key package.
    pub fn finalize(
        &self,
        round2_secret: &frost::keys::dkg::round2::SecretPackage,
        all_round1_publics: &BTreeMap<Identifier, frost::keys::dkg::round1::PublicPackage>,
        all_round2_publics: &BTreeMap<Identifier, frost::keys::dkg::round2::PublicPackage>,
    ) -> Result<DkgResult, SignerError> {
        let (key_package, pubkey_package, _proof) = frost::keys::dkg::part3(
            round2_secret,
            all_round1_publics,
            all_round2_publics,
        )
        .map_err(|e| SignerError::RoundError(format!("dkg finalize part3: {e}")))?;

        Ok(DkgResult {
            key_package,
            pubkey_package,
        })
    }
}

/// High-level DKG orchestrator that manages all participants (for in-process testing).
pub struct DistributedKeyGeneration {
    participants: Vec<DkgParticipant>,
    max_signers: u16,
    min_signers: u16,
}

impl DistributedKeyGeneration {
    /// Initialize DKG with the given number of participants and threshold.
    pub fn new(max_signers: u16, min_signers: u16) -> Result<Self, SignerError> {
        if min_signers > max_signers || min_signers < 2 {
            return Err(SignerError::InvalidKeyPackage(format!(
                "invalid threshold: t={min_signers}, n={max_signers}"
            )));
        }

        let participants: Vec<_> = (1..=max_signers)
            .map(|i| {
                let id = Identifier::try_from(i)
                    .expect("valid identifier");
                DkgParticipant::new(id, min_signers, max_signers)
            })
            .collect();

        Ok(Self {
            participants,
            max_signers,
            min_signers,
        })
    }

    /// Run the full DKG protocol in-process (all participants local).
    pub fn run_in_process(&mut self) -> Result<Vec<DkgResult>, SignerError> {
        // Round 1: all participants generate their public packages
        let mut round1_publics = BTreeMap::new();
        for p in &mut self.participants {
            let output = p.round1()?;
            round1_publics.insert(p.identifier, output.public_package);
        }

        // Round 2: each participant processes all round 1 public packages
        let mut round2_outputs = Vec::new();
        for p in &self.participants {
            let output = p.round2(&round1_publics)?;
            round2_outputs.push(output);
        }

        // Build round 2 public packages from each participant's proof
        // In frost-secp256k1, PublicPackage wraps ProofOfPossession
        let mut round2_publics = BTreeMap::new();
        for (i, p) in self.participants.iter().enumerate() {
            let proof = &round2_outputs[i].proof;
            // Construct PublicPackage from the proof bytes via new()
            round2_publics.insert(
                p.identifier,
                frost::keys::dkg::round2::PublicPackage::new(
                    proof.proof_of_possession().clone(),
                ),
            );
        }

        // Finalize: each participant produces their key package
        let mut results = Vec::new();
        for (i, p) in self.participants.iter().enumerate() {
            let result = p.finalize(
                &round2_outputs[i].secret_package,
                &round1_publics,
                &round2_publics,
            )?;
            results.push(result);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1 as frost;

    #[test]
    fn dkg_3_of_5_produces_valid_keys() {
        let mut dkg = DistributedKeyGeneration::new(5, 3).unwrap();
        let results = dkg.run_in_process().unwrap();
        assert_eq!(results.len(), 5);

        for result in &results {
            assert!(result.key_package.identifier() >= &Identifier::try_from(1u16).unwrap());
        }

        let pubkey = &results[0].pubkey_package;
        let message = b"dkg test message";

        let mut rng = OsRng;
        let mut commitments = BTreeMap::new();
        let mut nonces_list = Vec::new();

        for i in 0..3 {
            let (nonces, comm) = frost::round1::commit(
                results[i].key_package.secret_share(),
                &mut rng,
            );
            commitments.insert(*results[i].key_package.identifier(), comm);
            nonces_list.push((*results[i].key_package.identifier(), nonces));
        }

        let mut shares = BTreeMap::new();
        for (id, nonces) in &nonces_list {
            let share = frost::round2::sign(
                &results[0].key_package,
                nonces,
                &commitments,
                message,
            )
            .unwrap();
            shares.insert(*id, share);
        }

        let signature = frost::aggregate(&commitments, &shares, pubkey, message).unwrap();
        assert!(pubkey.group_public().verify(message, &signature).is_ok());
    }
}
