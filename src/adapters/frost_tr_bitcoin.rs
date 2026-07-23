//! Taproot-compatible FROST (`frost-secp256k1-tr`) for on-chain Bitcoin sighashes.
//!
//! Intent / off-chain proofs keep using `frost-secp256k1`. This module holds a
//! separate BIP-340 keyset used only for PSBT / Taproot key-path spends.
//!
//! On-chain signatures **must** cover the raw 32-byte sighash — no session/day
//! binding in the signed message (policy is enforced *before* sign via Intent gate).

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedPublicKey};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{schnorr, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::Signature as TaprootSignature;
use bitcoin::{Address, ScriptBuf, TxOut};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::{EvenY, KeyPackage, PublicKeyPackage, Tweak};
use frost_secp256k1_tr::round2::SignatureShare;
use frost_secp256k1_tr::{Identifier, Signature, SigningPackage};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::application::{AntiNoncePort, DailyRotationPort};
use crate::domain::{BitcoinNetwork, DomainError};

#[derive(Clone)]
pub struct FrostTrShareState {
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub pubkey_package: PublicKeyPackage,
    pub min_signers: usize,
}

#[derive(Default)]
pub struct FrostTrShareSlot {
    inner: RwLock<Option<FrostTrShareState>>,
}

impl FrostTrShareSlot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install(&self, state: FrostTrShareState) {
        *self.inner.write().expect("tr share lock") = Some(state);
    }

    pub fn snapshot(&self) -> Result<FrostTrShareState, DomainError> {
        self.inner
            .read()
            .expect("tr share lock")
            .clone()
            .ok_or_else(|| DomainError::ThresholdError("taproot FROST shares not installed".into()))
    }
}

#[derive(Debug)]
pub struct BitcoinSighashSignature {
    pub session_id: String,
    pub day_epoch: String,
    pub signature_hex: String,
    pub participants: usize,
    pub scheme: &'static str,
}

#[derive(Debug)]
pub struct SignedPsbtResult {
    pub session_id: String,
    pub day_epoch: String,
    pub signed_psbt: String,
    pub signatures: Vec<InputSignature>,
    pub participants: usize,
    pub scheme: &'static str,
}

#[derive(Debug, Clone)]
pub struct InputSignature {
    pub input_index: usize,
    pub sighash_hex: String,
    pub signature_hex: String,
}

pub struct DepositInfo {
    pub network: String,
    pub xonly_pubkey_hex: String,
    pub output_pubkey_hex: String,
    pub address: String,
    pub descriptor: String,
    pub scheme: &'static str,
}

pub struct FrostTrBitcoinOrchestrator {
    shares: Arc<FrostTrShareSlot>,
    anti_nonce: Box<dyn AntiNoncePort>,
    rotation: Arc<dyn DailyRotationPort>,
    network: BitcoinNetwork,
}

impl FrostTrBitcoinOrchestrator {
    pub fn new(
        shares: Arc<FrostTrShareSlot>,
        anti_nonce: Box<dyn AntiNoncePort>,
        rotation: Arc<dyn DailyRotationPort>,
        network: BitcoinNetwork,
    ) -> Self {
        Self {
            shares,
            anti_nonce,
            rotation,
            network,
        }
    }

    pub fn deposit_info(&self) -> Result<DepositInfo, DomainError> {
        let snap = self.shares.snapshot()?;
        let internal = xonly_from_verifying_key(snap.pubkey_package.verifying_key())?;
        let secp = Secp256k1::verification_only();
        let (output, _parity) = UntweakedPublicKey::from(internal).tap_tweak(&secp, None);
        let address = Address::p2tr_tweaked(output, self.network.to_bitcoin());
        let out_hex = hex::encode(output.to_x_only_public_key().serialize());
        let desc = format!("tr({out_hex})");
        Ok(DepositInfo {
            network: self.network.as_str().to_string(),
            xonly_pubkey_hex: hex::encode(internal.serialize()),
            output_pubkey_hex: out_hex,
            address: address.to_string(),
            descriptor: desc,
            scheme: "frost-secp256k1-tr-v3",
        })
    }

    /// Sign a raw 32-byte Bitcoin Taproot sighash (BIP-340). No message binding.
    pub fn sign_sighash(
        &self,
        session_id: &str,
        sighash32: &[u8],
    ) -> Result<BitcoinSighashSignature, DomainError> {
        if sighash32.len() != 32 {
            return Err(DomainError::ThresholdError(
                "bitcoin sighash must be exactly 32 bytes".into(),
            ));
        }
        self.anti_nonce.claim_session(session_id)?;
        let day_epoch = self.rotation.current_day_epoch()?;
        self.rotation.require_epoch(&day_epoch)?;

        let sig = self.sign_raw_quorum(sighash32)?;
        let sig_bytes = sig
            .serialize()
            .map_err(|e| DomainError::ThresholdError(format!("sig serialize: {e}")))?;
        Ok(BitcoinSighashSignature {
            session_id: session_id.to_string(),
            day_epoch: day_epoch.as_str().to_string(),
            signature_hex: hex::encode(sig_bytes),
            participants: self.shares.snapshot()?.min_signers,
            scheme: "frost-secp256k1-tr-v3",
        })
    }

    /// Intent-gated callers pass a funded PSBT; we sign Taproot key-path inputs.
    pub fn sign_psbt(
        &self,
        session_id: &str,
        psbt_b64: &str,
    ) -> Result<SignedPsbtResult, DomainError> {
        self.anti_nonce.claim_session(session_id)?;
        let day_epoch = self.rotation.current_day_epoch()?;
        self.rotation.require_epoch(&day_epoch)?;

        let mut psbt = Psbt::from_str(psbt_b64.trim())
            .map_err(|e| DomainError::ThresholdError(format!("invalid psbt: {e}")))?;
        if psbt.inputs.is_empty() {
            return Err(DomainError::ThresholdError("psbt has no inputs".into()));
        }

        let snap = self.shares.snapshot()?;
        let internal = xonly_from_verifying_key(snap.pubkey_package.verifying_key())?;
        let secp = Secp256k1::verification_only();
        let (tweaked, _) = UntweakedPublicKey::from(internal).tap_tweak(&secp, None);
        let our_output = tweaked.to_x_only_public_key();

        let prevouts = collect_prevouts(&psbt)?;
        let tx = psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(&tx);
        let mut signatures = Vec::new();
        let mut participants = 0usize;

        for (idx, input) in psbt.inputs.iter_mut().enumerate() {
            let Some(utxo) = input.witness_utxo.as_ref() else {
                continue;
            };
            if !is_p2tr(&utxo.script_pubkey) {
                continue;
            }
            // Only sign outputs that match our Taproot key-path deposit key.
            if !script_matches_output_key(&utxo.script_pubkey, our_output) {
                continue;
            }
            if input.tap_key_sig.is_some() {
                continue;
            }

            let sighash = cache
                .taproot_key_spend_signature_hash(
                    idx,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .map_err(|e| DomainError::ThresholdError(format!("taproot sighash: {e}")))?;
            let sighash_bytes = sighash.to_byte_array();
            let frost_sig = self.sign_raw_quorum(&sighash_bytes)?;
            participants = snap.min_signers;
            let sig_bytes = frost_sig
                .serialize()
                .map_err(|e| DomainError::ThresholdError(format!("sig serialize: {e}")))?;
            let schnorr = schnorr::Signature::from_slice(&sig_bytes)
                .map_err(|e| DomainError::ThresholdError(format!("schnorr decode: {e}")))?;
            input.tap_key_sig = Some(TaprootSignature {
                signature: schnorr,
                sighash_type: TapSighashType::Default,
            });
            signatures.push(InputSignature {
                input_index: idx,
                sighash_hex: hex::encode(sighash_bytes),
                signature_hex: hex::encode(sig_bytes),
            });
        }

        if signatures.is_empty() {
            return Err(DomainError::ThresholdError(
                "no Taproot key-path inputs matched mesh deposit key".into(),
            ));
        }

        Ok(SignedPsbtResult {
            session_id: session_id.to_string(),
            day_epoch: day_epoch.as_str().to_string(),
            signed_psbt: psbt.to_string(),
            signatures,
            participants,
            scheme: "frost-secp256k1-tr-v3",
        })
    }

    fn sign_raw_quorum(&self, message: &[u8]) -> Result<Signature, DomainError> {
        let snap = self.shares.snapshot()?;
        let min_signers = snap.min_signers;
        let key_packages = &snap.key_packages;
        let pubkey_package = &snap.pubkey_package;

        let mut rng = OsRng;
        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();

        let identifiers: Vec<Identifier> = key_packages.keys().copied().collect();
        if identifiers.len() < min_signers {
            return Err(DomainError::FailStop {
                online: identifiers.len(),
                need: min_signers,
            });
        }

        // BIP-341 key-path (no script tree): sign with merkle_root = None tweak.
        for id in identifiers.iter().take(min_signers) {
            let kp = key_packages
                .get(id)
                .ok_or_else(|| DomainError::ThresholdError("missing key package".into()))?
                .clone()
                .into_even_y(None)
                .tweak(None::<&[u8]>);
            let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
            nonces_map.insert(*id, nonces);
            commitments_map.insert(*id, commitments);
        }

        let mut message = message.to_vec();
        let signing_package = SigningPackage::new(commitments_map, &message);
        let mut signature_shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();

        for id in nonces_map.keys().copied().collect::<Vec<_>>() {
            let kp = key_packages[&id]
                .clone()
                .into_even_y(None)
                .tweak(None::<&[u8]>);
            let nonces = &nonces_map[&id];
            let share = frost::round2::sign(&signing_package, nonces, &kp)
                .map_err(|e| DomainError::ThresholdError(format!("frost-tr round2: {e}")))?;
            signature_shares.insert(id, share);
        }

        for (_, mut n) in nonces_map {
            n.zeroize();
        }

        let pubkey_tweaked = pubkey_package.clone().into_even_y(None).tweak(None::<&[u8]>);
        let signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_tweaked)
            .map_err(|e| DomainError::ThresholdError(format!("frost-tr aggregate: {e}")))?;

        pubkey_tweaked
            .verifying_key()
            .verify(&message, &signature)
            .map_err(|e| DomainError::ThresholdError(format!("frost-tr verify: {e}")))?;

        message.zeroize();
        Ok(signature)
    }
}

/// Lab dealer keygen for Taproot FROST (even-Y internal key; tweak applied at sign/deposit).
#[cfg(feature = "dealer_lab")]
pub fn generate_tr_dealer(
    max_signers: u16,
    min_signers: u16,
) -> Result<FrostTrShareState, DomainError> {
    let mut rng = OsRng;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|e| DomainError::ThresholdError(format!("frost-tr dealer: {e}")))?;

    let pubkey_package = pubkey_package.into_even_y(None);
    let mut key_packages = BTreeMap::new();
    for (identifier, secret_share) in &shares {
        let kp = KeyPackage::try_from(secret_share.clone())
            .map_err(|e| DomainError::ThresholdError(format!("tr key package: {e}")))?
            .into_even_y(None);
        key_packages.insert(*identifier, kp);
    }

    Ok(FrostTrShareState {
        key_packages,
        pubkey_package,
        min_signers: min_signers as usize,
    })
}

fn xonly_from_verifying_key(
    vk: &frost::VerifyingKey,
) -> Result<XOnlyPublicKey, DomainError> {
    let bytes = vk
        .serialize()
        .map_err(|e| DomainError::ThresholdError(format!("verifying key serialize: {e}")))?;
    // frost-tr verifying key serialize is x-only (32) or compressed (33).
    let xonly_bytes: [u8; 32] = match bytes.len() {
        32 => bytes.as_slice().try_into().unwrap(),
        33 => bytes[1..].try_into().unwrap(),
        n => {
            return Err(DomainError::ThresholdError(format!(
                "unexpected verifying key length {n}"
            )))
        }
    };
    XOnlyPublicKey::from_slice(&xonly_bytes)
        .map_err(|e| DomainError::ThresholdError(format!("xonly: {e}")))
}

fn collect_prevouts(psbt: &Psbt) -> Result<Vec<TxOut>, DomainError> {
    let mut out = Vec::with_capacity(psbt.inputs.len());
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(utxo) = &input.witness_utxo {
            out.push(utxo.clone());
            continue;
        }
        if let Some(tx) = &input.non_witness_utxo {
            let vout = psbt.unsigned_tx.input[i].previous_output.vout as usize;
            let txout = tx
                .output
                .get(vout)
                .cloned()
                .ok_or_else(|| DomainError::ThresholdError(format!("missing prevout {i}")))?;
            out.push(txout);
            continue;
        }
        return Err(DomainError::ThresholdError(format!(
            "psbt input {i} missing witness_utxo"
        )));
    }
    Ok(out)
}

fn is_p2tr(script: &ScriptBuf) -> bool {
    script.is_p2tr()
}

fn script_matches_output_key(script: &ScriptBuf, output_key: XOnlyPublicKey) -> bool {
    let expected = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
        output_key,
    ));
    *script == expected
}

impl DepositInfo {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"network":"{}","xonly_pubkey":"{}","output_pubkey":"{}","address":"{}","descriptor":"{}","scheme":"{}"}}"#,
            self.network,
            self.xonly_pubkey_hex,
            self.output_pubkey_hex,
            self.address,
            self.descriptor,
            self.scheme
        )
    }
}

impl BitcoinSighashSignature {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"session_id":"{}","day_epoch":"{}","signature":"{}","participants":{},"scheme":"{}"}}"#,
            self.session_id, self.day_epoch, self.signature_hex, self.participants, self.scheme
        )
    }
}

impl SignedPsbtResult {
    pub fn to_json(&self) -> String {
        let sigs: Vec<String> = self
            .signatures
            .iter()
            .map(|s| {
                format!(
                    r#"{{"input_index":{},"sighash":"{}","signature":"{}"}}"#,
                    s.input_index, s.sighash_hex, s.signature_hex
                )
            })
            .collect();
        format!(
            r#"{{"session_id":"{}","day_epoch":"{}","signed_psbt":"{}","signatures":[{}],"participants":{},"scheme":"{}"}}"#,
            self.session_id,
            self.day_epoch,
            self.signed_psbt,
            sigs.join(","),
            self.participants,
            self.scheme
        )
    }
}

/// Lab helper: build a tiny unsigned key-path PSBT spending a synthetic P2TR output.
#[cfg(all(test, feature = "dealer_lab"))]
pub fn lab_synthetic_funded_psbt(
    output_key: XOnlyPublicKey,
    network: bitcoin::Network,
    amount_sats: u64,
) -> Result<String, DomainError> {
    use bitcoin::absolute::LockTime;
    use bitcoin::{Amount, Sequence, Transaction, TxIn, Witness};

    let spk = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(output_key));
    let prev_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sats + 500),
            script_pubkey: spk.clone(),
        }],
    };
    let spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint {
                txid: prev_tx.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: Address::p2tr_tweaked(
                TweakedPublicKey::dangerous_assume_tweaked(output_key),
                network,
            )
            .script_pubkey(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(spend)
        .map_err(|e| DomainError::ThresholdError(format!("psbt: {e}")))?;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(amount_sats + 500),
        script_pubkey: spk,
    });
    Ok(psbt.to_string())
}

#[cfg(all(test, feature = "dealer_lab"))]
mod tests {
    use super::*;
    use crate::adapters::{LedgerDayEpochStub, PersistedAntiNonce, SystemClock};
    use crate::application::ClockPort;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempProbe(std::path::PathBuf);
    impl TempProbe {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "kv-tr-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempProbe {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn tr_sign_sighash_and_psbt_roundtrip() {
        let state = generate_tr_dealer(3, 2).unwrap();
        let tmp = TempProbe::new("psbt");
        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let rotation: Arc<dyn DailyRotationPort> =
            Arc::new(LedgerDayEpochStub::new(Arc::new(SystemClock)));
        let slot = Arc::new(FrostTrShareSlot::new());
        slot.install(state);
        let orch = FrostTrBitcoinOrchestrator::new(
            slot,
            Box::new(anti),
            rotation,
            BitcoinNetwork::Testnet3,
        );
        let deposit = orch.deposit_info().unwrap();
        assert!(deposit.address.starts_with("tb1p"));
        assert!(deposit.descriptor.starts_with("tr("));

        let sighash = [7u8; 32];
        let sig = orch.sign_sighash("btc-sess-1", &sighash).unwrap();
        assert_eq!(sig.signature_hex.len(), 128);

        let output = XOnlyPublicKey::from_slice(&hex::decode(&deposit.output_pubkey_hex).unwrap())
            .unwrap();
        let psbt = lab_synthetic_funded_psbt(output, bitcoin::Network::Testnet, 1_000).unwrap();
        let signed = orch.sign_psbt("btc-psbt-1", &psbt).unwrap();
        assert!(!signed.signed_psbt.is_empty());
        assert_eq!(signed.signatures.len(), 1);
        assert!(Psbt::from_str(&signed.signed_psbt).unwrap().inputs[0]
            .tap_key_sig
            .is_some());
    }

    #[test]
    fn tr_rejects_session_reuse() {
        let state = generate_tr_dealer(3, 2).unwrap();
        let tmp = TempProbe::new("reuse");
        let anti = PersistedAntiNonce::open(tmp.0.join("sessions.log")).unwrap();
        let rotation: Arc<dyn DailyRotationPort> =
            Arc::new(LedgerDayEpochStub::new(Arc::new(SystemClock)));
        let slot = Arc::new(FrostTrShareSlot::new());
        slot.install(state);
        let orch = FrostTrBitcoinOrchestrator::new(
            slot,
            Box::new(anti),
            rotation,
            BitcoinNetwork::Testnet3,
        );
        orch.sign_sighash("reuse-a", &[1u8; 32]).unwrap();
        let err = orch.sign_sighash("reuse-a", &[2u8; 32]).unwrap_err();
        assert!(matches!(err, DomainError::NonceReuse(_)));
    }

    struct FakeClock(AtomicU64);
    impl ClockPort for FakeClock {
        fn unix_now_secs(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }
}
