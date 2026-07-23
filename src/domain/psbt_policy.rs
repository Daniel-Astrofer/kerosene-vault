//! PSBT fee / locktime / nSequence policy bounds (High #13).
//!
//! Intent bind covers destination + amount + mesh change. This module refuses
//! hostile fee drains, unbounded locktime, and disallowed RBF before signing.

use bitcoin::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::Sequence;

use crate::domain::DomainError;

/// How Replace-By-Fee (BIP-125) signalling is treated on inputs we sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbfPolicy {
    /// Allow either RBF-enabled or final sequences.
    Allow,
    /// Require every signed input to signal RBF (`nSequence < 0xfffffffe`).
    Require,
    /// Forbid RBF signalling (`nSequence` must be final).
    Forbid,
}

impl RbfPolicy {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" | "any" => Some(Self::Allow),
            "require" | "rbf" => Some(Self::Require),
            "forbid" | "final" | "no_rbf" => Some(Self::Forbid),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Require => "require",
            Self::Forbid => "forbid",
        }
    }
}

/// Bound hostile PSBT fee / time / RBF before Taproot FROST sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsbtPolicy {
    /// Absolute fee cap (sum(inputs) − sum(outputs)), sats.
    pub max_fee_sats: u64,
    /// Max fee rate in sat/vB (uses unsigned tx weight estimate).
    pub max_fee_rate_sat_vb: u64,
    /// Max absolute locktime value (height or time). `LockTime::ZERO` always ok.
    pub max_locktime: u32,
    pub rbf: RbfPolicy,
}

impl PsbtPolicy {
    /// Conservative defaults for treasury withdraw PSBTs.
    pub fn lab_defaults() -> Self {
        Self {
            max_fee_sats: 50_000,
            max_fee_rate_sat_vb: 250,
            max_locktime: 0, // only LockTime::ZERO unless raised via env
            rbf: RbfPolicy::Allow,
        }
    }

    pub fn validate(&self, psbt: &Psbt) -> Result<(), DomainError> {
        let tx = &psbt.unsigned_tx;
        let mut in_sats: u64 = 0;
        for (i, input) in psbt.inputs.iter().enumerate() {
            let value = if let Some(utxo) = &input.witness_utxo {
                utxo.value.to_sat()
            } else if let Some(prev) = &input.non_witness_utxo {
                let vout = tx.input[i].previous_output.vout as usize;
                prev.output
                    .get(vout)
                    .map(|o| o.value.to_sat())
                    .ok_or_else(|| {
                        DomainError::InvalidIntent(format!("psbt input {i} missing prevout value"))
                    })?
            } else {
                return Err(DomainError::InvalidIntent(format!(
                    "psbt input {i} missing witness_utxo for fee policy"
                )));
            };
            in_sats = in_sats.saturating_add(value);
        }
        let out_sats: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        if out_sats > in_sats {
            return Err(DomainError::InvalidIntent(
                "psbt outputs exceed inputs".into(),
            ));
        }
        let fee = in_sats - out_sats;
        if fee > self.max_fee_sats {
            return Err(DomainError::InvalidIntent(format!(
                "psbt fee {fee} sats exceeds max_fee_sats {}",
                self.max_fee_sats
            )));
        }

        // Weight estimate: unsigned tx vbytes ≈ weight/4; use bitcoin's weight API.
        let weight_wu = tx.weight().to_wu();
        let vbytes = weight_wu.div_ceil(4).max(1);
        let fee_rate = fee / vbytes;
        if fee_rate > self.max_fee_rate_sat_vb {
            return Err(DomainError::InvalidIntent(format!(
                "psbt fee rate ~{fee_rate} sat/vB exceeds max {}",
                self.max_fee_rate_sat_vb
            )));
        }

        match tx.lock_time {
            LockTime::ZERO => {}
            other => {
                let raw = other.to_consensus_u32();
                if self.max_locktime == 0 {
                    return Err(DomainError::InvalidIntent(format!(
                        "psbt locktime {raw} refused (policy requires LockTime::ZERO)"
                    )));
                }
                if raw > self.max_locktime {
                    return Err(DomainError::InvalidIntent(format!(
                        "psbt locktime {raw} exceeds max {}",
                        self.max_locktime
                    )));
                }
            }
        }

        for (i, tin) in tx.input.iter().enumerate() {
            let seq = tin.sequence;
            let signals_rbf = is_rbf_signal(seq);
            match self.rbf {
                RbfPolicy::Allow => {}
                RbfPolicy::Require if !signals_rbf => {
                    return Err(DomainError::InvalidIntent(format!(
                        "psbt input {i} must signal RBF (policy=require)"
                    )));
                }
                RbfPolicy::Forbid if signals_rbf => {
                    return Err(DomainError::InvalidIntent(format!(
                        "psbt input {i} RBF signalling forbidden"
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn is_rbf_signal(seq: Sequence) -> bool {
    // BIP-125: nSequence < 0xfffffffe signals replaceability.
    seq.to_consensus_u32() < 0xffff_fffe
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};

    fn tiny_psbt(fee: u64, lock: LockTime, seq: Sequence) -> Psbt {
        let prev = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: lock,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: prev.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: seq,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000 - fee),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(spend).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new(),
        });
        psbt
    }

    #[test]
    fn rejects_absurd_fee() {
        let p = PsbtPolicy {
            max_fee_sats: 1_000,
            ..PsbtPolicy::lab_defaults()
        };
        let err = p
            .validate(&tiny_psbt(5_000, LockTime::ZERO, Sequence::ENABLE_RBF_NO_LOCKTIME))
            .unwrap_err();
        assert!(err.to_string().contains("fee"));
    }

    #[test]
    fn rejects_nonzero_locktime_when_max_zero() {
        let p = PsbtPolicy::lab_defaults();
        let err = p
            .validate(&tiny_psbt(
                500,
                LockTime::from_height(800_000).unwrap(),
                Sequence::MAX,
            ))
            .unwrap_err();
        assert!(err.to_string().contains("locktime"));
    }

    #[test]
    fn forbids_rbf_when_configured() {
        let p = PsbtPolicy {
            rbf: RbfPolicy::Forbid,
            ..PsbtPolicy::lab_defaults()
        };
        let err = p
            .validate(&tiny_psbt(500, LockTime::ZERO, Sequence::ENABLE_RBF_NO_LOCKTIME))
            .unwrap_err();
        assert!(err.to_string().contains("RBF"));
    }
}
