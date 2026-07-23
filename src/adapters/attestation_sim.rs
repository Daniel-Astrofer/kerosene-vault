use crate::application::AttestationPort;
use crate::domain::{AttestationMode, AttestationQuote, DomainError, Measurement};

/// Software / lab measurement attestation (honest non-TEE).
///
/// - [`AttestationMode::Sim`]: lab-only visualization.
/// - [`AttestationMode::Software`]: domestic prod-capable software measurement (not SEV).
pub struct SimAttestationAdapter {
    mode: AttestationMode,
    lab_root: Vec<u8>,
}

impl SimAttestationAdapter {
    pub fn new(lab_root_material: &[u8]) -> Self {
        Self::with_mode(AttestationMode::Sim, lab_root_material)
    }

    pub fn software(lab_root_material: &[u8]) -> Self {
        Self::with_mode(AttestationMode::Software, lab_root_material)
    }

    pub fn with_mode(mode: AttestationMode, lab_root_material: &[u8]) -> Self {
        let mode = if mode.is_software_measurement() {
            mode
        } else {
            AttestationMode::Sim
        };
        Self {
            mode,
            lab_root: lab_root_material.to_vec(),
        }
    }

    fn mac(&self, measurement: &Measurement) -> Vec<u8> {
        let mut out = Vec::new();
        let tag = match self.mode {
            AttestationMode::Software => b"kerosene-vault-software-v1".as_slice(),
            _ => b"kerosene-vault-sim-v1".as_slice(),
        };
        out.extend_from_slice(tag);
        out.extend_from_slice(&self.lab_root);
        out.extend_from_slice(measurement.as_hex().as_bytes());
        Measurement::from_bytes(&out).as_hex().as_bytes().to_vec()
    }
}

impl AttestationPort for SimAttestationAdapter {
    fn mode(&self) -> AttestationMode {
        self.mode
    }

    fn issue_quote(&self, measurement: &Measurement) -> Result<AttestationQuote, DomainError> {
        Ok(AttestationQuote {
            mode: self.mode,
            measurement: measurement.clone(),
            quote_blob: self.mac(measurement),
        })
    }

    fn verify_quote(&self, quote: &AttestationQuote) -> Result<(), DomainError> {
        if quote.mode != self.mode {
            return Err(DomainError::AttestationRejected(format!(
                "{} adapter only accepts {} quotes",
                self.mode.as_str(),
                self.mode.as_str()
            )));
        }
        let expected = self.mac(&quote.measurement);
        if expected != quote.quote_blob {
            return Err(DomainError::AttestationRejected(
                "software/sim quote mac mismatch".into(),
            ));
        }
        Ok(())
    }
}
