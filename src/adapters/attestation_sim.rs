use crate::application::AttestationPort;
use crate::domain::{AttestationMode, AttestationQuote, DomainError, Measurement};

pub struct SimAttestationAdapter {
    lab_root: Vec<u8>,
}

impl SimAttestationAdapter {
    pub fn new(lab_root_material: &[u8]) -> Self {
        Self {
            lab_root: lab_root_material.to_vec(),
        }
    }

    fn mac(&self, measurement: &Measurement) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"kerosene-vault-sim-v1");
        out.extend_from_slice(&self.lab_root);
        out.extend_from_slice(measurement.as_hex().as_bytes());
        Measurement::from_bytes(&out).as_hex().as_bytes().to_vec()
    }
}

impl AttestationPort for SimAttestationAdapter {
    fn mode(&self) -> AttestationMode {
        AttestationMode::Sim
    }

    fn issue_quote(&self, measurement: &Measurement) -> Result<AttestationQuote, DomainError> {
        Ok(AttestationQuote {
            mode: AttestationMode::Sim,
            measurement: measurement.clone(),
            quote_blob: self.mac(measurement),
        })
    }

    fn verify_quote(&self, quote: &AttestationQuote) -> Result<(), DomainError> {
        if quote.mode != AttestationMode::Sim {
            return Err(DomainError::AttestationRejected(
                "sim adapter only accepts sim quotes".into(),
            ));
        }
        let expected = self.mac(&quote.measurement);
        if expected != quote.quote_blob {
            return Err(DomainError::AttestationRejected(
                "sim quote mac mismatch".into(),
            ));
        }
        Ok(())
    }
}
