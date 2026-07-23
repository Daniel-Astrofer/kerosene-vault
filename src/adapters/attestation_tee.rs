use crate::application::AttestationPort;
use crate::domain::{AttestationMode, AttestationQuote, DomainError, Measurement};

/// SEV/SGX attestation adapter (F8 / Gate).
///
/// - Staging: `ATTESTATION_STAGING_STUB=1` issues measurement-bound stub quotes (not sim).
/// - Quotes are pinned to a constitution (or config) measurement; mismatch → reject.
/// - Production HW: without stub, quote issue/verify fail closed until real TEE plumbing lands.
pub struct TeeAttestationAdapter {
    mode: AttestationMode,
    staging_stub: bool,
    platform_root: Vec<u8>,
    /// Expected binary / constitution measurement pin.
    pinned_measurement: Measurement,
}

impl TeeAttestationAdapter {
    pub fn new(
        mode: AttestationMode,
        staging_stub: bool,
        platform_root: &[u8],
        pinned_measurement: Measurement,
    ) -> Result<Self, DomainError> {
        if !matches!(mode, AttestationMode::Sev | AttestationMode::Sgx) {
            return Err(DomainError::AttestationRejected(
                "TeeAttestationAdapter requires sev or sgx mode".into(),
            ));
        }
        Ok(Self {
            mode,
            staging_stub,
            platform_root: platform_root.to_vec(),
            pinned_measurement,
        })
    }

    pub fn pinned_measurement(&self) -> &Measurement {
        &self.pinned_measurement
    }

    fn quote_tag(&self) -> &'static [u8] {
        match self.mode {
            AttestationMode::Sev => b"kerosene-vault-sev-stub-v1",
            AttestationMode::Sgx => b"kerosene-vault-sgx-stub-v1",
            AttestationMode::Sim => b"invalid",
        }
    }

    fn mac(&self, measurement: &Measurement) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.quote_tag());
        out.extend_from_slice(&self.platform_root);
        out.extend_from_slice(measurement.as_hex().as_bytes());
        out.extend_from_slice(b"|pin|");
        out.extend_from_slice(self.pinned_measurement.as_hex().as_bytes());
        Measurement::from_bytes(&out).as_hex().as_bytes().to_vec()
    }

    fn enforce_pin(&self, measurement: &Measurement) -> Result<(), DomainError> {
        if measurement != &self.pinned_measurement {
            return Err(DomainError::MeasurementMismatch);
        }
        Ok(())
    }
}

impl AttestationPort for TeeAttestationAdapter {
    fn mode(&self) -> AttestationMode {
        self.mode
    }

    fn issue_quote(&self, measurement: &Measurement) -> Result<AttestationQuote, DomainError> {
        self.enforce_pin(measurement)?;
        if !self.staging_stub {
            return Err(DomainError::AttestationRejected(format!(
                "{} hardware quote unavailable (set ATTESTATION_STAGING_STUB=1 for staging only)",
                self.mode.as_str()
            )));
        }
        Ok(AttestationQuote {
            mode: self.mode,
            measurement: measurement.clone(),
            quote_blob: self.mac(measurement),
        })
    }

    fn verify_quote(&self, quote: &AttestationQuote) -> Result<(), DomainError> {
        if quote.mode == AttestationMode::Sim {
            return Err(DomainError::AttestationRejected(
                "TEE adapter rejects sim quotes".into(),
            ));
        }
        if quote.mode != self.mode {
            return Err(DomainError::AttestationRejected(format!(
                "quote mode {} != adapter {}",
                quote.mode.as_str(),
                self.mode.as_str()
            )));
        }
        self.enforce_pin(&quote.measurement)?;
        if !self.staging_stub {
            return Err(DomainError::AttestationRejected(format!(
                "{} hardware verify unavailable",
                self.mode.as_str()
            )));
        }
        let expected = self.mac(&quote.measurement);
        if expected != quote.quote_blob {
            return Err(DomainError::AttestationRejected(
                "TEE staging stub quote mac mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin() -> Measurement {
        Measurement::from_bytes(b"constitution-pin")
    }

    #[test]
    fn staging_stub_roundtrip_sev() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sev, true, b"plat", pin()).unwrap();
        let q = tee.issue_quote(&pin()).unwrap();
        assert_eq!(q.mode, AttestationMode::Sev);
        tee.verify_quote(&q).unwrap();
    }

    #[test]
    fn rejects_measurement_not_pinned() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sgx, true, b"plat", pin()).unwrap();
        let other = Measurement::from_bytes(b"other-binary");
        assert!(matches!(
            tee.issue_quote(&other),
            Err(DomainError::MeasurementMismatch)
        ));
        let bad = AttestationQuote {
            mode: AttestationMode::Sgx,
            measurement: other,
            quote_blob: vec![1, 2, 3],
        };
        assert!(matches!(
            tee.verify_quote(&bad),
            Err(DomainError::MeasurementMismatch)
        ));
    }

    #[test]
    fn rejects_sim_quote() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sgx, true, b"plat", pin()).unwrap();
        let bad = AttestationQuote {
            mode: AttestationMode::Sim,
            measurement: pin(),
            quote_blob: vec![1, 2, 3],
        };
        assert!(tee.verify_quote(&bad).is_err());
    }

    #[test]
    fn hw_path_fail_closed_without_stub() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sev, false, b"plat", pin()).unwrap();
        assert!(tee.issue_quote(&pin()).is_err());
    }
}
