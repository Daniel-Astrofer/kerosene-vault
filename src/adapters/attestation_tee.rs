use crate::application::AttestationPort;
use crate::domain::{AttestationMode, AttestationQuote, DomainError, Measurement};

/// SEV/SGX attestation adapter (F8).
///
/// - Staging: `ATTESTATION_STAGING_STUB=1` issues measurement-bound stub quotes (not sim).
/// - Production HW: without stub, quote issue/verify fail closed until real TEE plumbing lands.
pub struct TeeAttestationAdapter {
    mode: AttestationMode,
    staging_stub: bool,
    platform_root: Vec<u8>,
}

impl TeeAttestationAdapter {
    pub fn new(mode: AttestationMode, staging_stub: bool, platform_root: &[u8]) -> Result<Self, DomainError> {
        if !matches!(mode, AttestationMode::Sev | AttestationMode::Sgx) {
            return Err(DomainError::AttestationRejected(
                "TeeAttestationAdapter requires sev or sgx mode".into(),
            ));
        }
        Ok(Self {
            mode,
            staging_stub,
            platform_root: platform_root.to_vec(),
        })
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
        Measurement::from_bytes(&out).as_hex().as_bytes().to_vec()
    }
}

impl AttestationPort for TeeAttestationAdapter {
    fn mode(&self) -> AttestationMode {
        self.mode
    }

    fn issue_quote(&self, measurement: &Measurement) -> Result<AttestationQuote, DomainError> {
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

    #[test]
    fn staging_stub_roundtrip_sev() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sev, true, b"plat").unwrap();
        let m = Measurement::from_bytes(b"code");
        let q = tee.issue_quote(&m).unwrap();
        assert_eq!(q.mode, AttestationMode::Sev);
        tee.verify_quote(&q).unwrap();
    }

    #[test]
    fn rejects_sim_quote() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sgx, true, b"plat").unwrap();
        let m = Measurement::from_bytes(b"code");
        let bad = AttestationQuote {
            mode: AttestationMode::Sim,
            measurement: m,
            quote_blob: vec![1, 2, 3],
        };
        assert!(tee.verify_quote(&bad).is_err());
    }

    #[test]
    fn hw_path_fail_closed_without_stub() {
        let tee = TeeAttestationAdapter::new(AttestationMode::Sev, false, b"plat").unwrap();
        let m = Measurement::from_bytes(b"code");
        assert!(tee.issue_quote(&m).is_err());
    }
}
