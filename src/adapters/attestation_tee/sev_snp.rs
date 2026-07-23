//! AMD SEV-SNP attestation report verify path.
//!
//! Without `--features tee_hw` (CI / no guest device), issue and verify fail closed.
//! With `tee_hw`, issue and verify real SEV-SNP guest reports via `sev-snp-utilities`.
//!
//! Fail-closed rules:
//! - No `/dev/sev-guest` device → reject with a clear error.
//! - Empty or malformed reports → reject.
//! - Certificate chain + ECDSA signature → verified by `sev-snp-utilities`.
//! - Constitution pin is bound via SNP `REPORT_DATA` (user data), not the guest
//!   launch digest (`MEASUREMENT` field — that is firmware/VMM owned).
//!
//! Residual honesty: fetching and validating the AMD KDS cert chain depends on
//! `sev-snp-utilities`' internal wiring / cache. If that path errors, verification fails.

use crate::domain::{DomainError, Measurement};

#[cfg(feature = "tee_hw")]
use std::io::Cursor;

#[cfg(feature = "tee_hw")]
use sev_snp_utilities::{AttestationReport, Policy, Requester, Verification};

/// Pack our SHA-256 measurement (32 bytes) into SNP REPORT_DATA (64 bytes).
#[cfg(feature = "tee_hw")]
fn measurement_report_data(measurement: &Measurement) -> Result<[u8; 64], DomainError> {
    let digest = hex::decode(measurement.as_hex()).map_err(|e| {
        DomainError::AttestationRejected(format!("SEV-SNP measurement hex decode: {e}"))
    })?;
    if digest.len() != 32 {
        return Err(DomainError::AttestationRejected(
            "SEV-SNP measurement must be 32-byte SHA-256".into(),
        ));
    }
    let mut user_data = [0u8; 64];
    user_data[..32].copy_from_slice(&digest);
    Ok(user_data)
}

/// Issue a platform attestation report for `measurement`.
pub fn issue_report(measurement: &Measurement) -> Result<Vec<u8>, DomainError> {
    #[cfg(feature = "tee_hw")]
    {
        // Hard requirement for real guest reports.
        if !std::path::Path::new("/dev/sev-guest").exists() {
            return Err(DomainError::TeeRequired(
                "SEV-SNP quote issue: /dev/sev-guest missing (fail-closed without HW)".into(),
            ));
        }

        let user_data = measurement_report_data(measurement)?;
        let report_bytes = AttestationReport::request_raw(&user_data).map_err(|e| {
            DomainError::AttestationRejected(format!("SEV-SNP request_raw failed: {e}"))
        })?;
        Ok(report_bytes)
    }
    #[cfg(not(feature = "tee_hw"))]
    {
        let _ = measurement;
        Err(DomainError::AttestationRejected(
            "SEV-SNP hardware quote unavailable: rebuild with --features tee_hw (CI fail-closed without HW)"
                .into(),
        ))
    }
}

/// Verify an SEV-SNP attestation report and bind its measurement.
pub fn verify_report(measurement: &Measurement, report: &[u8]) -> Result<(), DomainError> {
    #[cfg(feature = "tee_hw")]
    {
        verify_report_structure(measurement, report)
    }
    #[cfg(not(feature = "tee_hw"))]
    {
        let _ = (measurement, report);
        Err(DomainError::AttestationRejected(
            "SEV-SNP hardware verify unavailable: rebuild with --features tee_hw (CI fail-closed without HW)"
                .into(),
        ))
    }
}

#[cfg(feature = "tee_hw")]
fn verify_report_structure(measurement: &Measurement, report: &[u8]) -> Result<(), DomainError> {
    if report.is_empty() {
        return Err(DomainError::AttestationRejected(
            "SEV-SNP report empty".into(),
        ));
    }

    let parsed = AttestationReport::from_reader(Cursor::new(report)).map_err(|e| {
        DomainError::AttestationRejected(format!("SEV-SNP report parse failed: {e}"))
    })?;

    let expected = measurement_report_data(measurement)?;
    if parsed.report_data.len() < 32 || parsed.report_data[..32] != expected[..32] {
        return Err(DomainError::AttestationRejected(
            "SEV-SNP REPORT_DATA measurement mismatch".into(),
        ));
    }

    // Verify certificate chain + ECDSA signature.
    let verify_fut = async {
        let policy = Policy::permissive();
        parsed.verify(Some(policy)).await
    };

    let verified = match tokio::runtime::Handle::try_current() {
        Ok(h) => h.block_on(verify_fut),
        Err(_) => tokio::runtime::Runtime::new()
            .map_err(|e| DomainError::AttestationRejected(format!("tokio runtime init: {e}")))?
            .block_on(verify_fut),
    }
    .map_err(|e| DomainError::AttestationRejected(format!("SEV-SNP verify failed: {e}")))?;

    if !verified {
        return Err(DomainError::AttestationRejected(
            "SEV-SNP report verification failed".into(),
        ));
    }

    Ok(())
}

#[cfg(feature = "tee_hw")]
#[cfg(test)]
mod tests {
    use super::*;

    fn pin() -> Measurement {
        Measurement::from_bytes(b"constitution-pin")
    }

    #[test]
    fn verify_rejects_empty_report_bytes() {
        let m = pin();
        let err = verify_report(&m, &[]).unwrap_err();
        assert!(err.to_string().contains("report empty"));
    }

    #[test]
    fn measurement_report_data_is_32_byte_prefix() {
        let m = pin();
        let data = measurement_report_data(&m).expect("pack");
        assert_eq!(data.len(), 64);
        assert_eq!(&data[32..], &[0u8; 32]);
        let digest = hex::decode(m.as_hex()).unwrap();
        assert_eq!(&data[..32], digest.as_slice());
    }
}
