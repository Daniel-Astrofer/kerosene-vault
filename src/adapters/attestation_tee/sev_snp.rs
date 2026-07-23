//! AMD SEV-SNP attestation report verify path.
//!
//! Without `--features tee_hw` (CI / no guest device), issue and verify fail closed.
//! With `tee_hw`, issue and verify real SEV-SNP guest reports via `sev-snp-utilities`.
//!
//! Fail-closed rules:
//! - No `/dev/sev-guest` device → reject with a clear error.
//! - Empty or malformed reports → reject.
//! - Certificate chain + ECDSA signature → verified by `sev-snp-utilities`.
//! - Report measurement is bound to the pinned `Measurement` here (pin-only gate).
//!
//! Residual honesty: fetching and validating the AMD KDS cert chain depends on
//! `sev-snp-utilities`' internal wiring / cache. If that path errors, verification fails.

use crate::domain::{DomainError, Measurement};

#[cfg(feature = "tee_hw")]
use std::io::Cursor;

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

        // We just request the raw report bytes here; verification binds the report measurement
        // to the pinned `Measurement`.
        let _ = measurement;
        let report_bytes = sev_snp_utilities::AttestationReport::request_raw().map_err(|e| {
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

    // Parse report and immediately bind the report measurement to our pinned pin.
    let parsed = sev_snp_utilities::AttestationReport::from_reader(Cursor::new(report)).map_err(|e| {
        DomainError::AttestationRejected(format!("SEV-SNP report parse failed: {e}"))
    })?;

    if parsed.measurement_hex() != measurement.as_hex() {
        return Err(DomainError::AttestationRejected(
            "SEV-SNP measurement mismatch".into(),
        ));
    }

    // Verify certificate chain + ECDSA signature.
    let verify_fut = async {
        let policy = sev_snp_utilities::Policy::permissive();
        parsed.verify(Some(policy)).await
    };

    let verified = match tokio::runtime::Handle::try_current() {
        Ok(h) => h.block_on(verify_fut),
        Err(_) => tokio::runtime::Runtime::new()
            .map_err(|e| DomainError::AttestationRejected(format!("tokio runtime init: {e}")))?
            .block_on(verify_fut),
    }?;

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
}
