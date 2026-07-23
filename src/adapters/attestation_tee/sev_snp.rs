//! AMD SEV-SNP attestation report verify path.
//!
//! Without `--features tee_hw` (CI / no guest device), issue and verify fail closed.
//! With `tee_hw`, the report decode + measurement bind structure is compiled; linking a
//! real VCEK/ARK/ASK verifier remains a platform ops step (still fail-closed until wired).

use crate::domain::{DomainError, Measurement};

/// Issue a platform attestation report for `measurement`.
pub fn issue_report(measurement: &Measurement) -> Result<Vec<u8>, DomainError> {
    #[cfg(feature = "tee_hw")]
    {
        // Structure only: real SNP guest request (SNP_GET_REPORT) is host/firmware specific.
        let _ = measurement;
        Err(DomainError::AttestationRejected(
            "SEV-SNP quote issue: tee_hw compiled but SNP_GET_REPORT / VCEK path not linked (fail-closed)"
                .into(),
        ))
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
    // Expected future layout hook: parse ATT_REPORT, check POLICY/SIGNATURE, compare
    // MEASUREMENT field to `measurement`. Until VCEK chain is linked, fail closed.
    let _ = measurement;
    Err(DomainError::AttestationRejected(
        "SEV-SNP quote verify: tee_hw path structured but VCEK/ARK/ASK verify not linked (fail-closed)"
            .into(),
    ))
}
