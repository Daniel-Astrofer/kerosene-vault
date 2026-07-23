//! Intel SGX DCAP / ECDSA quote verify path.
//!
//! Without `--features tee_hw` (CI / no enclave), issue and verify fail closed.
//! With `tee_hw`, quote parse + MRENCLAVE bind structure is compiled; QE/PCK collateral
//! verification remains ops-wired (still fail-closed until linked).

use crate::domain::{DomainError, Measurement};

/// Issue an SGX quote for `measurement` (MRENCLAVE bind target).
pub fn issue_report(measurement: &Measurement) -> Result<Vec<u8>, DomainError> {
    #[cfg(feature = "tee_hw")]
    {
        let _ = measurement;
        Err(DomainError::AttestationRejected(
            "SGX quote issue: tee_hw compiled but DCAP quote generation not linked (fail-closed)"
                .into(),
        ))
    }
    #[cfg(not(feature = "tee_hw"))]
    {
        let _ = measurement;
        Err(DomainError::AttestationRejected(
            "SGX hardware quote unavailable: rebuild with --features tee_hw (CI fail-closed without HW)"
                .into(),
        ))
    }
}

/// Verify an SGX quote and bind MRENCLAVE to `measurement`.
pub fn verify_report(measurement: &Measurement, report: &[u8]) -> Result<(), DomainError> {
    #[cfg(feature = "tee_hw")]
    {
        verify_report_structure(measurement, report)
    }
    #[cfg(not(feature = "tee_hw"))]
    {
        let _ = (measurement, report);
        Err(DomainError::AttestationRejected(
            "SGX hardware verify unavailable: rebuild with --features tee_hw (CI fail-closed without HW)"
                .into(),
        ))
    }
}

#[cfg(feature = "tee_hw")]
fn verify_report_structure(measurement: &Measurement, report: &[u8]) -> Result<(), DomainError> {
    if report.is_empty() {
        return Err(DomainError::AttestationRejected("SGX quote empty".into()));
    }
    // Expected future layout hook: parse Quote v3/v4, verify ECDSA + collateral, compare
    // MRENCLAVE to `measurement`. Until DCAP is linked, fail closed.
    let _ = measurement;
    Err(DomainError::AttestationRejected(
        "SGX quote verify: tee_hw path structured but DCAP/QE collateral verify not linked (fail-closed)"
            .into(),
    ))
}
