use crate::domain::DomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMode {
    Sim,
    Sev,
    Sgx,
}

impl AttestationMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sim" => Some(Self::Sim),
            "sev" => Some(Self::Sev),
            "sgx" => Some(Self::Sgx),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sim => "sim",
            Self::Sev => "sev",
            Self::Sgx => "sgx",
        }
    }

    pub fn is_lab_only(self) -> bool {
        matches!(self, Self::Sim)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement(String);

impl Measurement {
    /// Lab fingerprint of measured bytes. Replace with real SHA-256 (sha2) in F3.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(lab_fingerprint_hex(bytes))
    }

    pub fn from_hex(hex_str: impl Into<String>) -> Result<Self, DomainError> {
        let s = hex_str.into();
        if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DomainError::AttestationRejected(
                "lab measurement must be 16-byte hex (F1 placeholder)".into(),
            ));
        }
        Ok(Self(s.to_ascii_lowercase()))
    }

    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationQuote {
    pub mode: AttestationMode,
    pub measurement: Measurement,
    pub quote_blob: Vec<u8>,
}

fn lab_fingerprint_hex(input: &[u8]) -> String {
    let mut state: u64 = 0xcbf29ce484222325;
    for &b in input {
        state ^= u64::from(b);
        state = state.wrapping_mul(0x100000001b3);
    }
    for round in 0..4u64 {
        state ^= state << (13 + round);
        state = state.wrapping_mul(0x9e3779b97f4a7c15);
    }
    format!("{state:016x}{:016x}", !state)
}
