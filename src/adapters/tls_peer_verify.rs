//! Outbound peer TLS verify for vault↔vault mTLS.
//!
//! Clearnet: standard webpki hostname / IP match.
//! Tor onions: DNS SAN may include `.onion`, **or** URI SAN may carry a SPIFFE ID
//! (see `docs/MTLS_SPIFFE_LAYOUT.md`). Tor circuits are high-variance — verify is
//! independent of SOCKS timeouts/retries.

use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    SignatureScheme,
};
use x509_parser::prelude::*;

use crate::domain::DomainError;

/// How outbound mTLS peers authenticate the remote server certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsPeerVerifyPolicy {
    /// webpki: DNS / IP must match the URL host (clearnet default).
    Hostname,
    /// Chain to lab/ops CA + URI SAN must equal `expected` SPIFFE ID (ignore DNS).
    Spiffe { expected: String },
    /// Chain + SPIFFE URI **and** (when host is `.onion`) matching onion DNS SAN.
    /// Env name remains `onion_or_spiffe` for compat; semantics are AND (#24).
    OnionOrSpiffe { expected: String },
}

impl TlsPeerVerifyPolicy {
    pub fn parse(raw: &str, expected_spiffe: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "hostname" | "dns" | "webpki" => Some(Self::Hostname),
            "spiffe" => Some(Self::Spiffe {
                expected: expected_spiffe.to_string(),
            }),
            "onion_or_spiffe" | "onion+spiffe" | "tor" => Some(Self::OnionOrSpiffe {
                expected: expected_spiffe.to_string(),
            }),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hostname => "hostname",
            Self::Spiffe { .. } => "spiffe",
            Self::OnionOrSpiffe { .. } => "onion_or_spiffe",
        }
    }

    pub fn expected_spiffe(&self) -> Option<&str> {
        match self {
            Self::Hostname => None,
            Self::Spiffe { expected } | Self::OnionOrSpiffe { expected } => Some(expected.as_str()),
        }
    }
}

/// Build a rustls `ClientConfig` with client identity + peer verify policy.
pub fn build_mtls_rustls_client_config(
    client_cert_path: &Path,
    client_key_path: &Path,
    ca_path: &Path,
    verify: &TlsPeerVerifyPolicy,
) -> Result<ClientConfig, DomainError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let roots = load_root_store(ca_path)?;
    let (certs, key) = load_client_identity(client_cert_path, client_key_path)?;

    let builder = match verify {
        TlsPeerVerifyPolicy::Hostname => {
            let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| DomainError::AuthRejected(format!("peer TLS verifier: {e}")))?;
            ClientConfig::builder().with_webpki_verifier(verifier)
        }
        TlsPeerVerifyPolicy::Spiffe { expected }
        | TlsPeerVerifyPolicy::OnionOrSpiffe { expected } => {
            let require_onion_san = matches!(verify, TlsPeerVerifyPolicy::OnionOrSpiffe { .. });
            let verifier = Arc::new(OnionOrSpiffeVerifier::new(
                roots,
                expected.clone(),
                require_onion_san,
            )?);
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
        }
    };

    builder
        .with_client_auth_cert(certs, key)
        .map_err(|e| DomainError::AuthRejected(format!("mTLS client identity: {e}")))
}

fn load_root_store(ca_path: &Path) -> Result<RootCertStore, DomainError> {
    let ca_pem = std::fs::read(ca_path).map_err(|e| {
        DomainError::AuthRejected(format!(
            "read VAULT_TLS_CLIENT_CA_PATH {}: {e}",
            ca_path.display()
        ))
    })?;
    let mut roots = RootCertStore::empty();
    let mut n = 0usize;
    for ca in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
        let ca = ca.map_err(|e| DomainError::AuthRejected(format!("parse peer CA PEM: {e}")))?;
        roots
            .add(ca)
            .map_err(|e| DomainError::AuthRejected(format!("add peer CA: {e}")))?;
        n += 1;
    }
    if n == 0 {
        return Err(DomainError::AuthRejected(
            "VAULT_TLS_CLIENT_CA_PATH contains no certificates".into(),
        ));
    }
    Ok(roots)
}

fn load_client_identity(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), DomainError> {
    let cert_pem = std::fs::read(cert_path).map_err(|e| {
        DomainError::AuthRejected(format!(
            "read VAULT_TLS_CLIENT_CERT_PATH {}: {e}",
            cert_path.display()
        ))
    })?;
    let key_pem = std::fs::read(key_path).map_err(|e| {
        DomainError::AuthRejected(format!(
            "read VAULT_TLS_CLIENT_KEY_PATH {}: {e}",
            key_path.display()
        ))
    })?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DomainError::AuthRejected(format!("parse client cert PEM: {e}")))?;
    if certs.is_empty() {
        return Err(DomainError::AuthRejected(
            "VAULT_TLS_CLIENT_CERT_PATH contains no certificates".into(),
        ));
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| DomainError::AuthRejected(format!("parse client key PEM: {e}")))?
        .ok_or_else(|| {
            DomainError::AuthRejected("VAULT_TLS_CLIENT_KEY_PATH contains no private key".into())
        })?;
    Ok((certs, key))
}

/// Extract URI and DNS SANs from an end-entity certificate DER.
pub fn extract_sans(end_entity_der: &[u8]) -> Result<(Vec<String>, Vec<String>), DomainError> {
    let (_, cert) = X509Certificate::from_der(end_entity_der)
        .map_err(|e| DomainError::AuthRejected(format!("parse peer cert for SAN: {e}")))?;
    let mut uris = Vec::new();
    let mut dns = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                GeneralName::URI(u) => uris.push(u.to_string()),
                GeneralName::DNSName(d) => dns.push(d.to_string()),
                _ => {}
            }
        }
    }
    Ok((uris, dns))
}

fn server_name_host(server_name: &ServerName<'_>) -> String {
    match server_name {
        ServerName::DnsName(d) => d.as_ref().to_string(),
        ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
        _ => String::new(),
    }
}

fn name_error(err: &RustlsError) -> bool {
    matches!(
        err,
        RustlsError::InvalidCertificate(CertificateError::NotValidForName)
            | RustlsError::InvalidCertificate(CertificateError::NotValidForNameContext { .. })
    )
}

/// Wraps webpki chain+name verify; requires SPIFFE URI, and onion DNS SAN for `.onion` hosts.
struct OnionOrSpiffeVerifier {
    inner: Arc<WebPkiServerVerifier>,
    expected_spiffe: String,
    /// When true (OnionOrSpiffe policy), `.onion` hosts must also present a matching DNS SAN.
    require_onion_san: bool,
}

impl OnionOrSpiffeVerifier {
    fn new(
        roots: RootCertStore,
        expected_spiffe: String,
        require_onion_san: bool,
    ) -> Result<Self, DomainError> {
        if expected_spiffe.trim().is_empty() || !expected_spiffe.starts_with("spiffe://") {
            return Err(DomainError::AuthRejected(
                "VAULT_TLS_PEER_SPIFFE_ID must be a spiffe:// URI for onion/SPIFFE verify".into(),
            ));
        }
        let inner = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| DomainError::AuthRejected(format!("peer TLS verifier: {e}")))?;
        Ok(Self {
            inner,
            expected_spiffe,
            require_onion_san,
        })
    }

    fn spiffe_ok(&self, uris: &[String]) -> bool {
        uris.iter().any(|u| u == &self.expected_spiffe)
    }

    fn onion_san_ok(host: &str, dns_sans: &[String]) -> bool {
        host.ends_with(".onion")
            && dns_sans
                .iter()
                .any(|d| d.eq_ignore_ascii_case(host))
    }

    /// AND semantics: SPIFFE always required; onion host additionally needs matching DNS SAN.
    fn identity_ok(
        &self,
        end_entity: &CertificateDer<'_>,
        server_name: &ServerName<'_>,
    ) -> Result<bool, RustlsError> {
        let (uris, dns) = extract_sans(end_entity.as_ref()).map_err(|e| {
            RustlsError::InvalidCertificate(CertificateError::Other(rustls::OtherError(Arc::new(
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
            ))))
        })?;
        if !self.spiffe_ok(&uris) {
            return Ok(false);
        }
        let host = server_name_host(server_name);
        if self.require_onion_san && host.ends_with(".onion") {
            return Ok(Self::onion_san_ok(&host, &dns));
        }
        Ok(true)
    }
}

impl std::fmt::Debug for OnionOrSpiffeVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionOrSpiffeVerifier")
            .field("expected_spiffe", &self.expected_spiffe)
            .field("require_onion_san", &self.require_onion_san)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for OnionOrSpiffeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(v) => {
                if self.identity_ok(end_entity, server_name)? {
                    Ok(v)
                } else {
                    Err(RustlsError::InvalidCertificate(
                        CertificateError::NotValidForName,
                    ))
                }
            }
            Err(err) if name_error(&err) => {
                // Chain already validated by inner; name missed — require SPIFFE (+ onion SAN).
                if self.identity_ok(end_entity, server_name)? {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(err)
                }
            }
            Err(err) => Err(err),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verify_modes() {
        let id = "spiffe://kerosene.lab/vault/server";
        assert_eq!(
            TlsPeerVerifyPolicy::parse("hostname", id),
            Some(TlsPeerVerifyPolicy::Hostname)
        );
        assert_eq!(
            TlsPeerVerifyPolicy::parse("spiffe", id),
            Some(TlsPeerVerifyPolicy::Spiffe {
                expected: id.into()
            })
        );
        assert_eq!(
            TlsPeerVerifyPolicy::parse("onion_or_spiffe", id),
            Some(TlsPeerVerifyPolicy::OnionOrSpiffe {
                expected: id.into()
            })
        );
    }

    #[test]
    fn onion_san_match_is_case_insensitive() {
        assert!(OnionOrSpiffeVerifier::onion_san_ok(
            "abc.onion",
            &["ABC.onion".into(), "localhost".into()]
        ));
        assert!(!OnionOrSpiffeVerifier::onion_san_ok(
            "abc.onion",
            &["localhost".into()]
        ));
        assert!(!OnionOrSpiffeVerifier::onion_san_ok(
            "vault-1",
            &["vault-1".into()]
        ));
    }
}
