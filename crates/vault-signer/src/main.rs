//! vault-signer — FROST signing daemon.
//!
//! A minimal Unix socket-based daemon for FROST threshold signing operations.
//! Has NO network dependencies — communicates only via Unix domain socket IPC
//! with vault-identityd and other local daemons.
//!
//! # Security
//! - No TCP listener or network I/O
//! - Share material encrypted at rest
//! - Key material zeroized after use
//! - All messages authenticated with session IDs

use std::collections::BTreeMap;
use std::path::PathBuf;

use vault_signer::dkg::DistributedKeyGeneration;
use vault_signer::ipc::{SignerIpc, SignerRequest, SignerResponse};
use vault_signer::session::SigningSessionManager;
use vault_signer::signer::{FrostSigner, SerializedCommitments, SerializedSignatureShare, SignerError};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let socket_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/run/kerosene/signer.sock".to_string());

    let store_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "/var/lib/kerosene/signer".to_string());

    eprintln!("vault-signer starting");
    eprintln!("  socket: {socket_path}");
    eprintln!("  store:  {store_path}");

    // Ensure store directory exists
    let store = PathBuf::from(&store_path);
    std::fs::create_dir_all(&store).expect("failed to create store directory");

    // Initialize session manager and key state
    let session_manager = std::sync::Mutex::new(SigningSessionManager::new(64));
    let key_store = std::sync::Mutex::new(KeyStore::new(&store));

    // IPC handler
    let handler = move |request: SignerRequest| -> SignerResponse {
        handle_request(request, &session_manager, &key_store)
    };

    let ipc = SignerIpc::new(&socket_path);
    if let Err(e) = ipc.serve_blocking(handler) {
        eprintln!("vault-signer error: {e}");
        std::process::exit(1);
    }
}

/// In-memory + disk key store for FROST key packages.
struct KeyStore {
    path: PathBuf,
    key_packages: Option<(Vec<frost_secp256k1::keys::KeyPackage>, frost_secp256k1::keys::PublicKeyPackage)>,
}

impl KeyStore {
    fn new(path: &PathBuf) -> Self {
        Self {
            path: path.clone(),
            key_packages: None,
        }
    }
}

fn handle_request(
    request: SignerRequest,
    session_manager: &std::sync::Mutex<SigningSessionManager>,
    _key_store: &std::sync::Mutex<KeyStore>,
) -> SignerResponse {
    match request {
        SignerRequest::Health => {
            let sessions = session_manager.lock().unwrap().active_count();
            SignerResponse::Health {
                status: "ok".into(),
                active_sessions: sessions,
            }
        }
        SignerRequest::CreateSession {
            message,
            participants,
            min_signers,
        } => {
            let msg_bytes = match hex::decode(&message) {
                Ok(m) => m,
                Err(e) => return SignerResponse::Error { message: format!("invalid hex: {e}") },
            };

            let identifiers: Result<Vec<_>, _> = participants
                .iter()
                .map(|b| {
                    if b.len() == 2 {
                        let arr: [u8; 2] = [b[0], b[1]];
                        Ok(frost_secp256k1::Identifier::try_from(u16::from_be_bytes(arr)))
                    } else {
                        // Try raw identifier
                        frost_secp256k1::Identifier::try_from(b[0] as u16)
                    }
                })
                .collect();

            let identifiers = match identifiers {
                Ok(v) => v,
                Err(e) => return SignerResponse::Error { message: format!("invalid identifier: {e}") },
            };

            let mut mgr = session_manager.lock().unwrap();
            match mgr.create_session(msg_bytes, identifiers, min_signers as usize) {
                Ok(session_id) => SignerResponse::SessionCreated {
                    session_id: session_id.0,
                },
                Err(e) => SignerResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        SignerRequest::SubmitCommitments {
            session_id,
            commitments: _serialized,
        } => {
            // Deserialize and submit commitments to the session
            let mut mgr = session_manager.lock().unwrap();
            let session = match mgr.get_session_mut(&vault_signer::session::SessionId(session_id.clone())) {
                Ok(s) => s,
                Err(e) => return SignerResponse::Error { message: e.to_string() },
            };

            // For now, accept the commitments as opaque data
            // Full deserialization requires the frost-secp256k1 commitment format
            if _serialized.is_empty() {
                return SignerResponse::Error {
                    message: "no commitments provided".into(),
                };
            }

            SignerResponse::CommitmentsAccepted
        }
        SignerRequest::SubmitSignatureShare {
            session_id,
            share: _serialized,
        } => {
            let mut mgr = session_manager.lock().unwrap();
            let session = match mgr.get_session_mut(&vault_signer::session::SessionId(session_id.clone())) {
                Ok(s) => s,
                Err(e) => return SignerResponse::Error { message: e.to_string() },
            };

            SignerResponse::SignatureShareAccepted
        }
        SignerRequest::GetSignature { session_id } => {
            let mgr = session_manager.lock().unwrap();
            let session = match mgr.get_session(&vault_signer::session::SessionId(session_id)) {
                Ok(s) => s,
                Err(e) => return SignerResponse::Error { message: e.to_string() },
            };

            if session.state != vault_signer::session::SessionState::Complete {
                return SignerResponse::Error {
                    message: "session not yet complete".into(),
                };
            }

            // Return a placeholder signature
            SignerResponse::Signature {
                signature: vec![],
            }
        }
        SignerRequest::SessionStatus { session_id } => {
            let mgr = session_manager.lock().unwrap();
            let session = match mgr.get_session(&vault_signer::session::SessionId(session_id)) {
                Ok(s) => s,
                Err(e) => return SignerResponse::Error { message: e.to_string() },
            };

            let state_str = match &session.state {
                vault_signer::session::SessionState::AwaitingCommitments => "awaiting_commitments",
                vault_signer::session::SessionState::AwaitingSignatureShares => "awaiting_signature_shares",
                vault_signer::session::SessionState::Complete => "complete",
                vault_signer::session::SessionState::Failed(_) => "failed",
            };

            SignerResponse::SessionStatus {
                state: state_str.into(),
                commitments_count: session.commitments.len(),
                shares_count: session.signature_shares.len(),
                min_signers: session.min_signers,
            }
        }
    }
}
