//! vault-identityd — identity daemon library.
//!
//! Provides `IdentityDaemon` for managing vault identity lifecycle and
//! `IdentityServer` for exposing identity operations over a Unix socket
//! via an Axum HTTP server.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;
use tracing::{error, info, warn};
use vault_identity_core::error::IdentityError;
use vault_identity_core::hybrid_identity::HybridKeyPair;
use vault_identity_core::VaultIdentity;

// ---------------------------------------------------------------------------
// Identity daemon
// ---------------------------------------------------------------------------

/// The identity daemon manages vault cryptographic identity persistence.
pub struct IdentityDaemon {
    node_id: String,
    store_path: PathBuf,
    identity: Option<HybridKeyPair>,
}

impl IdentityDaemon {
    /// Initialize a new identity daemon.
    ///
    /// Creates the store directory if it does not exist.
    pub async fn new(node_id: &str, store_path: &str) -> Result<Self, IdentityError> {
        let path = PathBuf::from(store_path);
        fs::create_dir_all(&path)
            .map_err(|e| IdentityError::InternalError(format!("failed to create store dir: {e}")))?;

        Ok(Self {
            node_id: node_id.to_string(),
            store_path: path,
            identity: None,
        })
    }

    /// Path to the identity storage file.
    fn identity_file(&self) -> PathBuf {
        self.store_path.join(format!("identity-{}.bin", self.node_id))
    }

    /// Load existing identity from disk or generate a fresh one.
    pub async fn load_or_generate_identity(&mut self) -> Result<&HybridKeyPair, IdentityError> {
        if let Some(ref id) = self.identity {
            return Ok(id);
        }

        let file = self.identity_file();
        if file.exists() {
            info!("loading identity from {}", file.display());
            let bytes = fs::read(&file)
                .map_err(|e| IdentityError::DeserializationFailed(format!("read identity file: {e}")))?;
            let kp = HybridKeyPair::from_bytes(&bytes)?;
            self.identity = Some(kp);
        } else {
            info!("generating new hybrid identity for node {}", self.node_id);
            let kp = HybridKeyPair::generate(&self.node_id)?;
            let bytes = kp.to_bytes();
            fs::write(&file, &bytes)
                .map_err(|e| IdentityError::SerializationFailed(format!("write identity file: {e}")))?;
            // Set restrictive permissions on the key file
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(&file) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o600);
                    let _ = fs::set_permissions(&file, perms);
                }
            }
            info!("identity persisted to {}", file.display());
            self.identity = Some(kp);
        }

        Ok(self.identity.as_ref().unwrap())
    }

    /// Get the current identity (must be loaded first).
    pub fn current_identity(&self) -> Result<&HybridKeyPair, IdentityError> {
        self.identity.as_ref().ok_or(IdentityError::IdentityNotFound)
    }

    /// Rotate identity keys (generate new, archive old).
    pub async fn rotate_identity(&mut self) -> Result<&HybridKeyPair, IdentityError> {
        info!("rotating identity for node {}", self.node_id);

        // Archive existing identity if present
        let file = self.identity_file();
        if file.exists() {
            let archive = self.store_path.join(format!(
                "identity-{}.bak.{}",
                self.node_id,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            ));
            fs::rename(&file, &archive)
                .map_err(|e| IdentityError::RotationFailed(format!("archive old identity: {e}")))?;
            info!("archived old identity to {}", archive.display());
        }

        // Generate new identity
        let kp = HybridKeyPair::generate(&self.node_id)?;
        let bytes = kp.to_bytes();
        fs::write(&file, &bytes)
            .map_err(|e| IdentityError::RotationFailed(format!("write new identity: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&file) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = fs::set_permissions(&file, perms);
            }
        }

        self.identity = Some(kp);
        info!("identity rotated and persisted to {}", file.display());
        Ok(self.identity.as_ref().unwrap())
    }

    /// Sign a message with the current identity (hybrid: both Ed25519 + ML-DSA-65).
    pub fn sign(&self, message: &[u8]) -> Result<vault_identity_core::hybrid_identity::HybridSignature, IdentityError> {
        let id = self.current_identity()?;
        id.sign_hybrid(message)
    }
}

// ---------------------------------------------------------------------------
// IPC types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub node_id: String,
    pub ed25519_public: String, // hex
    pub ml_dsa65_public: String, // hex
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub message: String, // hex-encoded
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub ed25519_signature: String,  // hex
    pub ml_dsa65_signature: String, // hex
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateRequest {
    pub node_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub node_id: String,
    pub has_identity: bool,
    pub identity_created_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// Identity server (Axum)
// ---------------------------------------------------------------------------

/// Auth token validation constant.
const AUTH_HEADER: &str = "X-Vault-Auth-Token";

#[derive(Clone)]
pub struct IdentityServer {
    daemon: Arc<tokio::sync::Mutex<IdentityDaemon>>,
    socket_path: String,
    auth_token: Option<String>,
}

impl IdentityServer {
    pub fn new(daemon: IdentityDaemon, socket_path: &str, auth_token: Option<&str>) -> Self {
        Self {
            daemon: Arc::new(tokio::sync::Mutex::new(daemon)),
            socket_path: socket_path.to_string(),
            auth_token: auth_token.map(|s| s.to_string()),
        }
    }

    fn check_auth(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        if let Some(ref expected) = self.auth_token {
            match headers.get(AUTH_HEADER).and_then(|v| v.to_str().ok()) {
                Some(token) if token == expected => Ok(()),
                _ => {
                    warn!("unauthorized IPC request (missing or invalid auth token)");
                    Err(StatusCode::UNAUTHORIZED)
                }
            }
        } else {
            Ok(()) // No auth token configured — allow all IPC
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let app = self.router();

        // Remove existing socket file if present
        let _ = fs::remove_file(&self.socket_path);

        let listener = UnixListener::bind(&self.socket_path)?;

        // Set restrictive permissions on the socket
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&self.socket_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = fs::set_permissions(&self.socket_path, perms);
            }
        }

        info!("identity server listening on {}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let app = app.clone();
                    tokio::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(stream);
                        if let Err(e) = axum::serve(io, app).await {
                            error!("connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn router(&self) -> Router {
        let state = AppState {
            daemon: self.daemon.clone(),
            auth_token: self.auth_token.clone(),
        };

        Router::new()
            .route("/v1/identities/generate", post(handle_generate))
            .route("/v1/identities/current", get(handle_current))
            .route("/v1/identities/rotate", post(handle_rotate))
            .route("/v1/identities/certificate", get(handle_certificate))
            .route("/v1/identities/sign", post(handle_sign))
            .route("/v1/health", get(handle_health))
            .with_state(state)
    }
}

#[derive(Clone)]
struct AppState {
    daemon: Arc<tokio::sync::Mutex<IdentityDaemon>>,
    auth_token: Option<String>,
}

impl AppState {
    fn check_auth(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        if let Some(ref expected) = self.auth_token {
            match headers.get(AUTH_HEADER).and_then(|v| v.to_str().ok()) {
                Some(token) if token == expected => Ok(()),
                _ => {
                    warn!("unauthorized IPC request");
                    Err(StatusCode::UNAUTHORIZED)
                }
            }
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_generate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = state.check_auth(&headers) {
        return (status, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
    }

    let mut daemon = state.daemon.lock().await;
    match daemon.load_or_generate_identity().await {
        Ok(id) => {
            let info = IdentityInfo {
                node_id: id.node_id.clone(),
                ed25519_public: hex::encode(id.ed25519.verifying_key_bytes()),
                ml_dsa65_public: hex::encode(id.ml_dsa65.public_key()),
                created_at: id.created_at,
                expires_at: id.expires_at,
            };
            (StatusCode::OK, Json(serde_json::json!(info))).into_response()
        }
        Err(e) => {
            error!("generate identity failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

async fn handle_current(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = state.check_auth(&headers) {
        return (status, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
    }

    let daemon = state.daemon.lock().await;
    match daemon.current_identity() {
        Ok(id) => {
            let info = IdentityInfo {
                node_id: id.node_id.clone(),
                ed25519_public: hex::encode(id.ed25519.verifying_key_bytes()),
                ml_dsa65_public: hex::encode(id.ml_dsa65.public_key()),
                created_at: id.created_at,
                expires_at: id.expires_at,
            };
            (StatusCode::OK, Json(serde_json::json!(info))).into_response()
        }
        Err(IdentityError::IdentityNotFound) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "identity not found"}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}

async fn handle_rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = state.check_auth(&headers) {
        return (status, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
    }

    let mut daemon = state.daemon.lock().await;
    match daemon.rotate_identity().await {
        Ok(id) => {
            let info = IdentityInfo {
                node_id: id.node_id.clone(),
                ed25519_public: hex::encode(id.ed25519.verifying_key_bytes()),
                ml_dsa65_public: hex::encode(id.ml_dsa65.public_key()),
                created_at: id.created_at,
                expires_at: id.expires_at,
            };
            (StatusCode::OK, Json(serde_json::json!(info))).into_response()
        }
        Err(e) => {
            error!("rotate identity failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}

async fn handle_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = state.check_auth(&headers) {
        return (status, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
    }

    let daemon = state.daemon.lock().await;
    match daemon.current_identity() {
        Ok(id) => {
            // Return CSPRNG-based SPIFFE SVID info (Certificate generation expects x509 infra)
            // In production, this would be wired to SPIRE agent API.
            // For now, return the identity's public key material for SPIFFE binding.
            let svid_info = serde_json::json!({
                "note": "SPIFFE SVID certificate — placeholder (wire to SPIRE agent for full x509)",
                "spiffe_id": format!("spiffe://kerosene.lab/vault/{}", id.node_id),
                "ed25519_public": hex::encode(id.ed25519.verifying_key_bytes()),
                "ml_dsa65_public": hex::encode(id.ml_dsa65.public_key()),
            });
            (StatusCode::OK, Json(svid_info)).into_response()
        }
        Err(IdentityError::IdentityNotFound) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "identity not found"}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}

async fn handle_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SignRequest>,
) -> impl IntoResponse {
    if let Err(status) = state.check_auth(&headers) {
        return (status, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
    }

    let message = match hex::decode(&req.message) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("invalid hex message: {e}")})),
            )
                .into_response();
        }
    };

    let daemon = state.daemon.lock().await;
    match daemon.sign(&message) {
        Ok(sig) => {
            let resp = SignResponse {
                ed25519_signature: hex::encode(&sig.ed25519),
                ml_dsa65_signature: hex::encode(&sig.ml_dsa65),
            };
            (StatusCode::OK, Json(serde_json::json!(resp))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}

async fn handle_health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = state.check_auth(&headers) {
        return (status, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
    }

    let daemon = state.daemon.lock().await;
    let (has_identity, created_at) = match daemon.current_identity() {
        Ok(id) => (true, Some(id.created_at)),
        Err(_) => (false, None),
    };

    let health = HealthResponse {
        status: "ok".to_string(),
        node_id: daemon.node_id.clone(),
        has_identity,
        identity_created_at: created_at,
    };

    (StatusCode::OK, Json(serde_json::json!(health))).into_response()
}
