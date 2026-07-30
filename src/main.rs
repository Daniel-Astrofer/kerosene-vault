//! Thin binary wrapper — delegates all logic to `vault_core`.
//!
//! The full vault implementation now lives in `crates/vault-core/`.
//! This entry point calls `vault_core::bootstrap::VaultRuntime::build()`
//! and starts the Axum HTTP server.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsAcceptor;
use vault_core::adapters::{build_mtls_server_config, build_router, spawn_admin_unix_socket, PeerCertAcceptor};
use vault_core::bootstrap::{AuthMode, VaultConfig, VaultRuntime};

#[tokio::main]
async fn main() {
    let config = match VaultConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
    let auth_mode = config.auth_mode;
    let listen_addr = config.listen_addr.clone();
    let runtime = match VaultRuntime::build(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("runtime error: {e}");
            std::process::exit(1);
        }
    };
    let runtime = Arc::new(runtime);

    let group = runtime.threshold.group();
    eprintln!(
        "kerosene-vault node={} listen={} tier={} tee_available={} attestation={} ceremony={} stub={} n={} t={} online={} timelock_scale={} hardened={} open_economy={} bitcoin={} auth={}",
        runtime.config.node_id,
        runtime.config.listen_addr,
        runtime.config.node_tier.as_str(),
        runtime.config.tee_available,
        runtime.config.attestation_mode.as_str(),
        runtime.config.ceremony_mode.as_str(),
        runtime.config.attestation_staging_stub,
        group.n,
        group.t,
        runtime.online.online_count(),
        runtime.config.effective_lab_timelock_scale(),
        runtime.config.hardened,
        runtime.config.open_economy,
        runtime.config.bitcoin_network.as_str(),
        runtime.config.auth_mode.as_str()
    );

    // --- Admin API socket ---
    if let Some(ref admin_socket) = runtime.config.admin_unix_socket_path {
        match spawn_admin_unix_socket(runtime.clone(), admin_socket).await {
            Ok(()) => {
                eprintln!("admin_api=unix socket_path={admin_socket}");
            }
            Err(e) => {
                eprintln!("admin_api error: failed to start Unix socket listener: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("admin_api=disabled (set VAULT_ADMIN_UNIX_SOCKET to enable)");
    }

    let app = build_router(runtime.clone());

    match auth_mode {
        AuthMode::MutualTls => {
            let (cert, key, ca) = match runtime.config.require_mtls_paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("config error: {e}");
                    std::process::exit(1);
                }
            };
            let server_config = match build_mtls_server_config(Path::new(cert), Path::new(key), Path::new(ca)) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("mTLS config error: {e}");
                    std::process::exit(1);
                }
            };
            let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
            let acceptor = PeerCertAcceptor::new(RustlsAcceptor::new(rustls_config));
            let addr: SocketAddr = match listen_addr.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("bind address error: {e}");
                    std::process::exit(1);
                }
            };
            eprintln!("tls=mtls (client cert required; SPIFFE principal binding on)");
            if let Err(e) = axum_server::bind(addr).acceptor(acceptor).serve(app.into_make_service()).await {
                eprintln!("server error: {e}");
                std::process::exit(1);
            }
        }
        AuthMode::StaticToken => {
            eprintln!("tls=off (lab static_token)");
            let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("bind error: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("server error: {e}");
                std::process::exit(1);
            }
        }
    }
}
