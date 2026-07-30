use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum_server::tls_rustls::RustlsAcceptor;
use kerosene_vault::adapters::{
    build_admin_router, build_mtls_server_config, build_router, PeerCertAcceptor,
};
use kerosene_vault::bootstrap::{AuthMode, VaultConfig, VaultRuntime};

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
        "kerosene-vault lab-p0 node={} listen={} tier={} tee_available={} attestation={} ceremony={} stub={} n={} t={} online={} timelock_scale={} hardened={} open_economy={} bitcoin={} auth={}",
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

    let app = build_router(runtime.clone());
    if let Some(socket_path) = admin_socket_path() {
        let admin_runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_admin_socket(socket_path, admin_runtime).await {
                eprintln!("admin socket error: {error}");
                std::process::exit(1);
            }
        });
    }

    match auth_mode {
        AuthMode::MutualTls => {
            let (cert, key, ca) = match runtime.config.require_mtls_paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("config error: {e}");
                    std::process::exit(1);
                }
            };
            let server_config = match build_mtls_server_config(Path::new(cert), Path::new(key), Path::new(ca))
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("mTLS config error: {e}");
                    std::process::exit(1);
                }
            };
            let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
            // Inject verified client leaf into request extensions for SPIFFE→role binding.
            let acceptor = PeerCertAcceptor::new(RustlsAcceptor::new(rustls_config));
            let addr: SocketAddr = match listen_addr.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("bind address error: {e}");
                    std::process::exit(1);
                }
            };
            eprintln!("tls=mtls (client cert required; SPIFFE principal binding on)");
            if let Err(e) = axum_server::bind(addr)
                .acceptor(acceptor)
                .serve(app.into_make_service())
                .await
            {
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

fn admin_socket_path() -> Option<PathBuf> {
    std::env::var_os("VAULT_ADMIN_UNIX_SOCKET")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(unix)]
async fn serve_admin_socket(
    path: PathBuf,
    runtime: Arc<VaultRuntime>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::PermissionsExt;

    remove_stale_admin_socket(&path)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
    eprintln!("admin=unix socket={} mode=0660", path.display());
    axum::serve(listener, build_admin_router(runtime)).await?;
    Ok(())
}

#[cfg(unix)]
fn remove_stale_admin_socket(
    path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::FileTypeExt;

    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "refusing to replace non-socket admin path {}",
                path.display()
            )
            .into());
        }
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(not(unix))]
async fn serve_admin_socket(
    _path: PathBuf,
    _runtime: Arc<VaultRuntime>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("VAULT_ADMIN_UNIX_SOCKET is only supported on Unix".into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn admin_socket_never_replaces_a_regular_file() {
        let root = std::env::temp_dir().join(format!(
            "kerosene-vault-admin-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("vault-admin.sock");
        std::fs::write(&path, b"do not replace").unwrap();

        assert!(remove_stale_admin_socket(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"do not replace");

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
