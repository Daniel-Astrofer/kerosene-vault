//! mTLS boot path: rustls server config + optional Axum listen with client cert.
//! Lab static_token remains the default; this exercises the Gate visualize path.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use kerosene_vault::adapters::{build_mtls_server_config, build_router};
use kerosene_vault::bootstrap::{AuthMode, CeremonyMode, DkgMode, ShareStoreMode, VaultConfig, VaultRuntime};
use kerosene_vault::domain::{AttestationMode, BitcoinNetwork, NodeId};

fn gen_lab_certs(dir: &Path) {
    std::fs::create_dir_all(dir).expect("tmpdir");
    let status = Command::new("bash")
        .env("VAULT_LAB_MTLS_OUT", dir)
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("scripts/gen_lab_mtls_certs.sh"),
        )
        .status()
        .expect("run gen_lab_mtls_certs.sh");
    assert!(status.success(), "cert generation failed: {status}");
}

fn lab_mtls_cfg(listen: &str, certs: &Path, data_dir: &Path) -> VaultConfig {
    VaultConfig {
        node_id: NodeId::new("vault-mtls-1").unwrap(),
        attestation_mode: AttestationMode::Sim,
        listen_addr: listen.into(),
        lab_root: "kerosene-lab-mtls".into(),
        seed_peers: vec![],
        refuse_sim: false,
        genesis_n: Some(2),
        online_count: Some(2),
        lab_timelock_scale: 0,
        lab_timelock_env_set: false,
        lab_council_n: 3,
        lab_min_rebuilds: 3,
        hardened: false,
        attestation_staging_stub: false,
        ceremony_mode: CeremonyMode::Lab,
        open_economy: false,
        bitcoin_network: BitcoinNetwork::Testnet3,
        auth_mode: AuthMode::MutualTls,
        vault_token: None,
        tls_cert_path: Some(certs.join("vault-server.crt").display().to_string()),
        tls_key_path: Some(certs.join("vault-server.key").display().to_string()),
        tls_client_ca_path: Some(certs.join("ca.crt").display().to_string()),
        share_store_mode: ShareStoreMode::AeadDisk,
        share_passphrase: Some("kerosene-vault-lab-passphrase".into()),
        data_dir: Some(data_dir.display().to_string()),
        anti_nonce_shared_dir: None,
        measurement_pin_hex: None,
        dealer_requested: true,
        dkg_mode: DkgMode::DealerLab,
    }
}

#[test]
fn mtls_server_config_loads_from_lab_certs() {
    let root = tempfile_dir("mtls-cfg");
    let certs = root.join("certs");
    gen_lab_certs(&certs);
    let cfg = build_mtls_server_config(
        &certs.join("vault-server.crt"),
        &certs.join("vault-server.key"),
        &certs.join("ca.crt"),
    )
    .expect("build_mtls_server_config");
    assert!(!cfg.alpn_protocols.is_empty());
}

#[test]
fn mtls_runtime_boots_in_lab_visualize() {
    let root = tempfile_dir("mtls-runtime");
    let certs = root.join("certs");
    let data = root.join("data");
    gen_lab_certs(&certs);
    let cfg = lab_mtls_cfg("127.0.0.1:0", &certs, &data);
    assert!(cfg.validate_hygiene().is_ok());
    let runtime = VaultRuntime::build(cfg).expect("VaultRuntime::build with mTLS");
    assert_eq!(runtime.auth.mode_name(), "mtls");
    assert!(!runtime.auth.is_static_token());
    assert!(runtime.auth.authorize(None).is_ok());
    assert!(runtime.auth.authorize(Some("token")).is_err());
}

#[tokio::test]
async fn mtls_axum_health_requires_client_cert() {
    let root = tempfile_dir("mtls-serve");
    let certs = root.join("certs");
    let data = root.join("data");
    gen_lab_certs(&certs);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);

    let cfg = lab_mtls_cfg(&addr.to_string(), &certs, &data);
    let runtime = Arc::new(VaultRuntime::build(cfg).expect("runtime"));
    let app = build_router(runtime.clone());

    let (cert, key, ca) = runtime.config.require_mtls_paths().unwrap();
    let server_config =
        build_mtls_server_config(Path::new(cert), Path::new(key), Path::new(ca)).unwrap();
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(server_config);

    let serve = tokio::spawn(async move {
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await
            .expect("serve");
    });

    // Wait briefly for bind.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let client_pem = concat_pem(
        &certs.join("vault-client.crt"),
        &certs.join("vault-client.key"),
    );
    let identity = reqwest::Identity::from_pem(&client_pem).expect("client identity");
    let ca_cert =
        reqwest::Certificate::from_pem(&std::fs::read(certs.join("ca.crt")).unwrap()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let url = format!("https://{addr}/v1/health");
    let resp = client.get(&url).send().await.expect("health with client cert");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("vault-mtls-1") || body.contains("ready") || body.contains("status"));

    // No client cert → handshake / request must fail.
    let plain = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(certs.join("ca.crt")).unwrap()).unwrap(),
        )
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let no_cert = plain.get(&url).send().await;
    assert!(
        no_cert.is_err(),
        "expected TLS failure without client cert, got {no_cert:?}"
    );

    serve.abort();
}

fn concat_pem(cert: &Path, key: &Path) -> Vec<u8> {
    let mut out = std::fs::read(cert).unwrap();
    out.push(b'\n');
    out.extend(std::fs::read(key).unwrap());
    out
}

fn tempfile_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kerosene-vault-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[allow(dead_code)]
fn _addr_type_check(a: SocketAddr) -> SocketAddr {
    a
}
