use std::sync::Arc;

use kerosene_vault::adapters::build_router;
use kerosene_vault::bootstrap::{VaultConfig, VaultRuntime};

#[tokio::main]
async fn main() {
    let config = match VaultConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
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
        "kerosene-vault lab-p0 node={} listen={} attestation={} ceremony={} stub={} n={} t={} online={} timelock_scale={} hardened={} open_economy={} bitcoin={}",
        runtime.config.node_id,
        runtime.config.listen_addr,
        runtime.config.attestation_mode.as_str(),
        runtime.config.ceremony_mode.as_str(),
        runtime.config.attestation_staging_stub,
        group.n,
        group.t,
        runtime.online.count,
        runtime.config.effective_lab_timelock_scale(),
        runtime.config.hardened,
        runtime.config.open_economy,
        runtime.config.bitcoin_network.as_str()
    );

    let app = build_router(runtime.clone());
    let listener = match tokio::net::TcpListener::bind(&runtime.config.listen_addr).await {
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
