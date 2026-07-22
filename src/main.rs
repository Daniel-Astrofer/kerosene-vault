use std::io::{Read, Write};
use std::net::TcpListener;

use kerosene_vault::bootstrap::{VaultConfig, VaultRuntime};

fn main() {
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

    eprintln!(
        "kerosene-vault F1 skeleton node={} listen={} attestation={}",
        runtime.config.node_id,
        runtime.config.listen_addr,
        runtime.config.attestation_mode.as_str()
    );

    let listener = match TcpListener::bind(&runtime.config.listen_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind error: {e}");
            std::process::exit(1);
        }
    };

    for conn in listener.incoming() {
        match conn {
            Ok(mut socket) => {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf);
                let body = match runtime.get_health.execute() {
                    Ok(h) => h.to_json(),
                    Err(e) => format!(r#"{{"error":"{e}"}}"#),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes());
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}
