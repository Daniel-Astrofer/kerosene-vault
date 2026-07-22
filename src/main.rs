use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

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
    let runtime = Arc::new(runtime);

    eprintln!(
        "kerosene-vault F2 ledger node={} listen={} attestation={}",
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
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let (status, body) = handle_request(&runtime, &req);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes());
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}

fn handle_request(runtime: &VaultRuntime, req: &str) -> (&'static str, String) {
    let line = req.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    match (method, path) {
        ("GET", "/") | ("GET", "/health") => match runtime.get_health.execute() {
            Ok(h) => ("200 OK", h.to_json()),
            Err(e) => ("500 Internal Server Error", format!(r#"{{"error":"{e}"}}"#)),
        },
        ("GET", "/ledger") => match runtime.get_ledger.execute() {
            Ok(s) => ("200 OK", s.to_json()),
            Err(e) => ("500 Internal Server Error", format!(r#"{{"error":"{e}"}}"#)),
        },
        ("POST", path) if path.starts_with("/epoch/propose/") => {
            let id = path.trim_start_matches("/epoch/propose/");
            match runtime.propose_epoch.execute(id) {
                Ok(p) => ("200 OK", p.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        ("POST", path) if path.starts_with("/epoch/vote/") => {
            let id = path.trim_start_matches("/epoch/vote/");
            match runtime.vote_epoch.execute(id) {
                Ok(p) => ("200 OK", p.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        _ => (
            "404 Not Found",
            r#"{"error":"not found"}"#.to_string(),
        ),
    }
}
