use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use kerosene_vault::application::{BlobStorePort, LedgerPort, ReleaseStorePort};
use kerosene_vault::bootstrap::{VaultConfig, VaultRuntime};
use kerosene_vault::domain::{BucketKind, ContentHash, NodeId, SettlementIntent};

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

    let group = runtime.threshold.group();
    eprintln!(
        "kerosene-vault F9 economy node={} listen={} attestation={} ceremony={} stub={} n={} t={} online={} timelock_scale={} hardened={} open_economy={}",
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
        runtime.config.open_economy
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
                let mut buf = [0u8; 8192];
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

    if path.len() > 512 {
        return (
            "414 URI Too Long",
            r#"{"error":"request rejected: path too long"}"#.into(),
        );
    }
    if path.contains("..") {
        return (
            "400 Bad Request",
            r#"{"error":"request rejected: path traversal"}"#.into(),
        );
    }

    match (method, path) {
        ("GET", "/") | ("GET", "/health") => match runtime.get_health.execute() {
            Ok(h) => ("200 OK", h.to_json()),
            Err(e) => ("500 Internal Server Error", format!(r#"{{"error":"{e}"}}"#)),
        },
        ("GET", "/ledger") => match runtime.get_ledger.execute() {
            Ok(s) => ("200 OK", s.to_json()),
            Err(e) => ("500 Internal Server Error", format!(r#"{{"error":"{e}"}}"#)),
        },
        ("GET", "/threshold") => {
            let g = runtime.threshold.group();
            (
                "200 OK",
                format!(
                    r#"{{"n":{},"t":{},"commitment":"{}","scheme":"lab-shamir-threshold-v1","online":{}}}"#,
                    g.n, g.t, g.commitment, runtime.online.count
                ),
            )
        }
        ("GET", "/release/allowlist") => match runtime.get_allowlist.execute() {
            Ok(entries) => {
                let body = entries
                    .iter()
                    .map(|e| e.to_json())
                    .collect::<Vec<_>>()
                    .join(",");
                ("200 OK", format!("[{body}]"))
            }
            Err(e) => ("500 Internal Server Error", format!(r#"{{"error":"{e}"}}"#)),
        },
        ("GET", path) if path.starts_with("/release/check-hb/") => {
            let hb_raw = path.trim_start_matches("/release/check-hb/");
            match ContentHash::parse(hb_raw) {
                Ok(hb) => match runtime.get_allowlist.require_hb(&hb) {
                    Ok(()) => ("200 OK", r#"{"allowlisted":true}"#.into()),
                    Err(e) => ("403 Forbidden", format!(r#"{{"error":"{e}"}}"#)),
                },
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        ("GET", path) if path.starts_with("/release/") => {
            let id = path.trim_start_matches("/release/");
            match runtime.release_mesh.get_candidate(id) {
                Ok(c) => ("200 OK", c.to_json()),
                Err(e) => ("404 Not Found", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
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
        ("POST", path) if path.starts_with("/sign/") => {
            let rest = path.trim_start_matches("/sign/");
            let mut segs = rest.splitn(2, '/');
            let session_id = segs.next().unwrap_or("");
            let message_hash = segs.next().unwrap_or("");
            if session_id.is_empty() || message_hash.is_empty() {
                return (
                    "400 Bad Request",
                    r#"{"error":"usage /sign/{session_id}/{message_hash}"}"#.into(),
                );
            }
            match runtime
                .sign_message
                .run_lab_quorum_sign(session_id, message_hash)
            {
                Ok(sig) => ("200 OK", sig.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        // /release/propose/{id}/{source_label}/{council_csv}
        ("POST", path) if path.starts_with("/release/propose/") => {
            let rest = path.trim_start_matches("/release/propose/");
            let mut segs = rest.splitn(3, '/');
            let id = segs.next().unwrap_or("");
            let source_label = segs.next().unwrap_or("");
            let council_csv = segs.next().unwrap_or("");
            if id.is_empty() || source_label.is_empty() || council_csv.is_empty() {
                return (
                    "400 Bad Request",
                    r#"{"error":"usage /release/propose/{id}/{source_label}/{council_csv}"}"#.into(),
                );
            }
            let council = council_csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            match runtime
                .propose_release
                .execute(id, source_label.as_bytes(), council)
            {
                Ok(c) => ("200 OK", c.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        // /release/propose-tampered/... — lab pentest only
        ("POST", path) if path.starts_with("/release/propose-tampered/") => {
            if !runtime.config.lab_endpoints_enabled() {
                return (
                    "403 Forbidden",
                    r#"{"error":"lab flag forbidden outside lab: propose-tampered"}"#.into(),
                );
            }
            let rest = path.trim_start_matches("/release/propose-tampered/");
            let mut segs = rest.splitn(4, '/');
            let id = segs.next().unwrap_or("");
            let source_label = segs.next().unwrap_or("");
            let evil_hb = segs.next().unwrap_or("");
            let council_csv = segs.next().unwrap_or("");
            if id.is_empty() || source_label.is_empty() || evil_hb.is_empty() || council_csv.is_empty()
            {
                return (
                    "400 Bad Request",
                    r#"{"error":"usage /release/propose-tampered/{id}/{source}/{evil_hb}/{council}"}"#
                        .into(),
                );
            }
            let hs = ContentHash::from_bytes(source_label.as_bytes());
            let _ = runtime.release_mesh.put(&hs, source_label.as_bytes());
            let hb = match ContentHash::parse(evil_hb) {
                Ok(h) => h,
                Err(e) => return ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            };
            let council = council_csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            match runtime
                .propose_release
                .execute_with_hashes(id, hs, hb, council)
            {
                Ok(c) => ("200 OK", c.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        // /release/rebuild/{id}/{vault_id}
        ("POST", path) if path.starts_with("/release/rebuild/") => {
            let rest = path.trim_start_matches("/release/rebuild/");
            let mut segs = rest.splitn(2, '/');
            let id = segs.next().unwrap_or("");
            let vault_id = segs.next().unwrap_or("");
            let vault = match NodeId::new(vault_id) {
                Ok(v) => v,
                Err(e) => return ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            };
            match runtime.rebuild_release.execute(id, &vault) {
                Ok(c) => ("200 OK", c.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        ("POST", path) if path.starts_with("/release/cosign/") => {
            let id = path.trim_start_matches("/release/cosign/");
            match runtime.cosign_release.execute(id) {
                Ok(c) => ("200 OK", c.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        ("POST", path) if path.starts_with("/release/activate/") => {
            let id = path.trim_start_matches("/release/activate/");
            match runtime.activate_release.execute(id) {
                Ok(e) => ("200 OK", e.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        // /intent/gate/{id}/{bucket}/{destination}/{amount_sats}
        ("POST", path) if path.starts_with("/intent/gate/") => {
            let rest = path.trim_start_matches("/intent/gate/");
            let mut segs = rest.splitn(4, '/');
            let id = segs.next().unwrap_or("");
            let bucket_raw = segs.next().unwrap_or("");
            let destination = segs.next().unwrap_or("");
            let amount_raw = segs.next().unwrap_or("");
            if id.is_empty()
                || bucket_raw.is_empty()
                || destination.is_empty()
                || amount_raw.is_empty()
            {
                return (
                    "400 Bad Request",
                    r#"{"error":"usage /intent/gate/{id}/{bucket}/{destination}/{amount}"}"#.into(),
                );
            }
            let bucket = match BucketKind::parse(bucket_raw) {
                Ok(b) => b,
                Err(e) => return ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            };
            let amount = match amount_raw.parse::<u64>() {
                Ok(a) => a,
                Err(_) => {
                    return (
                        "400 Bad Request",
                        r#"{"error":"amount must be u64 sats"}"#.into(),
                    )
                }
            };
            let policy_hash = match runtime.ledger.constitution() {
                Ok(c) => c.hash,
                Err(e) => return ("500 Internal Server Error", format!(r#"{{"error":"{e}"}}"#)),
            };
            let intent = match SettlementIntent::new(id, bucket, destination, amount, policy_hash) {
                Ok(i) => i,
                Err(e) => return ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            };
            match runtime.gate_intent.execute(intent) {
                Ok(r) => ("200 OK", r.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        ("POST", path) if path.starts_with("/profit/allocate/") => {
            let amount_raw = path.trim_start_matches("/profit/allocate/");
            let amount = match amount_raw.parse::<u64>() {
                Ok(a) => a,
                Err(_) => {
                    return (
                        "400 Bad Request",
                        r#"{"error":"usage /profit/allocate/{profit_sats}"}"#.into(),
                    )
                }
            };
            match runtime.allocate_profit.execute(amount) {
                Ok(a) => ("200 OK", a.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        ("GET", "/economy/status") => match runtime.get_economy.execute() {
            Ok(v) => ("200 OK", v.to_json()),
            Err(e) => ("500 Internal Server Error", format!(r#"{{"error":"{e}"}}"#)),
        },
        ("POST", path) if path.starts_with("/economy/accrue/") => {
            let amount_raw = path.trim_start_matches("/economy/accrue/");
            let amount = match amount_raw.parse::<u64>() {
                Ok(a) => a,
                Err(_) => {
                    return (
                        "400 Bad Request",
                        r#"{"error":"usage /economy/accrue/{profit_sats}"}"#.into(),
                    )
                }
            };
            match runtime.accrue_rewards.execute(amount) {
                Ok(a) => ("200 OK", a.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        // /economy/miner/upsert/{id}/{destination}/{uptime_bps}/{streak}/{bond}/{waiting}
        ("POST", path) if path.starts_with("/economy/miner/upsert/") => {
            let rest = path.trim_start_matches("/economy/miner/upsert/");
            let mut segs = rest.splitn(6, '/');
            let id = segs.next().unwrap_or("");
            let destination = segs.next().unwrap_or("");
            let uptime_raw = segs.next().unwrap_or("");
            let streak_raw = segs.next().unwrap_or("");
            let bond_raw = segs.next().unwrap_or("");
            let waiting_raw = segs.next().unwrap_or("0");
            if id.is_empty() || destination.is_empty() {
                return (
                    "400 Bad Request",
                    r#"{"error":"usage /economy/miner/upsert/{id}/{dest}/{uptime}/{streak}/{bond}/{waiting}"}"#.into(),
                );
            }
            let node_id = match NodeId::new(id) {
                Ok(n) => n,
                Err(e) => return ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            };
            let uptime = uptime_raw.parse::<u32>().unwrap_or(0);
            let streak = streak_raw.parse::<u32>().unwrap_or(0);
            let bond = bond_raw.parse::<u64>().unwrap_or(0);
            let waiting = matches!(waiting_raw, "1" | "true" | "TRUE" | "waiting");
            let op = kerosene_vault::domain::MinerOperator {
                node_id,
                payout_destination: destination.to_string(),
                uptime_bps_30d: uptime,
                attestation_streak_days: streak,
                bond_sats: bond,
                waiting,
            };
            match runtime.upsert_miner.execute(op) {
                Ok(()) => ("200 OK", r#"{"status":"upserted"}"#.into()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        ("POST", path) if path.starts_with("/economy/payout/propose/") => {
            let rest = path.trim_start_matches("/economy/payout/propose/");
            let mut segs = rest.splitn(2, '/');
            let amount_raw = segs.next().unwrap_or("");
            let prefix = segs.next().unwrap_or("miner-pay");
            let amount = match amount_raw.parse::<u64>() {
                Ok(a) => a,
                Err(_) => {
                    return (
                        "400 Bad Request",
                        r#"{"error":"usage /economy/payout/propose/{amount}/{prefix}"}"#.into(),
                    )
                }
            };
            match runtime.propose_miner_payouts.execute(amount, prefix) {
                Ok(p) => ("200 OK", p.to_json()),
                Err(e) => ("400 Bad Request", format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
    }
}
