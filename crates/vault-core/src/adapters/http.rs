//! Axum HTTP surface: `/v1/health` public; protected routes require auth —
//! `X-Vault-Token` when `VAULT_AUTH_MODE=static_token`, or verified client cert
//! when `VAULT_AUTH_MODE=mtls` (static token header refused).
//!
//! App-layer principal (Critical #3): mTLS SPIFFE/SAN → role (`kfe` vs `vault`);
//! routes are authorized by role (not “any CA leaf = full power”).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::adapters::SlidingWindowLimiter;
use crate::application::{bind_session_to_intent, BlobStorePort, BucketLedgerPort, LedgerPort, ReleaseStorePort};
use crate::bootstrap::{AuthMode, CeremonyMode, VaultRuntime};
use crate::domain::{
    assert_channels_taproot_bucket, assert_shared_taproot_bucket, validate_destination, BucketKind, ContentHash,
    NodeId, SettlementIntent,
};

fn json_err(e: impl std::fmt::Display) -> String {
    serde_json::json!({ "error": e.to_string() }).to_string()
}

async fn security_headers_mw(request: Request, next: Next) -> Response {
    let mut resp = next.run(request).await;
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("cache-control"),
        axum::http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-frame-options"),
        axum::http::HeaderValue::from_static("DENY"),
    );
    resp
}

#[derive(Clone)]
pub struct AppState {
    pub runtime: Arc<VaultRuntime>,
    pub auth_limiter: Arc<SlidingWindowLimiter>,
    pub prepare_limiter: Arc<SlidingWindowLimiter>,
}

pub fn build_router(runtime: Arc<VaultRuntime>) -> Router {
    let state = AppState {
        runtime: runtime.clone(),
        auth_limiter: Arc::new(SlidingWindowLimiter::auth_defaults()),
        prepare_limiter: Arc::new(SlidingWindowLimiter::prepare_defaults()),
    };
    let protected = Router::new()
        .route("/v1/sign", post(v1_sign))
        .route("/v1/financial-quorum", post(v1_financial_quorum))
        .route("/v1/financial-quorum/context", get(v1_financial_quorum_context))
        .route("/v1/admin/status", get(v1_admin_status))
        .route("/v1/admin/ceremony", get(v1_admin_ceremony))
        .route("/v1/intent", post(v1_intent))
        // Two-phase Intent (High #9): reserve → commit after success, release on failure.
        .route("/v1/intent/reserve", post(v1_intent_reserve))
        .route("/v1/intent/release", post(v1_intent_release))
        .route("/v1/intent/commit", post(v1_intent_commit))
        .route("/v1/bitcoin/deposit", get(v1_bitcoin_deposit))
        .route("/v1/bitcoin/sign-sighash", post(v1_bitcoin_sign_sighash))
        .route("/v1/bitcoin/sign-psbt", post(v1_bitcoin_sign_psbt))
        // Over-wire FROST DKG round exchange (auth via token or mTLS). No dealer.
        .route("/v1/dkg/round1", post(v1_dkg_round1))
        .route("/v1/dkg/round2", post(v1_dkg_round2))
        .route("/v1/dkg/round3", post(v1_dkg_round3))
        .route("/v1/dkg/status", get(v1_dkg_status))
        .route("/v1/dkg/tr/round1", post(v1_dkg_tr_round1))
        .route("/v1/dkg/tr/round2", post(v1_dkg_tr_round2))
        .route("/v1/dkg/tr/round3", post(v1_dkg_tr_round3))
        .route("/v1/dkg/tr/status", get(v1_dkg_tr_status))
        // Item 1.5: Wire-based Taproot FROST reshare routes
        .route("/v1/reshare/tr/round1", post(v1_reshare_tr_round1))
        .route("/v1/reshare/tr/round2", post(v1_reshare_tr_round2))
        .route("/v1/reshare/tr/finalize", post(v1_reshare_tr_finalize))
        .route("/v1/reshare/tr/status", get(v1_reshare_tr_status))
        .route("/v1/anti-nonce/prepare", post(v1_anti_nonce_prepare))
        // Legacy alias — same durable prepare semantics as `/prepare`.
        .route("/v1/anti-nonce/ingest", post(v1_anti_nonce_prepare))
        .route("/v1/intent/consume/prepare", post(v1_intent_consume_prepare))
        .route("/v1/day/advance", post(v1_day_advance))
        .route("/v1/day/vote", post(v1_day_vote))
        .route("/v1/day/current", get(v1_day_current))
        .route("/v1/reshare/trigger", post(v1_reshare_trigger))
        .route("/v1/frost/tr/commit", post(v1_frost_tr_commit))
        .route("/v1/frost/tr/sign-share", post(v1_frost_tr_sign_share))
        .route("/health", get(legacy_dispatch))
        .route("/ledger", get(legacy_dispatch))
        .route("/threshold", get(legacy_dispatch))
        .route("/economy/status", get(legacy_dispatch))
        .route("/release/allowlist", get(legacy_dispatch))
        .route("/release/{*rest}", get(legacy_dispatch).post(legacy_dispatch))
        .route("/epoch/{*rest}", post(legacy_dispatch))
        .route("/sign/{*rest}", post(legacy_dispatch))
        .route("/intent/{*rest}", post(legacy_dispatch))
        .route("/profit/{*rest}", post(legacy_dispatch))
        .route("/economy/{*rest}", post(legacy_dispatch))
        .route_layer(from_fn_with_state(state.clone(), require_token_mw));

    Router::new()
        .route("/v1/health", get(v1_health))
        .route("/v1/metrics", get(v1_metrics))
        .route("/", get(v1_health))
        .merge(protected)
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(axum::middleware::from_fn(security_headers_mw))
        .with_state(state)
}

async fn require_token_mw(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer_cert: Option<Extension<Option<crate::adapters::PeerClientCert>>>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let token = headers.get("X-Vault-Token").and_then(|v| v.to_str().ok());
    state.runtime.auth.authorize(token).map_err(|e| (StatusCode::UNAUTHORIZED, json_err(e)))?;

    let rate_key =
        headers.get("X-Vault-Node-Id").and_then(|v| v.to_str().ok()).unwrap_or(state.runtime.config.node_id.as_str());
    state.auth_limiter.check(rate_key).map_err(|e| (StatusCode::TOO_MANY_REQUESTS, json_err(e)))?;

    let allowed = crate::adapters::mesh_allowed_node_ids(
        state.runtime.config.node_id.as_str(),
        state.runtime.config.seed_peers.iter().map(|(id, _)| id.as_str()),
    );
    let peer_cert = peer_cert.and_then(|Extension(c)| c);
    let principal = if matches!(state.runtime.config.auth_mode, AuthMode::StaticToken) {
        crate::adapters::MeshPrincipal::lab_omnipotent(state.runtime.config.node_id.as_str())
    } else if let Some(cert) = peer_cert.as_ref() {
        cert.to_principal(state.runtime.config.node_id.as_str(), &allowed)
            .map_err(|e| (StatusCode::UNAUTHORIZED, json_err(e)))?
    } else {
        return Err((
            StatusCode::UNAUTHORIZED,
            json_err("auth rejected: mTLS client certificate required for mesh principal"),
        ));
    };

    if let Some(class) = crate::adapters::route_class_for_path(request.uri().path()) {
        if !principal.allows_route(class) {
            return Err((
                StatusCode::FORBIDDEN,
                json_err(format!(
                    "auth rejected: role {} cannot call {} ({})",
                    principal.role.as_str(),
                    request.uri().path(),
                    match class {
                        crate::adapters::RouteClass::KfeSettlement => "kfe settlement only",
                        crate::adapters::RouteClass::VaultPeer => "vault peer only",
                        crate::adapters::RouteClass::SharedOps => "shared ops",
                        crate::adapters::RouteClass::AdminRead => "vault operator read only",
                    }
                )),
            ));
        }
    }

    request.extensions_mut().insert(principal);
    Ok(next.run(request).await)
}

async fn v1_health(State(state): State<AppState>) -> impl IntoResponse {
    match state.runtime.get_health.execute() {
        Ok(h) => (StatusCode::OK, h.to_public_json()),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, json_err(e)),
    }
}

async fn v1_metrics(State(state): State<AppState>) -> impl IntoResponse {
    match state.runtime.get_metrics.execute() {
        Ok(body) => (StatusCode::OK, body),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, json_err(e)),
    }
}

async fn v1_admin_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let request_id = admin_request_id(&headers);
    match state.runtime.get_health.execute() {
        Ok(health) => (
            StatusCode::OK,
            serde_json::json!({
                "contract_version": "0.1.0",
                "request_id": request_id,
                "local_ready": health.local_ready,
                "financial_ready": health.financial_ready,
                "node_id": state.runtime.config.node_id.as_str(),
                "ceremony_mode": state.runtime.config.ceremony_mode.as_str(),
                "bitcoin_network": state.runtime.config.bitcoin_network.as_str()
            })
            .to_string(),
        ),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, json_err(error)),
    }
}

async fn v1_admin_ceremony(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let request_id = admin_request_id(&headers);
    (
        StatusCode::OK,
        serde_json::json!({
            "contract_version": "0.1.0",
            "request_id": request_id,
            "mode": state.runtime.config.ceremony_mode.as_str(),
            "node_id": state.runtime.config.node_id.as_str(),
            "genesis_members": state.runtime.genesis_roster.len(),
            "online_members": state.runtime.online.online_count(),
            "required_threshold": state.runtime.threshold.group().t,
            "financial_ready": state.runtime.online.online_count()
                >= state.runtime.threshold.group().t
        })
        .to_string(),
    )
}

fn admin_request_id(headers: &HeaderMap) -> String {
    headers
        .get("X-Request-Id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .unwrap_or("vault-admin")
        .to_string()
}

#[derive(serde::Deserialize)]
struct SignBody {
    session_id: String,
    message_hash: String,
}

async fn v1_sign(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    if let Err(e) = state.runtime.auth.authorize_treasury_sign() {
        return (StatusCode::UNAUTHORIZED, json_err(e));
    }
    let req: SignBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    match state.runtime.sign_message.run_lab_quorum_sign(&req.session_id, &req.message_hash) {
        Ok(sig) => (StatusCode::OK, sig.to_json()),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

#[derive(serde::Deserialize)]
struct FinancialQuorumBody {
    proposal_hash: String,
    constitution_hash: String,
    constitution_epoch: u64,
    submitted_at_epoch_ms: i64,
    expires_at_epoch_ms: i64,
}

async fn v1_financial_quorum_context(State(state): State<AppState>) -> impl IntoResponse {
    match state.runtime.ledger.epoch() {
        Ok(epoch) => (
            StatusCode::OK,
            serde_json::json!({
                "constitution_hash": epoch.constitution_hash,
                "constitution_epoch": epoch.number,
                "configured_members": epoch.active_set.len(),
                "active_members": epoch.active_set
                    .iter()
                    .map(|node| node.as_str())
                    .collect::<Vec<_>>()
            })
            .to_string(),
        ),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, json_err(e)),
    }
}

async fn v1_financial_quorum(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    if let Err(e) = state.runtime.auth.authorize_treasury_sign() {
        return (StatusCode::UNAUTHORIZED, json_err(e));
    }
    let req: FinancialQuorumBody = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid financial quorum json: {e}"))),
    };
    if req.proposal_hash.len() != 64 || hex::decode(&req.proposal_hash).is_err() {
        return (StatusCode::BAD_REQUEST, json_err("proposal_hash must be 32-byte lowercase/uppercase hex"));
    }
    let now_ms =
        SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_millis() as i64).unwrap_or_default();
    if req.submitted_at_epoch_ms > now_ms + 30_000
        || req.expires_at_epoch_ms <= now_ms
        || req.expires_at_epoch_ms <= req.submitted_at_epoch_ms
    {
        return (
            StatusCode::BAD_REQUEST,
            json_err("financial quorum proposal is expired or outside allowed clock skew"),
        );
    }
    let epoch = match state.runtime.ledger.epoch() {
        Ok(value) => value,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, json_err(e)),
    };
    if req.constitution_hash != epoch.constitution_hash || req.constitution_epoch != epoch.number {
        return (StatusCode::CONFLICT, json_err("financial quorum constitution hash/epoch mismatch"));
    }
    let canonical = format!(
        "kerosene-financial-quorum-v1|{}|{}|{}|{}|{}",
        req.proposal_hash,
        req.constitution_hash,
        req.constitution_epoch,
        req.submitted_at_epoch_ms,
        req.expires_at_epoch_ms
    );
    let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
    let signer = match state.runtime.frost_tr.as_ref() {
        Some(value) => value,
        None => return (StatusCode::SERVICE_UNAVAILABLE, json_err("USERS distributed FROST signer is unavailable")),
    };
    let proof = match signer.sign_financial_quorum_proof(&digest) {
        Ok(value) => value,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, json_err(e)),
    };
    let accepted: std::collections::HashSet<&str> = proof.participant_node_ids.iter().map(String::as_str).collect();
    let unavailable =
        epoch.active_set.iter().map(|node| node.as_str()).filter(|node| !accepted.contains(node)).collect::<Vec<_>>();
    let response = serde_json::json!({
        "decision": "ACCEPTED",
        "proposal_hash": req.proposal_hash,
        "constitution_hash": req.constitution_hash,
        "constitution_epoch": req.constitution_epoch,
        "configured_members": epoch.active_set.len(),
        "required_threshold": proof.required_threshold,
        "accepted_members": proof.participant_node_ids,
        "rejected_members": Vec::<String>::new(),
        "unavailable_members": unavailable,
        "aggregate_proof": proof.signature_hex,
        "verifying_key": proof.verifying_key_hex,
        "signed_digest": hex::encode(digest),
        "decided_at_epoch_ms": now_ms
    });
    (StatusCode::OK, response.to_string())
}

async fn v1_bitcoin_deposit(State(state): State<AppState>, Query(q): Query<DepositQuery>) -> impl IntoResponse {
    let bucket_raw = q.bucket.as_deref().unwrap_or("USERS");
    let bucket = match BucketKind::parse(bucket_raw) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(e)),
    };
    let tr = match bucket {
        BucketKind::Users => state.runtime.frost_tr.as_ref(),
        BucketKind::Channels => state.runtime.frost_tr_channels.as_ref(),
        other => {
            return (
                StatusCode::BAD_REQUEST,
                json_err(format!("bitcoin deposit Taproot key not available for bucket {}", other.as_str())),
            );
        }
    };
    let Some(tr) = tr else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"taproot FROST not installed for bucket (dealer_lab / DKG required)"}"#.into(),
        );
    };
    match tr.deposit_info() {
        Ok(info) => (StatusCode::OK, info.to_json()),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

#[derive(serde::Deserialize)]
struct DepositQuery {
    /// `USERS` (default, shared omnibus) or `CHANNELS` (dedicated key ≠ USERS).
    bucket: Option<String>,
}

#[derive(serde::Deserialize)]
struct BitcoinSighashBody {
    session_id: String,
    /// Hex-encoded 32-byte Taproot sighash.
    sighash_hex: String,
    /// When set, Intent gate runs before signing (caps / replay / allowlist).
    intent_id: Option<String>,
    bucket: Option<String>,
    destination: Option<String>,
    amount_sats: Option<u64>,
}

async fn v1_bitcoin_sign_sighash(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    if let Err(e) = state.runtime.auth.authorize_treasury_sign() {
        return (StatusCode::UNAUTHORIZED, json_err(e));
    }
    // Raw sighash cannot bind PSBT outputs — opt-in lab only (#28).
    if !matches!(state.runtime.config.ceremony_mode, CeremonyMode::Lab) {
        return (
            StatusCode::FORBIDDEN,
            r#"{"error":"raw sighash signing refused outside lab; use Intent-bound /v1/bitcoin/sign-psbt"}"#.into(),
        );
    }
    if !state.runtime.config.lab_allow_raw_sighash {
        return (
            StatusCode::FORBIDDEN,
            r#"{"error":"raw sighash signing requires VAULT_LAB_ALLOW_RAW_SIGHASH=1; prefer Intent-bound /v1/bitcoin/sign-psbt"}"#.into(),
        );
    }
    let req: BitcoinSighashBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    // Full Intent fields required even in lab (still cannot bind outputs to sighash).
    if req.intent_id.as_deref().unwrap_or("").is_empty()
        || req.bucket.as_deref().unwrap_or("").is_empty()
        || req.destination.as_deref().unwrap_or("").is_empty()
        || req.amount_sats.unwrap_or(0) == 0
    {
        return (
            StatusCode::BAD_REQUEST,
            json_err(
                "raw sighash requires intent_id, bucket, destination, and amount_sats (outputs still unbound — prefer sign-psbt)",
            ),
        );
    }
    if let Err(e) = maybe_gate_intent(
        &state,
        req.intent_id.as_deref(),
        req.bucket.as_deref(),
        req.destination.as_deref(),
        req.amount_sats,
        true,
    ) {
        return (StatusCode::BAD_REQUEST, json_err(e));
    }
    let Some(tr) = state.runtime.frost_tr.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, r#"{"error":"taproot FROST not installed"}"#.into());
    };
    let sighash = match hex::decode(req.sighash_hex.trim()) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("sighash_hex: {e}"))),
    };
    match tr.sign_sighash(&req.session_id, &sighash) {
        Ok(sig) => (StatusCode::OK, sig.to_json()),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

#[derive(serde::Deserialize)]
struct BitcoinPsbtBody {
    /// Unique signing session (also used as Intent id when intent_id omitted).
    session_id: String,
    psbt: String,
    intent_id: Option<String>,
    bucket: Option<String>,
    destination: Option<String>,
    amount_sats: Option<u64>,
    /// When false, Intent must already be soft-reserved (CHANNELS→LND inject fund step).
    /// Sign without reserve/commit so openChannel failure can still release.
    #[serde(default = "default_commit_intent")]
    commit_intent: bool,
}

fn default_commit_intent() -> bool {
    true
}

async fn v1_bitcoin_sign_psbt(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    if let Err(e) = state.runtime.auth.authorize_treasury_sign() {
        return (StatusCode::UNAUTHORIZED, json_err(e));
    }
    let req: BitcoinPsbtBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    let intent_id = req.intent_id.as_deref().filter(|s| !s.is_empty()).unwrap_or(req.session_id.as_str());
    let destination = req.destination.as_deref().unwrap_or("");
    let amount = req.amount_sats.unwrap_or(0);
    let bucket_raw = req.bucket.as_deref().unwrap_or("USERS");
    let bucket = match BucketKind::parse(bucket_raw) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(e)),
    };

    // Select Taproot keyset: USERS omnibus vs dedicated CHANNELS key.
    let tr = match bucket {
        BucketKind::Users => {
            if let Err(e) = assert_shared_taproot_bucket(bucket) {
                return (StatusCode::BAD_REQUEST, json_err(e));
            }
            state.runtime.frost_tr.as_ref()
        }
        BucketKind::Channels => {
            if let Err(e) = assert_channels_taproot_bucket(bucket) {
                return (StatusCode::BAD_REQUEST, json_err(e));
            }
            state.runtime.frost_tr_channels.as_ref()
        }
        other => {
            return (
                StatusCode::BAD_REQUEST,
                json_err(format!(
                    "bucket {} cannot spend Taproot; only USERS (shared) or CHANNELS (own key)",
                    other.as_str()
                )),
            );
        }
    };

    let receipt_bucket;
    let receipt_amount;
    let receipt_intent_id;
    if req.commit_intent {
        let require_shared = matches!(bucket, BucketKind::Users);
        let receipt = match maybe_reserve_intent(
            &state,
            Some(intent_id),
            Some(bucket_raw),
            Some(destination).filter(|s| !s.is_empty()),
            req.amount_sats,
            require_shared,
        ) {
            Ok(r) => r,
            Err(e) => return (StatusCode::BAD_REQUEST, json_err(e)),
        };
        receipt_bucket = receipt.bucket;
        receipt_amount = receipt.amount_sats;
        receipt_intent_id = receipt.intent_id;
    } else {
        // Already soft-reserved (CHANNELS inject): sign-only, no Intent mutate.
        match state.runtime.buckets.has_reservation(intent_id) {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::BAD_REQUEST,
                    json_err(format!("commit_intent=false requires existing reservation for {intent_id}")),
                );
            }
            Err(e) => return (StatusCode::BAD_REQUEST, json_err(e)),
        }
        if destination.is_empty() || amount == 0 {
            return (StatusCode::BAD_REQUEST, json_err("destination and amount_sats required for PSBT bind"));
        }
        if let Err(e) = validate_destination(state.runtime.config.bitcoin_network, destination) {
            return (StatusCode::BAD_REQUEST, json_err(e));
        }
        receipt_bucket = bucket;
        receipt_amount = amount;
        receipt_intent_id = intent_id.to_string();
    }

    let Some(tr) = tr else {
        if req.commit_intent {
            let _ = state.runtime.gate_intent.release(&receipt_intent_id, receipt_bucket, receipt_amount);
        }
        return (StatusCode::SERVICE_UNAVAILABLE, r#"{"error":"taproot FROST not installed for bucket"}"#.into());
    };
    // Fail-stop if online < t (probed liveness — High #7).
    let online = state.runtime.online.online_count();
    let need = state.runtime.threshold.group().t;
    if online < need {
        if req.commit_intent {
            let _ = state.runtime.gate_intent.release(&receipt_intent_id, receipt_bucket, receipt_amount);
        }
        return (StatusCode::BAD_REQUEST, json_err(format!("fail-stop: online {online} < t {need}")));
    }
    match tr.sign_psbt(&req.session_id, &req.psbt, destination, amount) {
        Ok(signed) => {
            if req.commit_intent {
                if let Err(e) = state.runtime.gate_intent.commit(&receipt_intent_id) {
                    return (StatusCode::BAD_REQUEST, json_err(e));
                }
            }
            (StatusCode::OK, signed.to_json())
        }
        Err(e) => {
            if req.commit_intent {
                let _ = state.runtime.gate_intent.release(&receipt_intent_id, receipt_bucket, receipt_amount);
            }
            (StatusCode::BAD_REQUEST, json_err(e))
        }
    }
}

fn build_settlement_intent(
    state: &AppState,
    intent_id: Option<&str>,
    bucket: Option<&str>,
    destination: Option<&str>,
    amount_sats: Option<u64>,
    require_shared_tr: bool,
) -> Result<SettlementIntent, crate::domain::DomainError> {
    let Some(id) = intent_id.filter(|s| !s.is_empty()) else {
        return Err(crate::domain::DomainError::InvalidIntent("intent_id required before bitcoin sign".into()));
    };
    let bucket_raw = bucket.unwrap_or("USERS");
    let destination = destination.unwrap_or("");
    let amount = amount_sats.unwrap_or(0);
    if destination.is_empty() || amount == 0 {
        return Err(crate::domain::DomainError::InvalidIntent(
            "destination and amount_sats required for Intent gate".into(),
        ));
    }
    validate_destination(state.runtime.config.bitcoin_network, destination)?;
    let bucket = BucketKind::parse(bucket_raw)?;
    if require_shared_tr {
        assert_shared_taproot_bucket(bucket)?;
    }
    let constitution = state.runtime.ledger.constitution()?;
    SettlementIntent::new(id, bucket, destination, amount, constitution.hash)
}

/// Two-phase reserve (High #9) — do not durable-burn before successful sign.
fn maybe_reserve_intent(
    state: &AppState,
    intent_id: Option<&str>,
    bucket: Option<&str>,
    destination: Option<&str>,
    amount_sats: Option<u64>,
    require_shared_tr: bool,
) -> Result<crate::application::GateReceipt, crate::domain::DomainError> {
    let intent = build_settlement_intent(state, intent_id, bucket, destination, amount_sats, require_shared_tr)?;
    state.runtime.gate_intent.reserve(intent)
}

fn maybe_gate_intent(
    state: &AppState,
    intent_id: Option<&str>,
    bucket: Option<&str>,
    destination: Option<&str>,
    amount_sats: Option<u64>,
    require_shared_tr: bool,
) -> Result<(), crate::domain::DomainError> {
    let intent = build_settlement_intent(state, intent_id, bucket, destination, amount_sats, require_shared_tr)?;
    let _ = state.runtime.gate_intent.execute(intent)?;
    Ok(())
}

async fn v1_anti_nonce_prepare(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    #[derive(serde::Deserialize)]
    struct PrepareBody {
        session_id: String,
        /// Required: bind prepare to Intent (High #8).
        intent_id: String,
        #[serde(default)]
        durable: bool,
    }
    let req: PrepareBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    let principal = state.runtime.config.node_id.as_str();
    if let Err(e) = state.prepare_limiter.check(principal) {
        return (StatusCode::TOO_MANY_REQUESTS, json_err(e));
    }
    if let Err(e) = bind_session_to_intent(&req.session_id, &req.intent_id) {
        return (StatusCode::BAD_REQUEST, json_err(e));
    }
    let result = if req.durable {
        state.runtime.anti_nonce.prepare_remote_durable(&req.session_id)
    } else {
        state.runtime.anti_nonce.prepare_remote_bound(&req.session_id, &req.intent_id)
    };
    match result {
        Ok(already_seen) => (StatusCode::OK, format!(r#"{{"ok":true,"already_seen":{already_seen}}}"#)),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

async fn v1_intent_consume_prepare(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    #[derive(serde::Deserialize)]
    struct PrepareBody {
        intent_id: String,
        #[serde(default)]
        durable: bool,
    }
    let req: PrepareBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    let principal = state.runtime.config.node_id.as_str();
    if let Err(e) = state.prepare_limiter.check(principal) {
        return (StatusCode::TOO_MANY_REQUESTS, json_err(e));
    }
    let result = if req.durable {
        state.runtime.buckets.prepare_remote_durable(&req.intent_id)
    } else {
        state.runtime.buckets.prepare_remote(&req.intent_id)
    };
    match result {
        Ok(already_seen) => (StatusCode::OK, format!(r#"{{"ok":true,"already_seen":{already_seen}}}"#)),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

async fn v1_day_current(State(state): State<AppState>) -> impl IntoResponse {
    match state.runtime.daily_rotation.current_day_epoch() {
        Ok(d) => (StatusCode::OK, format!(r#"{{"day_epoch":"{}"}}"#, d.as_str())),
        Err(e) => (StatusCode::CONFLICT, json_err(e)),
    }
}

async fn v1_day_vote(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(principal): Extension<crate::adapters::MeshPrincipal>,
    body: Bytes,
) -> impl IntoResponse {
    #[derive(serde::Deserialize)]
    struct VoteBody {
        /// Optional; if present must match authenticated vault identity (no client spoofing).
        #[serde(default)]
        voter: Option<String>,
        day_epoch: String,
    }
    let req: VoteBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    let target = match crate::domain::DayEpoch::parse(req.day_epoch) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(e)),
    };
    let header_node = headers.get("X-Vault-Node-Id").and_then(|v| v.to_str().ok());
    let mtls_peer_hook = headers.get("X-Vault-Mtls-Peer-Node").and_then(|v| v.to_str().ok());
    let allowed = crate::adapters::mesh_allowed_node_ids(
        state.runtime.config.node_id.as_str(),
        state.runtime.config.seed_peers.iter().map(|(id, _)| id.as_str()),
    );
    let voter = match crate::adapters::resolve_mesh_caller_identity_with_principal(
        state.runtime.config.node_id.as_str(),
        &allowed,
        header_node,
        req.voter.as_deref(),
        mtls_peer_hook,
        Some(&principal),
    ) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(e)),
    };
    match state.runtime.daily_rotation.record_vote(&voter, &target) {
        Ok(()) => (
            StatusCode::OK,
            format!(
                r#"{{"ok":true,"voter":"{}","self_voter":"{}","self_day_epoch":"{}"}}"#,
                voter,
                state.runtime.config.node_id.as_str(),
                target.as_str()
            ),
        ),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

async fn v1_day_advance(State(state): State<AppState>) -> impl IntoResponse {
    match state.runtime.daily_rotation.advance() {
        Ok(d) => (StatusCode::OK, format!(r#"{{"day_epoch":"{}","advanced":true}}"#, d.as_str())),
        Err(e) => (StatusCode::CONFLICT, json_err(e)),
    }
}

async fn v1_reshare_trigger(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    if let Err(e) = state.runtime.auth.authorize_reshare_trigger() {
        return (StatusCode::FORBIDDEN, json_err(e));
    }
    #[derive(serde::Deserialize)]
    struct TriggerBody {
        #[serde(default)]
        reason: Option<String>,
    }
    let reason = match serde_json::from_slice::<TriggerBody>(&body) {
        Ok(r) => r.reason.unwrap_or_else(|| "manual".into()),
        Err(_) => "manual".into(),
    };
    match state.runtime.reshare_hook.trigger_manual(&reason) {
        Ok(()) => (
            StatusCode::OK,
            serde_json::json!({
                "reshared": true,
                "policy": state.runtime.reshare_hook.policy().as_str(),
                "reason": reason,
            })
            .to_string(),
        ),
        Err(e) => (StatusCode::CONFLICT, json_err(e)),
    }
}

async fn v1_frost_tr_commit(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let req: crate::adapters::TrCommitRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    match state.runtime.tr_cosign_peer.handle_commit(&req) {
        Ok(resp) => (StatusCode::OK, serde_json::to_string(&resp).unwrap_or_else(|e| json_err(e))),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

async fn v1_frost_tr_sign_share(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let req: crate::adapters::TrSignShareRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    match state.runtime.tr_cosign_peer.handle_sign_share(&req) {
        Ok(Some(resp)) => (StatusCode::OK, serde_json::to_string(&resp).unwrap_or_else(|e| json_err(e))),
        Ok(None) => (StatusCode::OK, r#"{"skipped":true,"reason":"not in signing set"}"#.into()),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

/// Round1: start local part1 (`roster` / seated genesis) or ingest a peer package (`package_hex`).
/// Optional `fanout: true` on start POSTs the local package to seated `VAULT_SEED_PEERS`.
/// Omitting `roster` uses SEV-priority `genesis_roster` from boot seating (production-native path).
async fn v1_dkg_round1(
    State(state): State<AppState>,
    Extension(principal): Extension<crate::adapters::MeshPrincipal>,
    body: Bytes,
) -> impl IntoResponse {
    dkg_round1_impl(state, principal, body, false).await
}

async fn v1_dkg_tr_round1(
    State(state): State<AppState>,
    Extension(principal): Extension<crate::adapters::MeshPrincipal>,
    body: Bytes,
) -> impl IntoResponse {
    dkg_round1_impl(state, principal, body, true).await
}

async fn dkg_round1_impl(
    state: AppState,
    principal: crate::adapters::MeshPrincipal,
    body: Bytes,
    taproot: bool,
) -> (StatusCode, String) {
    #[derive(serde::Deserialize)]
    struct Round1Body {
        session_id: String,
        #[serde(default)]
        roster: Option<Vec<String>>,
        #[serde(default)]
        max_signers: Option<u16>,
        #[serde(default)]
        min_signers: Option<u16>,
        #[serde(default)]
        fanout: bool,
        #[serde(default)]
        sender_node_id: Option<String>,
        #[serde(default)]
        sender_identifier: Option<u16>,
        #[serde(default)]
        transcript_hex: Option<String>,
        #[serde(default)]
        package_hex: Option<String>,
    }
    let req: Round1Body = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };

    let is_start = req.roster.is_some() || req.package_hex.is_none();
    if is_start && req.package_hex.is_none() {
        let seated: Vec<String> = state.runtime.genesis_roster.iter().map(|n| n.as_str().to_string()).collect();
        let roster = match &req.roster {
            None => seated.clone(),
            Some(r) if r.is_empty() => seated.clone(),
            Some(roster_in) => {
                let mut provided = roster_in.clone();
                provided.sort();
                let mut expected = seated.clone();
                expected.sort();
                if provided != expected
                    && matches!(
                        state.runtime.config.ceremony_mode,
                        crate::bootstrap::CeremonyMode::Staging | crate::bootstrap::CeremonyMode::Production
                    )
                {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!(
                            r#"{{"error":"DKG roster must match seated genesis roster {:?} (got {:?})"}}"#,
                            seated, roster_in
                        ),
                    );
                }
                if roster_in.len() == seated.len() {
                    seated
                } else {
                    roster_in.clone()
                }
            }
        };
        if roster.len() < 2 {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"error":"genesis_roster empty; set VAULT_SEED_PEERS + VAULT_GENESIS_N"}"#.into(),
            );
        }
        let max = req.max_signers.unwrap_or(roster.len() as u16);
        let min = req.min_signers.unwrap_or_else(|| ((max as usize * 2).div_ceil(3)).max(2).min(max as usize) as u16);
        let start = crate::adapters::DkgStartRequest {
            session_id: req.session_id.clone(),
            max_signers: max,
            min_signers: min,
            roster,
        };
        let start_result =
            if taproot { state.runtime.tr_wire_dkg.start(start) } else { state.runtime.wire_dkg.start(start) };
        return match start_result {
            Ok((status, wire)) => {
                if req.fanout {
                    let fanout = if taproot {
                        state.runtime.tr_wire_dkg.fanout_round1(&wire).await
                    } else {
                        state.runtime.wire_dkg.fanout_round1(&wire).await
                    };
                    if let Err(e) = fanout {
                        return (
                            StatusCode::BAD_GATEWAY,
                            serde_json::json!({
                                "error": e.to_string(),
                                "status": status,
                            })
                            .to_string(),
                        );
                    }
                }
                (
                    StatusCode::OK,
                    serde_json::json!({
                        "status": status,
                        "round1": wire,
                    })
                    .to_string(),
                )
            }
            Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
        };
    }

    let Some(package_hex) = req.package_hex else {
        return (
            StatusCode::BAD_REQUEST,
            r#"{"error":"round1 requires roster (start) or package_hex (ingest)"}"#.into(),
        );
    };
    let sender_node_id = req.sender_node_id.unwrap_or_default();
    let lab_token = matches!(state.runtime.config.auth_mode, AuthMode::StaticToken);
    if let Err(e) = crate::adapters::bind_dkg_sender_to_peer(&sender_node_id, Some(&principal), lab_token) {
        return (StatusCode::UNAUTHORIZED, json_err(e));
    }
    let msg = crate::adapters::Round1WireMessage {
        session_id: req.session_id,
        sender_node_id,
        sender_identifier: req.sender_identifier.unwrap_or(0),
        max_signers: req.max_signers.unwrap_or(0),
        min_signers: req.min_signers.unwrap_or(0),
        transcript_hex: req.transcript_hex.unwrap_or_default(),
        package_hex,
        envelope: None,
    };
    let result =
        if taproot { state.runtime.tr_wire_dkg.ingest_round1(msg) } else { state.runtime.wire_dkg.ingest_round1(msg) };
    match result {
        Ok(status) => (StatusCode::OK, serde_json::to_string(&status).unwrap_or_else(|e| json_err(e))),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

/// Round2: ingest peer package, or `deliver: true` to fan-out local outbound packages.
async fn v1_dkg_round2(
    State(state): State<AppState>,
    Extension(principal): Extension<crate::adapters::MeshPrincipal>,
    body: Bytes,
) -> impl IntoResponse {
    dkg_round2_impl(state, principal, body, false).await
}

async fn v1_dkg_tr_round2(
    State(state): State<AppState>,
    Extension(principal): Extension<crate::adapters::MeshPrincipal>,
    body: Bytes,
) -> impl IntoResponse {
    dkg_round2_impl(state, principal, body, true).await
}

async fn dkg_round2_impl(
    state: AppState,
    principal: crate::adapters::MeshPrincipal,
    body: Bytes,
    taproot: bool,
) -> (StatusCode, String) {
    #[derive(serde::Deserialize)]
    struct Round2Body {
        session_id: String,
        #[serde(default)]
        deliver: bool,
        #[serde(default)]
        fanout: bool,
        #[serde(default)]
        sender_node_id: Option<String>,
        #[serde(default)]
        sender_identifier: Option<u16>,
        #[serde(default)]
        recipient_node_id: Option<String>,
        #[serde(default)]
        recipient_identifier: Option<u16>,
        #[serde(default)]
        transcript_hex: Option<String>,
        #[serde(default)]
        package_hex: Option<String>,
    }
    let req: Round2Body = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };

    if req.deliver {
        let outbound = if taproot {
            state.runtime.tr_wire_dkg.take_round2_outbound(&req.session_id)
        } else {
            state.runtime.wire_dkg.take_round2_outbound(&req.session_id)
        };
        match outbound {
            Ok(msgs) => {
                if req.fanout {
                    let fanout = if taproot {
                        state.runtime.tr_wire_dkg.fanout_round2(&msgs).await
                    } else {
                        state.runtime.wire_dkg.fanout_round2(&msgs).await
                    };
                    if let Err(e) = fanout {
                        return (StatusCode::BAD_GATEWAY, json_err(e));
                    }
                }
                (StatusCode::OK, serde_json::json!({ "outbound": msgs }).to_string())
            }
            Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
        }
    } else {
        let Some(package_hex) = req.package_hex else {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"error":"round2 requires package_hex (ingest) or deliver=true"}"#.into(),
            );
        };
        let sender_node_id = req.sender_node_id.unwrap_or_default();
        let lab_token = matches!(state.runtime.config.auth_mode, AuthMode::StaticToken);
        if let Err(e) = crate::adapters::bind_dkg_sender_to_peer(&sender_node_id, Some(&principal), lab_token) {
            return (StatusCode::UNAUTHORIZED, json_err(e));
        }
        let msg = crate::adapters::Round2WireMessage {
            session_id: req.session_id,
            sender_node_id,
            sender_identifier: req.sender_identifier.unwrap_or(0),
            recipient_node_id: req.recipient_node_id.unwrap_or_default(),
            recipient_identifier: req.recipient_identifier.unwrap_or(0),
            transcript_hex: req.transcript_hex.unwrap_or_default(),
            package_hex,
            envelope: None,
        };
        let result = if taproot {
            state.runtime.tr_wire_dkg.ingest_round2(msg)
        } else {
            state.runtime.wire_dkg.ingest_round2(msg)
        };
        match result {
            Ok(status) => (StatusCode::OK, serde_json::to_string(&status).unwrap_or_else(|e| json_err(e))),
            Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
        }
    }
}

/// Round3: finalize part3 when round2 inbox is complete; persists only local share.
async fn v1_dkg_round3(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    dkg_round3_impl(state, body, false).await
}

async fn v1_dkg_tr_round3(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    dkg_round3_impl(state, body, true).await
}

async fn dkg_round3_impl(state: AppState, body: Bytes, taproot: bool) -> (StatusCode, String) {
    let req: crate::adapters::Round3WireRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    if !req.finalize {
        let status = if taproot {
            state.runtime.tr_wire_dkg.status(&req.session_id)
        } else {
            state.runtime.wire_dkg.status(&req.session_id)
        };
        return match status {
            Ok(status) => (StatusCode::OK, serde_json::to_string(&status).unwrap_or_else(|e| json_err(e))),
            Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
        };
    }
    let result = if taproot {
        state.runtime.tr_wire_dkg.finalize_round3(&req.session_id, state.runtime.share_store.as_ref())
    } else {
        state.runtime.wire_dkg.finalize_round3(&req.session_id, state.runtime.share_store.as_ref())
    };
    match result {
        Ok(status) => (StatusCode::OK, serde_json::to_string(&status).unwrap_or_else(|e| json_err(e))),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

async fn v1_dkg_status(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    dkg_status_impl(state, q, false).await
}

async fn v1_dkg_tr_status(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    dkg_status_impl(state, q, true).await
}

async fn dkg_status_impl(
    state: AppState,
    q: std::collections::HashMap<String, String>,
    taproot: bool,
) -> (StatusCode, String) {
    let Some(session_id) = q.get("session_id") else {
        return (StatusCode::BAD_REQUEST, r#"{"error":"session_id query required"}"#.into());
    };
    let status =
        if taproot { state.runtime.tr_wire_dkg.status(session_id) } else { state.runtime.wire_dkg.status(session_id) };
    match status {
        Ok(status) => (StatusCode::OK, serde_json::to_string(&status).unwrap_or_else(|e| json_err(e))),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

#[derive(serde::Deserialize)]
struct IntentBody {
    intent_id: String,
    bucket: String,
    destination: String,
    amount_sats: u64,
    #[serde(default)]
    ed25519_signature_hex: Option<String>,
    #[serde(default)]
    ml_dsa65_signature_hex: Option<String>,
    #[serde(default)]
    ed25519_key_id: Option<String>,
    #[serde(default)]
    ml_dsa_key_id: Option<String>,
}

async fn v1_intent(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    match parse_settlement_intent(&state, &body) {
        Ok(intent) => match state.runtime.gate_intent.execute(intent) {
            Ok(r) => (StatusCode::OK, r.to_json()),
            Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
        },
        Err(resp) => resp,
    }
}

async fn v1_intent_reserve(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    match parse_settlement_intent(&state, &body) {
        Ok(intent) => match state.runtime.gate_intent.reserve(intent) {
            Ok(r) => (StatusCode::OK, r.to_json()),
            Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
        },
        Err(resp) => resp,
    }
}

#[derive(serde::Deserialize)]
struct IntentReleaseBody {
    intent_id: String,
    bucket: String,
    amount_sats: u64,
}

async fn v1_intent_release(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let req: IntentReleaseBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    let bucket = match BucketKind::parse(&req.bucket) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(e)),
    };
    match state.runtime.gate_intent.release(&req.intent_id, bucket, req.amount_sats) {
        Ok(()) => (
            StatusCode::OK,
            format!(
                r#"{{"intent_id":"{}","bucket":"{}","amount_sats":{},"status":"RELEASED"}}"#,
                req.intent_id,
                bucket.as_str(),
                req.amount_sats
            ),
        ),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

#[derive(serde::Deserialize)]
struct IntentCommitBody {
    intent_id: String,
}

async fn v1_intent_commit(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let req: IntentCommitBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}"))),
    };
    if req.intent_id.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, json_err("intent_id required"));
    }
    match state.runtime.gate_intent.commit(req.intent_id.trim()) {
        Ok(()) => (StatusCode::OK, format!(r#"{{"intent_id":"{}","status":"COMMITTED"}}"#, req.intent_id.trim())),
        Err(e) => (StatusCode::BAD_REQUEST, json_err(e)),
    }
}

fn parse_settlement_intent(state: &AppState, body: &Bytes) -> Result<SettlementIntent, (StatusCode, String)> {
    use crate::domain::IntentSignature;

    let req: IntentBody = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return Err((StatusCode::BAD_REQUEST, json_err(format!("invalid json: {e}")))),
    };
    if let Err(e) = validate_destination(state.runtime.config.bitcoin_network, &req.destination) {
        return Err((StatusCode::BAD_REQUEST, json_err(e)));
    }
    let bucket = match BucketKind::parse(&req.bucket) {
        Ok(b) => b,
        Err(e) => return Err((StatusCode::BAD_REQUEST, json_err(e))),
    };
    let constitution = match state.runtime.ledger.constitution() {
        Ok(c) => c,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, json_err(e))),
    };
    let policy_hash = constitution.hash;
    let require_pq =
        constitution.downgrade_policy.require_pq_signatures && constitution.downgrade_policy.hybrid_signature_required;

    let mut intent = SettlementIntent::new(req.intent_id, bucket, req.destination, req.amount_sats, policy_hash)
        .map_err(|e| (StatusCode::BAD_REQUEST, json_err(e)))?;

    // Hybrid signature validation: AND logic, both must verify.
    let has_sigs = req.ed25519_signature_hex.is_some() || req.ml_dsa65_signature_hex.is_some();
    if has_sigs || require_pq {
        let ed_sig_hex = req.ed25519_signature_hex.unwrap_or_default();
        let ml_sig_hex = req.ml_dsa65_signature_hex.unwrap_or_default();

        // Canonical hash: bind intent fields deterministically.
        let canon_bytes = serde_json::json!({
            "intent_id": intent.intent_id,
            "bucket": intent.bucket.as_str(),
            "destination": intent.destination,
            "amount_sats": intent.amount_sats,
            "policy_hash": intent.policy_hash,
        })
        .to_string();

        let ed_sig_bytes = hex::decode(&ed_sig_hex)
            .map_err(|e| (StatusCode::BAD_REQUEST, json_err(format!("ed25519_sig hex: {e}"))))?;
        let ml_sig_bytes = if ml_sig_hex.is_empty() {
            Vec::new()
        } else {
            hex::decode(&ml_sig_hex)
                .map_err(|e| (StatusCode::BAD_REQUEST, json_err(format!("ml_dsa65_sig hex: {e}"))))?
        };
        let mut ed_arr = [0u8; 64];
        ed_arr.copy_from_slice(&ed_sig_bytes[..64.min(ed_sig_bytes.len())]);
        if ed_sig_bytes.len() != 64 {
            return Err((StatusCode::BAD_REQUEST, json_err("ed25519_sig must be 64 bytes")));
        }

        let sig = IntentSignature {
            ed25519_signature: ed_arr,
            ml_dsa65_signature: ml_sig_bytes,
            ed25519_key_id: req.ed25519_key_id.unwrap_or_default(),
            ml_dsa_key_id: req.ml_dsa_key_id.unwrap_or_default(),
            canonical_hash: IntentSignature::compute_canonical_hash(canon_bytes.as_bytes()),
        };

        if let Err(e) = sig.validate_stub(require_pq) {
            return Err((StatusCode::UNAUTHORIZED, json_err(e)));
        }
        intent = intent.with_signature(sig);
    }

    Ok(intent)
}

async fn v1_reshare_tr_round1(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let _ = state;
    let _ = body;
    (StatusCode::NOT_IMPLEMENTED, json_err("WireReshareHub not yet wired into VaultRuntime; see bootstrap/wiring.rs"))
}

async fn v1_reshare_tr_round2(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let _ = state;
    let _ = body;
    (StatusCode::NOT_IMPLEMENTED, json_err("WireReshareHub not yet wired"))
}

async fn v1_reshare_tr_finalize(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let _ = state;
    let _ = body;
    (StatusCode::NOT_IMPLEMENTED, json_err("WireReshareHub not yet wired"))
}

async fn v1_reshare_tr_status(State(state): State<AppState>) -> impl IntoResponse {
    let _ = state;
    (StatusCode::NOT_IMPLEMENTED, json_err("WireReshareHub not yet wired"))
}

async fn legacy_dispatch(State(state): State<AppState>, req: Request) -> impl IntoResponse {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let (status, body) = dispatch_legacy(&state.runtime, &method, &path);
    (status, body)
}

fn status_from_str(s: &str) -> StatusCode {
    match s.split_whitespace().next().unwrap_or("500") {
        "200" => StatusCode::OK,
        "400" => StatusCode::BAD_REQUEST,
        "403" => StatusCode::FORBIDDEN,
        "404" => StatusCode::NOT_FOUND,
        "414" => StatusCode::URI_TOO_LONG,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Legacy path dispatcher (token already checked by middleware except public health).
pub fn dispatch_legacy(runtime: &VaultRuntime, method: &str, path: &str) -> (StatusCode, String) {
    if path.len() > 512 {
        return (StatusCode::URI_TOO_LONG, r#"{"error":"request rejected: path too long"}"#.into());
    }
    if path.contains("..") {
        return (StatusCode::BAD_REQUEST, r#"{"error":"request rejected: path traversal"}"#.into());
    }

    let (code, body) = match (method, path) {
        ("GET", "/") | ("GET", "/health") | ("GET", "/v1/health") => match runtime.get_health.execute() {
            Ok(h) => ("200 OK", h.to_json()),
            Err(e) => ("500 Internal Server Error", json_err(e)),
        },
        ("GET", "/ledger") => match runtime.get_ledger.execute() {
            Ok(s) => ("200 OK", s.to_json()),
            Err(e) => ("500 Internal Server Error", json_err(e)),
        },
        ("GET", "/threshold") => {
            let g = runtime.threshold.group();
            (
                "200 OK",
                format!(
                    r#"{{"n":{},"t":{},"commitment":"{}","scheme":"lab-shamir-threshold-v1","online":{}}}"#,
                    g.n,
                    g.t,
                    g.commitment,
                    runtime.online.online_count()
                ),
            )
        }
        ("GET", "/release/allowlist") => match runtime.get_allowlist.execute() {
            Ok(entries) => {
                let body = entries.iter().map(|e| e.to_json()).collect::<Vec<_>>().join(",");
                ("200 OK", format!("[{body}]"))
            }
            Err(e) => ("500 Internal Server Error", json_err(e)),
        },
        ("GET", path) if path.starts_with("/release/check-hb/") => {
            let hb_raw = path.trim_start_matches("/release/check-hb/");
            match ContentHash::parse(hb_raw) {
                Ok(hb) => match runtime.get_allowlist.require_hb(&hb) {
                    Ok(()) => ("200 OK", r#"{"allowlisted":true}"#.into()),
                    Err(e) => ("403 Forbidden", json_err(e)),
                },
                Err(e) => ("400 Bad Request", json_err(e)),
            }
        }
        ("GET", path) if path.starts_with("/release/") => {
            let id = path.trim_start_matches("/release/");
            match runtime.release_mesh.get_candidate(id) {
                Ok(c) => ("200 OK", c.to_json()),
                Err(e) => ("404 Not Found", json_err(e)),
            }
        }
        ("POST", path) if path.starts_with("/epoch/propose/") => {
            let id = path.trim_start_matches("/epoch/propose/");
            match runtime.propose_epoch.execute(id) {
                Ok(p) => ("200 OK", p.to_json()),
                Err(e) => ("400 Bad Request", json_err(e)),
            }
        }
        ("POST", path) if path.starts_with("/epoch/vote/") => {
            let id = path.trim_start_matches("/epoch/vote/");
            match runtime.vote_epoch.execute(id) {
                Ok(p) => ("200 OK", p.to_json()),
                Err(e) => ("400 Bad Request", json_err(e)),
            }
        }
        ("POST", path) if path.starts_with("/sign/") => {
            let rest = path.trim_start_matches("/sign/");
            let mut segs = rest.splitn(2, '/');
            let session_id = segs.next().unwrap_or("");
            let message_hash = segs.next().unwrap_or("");
            if session_id.is_empty() || message_hash.is_empty() {
                ("400 Bad Request", r#"{"error":"usage /sign/{session_id}/{message_hash}"}"#.into())
            } else {
                match runtime.sign_message.run_lab_quorum_sign(session_id, message_hash) {
                    Ok(sig) => ("200 OK", sig.to_json()),
                    Err(e) => ("400 Bad Request", json_err(e)),
                }
            }
        }
        ("POST", path) if path.starts_with("/release/propose-tampered/") => {
            if !runtime.config.lab_endpoints_enabled() {
                ("403 Forbidden", r#"{"error":"lab flag forbidden outside lab: propose-tampered"}"#.into())
            } else {
                let rest = path.trim_start_matches("/release/propose-tampered/");
                let mut segs = rest.splitn(4, '/');
                let id = segs.next().unwrap_or("");
                let source_label = segs.next().unwrap_or("");
                let evil_hb = segs.next().unwrap_or("");
                let council_csv = segs.next().unwrap_or("");
                if id.is_empty() || source_label.is_empty() || evil_hb.is_empty() || council_csv.is_empty() {
                    (
                        "400 Bad Request",
                        r#"{"error":"usage /release/propose-tampered/{id}/{source}/{evil_hb}/{council}"}"#.into(),
                    )
                } else {
                    let hs = ContentHash::from_bytes(source_label.as_bytes());
                    let _ = runtime.release_mesh.put(&hs, source_label.as_bytes());
                    match ContentHash::parse(evil_hb) {
                        Ok(hb) => {
                            let council = council_csv
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect();
                            match runtime.propose_release.execute_with_hashes(id, hs, hb, council) {
                                Ok(c) => ("200 OK", c.to_json()),
                                Err(e) => ("400 Bad Request", json_err(e)),
                            }
                        }
                        Err(e) => ("400 Bad Request", json_err(e)),
                    }
                }
            }
        }
        ("POST", path) if path.starts_with("/release/propose/") => {
            let rest = path.trim_start_matches("/release/propose/");
            let mut segs = rest.splitn(3, '/');
            let id = segs.next().unwrap_or("");
            let source_label = segs.next().unwrap_or("");
            let council_csv = segs.next().unwrap_or("");
            if id.is_empty() || source_label.is_empty() || council_csv.is_empty() {
                ("400 Bad Request", r#"{"error":"usage /release/propose/{id}/{source_label}/{council_csv}"}"#.into())
            } else {
                let council = council_csv.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                match runtime.propose_release.execute(id, source_label.as_bytes(), council) {
                    Ok(c) => ("200 OK", c.to_json()),
                    Err(e) => ("400 Bad Request", json_err(e)),
                }
            }
        }
        ("POST", path) if path.starts_with("/release/rebuild/") => {
            let rest = path.trim_start_matches("/release/rebuild/");
            let mut segs = rest.splitn(2, '/');
            let id = segs.next().unwrap_or("");
            let vault_id = segs.next().unwrap_or("");
            match NodeId::new(vault_id) {
                Ok(vault) => match runtime.rebuild_release.execute(id, &vault) {
                    Ok(c) => ("200 OK", c.to_json()),
                    Err(e) => ("400 Bad Request", json_err(e)),
                },
                Err(e) => ("400 Bad Request", json_err(e)),
            }
        }
        ("POST", path) if path.starts_with("/release/cosign/") => {
            let id = path.trim_start_matches("/release/cosign/");
            match runtime.cosign_release.execute(id) {
                Ok(c) => ("200 OK", c.to_json()),
                Err(e) => ("400 Bad Request", json_err(e)),
            }
        }
        ("POST", path) if path.starts_with("/release/activate/") => {
            let id = path.trim_start_matches("/release/activate/");
            match runtime.activate_release.execute(id) {
                Ok(e) => ("200 OK", e.to_json()),
                Err(e) => ("400 Bad Request", json_err(e)),
            }
        }
        ("POST", path) if path.starts_with("/intent/gate/") => {
            let rest = path.trim_start_matches("/intent/gate/");
            let mut segs = rest.splitn(4, '/');
            let id = segs.next().unwrap_or("");
            let bucket_raw = segs.next().unwrap_or("");
            let destination = segs.next().unwrap_or("");
            let amount_raw = segs.next().unwrap_or("");
            if id.is_empty() || bucket_raw.is_empty() || destination.is_empty() || amount_raw.is_empty() {
                ("400 Bad Request", r#"{"error":"usage /intent/gate/{id}/{bucket}/{destination}/{amount}"}"#.into())
            } else if let Err(e) = validate_destination(runtime.config.bitcoin_network, destination) {
                ("400 Bad Request", json_err(e))
            } else {
                match BucketKind::parse(bucket_raw) {
                    Ok(bucket) => match amount_raw.parse::<u64>() {
                        Ok(amount) => match runtime.ledger.constitution() {
                            Ok(c) => match SettlementIntent::new(id, bucket, destination, amount, c.hash) {
                                Ok(intent) => match runtime.gate_intent.execute(intent) {
                                    Ok(r) => ("200 OK", r.to_json()),
                                    Err(e) => ("400 Bad Request", json_err(e)),
                                },
                                Err(e) => ("400 Bad Request", json_err(e)),
                            },
                            Err(e) => ("500 Internal Server Error", json_err(e)),
                        },
                        Err(_) => ("400 Bad Request", r#"{"error":"amount must be u64 sats"}"#.into()),
                    },
                    Err(e) => ("400 Bad Request", json_err(e)),
                }
            }
        }
        ("POST", path) if path.starts_with("/profit/allocate/") => {
            let amount_raw = path.trim_start_matches("/profit/allocate/");
            match amount_raw.parse::<u64>() {
                Ok(amount) => match runtime.allocate_profit.execute(amount) {
                    Ok(a) => ("200 OK", a.to_json()),
                    Err(e) => ("400 Bad Request", json_err(e)),
                },
                Err(_) => ("400 Bad Request", r#"{"error":"usage /profit/allocate/{profit_sats}"}"#.into()),
            }
        }
        ("GET", "/economy/status") => match runtime.get_economy.execute() {
            Ok(v) => ("200 OK", v.to_json()),
            Err(e) => ("500 Internal Server Error", json_err(e)),
        },
        ("POST", path) if path.starts_with("/economy/accrue/") => {
            let amount_raw = path.trim_start_matches("/economy/accrue/");
            match amount_raw.parse::<u64>() {
                Ok(amount) => match runtime.accrue_rewards.execute(amount) {
                    Ok(a) => ("200 OK", a.to_json()),
                    Err(e) => ("400 Bad Request", json_err(e)),
                },
                Err(_) => ("400 Bad Request", r#"{"error":"usage /economy/accrue/{profit_sats}"}"#.into()),
            }
        }
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
                (
                    "400 Bad Request",
                    r#"{"error":"usage /economy/miner/upsert/{id}/{dest}/{uptime}/{streak}/{bond}/{waiting}"}"#.into(),
                )
            } else {
                match NodeId::new(id) {
                    Ok(node_id) => {
                        let uptime = uptime_raw.parse::<u32>().unwrap_or(0);
                        let streak = streak_raw.parse::<u32>().unwrap_or(0);
                        let bond = bond_raw.parse::<u64>().unwrap_or(0);
                        let waiting = matches!(waiting_raw, "1" | "true" | "TRUE" | "waiting");
                        let op = crate::domain::MinerOperator {
                            node_id,
                            payout_destination: destination.to_string(),
                            uptime_bps_30d: uptime,
                            attestation_streak_days: streak,
                            bond_sats: bond,
                            waiting,
                        };
                        match runtime.upsert_miner.execute(op) {
                            Ok(()) => ("200 OK", r#"{"status":"upserted"}"#.into()),
                            Err(e) => ("400 Bad Request", json_err(e)),
                        }
                    }
                    Err(e) => ("400 Bad Request", json_err(e)),
                }
            }
        }
        ("POST", path) if path.starts_with("/economy/payout/propose/") => {
            let rest = path.trim_start_matches("/economy/payout/propose/");
            let mut segs = rest.splitn(2, '/');
            let amount_raw = segs.next().unwrap_or("");
            let prefix = segs.next().unwrap_or("miner-pay");
            match amount_raw.parse::<u64>() {
                Ok(amount) => match runtime.propose_miner_payouts.execute(amount, prefix) {
                    Ok(p) => ("200 OK", p.to_json()),
                    Err(e) => ("400 Bad Request", json_err(e)),
                },
                Err(_) => ("400 Bad Request", r#"{"error":"usage /economy/payout/propose/{amount}/{prefix}"}"#.into()),
            }
        }
        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
    };
    (status_from_str(code), body)
}
