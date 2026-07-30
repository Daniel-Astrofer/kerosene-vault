//! Lab P0 adapters: FROST dealer/sign, share store, auth, day rotation, HTTP.

mod admin_api;
mod attestation_sim;
mod attestation_tee;
mod audit_keys;
mod auth_identity;
mod auth_mtls;
mod auth_static;
mod bucket_memory;
mod channel_inject;
mod clock;
mod daily_rotation;
mod dkg_distributed;
mod dkg_tr_wire;
mod dkg_wire;
mod durable_fs;
mod economy_memory;
#[cfg(feature = "dealer_lab")]
mod frost_dealer;
mod frost_reshare;
mod frost_sign;
mod frost_tr_bitcoin;
mod frost_wire_cosign;
mod http;
mod http_peer;
mod hybrid_envelope;
mod identity_hybrid;
mod intent_consume;
mod ledger_memory;
mod peer_memory;
mod rate_limit;
mod release_memory;
mod release_persist;
mod reshare_wire;
mod session_persist;
mod share_aead;
mod share_tee;
mod share_tpm;
mod share_tpm_tss;
mod sync_util;
mod threshold_state;
mod tls_mtls_acceptor;
mod tls_peer_verify;

pub use admin_api::{build_admin_router, spawn_admin_unix_socket, spawn_admin_tcp, validate_admin_request_path};
pub use attestation_sim::SimAttestationAdapter;
pub use attestation_tee::TeeAttestationAdapter;
pub use audit_keys::MeshAuditKeyAllowlist;
pub use auth_identity::{
    bind_dkg_sender_to_peer, mesh_allowed_node_ids, parse_spiffe_principal, principal_from_cert_sans,
    resolve_mesh_caller_identity, resolve_mesh_caller_identity_with_principal, route_class_for_path, MeshPrincipal,
    MeshRole, RouteClass,
};
pub use auth_mtls::{build_mtls_server_config, MutualTlsAuthAdapter};
pub use auth_static::StaticTokenAuthAdapter;
pub use bucket_memory::{InMemoryBucketLedger, PersistedBucketLedger};
pub use channel_inject::StubChannelInject;
pub use clock::SystemClock;
pub use daily_rotation::{
    DayVoteTransport, HttpDayVoteTransport, LedgerDayEpochStub, MemoryDayVoteTransport, NoopDayVoteTransport,
    NoopReshareHook, PeerDayVote, QuorumDailyRotation, RecordingReshareHook,
};
pub use dkg_distributed::{DistributedDkgAdapter, FrostDistributedBundle};
pub use dkg_tr_wire::{session_transcript_tr, TrWireDkgHub};
pub use dkg_wire::{
    session_transcript, DistributedWireDkgPort, DkgStartRequest, Round1WireMessage, Round2WireMessage,
    Round3WireRequest, WireDkgHub, WireDkgPeerAuth, WireDkgStatus,
};
pub use economy_memory::{InMemoryEconomy, PersistedEconomy};
#[cfg(feature = "dealer_lab")]
pub use frost_dealer::{dealer_fatal_banner, DealerLabAdapter, FrostDealerBundle};
pub use frost_reshare::{refresh_shares_in_process, FrostShareSlot, FrostShareState, PolicyReshareHook};
pub use frost_sign::{FrostAggregateResult, FrostSignOrchestrator};
#[cfg(feature = "dealer_lab")]
pub use frost_tr_bitcoin::generate_tr_dealer;
pub use frost_tr_bitcoin::{
    load_tr_channels_shares, load_tr_shares, persist_tr_channels_shares, persist_tr_shares,
    refresh_tr_shares_in_process, FrostTrBitcoinOrchestrator, FrostTrShareSlot, FrostTrShareState, SignedPsbtResult,
};
pub use frost_wire_cosign::{
    sign_raw_wire, sign_raw_wire_attributed, tr_state_local_only, AttributedWireSignature, HttpTrCosignTransport,
    NoopTrCosignTransport, TrCommitRequest, TrCommitResponse, TrCosignPeerState, TrCosignTransport, TrSignShareRequest,
    TrSignShareResponse,
};
pub use http::{build_router, AppState};
pub use http_peer::{peer_addr_is_onion, post_json_with_retry, PeerHttpSettings, VaultTransport};
pub use hybrid_envelope::HybridEnvelopeAdapter;
pub use identity_hybrid::HybridIdentity;
pub use intent_consume::{
    HttpIntentConsumeTransport, IntentConsumeQuorumTransport, IntentPrepareAck, MemoryIntentConsumeTransport,
    QuorumBucketLedger,
};
pub use ledger_memory::InMemoryLedger;
pub use peer_memory::InMemoryPeerDirectory;
pub use rate_limit::SlidingWindowLimiter;
pub use release_memory::InMemoryReleaseMesh;
pub use release_persist::PersistedReleaseMesh;
pub use reshare_wire::{
    ReshareRound1WireMessage, ReshareRound2WireMessage, ReshareStartRequest, WireReshareHub, WireResharePeerAuth,
    WireResharePhase, WireReshareStatus,
};
pub use session_persist::{
    HttpAntiNonceTransport, MemoryAntiNonceTransport, PersistedAntiNonce, QuorumAntiNonce, SharedAntiNonce,
};
pub use share_aead::{build_seed_aad, build_seed_share_id, AeadDiskShareStore, SeedKind};
pub use share_tee::{TeeSealAdapter, TeeSealShareStore};
pub use share_tpm::{
    build_tpm_seal_port, resolve_aead_passphrase, sealed_passphrase_path, tpm_device_present, validate_tpm_counter,
    CounterSealedBlob, ResolvedPassphrase, TpmSealAdapter, TpmSealPort,
};
pub use share_tpm_tss::{
    build_seal_aad, pcr_composite_digest, TpmTssSealAdapter, TSS_MAGIC, TSS_MODE_HW, VAULT_PCR_BASE,
};
pub use threshold_state::ThresholdVaultState;
pub use tls_mtls_acceptor::{PeerCertAcceptor, PeerClientCert};
pub use tls_peer_verify::{build_mtls_rustls_client_config, extract_sans, TlsPeerVerifyPolicy};
