//! Lab P0 adapters: FROST dealer/sign, share store, auth, day rotation, HTTP.

mod attestation_sim;
mod attestation_tee;
mod auth_mtls;
mod auth_static;
mod bucket_memory;
mod clock;
mod daily_rotation;
mod dkg_distributed;
mod dkg_wire;
mod economy_memory;
#[cfg(feature = "dealer_lab")]
mod frost_dealer;
mod frost_reshare;
mod frost_sign;
mod frost_tr_bitcoin;
mod http;
mod http_peer;
mod ledger_memory;
mod peer_memory;
mod release_memory;
mod session_persist;
mod share_aead;
mod share_tee;
mod share_tpm;
mod threshold_state;

pub use attestation_sim::SimAttestationAdapter;
pub use attestation_tee::TeeAttestationAdapter;
pub use auth_mtls::{build_mtls_server_config, MutualTlsAuthAdapter};
pub use auth_static::StaticTokenAuthAdapter;
pub use bucket_memory::InMemoryBucketLedger;
pub use clock::SystemClock;
pub use daily_rotation::{
    LedgerDayEpochStub, NoopReshareHook, QuorumDailyRotation, RecordingReshareHook,
};
pub use dkg_distributed::{DistributedDkgAdapter, FrostDistributedBundle};
pub use dkg_wire::{
    session_transcript, DkgStartRequest, DistributedWireDkgPort, Round1WireMessage,
    Round2WireMessage, Round3WireRequest, WireDkgHub, WireDkgPeerAuth, WireDkgStatus,
};
pub use economy_memory::InMemoryEconomy;
#[cfg(feature = "dealer_lab")]
pub use frost_dealer::{dealer_fatal_banner, DealerLabAdapter, FrostDealerBundle};
pub use frost_reshare::{
    refresh_shares_in_process, FrostShareSlot, FrostShareState, PolicyReshareHook,
};
pub use frost_sign::{FrostAggregateResult, FrostSignOrchestrator};
pub use frost_tr_bitcoin::{
    load_tr_shares, persist_tr_shares, refresh_tr_shares_in_process, FrostTrBitcoinOrchestrator,
    FrostTrShareSlot, FrostTrShareState, SignedPsbtResult,
};
#[cfg(feature = "dealer_lab")]
pub use frost_tr_bitcoin::generate_tr_dealer;
pub use http::{build_router, AppState};
pub use http_peer::{
    peer_addr_is_onion, post_json_with_retry, PeerHttpSettings, VaultTransport,
};
pub use ledger_memory::InMemoryLedger;
pub use peer_memory::InMemoryPeerDirectory;
pub use release_memory::InMemoryReleaseMesh;
pub use session_persist::{
    HttpAntiNonceTransport, MemoryAntiNonceTransport, PersistedAntiNonce, QuorumAntiNonce,
    SharedAntiNonce,
};
pub use share_aead::AeadDiskShareStore;
pub use share_tee::{TeeSealAdapter, TeeSealShareStore};
pub use share_tpm::{
    build_tpm_seal_port, resolve_aead_passphrase, sealed_passphrase_path, tpm_device_present,
    ResolvedPassphrase, TpmSealAdapter, TpmSealPort,
};
pub use threshold_state::ThresholdVaultState;
