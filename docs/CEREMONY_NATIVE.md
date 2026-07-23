# Production-native genesis ceremony (short runbook)

Same binary and FROST over-wire rounds as lab (`VAULT_DKG_MODE=distributed_wire`).
Only config / attestation / auth differ. Dealer and `ATTESTATION_MODE=sim` are refused.

## All-domestic (Ryzen-class / home PC)

1. On each of N hosts (example N=3):
   - `VAULT_CEREMONY_MODE=production` (or `KEROSENE_ENV=production`)
   - `VAULT_NODE_TIER=domestic` (or `auto` with no `/dev/sev-guest`)
   - `ATTESTATION_MODE=software`
   - `VAULT_SHARE_STORE=aead_disk`
   - Optional TPM seal (disk-at-rest; **not** SEV): `VAULT_SHARE_TPM_SEAL=1` + real TPM, or lab mock `VAULT_SHARE_TPM_STUB=1`. Fail-closed without TPM unless lab `VAULT_SHARE_TPM_CLEAR_FALLBACK=1`.
   - `VAULT_DKG_MODE=distributed_wire`
   - `VAULT_AUTH_MODE=mtls` + TLS paths
   - `VAULT_GENESIS_N=3` + reciprocal `VAULT_SEED_PEERS`
   - **Do not** set `ATTESTATION_STAGING_STUB` or `LAB_TIMELOCK_SCALE`
2. Gate: `./scripts/genesis_ceremony_checklist.sh`
3. Bring up peers (compose reference: `infra/docker/compose/vault-mesh-ceremony.compose.yaml`).
4. Confirm `GET /health` (auth): `node_tier=domestic`, `attestation_mode=software`, `tee_available=false`, `genesis_roster` lists N ids. Public `GET /v1/health` returns status only (no roster).
5. Run `./backend/kerosene-vault/scripts/genesis_dkg_wire.sh` (mTLS client certs).
6. Cutover kfe: mesh enabled, `kfe.mpc.signing-enabled=false` — do not revive HashiCorp/mpc for treasury.

## Mixed SEV-priority

1. Same as above for domestic members; SEV hosts set `VAULT_NODE_TIER=sev`, `ATTESTATION_MODE=sev`, `VAULT_SHARE_STORE=tee_seal`, and real `/dev/sev-guest` (no stub).
2. Publish peer tiers on every node: `VAULT_PEER_TIERS=vault-epyc=sev,...`
3. Boot seating fills `VAULT_GENESIS_N` preferring SEV > SGX > domestic; authenticated `/health` `genesis_roster` shows the seated set.
4. Run the **same** `genesis_dkg_wire.sh` — roster must match seating (enforced in production).

## Lab vs production

| | Lab | Production ceremony |
| --- | --- | --- |
| Binary | same crate | `--features production` preferred |
| DKG | `distributed_wire` (or dealer_lab visualize) | **only** `distributed_wire` |
| Transport | clearnet lab **or** Tor lab (`vault-mesh-tor`) | **`VAULT_TRANSPORT=tor`** + onion peers + SOCKS (required) |
| Attestation | `sim` OK | `software` / `sev` / `sgx` honest |
| Auth | static token OK | mTLS |
| Seating | same algorithm | same algorithm |

**Tor runbook:** `docs/CEREMONY_TOR.md`. `deploy.sh` still starts clearnet `vault-mesh-lab` — not the Tor ceremony profile.

See `VAULT_MESH_PLAN.md` §3.1.

### Optional TPM seal (domestic AEAD)

| Var | Meaning |
| --- | --- |
| `VAULT_SHARE_TPM_SEAL=1` | Seal AEAD passphrase before `AeadDiskShareStore` (off by default) |
| `VAULT_SHARE_TPM_STUB=1` | Lab/mock TPM envelope (no HW); refused in production ceremony |
| `VAULT_SHARE_TPM_CLEAR_FALLBACK=1` | Lab only: clear passphrase if TPM unavailable; refused when hardened |

TPM binds disk-at-rest to the machine; it does **not** isolate share RAM after unseal (unlike SEV-SNP).

## Gaps (planned — do not claim shipped)

| Gap | Notes |
| --- | --- |
| **Full SNP VCEK verification** | HW path **fail-closed** without real `/dev/sev-guest` + VCEK chain; staging stub is lab-only (`ATTESTATION_STAGING_STUB`). Not production-complete. |
| **CHANNELS → LND inject** | CHANNELS bucket cannot spend shared Taproot key; kfe `ChannelsMeshInjectGateway` fail-closed (`CHANNELS_MESH_INJECT_NOT_WIRED`); go-live requires inject + disables auto-open — inject wiring still planned |
| **Deposit xpub vs `tb1p`** | Ceremony yields stable mesh `tb1p` deposit (`tr()`); user-visible xpub / HD from group VK is not implemented; product `bitcoin.platform.master-xpub` ≠ mesh deposit |
| **Economy / release durability (#18)** | `InMemoryEconomy` / `InMemoryReleaseMesh` — restart loses state; not an authenticated mesh ledger |
| **Supply-chain audit (#38)** | Crate dependencies not audited in this hygiene pass — residual |
| **Side-channel analysis (#39)** | Full FROST/nonce zeroize side-channel review residual |
| **mTLS pin / CRL (#36)** | Short-lived rotation scripts exist; runtime pin/CRL not enforced |
| **Legacy HTTP surface (#37)** | Path traversal blocked; large legacy route surface remains behind auth |

Go-live kfe: `kfe-service-vaultmesh-go-live.properties` sets `mesh-only` + `require-mtls` (refuses `api-token`). Vault hygiene refuses `static_token` / `ATTESTATION_MODE=sim` / clearnet under staging/production; production ceremony requires `VAULT_TRANSPORT=tor` + mTLS.
