# Production-native genesis ceremony (short runbook)

Same binary and FROST over-wire rounds as lab (`VAULT_DKG_MODE=distributed_wire`).
Only config / attestation / auth differ. Dealer and `ATTESTATION_MODE=sim` are refused.

## All-domestic (Ryzen-class / home PC)

1. On each of N hosts (example N=3):
   - `VAULT_CEREMONY_MODE=production` (or `KEROSENE_ENV=production`)
   - `VAULT_NODE_TIER=domestic` (or `auto` with no `/dev/sev-guest`)
   - `ATTESTATION_MODE=software`
   - `VAULT_SHARE_STORE=aead_disk`
   - `VAULT_DKG_MODE=distributed_wire`
   - `VAULT_AUTH_MODE=mtls` + TLS paths
   - `VAULT_GENESIS_N=3` + reciprocal `VAULT_SEED_PEERS`
   - **Do not** set `ATTESTATION_STAGING_STUB` or `LAB_TIMELOCK_SCALE`
2. Gate: `./scripts/genesis_ceremony_checklist.sh`
3. Bring up peers (compose reference: `infra/docker/compose/vault-mesh-ceremony.compose.yaml`).
4. Confirm `GET /v1/health`: `node_tier=domestic`, `attestation_mode=software`, `tee_available=false`, `genesis_roster` lists N ids.
5. Run `./backend/kerosene-vault/scripts/genesis_dkg_wire.sh` (mTLS client certs).
6. Cutover kfe: mesh enabled, `kfe.mpc.signing-enabled=false` — do not revive HashiCorp/mpc for treasury.

## Mixed SEV-priority

1. Same as above for domestic members; SEV hosts set `VAULT_NODE_TIER=sev`, `ATTESTATION_MODE=sev`, `VAULT_SHARE_STORE=tee_seal`, and real `/dev/sev-guest` (no stub).
2. Publish peer tiers on every node: `VAULT_PEER_TIERS=vault-epyc=sev,...`
3. Boot seating fills `VAULT_GENESIS_N` preferring SEV > SGX > domestic; health `genesis_roster` shows the seated set.
4. Run the **same** `genesis_dkg_wire.sh` — roster must match seating (enforced in production).

## Lab vs production

| | Lab | Production ceremony |
| --- | --- | --- |
| Binary | same crate | `--features production` preferred |
| DKG | `distributed_wire` (or dealer_lab visualize) | **only** `distributed_wire` |
| Attestation | `sim` OK | `software` / `sev` / `sgx` honest |
| Auth | static token OK | mTLS |
| Seating | same algorithm | same algorithm |

See `VAULT_MESH_PLAN.md` §3.1.
