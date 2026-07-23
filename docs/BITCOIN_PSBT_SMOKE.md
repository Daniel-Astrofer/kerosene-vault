# Mesh Bitcoin send smoke (testnet3)

Lab path: **FE → kfe ONCHAIN outbound → Core funds PSBT → vault mesh Taproot FROST signs → Core finalize/broadcast**.

## Prerequisites

- Vault mesh up with `dealer_lab` (Taproot FROST keyset installed)
- `bitcoin.network=testnet3`
- kfe: `kfe.vaultmesh.enabled=true`, `mesh-only=true`, `submit-on-outbound=true`, `kfe.mpc.signing-enabled=false`
- Bitcoin Core wallet can see mesh UTXOs (watch-only `tr()` import)

## Steps

```bash
TOKEN=kerosene-vault-lab-only
VAULT=http://127.0.0.1:7701

# 1) Mesh deposit address + descriptor
curl -s -H "X-Vault-Token: $TOKEN" "$VAULT/v1/bitcoin/deposit"
# → {"network":"testnet3","address":"tb1p…","descriptor":"tr(…)","scheme":"frost-secp256k1-tr-v3",…}

# 2) Import watch-only into Core (example; use your RPC wrapper)
# bitcoin-cli importdescriptors '[{"desc":"tr(OUTPUT_PUBKEY)#checksum","timestamp":"now","active":false,"internal":false}]'

# 3) Fund tb1p… on testnet3; wait for confirmation

# 4) FE / API: submit ONCHAIN OUTBOUND to a tb1… destination (user withdraw)
# Outbox drain: createFundedPsbt → POST /v1/bitcoin/sign-psbt → finalizepsbt → sendrawtransaction

# Optional: direct vault PSBT sign (after Intent fields)
# curl -s -X POST -H "X-Vault-Token: $TOKEN" -H 'Content-Type: application/json' \
#   "$VAULT/v1/bitcoin/sign-psbt" \
#   -d '{"session_id":"btc-psbt-smoke-1","intent_id":"smoke-1","bucket":"USERS","destination":"tb1q…","amount_sats":1000,"psbt":"<base64>"}'
```

## Fail-stop / mesh-only

- Online &lt; t → vault returns fail-stop; kfe marks provider failure (no mpc fallback)
- `mesh-only=true` disables local Core `walletprocesspsbt` signing even if the flag is set

## Remaining gaps vs legacy Core/mpc path

- Treasury UTXOs must live on the mesh Taproot deposit (not hot Core keys)
- Single key-path Taproot spend path; no BIP32 change derivation under FROST yet
- Multi-input works if all inputs are mesh `tr()` UTXOs; mixed script types not signed
- Distributed DKG for Taproot keyset still lab-dealer for this path
