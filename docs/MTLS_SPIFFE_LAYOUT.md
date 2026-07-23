# Vault mesh mTLS — SPIFFE-like layout (Gate)

Lab ≠ go-live. Materials under `lab-certs/` are for **visualize / staging** only.
A real SPIRE/SPIFFE agent is **not** required; paths and URI SANs mirror the SPIFFE SVID layout so production can drop in an agent later.

## Trust domain & SPIFFE IDs

| Identity | SPIFFE ID (lab default) | Role |
| --- | --- | --- |
| Trust domain | `kerosene.lab` | Lab / staging visualize |
| Vault server (per node) | `spiffe://kerosene.lab/vault/{VAULT_NODE_ID}` | rustls server cert (`serverAuth`); default outbound peer expect |
| Shared lab alias (optional) | `spiffe://kerosene.lab/vault/server` | Compose/scripts when `VAULT_MTLS_SPIFFE_VAULT` / `VAULT_TLS_PEER_SPIFFE_ID` override |
| kfe client | `spiffe://kerosene.lab/kfe` | Client cert to vault (`clientAuth`) |

Staging override: set `VAULT_MTLS_TRUST_DOMAIN=kerosene.staging` when generating. Each vault should use a **unique** SPIFFE ID (`VAULT_TLS_PEER_SPIFFE_ID=spiffe://…/vault/vault-1`, etc.).

## On-disk layout

After `./scripts/gen_lab_mtls_certs.sh` (or rotate):

```text
lab-certs/
  ca.crt / ca.key                 # trust anchor (flat, compose mounts)
  vault-server.crt / .key         # vault listen (VAULT_TLS_*)
  vault-client.crt / .key         # PEM client (curl / ops)
  vault-client.pkcs8.key          # PKCS#8 PEM for Java
  kfe-client.p12                  # PKCS12 client keystore (kfe)
  truststore.p12                  # PKCS12 truststore (CA only)
  rotation.json                   # last leaf issue metadata (rotate)
  spiffe/
    trust-bundle.pem              # = ca.crt
    vault/server/
      svid.pem / key.pem          # SPIFFE-like SVID paths
    kfe/
      svid.pem / key.pem
```

Compose / vault continue to use the **flat** `VAULT_TLS_*` paths. The `spiffe/` tree is the documented agent-compatible mirror.

## Short-lived rotation

```bash
# First materialization (long-lived lab CA + leaves)
./backend/kerosene-vault/scripts/gen_lab_mtls_certs.sh

# Rotate leaves only (default TTL 24h); reuses CA
VAULT_LAB_MTLS_TTL_HOURS=24 \
  ./backend/kerosene-vault/scripts/rotate_lab_mtls_certs.sh

# Optional post-rotate hook (reload vault / notify kfe)
VAULT_MTLS_ROTATE_HOOK=/path/to/hook.sh \
  ./backend/kerosene-vault/scripts/rotate_lab_mtls_certs.sh
```

Hook receives env: `VAULT_LAB_MTLS_OUT`, `VAULT_TLS_CERT_PATH`, `VAULT_TLS_KEY_PATH`,
`VAULT_TLS_CLIENT_CA_PATH`, `KFE_CLIENT_P12`, `ROTATION_JSON`.

Production Gate still requires operational cert rotation (SPIRE or equivalent) before ceremony —
these scripts are the **Gate visualize** path, not the ceremony CA.

## Tor / onion peers

When `VAULT_TRANSPORT=tor`, outbound mTLS defaults to
`VAULT_TLS_VERIFY_MODE=onion_or_spiffe` (**AND** semantics):

1. Verify the leaf chains to `VAULT_TLS_CLIENT_CA_PATH`.
2. Require URI SAN equals `VAULT_TLS_PEER_SPIFFE_ID` (default `spiffe://kerosene.lab/vault/{VAULT_NODE_ID}`).
3. When the peer host is `.onion`, **also** require a DNS SAN equal to that onion.

Hostname-only match without SPIFFE is refused. Env name stays `onion_or_spiffe` for compat.

Mint onion DNS SANs after HS discovery:

```bash
VAULT_LAB_MTLS_ONION_SANS=a.onion,b.onion,c.onion \
  ./backend/kerosene-vault/scripts/gen_lab_mtls_certs.sh
# or rotate leaves:
VAULT_LAB_MTLS_ONION_SANS=… ./backend/kerosene-vault/scripts/rotate_lab_mtls_certs.sh
```

`VAULT_AUTH_MODE=mtls ./backend/kerosene-vault/scripts/lab_dkg_wire_tor.sh` does this automatically.
See `docs/CEREMONY_TOR.md`. Staging/production ceremony modes refuse `static_token`.

## kfe TLS properties

When vaults run `VAULT_AUTH_MODE=mtls`, kfe must present a client cert and **must not**
send `X-Vault-Token` (vault refuses static tokens in mTLS mode).

```properties
kfe.vaultmesh.base-url=https://127.0.0.1:7801
kfe.vaultmesh.api-token=
kfe.vaultmesh.tls.enabled=true
# PEM (preferred with vault-client.pkcs8.key):
kfe.vaultmesh.tls.cert-path=/certs/vault-client.crt
kfe.vaultmesh.tls.key-path=/certs/vault-client.pkcs8.key
kfe.vaultmesh.tls.ca-path=/certs/ca.crt
# Or PKCS12:
# kfe.vaultmesh.tls.keystore-path=/certs/kfe-client.p12
# kfe.vaultmesh.tls.keystore-password=changeit
# kfe.vaultmesh.tls.truststore-path=/certs/truststore.p12
# kfe.vaultmesh.tls.truststore-password=changeit
```

See `kfe-service-vaultmesh-go-live.properties` and staging compose comments.
