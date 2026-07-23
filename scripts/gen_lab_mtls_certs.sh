#!/usr/bin/env bash
# Generate lab-only CA + vault server/client certs for VAULT_AUTH_MODE=mtls.
# Emits flat paths (compose) + SPIFFE-like SVID tree. Lab ≠ go-live.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=mtls_cert_lib.sh
source "$SCRIPT_DIR/mtls_cert_lib.sh"

OUT_DIR="${VAULT_LAB_MTLS_OUT:-$ROOT_DIR/lab-certs}"
DAYS="${VAULT_LAB_MTLS_DAYS:-825}"
TRUST_DOMAIN="${VAULT_MTLS_TRUST_DOMAIN:-kerosene.lab}"
CN_SERVER="${VAULT_LAB_MTLS_SERVER_CN:-kerosene-vault-lab}"
CN_CLIENT="${VAULT_LAB_MTLS_CLIENT_CN:-kerosene-kfe-lab}"
P12_PASS="${VAULT_LAB_MTLS_P12_PASSWORD:-changeit}"
SPIFFE_VAULT="${VAULT_MTLS_SPIFFE_VAULT:-spiffe://${TRUST_DOMAIN}/vault/server}"
SPIFFE_KFE="${VAULT_MTLS_SPIFFE_KFE:-spiffe://${TRUST_DOMAIN}/kfe}"

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

echo "[1/5] Lab root CA → $OUT_DIR/ca.crt"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" -out ca.crt \
  -subj "/C=CH/ST=Zurich/L=Zurich/O=Kerosene Lab/OU=Vault Mesh/CN=Kerosene Lab Vault CA"

echo "[2/5] Vault server cert (CN=$CN_SERVER, SPIFFE=$SPIFFE_VAULT)"
# Optional onion DNS SANs (comma-separated) for Tor mTLS hostname verify.
# SPIFFE URI is always present — Tor clients may verify URI when onions change.
EXTRA_SAN="DNS:localhost,DNS:vault-1,DNS:vault-2,DNS:vault-3,DNS:$CN_SERVER,IP:127.0.0.1"
if [[ -n "${VAULT_LAB_MTLS_ONION_SANS:-}" ]]; then
  IFS=',' read -r -a _onions <<< "${VAULT_LAB_MTLS_ONION_SANS}"
  for o in "${_onions[@]}"; do
    o="$(echo "$o" | tr -d '[:space:]')"
    o="${o#http://}"; o="${o#https://}"; o="${o%%:*}"; o="${o%%/*}"
    [[ -n "$o" ]] || continue
    EXTRA_SAN="${EXTRA_SAN},DNS:${o}"
  done
fi
mtls_issue_leaf \
  "vault-server" "$CN_SERVER" "serverAuth" "$SPIFFE_VAULT" "$DAYS" \
  "$EXTRA_SAN"

echo "[3/5] Vault client cert for kfe↔vault (CN=$CN_CLIENT, SPIFFE=$SPIFFE_KFE)"
mtls_issue_leaf \
  "vault-client" "$CN_CLIENT" "clientAuth" "$SPIFFE_KFE" "$DAYS" \
  "DNS:localhost,DNS:$CN_CLIENT"

echo "[4/5] Java materials (PKCS#8 + PKCS12) + SPIFFE-like tree"
mtls_write_java_materials "$OUT_DIR" "$P12_PASS"
mtls_sync_spiffe_tree "$OUT_DIR" "$SPIFFE_VAULT" "$SPIFFE_KFE"

chmod 0600 ca.key vault-server.key vault-client.key vault-client.pkcs8.key 2>/dev/null || true
chmod 0600 kfe-client.p12 truststore.p12 2>/dev/null || true

echo "[5/5] Env hint (lab / staging visualize):"
cat <<EOF
  VAULT_AUTH_MODE=mtls
  VAULT_TLS_CERT_PATH=$OUT_DIR/vault-server.crt
  VAULT_TLS_KEY_PATH=$OUT_DIR/vault-server.key
  VAULT_TLS_CLIENT_CA_PATH=$OUT_DIR/ca.crt
  # kfe (PEM):
  #   kfe.vaultmesh.tls.enabled=true
  #   kfe.vaultmesh.tls.cert-path=$OUT_DIR/vault-client.crt
  #   kfe.vaultmesh.tls.key-path=$OUT_DIR/vault-client.pkcs8.key
  #   kfe.vaultmesh.tls.ca-path=$OUT_DIR/ca.crt
  # kfe (PKCS12):
  #   kfe.vaultmesh.tls.keystore-path=$OUT_DIR/kfe-client.p12
  #   kfe.vaultmesh.tls.truststore-path=$OUT_DIR/truststore.p12
  #   password=$P12_PASS
  # curl:
  #   --cert $OUT_DIR/vault-client.crt --key $OUT_DIR/vault-client.key --cacert $OUT_DIR/ca.crt
  # SPIFFE-like: $OUT_DIR/spiffe/ (see docs/MTLS_SPIFFE_LAYOUT.md)
Lab mTLS materials written to $OUT_DIR (not for go-live).
EOF
