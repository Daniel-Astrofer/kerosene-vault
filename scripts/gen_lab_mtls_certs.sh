#!/usr/bin/env bash
# Generate lab-only CA + vault server/client certs for VAULT_AUTH_MODE=mtls.
# Lab ≠ go-live — do not reuse these materials for ceremony / production.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${VAULT_LAB_MTLS_OUT:-$ROOT_DIR/lab-certs}"
DAYS="${VAULT_LAB_MTLS_DAYS:-825}"
CN_SERVER="${VAULT_LAB_MTLS_SERVER_CN:-kerosene-vault-lab}"
CN_CLIENT="${VAULT_LAB_MTLS_CLIENT_CN:-kerosene-kfe-lab}"

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

echo "[1/4] Lab root CA → $OUT_DIR/ca.crt"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" -out ca.crt \
  -subj "/C=CH/ST=Zurich/L=Zurich/O=Kerosene Lab/OU=Vault Mesh/CN=Kerosene Lab Vault CA"

echo "[2/4] Vault server cert (CN=$CN_SERVER)"
openssl genrsa -out vault-server.key 2048
openssl req -new -key vault-server.key -out vault-server.csr \
  -subj "/C=CH/ST=Zurich/L=Zurich/O=Kerosene Lab/OU=Vault Server/CN=$CN_SERVER"
cat > vault-server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:vault-1,DNS:vault-2,DNS:vault-3,DNS:$CN_SERVER,IP:127.0.0.1
EOF
openssl x509 -req -in vault-server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out vault-server.crt -days "$DAYS" -sha256 -extfile vault-server.ext

echo "[3/4] Vault client cert for kfe↔vault (CN=$CN_CLIENT)"
openssl genrsa -out vault-client.key 2048
openssl req -new -key vault-client.key -out vault-client.csr \
  -subj "/C=CH/ST=Zurich/L=Zurich/O=Kerosene Lab/OU=Vault Client/CN=$CN_CLIENT"
cat > vault-client.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:localhost,DNS:$CN_CLIENT,URI:spiffe://kerosene.lab/kfe
EOF
openssl x509 -req -in vault-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out vault-client.crt -days "$DAYS" -sha256 -extfile vault-client.ext

chmod 0600 ca.key vault-server.key vault-client.key
rm -f vault-server.csr vault-client.csr vault-server.ext vault-client.ext ca.srl

echo "[4/4] Env hint (lab / staging visualize):"
cat <<EOF
  VAULT_AUTH_MODE=mtls
  VAULT_TLS_CERT_PATH=$OUT_DIR/vault-server.crt
  VAULT_TLS_KEY_PATH=$OUT_DIR/vault-server.key
  VAULT_TLS_CLIENT_CA_PATH=$OUT_DIR/ca.crt
  # vault↔vault peer DKG (required when VAULT_AUTH_MODE=mtls):
  VAULT_TLS_CLIENT_CERT_PATH=$OUT_DIR/vault-client.crt
  VAULT_TLS_CLIENT_KEY_PATH=$OUT_DIR/vault-client.key
  # client (kfe / curl):
  #   --cert $OUT_DIR/vault-client.crt --key $OUT_DIR/vault-client.key --cacert $OUT_DIR/ca.crt
Lab mTLS materials written to $OUT_DIR (not for go-live).
EOF
