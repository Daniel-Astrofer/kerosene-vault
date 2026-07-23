#!/usr/bin/env bash
# Rotate short-lived leaf certs for lab/staging mTLS (reuses CA).
# SPIFFE-like layout refreshed in place. Lab ≠ go-live / ceremony.
#
# Usage:
#   ./scripts/gen_lab_mtls_certs.sh          # once (creates CA)
#   VAULT_LAB_MTLS_TTL_HOURS=24 ./scripts/rotate_lab_mtls_certs.sh
#
# Optional reload hook:
#   VAULT_MTLS_ROTATE_HOOK=/path/to/hook.sh ./scripts/rotate_lab_mtls_certs.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=mtls_cert_lib.sh
source "$SCRIPT_DIR/mtls_cert_lib.sh"

OUT_DIR="${VAULT_LAB_MTLS_OUT:-$ROOT_DIR/lab-certs}"
TTL_HOURS="${VAULT_LAB_MTLS_TTL_HOURS:-24}"
TRUST_DOMAIN="${VAULT_MTLS_TRUST_DOMAIN:-kerosene.lab}"
CN_SERVER="${VAULT_LAB_MTLS_SERVER_CN:-kerosene-vault-lab}"
CN_CLIENT="${VAULT_LAB_MTLS_CLIENT_CN:-kerosene-kfe-lab}"
P12_PASS="${VAULT_LAB_MTLS_P12_PASSWORD:-changeit}"
SPIFFE_VAULT="${VAULT_MTLS_SPIFFE_VAULT:-spiffe://${TRUST_DOMAIN}/vault/server}"
SPIFFE_KFE="${VAULT_MTLS_SPIFFE_KFE:-spiffe://${TRUST_DOMAIN}/kfe}"
HOOK="${VAULT_MTLS_ROTATE_HOOK:-}"

if [[ ! -f "$OUT_DIR/ca.crt" || ! -f "$OUT_DIR/ca.key" ]]; then
  echo "error: CA missing under $OUT_DIR — run gen_lab_mtls_certs.sh first" >&2
  exit 1
fi

# OpenSSL -days is day-granularity; ceil hours → days (min 1).
DAYS=$(( (TTL_HOURS + 23) / 24 ))
if [[ "$DAYS" -lt 1 ]]; then
  DAYS=1
fi

STAGING="$(mktemp -d "${TMPDIR:-/tmp}/kerosene-mtls-rotate.XXXXXX")"
cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

cp -f "$OUT_DIR/ca.crt" "$OUT_DIR/ca.key" "$STAGING/"
cd "$STAGING"

echo "[rotate] issuing leaves TTL≈${TTL_HOURS}h (openssl days=${DAYS}) → $OUT_DIR"
mtls_issue_leaf \
  "vault-server" "$CN_SERVER" "serverAuth" "$SPIFFE_VAULT" "$DAYS" \
  "DNS:localhost,DNS:vault-1,DNS:vault-2,DNS:vault-3,DNS:$CN_SERVER,IP:127.0.0.1"
mtls_issue_leaf \
  "vault-client" "$CN_CLIENT" "clientAuth" "$SPIFFE_KFE" "$DAYS" \
  "DNS:localhost,DNS:$CN_CLIENT"

mtls_write_java_materials "$STAGING" "$P12_PASS"
mtls_sync_spiffe_tree "$STAGING" "$SPIFFE_VAULT" "$SPIFFE_KFE"

# Atomic-ish publish: copy leaves + java + spiffe; never overwrite CA from staging blanks.
install -m 0644 vault-server.crt vault-client.crt "$OUT_DIR/"
install -m 0600 vault-server.key vault-client.key vault-client.pkcs8.key "$OUT_DIR/"
install -m 0600 kfe-client.p12 truststore.p12 "$OUT_DIR/"
rm -rf "$OUT_DIR/spiffe"
cp -a spiffe "$OUT_DIR/spiffe"
mtls_write_rotation_json "$OUT_DIR" "$TTL_HOURS" "$SPIFFE_VAULT" "$SPIFFE_KFE"

export VAULT_LAB_MTLS_OUT="$OUT_DIR"
export VAULT_TLS_CERT_PATH="$OUT_DIR/vault-server.crt"
export VAULT_TLS_KEY_PATH="$OUT_DIR/vault-server.key"
export VAULT_TLS_CLIENT_CA_PATH="$OUT_DIR/ca.crt"
export KFE_CLIENT_P12="$OUT_DIR/kfe-client.p12"
export ROTATION_JSON="$OUT_DIR/rotation.json"

echo "[rotate] published leaves + SPIFFE tree under $OUT_DIR"
cat "$OUT_DIR/rotation.json"

if [[ -n "$HOOK" ]]; then
  if [[ ! -x "$HOOK" ]]; then
    echo "error: VAULT_MTLS_ROTATE_HOOK is not executable: $HOOK" >&2
    exit 1
  fi
  echo "[rotate] invoking hook $HOOK"
  "$HOOK"
fi

echo "[rotate] done — restart/reload vault (and kfe TLS materials) to pick up new leaves"
