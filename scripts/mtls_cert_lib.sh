#!/usr/bin/env bash
# Shared helpers for lab/staging mTLS materialization (SPIFFE-like). Not for ceremony.
# shellcheck shell=bash

mtls_issue_leaf() {
  local prefix="$1"
  local cn="$2"
  local eku="$3"
  local spiffe_id="$4"
  local days="$5"
  local extra_san="$6"

  openssl genrsa -out "${prefix}.key" 2048
  openssl req -new -key "${prefix}.key" -out "${prefix}.csr" \
    -subj "/C=CH/ST=Zurich/L=Zurich/O=Kerosene Lab/OU=Vault Mesh/CN=${cn}"
  cat > "${prefix}.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=${eku}
subjectAltName=${extra_san},URI:${spiffe_id}
EOF
  openssl x509 -req -in "${prefix}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "${prefix}.crt" -days "${days}" -sha256 -extfile "${prefix}.ext"
  rm -f "${prefix}.csr" "${prefix}.ext" ca.srl
}

mtls_write_java_materials() {
  local out_dir="$1"
  local p12_pass="$2"
  openssl pkcs8 -topk8 -nocrypt -in "${out_dir}/vault-client.key" \
    -out "${out_dir}/vault-client.pkcs8.key"
  openssl pkcs12 -export \
    -inkey "${out_dir}/vault-client.key" \
    -in "${out_dir}/vault-client.crt" \
    -certfile "${out_dir}/ca.crt" \
    -out "${out_dir}/kfe-client.p12" \
    -name kfe-client \
    -passout "pass:${p12_pass}"
  # Truststore: CA only
  openssl pkcs12 -export \
    -nokeys \
    -in "${out_dir}/ca.crt" \
    -out "${out_dir}/truststore.p12" \
    -name vault-mesh-ca \
    -passout "pass:${p12_pass}"
}

mtls_sync_spiffe_tree() {
  local out_dir="$1"
  local spiffe_vault="$2"
  local spiffe_kfe="$3"
  mkdir -p "${out_dir}/spiffe/vault/server" "${out_dir}/spiffe/kfe"
  cp -f "${out_dir}/ca.crt" "${out_dir}/spiffe/trust-bundle.pem"
  cp -f "${out_dir}/vault-server.crt" "${out_dir}/spiffe/vault/server/svid.pem"
  cp -f "${out_dir}/vault-server.key" "${out_dir}/spiffe/vault/server/key.pem"
  cp -f "${out_dir}/vault-client.crt" "${out_dir}/spiffe/kfe/svid.pem"
  cp -f "${out_dir}/vault-client.key" "${out_dir}/spiffe/kfe/key.pem"
  chmod 0600 "${out_dir}/spiffe/vault/server/key.pem" "${out_dir}/spiffe/kfe/key.pem"
  cat > "${out_dir}/spiffe/README.txt" <<EOF
SPIFFE-like SVID mirror (no SPIRE agent required).
  vault: ${spiffe_vault}
  kfe:   ${spiffe_kfe}
See docs/MTLS_SPIFFE_LAYOUT.md
EOF
}

mtls_write_rotation_json() {
  local out_dir="$1"
  local ttl_hours="$2"
  local spiffe_vault="$3"
  local spiffe_kfe="$4"
  local issued
  issued="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local expires
  if expires="$(date -u -d "+${ttl_hours} hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"; then
    :
  elif expires="$(date -u -v+"${ttl_hours}"H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"; then
    :
  else
    expires="unknown"
  fi
  cat > "${out_dir}/rotation.json" <<EOF
{
  "issued_at": "${issued}",
  "expires_at": "${expires}",
  "ttl_hours": ${ttl_hours},
  "spiffe_vault": "${spiffe_vault}",
  "spiffe_kfe": "${spiffe_kfe}",
  "trust_bundle": "${out_dir}/spiffe/trust-bundle.pem"
}
EOF
}
