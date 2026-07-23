#!/usr/bin/env bash
# Lab: run over-wire FROST DKG across 3 vault peers (no dealer).
# Expects vault-mesh-lab.compose.yaml with VAULT_DKG_MODE=distributed_wire
# and matching VAULT_API_TOKEN on all nodes.
#
# Usage (repo root):
#   VAULT_DKG_MODE=distributed_wire docker compose -f infra/docker/compose/vault-mesh-lab.compose.yaml up --build -d
#   ./backend/kerosene-vault/scripts/lab_dkg_wire.sh
#
# In-process fallback (no compose peers): VAULT_DKG_MODE=distributed inside one process.
set -euo pipefail

TOKEN="${VAULT_API_TOKEN:-kerosene-vault-lab-only}"
SESSION_ID="${VAULT_DKG_SESSION:-lab-dkg-$(date -u +%Y%m%dT%H%M%SZ)}"
ROSTER='["vault-1","vault-2","vault-3"]'
MAX=3
MIN=2

BASES=(
  "${VAULT1_URL:-http://127.0.0.1:7701}"
  "${VAULT2_URL:-http://127.0.0.1:7702}"
  "${VAULT3_URL:-http://127.0.0.1:7703}"
)

post_json() {
  local url="$1"
  local body="$2"
  curl -fsS -X POST \
    -H "X-Vault-Token: ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "$url"
}

echo "== Over-wire DKG session=$SESSION_ID (n=$MAX t=$MIN, no dealer) =="

echo "-- Round1 start on each vault"
declare -a R1_MSGS=()
for base in "${BASES[@]}"; do
  resp="$(post_json "${base}/v1/dkg/round1" "$(cat <<EOF
{"session_id":"${SESSION_ID}","max_signers":${MAX},"min_signers":${MIN},"roster":${ROSTER},"fanout":false}
EOF
)")"
  msg="$(echo "$resp" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["round1"]))')"
  R1_MSGS+=("$msg")
  echo "  started at $base"
done

echo "-- Round1 ingest (cross-post packages)"
for base in "${BASES[@]}"; do
  for msg in "${R1_MSGS[@]}"; do
    post_json "${base}/v1/dkg/round1" "$msg" >/dev/null
  done
done

echo "-- Round2 deliver + cross-ingest"
declare -a R2_MSGS=()
for base in "${BASES[@]}"; do
  resp="$(post_json "${base}/v1/dkg/round2" "{\"session_id\":\"${SESSION_ID}\",\"deliver\":true,\"fanout\":false}")"
  while IFS= read -r line; do
    [[ -n "$line" ]] && R2_MSGS+=("$line")
  done < <(echo "$resp" | python3 -c 'import json,sys; [print(json.dumps(m)) for m in json.load(sys.stdin).get("outbound",[])]')
done

for msg in "${R2_MSGS[@]}"; do
  recip="$(echo "$msg" | python3 -c 'import json,sys; print(json.load(sys.stdin)["recipient_node_id"])')"
  case "$recip" in
    vault-1) base="${BASES[0]}" ;;
    vault-2) base="${BASES[1]}" ;;
    vault-3) base="${BASES[2]}" ;;
    *) echo "unknown recipient $recip"; exit 1 ;;
  esac
  post_json "${base}/v1/dkg/round2" "$msg" >/dev/null
done

echo "-- Round3 finalize (each vault keeps only its share)"
for base in "${BASES[@]}"; do
  st="$(post_json "${base}/v1/dkg/round3" "{\"session_id\":\"${SESSION_ID}\",\"finalize\":true}")"
  echo "  $base -> $st"
done

echo "OK: over-wire DKG complete (lab only; not go-live)."
