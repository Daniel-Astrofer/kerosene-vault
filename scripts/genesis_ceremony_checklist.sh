#!/usr/bin/env bash
# F8 production genesis ceremony checklist (human + automation gate).
# Does NOT perform DKG — prints required steps and fails if env is unsafe.
set -euo pipefail

echo "== Kerosene vault genesis ceremony checklist (F8) =="
MODE="${VAULT_CEREMONY_MODE:-${KEROSENE_ENV:-lab}}"
echo "ceremony_mode=$MODE"

fail=0
check() {
  local ok="$1" msg="$2"
  if [[ "$ok" == "1" ]]; then
    echo "[OK] $msg"
  else
    echo "[!!] $msg"
    fail=1
  fi
}

case "$MODE" in
  production|prod)
    check "$([[ "${ATTESTATION_MODE:-}" == "sev" || "${ATTESTATION_MODE:-}" == "sgx" ]] && echo 1 || echo 0)" \
      "ATTESTATION_MODE is sev|sgx (got ${ATTESTATION_MODE:-unset})"
    check "$([[ -z "${LAB_TIMELOCK_SCALE+x}" ]] && echo 1 || echo 0)" \
      "LAB_TIMELOCK_SCALE unset"
    check "$([[ "${ATTESTATION_STAGING_STUB:-0}" != "1" ]] && echo 1 || echo 0)" \
      "ATTESTATION_STAGING_STUB not enabled"
    check "$([[ -n "${VAULT_GENESIS_N:-}" ]] && echo 1 || echo 0)" \
      "VAULT_GENESIS_N set (${VAULT_GENESIS_N:-})"
    check "$([[ -n "${VAULT_SEED_PEERS:-}" ]] && echo 1 || echo 0)" \
      "VAULT_SEED_PEERS set"
    echo
    echo "Manual ceremony steps:"
    echo "  1. Bring N vaults with identical constitution seed / peer set"
    echo "  2. Verify TEE quotes (hardware) on each node"
    echo "  3. Run DKG genesis; confirm no node holds full key"
    echo "  4. Freeze mpc-sidecar / HashiCorp wallet-arming (kfe.mpc.signing-enabled=false)"
    echo "  5. Enable kfe.vaultmesh.enabled=true + mesh-only=true"
    echo "  6. Smoke Intent → Receipt; confirm fail-stop runbook"
    echo "  7. Do NOT re-enable mpc as silent rollback"
    ;;
  staging)
    check "$([[ "${ATTESTATION_MODE:-}" == "sev" || "${ATTESTATION_MODE:-}" == "sgx" ]] && echo 1 || echo 0)" \
      "ATTESTATION_MODE is sev|sgx"
    check "$([[ -z "${LAB_TIMELOCK_SCALE+x}" ]] && echo 1 || echo 0)" \
      "LAB_TIMELOCK_SCALE unset"
    echo "Staging may use ATTESTATION_STAGING_STUB=1 until hardware arrives."
    ;;
  *)
    echo "Lab mode: no production gates."
    ;;
esac

if [[ "$fail" -ne 0 ]]; then
  echo "Ceremony checklist FAILED"
  exit 1
fi
echo "Ceremony checklist PASSED (or lab)"
