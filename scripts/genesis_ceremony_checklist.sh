#!/usr/bin/env bash
# F8 production genesis ceremony checklist (human + automation gate).
# Does NOT perform DKG — prints required steps and fails if env is unsafe.
#
# Native ceremony supports:
#   - all-domestic (Ryzen/home PC): VAULT_NODE_TIER=domestic ATTESTATION_MODE=software
#   - mixed: SEV/SGX peers preferred for genesis seats via VAULT_PEER_TIERS
# Does NOT require every node to have EPYC/SEV. Refuses fake TEE claims / staging stub in prod.
#
# Same code path as lab over-wire DKG: VAULT_DKG_MODE=distributed_wire (config differs only).
set -euo pipefail

echo "== Kerosene vault genesis ceremony checklist (F8) =="
MODE="${VAULT_CEREMONY_MODE:-${KEROSENE_ENV:-lab}}"
TIER="${VAULT_NODE_TIER:-auto}"
ATT="${ATTESTATION_MODE:-}"
DKG="${VAULT_DKG_MODE:-${VAULT_DKG:-}}"
echo "ceremony_mode=$MODE node_tier=$TIER attestation_mode=${ATT:-unset} dkg_mode=${DKG:-unset}"

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
    check "$([[ -z "${LAB_TIMELOCK_SCALE+x}" ]] && echo 1 || echo 0)" \
      "LAB_TIMELOCK_SCALE unset"
    check "$([[ "${ATTESTATION_STAGING_STUB:-0}" != "1" ]] && echo 1 || echo 0)" \
      "ATTESTATION_STAGING_STUB not enabled"
    check "$([[ -n "${VAULT_GENESIS_N:-}" ]] && echo 1 || echo 0)" \
      "VAULT_GENESIS_N set (${VAULT_GENESIS_N:-})"
    check "$([[ -n "${VAULT_SEED_PEERS:-}" ]] && echo 1 || echo 0)" \
      "VAULT_SEED_PEERS set"
    check "$([[ "${DKG}" == "distributed_wire" || "${DKG}" == "wire" || "${DKG}" == "over_wire" ]] && echo 1 || echo 0)" \
      "VAULT_DKG_MODE=distributed_wire (got ${DKG:-unset})"
    check "$([[ "${VAULT_AUTH_MODE:-}" == "mtls" || "${VAULT_AUTH_MODE:-}" == "mutual_tls" ]] && echo 1 || echo 0)" \
      "VAULT_AUTH_MODE=mtls (got ${VAULT_AUTH_MODE:-unset})"

    case "${ATT}" in
      software|sev|sgx)
        check 1 "ATTESTATION_MODE is software|sev|sgx (got ${ATT})"
        ;;
      sim|"")
        check 0 "ATTESTATION_MODE must be software (domestic) or sev|sgx (got ${ATT:-unset}; sim is lab-only)"
        ;;
      *)
        check 0 "ATTESTATION_MODE is software|sev|sgx (got ${ATT})"
        ;;
    esac

    case "${TIER}" in
      domestic|sev|sgx|auto)
        check 1 "VAULT_NODE_TIER is domestic|sev|sgx|auto (got ${TIER})"
        ;;
      *)
        check 0 "VAULT_NODE_TIER is domestic|sev|sgx|auto (got ${TIER})"
        ;;
    esac

    if [[ "${ATT}" == "sev" || "${ATT}" == "sgx" || "${TIER}" == "sev" || "${TIER}" == "sgx" ]]; then
      echo "[..] TEE claim: ensure /dev/sev-guest (or SGX device) exists; stub forbidden in production"
      if [[ -e /dev/sev-guest || -e /dev/sev || -e /dev/sgx_enclave || -e /dev/sgx/enclave || -e /dev/isgx ]]; then
        check 1 "TEE device node present on this host"
      else
        check 0 "TEE device node missing (cannot advertise SEV/SGX without HW)"
      fi
    else
      echo "[..] Domestic-native path: AEAD share store + software measurement (TPM optional seal); not SEV"
    fi

    echo
    echo "Manual ceremony steps (same FROST wire path as lab; config only differs):"
    echo "  1. Bring N vaults with identical constitution seed / peer set"
    echo "     - All domestic: VAULT_NODE_TIER=domestic ATTESTATION_MODE=software VAULT_SHARE_STORE=aead_disk"
    echo "     - Mixed: set VAULT_PEER_TIERS=id=sev,... so seating prefers SEV > SGX > domestic"
    echo "  2. Verify honest labels on GET /v1/health (node_tier, attestation_mode, tee_available, genesis_roster)"
    echo "  3. Run ./backend/kerosene-vault/scripts/genesis_dkg_wire.sh (VAULT_DKG_MODE=distributed_wire)"
    echo "  4. Freeze mpc-sidecar / HashiCorp wallet-arming (kfe.mpc.signing-enabled=false)"
    echo "  5. Enable kfe.vaultmesh.enabled=true + mesh-only=true (no hard tee_hw require)"
    echo "  6. Smoke Intent → Receipt; confirm fail-stop runbook"
    echo "  7. Do NOT re-enable mpc as silent rollback"
    ;;
  staging)
    check "$([[ "${ATT}" == "sev" || "${ATT}" == "sgx" || "${ATT}" == "software" ]] && echo 1 || echo 0)" \
      "ATTESTATION_MODE is software|sev|sgx"
    check "$([[ -z "${LAB_TIMELOCK_SCALE+x}" ]] && echo 1 || echo 0)" \
      "LAB_TIMELOCK_SCALE unset"
    check "$([[ "${DKG}" == "distributed_wire" || "${DKG}" == "wire" || "${DKG}" == "over_wire" || -z "${DKG}" ]] && echo 1 || echo 0)" \
      "VAULT_DKG_MODE is distributed_wire or default (got ${DKG:-default})"
    echo "Staging may use ATTESTATION_STAGING_STUB=1 for TEE claims until hardware arrives."
    echo "Domestic staging: VAULT_NODE_TIER=domestic ATTESTATION_MODE=software (no stub)."
    ;;
  *)
    echo "Lab mode: no production gates. Compose sets VAULT_NODE_TIER=domestic + ATTESTATION_MODE=sim."
    echo "Exercise production path locally with VAULT_DKG_MODE=distributed_wire + lab_dkg_wire.sh / genesis_dkg_wire.sh."
    ;;
esac

if [[ "$fail" -ne 0 ]]; then
  echo "Ceremony checklist FAILED"
  exit 1
fi
echo "Ceremony checklist PASSED (or lab)"
