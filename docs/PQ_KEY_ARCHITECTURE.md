# PQ Key Architecture — Kerosene Vault Mesh

> **Document Status:** Draft  
> **Last Updated:** 2026-07-30  
> **Related:** `docs/security/QUANTUM_THREAT_MODEL.md`, `docs/plans/VAULT_IMPLEMENTATION_PLAN.md`

## Key Tree Namespace

```
vault/<node_id>/
  ├── custody/          # FROST secp256k1 — Bitcoin custody
  │   └── frost_share
  ├── identity/         # Vault identity authentication
  │   ├── ed25519       # Classical identity key
  │   └── ml_dsa_65     # PQ identity key
  ├── transport/        # Ephemeral + static KEM
  │   ├── x25519_eph    # X25519 ephemeral (per envelope)
  │   ├── x25519_static # X25519 static receptor
  │   └── ml_kem_768    # ML-KEM-768 keypair
  └── audit/            # Audit signing keys
      ├── ed25519       # Classical audit key
      └── ml_dsa_65     # PQ audit key
```

## Domain Definitions

| Domain | Classical | PQ | Purpose | Lifecycle Owner |
|---|---|---|---|---|
| `custody/` | FROST secp256k1 | None (on-chain limitation) | Bitcoin transaction signing | VaultRoster (quorum) |
| `identity/` | Ed25519 | ML-DSA-65 | Vault authentication | VaultRoster (quorum) |
| `transport/` | X25519 | ML-KEM-768 | Wire encryption | Per-vault (automatic) |
| `audit/` | Ed25519 | ML-DSA-65 | Audit log signing | VaultRoster (quorum) |

Each domain has **independent lifecycle**. Key rotation in one domain does NOT affect any other domain.

---

## Domain Separation

| Domain | Purpose | Algorithms | Compromise Impact |
|---|---|---|---|
| `custody/` | Bitcoin transaction signing | FROST secp256k1 | Fund loss if CRQC available |
| `identity/` | Vault authentication | Ed25519 + ML-DSA-65 | Impersonation of vault |
| `transport/` | Wire encryption | X25519 + ML-KEM-768 | Decrypt past/future traffic |
| `audit/` | Audit log signing | Ed25519 + ML-DSA-65 | Audit log forgery |

### Domain Isolation Properties

1. **`custody/` is isolated by protocol:** FROTS shares exist only in the vault mesh's internal DKG/reshare protocol. They are never transmitted over the same channels as identity or transport material. The on-chain Taproot address exposes only the aggregate public key (secp256k1), not individual shares.

2. **`identity/` is isolated by purpose:** Identity keys authenticate vault-to-vault communication. They do not sign transactions, do not participate in DKG, and do not authorize fund movement. An identity key compromise allows impersonation but not fund theft.

3. **`transport/` is isolated by epoch:** Transport keys are ephemeral (X25519 ephemeral per envelope) or short-lived (X25519 static + ML-KEM-768 keypair per key epoch). They have no authority beyond the current epoch's wire encryption.

4. **`audit/` is isolated by append-only semantics:** Audit keys sign log entries. Compromise allows forging past entries (if old keys are compromised) but does not affect current operations.

---

## Lifecycle Independence Guarantees

1. Rotation of `identity/` keys does NOT require re-DKG or reshare in `custody/`
2. Compromise of a `transport/` static key does NOT compromise `custody/` shares
3. `audit/` key rotation does NOT invalidate past audit entries (old public keys retained for verification)
4. Each domain maintains its own `created_at`, `expires_at`, `revoked_at` timestamps

---

## Domain Lifecycles

### `custody/` — FROST secp256k1

| Event | Action | Trigger |
|---|---|---|
| **Genesis** | Initial DKG creates 2/3 threshold shares | VaultRoster formation |
| **Daily rotation** | Distributed reshare (3-round wire protocol) rotates all shares | Day-advance hook |
| **Threshold recovery** | Full DKG after node loss (admission of new vault) | VaultRoster update |
| **Compromise** | Emergency reshare with new epoch; rotate all shares (same VK) | Quorum governance |
| **Expiration** | Shares have no expiration; reshare is continuous | N/A |

**Invariant:** The aggregate verification key (VK) — and therefore the Taproot address `tb1p` — is **immutable** after genesis. Reshare produces new shares with the same VK.

### `identity/` — Ed25519 + ML-DSA-65

| Event | Action | Trigger |
|---|---|---|
| **Genesis** | Generate Ed25519 + ML-DSA-65 keypair from vault seed | Vault boot (first time) |
| **Rotation** | Generate new Ed25519 + ML-DSA-65 keypair; register new public keys in roster | Every N epochs (default 90 days) or on quorum decision |
| **Atomic bind** | Both keys rotate in the same transaction; no window with only one rotated | Always |
| **Revocation** | Mark old keys as `revoked_at` in roster; all vaults reject signatures from revoked keys | Quorum governance |
| **Compromise** | Immediate quorum revocation + replacement; re-authentication of all mesh peers | Compromise detection |

**Key management:**
- Old public keys retained for verification of past signatures until `expires_at`
- New key registration requires quorum mesh approval (no unilateral identity change)
- Vault identity is the binding anchor for mTLS certificates, transport keys, and audit keys

### `transport/` — X25519 + ML-KEM-768

| Event | Action | Trigger |
|---|---|---|
| **Genesis** | Generate X25519 static + ML-KEM-768 keypair from vault seed | Vault boot (first time) |
| **Per-message ephemeral** | Generate fresh X25519 ephemeral keypair for each HybridEnvelope seal | Every envelope |
| **Epoch rotation** | Generate new X25519 static + ML-KEM-768 keypair | Every key epoch (default 1 day) |
| **Old key retention** | Retain previous epoch's static keys for decrypting in-flight messages | Until `expires_at` (1 epoch after rotation) |
| **Compromise** | Rotate transport keys immediately; re-establish encrypted sessions with all peers | Compromise detection |

**Key management:**
- X25519 ephemeral keys exist only in memory and are zeroized after use
- ML-KEM-768 encapsulation produces a fresh ciphertext per message (non-deterministic)
- Old static keys are deleted after the grace period (1 epoch)

### `audit/` — Ed25519 + ML-DSA-65

| Event | Action | Trigger |
|---|---|---|
| **Genesis** | Generate Ed25519 + ML-DSA-65 keypair from vault seed | Vault boot (first time) |
| **Rotation** | Generate new keypair (annual or on compromise) | Time-based or quorum decision |
| **Revocation** | Mark old keys as `revoked_at`; public keys retained for verification | Quorum governance |
| **Compromise** | Revoke immediately; rotate new keys; past entries remain verifiable with old public keys | Compromise detection |

**Key management:**
- Old public keys are retained indefinitely for audit trail verification
- Audit record includes the key ID that signed it (not just the signature)
- Rotation does not invalidate past entries

---

## KeyStore Namespace Design

Each key stored in the vault's KeyStore has the following structure:

```
vault/<node_id>/<domain>/<key_id>
```

### Key Record Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `key_id` | String | Yes | Unique identifier within the domain (e.g., "frost_share", "ed25519", "ml_kem_768") |
| `key_kind` | Enum | Yes | `FrostTr`, `Ed25519`, `MlDsa65`, `X25519Static`, `X25519Eph`, `MlKem768` |
| `key_material` | Sealed blob | Yes | Encrypted private key material (AEAD, TPM-sealed, or TEE-sealed) |
| `namespace` | String | Yes | `custody/`, `identity/`, `transport/`, `audit/` |
| `created_at` | DayEpoch | Yes | Epoch of key creation |
| `expires_at` | DayEpoch | No | Epoch after which the key is considered expired and rejected |
| `revoked_at` | DayEpoch | No | Epoch of revocation (if applicable) |
| `parent_key_id` | String | No | Key ID of the key that authorized or created this key |
| `public_key` | Bytes | Yes | Public key material (shared with peers via roster) |
| `node_id` | NodeId | Yes | The vault node that owns this key |
| `key_epoch` | u64 | Yes | Monotonic epoch counter for this key version |

### Namespace Examples

```
# custody/ namespace — FROST share (per vault)
vault/node-1/custody/frost_share
  key_kind: FrostTr
  created_at: 42
  expires_at: none
  revoked_at: none
  parent_key_id: "dkg-session-7f3a"

# identity/ namespace — hybrid identity keypair
vault/node-1/identity/ed25519
  key_kind: Ed25519
  created_at: 42
  expires_at: 132   # 90 days after genesis
  revoked_at: none
  parent_key_id: "vault-seed-v1"

vault/node-1/identity/ml_dsa_65
  key_kind: MlDsa65
  created_at: 42
  expires_at: 132
  revoked_at: none
  parent_key_id: "vault-seed-v1"

# transport/ namespace — static KEM keys
vault/node-1/transport/x25519_static
  key_kind: X25519Static
  created_at: 42
  expires_at: 43    # 1 epoch
  revoked_at: none
  parent_key_id: "vault-seed-v1"

vault/node-1/transport/ml_kem_768
  key_kind: MlKem768
  created_at: 42
  expires_at: 43
  revoked_at: none
  parent_key_id: "vault-seed-v1"

# audit/ namespace
vault/node-1/audit/ed25519
  key_kind: Ed25519
  created_at: 42
  expires_at: 407   # 1 year
  revoked_at: none
  parent_key_id: "vault-seed-v1"
```

### KeyStore Operations

| Operation | Description | Authorization |
|---|---|---|
| `put(namespace, key_record)` | Store a sealed key | Local vault only (never remote) |
| `get(namespace, key_id)` | Retrieve and unseal a key | Local vault only |
| `list(namespace)` | List key IDs in a namespace | Local vault only |
| `revoke(namespace, key_id, epoch)` | Mark a key as revoked at given epoch | Quorum governance (for identity/audit) or local (for transport) |
| `delete(namespace, key_id)` | Remove expired/revoked key from store | Local vault only (after expiration grace period) |

### Namespaced Access Control

The KeyStore enforces namespace isolation at the API level:

- `get("custody/*")` — only accessible by the FROST signing flow and the reshare protocol
- `get("identity/*")` — accessible by the authentication and TLS subsystems
- `get("transport/*")` — accessible by the HybridEnvelope seal/open flow
- `get("audit/*")` — accessible only by the audit logging subsystem
- Cross-namespace access is denied by the KeyStore implementation

---

## Key Binding Rules

- Identity keys bind to custody shares: vault identified by identity public key hash in FROST roster
- Transport keys bind to identity keys: mesh TLS certs identify vaults by identity pubkey
- Audit keys bind to identity keys: audit record includes signer identity
- Binding is **not** cryptographic between domains (different key materials) but **logical** via the roster and peer identity records
- A change in identity keys requires re-issuance of mTLS certificates and re-establishment of transport sessions

---

## Atomic Rotation (within a Domain)

When `identity/` keys rotate:
- Ed25519 and ML-DSA-65 keys rotate together (atomic bind)
- No window where only one key is rotated
- Old keys retained for verification of past signatures until expired
- New key registration requires quorum mesh approval
- Both new public keys are published in the same roster update

When `transport/` keys rotate:
- X25519 static + ML-KEM-768 keypair rotate together
- X25519 ephemeral regenerated per envelope
- Old static keys retained for decrypting in-flight messages until expired
- Rotation is automatic (triggered by day-advance), does not require quorum

When `audit/` keys rotate:
- Ed25519 + ML-DSA-65 rotate together (atomic bind)
- Old public keys retained indefinitely for verification
- Rotation does not invalidate past entries

---

## Key Derivation

All domain keys derived from a vault seed via HKDF-SHA-384 with domain-specific info strings:

```
identity_ed25519_seed   = HKDF-Expand(vault_seed, "kerosene-vault-identity-ed25519-v1", 32)
identity_ml_dsa_seed    = HKDF-Expand(vault_seed, "kerosene-vault-identity-mldsa65-v1", 32)
transport_x25519_seed   = HKDF-Expand(vault_seed, "kerosene-vault-transport-x25519-v1", 32)
transport_mlkem_seed    = HKDF-Expand(vault_seed, "kerosene-vault-transport-mlkem768-v1", 64)
audit_ed25519_seed      = HKDF-Expand(vault_seed, "kerosene-vault-audit-ed25519-v1", 32)
audit_ml_dsa_seed       = HKDF-Expand(vault_seed, "kerosene-vault-audit-mldsa65-v1", 32)
```

The vault seed is protected by TPM/TEE and never leaves the secure enclave in cleartext.

---

## Key Storage

| Domain | Classical Private Key | PQ Private Key | Storage |
|---|---|---|---|
| `custody/` | FROST secp256k1 share | N/A | TEE-sealed disk store (AES-256-GCM with TPM-bound key or TEE seal) |
| `identity/` | Ed25519 | ML-DSA-65 seed | TPM/TEE protected, loaded at boot from sealed seed |
| `transport/` | X25519 static | ML-KEM-768 seed | Memory-only for ephemeral; TEE-sealed for static keys |
| `transport/` (ephemeral) | X25519 ephemeral | N/A | Memory-only; zeroized after use |
| `audit/` | Ed25519 | ML-DSA-65 seed | TPM/TEE protected |

### Storage Policies

- **Sealed shares** include AAD bind: `key_id + node_id + key_epoch` (anti-swap between vaults)
- **Backup**: Sealed key material is backed up with the same protection; backup media also protected by HybridEnvelope
- **Cleanup**: Expired keys are deleted after a configurable grace period
- **Zeroization**: All private key material is zeroized on drop (implemented via `zeroize::Zeroize` or platform-specific secure erase)
