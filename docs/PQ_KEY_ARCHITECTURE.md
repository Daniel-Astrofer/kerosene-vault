# PQ Key Architecture — Kerosene Vault Mesh

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

## Domain Separation

| Domain | Purpose | Algorithms | Compromise Impact |
|--------|---------|------------|-------------------|
| `custody/` | Bitcoin transaction signing | FROST secp256k1 | Fund loss if CRQC available |
| `identity/` | Vault authentication | Ed25519 + ML-DSA-65 | Impersonation of vault |
| `transport/` | Wire encryption | X25519 + ML-KEM-768 | Decrypt past/future traffic |
| `audit/` | Audit log signing | Ed25519 + ML-DSA-65 | Audit log forgery |

Each domain has independent lifecycle. Key rotation in one domain does NOT affect any other domain.

## Lifecycle Independence Guarantees

1. Rotation of `identity/` keys does NOT require re-DKG or reshare in `custody/`
2. Compromise of a `transport/` static key does NOT compromise `custody/` shares
3. `audit/` key rotation does NOT invalidate past audit entries (old public keys retained for verification)
4. Each domain maintains its own `created_at`, `expires_at`, `revoked_at` timestamps

## Key Binding Rules

- Identity keys bind to custody shares: vault identified by identity public key hash in FROST roster
- Transport keys bind to identity keys: mesh TLS certs identify vaults by identity pubkey
- Audit keys bind to identity keys: audit record includes signer identity

## Atomic Rotation (within a Domain)

When `identity/` keys rotate:
- Ed25519 and ML-DSA-65 keys rotate together (atomic bind)
- No window where only one key is rotated
- Old keys retained for verification of past signatures until expired
- New key registration requires quorum mesh approval

When `transport/` keys rotate:
- X25519 static + ML-KEM-768 keypair rotate together
- X25519 ephemeral regenerated per envelope
- Old static keys retained for decrypting in-flight messages until expired

## Key Derivation

All domain keys derived from a vault seed via HKDF-SHA-384 with domain-specific info strings:

```
identity_ed25519_seed   = HKDF-Expand(vault_seed, "kerosene-vault-identity-ed25519-v1", 32)
identity_ml_dsa_seed     = HKDF-Expand(vault_seed, "kerosene-vault-identity-mldsa65-v1", 32)
transport_x25519_seed   = HKDF-Expand(vault_seed, "kerosene-vault-transport-x25519-v1", 32)
transport_mlkem_seed    = HKDF-Expand(vault_seed, "kerosene-vault-transport-mlkem768-v1", 64)
audit_ed25519_seed      = HKDF-Expand(vault_seed, "kerosene-vault-audit-ed25519-v1", 32)
audit_ml_dsa_seed       = HKDF-Expand(vault_seed, "kerosene-vault-audit-mldsa65-v1", 32)
```

The vault seed is protected by TPM/TEE and never leaves the secure enclave in cleartext.

## Key Storage

- `custody/` shares: TEE-sealed disk store (AES-256-GCM with TPM-bound key)
- `identity/` private keys: TPM/TEE protected, loaded at boot
- `transport/` private keys: memory-only for ephemeral; TEE-sealed for static
- `audit/` private keys: TPM/TEE protected
