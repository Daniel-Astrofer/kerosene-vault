# Kerosene Node integration

`kerosene-vault` can obtain its initial peer roster from the verified
Vault-plane manifest served by a local `kerosene-node`. This replaces a
hand-maintained `VAULT_SEED_PEERS` list for production-like deployments.

## Configuration

| Variable | Meaning |
| --- | --- |
| `VAULT_KEROSENE_NODE_URL` | HTTPS URL of the local Vault-plane Node |
| `VAULT_KEROSENE_NETWORK_ID` | Expected network ID |
| `VAULT_KEROSENE_NODE_MEMBER_ID` | Local member ID, excluded from seed peers |
| `VAULT_KEROSENE_NODE_CLIENT_IDENTITY_PEM` | Client certificate and key for Node mTLS |
| `VAULT_KEROSENE_NODE_CA_PATH` | CA used to verify the Node |
| `VAULT_KEROSENE_SERVICE_PORT` | Vault service port derived on each signed onion host; default `7801` |
| `VAULT_KEROSENE_NODE_ALLOW_EMPTY` | Permit an empty/absent manifest during controlled bootstrap |

When `VAULT_KEROSENE_NODE_URL` is present, `VAULT_SEED_PEERS` is ignored. The
Vault fails closed if the Node response has a different network, is not on the
`vault` plane, or contains anything other than HTTPS v3 onion endpoints.
Financial peer URLs retain the signed onion hostname and use only the locally
fixed Vault service port.

The Node verifies the manifest signatures and membership transitions. The Vault
does not accept an unsigned service directory and the Node never receives a
FROST share, nonce, Vault TLS private key or signing authority.

## Lifecycle

Peer discovery is a startup snapshot in the current release. Restart the Vault
after an accepted membership transition so that its mesh roster is rebuilt.
This limitation is intentional and must not be mistaken for live reconciliation.

An empty manifest may be allowed only for the first controlled staging
bootstrap. In that state the Vault can expose local health and administration,
but it has no peer quorum and must not be treated as financially ready. Adding a
Node or publishing a manifest never activates a signer automatically.
