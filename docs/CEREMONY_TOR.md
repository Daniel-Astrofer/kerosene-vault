# Genesis ceremony over private Tor mesh

Minimum-viable **real Tor** path for vault↔vault (and operator→vault) traffic.
Same FROST `VAULT_DKG_MODE=distributed_wire` binary path as lab/production — not `dealer_lab`.

## What deploy.sh still does

| Path | Compose | Transport | DKG | Auth |
| --- | --- | --- | --- | --- |
| `bash infra/deploy.sh` / `ensure-vault-mesh-lab.sh` | `vault-mesh-lab.compose.yaml` | Clearnet host ports `:7701–7703` | default `dealer_lab` | `static_token` |
| Staging opt-in | `vault-mesh-staging.compose.yaml` | Clearnet published ports | `distributed_wire` | mTLS |
| **This profile** | `vault-mesh-tor.compose.yaml` | Real Tor HS + SOCKS; **no vault host ports** | `distributed_wire` | lab: static_token; prod: mTLS |

Lab clearnet remains the local-full / kfe visualize path. **Production genesis ceremony must use Tor** (`VAULT_TRANSPORT=tor`).

## Operator: Tor lab smoke (real network variation)

From repo root (needs Docker + Internet for Tor circuits):

```bash
./backend/kerosene-vault/scripts/lab_dkg_wire_tor.sh
```

What it does:

1. Starts 3 Tor daemons (onion HS → vault:7701, SOCKS on `127.0.0.1:19051–19053`).
2. Waits for `.onion` hostnames (Tor bootstrap — expect tens of seconds).
3. Starts 3 vaults on a private Docker network with `VAULT_SEED_PEERS=…onion…` and `VAULT_SOCKS_PROXY=socks5h://tor-N:9050`.
4. Runs over-wire DKG rounds via `curl --socks5-hostname` with retries/jitter.

Expect slower rounds, occasional retries on circuit drops — that is intentional.

## Production ceremony checklist extras

`genesis_ceremony_checklist.sh` (production mode) requires:

- `VAULT_TRANSPORT=tor`
- `VAULT_SOCKS_PROXY` set (e.g. `socks5h://127.0.0.1:9050`)
- Onion `VAULT_SEED_PEERS`
- `VAULT_CLEARNET_PUBLISH` unset / not `1`
- Existing Gate: `distributed_wire`, mTLS, honest attestation tiers (domestic / SEV seating from `ef61341f` unchanged)

Binary hygiene also refuses production clearnet transport and clearnet publish.

## Config knobs

| Env | Meaning |
| --- | --- |
| `VAULT_TRANSPORT=tor\|clearnet` | Mesh transport; production defaults to `tor` |
| `VAULT_SOCKS_PROXY` | `socks5h://host:9050` (hostname via Tor — required for `.onion`) |
| `VAULT_HTTP_TIMEOUT_SECS` | Default 180 on Tor / 30 clearnet |
| `VAULT_HTTP_MAX_RETRIES` | Default 5 on Tor / 1 clearnet |
| `VAULT_HTTP_RETRY_BASE_MS` / `_JITTER_MS` | Backoff with jitter |
| `VAULT_CLEARNET_PUBLISH=1` | Forbidden in production ceremony |

## Remaining work (honest gaps)

Shipped MVP: SOCKS outbound + onion listeners + wire DKG + Tor timeouts/retries + compose/script + hygiene.

Not done yet:

1. **mTLS + onion SAN / SPIFFE verify** — Tor lab uses `static_token`. Production mTLS over `.onion` needs onion SANs on certs or custom SPIFFE hostname verify.
2. **Client-auth onion (authorized_clients)** — HS is v3 public onion; optional restricted discovery later.
3. **deploy.sh does not switch** to Tor mesh — intentional (local-full still clearnet lab).
4. **Host Tor instead of sidecar** — supported via env (`VAULT_SOCKS_PROXY=socks5h://127.0.0.1:9050`) but not automated.
5. **Anti-nonce / day-advance under Tor** — uses same SOCKS client settings; long-run soak not automated in CI.
6. **No HashiCorp / mpc-sidecar** — do not revive; cutover remains mesh-only.

## Domestic + SEV seating

Unchanged: `VAULT_NODE_TIER` / `VAULT_PEER_TIERS` / genesis seating from domestic-first + SEV priority. Tor is transport only.
