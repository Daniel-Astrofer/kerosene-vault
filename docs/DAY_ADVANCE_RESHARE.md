# Day advance + reshare (kfe → vault)

Vaults **execute** rotation when asked. There is **no** vault-side day cron — kfe (or ops) calls these endpoints. With `VAULT_RESHARE_POLICY=daily`, a successful advance refreshes **Intent FROST** and **Taproot FROST** (`frost-secp256k1-tr`) shares while keeping the Taproot group verifying key identical (`tb1p` / deposit unchanged).

Auth: same as other protected routes (`X-Vault-Token` lab, or mTLS client cert).

Persist: `day_epoch` is stored at `$VAULT_DATA_DIR/day_epoch` and loaded on boot.

## `GET /v1/day/current`

**Response 200**

```json
{"day_epoch":"2026-07-22"}
```

**Response 409** — calendar ahead of ledger day (stale; signing also refuses until advance):

```json
{"error":"day_epoch stale: have 2026-07-21, need 2026-07-22"}
```

## `POST /v1/day/vote`

Record a vote toward a target UTC day. Voter identity is resolved from auth hooks (priority):

1. `X-Vault-Mtls-Peer-Node` (optional mTLS/SPIFFE → node-id hook when present)
2. `X-Vault-Node-Id` when it is a **known** mesh node (`VAULT_NODE_ID` or `VAULT_SEED_PEERS`)
3. Otherwise this vault’s `VAULT_NODE_ID` (kfe self-vote path)

Client-supplied `voter` is optional and **must match** that identity (spoofed / unknown peer ids are rejected).

Outbound peer fan-out on advance uses mTLS (`tls_peer_verify` / `onion_or_spiffe`) or lab token over the existing peer HTTP channel; peer identity for collected votes is the configured seed peer id on that authenticated channel.

**Request**

```json
{"day_epoch":"2026-07-22"}
```

Optional: `"voter":"<authenticated-node-id>"` (mismatch → 400).

**Response 200**

```json
{"ok":true,"voter":"vault-1","self_voter":"vault-1","self_day_epoch":"2026-07-22"}
```

**Response 400** — invalid JSON / day format / voter identity mismatch / unknown peer id.

## `POST /v1/day/advance`

Records this vault’s vote for today’s UTC day, then **fans out** authenticated votes to `VAULT_SEED_PEERS` and collects peer self-votes until quorum `t = ⌈2n/3⌉` (solo / no peers: `t = 1`). Fail-closed when quorum unmet (peers unreachable). Idempotent when already on the live day (still ensures disk persist). On a real advance with `VAULT_RESHARE_POLICY=daily`, runs Intent + Taproot share refresh.

**Request:** empty body (or omit).

**Response 200**

```json
{"day_epoch":"2026-07-22","advanced":true}
```

**Response 409** — clock behind ledger day, or quorum not met:

```json
{"error":"quorum not met: have 1, need 2"}
```

Typical mesh sequence (n=3, t=2):

1. `GET /v1/day/current` — detect stale.
2. `POST /v1/day/vote` (optional; advance also self-votes) and/or `POST /v1/day/advance` — advance fans out to peers.
3. Repeat on other vaults so each node’s persisted day catches up.

Do **not** POST `voter=vault-2` to vault-1 under a shared lab token without `X-Vault-Node-Id: vault-2` from a known peer — spoof of unknown ids is closed.

## Intent consume mesh prepare

`POST /v1/intent/consume/prepare` — durable peer prepare for Intent ids (same pattern as `/v1/anti-nonce/prepare`). Gate/sign authorize requires local fsync + `⌈2n/3⌉` peer ACKs (fail-closed if peers unreachable when configured). Cross-node double-spend → `already_seen` / Intent replay.

## `POST /v1/reshare/trigger`

Explicit share refresh (always runs crypto regardless of policy). Used when `VAULT_RESHARE_POLICY=manual`, or ops wants an out-of-band refresh.

**Request**

```json
{"reason":"ops-manual"}
```

`reason` optional (defaults to `"manual"`).

**Response 200**

```json
{"reshared":true,"policy":"manual","reason":"ops-manual"}
```

**Response 409** — FROST material missing or refresh failed (e.g. verifying-key drift — should never happen; asserted in code).

## Lab compose

`infra/docker/compose/vault-mesh-lab.compose.yaml` accepts optional:

```yaml
VAULT_RESHARE_POLICY: daily   # or omit / manual (default)
```

Do **not** add a vault container cron for day roll — the server asks.
