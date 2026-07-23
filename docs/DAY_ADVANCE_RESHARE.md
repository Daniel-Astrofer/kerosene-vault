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

Record **this vault’s** vote toward a target UTC day. The voter is derived from the authenticated vault identity (`VAULT_NODE_ID`); client-supplied `voter` is optional and **must match** that identity (spoofed peer ids are rejected under shared auth).

**Request**

```json
{"day_epoch":"2026-07-22"}
```

Optional: `"voter":"<this-vault-node-id>"` (mismatch → 400).

**Response 200**

```json
{"ok":true,"voter":"vault-1"}
```

**Response 400** — invalid JSON / day format / voter identity mismatch.

## `POST /v1/day/advance`

Local voter auto-records a vote for today’s UTC day, then advances (local self-vote quorum). Idempotent when already on the live day (still ensures disk persist). On a real advance with `VAULT_RESHARE_POLICY=daily`, runs Intent + Taproot share refresh.

**Request:** empty body (or omit).

**Response 200**

```json
{"day_epoch":"2026-07-22","advanced":true}
```

**Response 409** — clock behind ledger day:

```json
{"error":"day_epoch stale: have 2026-07-22, need 2026-07-21"}
```

Typical kfe sequence for n=3:

1. `GET /v1/day/current` on each vault — detect stale.
2. `POST /v1/day/vote` **on that vault** (identity = its `VAULT_NODE_ID`) for today’s `day_epoch`.
3. `POST /v1/day/advance` **on that vault** — repeat per vault so each node’s persisted day catches up.

Do **not** POST `voter=vault-2` to vault-1 under a shared lab token — that spoof path is closed.

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
