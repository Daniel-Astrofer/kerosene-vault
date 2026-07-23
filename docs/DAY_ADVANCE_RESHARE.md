# Day advance + reshare (kfe → vault)

Vaults **execute** rotation when asked. There is **no** vault-side day cron — kfe (or ops) calls these endpoints. With `VAULT_RESHARE_POLICY=daily`, a successful advance refreshes **Intent FROST** and **Taproot FROST** (`frost-secp256k1-tr`) shares while keeping the Taproot group verifying key identical (`tb1p` / deposit unchanged).

Auth: same as other protected routes (`X-Vault-Token` lab, or mTLS client cert).

Persist: `day_epoch` is stored at `$VAULT_DATA_DIR/day_epoch` and loaded on boot. Peer votes use the existing quorum APIs (`governance_t`).

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

Record a peer (or coordinator) vote toward a target UTC day. Required until `governance_t` votes match the live calendar day.

**Request**

```json
{"voter":"vault-2","day_epoch":"2026-07-22"}
```

**Response 200**

```json
{"ok":true}
```

**Response 400** — invalid JSON / day format.

## `POST /v1/day/advance`

Local voter auto-records a vote for today’s UTC day, then advances if quorum is met. Idempotent when already on the live day (still ensures disk persist). On a real advance with `VAULT_RESHARE_POLICY=daily`, runs Intent + Taproot share refresh.

**Request:** empty body (or omit).

**Response 200**

```json
{"day_epoch":"2026-07-22","advanced":true}
```

**Response 409** — quorum not met, or clock behind ledger day:

```json
{"error":"quorum not met: have 1, need 2"}
```

Typical kfe sequence for n=3, `governance_t=2`:

1. `GET /v1/day/current` on each vault (or one) — detect stale.
2. `POST /v1/day/vote` on vault-1 with `voter=vault-2` (and/or vault-3) for today’s `day_epoch`.
3. `POST /v1/day/advance` on vault-1 (local vote + quorum) — repeat per vault as needed so each node’s persisted day catches up.

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
