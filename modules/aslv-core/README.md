# ASLV M0 — `aslv-core` (shared foundation)

M0 has **no vulnerabilities of its own by design** (CONTRACT §6). It provides the
shared plumbing every other ASLV module talks to:

| Service | Image target | Port (container) | Role |
|---|---|---|---|
| **collector** | `collector` (Go → scratch) | `8090` (env `COLLECTOR_PORT`) | activity sink + event-verified `ASLV{CORS-…}` / `ASLV{CSRF-…}` minter |
| **stub-auth** | `stubs` + `STUB=auth` | `3000` | dev JWT signer for M3/M4 standalone JWT-validation testing |
| **stub-portal** | `stubs` + `STUB=portal` | `3000` | minimal static portal upstream for M1/M5 standalone |
| **stub-mail** | `stubs` + `STUB=mail` | `3000` HTTP + `1025` SMTP | in-memory mailbox (standalone replacement for MailHog) |

Postgres (full mode, internal only) is part of the organization narrative; see
the honest note at the bottom.

## Collector endpoints (:8090)

| Method + path | Purpose |
|---|---|
| `POST /ingest` | Activity row(s): a single JSON object, a JSON array, or an NDJSON body. Rows are normalized (`ts` defaulted to now UTC), appended to `/data/activity.jsonl` and to an in-memory ring (last 5000). |
| `GET /internal/activity` | NDJSON of stored rows, **latest first**, capped at 5000. This is what the TUI polls through the per-mode collector mgmt port (CONTRACT §2: full=`18090` … m5=`18095`). |
| `POST /exfil` | Records `{origin, referer, payload}` (+`sec_fetch_site`) to `/data/exfil.jsonl`. Missing body fields fall back to the request's `Origin` / `Referer` / `Sec-Fetch-Site` headers. |
| `GET /verify` | **Dual-check mint** (semantics copied from `dsltv/base/runtime.js` `collectorRouter /verify`): the latest exfil hit must (1) carry a cross-site attacker context — `origin`/`referer` containing `ATTACKER_HOST` (default `attacker.aslv.lab`) or `Sec-Fetch-Site: cross-site` — AND (2) a `payload` containing the innocent session-bound secret. On pass → mints `ASLV{CORS-<9 digits>}` where the digits derive from `sha256(secret+":CORS")` (deterministic per boot). A second branch checks the portal's CSRF state (`GET {PORTAL_INTERNAL_URL}/_internal/csrf-state` → `{"changed":true}`) and mints `ASLV{CSRF-…}` (digits from `sha256(secret+":CSRF")`). Response: `{"checked_at","cors":{verified,flag,reason},"csrf":{…},"verified":<any>,"flag":<latest minted>}`. |
| `GET /healthz` | Liveness. |

Minted flags are persisted in `/data/minted.json` so repeat calls return the
same flag, and are appended to the flag registry
(`/registry/flags.ndjson`, `REGISTRY_DIR` env, fallback
`/data/registry-fallback.ndjson`) with `unit:"m2"` — the CORS/CSRF categories
belong to the M2 surface even though M0 does the minting.

### Innocent secret source

`GET {PORTAL_INTERNAL_URL}/_internal/innocent-secret` → `{"api_key":"<32-hex>"}`
(cached 60 s; also accepts a `secret` field).

- **full mode / m2 standalone**: `PORTAL_INTERNAL_URL` → the real portal (M2,
  `modules/aslv-portal`, owned by agent 2-b). Coordination requirement: M2 must
  implement `/_internal/innocent-secret` and `/_internal/csrf-state`.
- **other standalone modes**: `PORTAL_INTERNAL_URL` → the M0 **stub-portal**,
  which serves a per-boot random secret so `/verify` never crashes.

## Stub services

### `STUB=auth` (stub-auth) — dev JWT signer
- `POST /issue` `{sub, role, tenant, alg?}` → dev JWT. Default `alg=HS256`
  signed with the well-known dev secret `aslv-stub-dev-key` (any `sub`/`role`
  claims accepted — that is the point). `alg:"RS256"` signs with the stub's
  boot-generated RSA key.
- `GET /jwks.json` → the stub's boot RSA public JWK (`kid:"stub-1"`).
  *Deviation from the original "empty JWKS" sketch, documented:* exposing the
  public RSA key is what makes M4's RS256-via-JWKS and HS256-confusion
  validation paths genuinely exercisable in standalone mode (M4 derives its
  confused HMAC key from the JWKS `n`+`e` strings).
- `GET /whoami` (`Authorization: Bearer …` or `?token=`) → verification result
  + decoded claims.
- `GET /healthz`.

### `STUB=portal` (stub-portal) — minimal portal upstream
- `GET /` and `GET /login` — login form; `POST /login` accepts **any**
  credentials → session cookie → `GET /me` stub account page.
- `GET /_internal/innocent-secret` → `{"username","api_key"}` (per-boot random).
- `GET /_internal/csrf-state` → `{"changed":false}`.
- `GET /_internal/user/{username}` → `{"username","email","recovery_email":null}`
  (M5's cross-module forgot fallback in standalone modes).

### `STUB=mail` (stub-mail) — in-memory mailbox
- `POST /internal/mail` `{to, subject, body}` → `{id}`.
- Mini SMTP server on `:1025` — parses `HELO/EHLO`, `MAIL FROM`, `RCPT TO`,
  `DATA` (terminator `\r\n.\r\n`, `Subject:` header extracted), `RSET`, `NOOP`,
  `QUIT`.
- `GET /` — dark-theme mail UI (list).
- `GET /mail/{id}` — JSON with extracted links (`https?://…` regex) — mail is a
  **token carrier, never a flag carrier**.
- Storage is in-memory: restarting the stub clears the mailbox (acceptable for
  standalone stubbing; MailHog is the full-mode mailbox).

## Environment

| Var | Default | Notes |
|---|---|---|
| `COLLECTOR_PORT` | `8090` | collector listen port |
| `DATA_DIR` | `/data` | activity.jsonl, exfil.jsonl, minted.json |
| `REGISTRY_DIR` | `/registry` | shared flag registry volume (fallback: `DATA_DIR/registry-fallback.ndjson`) |
| `ATTACKER_HOST` | `attacker.aslv.lab` | cross-site context match for the CORS dual-check |
| `PORTAL_INTERNAL_URL` | `http://portal:3000` | innocent-secret + csrf-state source (M2 in full mode, stub-portal otherwise) |
| `STUB` | `portal` | stub personality: `auth` \| `portal` \| `mail` |
| `PORT` / `SMTP_PORT` | `3000` / `1025` | stub listen ports |

## Honest Postgres note (v1)

The compose file keeps a **Postgres** service (full mode, internal only, port
`5432`) for the organization narrative and future use, but **v1 of the
collector archives activity to NDJSON files only**. Reason: Go's standard
library ships no Postgres driver, and adding `lib/pq` (plus credentials
management) is deferred to a v2 — the NDJSON + in-memory ring already satisfies
FR-8 (`GET /internal/activity`) and FR-10 (exports). Nothing in the lab
*requires* Postgres; treat it as scaffolding.

## Standalone vs full mode

- Every ASLV compose profile deploys one M0 **collector** instance (its mgmt
  port is published per CONTRACT §2) and the stubs it needs: m4 → `stub-auth`;
  m5 → `stub-mail` + `stub-portal`; m1/m3 → as their agents documented.
- In **full mode**, the collector is reached at `collector.aslv.lab:18024`
  (player-facing `/verify`), MailHog replaces stub-mail, M2 replaces
  stub-portal, and M5 replaces stub-auth.
