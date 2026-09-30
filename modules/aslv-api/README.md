# ASLV M4 — `aslv-api` (API composite: BOLA / BFLA / BOPLA + mass assignment + shadow version)

Go REST API on the path-based scheme `aslv.lab/user/v1/{user}/…` (arch §7.2).
SQLite via `modernc.org/sqlite` (pure Go, CGO disabled). Port **8080** in the
container (`API_PORT`), published as **18025** in standalone mode.

Stack layout (3 Go files, single `main` package):

```
cmd/server/main.go      config, DB bootstrap + seed, flags/registry, sessions, activity, mux
cmd/server/handlers.go  all HTTP handlers (the bug surfaces + stage-gated flags)
cmd/server/jwt.go       deliberately loose JWT validation (the M5→M4 trust edge)
```

## Endpoint map (binding for solvers/chains)

| Method + path | Auth | Behavior |
|---|---|---|
| `GET /healthz` | — | liveness |
| `GET /` | — | service banner |
| `POST /user/v1/login` | — | `{username,password}` → `sid` session cookie (`SameSite=None`, feeds the M2↔M4 CORS edge). Testers: `0xnhsec`/`vlh-tester-01`, `Noshiro`/`vlh-tester-02`. |
| `POST /user/v1/logout` | session | destroys session |
| `GET /user/v1/list` | any | directory: `[{username, uuid, role, tenant}]` — the mild enumeration surface that reveals the innocent uuid in standalone mode |
| `GET /user/v1/{user}/profile` | any | **excessive data exposure**: `{user}` = username or uuid. Returns `uuid`+`email`+`tenant` for ANY user (the M4→M3 pivot leak). Full data (`api_key`, `original_role`) only when `{user}` == owner. When owner's `role==admin` AND `original_role!=admin` (i.e. escalated via PATCH) → `flag1 = ASLV{API-…}` (**stage 1**). |
| `GET /user/v1/{user}/orders` | any | order summaries for the user |
| `GET /user/v1/{user}/orders/{id}` | any | **BOLA**: order resolved by `{id}` only — NO ownership check between `{user}` and `{id}` (or the caller). Innocent's order `1001` carries `secret_note` = pivot material (innocent email + tenant + cross-tenant document reference). |
| `POST /admin/v1/restart` | any authed | **BFLA**: no role check on the privileged function → `{restarted:true, hint}` |
| `PATCH /user/v1/{user}` | session, self only | **mass assignment**: body may contain `{role, email, full_name, bio, phone}` — `role` is bindable → self-escalation. |
| `GET /admin/v1/panel` | any authed with role==admin | **stage 2**: verifies the server-side role (session `users.role` or the blindly-trusted JWT `role` claim) → `flag2 = ASLV{API-…}` (distinct digits from flag1). |
| `GET /v1/user/{user}/profile?export=full` | any | **shadow version** (forgotten old route): same profile + `legacy_route:true`; with `export=full` it also returns `api_key` when `{user}` is the innocent (or the caller's own) — the field the new route restricted to self. |
| `GET /internal/activity` | — | NDJSON activity rows, latest first (cap 5000) |

CORS edge (M2↔M4, arch §5.2): every response under `/user/v1/*` and `/v1/user/*`
REFLECTS any request `Origin` and adds `Access-Control-Allow-Credentials: true`
(+ preflight handling). Combined with the `SameSite=None` session cookie this
makes the shadow route a genuine cross-origin exfil target for the collector's
CORS dual-check.

### JWT validation trust edge (M5→M4, arch §5.2) — `Authorization: Bearer <jwt>`

`cmd/server/jwt.go` accepts tokens from the JWKS at `JWKS_URL`
(default `http://identity:3000/jwks.json`; standalone compose sets it to the
stub-auth service, e.g. `http://stub-auth:3000/jwks.json` — must match the
compose service name). Validation is deliberately loose:

- `alg: RS256` → signature verified against the JWKS RSA key (`kid` honored,
  else first key). **`alg: HS256` → signature verified with the HMAC key
  `n + "." + e`** — the literal base64url strings from the JWKS JSON
  (algorithm confusion: anyone who can READ the public JWKS can FORGE an
  admin token).
- `sub` / `role` claims are trusted **without** aud/scope/owner checks.
- No other algorithms (no `none` here — that surface belongs to M5).

 JWKS is cached for 5 minutes. If the JWKS is unreachable, Bearer auth fails
 closed (401) — session auth still works.

## Flags (stage-gated, two distinct values, regenerated per boot)

- `flag1 ASLV{API-<digits1>}` — appears in your OWN profile only after
  self-escalation via `PATCH /user/v1/{self} {"role":"admin"}` (the seed stores
  `original_role`; the seeded `admin` account can never satisfy the gate).
- `flag2 ASLV{API-<digits2>}` — `GET /admin/v1/panel` with a server-side admin
  role (escalated session, blindly-trusted JWT claim, or a real admin).

Registry: both flags append `note:"held"` lines at boot; first earn appends
`note:"minted"` (`unit:"m4"`, `archetype:"stage-gated"`, extra `stage` field).

## Seeding

Testers (known passwords), innocent `usr_<hex>` (random password + 32-hex
`api_key` + uuid + tenant), `admin` (random password, `original_role=admin`).
Orders `1001..1005` (innocent: 1001/1002, 1001 carries the pivot note).
Container-internal grading dump at `/data/seed.json` (never player-accessible).

**Org-wide seed override (full mode)**: envs `INNOCENT_USERNAME`,
`INNOCENT_PASSWORD`, `INNOCENT_API_KEY`, `INNOCENT_UUID` — when the full-mode
compose passes the SAME values to M2/M3/M4/M5, the innocent identity is
consistent across the organization (chain A/B depend on this; see worklog).
`tenant = "t" + first 6 hex of sha256("aslv-tenant:"+username)` — deterministic.

## Standalone mode (profile `m4`, port 18025)

Services: `m4-app` (this image), `m4-sidecar` (nginx:alpine, binds 18025:80,
template below), `stub-auth` (aslv-core stubs, `STUB=auth`), one M0 collector
(mgmt port 18094). Sidecar vhosts:

| Host | Upstream |
|---|---|
| default (`localhost:18025`) | `APP_HOST:8080` (the API) |
| `api.aslv.lab`, `aslv.lab`, `www.aslv.lab` | `APP_HOST:8080` |
| `auth.aslv.lab` | `AUTH_HOST:3000` (stub-auth) |

Sidecar template env: `APP_HOST`, `AUTH_HOST`.
Set `JWKS_URL=http://stub-auth:3000/jwks.json` (or whatever the stub-auth
service is named) on the app service — the stub's `/jwks.json` exposes a boot
RSA key so both the RS256 and HS256-confusion paths are exercisable standalone.

## Full mode (gateway :18024)

M4 is reached at `aslv.lab` + `/user/v1/…` (CONTRACT §4). **Gateway routing
requirement (for the compose/gateway owner):** the M4-owned path prefixes are
`/user/v1/`, `/admin/v1/`, `/v1/user/` — all three must route to the m4
service (adding an `api.aslv.lab` vhost → m4 is a compatible alternative; the
chain solvers try `aslv.lab` first, then `api.aslv.lab`). M2 (portal) must not
use those prefixes. `JWKS_URL=http://identity:3000/jwks.json` (M5 service).

## Intended path (standalone)

1. `POST /user/v1/login` as `0xnhsec` → session cookie.
2. `GET /user/v1/list` → find the innocent (`role:"innocent"`) → uuid.
3. `GET /user/v1/{innocent-uuid}/profile` → excessive exposure leak (email,
   tenant, uuid) — the pivot material.
4. (BOLA demo) `GET /user/v1/0xnhsec/orders/1001` → innocent's `secret_note`.
5. (BOPLA/shadow demo) `GET /v1/user/{innocent-uuid}/profile?export=full` →
   innocent `api_key`.
6. (BFLA demo) `POST /admin/v1/restart` → works without any admin role.
7. `PATCH /user/v1/0xnhsec` `{"role":"admin"}` → mass assignment escalation.
8. `GET /user/v1/0xnhsec/profile` → `flag1` (stage 1).
9. `GET /admin/v1/panel` → `flag2` (stage 2).

Shortcut guard (QA): calling `/admin/v1/panel` without escalation returns 403
with NO flag — see `qa/solvers/aslv/m4/shortcut.mjs`.

## Environment

| Var | Default | Notes |
|---|---|---|
| `API_PORT` | `8080` | listen port |
| `DATA_DIR` | `/data` | `api.db`, `seed.json` |
| `REGISTRY_DIR` | `/registry` | shared flag registry (fallback `DATA_DIR/registry-fallback.ndjson`) |
| `JWKS_URL` | `http://identity:3000/jwks.json` | RS256 keys / HS256-confusion material source |
| `ACTIVITY_SINK` | *(empty)* | collector `/ingest` URL — rows are POSTed asynchronously |
| `LAB_DOMAIN` | `aslv.lab` | seeded email domain |
| `INNOCENT_USERNAME/PASSWORD/API_KEY/UUID` | *(random)* | org-wide seed override (full mode) |
