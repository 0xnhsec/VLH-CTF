# ASLV M2 — `aslv-portal` (CORS + CSRF, event-verified)

Public web-app module of the ASLV product line. **Bug classes:** CORS
(reflected origin + credentials) and CSRF (token-less state change). **Flags:**
`ASLV{CORS-...}` and `ASLV{CSRF-...}` — **archetype: event-verified** (arch
§7.0): neither flag exists at boot; the embedded collector mints each one only
when its dual check observes the exploit.

## Architecture

```
 standalone (host :18022)                     full mode (gateway :18024)
 ┌───────────────────────┐                    ┌──────────────────────────┐
 │ nginx sidecar         │                    │ M1 gateway (other module)│
 │  victim/www/portal ───┼─► portal-std:3000  │  aslv.lab / www ─────────┼─► portal:3000
 │  attacker ────────────┼─► portal-std:3000  │  collector.aslv.lab ─────┼─► portal:3000
 │  collector ───────────┼─► portal-std:3000  │  attacker.aslv.lab ──────┼─► portal:3000
 │  mail ────────────────┼─► stub-mail-2:3000 │  mail.aslv.lab ─────────► mailhog:8025
 │  default ─────────────┼─► portal-std:3000  └──────────────────────────┘
 └───────────────────────┘
        one Express app (:3000) dispatches by Host header
```

The app is deliberately minimal Express — **no CSRF middleware, no `cors`
package** (arch §5.1: "Express (minimal, no built-in CSRF)"). SQLite at
`/data/portal.db` (named volume, standalone persistence). Sidecar template
needs env `LAB_PORT`, `APP_HOST`, `MAIL_HOST` (envsubst).

## Seeded accounts (per boot)

| Account | Password | Role | Notes |
|---|---|---|---|
| `0xnhsec` | `vlh-tester-01` | tester | known — documented in player guide |
| `Noshiro` | `vlh-tester-02` | tester | known |
| `usr_<4hex>` | random 16 hex | innocent | never player-visible; holds the 32-hex `api_key` the verifier matches |
| `admin` | random 16 hex | admin | never player-visible |

The innocent's `api_key` **is** visible on her own `/me` page and in
`/api/secret` responses when she is logged in — that is the exfil target. Her
password is never exposed (grading-only dump inside `/data/seed.json`).

## Endpoints

**victim vhost (`victim.aslv.lab`) + portal vhost (`portal.aslv.lab`,
`www.aslv.lab`, `aslv.lab` in full mode):**

| Method + path | Behavior |
|---|---|
| `GET /login`, `POST /login`, `POST /logout` | session login (cookie `sid`, HttpOnly, SameSite=Lax) |
| `GET /me` | own profile incl. `api_key` (the exfil target) |
| `GET /account` | recovery-email change form (**no CSRF token**) |
| `POST /account/recovery-email` | `{email}` — session auth only, no token, no origin check (**CSRF surface**) |
| `GET /api/secret` | session auth; returns own `{username, api_key, ...}`; **reflects `Origin` in `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials: true`** (**CORS surface**) |
| `GET /api/quotes` | public, CORS-reflecting warm-up (standalone mini-API) |
| `OPTIONS /api/secret`, `/api/quotes` | preflight with the same reflection |
| `GET /healthz` | liveness |

**collector vhost (`collector.aslv.lab`):**

| Method + path | Behavior |
|---|---|
| `GET /verify` (`?category=CORS\|CSRF`) | dual check → mints the event-verified flag |
| `POST /collect` / `POST /exfil` | record an exfil hit with origin context |
| `POST /victim` | victim bot: `{url, origin?, referer?, method?, body?, cookies?}` — logs in the innocent, fetches the URL with her cookie, pipes the response into the exfil verifier when an attacker origin is supplied |
| `GET /internal/activity` | NDJSON latest 5000 activity rows (also served on every vhost — main-listener convention) |
| `POST /ingest`, `POST /internal/ingest` | accept forwarded activity rows |

**attacker vhost (`attacker.aslv.lab`):** `GET /` (store UI), `PUT/POST
/pages/:name`, `GET /pages/:name`, `GET /leaks` (captured hits).

**mail vhost (`mail.aslv.lab`):** mini mailbox fallback (`POST
/internal/mail`, `GET /`, `GET /mail/:id`) — in standalone the sidecar routes
mail to `stub-mail-2`; this vhost keeps the module self-sufficient when the
stub is absent.

## Intended exploit path

**CORS (`ASLV{CORS-...}`):**
1. Store an exploit page on the attacker vhost (`PUT /pages/x.html` on
   `attacker.aslv.lab`).
2. Make the innocent browser session fetch
   `http://victim.aslv.lab:<port>/api/secret` cross-site from the attacker
   origin. Solo play: `POST http://collector.aslv.lab:<port>/victim` with
   `{"url":"http://victim.aslv.lab:<port>/api/secret","origin":"http://attacker.aslv.lab:<port>"}`.
   The bot pipes the credentialed response (innocent `api_key`) into the
   exfil verifier with the cross-site context.
3. `GET /verify?category=CORS` → dual check (attacker origin + payload bound
   to the innocent secret) passes → flag minted.

**CSRF (`ASLV{CSRF-...}`):**
1. The innocent browser session POSTs `/account/recovery-email` cross-site
   (no token exists to forge). Solo play: `POST /victim` with
   `{"url":"http://victim.aslv.lab:<port>/account/recovery-email","method":"POST","body":{"email":"attacker@evil.example"},"origin":"http://attacker.aslv.lab:<port>"}`.
2. `GET /verify?category=CSRF` → the verifier inspects only the innocent row;
   her `recovery_email` differs from the seed value → flag minted.

Anti-shortcut: a tester changing *their own* recovery email never satisfies
the CSRF checker; exfiltrating a *tester* api_key never satisfies the CORS
dual check (the payload must contain the innocent session-bound secret).

## Standalone vs full differences

- Standalone: own nginx sidecar binds 18022 (`sidecar/nginx.conf.template`,
  env `LAB_PORT`/`APP_HOST`/`MAIL_HOST`), mail routes to `stub-mail-2`,
  `STANDALONE=1`, own mini-API (`/api/quotes`, `/api/secret`), self-contained
  verification — no M0/M3/M4 dependency.
- Full: the M1 gateway routes `aslv.lab`/`www` (portal), `collector.aslv.lab`
  and `attacker.aslv.lab` to this app's :3000; `ACTIVITY_SINK` points at the
  M0 collector's `/ingest`; the juiciest CORS targets beyond this module are
  the M3/M4 API responses (their agents implement reflected ACAO — the M2
  exploit-page workflow is the delivery vehicle for those chains).
- Event flags derive deterministically from the innocent `api_key` (hash), so
  they are stable for a given boot-vintage (same pattern as the DSLTV base).

## Files

- `src/server.js` — vhost dispatch + all routes (victim/portal/collector/attacker/mail)
- `src/db.js` — SQLite schema + seeding + session/user helpers
- `src/flags.js` — event-verified flag minting + registry append
- `src/activity.js` — activity middleware, `/internal/activity`, `/ingest`, ACTIVITY_SINK forwarding
- `sidecar/nginx.conf.template` — standalone vhost sidecar
- `Dockerfile` (node:20-slim), `entrypoint.sh`, `.dockerignore`, `package.json`
- Solver: `qa/solvers/aslv/m2/{solver,shortcut}.mjs`
