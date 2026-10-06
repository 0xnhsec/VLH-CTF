# VLH-CTF QA — solver suite (FR-14)

Intended-path solvers must **pass** against a running lab; shortcut suites must
prove the naive paths stay **blocked** (exit 0 only when nothing leaks).
Run pre-release and after any flag-placement change (architecture-decisions
§7.4 QA rule). All scripts are Node 20+ built-ins only — no dependencies.

## Policy

| Suite | File | Exit 0 means | Exit 1 means |
|---|---|---|---|
| Intended path | `solver.mjs` | the documented exploit chain earned the flag(s) — regex-asserted | the lab (or the solver) is broken |
| Shortcut | `shortcut.mjs` | every naive/unauthenticated/direct attempt was **blocked** — no flag | **SHORTCUT LEAKED** — a flag was reachable without the technique (critical placement bug) |

Shortcut semantics per archetype:

- **Event-verified** (M2 CORS/CSRF): the dual check must reject exfil hits that
  lack the innocent's session-bound secret, and state checks must inspect only
  the innocent row. A flag reported as `already minted` (a previous intended
  run against the same boot) is a WARN, not a leak — restart the lab to
  re-verify placement from a clean boot.
- **Identity-gated** (M5, JWT labs): unauthenticated calls, mere logins,
  legitimately issued tokens and self-referencing state must never satisfy the
  claim/identity/provenance gates.
- **Resource-resident** (M3, M4): wrong-tenant Hosts, unauthenticated reads,
  properly gated admin surfaces and non-admin impersonation targets must 401/403/404.
- **Location-locked** (M1): plain requests to `/internal/flag` with any Host,
  naive pipelining and duplicate-Host tricks must never surface the flag —
  only a genuine front/back-end framing desync (or the edge-front's
  internal-host routing context) reaches it.

## Running

Start the profile you want to test first (labs must be RUNNING — a refused
connection is reported as FAIL with a compose hint):

```sh
docker compose --profile m1 up -d      # M1_URL  default http://localhost:18021
docker compose --profile m2 up -d      # M2_URL  default http://localhost:18022
docker compose --profile m3 up -d      # M3_URL  default http://localhost:18023
docker compose --profile m4 up -d      # M4_URL  default http://localhost:18025
docker compose --profile m5 up -d      # M5_URL  default http://localhost:18026
docker compose --profile full up -d    # FULL_URL default http://localhost:18024
docker compose --profile dsltv-jwt-none-alg up -d   # LAB default http://localhost:8119
```

```sh
make qa                                        # everything discovered under qa/solvers/
node qa/run-all.mjs SKIP=chain                 # skip full-mode chains (heavy profile)
node qa/run-all.mjs SKIP=jwt                   # skip the DSLTV JWT labs
node qa/run-all.mjs ONLY=m1                    # run only paths matching "m1"
M1_URL=http://localhost:18021 node qa/solvers/aslv/m1/solver.mjs   # single solver
LAB=http://localhost:8119 node qa/solvers/dsltv/jwt/none-alg/solver.mjs
```

DSLTV note: only ONE dsltv sidecar can bind `:8119` at a time (FR-3/FR-16), so
the JWT solvers run one lab at a time (`SKIP=jwt` avoids 7 lab-swaps during a
full run). Each JWT solver picks its vhost via the `Host` header
(`victim.target.lab` / `attacker.target.lab` / `collector.target.lab`) — no DNS
needed.

## Suites that exist

| Suite | Kind | Flags | Technique (intended path) |
|---|---|---|---|
| `aslv/m1` | solver + shortcut | `ASLV{HTTP-…}` | raw-socket CL.TE smuggling (edge-front ⇄ edge-back desync) + host-routing bypass into the location-locked internal zone |
| `aslv/m2` | solver + shortcut | `ASLV{CORS-…}`, `ASLV{CSRF-…}` | reflected-Origin credentialed read of `/api/secret` + token-less `/account/recovery-email` state change, both driven via the victim bot; flags minted at `collector.aslv.lab/verify` |
| `aslv/m3` | solver + shortcut | `ASLV{IDOR-…}`, `ASLV{BAC-…}` | `/support/tickets` leak → `/api/documents/{uuid}` read from the innocent's tenant subdomain (misplaced check) → `/admin/users/impersonate?user_id=admin` (checks the TARGET, not the caller) |
| `aslv/m4` | solver + shortcut | `ASLV{API-…}` ×2 | `/user/v1/list` → excessive data exposure → BOLA order pivot → mass-assignment `PATCH {role:"admin"}` (stage 1) → `/admin/v1/panel` server-side role check (stage 2) |
| `aslv/m5` | solver + shortcut (pre-existing) | `ASLV{AUTH-…}`, `ASLV{JWT-…}`, `ASLV{OAUTH-…}` | predictable reset token + provenance gate, jwk-injection forge, login-CSRF via the victim bot |
| `aslv/chain/a` | solver | `ASLV{IDOR, AUTH, JWT}` (+`API` bonus) | identity-led: M4 leak → M3 tenant IDOR → M5 reset takeover → M5 JWT forge → M4 panel with the HS256-confusion bearer (M5→M4 trust edge) |
| `aslv/chain/b` | solver | `ASLV{CSRF, AUTH, BAC}` | browser-led: M2 CSRF via victim bot → M5 reset (mail-steering check + predictable token) → M3 misplaced-check impersonation |
| `aslv/chain/c` | solver | `ASLV{HTTP-…}` (+`API` bonus) | edge-led: M1 smuggling → `/internal/flag` → `/internal/admin-token` probe (documented SKIP — no such route) → M4 panel via the M5→M4 trust edge |
| `dsltv/jwt/none-alg` | solver | `DSLTV{JWT-NoneAlg-…}` | forge `alg=none`, empty signature, gated sub+role pair |
| `dsltv/jwt/weak-hmac` | solver | `DSLTV{JWT-WeakHMAC-…}` | offline dictionary attack on the HS256 secret (`flag-hunter`), re-sign gated claims |
| `dsltv/jwt/alg-confusion` | solver | `DSLTV{JWT-AlgConfusion-…}` | HS256-sign with the public RSA key PEM (fetched from `/pubkey`) as the HMAC secret |
| `dsltv/jwt/jku-bypass` | solver | `DSLTV{JWT-JkuBypass-…}` | host your JWKS on the exploit server (`PUT /pages/keys.json` on the attacker vhost), `jku` header points there |
| `dsltv/jwt/jwk-injection` | solver | `DSLTV{JWT-JwkInjection-…}` | generate an RSA pair, embed the public JWK in the header, self-sign |
| `dsltv/jwt/kid-injection` | solver | `DSLTV{JWT-KidInjection-…}` | SQLi `kid`: `' UNION SELECT '<secret>' -- ` returns a chosen HMAC key |
| `dsltv/jwt/exp-not-checked` | solver | `DSLTV{JWT-ExpNotChecked-…}` | replay the innocent's expired pre-migration token retained in `/leaked-tokens` |

Accounts (CONTRACT §1, public): `0xnhsec`/`vlh-tester-01`, `Noshiro`/`vlh-tester-02`.
Innocent identities are never guessed — every solver discovers them through the
module's documented leak point (M2: victim bot session; M3: `/support/tickets`;
M4: `/user/v1/list`; M5: `/directory`; JWT labs: `/api/directory`).

## Roadmap (not yet built)

- **DSLTV solver suite for the remaining 47 subclasses** (cors 6, csrf 6, idor 3,
  bac 7, oauth 7, auth 5, http 6, api 7) — same two-suite pattern. The JWT
  seven shipped first because they gate the M5/chain surfaces.
- Shortcut suites for the DSLTV JWT labs (forge variants that must NOT mint:
  wrong claim pairs, bad signatures, non-`none` algs, unknown kids).
- CI wiring (run `make qa` against ephemeral compose profiles pre-release).

## Known gaps found while writing these solvers (report to module owners)

1. **Direct edge-front ports are not exposed by `docker-compose.yml`.**
   `modules/aslv-edge/README.md` §"Ports the compose file MUST provide" mandates
   `18027 → edge-front-std:8080` (m1) and `18028 → edge-front:8080` (full) — the
   compose file (Task 1) has no such bindings. The M1/chain-C solvers fall back
   to the documented through-gateway paths (absolute-form mismatch +
   pre-chunked CL.TE smuggle whose relay is best-effort per the module README),
   but the deterministic lab bench is currently unreachable from the host.
2. **`gateway-full.conf` routes only `/user/v1/*` to M4.** `/admin/v1/panel`
   (chain A/C final hop) lands on the M2 portal (404) in full mode. The chain
   solvers treat the API flag as BONUS and WARN with this explanation until the
   gateway gains an `/admin/v1/` (or api vhost) route.
3. **Full-mode `identity` service lacks `PORTAL_INTERNAL_URL`.** M5's `/forgot`
   supports consulting the portal for the recovery address (chain B's
   mail-steering hop), but the compose full profile does not set it, so reset
   mail goes to the innocent's own address. The takeover still works via the
   predictable token (the AUTH win state); chain B reports the mail's actual
   destination with a WARN.
   *Decision (portal nav fix):* kept unset on purpose — the portal exposes no
   `/_internal/user/` route, so the env var would be a silent no-op (an empty
   or wrong base URL is worse than absent). Set it the moment M2 ships that
   endpoint.
4. ~~**Full-mode `client.aslv.lab` is not a gateway vhost.**~~ **RESOLVED** —
   `gateway-full.conf` now routes `client.aslv.lab` → identity and
   `victim.aslv.lab` → portal explicitly (both ahead of the `*.aslv.lab` tenant
   regex), and the full profile sets `AUTH_ORIGIN` / `CLIENT_REDIRECT_URI` to
   the gateway origin. Both vhosts answer 200 through the gateway on 18024; the
   M5 standalone path is unchanged.
5. **`modules/aslv-app` (M3) was incomplete at authoring time** (no
   `routes/`, views, seeders, Dockerfile, sidecar — the controllers and
   middleware exist). The M3 solvers target the contract paths
   (`POST /login`, `GET /support/tickets`, `GET /api/documents/{uuid}`,
   `GET /admin/users/impersonate?user_id=admin`) with tolerant parsing + a
   `_token` fallback for the Laravel CSRF dance; re-verify against Task 2-b's
   final routes once shipped.
6. **Org-wide seed sync (`INNOCENT_*` envs) is not wired in the full profile** —
   each module seeds its own innocent with a different username/password. Chain
   B therefore expects the M3 innocent login to fail (documented WARN) and
   completes via the tester session (the M3 misplaced check does not care who
   the caller is).
7. **`api-std` (m4 standalone) has no `JWKS_URL` env** — it defaults to
   `http://identity:3000/jwks.json`, but no identity service exists in the m4
   profile, so M4's Bearer/JWT trust edge is inert in standalone mode (all
   forged-token attempts 401). `jwt.go` documents stub-auth as the standalone
   JWKS source — compose should set
   `JWKS_URL=http://stub-auth-4:3000/jwks.json`. The m4 shortcut treats the
   dead surface as correctly blocked; the intended M4 path (session +
   mass-assignment) is unaffected.
