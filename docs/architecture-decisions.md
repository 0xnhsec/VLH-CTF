# ASLV / DSLTV — Architecture Decisions

Status: living document, pre-PRD. Captures decisions made during design discussion,
not yet a build spec.

**Project name:** VLH-CTF (Vulnerabilities Logic Homelabs - Capture The Flag)

> **Rev 4 changes:** Standalone infra finalized (§6): `nginx:alpine` sidecar pattern
> for M2 standalone and all DSLTV subclasses (app containers never directly exposed,
> sidecar holds the port). SQLite per-module/per-subclass via named volume replaces
> shared Postgres for standalone mode; Postgres (M0) scoped to full mode only.
> DNS handled via compose `extra_hosts` injected into containers that need it;
> host `/etc/hosts` edit is optional, not required. Gaps #1 and #4 from Rev 3 review
> resolved.
>
> Rev 3 changes: ASLV restructured from "single monolithic target" into a modular
> multi-asset architecture (§5): one organization, six modules, trust edges between
> modules are the chain surface. Deployment modes added (§6). Flag placement rewritten
> per-module (§7); §7.5 defines identity-plane win-state separation (JWT/AUTH/OAUTH
> convergence). BAC/IDOR split confirmed.
> Rev 2 changes (archetype model, §7.3/§7.4/§8) carried forward.

---

## 1. Project Naming

- **VLH-CTF** — Vulnerabilities Logic Homelabs - Capture The Flag — overall project name.
- **ASLV** — AttackSuiteLogicVuln — Main class, chained/composite target, high-critical
  technique. Implemented as a modular multi-asset organization (see §5).
- **DSLTV** — DefinitionSubjectLogicTechnicalVuln — Standalone class,
  single-bug-class-per-subclass, low-high severity, PortSwigger-referenced but designed
  to exceed 2017–2024-era difficulty.

Bug classes covered (10 distinct categories — BAC and IDOR are **separate**, confirmed:
IDOR = missing ownership check on an object reference; BAC = generalized misplaced or
absent authorization):
`CORS, CSRF, BAC, IDOR, API, OAUTH, AUTH, HTTP (Host Header / Request Smuggling), JWT`

**Why ASLV is modular, not monolithic:** implementing all classes inside one app
produces (1) cramming artifacts, (2) overlapping win conditions (JWT/AUTH/OAUTH all
terminate at "become another identity"), and (3) an untestable surface. ASLV models
one organization whose assets are each natively buggy in their own domain. Chaining =
abusing trust between assets, like real-world pivoting. DSLTV stubs its dependencies
with fakes; ASLV's inter-module trust edges are real and attackable.

## 2. Ports

### ASLV (modular)

| Mode | Port | Notes |
|---|---|---|
| Full-chain (all modules) | `18024` | Single Nginx gateway, only host-exposed port. |
| M1 standalone | `18021` | Edge module + stubs. |
| M2 standalone | `18022` | Portal module + own `nginx:alpine` vhost sidecar (§6). |
| M3 standalone | `18023` | App module + stubs. |
| M4 standalone | `18025` | API module + stubs. |
| M5 standalone | `18026` | Identity module + stubs. |

- Only one standalone module binds at a time — Docker enforces exclusivity. M0 is
  never directly host-exposed (reachable only via M1 vhost routing in full mode).
- Ad-hoc profile selection (e.g. M3 + M5 together) supported via compose profiles;
  advanced usage, not a formal mode.

### DSLTV

- Base port `8119`. A per-subclass `nginx:alpine` sidecar binds `8119` and proxies to
  the app container, which stays internal-network-only, never directly exposed (§6).
  Only one subclass sidecar+app pair runs at a time — Docker enforces exclusivity.
- `811911` (originally proposed) is not a valid TCP port (max 65535); repurposed as
  project/namespace identifier (docker network name, container label prefix).

## 3. Flag Format

- ASLV: `ASLV{CATEGORY-numericstring}` — e.g. `ASLV{IDOR-0193884721}`
- DSLTV: `DSLTV{CATEGORY-SubName-numericstring}` — e.g. `DSLTV{JWT-NoneAlg-293883894}`
- Regenerated per container start/restart (entrypoint writes to env/seed), never
  hardcoded.
- Numeric-only charset. Categories unique per module (§5); no module dimension needed
  inside the flag, registry maps it.
- **Dynamic minting (event-verified categories):** CORS/CSRF flags don't exist at
  boot; collector mints at verification time (§7.1); numeric string derives from the
  innocent-session-bound secret.
- **Flag registry:** every module writes minted/held flags to an internal store
  (shared volume file / registry endpoint), grading-only, never player-accessible.

## 4. User Model

Three account tiers, shared pattern across ASLV and DSLTV where relevant:

1. **Known tester accounts** — `0xnhsec`, `Noshiro`. Password known. Two-party
   simulation (attacker vs victim) for CSRF/CORS/OAuth login-CSRF. Victim role played
   via separate browser container profile (Firefox Multi-Account Containers), not
   incognito.
2. **Innocent account(s)** — UUID-identified, password randomly generated at seed
   time, never player-accessible (internal seed log, grading-only). Target for
   IDOR/BAC flags and AUTH/OAUTH takeover — identity discovered via legitimate leak
   point, never guessed.
   - Holds a **session-bound secret** (e.g. `api_key`), regenerated per restart,
     server-side only. Value event-verified collectors match against (§7.1).
3. **Privileged/admin account** — vertical escalation target (BAC vertical, mass
   assignment → role escalation, JWT forge-to-admin).

**Carrier rule:** email (MailHog) and activity logs are token carriers, never flag
carriers.

**Session provenance (M0/M5):** every session records `auth_method`
(`password` | `reset` | `oauth_link` | `token`) at creation — keeps JWT/AUTH/OAUTH
win conditions distinct (§7.5).

## 5. Module & Stack Architecture (ASLV)

One organization, six modules. M0 = shared foundation, no bugs of its own. M1–M5 each
host one bug domain natively. Trust edges between modules (§5.2) are the chain surface.

### 5.1 Modules

| ID | Codename | Asset metaphor | Stack | Bug classes | Archetype | Own port |
|---|---|---|---|---|---|---|
| M0 | `aslv-core` | shared foundation | Custom Auth Service (Node/Express), Postgres (full mode only, §6), MailHog, Collector (Go), seed registry | — | — | never exposed |
| M1 | `aslv-edge` | edge/infra | Nginx gateway + Go raw TCP backend | HTTP (smuggling, host header) | Location-locked | `18021` |
| M2 | `aslv-portal` | public web app | Express (minimal, no built-in CSRF) + exploit-server vhost, own `nginx:alpine` sidecar in standalone (§6) | CORS, CSRF | Event-verified | `18022` |
| M3 | `aslv-app` | internal business app | Laravel, subdomain-per-tenant (`{user}.aslv.lab/v1/...`, §7.2) | IDOR, BAC | Resource-resident | `18023` |
| M4 | `aslv-api` | API services | Go (REST, optional GraphQL), path-based (`aslv.lab/user/v1/{user}/`, §7.2) | API (BOLA/BFLA/BOPLA, composite) | Stage-gated + Resource-resident | `18025` |
| M5 | `aslv-identity` | SSO/identity plane | Node/Express custom authorization server + login/reset/MFA surfaces | JWT, AUTH, OAUTH | Identity-gated | `18026` |

Notes:
- Auth Service is M5-owned (bug surface, not neutral plumbing). M0 consumes M5 for
  internal needs only, holds no auth logic itself.
- M1's backend must be raw-controlled (Go TCP / tightly constrained `net/http`) —
  auto-repairing frameworks kill smuggling (§8).
- M2 hosts both victim-facing portal and attacker exploit-server vhost
  (`attacker.aslv.lab`, §7.1). Full mode: juiciest CORS targets are M3/M4 API
  responses. Standalone mode: M2 ships its own mini-API + own vhost sidecar (§6), no
  M3/M4 dependency.
- Collector (M0) doubles as DSLTV sidecar image (open item — implementation sharing).

### 5.2 Trust edges (the chain surface)

| Edge | Trust mechanism | Chain abuse path |
|---|---|---|
| M5 → M3, M4 | M3/M4 validate M5-issued JWT signature only — aud/scope/role checks loose (by design) | Forged/escalated token grants admin actions on M3/M4 |
| M2 ↔ M3/M4 (browser) | Portal JS calls app/API cross-origin with credentials | CORS misconfig on M3/M4 responses → exfil via M2-hosted exploit |
| M2 forms | Cookie session on portal vhost | CSRF state-change on portal actions |
| M1 → M3/M4 | Nginx routes; internal endpoints unrouted at edge | Smuggling desync reaches internal-only endpoints; Host-header poisoning steers M0 mail links |
| M0 ↔ M5/M3 | Mail delivers reset / OAuth mail | Reset poisoning (via M1) or predicted tokens (via M5) yield takeover material |
| M4 → M3 | Excessive data exposure on M4 leaks identifiers | Innocent UUID leaked at M4 feeds M3 cross-tenant IDOR |

### 5.3 Canonical chain examples

| Chain | Path | Flags earned |
|---|---|---|
| A (identity-led) | M4 excessive exposure leaks UUID → M3 cross-tenant IDOR → innocent email leaked → M5 predictable reset → takeover → M5 JWT forge to admin → M4 admin endpoint | IDOR, AUTH, JWT, API |
| B (browser-led) | M2 CSRF changes innocent recovery email → M5 reset via attacker-controlled recovery → takeover as innocent → M3 IDOR as innocent | CSRF, AUTH, IDOR |
| C (edge-led) | M1 smuggling reaches M3 internal endpoint → leaks admin token or innocent UUID → pivot into M3/M4 as elevated identity | HTTP, then downstream |

Pivot material rule (ASLV-only): every flag resource carries at least one artifact for
the next edge. DSLTV resources carry none — a DSLTV flag is a terminus.

**Scope note (applies to all of §7):** an ASLV per-category flag represents one
deliberately chosen technique, picked for chainability — full technique breadth
(every subclass of a category) lives exclusively in DSLTV, not in ASLV.

## 6. Deployment & TUI

- Deployment: Docker + docker-compose. Compose profiles drive both dimensions:
  `m1`–`m5` (ASLV modules) and DSLTV subclasses.
- **Deployment modes (ASLV):**
  - `full` — all modules, live trust edges, gateway on `18024`, Postgres (M0) for
    persistence across the whole organization.
  - `standalone` — one module + stub services (`stub-auth` signs dev tokens,
    `stub-portal` static pages, mini-collector, seed). Module binds its own `1802x`
    port. **Persistence: SQLite via named volume, local to the module container** —
    no Postgres/M0 dependency. **M1 requirement (CORS/CSRF genuineness):** M2
    standalone bundles its own `nginx:alpine` sidecar doing vhost routing
    (`victim.aslv.lab` / `attacker.aslv.lab` / `collector.aslv.lab`) internally, so
    origin-genuine testing works with M1 fully offline.
  - Ad-hoc pair selection via profiles — supported, undocumented as a formal mode.
- **DSLTV infra pattern:** each subclass = `nginx:alpine` sidecar (binds `8119`) +
  app container (internal-network-only, never directly exposed) + SQLite via named
  volume (per-subclass, independent). No custom heavyweight proxy image needed.
- **DNS resolution:** compose `extra_hosts` directive injects `victim.aslv.lab` /
  `attacker.aslv.lab` / `collector.aslv.lab` → `127.0.0.1` mappings into containers
  that need them. Host-level `/etc/hosts` edit is optional (only needed if the player
  wants to hit these hostnames directly from a host browser), not a hard requirement.
- Install flow: installer script (deps/pkg setup) → second script launches TUI.
- **TUI stack: Bubble Tea (Go) + Lip Gloss (styling) + Bubbles (widgets)**
  - Matches M4's Go toolchain — single static binary, no Python runtime dependency.
  - Mouse + keyboard: `tea.WithMouseCellMotion()`.
  - Log viewer: `bubbles/viewport` + goroutine streaming Docker logs.
  - Activity table: `bubbles/table`.
  - Alert colors (green/red) as Lip Gloss style constants.
  - Docker control via Docker SDK for Go, not shelled-out CLI.
  - Menu driven by manifests: `aslv-manifest.yaml` (modules) + `dsltv-manifest.yaml`
    (subclasses) — adding a module/subclass is a data change.
  - Config at `~/.config/aslv-dsltv/config.toml`; port conflicts trigger
    auto-generated `docker-compose.override.yml`.
- Caveat: TUI needs the Docker socket — host-root-equivalent access. Acceptable for
  personal home lab; explicit warning required if ever shared.

### Export formats

- NDJSON — append-only, streamed per event.
- CSV — `encoding/csv`; free-text/binary fields escaped or base64-encoded.
- Fields: Timestamp, user log, user activities, IP activities, data, latency, plus
  `is_authenticated: bool` + `identifier` (username if authenticated, IP/session-id
  if anonymous).

## 7. Flag Placement Strategy

**Core principle: a flag is proof that a specific trust boundary was broken.** Five
placement archetypes:

| Archetype | Mechanism | Used by |
|---|---|---|
| Resource-resident | Flag = content of a protected resource; readable only via a broken object/ownership reference | IDOR, BAC, API (partial) |
| Identity-gated | Endpoint returns flag only when server-side claims/state match a target identity | JWT, AUTH, OAUTH |
| Event-verified | No static flag; independent verifier mints it when the exploit is observed | CORS, CSRF |
| Location-locked | Flag lives where normal routing cannot reach | HTTP |
| Stage-gated | flag_n appears only after previous stage's state exists server-side | API (composite) |

### 7.0 Per-module placement (ASLV)

| Module | Class | Archetype | Flag surface & gate | Anti-shortcut / pivot |
|---|---|---|---|---|
| M3 | IDOR | Resource-resident | Flag inside innocent private resource (`/api/documents/{uuid}`); UUID only via chained leak point | Resource carries pivot material: innocent email, tenant subdomain, next-stage hint |
| M3 | BAC | Resource-resident | Horizontal: innocent resource, authz check exists-but-misplaced. Vertical: admin-only resource behind escalation | Misplaced ≠ absent — separates ASLV from DSLTV difficulty |
| M5 | JWT | Identity-gated | Flag only when claim combo the issuer never mints appears (`sub=innocent_uuid` AND `role=admin`) | Gate on impossible-claim combos, not reachability |
| M5 | AUTH | Identity-gated | Flag only for sessions with provenance `via=reset` AND `sub=innocent` | MailHog = token carrier only; provenance is about how the session was created |
| M5 | OAUTH | Identity-gated | Flag requires DB row linking innocent ↔ attacker OAuth identity | Password login as innocent impossible; flag checks linked-identity state |
| M2 | CORS | Event-verified | Exploit page at `attacker.aslv.lab` runs in victim profile; exfil to `collector.aslv.lab`, dual verification (§7.1) | Origin context + payload binding to innocent session secret |
| M2 | CSRF | Event-verified | Verifier checks DB state: innocent row `recovery_email == attacker-seeded value` | Checker inspects only the innocent row |
| M1 | HTTP | Location-locked | Smuggling: `/internal/flag` unrouted at Nginx. Host header: poisoned reset link → MailHog → takeover → flag | Unroutable, not merely unlinked; §8 tooling constraint applies |
| M4 | API | Stage-gated | flag1 = escalation proof in own profile after mass assignment; flag2 = admin endpoint verifying role claim server-side | Two flags so stage 2 can't be skipped |

### 7.1 Domain / origin scheme for CORS & CSRF (kept fully within Docker)

- DNS: compose `extra_hosts` on containers that need it — `victim.aslv.lab`,
  `attacker.aslv.lab`, `collector.aslv.lab` → `127.0.0.1`. Host `/etc/hosts` edit
  optional, only for direct host-browser access.
- Nginx (M1 in full mode; own `nginx:alpine` sidecar in M2/DSLTV standalone) does
  Host-header vhost routing — same IP/port, different `server_name` blocks.
- Browser origin = scheme + host + port; hosts differ, so SOP/CORS genuinely enforced.
- Collector (M0 in full mode; per-subclass mini-collector in standalone): logs
  incoming requests to file/SQLite with a read-only verification endpoint.
- **Dual-check win condition:**
  1. Attacker context: `Origin: attacker.aslv.lab` / `Sec-Fetch-Site: cross-site`.
  2. Payload matches the secret bound to the innocent session (server-side store, §4).
  On match, flag minted (§3), exposed at `/verify`.
- Honest limitation (by design, not anti-cheat): solo play means the player can drive
  both sides. Dual check makes the intended path cheaper than shortcuts, not
  impossible to bypass.

### 7.2 Core app URL scheme

- Subdomain-per-tenant (`{user}.aslv.lab/v1/path`) — M3 (Laravel). Tenant isolation
  relies on subdomain for display; authz validates session/token validity only, not
  tenant boundary → cross-tenant IDOR/BAC.
- Path-based (`aslv.lab/user/v1/{user}/`) — M4 (Go). Path parameter trusted for data
  resolution without verifying `{user}` == token owner.
- Both schemes on different layers = bug found via one becomes a pivot into the other
  (edge M4→M3 in §5.2).

### 7.3 DSLTV flag placement (per subclass)

Each subclass = one isolated container behind its own `nginx:alpine` sidecar (§6),
one archetype, one win condition. No chaining, no pivot material. BAC/IDOR confirmed
split — separate categories, separate folders, separate manifest slots.

| Category | Subclass slug | Archetype | Win condition |
|---|---|---|---|
| CORS | `ReflectedOrigin` | Event-verified | Collector receives exfil of victim-session data; dual check per §7.1 |
| CORS | `NullOrigin` | Event-verified | Exfil via sandboxed-iframe (null origin) under `ACAO: null` + credentials |
| CORS | `WeakOriginRegex` | Event-verified | Substring/dot/prefix bypasses; exfil from origin passing flawed validation |
| CORS | `SubdomainTrust` | Event-verified | Exfil via seeded "compromised subdomain" allowed by `*.target` trust |
| CORS | `WildcardCreds` | Event-verified | cut candidate — browsers block `*` + credentials |
| CORS | `MissingVary` | Event-verified (cache) | Verifier observes poisoned cached ACAO; cut candidate (heaviest CORS build) |
| CSRF | `MissingToken` / `ContentTypeBypass` / `MethodSwitch` / `ExistenceCheck` / `NoSessionBinding` / `SameSiteNone` | Event-verified | Shared checker: innocent-row state change; per-subclass entry constraint |
| IDOR | `NumericId` / `WriteDelete` / `FilePath` | Resource-resident | Flag in innocent object; reference type differs per subclass |
| BAC | `VerticalEsc` / `HorizontalEsc` / `RoleParamTamper` / `MethodBypass` / `CrossTenant` / `WorkflowBypass` / `MassAssign` | Resource-resident | Flag in target resource; per-subclass entry constraint |
| JWT | `NoneAlg` | Identity-gated | Forge token (sig stripped) → claim-matched endpoint returns flag |
| JWT | `WeakHMAC` | Identity-gated | Crack weak secret offline → forge → gated endpoint |
| JWT | `AlgConfusion` | Identity-gated | RS256→HS256 signed with public key → gated endpoint |
| JWT | `JkuBypass` / `JwkInjection` / `KidInjection` | Identity-gated | Three separate containers; key-control forge → gated endpoint |
| JWT | `ExpNotChecked` | Identity-gated (state variant) | Logout clears client cookie only → replay old token → flag |
| OAuth | `RedirectUriBypass` | Identity-gated | Bypass registration regex → code lands on attacker redirect → exchange → flag |
| OAuth | `MissingState` | Identity-gated | Login-CSRF: victim processes attacker's code → link → innocent session → flag |
| OAuth | `PreAuthLinking` | Identity-gated | Register with innocent's unverified email → social login maps onto innocent → flag |
| OAuth | `RefererCodeLeak` | Identity-gated | Callback loads attacker-hosted asset → Referer leaks code → exchange → flag |
| OAuth | `ImplicitGrantAbuse` | Identity-gated | Token in URL fragment captured by attacker script → API call as innocent |
| OAuth | `ScopeCreep` | Identity-gated (scope variant) | Flag only when token scope includes over-broad scope AND sub=innocent |
| OAuth | `NoPkce` | Identity-gated | Intercept simulated custom-scheme callback → exchange → flag |
| AUTH | `NoRateLimit` | Identity-gated | Seeded weak-password account; brute-force → login → flag |
| AUTH | `ResetTokenPredictable` | Identity-gated | UserEnumeration folded in as prerequisite → derive reset token → takeover → flag |
| AUTH | `MfaBypass` | Identity-gated | Direct-endpoint and response-tampering variants → flag |
| AUTH | `SessionFixation` | Identity-gated | Fixate victim session → hijack → flag |
| AUTH | `DefaultCreds` | Resource-resident | Warm-up: `admin/admin` → admin panel flag |
| HTTP | `SmuggleClTe` / `SmuggleTeCl` / `SmuggleTeTe` | Location-locked | `/internal/flag` unrouted at Nginx; reachable only via desync (§8) |
| HTTP | `HostResetPoison` | Location-locked (in-container chain) | Poisoned reset link → MailHog viewer → token → innocent takeover → flag |
| HTTP | `HostRoutingBypass` | Location-locked | Internal admin vhost via Host/Duplicate-Host/X-Forwarded-Host tricks |
| HTTP | `HostCachePoison` | Location-locked (cache) | Requires in-container proxy_cache; cut candidate |
| API | `Bola` / `Bfla` / `Bopla` / `ShadowVersion` | Resource-resident | Classic definitions; Bopla flag inside over-exposed response fields; ShadowVersion behind old route |
| API | `MassAssignEsc` | Stage-gated (2 stages) | Escalate own account → flag1 in profile → flag2 at claim-checked admin endpoint |
| API | `SsrfInternal` | Location-locked | Internal metadata sidecar holds flag; SSRF via profile-image URL |
| API | `SensitiveFlow` | Stage-gated | Bot-checkout wins limited item; item record contains flag |

**Placement decisions applied:**
- JWT sensitive-info-in-payload — dropped as standalone; side-note inside `NoneAlg` /
  `JwkInjection`.
- AUTH `UserEnumeration` — folded into `ResetTokenPredictable`.
- AUTH cookie-flag issues (Secure/HttpOnly) — side-note only (needs XSS, out of taxonomy).
- AUTH reset-poisoning — kept only under HTTP `HostResetPoison`.
- API `UnrestrictedResourceConsumption` — cut (DoS has no verifiable terminal state).
- API `UnsafeConsumption` — cut candidate (needs third-party simulator; contrived).

### 7.4 Anti-shortcut rules & QA policy

Placement checklist (every container/module before it ships):

1. Innocent/admin credentials never enter player-accessible scope.
2. Flag gates validate claims/identity/state/provenance server-side — never mere
   endpoint reachability.
3. Email and logs are token carriers, never flag carriers.
4. Event-verified collectors validate origin context + payload binding, not just
   "a request arrived".
5. Zero flag-reveal logic client-side.
6. Per-restart regeneration also regenerates every session-bound secret used by
   verifiers.
7. Pivot material rule (ASLV only, §5.3).

**QA rule — solver scripts.** `qa/solvers/<module>/` per module + `qa/solvers/chain/`
for full-mode edge traversal. Two suites each: (a) intended path must succeed;
(b) shortcut tests must fail. Run pre-release and after any placement change.

### 7.5 Identity-plane win-state separation (JWT / AUTH / OAUTH convergence)

| Class | Win state | Enforcement mechanism |
|---|---|---|
| JWT | Session/claims carrying a combo the real issuer never mints | Flag endpoint matches on claim combination |
| AUTH | Session created through the reset flow | Provenance `auth_method=reset` (§4); flag endpoint requires `via=reset` AND `sub=innocent` |
| OAUTH | Innocent account linked to attacker's OAuth identity | `linked_identities` table row; flag endpoint reads that table |

Notes:
- Provenance records how the session was created, not which bug produced the
  credential — a chain reaching the reset flow via M1 host-header poisoning
  legitimately earns the AUTH flag.
- In full mode, alternative cross-module paths are legitimate chain finds, not
  cheating — solver shortcut tests distinguish "skip the technique" shortcuts from
  legitimate cross-module paths.

## 8. Testing & tooling constraints

- Smuggling (CL.TE / TE.CL / TE.TE) is untestable with normal HTTP clients. Python
  `requests`, JS `fetch`, default `curl` normalize headers/whitespace — exactly the
  ambiguity smuggling exploits. Player docs must require raw sockets (`nc`, manual
  Python `socket`, or Burp Repeater "send group in sequence (single connection)").
- Same constraint for duplicate-Host-header tests (clients collapse dupes).
- M1 backend must not auto-repair ambiguous framing — raw TCP listener or tightly
  controlled `net/http` (§5.1).
- Browser-dependent categories (M2, M5 OAuth flows) require real browser profile
  isolation per §4 — devtools-only testing misses SameSite/origin behavior.

## Open items

- Stub interface spec per module (`stub-auth` signing key handling, seed format,
  mini-collector endpoints).
- Chain discoverability — how players learn trust edges exist.
- M2 standalone mini-API scope — how small can the self-contained CORS/CSRF target be.
- Slug table §7.3 naming convention — final sign-off.
- Cut-candidate review: `WildcardCreds`, `MissingVary`, `HostCachePoison`,
  API `UnsafeConsumption`.
- Manifest schemas (`aslv-manifest.yaml` module fields; `dsltv-manifest.yaml`).
- Whether OAuth DSLTV subclasses reuse M5's auth server in isolated mode or ship
  their own mini-AS.
- Collector implementation: shared image for M0 collector + DSLTV sidecar?
- Solver script format (Go, matching TUI/M4 toolchain?) and CI wiring.
- Scoring across modes (standalone vs full-chain: chain-bonus, partial credit).
- Full PRD (this document feeds into it, not a replacement).

## Revision Notes

- **Rev 4:** Standalone infra finalized — `nginx:alpine` sidecar pattern for M2
  standalone and all DSLTV subclasses; SQLite per-module/subclass via named volume
  replaces shared Postgres in standalone mode (Postgres scoped to full mode only);
  DNS via compose `extra_hosts`, host `/etc/hosts` optional. Project named VLH-CTF.
- **Rev 3:** ASLV restructured to modular multi-asset architecture (§5: M0–M5,
  trust-edge table, canonical chains); deployment modes + stubs (§6); per-module
  flag placement (§7.0); §7.5 identity-plane win-state separation; ports updated
  (§2, module range 18021–18026); BAC/IDOR split confirmed; solver structure
  per-module + chain (§7.4); Auth Service moved from shared infra to M5 ownership.
- **Rev 2:** §7 archetype model; §7.3 DSLTV per-subclass placement + slugs; §7.4
  anti-shortcut + solver QA; §8 tooling constraints; §3 dynamic minting + registry;
  §4 session-bound secret + carrier rule.
