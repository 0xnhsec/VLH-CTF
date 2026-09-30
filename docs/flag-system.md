# VLH-CTF — Flag System

How flags are generated, placed, verified, and regenerated. Binding references:
PRD FR-17..20, architecture-decisions §3/§7, CONTRACT §3.

---

## 1. Formats

```
ASLV{CATEGORY-<9-10 digits>}            e.g. ASLV{IDOR-0193884721}
DSLTV{CATEGORY-SubName-<9-10 digits>}   e.g. DSLTV{JWT-NoneAlg-293883894}
```

- `CATEGORY` is uppercase and one of: `CORS, CSRF, IDOR, BAC, API, OAUTH, AUTH,
  HTTP, JWT`.
- `SubName` (DSLTV only) is the PascalCase subclass name exactly as in the
  manifest / arch §7.3 table.
- Numeric charset is digits only. The number is derived at container start
  (entrypoint) — **never hardcoded, never in an env var, never in the image**.
- **Regenerated on every container start/restart** (FR-4). No flag survives a
  restart; no flag can be memorized or shared.

## 2. The five placement archetypes (arch §7)

A flag is *proof that a specific trust boundary was broken*:

| Archetype | Mechanism | Used by |
|---|---|---|
| **Resource-resident** | Flag is the content of a protected resource, readable only via a broken object/ownership reference | IDOR, BAC, API (partial), AUTH DefaultCreds |
| **Identity-gated** | Endpoint returns the flag only when server-side claims/state match a target identity — never mere login success | JWT, AUTH, OAUTH |
| **Event-verified** | No static flag exists at boot; an independent verifier **mints** it when the exploit is observed | CORS, CSRF |
| **Location-locked** | Flag lives where normal routing cannot reach (unrouted at the edge, not merely unlinked) | HTTP (smuggling, host-header) |
| **Stage-gated** | flag_n appears only after the previous stage's state exists server-side | API composite (MassAssignEsc, SensitiveFlow) |

Per-module placement (ASLV) and per-subclass win conditions (DSLTV) are recorded
in `manifests/*.yaml` and in arch §7.0 / §7.3.

## 3. Event-verified minting (CORS / CSRF) — the dual check

These flags **do not exist at boot**. The collector mints one only when *both*
checks pass:

1. **Cross-site context observed** — the exfil/hit request arrived with
   `Origin: http://attacker.aslv.lab` / `http://attacker.target.lab` (or a
   `Referer` from an attacker host, or `Sec-Fetch-Site: cross-site`), **and**
2. **Payload matches the innocent user's session-bound secret** — the 32-hex
   `api_key` bound to the innocent account, regenerated per restart, visible only
   on the victim's own page (that is the exfil target for CORS).

For **CSRF** the equivalent state check is: the innocent user's row actually
changed as a result of a cross-site request (classic case: `recovery_email`
changed to the attacker-seeded value). The checker inspects *only* the innocent
row.

On success the collector mints the flag (numeric derived from a hash of the
innocent secret — deterministic per boot, grading-friendly) and serves the
result at `GET /verify`:

```json
{"verified": true, "flag": "DSLTV{CORS-ReflectedOrigin-482910573}"}
```

or `{"verified": false}` otherwise. Solo self-play cannot fully prevent
shortcutting — the dual check makes the intended path cheaper than shortcuts,
not impossible (documented limitation, PRD §10).

## 4. Identity-plane separation (arch §7.5)

JWT / AUTH / OAUTH would otherwise all collapse into "become another identity".
They are kept distinct by **what the flag endpoint inspects**:

| Class | Win state | Enforcement |
|---|---|---|
| JWT | Session/claims carrying a combo the real issuer never mints (e.g. `sub=innocent` **AND** `role=admin`) | Claim-combination match |
| AUTH | Session created *through the reset flow* | Provenance `auth_method=reset` AND `sub=innocent` |
| OAUTH | Innocent account linked to the attacker's OAuth identity | `linked_identities` row in the DB |

Every M5/base-issued session records **`auth_method` ∈ `password | reset |
oauth_link | token`** at creation. Provenance records *how the session was
created*, not which bug produced the credential — a chain that legitimately
reaches the reset flow (e.g. via M1 host-header poisoning) legitimately earns
the AUTH flag.

## 5. Flag registry (grading-only)

Every app appends NDJSON lines to `/registry/flags.ndjson`:

```json
{"flag":"ASLV{IDOR-0193884721}","category":"IDOR","unit":"m3","archetype":"resource-resident","minted_at":"2026-01-02T10:11:12Z","note":"held"}
```

- Shared `vlh-registry` volume in ASLV full mode; per-deployment
  `<name>-registry` volume otherwise (see `docker-compose.yml`).
- **Grading-only: no route may ever serve it.** QA solvers read it via the
  grading harness, never through the lab surface.

## 6. Anti-shortcut checklist (arch §7.4 — enforced per container)

1. Innocent/admin credentials never enter player-accessible scope (innocent
   password lives only in the container-internal seed log + registry volume).
2. Flag gates validate claims/identity/state/provenance **server-side** — never
   mere endpoint reachability.
3. Email and activity logs are **token carriers, never flag carriers**.
4. Event-verified collectors validate origin context + payload binding, not just
   "a request arrived".
5. Zero flag-reveal logic client-side (no flag strings in HTML/JS except from
   the gated endpoint on success).
6. Per-restart regeneration also regenerates every session-bound secret used by
   verifiers.
7. **Pivot material rule (ASLV only):** every flag resource carries at least one
   artifact for the next trust edge. DSLTV flags are termini — no pivot material.

QA policy: every module/subclass ships solver scripts
(`qa/solvers/...`) — the intended-path suite must pass, the shortcut suite must
fail (FR-14). Run with `make qa`.
