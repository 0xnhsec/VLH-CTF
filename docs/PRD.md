# VLH-CTF — Product Requirements Document

Status: Draft v1. Derived from `architecture-decisions.md` (Rev 4). This is the build
spec; architecture-decisions.md remains the design-rationale record.

---

## 1. Overview

**VLH-CTF** (Vulnerabilities Logic Homelabs - Capture The Flag) is a self-hosted,
Docker-based web exploitation home lab targeting **logic-flaw and business-logic
vulnerabilities**, not memory-corruption/technical exploitation (HTTP smuggling is
the sole exception requiring true technical exploitation).

Two independent product lines:
- **ASLV** (AttackSuiteLogicVuln) — modular, chainable, high-critical difficulty.
- **DSLTV** (DefinitionSubjectLogicTechnicalVuln) — standalone, single-bug-class,
  low-high difficulty, PortSwigger-tier foundation.

Controlled by a single TUI application.

## 2. Goals

- Provide a home lab that trains **chained exploitation reasoning** (ASLV) distinct
  from **single-technique mastery** (DSLTV), for one operator: Bangkit (0xnhsec).
- Cover 10 bug categories: CORS, CSRF, BAC, IDOR, API, OAuth, AUTH, HTTP (Host Header
  + Request Smuggling), JWT.
- Every exploit outcome is objectively verifiable via a flag, generated per session,
  never guessable or hardcoded.
- Fully local, Docker-only, no external infrastructure dependency.
- Operable via one TUI: deploy, switch, monitor, export.

## 3. Non-Goals

- Not a multiplayer CTF platform — single operator, self-play (attacker + victim
  roles both played by the same person via isolated browser profiles).
- Not an anti-cheat system — dual-check flag verification (§CORS/CSRF) raises the
  cost of shortcuts, does not eliminate them.
- Not covering memory-safety/binary exploitation categories.
- Not shipping a scoring/leaderboard system in v1 (open item).

## 4. Users

- Primary and only user: operator (Bangkit), self-taught security researcher and
  bug bounty hunter, Arch/CachyOS + fish shell environment.

## 5. Scope

### 5.1 ASLV — modules

Six modules, one organization narrative. See architecture-decisions.md §5 for full
trust-edge and chain design.

| Module | Codename | Classes | Stack |
|---|---|---|---|
| M0 | aslv-core | — (shared foundation) | Node/Express (auth internals), Postgres (full mode), MailHog, Go collector |
| M1 | aslv-edge | HTTP (Host Header, Smuggling) | Nginx + Go raw TCP |
| M2 | aslv-portal | CORS, CSRF | Express (minimal) |
| M3 | aslv-app | IDOR, BAC | Laravel |
| M4 | aslv-api | API (composite) | Go |
| M5 | aslv-identity | JWT, AUTH, OAuth | Node/Express |

Deployment modes: `full` (all modules, port 18024), `standalone` (one module +
stubs, ports 18021–18026), ad-hoc pair (advanced/undocumented formal support).

### 5.2 DSLTV — subclasses

Full subclass list and win conditions: architecture-decisions.md §7.3. Summary count
per category:

| Category | Subclass count |
|---|---|
| CORS | 6 (2 cut-candidates pending review) |
| CSRF | 6 (shared checker, per-subclass entry constraint) |
| IDOR | 3 |
| BAC | 7 |
| JWT | 7 |
| OAuth | 7 |
| AUTH | 5 |
| HTTP | 4 (1 cut-candidate pending review) |
| API | 7 (2 cut) |

Each subclass = isolated container + `nginx:alpine` sidecar (port 8119) + SQLite
volume. One active at a time, enforced by Docker port binding.

## 6. Functional Requirements

### 6.1 Deployment

- FR-1: Installer script installs required deps/pkgs for the host (Arch-family target).
- FR-2: `docker-compose` profiles select ASLV mode/module or DSLTV subclass.
- FR-3: Starting a profile that conflicts with an active one on the same port must
  fail cleanly with a clear error (Docker's native behavior), surfaced by the TUI.
- FR-4: All flags regenerate on every container start/restart; no flag persists
  across restarts.

### 6.2 TUI

- FR-5: Deploy/stop/restart any ASLV module or mode, or any DSLTV subclass, via
  keyboard and mouse.
- FR-6: Detect and display currently active profile/port occupant before allowing a
  new deployment on the same port.
- FR-7: Tail live logs per container (Bubbles `viewport`).
- FR-8: Display activity table (Bubbles `table`) with: timestamp, identifier
  (username or IP/session-id), `is_authenticated`, data, latency.
- FR-9: Alert coloring: green = normal/success, red = error/alert. No other color
  carries semantic meaning.
- FR-10: Export activity log as NDJSON or CSV, on demand.
- FR-11: Config (default ports, overrides) persisted at
  `~/.config/aslv-dsltv/config.toml`; port conflicts trigger auto-generated
  `docker-compose.override.yml`.

### 6.3 ASLV chaining

- FR-12: Each module's flag is retrievable independently (standalone mode) or as
  part of a chain (full mode) — same flag mechanism, no mode-specific flag logic.
- FR-13: Trust edges (§5.2 of architecture doc) must be live and attackable in full
  mode — no edge may be simulated/stubbed when `full` profile is active.
- FR-14: Solver scripts (`qa/solvers/<module>/`, `qa/solvers/chain/`) must exist per
  module and per canonical chain; intended-path suite passes, shortcut suite fails.

### 6.4 DSLTV isolation

- FR-15: A DSLTV subclass container must not depend on any other subclass or on
  ASLV modules — fully self-contained (own SQLite, own sidecar, own seed).
- FR-16: Switching subclasses tears down the previous container+sidecar pair before
  starting the new one.

### 6.5 Flag system

- FR-17: Flag format enforced: `ASLV{CATEGORY-numericstring}`,
  `DSLTV{CATEGORY-SubName-numericstring}`.
- FR-18: Event-verified flags (CORS, CSRF) are minted only after dual-check passes
  (origin context + session-bound-secret match) — never pre-generated.
- FR-19: Identity-gated flags (JWT, AUTH, OAuth) validate server-side claims/state/
  provenance — never mere authentication success.
- FR-20: No flag-reveal logic exists client-side, in any category.

## 7. Non-Functional Requirements

- NFR-1: Fully offline-capable — no external network dependency for any lab to
  function (per architecture-decisions.md §7.1 domain scheme).
- NFR-2: Target host: Arch Linux family (CachyOS), fish shell environment.
- NFR-3: TUI ships as a single static Go binary.
- NFR-4: Docker socket access is required and must be documented as
  host-root-equivalent risk.
- NFR-5: HTTP smuggling categories must remain testable only via raw-socket tooling
  by design — no auto-normalizing proxy/framework in M1 backend or DSLTV HTTP
  subclass containers (architecture-decisions.md §8).

## 8. Data Model (summary)

- Three user tiers: known tester (`0xnhsec`, `Noshiro`), innocent (UUID-only,
  password never exposed), privileged/admin. Full definitions:
  architecture-decisions.md §4.
- Session provenance field `auth_method` (`password` | `reset` | `oauth_link` |
  `token`) required on every M5-issued session — backbone of §7.5 identity-plane
  separation.
- Flag registry: internal store (file/registry endpoint), grading-only, never in
  player-accessible scope.

## 9. Milestones (proposed, sequencing not yet locked)

1. M0 core + TUI skeleton (deploy/stop single container, log tail).
2. DSLTV: JWT category (7 subclasses) end-to-end, including sidecar+SQLite pattern.
3. DSLTV: remaining 8 categories.
4. ASLV M5 (identity plane) standalone.
5. ASLV M1–M4 standalone, each independently.
6. ASLV full-chain mode + solver scripts for canonical chains A/B/C.
7. Export (NDJSON/CSV) + config override flow.
8. Hardening pass: cut-candidate review, QA solver suite complete for all modules
   and subclasses.

## 10. Risks

- Docker socket exposure to TUI = host-root-equivalent; single-operator context
  makes this acceptable, but blocks safely sharing the tool as-is.
- Solo self-play on event-verified flags (CORS/CSRF) cannot fully prevent
  shortcutting — accepted as documented limitation (NFR out of scope: anti-cheat).
- Six-stack polyglot (Node, PHP/Laravel, Go, Nginx) increases maintenance surface
  versus single-stack — accepted for realism per architecture rationale.
- Cut-candidate subclasses (`WildcardCreds`, `MissingVary`, `HostCachePoison`, API
  `UnsafeConsumption`) may need replacement content if cut — not yet resourced.

## 11. Success Criteria

- All 10 categories playable in DSLTV with independently verifiable flags.
- ASLV playable in both standalone (per-module) and full-chain mode, with at least
  the three canonical chains (A/B/C) solver-verified.
- TUI performs full lifecycle (deploy/monitor/export) without manual `docker`
  CLI intervention.
- Zero flag guessable without exploiting the intended vulnerability (solver
  shortcut-suite requirement, FR-14).

## 12. Out of Scope / Open Items

Carried from architecture-decisions.md (unresolved as of this PRD draft):

- Scoring/leaderboard system.
- Stub interface spec per module.
- Chain discoverability mechanism (recon surface vs hints vs docs).
- M2 standalone mini-API exact scope.
- Final sign-off on DSLTV slug naming convention.
- Cut-candidate replacement decision.
- Manifest schema definitions (`aslv-manifest.yaml`, `dsltv-manifest.yaml`).
- OAuth DSLTV: reuse M5 auth server vs standalone mini-AS.
- Collector implementation sharing between M0 and DSLTV sidecar.
- Solver script language/format and CI wiring.
