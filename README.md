# VLH-CTF

**Vulnerabilities Logic Homelabs — Capture The Flag.** A self-hosted, Docker-based
web-exploitation home lab focused on **logic flaws and business-logic vulnerabilities**
(HTTP request smuggling is the one deliberately technical exception). Fully local,
single operator, controlled from one TUI.

Two independent product lines:

| Line | What it is | Difficulty |
|---|---|---|
| **ASLV** (AttackSuiteLogicVuln) | One organization, six modules (M0–M5) with **real trust edges between them** — flags are chained pivots across assets. Modes: `full` (all modules, port 18024) or standalone per module (18021–18026). | high–critical |
| **DSLTV** (DefinitionSubjectLogicTechnicalVuln) | **54 standalone subclasses** — one bug class each (CORS, CSRF, IDOR, BAC, JWT, OAuth, AUTH, HTTP, API), isolated container + sidecar on port 8119, PortSwigger-tier foundation that goes beyond it. | low–critical |

Everything is objectively verifiable via per-boot flags — never hardcoded, never
guessable, regenerated on every restart.

## Quickstart (Arch-family host)

```fish
./installer.sh          # deps (docker, go, nodejs, jq, curl), base image, TUI build
./run-tui.sh            # launch the TUI → deploy / monitor / export
```

Optional: `./installer.sh --hosts` adds the lab hostnames to `/etc/hosts` (only
needed for host-browser play — containers resolve everything via compose
`extra_hosts`).

Manual equivalents:

```fish
make base      # build the shared DSLTV base image (vlh-dsltv-base:1.0.0)
make tui       # build bin/vlh-tui
make up-full   # or: up-m1 .. up-m5, or: up-dsltv-jwt-none-alg (any manifest profile)
```

## Ports

| Purpose | Port |
|---|---|
| ASLV full-chain gateway (only exposed port in full mode) | **18024** |
| ASLV M1 / M2 / M3 / M4 / M5 standalone | 18021 / 18022 / 18023 / 18025 / 18026 |
| DSLTV sidecar (always; **one subclass at a time**) | **8119** |
| Collector management API (loopback; TUI polls) | full=18090, m1..m5=18091–18095, dsltv=18119 |

## Domains (all resolve to 127.0.0.1)

- **ASLV full mode** — single gateway, Host-header vhosts: `aslv.lab`,
  `www.aslv.lab` (portal, `/user/v1/` → API), `*.aslv.lab` tenants (app),
  `auth.aslv.lab` (identity), `mail.aslv.lab` (MailHog), `collector.aslv.lab`,
  `attacker.aslv.lab` (exploit server), `edge.aslv.lab` (smuggling surface).
- **ASLV standalone** — module sidecars route `victim/attacker/collector/mail`
  `.aslv.lab` vhosts on the module port.
- **DSLTV** — `victim.target.lab`, `attacker.target.lab`, `collector.target.lab`,
  `mail.target.lab` on :8119 (any other `*.target.lab` host is also routed to the
  attacker vhost — that is intentional).

## Flags

```
ASLV{CATEGORY-<9-10 digits>}            e.g. ASLV{IDOR-0193884721}
DSLTV{CATEGORY-SubName-<9-10 digits>}   e.g. DSLTV{JWT-NoneAlg-293883894}
```

Five placement archetypes (resource-resident, identity-gated, event-verified,
location-locked, stage-gated) — see **docs/flag-system.md**. CORS/CSRF flags do not
exist at boot: the collector mints them only when the exploit is actually observed
(dual check). Innocent/admin credentials are never exposed to the player.

## Repository layout

```
vlh-ctf/
├── installer.sh  run-tui.sh  Makefile  .env.example   # operator entry points
├── docker-compose.yml        # GENERATED — make compose (139 services, 60 profiles)
├── tools/                    # gen-compose.mjs (compose generator)
├── manifests/                # aslv-manifest.yaml + dsltv-manifest.yaml (source of truth)
├── modules/                  # ASLV: aslv-core, aslv-edge, aslv-portal, aslv-app, aslv-api, aslv-identity
├── dsltv/                    # DSLTV: base/ + 9 category folders / 54 subclasses
├── tui/                      # vlh-tui (Go, Bubble Tea)
├── qa/                       # solver suite (qa/run-all.mjs)
├── docs/                     # player guide, deployment, flag system, schemas, PRD, arch decisions
├── exports/                  # NDJSON/CSV activity exports (gitignored)
└── bin/                      # built TUI binary (gitignored)
```

## ⚠️ Security note (NFR-4)

The TUI (and anything that manages this lab) talks to the **Docker socket**, which
is **host-root-equivalent**. This project is built as a personal home lab for a
single operator; do not expose it to untrusted users or networks, and understand
that handing someone the TUI is handing them the host. Labs are also deliberately
vulnerable applications — never expose their ports beyond localhost.

## Documentation

- `docs/player-guide.md` — start here: per-category walkthroughs, known tester
  accounts, raw-socket tooling requirements for smuggling labs.
- `docs/deployment.md` — modes, ports, DNS/hosts, lifecycle, persistence model.
- `docs/flag-system.md` — formats, archetypes, dual-check minting, registry.
- `docs/manifest-schema.md` — manifest schemas (adding a subclass = data change).
- `docs/tui.md` — TUI usage, config, port-conflict override flow, exports.
- `docs/PRD.md` + `docs/architecture-decisions.md` — verbatim source documents.

## License

MIT — see [LICENSE](LICENSE). Author: Bangkit (0xnhsec).
