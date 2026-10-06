# VLH-CTF — Deployment & Operations

How the lab is deployed, addressed, monitored, and torn down. For the player-facing
view see `player-guide.md`; for the compose file itself read its header (it is
generated — regenerate with `make compose`).

---

## 1. Deployment modes

| Mode | Compose profile | Port | What runs |
|---|---|---|---|
| **ASLV full-chain** | `full` | 18024 | All six modules behind one nginx gateway; every trust edge live (nothing stubbed, FR-13); M0 collector + Postgres + MailHog. |
| **ASLV standalone** | `m1` `m2` `m3` `m4` `m5` | 18021 / 18022 / 18023 / 18025 / 18026 | One real module + aslv-core stubs (`stub-auth` signs dev tokens, `stub-portal` static pages, `stub-mail` replaces MailHog). Each module still gets the exact same flags it has in full mode (FR-12). |
| **DSLTV subclass** | `dsltv-<category>-<slug>` (54) | 8119 | Exactly one subclass: `<slug>-app` (internal only) + `<slug>-edge` nginx L4 sidecar. Fully self-contained (FR-15). |
| Ad-hoc pair | any set of profiles | — | Advanced, undocumented as a formal mode (arch §6). Do not combine `full` with a module's standalone profile — they share that module's data/registry volumes. |

Preferred way to drive all of this: the TUI (`./run-tui.sh`). Manual equivalents:

```fish
make base                 # once (shared DSLTV base image)
make up-full              # or up-m1 .. up-m5
make up-dsltv-jwt-none-alg   # any manifest profile via the generic rule
make down                 # stop, keep volumes
make clean                # stop, remove volumes (all flags regenerate)
```

### Exclusivity (FR-3 / FR-16)

- **DSLTV:** every `<slug>-edge` sidecar binds host `8119` and loopback `18119`.
  Only one `dsltv-*` profile can ever be active — Docker rejects the second port
  binding with a clean error; the TUI surfaces it and tears the previous pair down
  before starting a new one.
- **ASLV standalone:** distinct `1802x` ports, so standalone modules may co-exist
  with *each other*, but each shares its data volume with its `full`-mode twin —
  never run `full` and `mX` for the same module simultaneously.

---

## 2. Port map (binding — CONTRACT §2)

| Purpose | Port |
|---|---|
| ASLV full-chain gateway (only exposed port in full mode) | `18024` |
| M1 standalone (edge is its own gateway) | `18021` |
| M2 standalone | `18022` |
| M3 standalone | `18023` |
| M4 standalone | `18025` |
| M5 standalone | `18026` |
| DSLTV sidecar (always) | `8119` |
| Collector management API, host loopback (TUI polls) | full=`18090`, m1=`18091`, m2=`18092`, m3=`18093`, m4=`18094`, m5=`18095`, dsltv=`18119` |
| MailHog UI (full mode, via `mail.aslv.lab` vhost) | internal `8025`; SMTP internal `1025` |
| Postgres (M0, full mode, internal only) | internal `5432` |

Internal container ports are never host-exposed: apps `3000` (node) / `8080` (go) /
`8000` (php), collector `8090`, nginx sidecars internal `80`.

### Collector management endpoints (loopback)

The TUI's Activity view polls these every ~2 s; they are also handy by hand:

| Mode | URL | Host header |
|---|---|---|
| full | `http://127.0.0.1:18090/internal/activity` | (direct, no vhost) |
| m1 | `http://127.0.0.1:18091/internal/activity` | `edge.aslv.lab` |
| m2 | `http://127.0.0.1:18092/internal/activity` | `collector.aslv.lab` |
| m3 | `http://127.0.0.1:18093/internal/activity` | `collector.aslv.lab` |
| m4 | `http://127.0.0.1:18094/internal/activity` | `collector.aslv.lab` |
| m5 | `http://127.0.0.1:18095/internal/activity` | `collector.aslv.lab` |
| dsltv (active subclass) | `http://127.0.0.1:18119/internal/activity` | `collector.target.lab` |

`GET /verify` (event-verified mint result) lives on the same bindings.

---

## 3. DNS & domains

Three layers, no external DNS needed (NFR-1):

1. **In-container (automatic):** compose `extra_hosts` pins the lab hostnames to
   `127.0.0.1` where needed (e.g. the ASLV full gateway, for any in-container
   absolute-URL use). All container-to-container traffic uses compose service
   names on the `811911_vlh` network.
2. **In-app (DSLTV):** the base runtime routes by `Host` header inside one
   container and rewrites lab URLs to `127.0.0.1:<listen>` + Host internally, so
   DSLTV needs no host mapping at all — the sidecar is a raw L4 pass-through.
3. **Host (optional):** browsers cannot set a `Host` header, so host-side play
   uses `/etc/hosts`. `./installer.sh --hosts` installs an idempotent marked block
   (`victim/attacker/collector/mail .target.lab` + `.aslv.lab` hosts → 127.0.0.1).
   The block covers every full-mode gateway vhost: `aslv.lab`, `www.aslv.lab`,
   `victim.aslv.lab`, `attacker.aslv.lab`, `collector.aslv.lab`, `mail.aslv.lab`,
   `auth.aslv.lab`, `client.aslv.lab`, `edge.aslv.lab`, `app.aslv.lab`,
   `api.aslv.lab`. The TUI prints those entry points (with the real host port)
   under the Status table and warns when one is missing from `/etc/hosts`.
   `/etc/hosts` cannot express **wildcards** — `*.aslv.lab` tenant subdomains
   (M3) or arbitrary `*.target.lab` attacker hosts need a local dnsmasq
   (`address=/.aslv.lab/127.0.0.1`, `address=/.target.lab/127.0.0.1`) or
   `curl --resolve` per request (see player guide).

---

## 4. Lifecycle via the TUI

`./run-tui.sh` → menu-driven from `manifests/aslv-manifest.yaml` +
`manifests/dsltv-manifest.yaml`:

- **Deploy** an ASLV mode or DSLTV subclass (initial `up` uses
  `docker compose --profile …` via exec; all lifecycle/status/log operations are
  pure Docker SDK — see `docs/tui.md`).
- **Status** — container table with port occupants; green = running, red =
  stopped/error (FR-9: only green/red carry meaning).
- **Switch subclass** — tears down the previous `<slug>-app`/`<slug>-edge` pair
  before starting the new one (FR-16).
- **Logs** — live per-container tail (Bubbles viewport, follow toggle).
- **Activity** — table polling the collector mgmt port for the active profile
  (timestamp, identifier, `is_authenticated`, data, latency).
- **Export** — NDJSON/CSV into `./exports/`.

Every `up -d --build` regenerates all flags (entrypoint-generated, FR-4). A
`down` (without `-v`) keeps volumes but flags still regenerate on next start.

---

## 5. Mail (MailHog vs stub-mail)

- **Full mode:** MailHog (`mailhog/mailhog:v1.0.1`). M5 identity sends over SMTP
  to `mailhog:1025` (MailHog has no mail-creating HTTP API). UI at
  `http://mail.aslv.lab:18024` (vhost-routed, internal :8025).
- **Standalone m1/m2/m3/m5:** `stub-mail` (aslv-core) receives identity/portal
  mail and serves a minimal mailbox UI on the `mail.aslv.lab` vhost.
- **DSLTV:** the base runtime embeds the mailbox on `mail.target.lab` (`POST
  /internal/mail` internally, UI + `GET /mail/<id>` JSON).

Mail is always a **token carrier, never a flag carrier** (CONTRACT §3).

---

## 6. Persistence model (honest v1 interpretation of arch §6)

- **Per-module / per-subclass app data = SQLite on named Docker volumes, in BOTH
  ASLV modes.** Volumes: `m1-data`…`m5-data` (ASLV), `<slug>-data` (DSLTV).
  This is the Rev 4 decision: standalone never depends on Postgres/M0, and in v1
  we keep the same SQLite persistence in full mode for consistency (one less
  moving part; module code is identical across modes).
- **Postgres (M0) exists in full mode only** and serves as the **activity
  archive** — the collector also writes activity rows there (`DATABASE_URL`).
  It is *not* the system of record for flags or app state.
- **Flag registries:** `vlh-registry` shared volume in full mode;
  `<module>-registry` / `<slug>-registry` per deployment otherwise. Grading-only,
  never served by any route.
- **Flags regenerate on every container start/restart** (FR-4) — volumes persist
  *data*, not flag values, and event-verified flags (CORS/CSRF) are minted only
  at verification time.
- `make clean` (`docker compose down -v`) wipes everything — fresh lab, fresh
  flags, fresh innocents.

---

## 7. Env & config

- `.env` (copy from `.env.example`): `EDGE_MODE` (`cl-te|te-cl|te-te` — M1
  edge-front desync flavor), `POSTGRES_USER/PASSWORD/DB` (full-mode collector
  archive).
- TUI config: `~/.config/aslv-dsltv/config.toml` (ports, export dir, compose
  path) — see `docs/tui.md`. Port conflicts produce a generated
  `docker-compose.override.yml`.
- `docker-compose.yml` is **generated** — never hand-edit it; change the
  manifests (`dsltv-manifest.yaml` is the source of truth for DSLTV) or
  `tools/gen-compose.mjs` (ASLV map), then `make compose`.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `up` fails with "port is already allocated" (8119) | Another DSLTV subclass is active — by design (FR-3). Stop it (TUI switch or `make down`) first. |
| `up` fails on 18024/1802x | Another ASLV mode or a stray process holds the port. `docker compose down` then retry. |
| Host browser can't reach `victim.target.lab` | Add `/etc/hosts` entries (`./installer.sh --hosts`) or use `curl --resolve`. |
| Smuggling labs "don't work" in a browser/proxy | They cannot — raw sockets only (arch §8). See player guide. |
| Flags differ from yesterday | Correct — everything regenerates per boot (FR-4). The registry volume is grading-only. |
