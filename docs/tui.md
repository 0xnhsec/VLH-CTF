# VLH-CTF — TUI Guide

`vlh-tui` is the single control surface for the lab (PRD FR-5..11): deploy,
switch, monitor, and export — no manual `docker` CLI needed for normal play.

```fish
./run-tui.sh        # or: make tui && ./run-tui.sh
```

Requirements: Docker running; the TUI uses the Docker socket (host-root-
equivalent — NFR-4). It is a single static Go binary (Bubble Tea + Lip Gloss +
Bubbles; CGO disabled).

> Implementation details and exact key handling live in `tui/README.md`
> (owned by the TUI module). This page documents the contract-level behavior.

---

## 1. Model

- The menu is **data-driven** from `manifests/aslv-manifest.yaml` (modes +
  modules) and `manifests/dsltv-manifest.yaml` (categories → subclasses).
  Adding a lab is a manifest change, not a TUI change.
- Lifecycle operations (start/stop/restart/logs/status) go through the
  **Docker SDK for Go**; the initial profile bring-up invokes
  `docker compose --profile <p> up -d --build` (documented, allowed exception —
  compose file-level orchestration via SDK is impractical).
- Deploying a DSLTV subclass while another one runs: the TUI **tears down the
  previous `<slug>-app`/`<slug>-edge` pair first** (FR-16). If a port is still
  occupied (e.g. by a foreign process), Docker's clean port-binding error is
  surfaced (FR-3).

## 2. Views

| View | What it shows |
|---|---|
| **Main menu** | ASLV modes (full / m1..m5) and DSLTV categories → subclasses |
| **Status** | Container table for compose project `vlh-ctf` (filtered by compose labels), port occupants, running state — green = running/OK, red = stopped/error (FR-9: no other semantic colors). Below the table: the active profiles and the **copyable play URLs** (`http://<vhost>:<real port>/`) of every running profile — the port is read from the container that publishes it, so a FR-11 remap shows up correctly, and a red hint names any vhost missing from `/etc/hosts` |
| **Logs** | Live per-container log tail (Bubbles viewport, follow toggle on/off) |
| **Activity** | Table polling the active mode's collector mgmt port every ~2 s: timestamp, identifier, `is_authenticated`, data, latency. Red rows flag anomalies (e.g. anonymous hits on authenticated endpoints) |
| **Export** | Activity log → `exports/*.ndjson` or `exports/*.csv` |
| **Help** | Keybindings + config location |

## 3. Keybindings (summary)

- `↑/↓` (or mouse wheel / click) — navigate lists and tables
- `enter` — select / deploy the highlighted profile
- `l` — logs for the highlighted container; `f` — toggle log follow
- `a` — activity view; `e` — export (NDJSON/CSV)
- `s` / `r` / `x` — stop / restart / teardown the active profile
- `q` / `esc` — back / quit
- `?` — help

(Mouse support is enabled via `tea.WithMouseCellMotion()` — clicking rows and
scrolling work everywhere.)

## 4. Configuration — `~/.config/aslv-dsltv/config.toml`

```toml
# VLH-CTF TUI configuration (defaults shown)
[lab]
compose_file = "./docker-compose.yml"   # repo-root compose file
export_dir   = "./exports"

[ports]
# lab ports (match the manifests unless you override)
full = 18024
m1 = 18021
m2 = 18022
m3 = 18023
m4 = 18025
m5 = 18026
dsltv = 8119

[collector]
# loopback collector mgmt ports the Activity view polls
full = 18090
m1 = 18091
m2 = 18092
m3 = 18093
m4 = 18094
m5 = 18095
dsltv = 18119
```

The TUI creates the file with defaults on first run; `collector` defaults are
seeded from the manifests.

## 5. Port conflicts → `docker-compose.override.yml` (FR-11)

If a configured port is occupied (or you want to move a lab port):

1. Change the port in the config editor (or edit `config.toml`).
2. The TUI writes a **generated** `docker-compose.override.yml` next to
   `docker-compose.yml` overriding the affected service's port binding — the
   generated base compose file is never modified.
3. Restart the profile from the TUI; the override applies automatically.
4. Deleting the override file (or resetting the port in config) restores the
   manifest defaults.

Keep overrides out of commits — they are machine-local.

## 6. Exports (FR-10)

- **NDJSON** — append-only, one JSON object per line, streamed per event
  (`exports/<profile>-<date>.ndjson`).
- **CSV** — proper `encoding/csv` escaping; free-text/binary fields are escaped
  or base64-encoded (arch §6).
- Fields: timestamp, identifier (username when authenticated, IP/session-id when
  anonymous), `is_authenticated`, activity/data, latency.

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| "cannot connect to the Docker daemon" | `sudo systemctl start docker` (installer enables it) |
| Deploy fails: port already allocated | Expected exclusivity (FR-3/FR-16) — stop the active profile first; TUI usually does this for you |
| Activity table empty | Wrong collector port for the active mode — check `config.toml` `[collector]` against `docs/deployment.md` §2 |
| `bin/vlh-tui` missing | `make tui` (or re-run `./installer.sh`) |
