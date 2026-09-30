# vlh-tui — VLH-CTF lab controller

Terminal UI (Bubble Tea) for the VLH-CTF Docker home lab. Menu-driven from
`manifests/aslv-manifest.yaml` + `manifests/dsltv-manifest.yaml` — deploying a
newly added DSLTV subclass is a pure data change, no code edit (PRD FR-5).

Implements PRD FR-5..FR-11: keyboard+mouse deploy/stop/restart of any ASLV mode
or DSLTV subclass, pre-deploy port-occupancy detection, live log tailing, the
activity table, green/red-only semantics, NDJSON/CSV export, and the TOML
config with auto-generated `docker-compose.override.yml` port remaps.

## Build

Requires Go >= 1.23 and a reachable Docker daemon at runtime (not for build).

```sh
cd tui
go mod tidy      # generates go.sum + indirect deps (not committed — the dev sandbox had no Go toolchain)
go build         # ./tui
# static binary per CONTRACT §9 (NFR-3), same as `make tui` from the repo root:
CGO_ENABLED=0 go build -o ../bin/vlh-tui .
```

Run **from the repository root** (`docker-compose.yml` and `manifests/` are
resolved relative to the working directory unless overridden in the config):

```sh
./bin/vlh-tui        # or: make tui && ./run-tui.sh
```

## Keybindings

| Context | Key | Action |
|---|---|---|
| everywhere | `↑/k` `↓/j` wheel | move selection (click = select + open) |
| everywhere | `ctrl+c` | quit |
| menus | `enter` / `d` | open deploy confirmation for selection |
| menus | `s` / `r` | stop / restart the selected **profile** (Docker SDK) |
| menus | `l` | logs — container picker |
| menus | `a` / `e` / `?` | activity / export / help |
| menus | right-click / middle-click | stop / restart the clicked item (mouse parity for FR-5) |
| confirm screen | `enter`/`d`/click | deploy — **blocked** while the port is held by another profile/process |
| confirm screen | `D` | force deploy past the red warning (docker still refuses hard bind conflicts) |
| confirm screen | `p` / `0` | pick next free port (writes `docker-compose.override.yml`) / clear remap |
| confirm screen | `x` | stop the conflicting lab profile, then deploy (FR-16 subclass switching) |
| confirm screen | `R` | re-check port occupancy |
| status | `s`/`r`/`l` | stop / restart / logs of the selected container |
| status | `R` | refresh |
| logs | `f` | toggle follow (auto-scroll) |
| logs | `g` / `G` | top / bottom |
| activity | `tab` | cycle the active profile being polled |
| activity | `R` | poll immediately |
| export | `enter` | write cached rows as NDJSON or CSV |
| everywhere | `esc` / `q` | back (quit on main menu) |

## Architecture

```
tui/
├── main.go                      entrypoint: config + manifests + docker client → tea program
├── internal/config/             config.toml load/save + compose port-override generator
├── internal/manifest/           ASLV/DSLTV manifest types (yaml.v3)
├── internal/dockerops/          Docker SDK wrapper + compose CLI orchestration
├── internal/collector/          /internal/activity NDJSON poller (2s timeout)
├── internal/exporter/           NDJSON + CSV writers
└── internal/ui/                 bubbletea model: app (state machine), status, logs,
                                 activity, export, help, lipgloss styles
```

- Colors (FR-9): green `#22C55E` = normal/success, red `#EF4444` = error/alert.
  Gray dim is neutral chrome only; no other color carries meaning.
- Long operations (compose up/down, docker list, polls, exports, log streaming)
  run as `tea.Cmd`s — `Update` never blocks.
- Log streaming uses the re-arm pattern: each `logsMsg` returns a command that
  reads the next line from the stream channel; a session id drops stale lines
  after switching containers. The in-memory ring buffer caps at 2000 lines.

### Documented compromise: Docker SDK vs `docker compose` CLI (CONTRACT §9)

The PRD's NFR says "Docker control via Docker SDK for Go, not shelled-out CLI".
Compose-file orchestration is not a supported SDK surface, so the split is:

- **Docker SDK** (`github.com/docker/docker/client`): container listing
  (filtered by label `com.docker.compose.project=vlh-ctf` OR `811911.vlh=1`),
  per-profile start/stop/restart, per-container stop/restart, log streaming
  (`ContainerLogs` + `stdcopy` demux), i.e. the whole runtime lifecycle.
- **exec.Command** — ONLY for `docker compose -f <file> --profile <p> up -d
  --build` (deploy) and `... down` (full profile teardown / FR-16 switching),
  run with cwd at the compose file's directory. This is the documented
  compromise sanctioned by CONTRACT §9.

### Port occupancy (FR-6) and overrides (FR-11)

Before every deploy, the confirmation screen shows the target port and its
current occupant, computed from (a) running lab containers' published ports +
labels, and (b) a `net.Listen("tcp", "127.0.0.1:<port>")` probe for non-lab
occupants. Deployment is blocked (red) while another profile or process holds
the port; `D` forces, `p` remaps, `x` tears the conflicting profile down first.

Remapping parses the base `docker-compose.yml` (short and long `ports`
syntaxes), swaps the host side of the conflicting mapping, and writes
`docker-compose.override.yml` next to it:

```yaml
# Generated by vlh-tui — host port remap (requires docker compose >= 2.24 for !override).
services:
  none-alg-edge:
    ports: !override
      - "127.0.0.1:8120:80"
```

The `!override` tag makes compose **replace** the service's port list instead
of merging (plain override files would bind both ports) — it requires docker
compose >= 2.24 (always true on an updated Arch install). The override file is
regenerated wholesale on each remap; delete it to restore default bindings.

### Active-profile detection

Running profiles are detected from container labels first (`811911.profile`,
see below), then naming conventions: DSLTV services are `<slug>-app` /
`<slug>-edge` (CONTRACT §7); ASLV profiles additionally match by their unique
ports (18021–18026). All 54 DSLTV subclasses share port 8119, so DSLTV relies
on labels/names, never on the port alone.

## Config file

`~/.config/aslv-dsltv/config.toml` (created with defaults on first run):

```toml
# Host ports per compose profile (contract §2).
[default_ports]
full = 18024
m1 = 18021
m2 = 18022
m3 = 18023
m4 = 18025
m5 = 18026
dsltv = 8119

# Collector management API ports (host loopback) the TUI polls for activity.
[collector_ports]
full = 18090
m1 = 18091
m2 = 18092
m3 = 18093
m4 = 18094
m5 = 18095
dsltv = 18119

export_dir = "./exports"       # NDJSON/CSV output (created on demand)
compose_file = "docker-compose.yml"
manifest_dir = "manifests"
```

Partial files are fine — missing keys are backfilled from defaults at load.

## Compose-file expectations (for lab authors)

- Project name `vlh-ctf` (`name: vlh-ctf`); every service labelled
  `811911.vlh=1`. **Recommended:** also `811911.profile: <profile>` per service
  — it makes profile detection and `x` (teardown+deploy) exact.
- Every service must belong to a compose profile; there must be no
  default-profile services, otherwise `up --profile X` starts them too.
- DSLTV services named `<slug>-app` / `<slug>-edge` (contract §7).
- Collector mgmt endpoints published on host loopback: the DSLTV app container
  publishes its port 8080 as `127.0.0.1:18119:8080`; the ASLV M0 collector
  publishes 8090 as `127.0.0.1:1809x:8090`.
- The activity feed must answer `GET /internal/activity` with NDJSON lines
  `{"ts","identifier","is_authenticated","data","latency","unit"}` (same shape
  as `dsltv/base/runtime.js`). The TUI sends `Host: collector.aslv.lab:<port>`
  (ASLV) / `Host: collector.target.lab:18119` (DSLTV) — required by the DSLTV
  runtime's Host-header vhost routing — while dialing `127.0.0.1:<port>`.

## Security note (NFR-4)

This tool talks to the Docker socket (`/var/run/docker.sock`), which is
**host-root-equivalent**. Single-operator home lab use only; never run it on a
host shared with untrusted users.
