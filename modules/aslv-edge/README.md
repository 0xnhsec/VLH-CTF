# ASLV M1 — `aslv-edge` (HTTP: request smuggling + host-header quirks)

Edge/infrastructure module of the ASLV product line. **Bug class:** HTTP
(smuggling CL.TE / TE.CL / TE.TE, host-header routing bypass). **Flag:**
`ASLV{HTTP-<digits>}` — **archetype: location-locked** (arch §7.0): the flag
lives at `edge-back`'s `/internal/flag`, a route that **no gateway vhost can
reach** — it is unrouted, not merely unlinked.

## Architecture

```
                 full mode (host :18024)          standalone (host :18021)
 client ──────►  nginx gateway-full  ──────────►  nginx gateway-standalone
                    │  vhost routing                  │  vhost routing
                    │  edge.aslv.lab ────────►  edge-front-std:8080  (Go, :8080)
                    │                                 │  re-frames CL ⇄ TE  ◄── ALSO exposed
                    │                                 ▼                        directly on the host
                    │                            edge-back-std:8081  (Go, raw :8081)
                    │                                 │  /internal/flag  (location-locked)
                    │                                 ▼
                    │                            edge-back-std:8090  (mini collector, net/http)
                    ├── aslv.lab / www ──► portal:3000        (M2, other module)
                    ├── /user/v1/ ───────► api:8080            (M4, other module)
                    ├── <tenant>.aslv.lab ► app:80             (M3, other module)
                    ├── auth.aslv.lab ───► identity:3000       (M5, other module)
                    ├── mail.aslv.lab ───► mailhog:8025
                    ├── collector.aslv.lab ► portal:3000       (M2 embeds collector endpoints)
                    ├── attacker.aslv.lab ► portal:3000        (M2 exploit server)
                    └── internal.aslv.lab ► 404                (location-locked, always)
```

Three images, four Docker targets (compose builds each with `--target`):

| Target | Base | Listens | Purpose |
|---|---|---|---|
| `gateway-full` | nginx:1.27-alpine | :80 (host 18024) | full-chain vhost gateway (`conf/gateway-full.conf`) |
| `gateway-standalone` | nginx:1.27-alpine | :80 (host 18021) | M1 standalone gateway (`conf/gateway-standalone.conf`) |
| `edgefront` | scratch (static) | :8080 | raw TCP desync proxy (the smuggling engine) |
| `edgeback` | alpine:3.20 | :8081 + :8090 | raw HTTP origin (flag) + mini collector |

Deviation from the task sketch: `edgeback` uses `alpine:3.20` instead of
`scratch` because the specified **sh entrypoint** (generate flag + secret at
start, write files, register the flag, exec the binary) requires a shell. The
binary itself also re-generates the flag if `/data/flag.txt` is missing, so the
guarantees hold either way. `edgefront` remains pure `scratch`.

## Ports the compose file MUST provide (m1 + full profiles)

- `18021` → `gateway-standalone:80` (m1 profile) — per CONTRACT §2.
- **`18027` → `edge-front-std:8080` (m1 profile) — REQUIRED for the
  deterministic desync labs.** The nginx gateway is an HTTP proxy: it delimits
  requests correctly and will never forward smuggled prefix bytes that sit
  beyond a declared `Content-Length` (they would be parsed as the next
  pipelined request and 404'd). The labs therefore play against the edge-front
  port directly with a raw socket.
- `18028` → `edge-front:8080` (full profile) — same, full-mode flavour.
- `18091` → `edge-back-std:8090` (m1 profile) — collector mgmt port per
  CONTRACT §2.
- `EDGE_MODE` env must be set on the `edge-front(-std)` service
  (`cl-te` | `te-cl` | `te-te`, default `cl-te`). The back-end needs no mode
  env: it deterministically honors strict `Transfer-Encoding: chunked` when
  present and `Content-Length` otherwise (obfuscated TE headers are not
  recognized — that is the TE.TE surface).

## Endpoints

**edge-back :8081** (raw, manually parsed — multi-request-per-connection):

| Path | Behavior |
|---|---|
| `/internal/flag` | `ASLV{HTTP-...}` — **only** when the request's Host is `internal.aslv.lab` (the internal zone's own host gate; 403 otherwise) |
| `/internal/*` | 404 |
| `/app`, `/app/*` | 200 simple pages |
| `/app/vault` | 200 — shows the synthetic 32-hex innocent secret generated at boot |
| `/healthz` | `{"ok":true,...}` |
| anything else | 404 |

**edge-back :8090** (mini collector — net/http, not in the smuggling path):

| Path | Behavior |
|---|---|
| `GET /internal/activity` | NDJSON, latest 5000 activity rows (newest first) |
| `POST /internal/ingest` (alias `/ingest`) | append forwarded NDJSON activity rows |
| `GET /healthz` | liveness |

Activity: every :8081 request is logged as
`{"ts","identifier","is_authenticated","data","latency_ms"}` to
`/data/activity.jsonl` and, when `ACTIVITY_SINK` is set, POSTed there
(fire-and-forget, 1s timeout).

**Gateway vhosts** — see `conf/gateway-full.conf` and
`conf/gateway-standalone.conf` (each vhost is documented inline).

## Seeded accounts

None — M1 has no login surface. Tester accounts live in the other modules. The
only "secret" is the synthetic innocent secret (`/app/vault`), generated at
boot, never registered as a flag.

## Intended exploit path (standalone)

1. **Request smuggling (primary, the technique win).** With `EDGE_MODE=cl-te`
   (default), open a raw socket to the edge-front port (`nc localhost 18027`
   or a Node/Python socket — per arch §8, curl/fetch cannot do this) and send:

   ```
   POST /app/search HTTP/1.1
   Host: edge.aslv.lab
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 9

   q=desyncGET /internal/flag HTTP/1.1
   Host: internal.aslv.lab
   X-Vlh: 1

   ```

   The front (CL rule) treats `q=desync` as the whole body, forwards the
   request to the back-end re-framed as chunked with a true-length chunk plus
   `0\r\n\r\n`, then appends the leftover bytes RAW. The back-end (TE rule)
   finishes request #1 at the terminator, parses `GET /internal/flag` as its
   next pipelined request, and answers it. Both responses come back on your
   socket — the second contains `ASLV{HTTP-...}`.

   Alternate classic variant (works through the gateway's edge vhost
   best-effort, because the whole payload sits *inside* the declared
   Content-Length): body = `0\r\n\r\nGET /internal/flag HTTP/1.1\r\nHost:
   internal.aslv.lab\r\n\r\n` with `Content-Length` covering all of it — the
   front passes pre-chunked bodies through verbatim, so the back-end stops at
   the embedded `0`-chunk and reads the rest as the next request.

   `te-cl` mode: send `Content-Length: 4` + `Transfer-Encoding: chunked` with a
   chunk whose data is `XXXX` + the smuggled request; the front de-chunks and
   forwards with the *client's* CL kept verbatim. `te-te` mode: same payload —
   the front additionally obfuscates the TE header (`Transfer-Encoding :
   chunked`, space before the colon) so the back-end falls back to CL.

2. **Host-routing bypass (the host-header quirks win).** On the edge-front
   port, a plain request that carries the internal host in a *duplicate* Host
   header or an absolute-form target is re-routed into the internal zone:

   ```
   GET /flag HTTP/1.1
   Host: edge.aslv.lab
   Host: internal.aslv.lab

   ```

   or `GET http://internal.aslv.lab/flag HTTP/1.1` — the front prefixes the
   forwarded path with `/internal/` and forces `Host: internal.aslv.lab`, so
   the back-end's host gate opens. Through the nginx gateway this is blocked
   by design (duplicate Host → nginx 400; `Host: internal.aslv.lab` → the 404
   server), which is exactly the location-locked property; the
   absolute-form-vs-Host mismatch (`GET http://edge.aslv.lab/flag` with
   `Host: internal.aslv.lab`) is the one variant worth trying through :18021 —
   nginx routes by the absolute URI but the edge vhost forwards the client's
   `$http_host` to the front (nginx-version-dependent; the direct port is the
   deterministic path).

3. **Trust edges (full mode, other modules realize them):** the gateway
   forwards arbitrary `X-Forwarded-Host` to the portal/identity upstreams
   (host-header poisoning of mail/reset links — M5's chain), and the edge pair
   models "smuggling reaches internal-only endpoints" (chain C).

## Anti-shortcut guarantees

- `GET /internal/flag` with any *routable* Host through the gateway: 404
  (internal vhost) or 403 (edge vhost — the front refuses /internal paths for
  parsed requests without internal-host context).
- The back-end's `/internal/flag` additionally requires the internal Host, so
  even keepalive-reused raw-piped requests through the gateway cannot fetch it.
- The flag is regenerated at every container start and never lives in an env
  var or in any client-side code.

## Standalone vs full differences

- Standalone: gateway on 18021 with stub vhosts (`stub-portal-1`,
  `stub-auth-1`, `stub-mail-1`), the collector vhost points at edge-back's own
  mini collector (`edge-back-std:8090`), edge-front direct on 18027.
- Full: gateway on 18024 routes the real M2–M5 services; the collector vhost
  points at the M2 portal (which embeds the collector endpoints); edge-front
  direct on 18028. `ACTIVITY_SINK` may be set to the M0 collector's
  `/ingest`.
- The desync labs themselves behave identically in both modes.

## Files

- `cmd/edgefront/main.go` — desync engine (~330 lines, heavily commented)
- `cmd/edgeback/main.go` — raw origin + mini collector
- `internal/httparse/httparse.go` — shared strict HTTP/1.1 parser (the
  anti-auto-repairing core)
- `conf/gateway-full.conf`, `conf/gateway-standalone.conf` — nginx vhosts
- `entrypoint-edgeback.sh` — flag/secret generation at start
- `Dockerfile` — four targets; `.dockerignore`
- Solver: `qa/solvers/aslv/m1/{solver,shortcut}.mjs`
