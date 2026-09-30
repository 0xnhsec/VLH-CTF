# AUTH / MfaBypass — Vaultis

Bug: the MFA code verification endpoint `POST /mfa/verify` has **no rate
limit** and the (static, per-account) code is only **4 digits** — a 10,000
attempt brute-force completes *anyone's* pending step-1 login.

Why exploitable: step 1 (password) and step 2 (code) are separate; stealing the
pending `mfa_token` plus brute-forcing the code yields a fully verified session
without ever knowing the account password.

Intended path:
1. Make the victim start their SSO login via the victim bot:
   `POST http://collector.target.lab:8119/victim` with body
   `{"url":"http://victim.target.lab:8119/__sso"}` — the response `excerpt`
   shows the innocent user's pending `mfa_token`.
2. Brute-force the 4-digit code (no rate limit):
   loop `POST /mfa/verify {"mfa_token":"<token>","code":"0000"…"9999"}` —
   success returns a `sid` cookie for the innocent account.
3. `GET /flag` with that cookie → `DSLTV{AUTH-MfaBypass-<n>}` (server checks
   the session is the innocent account AND `mfa_verified=1`).

Hint: try your own login first (step 1 mails *your* code to
`mail.target.lab`) to see the flow end-to-end.

Flag format: `DSLTV{AUTH-MfaBypass-<digits>}` — regenerated at every boot.
