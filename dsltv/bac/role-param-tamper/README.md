# BAC / RoleParamTamper — FleetOps

Bug: `POST /api/profile` mass-binds request-body fields onto the account row —
including `role`. The web form dropped the role input in v2.1 but the API never
stopped accepting it (parameter tampering → self-promotion).

Why exploitable: the dispatcher console at `/admin/panel` is properly
role-checked, so the *only* way in is a real role change on your own row.

Intended path:
1. Sign in as `0xnhsec` / `vlh-tester-01`.
2. `POST /api/profile` with body `{"email":"p@target.lab","role":"admin"}`
   (JSON, or add a `role` field to the HTML form).
3. `GET /admin/panel` — the dispatch passphrase holds
   `DSLTV{BAC-RoleParamTamper-<n>}`.

Flag format: `DSLTV{BAC-RoleParamTamper-<digits>}` — regenerated at every boot.
