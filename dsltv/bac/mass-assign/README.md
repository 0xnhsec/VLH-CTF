# BAC / MassAssign — SignupDirect

Bug: `POST /register` binds the entire request body onto the new user row —
mass assignment. The `role` column is client-controlled, so you can register
straight in as an administrator.

Why exploitable: the registration UI never shows a role field, but the API
never stopped binding it; `/admin/panel` is properly role-checked, so the only
way in is a genuinely elevated row.

Intended path:
1. `POST /register` with body `{"username":"evil","password":"evil123","role":"admin"}`
   (auto-signs you in; or register via the form then sign in).
2. `GET /admin/panel` — the audit key holds `DSLTV{BAC-MassAssign-<n>}`.

Flag format: `DSLTV{BAC-MassAssign-<digits>}` — regenerated at every boot.
