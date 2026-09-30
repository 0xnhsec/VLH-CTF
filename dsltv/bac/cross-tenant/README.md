# BAC / CrossTenant — Tenantly

Bug: `GET /tenant/dashboard` resolves the tenant from the client-supplied
**`X-Tenant-Id` header** and renders that tenant's board with **no membership
check** — tenant isolation exists only in the client UI (cross-tenant BAC).

Why exploitable: the tenant directory `GET /api/tenants` is a public feature
and lists every tenant id together with its member usernames — including the
innocent user's private workspace.

Intended path:
1. Sign in as `0xnhsec` / `vlh-tester-01` (member of the `tn-acme` workspace).
2. `GET /api/tenants` → note the tenant whose only member is the innocent
   account `usr_…` (role `innocent`).
3. `GET /tenant/dashboard` with header `X-Tenant-Id: tn-xxxx` → the private
   workspace board holds `DSLTV{BAC-CrossTenant-<n>}`.

Flag format: `DSLTV{BAC-CrossTenant-<digits>}` — regenerated at every boot
(the tenant id also rotates per boot).
