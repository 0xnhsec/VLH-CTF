# BAC / MethodBypass — Aegis Gateway

Bug: authorization is enforced **per handler, not per resource**. `GET
/admin/panel` checks the admin role; the later-added `POST /admin/panel`
handler ("mobile-app compat", v3.4) forgot the check entirely.

Why exploitable: the same console content is served on both methods — switching
the HTTP verb bypasses the guard (method-based access control bypass).

Intended path:
1. Sign in as `0xnhsec` / `vlh-tester-01`.
2. `GET /admin/panel` → 403 (the GET handler is properly protected).
3. `POST /admin/panel` (e.g. `curl -X POST` with your session cookie) → the
   master override phrase holds `DSLTV{BAC-MethodBypass-<n>}`.

Flag format: `DSLTV{BAC-MethodBypass-<digits>}` — regenerated at every boot.
