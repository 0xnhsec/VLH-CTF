# BAC / VerticalEsc — Ctrl Center

Bug: `GET /admin/panel` checks only that the caller is **logged in** — the role
(vertical authorization level) is never validated. Classic missing
function-level authorization → vertical privilege escalation.

Why exploitable: the portal seeds `tester`-role operator accounts, but the ops
console was written assuming "authenticated == staff".

Intended path:
1. Sign in at `/` as `0xnhsec` / `vlh-tester-01` (or `Noshiro` / `vlh-tester-02`).
2. Open `/admin/panel` — the console renders for any authenticated session.
3. The staff bulletin inside the panel holds `DSLTV{BAC-VerticalEsc-<n>}`.

Flag format: `DSLTV{BAC-VerticalEsc-<digits>}` — regenerated at every boot.
