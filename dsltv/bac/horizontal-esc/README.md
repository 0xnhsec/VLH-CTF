# BAC / HorizontalEsc — Ordery

Bug: the ownership check exists but is **misplaced** — `GET /api/orders`
(your list) filters by the session user, while `GET /api/orders/{username}/{id}`
(single-order fetch) trusts the path parameters and returns **any** account's
order. Horizontal privilege escalation (same privilege level, another victim).

Why exploitable: order ids are small sequential integers and the account
directory `GET /api/users` is a public feature of the portal.

Intended path:
1. Sign in as `0xnhsec` / `vlh-tester-01`.
2. `GET /api/users` → note the innocent account (`usr_…`, role `innocent`).
3. `GET /api/orders/usr_xxxx/3` (try small ids) → the innocent user's
   "flag box" order note holds `DSLTV{BAC-HorizontalEsc-<n>}`.

Flag format: `DSLTV{BAC-HorizontalEsc-<digits>}` — regenerated at every boot.
