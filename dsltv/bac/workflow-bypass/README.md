# BAC / WorkflowBypass — Shopflow

Bug: ordering the limited **flag box** requires the checkout workflow state
`address_verified` on `POST /checkout` — a state only staff can grant
(`POST /verify-address` merely submits for review; no staff endpoint exists).
The later "quick-buy" endpoint `POST /checkout/confirm` (create + confirm in
one step) skips the state check entirely.

Why exploitable: the workflow gate and the fast path validate different things —
the confirm route trusts that the client already passed the gate (workflow /
state-machine bypass).

Intended path:
1. Sign in as `0xnhsec` / `vlh-tester-01`.
2. `POST /checkout {"sku":"flag-box"}` → 403 `address not verified` (and
   `POST /verify-address` only yields `pending_review`).
3. `POST /checkout/confirm {"sku":"flag-box"}` → confirmed order whose
   `details` field holds `DSLTV{BAC-WorkflowBypass-<n>}`.

Flag format: `DSLTV{BAC-WorkflowBypass-<digits>}` — regenerated at every boot.
