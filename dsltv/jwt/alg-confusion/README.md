# JWT / AlgConfusion — KeySmith

Bug: the verifier takes the algorithm from the **token header**. Server tokens
are RS256, but a token claiming `alg: HS256` is verified as an HMAC **using the
RSA public key PEM string as the shared secret** (RS256→HS256 algorithm
confusion). The public key is, of course, public.

Why exploitable: you know the "secret" (it's the published PEM), so you can
mint perfectly "valid" HS256 tokens for any claims.

Intended path:
1. `POST /login {"username":"0xnhsec","password":"vlh-tester-01"}` → RS256 token.
2. Fetch the public key: `GET /pubkey` (PEM).
3. `GET /api/directory` → find the innocent account (`usr_…`, role `innocent`).
4. Forge `{"alg":"HS256","typ":"JWT"}` / `{"sub":"usr_…","role":"admin"}` and
   HMAC-sign it with the PEM text as the key.
5. `GET /flag/jwt` with `Authorization: Bearer <forged>` →
   `DSLTV{JWT-AlgConfusion-<n>}` (server verifies, then checks the claim pair).

Flag format: `DSLTV{JWT-AlgConfusion-<digits>}` — regenerated at every boot.
