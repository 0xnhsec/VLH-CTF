# JWT / JwkInjection — SelfKey

Bug: the verifier honors an **embedded `jwk` header claim** — if the token
header carries its own public key, verification uses *that* key instead of the
platform key set ("self-describing tokens" feature = key control flaw).

Why exploitable: the token supplies both the claims and the key that
"validates" them — sign with your own private key and verify against your own
public JWK.

Intended path:
1. `POST /login {"username":"0xnhsec","password":"vlh-tester-01"}` → RS256 token.
2. Generate your own RSA keypair; export the public key as a JWK
   (`kty`, `n`, `e`).
3. `GET /api/directory` → find the innocent account (`usr_…`, role `innocent`).
4. Forge header `{"alg":"RS256","typ":"JWT","kid":"atk","jwk":{…yours…}}` and
   payload `{"sub":"usr_…","role":"admin"}`, signed with **your private key**.
5. `GET /flag/jwt` with `Authorization: Bearer <forged>` →
   `DSLTV{JWT-JwkInjection-<n>}` (server verifies against the embedded JWK,
   then checks the claim pair).

Flag format: `DSLTV{JWT-JwkInjection-<digits>}` — regenerated at every boot.
