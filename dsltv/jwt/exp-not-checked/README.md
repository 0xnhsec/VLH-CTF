# JWT / ExpNotChecked — ChronoAuth (state variant)

Bug: the verifier **ignores `exp`** (`ignoreExpiration: true`) and logout
(`POST /logout`) only clears the client cookie — stateless JWTs are never
revoked. Expired tokens therefore never die.

Why exploitable: the security audit log at `GET /leaked-tokens` retained the
innocent user's token from a logout 30 days ago. It was minted by the legacy
**migration script**, which issued `role=admin` (legacy claim mapping), and it
expired long ago — but replay still "verifies".

Intended path:
1. `GET /leaked-tokens` → copy the retained token from the audit log row.
2. `GET /flag/jwt` with `Authorization: Bearer <leaked-token>` →
   `DSLTV{JWT-ExpNotChecked-<n>}` (server verifies the signature, ignores exp,
   then checks the claim pair AND that `iat` pre-dates the migration — a
   genuine replay of the pre-migration token).

A login as `0xnhsec` / `vlh-tester-01` shows the normal token flow; the gate
needs the innocent identity with the pre-migration admin claim.

Flag format: `DSLTV{JWT-ExpNotChecked-<digits>}` — regenerated at every boot.
