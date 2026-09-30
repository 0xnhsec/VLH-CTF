# JWT / WeakHMAC — HashHouse

Bug: every token is HS256-signed with a **weak, human-chosen secret** (see
`/changelog`: "the intern picked the secret on a Friday"). Verification is
otherwise correct — the secret is the flaw.

Why exploitable: HMAC-SHA256 over a known header+payload falls instantly to an
offline dictionary attack (`hashcat -m 16500 token.txt wordlist` or a small
cracking script); short wordlist-y secrets crack in seconds.

Intended path:
1. `POST /login {"username":"0xnhsec","password":"vlh-tester-01"}` → grab a token.
2. Crack the secret offline (wordlist attack against the HS256 signature).
3. `GET /api/directory` → find the innocent account (`usr_…`, role `innocent`).
4. Forge `{"sub":"usr_…","role":"admin"}` signed HS256 with the cracked secret.
5. `GET /flag/jwt` with `Authorization: Bearer <forged>` →
   `DSLTV{JWT-WeakHMAC-<n>}` (server verifies the signature, then the claim pair).

Flag format: `DSLTV{JWT-WeakHMAC-<digits>}` — regenerated at every boot.
