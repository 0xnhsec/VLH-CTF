# IDOR — WriteDelete · Scrappad (difficulty: medium)

Scrappad pads live at `/api/notes/{id}`. The **read** path enforces ownership (`GET /api/notes/{id}` answers `403 not your note` for other users' pads — SEC-40 claims reads are owner-only), but the **write** paths were mounted without the ownership middleware: `PATCH /api/notes/{id}` and `DELETE /api/notes/{id}` operate on any note. PATCH returns the updated object **including the untouched body** — so patching the innocent's note (title only!) echoes the note's secret body, which holds the flag. Missing authorization on the read path is a leak; missing it on the write path is a leak *and* a destructive primitive.

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01` — your pads are ids 1–2.
2. Prove reads are guarded: `curl -si -b "sid=<sid>" http://victim.target.lab:8119/api/notes/5` → 403 (exists, not yours).
3. Switch to the unguarded verb — patch the title only: `curl -si -b "sid=<sid>" -X PATCH -H 'Content-Type: application/json' -d '{"title":"mine now"}' http://victim.target.lab:8119/api/notes/5`
4. The 200 response echoes the full note — the innocent's original `body` is the flag. (You can also `DELETE` anyone's pad: same missing check, no body needed.)

Flag: `DSLTV{IDOR-WriteDelete-<9-10 digits>}` (resource-resident — regenerated every restart).
