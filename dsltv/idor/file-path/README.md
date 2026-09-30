# IDOR — FilePath · Docvault (difficulty: medium)

Docvault serves documents by **file path**: `GET /files?path=notes/<name>.txt`. The handler requires a login and blocks traversal (resolved paths must stay inside the vault — `..` and absolute paths get a 400), but it **never maps the requested file to the requesting user's ownership**: the file path is the only reference, and the workspace `/catalog` openly lists every document's path, owner included. The innocent's seeded private file contains the flag. (Reference type is what separates this subclass from `NumericId` and from a traversal bug.)

Intended path:
1. Log in at http://victim.target.lab:8119/ as `0xnhsec` / `vlh-tester-01` — the dashboard lists *your* documents (plus the shared welcome note).
2. Open the workspace catalog at http://victim.target.lab:8119/catalog — it lists every document's path, including the innocent's `notes/usr_xxxxxxxx-private.txt`.
3. Fetch it by path — no ownership check: `curl -si -b "sid=<sid>" "http://victim.target.lab:8119/files?path=notes/usr_xxxxxxxx-private.txt"` (replace the username from the catalog).
4. The innocent's private file body contains the flag. (Trying `path=../../../../etc/passwd` correctly returns 400 — that is a different bug class.)

Flag: `DSLTV{IDOR-FilePath-<9-10 digits>}` (resource-resident — regenerated every restart).
