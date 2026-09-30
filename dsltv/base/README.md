# DSLTV base runtime — subclass author guide

Shared runtime for **every** DSLTV subclass. A subclass = ONE file (`vuln.js`) + a tiny Dockerfile. The base provides boot, seeding, flags, vhosts, exploit server, collector/verifier, mail, activity log.

## Folder contract

```
dsltv/<category>/<slug>/
├── Dockerfile   # FROM vlh-dsltv-base:1.0.0; COPY vuln.js /app/vuln.js (+ optional seed.js)
└── vuln.js      # module.exports = { meta, setup(ctx) }
```

Dockerfile template (copy exactly, adjust slug label):

```dockerfile
FROM vlh-dsltv-base:1.0.0
LABEL 811911.vlh=1 dsltv.category=jwt dsltv.slug=none-alg
COPY vuln.js /app/vuln.js
```

HTTP-smuggling subclasses additionally set `ENV LISTEN_PORT=8081` and start their raw-TCP front on 8080 inside setup().

## vuln.js shape

```js
'use strict';
module.exports = {
  meta: {
    category: 'JWT',            // UPPER: CORS|CSRF|IDOR|BAC|JWT|OAUTH|AUTH|HTTP|API
    subName: 'NoneAlg',         // PascalCase — appears in the flag: DSLTV{JWT-NoneAlg-<n>}
    archetype: 'identity-gated',// resource-resident|identity-gated|event-verified|location-locked|stage-gated
    eventKind: undefined,       // 'cors'|'csrf' only for event-verified
    difficulty: 'low',          // low|medium|high|critical
    description: 'one-line description',
    flags: [{ category: 'JWT', subName: 'NoneAlg', archetype: 'identity-gated' }],
    // omit `flags` to auto-use {category, subName, archetype, eventKind}
  },
  async setup(ctx) { /* mount routes on ctx.app (victim vhost) */ },
};
```

## ctx API (exact)

- `ctx.app` — express Router for the **victim** vhost (`victim.target.lab`). Mount ALL player-facing UI + vulnerable endpoints here.
- `ctx.attacker`, `ctx.collector`, `ctx.mail` — routers for those vhosts (usually don't touch; base already provides exploit server, /collect + /verify dual-check, mail UI).
- `ctx.db` — better-sqlite3 handle (tables: users, sessions, flags, activity, exfil_hits, mailbox, attacker_pages, kv). Create extra tables in setup() with `ctx.db.exec(...)`.
- `ctx.users` — `{ byUsername(u), byId(id), all(), innocent(), admin(), verify(u,p) }`. Innocent: username `usr_<hex>`, random password, `role='innocent'`, `api_key` = session-bound secret (visible on victim's `/me` page — that is the CORS exfil target).
- `ctx.flags` —
  - `held(category, subName)` → the boot-generated flag string (for identity-gated/resource-resident/stage-gated endpoints; NEVER send to client except through the gated endpoint).
  - `mintEvent(cat, sub)` → mints the event-verified flag (only the base /verify path should call this; subclasses normally never call it).
  - `eventFlag(cat, sub)` → deterministic numeric form (grading only).
- `ctx.session` — `{ create(user, authMethod), get(req) -> {user, session}|null, destroy(req) }`. Sessions carry `auth_method` provenance (password|reset|oauth_link|token).
- `ctx.login(res, user, opts)` / `ctx.logout(req, res)` — cookie helpers. `opts.cookie` = array of extra cookie attrs, e.g. `['SameSite=None']` (SameSiteNone subclass). Default cookie: `HttpOnly; SameSite=Lax`.
- `ctx.requireAuth(req)` — alias of `ctx.session.get(req)`.
- `ctx.state` — persistent kv: `get(key)`, `set(key, value)` (JSON). Use for stage gates.
- `ctx.mail.send({to, subject, body})` → id. Mail UI at `mail.target.lab`.
- `ctx.render(title, bodyHtml, opts)` → themed HTML page (dark green lab theme). `ctx.esc(s)` HTML-escape.
- `ctx.jwt` (jsonwebtoken), `ctx.crypto`, `ctx.express`, `ctx.randHex(n)`, `ctx.randDigits(n)`, `ctx.nowIso()`.
- `ctx.urls` — `{ victim, attacker, collector, mail }` absolute URLs (port 8119).
- `ctx.labDomain` — `target.lab`.

## Rules (binding — PRD FR-17..20 + arch §7.4)

1. Flag gates validate server-side state/claims/provenance — never mere reachability, never client-side reveal.
2. Innocent/admin passwords NEVER enter player-visible scope (they live in `/data/seed.json`, container-internal only).
3. Event-verified subclasses: DO NOT touch /verify — base implements the dual-check (CORS: cross-site + api_key payload; CSRF: innocent `recovery_email` row changed from seed value). Your job: make the vulnerable change endpoint + a victim page where the innocent is logged in.
4. Zero flag strings in client HTML/JS unless returned by the gated endpoint on success.
5. Every request is auto-logged to activity (identifier, is_authenticated, data, latency) — don't build your own logger.
6. `node --check vuln.js` must pass.

## Sidecar

Compose mounts `./dsltv/base/sidecar/nginx.conf.template` into every `nginx:alpine` sidecar; it does L4 raw pass-through of `8119 → <slug>-app:8080` (env `LAB_PORT=8119`, `APP_HOST=<slug>-app`). Vhosts are routed inside the app by Host header, so origins are genuinely distinct and smuggling framing is never normalized (NFR-5).

## Vhost model (important for exploit design)

- `victim.target.lab` (also `localhost`, bare IPs) → your `ctx.app` routes.
- `attacker.target.lab` → exploit server (page store). **Any other `*.target.lab` host is ALSO routed to the attacker vhost** (catch-all — models attacker-owned subdomains / wildcard DNS). Use e.g. `http://victim-evil.target.lab:8119/pages/x.html` or `http://evilclient.target.lab:8119/...` for regex-bypass labs (WeakOriginRegex, RedirectUriBypass, SubdomainTrust).
- `collector.target.lab` → `POST /collect`, `GET /verify` (dual-check), `GET /internal/activity` (NDJSON), **`POST /victim`** (victim bot).
- `mail.target.lab` → mailbox UI + `POST /internal/mail`.

## Victim bot — `POST http://collector.target.lab:8119/victim`

Solo self-play (PRD §3). Server-side victim simulation: logs in as the innocent user, fetches a URL with their session cookie, follows redirects with a cookie jar.

```json
{ "url": "http://victim.target.lab:8119/api/secret",
  "origin": "http://attacker.target.lab:8119",
  "referer": "http://attacker.target.lab:8119/pages/exploit.html",
  "method": "POST", "body": {"recovery_email": "attacker@evil.example"},
  "sso": false, "cookies": {"sid": "fixated-sid-optional"} }
```

- `origin` set → the fetched response is piped to the exfil verifier with cross-site context (models the SOP-permitted read a vulnerable ACAO would grant).
- `sso: true` → bot first visits `GET /__sso` on the victim vhost (subclass-provided route that establishes an innocent *client-app* session — OAuth labs).
- `cookies` → session fixation labs.
- Response: `{hops: [{url, status, location}], finalUrl, status, excerpt}` — redirect `Location` headers incl. fragments are visible (implicit-grant token capture).

## Attacker hit log — `GET http://attacker.target.lab:8119/leaks`

Every request any attacker-space host received, with Referer/Origin — use for RefererCodeLeak-style labs (bot with `referer` set, or direct asset hits).
