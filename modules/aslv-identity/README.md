# ASLV M5 — `aslv-identity` (JWT / AUTH / OAUTH identity plane)

Node/Express **custom Authorization Server + demo client app** (one process,
Host-dispatched vhosts). Port **3000** in the container, published as **18026**
in standalone mode. THREE identity-gated flags with §7.5 win-state separation.

```
src/server.js    AS surfaces: login/MFA/forgot/reset/register/directory, flag
                 endpoints, victim bot, __sso, mail transport (SMTP + HTTP)
src/db.js        schema, seed, boot RS256 keypair, shared helpers
src/jwt.js       /jwt/issue (real issuer), /jwks.json, DELIBERATELY VULNERABLE verify
src/oauth.js     /oauth/* AS endpoints + client.aslv.lab client app
src/flags.js     identity-gated flag generation + registry
src/activity.js  activity middleware → sqlite + ACTIVITY_SINK + /internal/activity
```

## Endpoint map (binding for solvers/chains)

### `auth.aslv.lab` (default vhost)

| Method + path | Behavior |
|---|---|
| `GET /healthz` | liveness |
| `GET /` | home (login form; register/reset/directory links) |
| `POST /login` `{username,password}` | generic error on failure. If the account has MFA → creates a **pending** session + `{"mfa_required":true}`; else full session (`auth_method:"password"`). Testers: `0xnhsec`/`vlh-tester-01`, `Noshiro`/`vlh-tester-02`. |
| `POST /mfa/verify` `{code, user}` | **FLAW**: validates `code` against the **body `user`**'s MFA secret (not the session's user), then promotes the **session's own user** to fully authenticated. Verify your own code → hijack a pending innocent session (obtainable via the victim bot's `mfa_pending` option). |
| `POST /register` `{username,password}` | open registration; new accounts are MFA-enabled (6-digit code returned once + visible on `/me`). |
| `GET /directory` | **legitimate leak point**: `[{username, uuid, email, role}]` — how players learn the innocent uuid/username. |
| `GET /me` | own account incl. `uuid`, `api_key`, `mfa_code`, `auth_method`, linked identities. |
| `POST /logout` | destroys session |
| `POST /forgot` `{username}` | generic response (no enumeration). Creates a **predictable reset token**: `hex(md5(username + ":" + <UTC YYYYMMDD>))[0:12] + "-" + NN` where `NN` = per-user per-day issuance counter (2 digits). Mails a reset link; the link host honors **`X-Forwarded-Host`** (M1 host-poison feeder). Mail target: the **portal's** recovery view first (`GET {PORTAL_INTERNAL_URL}/_internal/user/{username}` → `recovery_email || email`, the chain-B cross-module hop), else the local user's `recovery_email || email`. |
| `POST /reset` `{token, new_password}` | valid unused token (< 24 h) → local account: password updated + **session created with `auth_method:"reset"`** (Set-Cookie). Portal-only username → delegated response (no local session). |
| `POST /jwt/issue` `{username,password}` | real RS256 issuer: `{sub: user.uuid, role, tenant, iat}` (1 h). Never mints `sub=innocent & role=admin`. |
| `GET /jwks.json` | boot RSA public key (`kid`, `n`, `e`) — consumed by M3/M4 (signature-only validation edge). Regenerated per boot. |
| `GET /whoami` | Bearer → result of the vulnerable verify (`{verified, via, claims}`). |
| `GET /flag/auth` | **AUTH flag**: session user == innocent AND `auth_method == "reset"` (provenance gate — NOT mere login). |
| `GET /flag/jwt` | **JWT flag**: Bearer verified by the vulnerable verifier AND claims `sub == innocent.uuid` AND `role == "admin"`. Verifier accepts, in order: `alg=none`; `header.jwk` (embedded key — jwk injection); `header.jku` (attacker URL fetched — jku); `header.kid` (**SQL string concat** into the keys table — a `UNION SELECT` can return an attacker-chosen key row; table cols `kid,kty,n,e,public_pem,private_pem,created_at`); default issuer key. |
| `GET /flag/oauth` | **OAUTH flag**: any authenticated session + a `linked_identities` row linking the innocent client identity to a **foreign** oauth_sub. |
| `GET /__sso` | innocent logged in at AS (`sid`) AND client (`csid`) — victim-bot feeder. |
| `POST /victim` | victim bot (solo play): `{url, sso, cookies, origin, referer, method, body, mfa_pending}`. `*.aslv.lab` URLs are rewritten to `127.0.0.1:3000` with the Host header preserved; redirects followed with a cookie jar. `mfa_pending: true` returns a pending innocent `sid` (models the leaked MFA-prompt session). |
| `GET /internal/activity` | NDJSON activity rows (latest first, cap 5000). |
| `GET /oauth/authorize` | requires full AS session. Params `client_id` (must be `web`), `redirect_uri` (**substring check `includes('client.aslv.lab')`** → bypass `https://attacker.aslv.lab/client.aslv.lab/callback`), `response_type=code|token`, `state` (echoed), `scope` (any string accepted — scope creep). `code` → 302 `?code&state`; `token` → 302 `#access_token…` (implicit). |
| `POST /oauth/token` | `grant_type=authorization_code` + `{code}` → `{access_token,…}`. **redirect_uri NOT re-validated, no PKCE.** |
| `GET /oauth/userinfo` | Bearer access token → `{sub, username, email, role, scope}`. |

### `client.aslv.lab` (demo client app "web")

| Method + path | Behavior |
|---|---|
| `GET /client` (or `/`) | landing page |
| `GET /client/login` | 302 → `/oauth/authorize?…&state=<random>` — state generated… |
| `GET /client/callback?code&state` | **state NEVER validated** (login-CSRF). Exchanges the code server-side; if a client session (`csid`) exists whose user differs from the code's AS identity → **`linked_identities` row + session switched**; else creates a client session. |
| `GET /client/me` | client-session identity + linked identities |
| `GET /client/implicit` | implicit-grant landing page whose JS posts `#access_token` to the finish endpoint (real browser flow; solo: victim bot finalUrl keeps the fragment, or POST manually) |
| `POST /client/implicit/finish` `{access_token}` | buggy client: token → client session for its sub |

## Intended paths (standalone, see `qa/solvers/aslv/m5/solver.mjs`)

- **AUTH**: register your own account → observe your own reset token in
  stub-mail (`mail.aslv.lab:18026`) → derive the pattern
  `md5(username:YYYYMMDD)[0:12]-NN` → `GET /directory` → trigger `/forgot` for
  the innocent → compute their token (counter starts at 01 each UTC day) →
  `POST /reset` (session comes back with `auth_method:"reset"`) →
  `GET /flag/auth`.
- **JWT**: generate your own RSA keypair → forge `alg:RS256` with
  `header.jwk = {kty,n,e}` and claims `{sub: <innocent uuid>, role: "admin"}`
  (innocent uuid from `/directory`) → `GET /flag/jwt`. (`alg=none` and `jku`
  also work — the verifier is deliberately loose; the gate is the claim combo.)
- **OAUTH**: log in at the AS as yourself → `GET /oauth/authorize` (code
  grant) → take the `code` from the 302 Location (do NOT exchange it) →
  `POST /victim` with `{"url":"http://client.aslv.lab:18026/client/callback?code=…&state=evil","sso":true}`
  → the innocent (logged in at the client by the bot) processes YOUR code →
  linking row → `GET /flag/oauth`.

Shortcut guards: all `/flag/*` endpoints reject unauthenticated callers and
wrong-state callers (401/403, never a flag) — see `qa/solvers/aslv/m5/shortcut.mjs`.

## Mail transport + trust edges

- `SMTP_HOST` set (full mode → `mailhog:1025`): raw-socket SMTP client
  (HELO/MAIL/RCPT/DATA/QUIT).
- else `MAIL_HTTP_URL` (standalone default `http://stub-mail:3000`):
  `POST /internal/mail`.
- If both fail → console log (tokens remain computable — the AUTH bug is the
  predictable pattern, not the mailbox).
- `PORTAL_INTERNAL_URL` (full mode → the M2 portal): recovery-address lookup
  hop for `/forgot` (chain B). Also the fallback for portal-only usernames.
- JWKS consumers: M3/M4 fetch `http://identity:3000/jwks.json` (full mode) —
  set their `JWKS_URL` env accordingly (service name is the compose owner's call).
- `X-Forwarded-Host` is honored when building reset links (M1 edge).

## Seeding

Testers (MFA-enabled, codes on own `/me`), innocent `usr_<hex>` (random
password + 32-hex api_key + uuid + MFA), `admin` (random password, no MFA).
RS256 keypair regenerated every boot. Grading dump at `/data/seed.json`
(container-internal). **Org-wide seed override** (full mode):
`INNOCENT_USERNAME/PASSWORD/API_KEY/UUID` — same convention as M2/M3/M4.

## Standalone mode (profile `m5`, port 18026)

Services: `m5-app` (this image), `m5-sidecar` (nginx:alpine, binds 18026:80,
template `sidecar/nginx.conf.template`), `stub-mail` + `stub-portal`
(aslv-core stubs), one M0 collector (mgmt port 18095). Sidecar vhosts:

| Host | Upstream |
|---|---|
| default (`localhost:18026`), `auth.aslv.lab`, `client.aslv.lab` | `APP_HOST:3000` |
| `mail.aslv.lab` | `MAIL_HOST:3000` |
| `portal.aslv.lab`, `www.portal.aslv.lab` | `PORTAL_HOST:3000` |

Sidecar env: `APP_HOST`, `MAIL_HOST`, `PORTAL_HOST`.
App env to set: `MAIL_HTTP_URL=http://stub-mail:3000`,
`PORTAL_INTERNAL_URL=http://stub-portal:3000`,
`AUTH_ORIGIN=http://auth.aslv.lab:18026` (used for cross-vhost redirects).

## Full mode (gateway :18024)

`auth.aslv.lab` → m5 entirely; `mail.aslv.lab` → MailHog; portal = M2. Set
`SMTP_HOST=mailhog:1025`, `PORTAL_INTERNAL_URL=http://portal:3000` (M2),
`AUTH_ORIGIN=http://auth.aslv.lab:18024`, `CLIENT_REDIRECT_URI` to taste.

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `3000` | listen port |
| `DATA_DIR` / `REGISTRY_DIR` | `/data` / `/registry` | identity.db / flags.ndjson (fallback `DATA_DIR/registry-fallback.ndjson`) |
| `LAB_DOMAIN` | `aslv.lab` | emails |
| `SMTP_HOST` | *(empty)* | `host[:port]` raw-socket SMTP (full mode) |
| `MAIL_HTTP_URL` | `http://stub-mail:3000` | stub-mail HTTP transport (standalone) |
| `PORTAL_INTERNAL_URL` | *(empty)* | M2 portal (full mode) / stub-portal (standalone) for the forgot hop |
| `AUTH_ORIGIN` | `http://auth.aslv.lab:18026` | absolute origin used in client → AS redirects |
| `CLIENT_REDIRECT_URI` | `http://client.aslv.lab/client/callback` | registered client redirect (the substring check targets this string) |
| `ACTIVITY_SINK` | *(empty)* | collector `/ingest` URL |
| `INNOCENT_USERNAME/PASSWORD/API_KEY/UUID` | *(random)* | org-wide seed override (full mode) |

*Deviation note:* the task sketch used `https://client.aslv.lab/client/callback`
— the lab serves plain HTTP only, so the default redirect uses `http://`
(override via `CLIENT_REDIRECT_URI`). The flawed substring check is unchanged.
