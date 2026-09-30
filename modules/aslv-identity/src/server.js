'use strict';
/*
 * VLH-CTF — ASLV M5 aslv-identity: the identity plane (auth.aslv.lab).
 *
 * THREE identity-gated flags with §7.5 win-state separation:
 *   AUTH  (predictable reset tokens + provenance gate)   → GET /flag/auth
 *   JWT   (forged impossible claim combo)                → GET /flag/jwt
 *   OAUTH (login-CSRF identity linking)                  → GET /flag/oauth
 *
 * Also carries: MFA verify flaw (validate the BODY user's code, promote the
 * SESSION user — session hijack), org directory (legitimate leak point for
 * the innocent identity), the JWKS consumed by M3/M4, a victim bot for solo
 * play, and the X-Forwarded-Host honored when building reset links (the M1
 * host-poison feeder edge).
 */
const express = require('express');
const net = require('net');
const crypto = require('crypto');
const http = require('http');

const {
  db, randHex, randDigits, nowIso, sha256, esc, render, usersApi, INNOCENT, LAB_DOMAIN,
} = require('./db');
const flags = require('./flags');
const { issueToken, jwksJSON, vulnerableVerify } = require('./jwt');
const oauth = require('./oauth');
const activity = require('./activity');

const PORT = parseInt(process.env.PORT || '3000', 10);
const SMTP_HOST = process.env.SMTP_HOST || '';           // full mode: mailhog:1025
const MAIL_HTTP_URL = (process.env.MAIL_HTTP_URL || '').replace(/\/+$/, ''); // standalone: http://stub-mail:3000
const PORTAL_INTERNAL_URL = (process.env.PORTAL_INTERNAL_URL || '').replace(/\/+$/, '');

/* ----------------------------------------------------------- mail transport */

function smtpSend(to, subject, body) {
  return new Promise((resolve) => {
    const [host, portStr] = SMTP_HOST.split(':');
    const port = parseInt(portStr || '1025', 10);
    const sock = net.connect(port, host);
    let stage = 0;
    let buf = '';
    const from = 'no-reply@aslv.lab';
    const msg = [`From: ${from}`, `To: ${to}`, `Subject: ${subject}`, '', body, ''].join('\r\n');
    const steps = [
      `HELO identity\r\n`,
      `MAIL FROM:<${from}>\r\n`,
      `RCPT TO:<${to}>\r\n`,
      `DATA\r\n`,
      `${msg.replace(/^\./gm, '..')}\r\n.\r\n`,
      `QUIT\r\n`,
    ];
    sock.setTimeout(5000, () => { sock.destroy(); resolve(false); });
    sock.on('error', () => resolve(false));
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      // advance one command per reply line batch
      if (stage === 4) { // DATA accepted -> send body
        sock.write(steps[4]);
        stage = 5;
        return;
      }
      if (buf.includes('221')) { sock.end(); resolve(true); return; }
      if (stage < steps.length) {
        sock.write(steps[stage]);
        stage += 1;
        buf = '';
      }
    });
    sock.on('connect', () => { buf = ''; });
  });
}

async function sendMail({ to, subject, body }) {
  try {
    if (SMTP_HOST) {
      const ok = await smtpSend(to, subject, body);
      if (ok) return 'smtp';
    }
    if (MAIL_HTTP_URL) {
      const resp = await fetch(`${MAIL_HTTP_URL}/internal/mail`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ to, subject, body }),
      });
      if (resp.ok) return 'http';
    }
  } catch (_) { /* best effort */ }
  console.log(`[identity] mail delivery fell back to console (to=${to} subject=${subject})`);
  return 'console';
}

/* ------------------------------------------------------------ reset tokens */

function daystamp() {
  return new Date().toISOString().slice(0, 10).replace(/-/g, ''); // UTC YYYYMMDD
}

// DELIBERATELY VULNERABLE (the AUTH bug): the reset token is a PREDICTABLE
// function of username + UTC day + a small per-user daily counter:
//   hex(md5(username + ":" + YYYYMMDD)).slice(0,12) + "-" + NN
function makeResetToken(username, counter) {
  const h = crypto.createHash('md5').update(`${username}:${daystamp()}`).digest('hex');
  return `${h.slice(0, 12)}-${String(counter).padStart(2, '0')}`;
}

async function portalUserLookup(username) {
  if (!PORTAL_INTERNAL_URL) return null;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 3000);
    const resp = await fetch(`${PORTAL_INTERNAL_URL}/_internal/user/${encodeURIComponent(username)}`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!resp.ok) return null;
    const j = await resp.json();
    if (!j || !j.email) return null;
    return { email: String(j.email), recovery_email: j.recovery_email ? String(j.recovery_email) : null, source: 'portal' };
  } catch (_) {
    return null;
  }
}

/* ------------------------------------------------------------------ session */

function getFullSession(req) {
  const sid = /(?:^|;\s*)sid=([^;]*)/.exec(String(req.headers.cookie || ''))?.[1];
  if (!sid) return null;
  const s = db.prepare('SELECT * FROM sessions WHERE sid = ?').get(sid);
  if (!s || s.mfa_pending) return null;
  const u = usersApi.byId(s.user_id);
  return u ? { user: u, session: s } : null;
}

function createSession(user, authMethod, mfaPending) {
  const sid = randHex(32);
  db.prepare('INSERT INTO sessions (sid, user_id, auth_method, mfa_pending, created_at) VALUES (?,?,?,?,?)')
    .run(sid, user.id, authMethod, mfaPending ? 1 : 0, nowIso());
  return sid;
}

const SID_COOKIE = (sid) => `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`;

/* ---------------------------------------------------------------------- app */

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb', strict: false }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));
app.use(activity.middleware);

/* AS + client vhost dispatch (Host header). */
const hostOf = (req) => String(req.headers.host || '').split(':')[0].toLowerCase();
app.use((req, res, next) => {
  if (hostOf(req) === 'client.aslv.lab') return oauth.clientRouter(req, res, next);
  next();
});
const asApp = express.Router();
app.use(asApp);
// NOTE: the client app is served on its own vhost (client.aslv.lab) via the
// dispatch above; unmatched client-vhost paths fall through to the AS router.

asApp.use(oauth.asRouter);
asApp.use(activity.router);

/* ---------------------------------------------------------------- home + ui */

asApp.get('/', (req, res) => {
  const auth = getFullSession(req);
  res.type('html').send(render('Sign in', `
    <h1>auth.aslv.lab — organization identity</h1>
    ${auth ? `<div class="card">Signed in as <b>${esc(auth.user.username)}</b> — <a href="/me">account</a> · <a href="/logout">logout</a></div>` : `
    <div class="card">
      <form method="POST" action="/login">
        <p><input name="username" placeholder="username" value="0xnhsec" required>
           <input name="password" type="password" placeholder="password" required>
           <button>sign in</button></p>
      </form>
      <p class="muted">No account? <a href="/register">register</a> · forgot password? <a href="/reset">reset</a> · <a href="/directory">staff directory</a></p>
    </div>`}
    <div class="card"><p class="muted">This AS also exposes: <code>/jwt/issue</code>, <code>/jwks.json</code>,
    <code>/oauth/authorize</code>, <code>/oauth/token</code>, <code>/oauth/userinfo</code>.
    The demo client app lives at <code>client.aslv.lab</code>.</p></div>`));
});

asApp.get('/healthz', (req, res) => res.json({ ok: true, service: 'aslv-identity' }));

asApp.get('/login', (req, res) => res.redirect('/'));
asApp.get('/register', (req, res) => {
  res.type('html').send(render('Register', `
    <h1>Register</h1>
    <div class="card"><form method="POST" action="/register">
      <p><input name="username" placeholder="username (a-z0-9_)" required>
         <input name="password" type="password" placeholder="password (min 6)" required>
         <button>create account</button></p>
    </form><p class="muted">Open registration — new accounts get MFA enabled by default (your code is shown once).</p></div>`));
});

asApp.get('/reset', (req, res) => {
  const token = String(req.query.token || '');
  res.type('html').send(render('Reset password', `
    <h1>Reset password</h1>
    <div class="card"><form method="POST" action="/reset">
      <p><input name="token" placeholder="reset token" value="${esc(token)}" size="40" required>
         <input name="new_password" type="password" placeholder="new password" required>
         <button>reset</button></p>
    </form><p class="muted">Tokens arrive by mail. Request one via POST /forgot {"username": "..."}.</p></div>`));
});

/* ------------------------------------------------------------------- AUTH */

asApp.post('/login', (req, res) => {
  const b = req.body || {};
  const user = usersApi.verify(b.username, b.password);
  if (!user) return res.status(401).json({ error: 'invalid username or password' });
  if (user.mfa_enabled) {
    const sid = createSession(user, 'password', true);
    res.setHeader('Set-Cookie', SID_COOKIE(sid));
    return res.json({ ok: true, mfa_required: true, note: 'POST /mfa/verify {code, user}' });
  }
  const sid = createSession(user, 'password', false);
  res.setHeader('Set-Cookie', SID_COOKIE(sid));
  res.json({ ok: true, username: user.username, role: user.role, auth_method: 'password' });
});

asApp.post('/logout', (req, res) => {
  const sid = /(?:^|;\s*)sid=([^;]*)/.exec(String(req.headers.cookie || ''))?.[1];
  if (sid) db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
  res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// DELIBERATELY VULNERABLE: the MFA code is validated against the user supplied
// in the BODY (instead of the session's user), then the SESSION (whatever user
// it belongs to) is promoted to fully authenticated. Verify your own code,
// hijack the innocent's pending session.
asApp.post('/mfa/verify', (req, res) => {
  const b = req.body || {};
  const sid = /(?:^|;\s*)sid=([^;]*)/.exec(String(req.headers.cookie || ''))?.[1];
  if (!sid) return res.status(401).json({ error: 'session required (login first)' });
  const session = db.prepare('SELECT * FROM sessions WHERE sid = ?').get(sid);
  if (!session) return res.status(401).json({ error: 'invalid session' });
  const sessionUser = usersApi.byId(session.user_id);
  const target = b.user ? usersApi.byUsername(b.user) : sessionUser;
  if (!target) return res.status(400).json({ error: 'no such user' });
  if (!target.mfa_enabled) return res.status(400).json({ error: 'that account has no MFA' });
  if (String(b.code || '') !== String(target.mfa_secret)) {
    return res.status(401).json({ error: 'invalid code' });
  }
  db.prepare('UPDATE sessions SET mfa_pending = 0 WHERE sid = ?').run(sid);
  res.json({ ok: true, username: sessionUser.username, note: `code checked against '${target.username}', session promoted` });
});

asApp.post('/register', (req, res) => {
  const b = req.body || {};
  const username = String(b.username || '').toLowerCase();
  if (!/^[a-z0-9_]{3,32}$/.test(username)) return res.status(400).json({ error: 'username must match [a-z0-9_]{3,32}' });
  if (String(b.password || '').length < 6) return res.status(400).json({ error: 'password must be at least 6 chars' });
  if (usersApi.byUsername(username)) return res.status(409).json({ error: 'username taken' });
  const mfa = randDigits(6);
  db.prepare(`INSERT INTO users (username, password, uuid, email, recovery_email, role, tenant, api_key, mfa_enabled, mfa_secret, created_at)
              VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(username, sha256(b.password), crypto.randomUUID(), `${username}@${LAB_DOMAIN}`, `${username}+recovery@${LAB_DOMAIN}`,
      'user', 't' + sha256('aslv-tenant:' + username).slice(0, 6), randHex(32), 1, mfa, nowIso());
  res.json({ ok: true, username, mfa_code: mfa, note: 'save this MFA code — it is also visible on /me' });
});

asApp.get('/directory', (req, res) => {
  // The org directory is the LEGITIMATE leak point for the innocent identity
  // (arch §4: "identity discovered via legitimate leak point, never guessed").
  const rows = db.prepare('SELECT username, uuid, email, role FROM users ORDER BY id').all();
  res.json({ users: rows, count: rows.length });
});

asApp.get('/me', (req, res) => {
  const auth = getFullSession(req);
  if (!auth) return res.status(401).json({ error: 'authentication required' });
  const u = auth.user;
  const links = db.prepare('SELECT * FROM linked_identities WHERE client_user_uuid = ? ORDER BY id DESC').all(u.uuid);
  res.json({
    username: u.username, uuid: u.uuid, email: u.email, role: u.role,
    api_key: u.api_key, mfa_code: u.mfa_secret,
    auth_method: auth.session.auth_method,
    linked_identities: links.map((l) => ({ oauth_sub: l.oauth_sub, at: l.created_at })),
  });
});

asApp.post('/forgot', async (req, res) => {
  const rawUsername = String((req.body || {}).username || '');
  // Mail systems are case-insensitive — resolve the canonical local account
  // (exact match first, then lowercase) so tokens derive from the stored name.
  const local = usersApi.byUsername(rawUsername) || usersApi.byUsername(rawUsername.toLowerCase());
  const username = local ? local.username : rawUsername.toLowerCase();
  const portal = await portalUserLookup(username);

  if (!local && !portal) {
    // Generic response — no user enumeration.
    return res.json({ ok: true, message: 'if the account exists, a reset link has been sent' });
  }

  // Mail target: local recovery email, but the PORTAL is the organization's
  // recovery source of truth (cross-module hop for the browser-led chain —
  // a CSRF'd portal recovery_email steers the reset mail).
  let to = null;
  if (portal && (portal.recovery_email || portal.email)) {
    to = portal.recovery_email || portal.email;
  } else if (local) {
    to = local.recovery_email || local.email;
  }

  const day = daystamp();
  const counter = (db.prepare('SELECT COUNT(*) c FROM reset_tokens WHERE username = ? AND day = ?').get(username, day).c || 0) + 1;
  const token = makeResetToken(username, counter);
  db.prepare('INSERT INTO reset_tokens (token, username, user_id, day, counter, used, created_at) VALUES (?,?,?,?,?,0,?)')
    .run(token, username, local ? local.id : null, day, counter, nowIso());

  // The link host honors X-Forwarded-Host (the M1 host-poison feeder edge).
  const linkHost = String(req.headers['x-forwarded-host'] || 'auth.aslv.lab').split(',')[0].trim();
  const link = `http://${linkHost}/reset?token=${token}`;
  await sendMail({
    to: to || `${username}@${LAB_DOMAIN}`,
    subject: 'Password reset',
    body: `Hello ${username},\n\nReset your password: ${link}\n\nThe link expires in 24 hours.\n`,
  });
  res.json({ ok: true, message: 'if the account exists, a reset link has been sent' });
});

asApp.post('/reset', (req, res) => {
  const b = req.body || {};
  const row = db.prepare('SELECT * FROM reset_tokens WHERE token = ? AND used = 0').get(String(b.token || ''));
  if (!row) return res.status(400).json({ error: 'invalid or used token' });
  if (Date.now() - new Date(row.created_at).getTime() > 24 * 60 * 60 * 1000) {
    return res.status(400).json({ error: 'token expired' });
  }
  db.prepare('UPDATE reset_tokens SET used = 1 WHERE token = ?').run(row.token);
  if (row.user_id) {
    const user = usersApi.byId(row.user_id);
    if (!user) return res.status(400).json({ error: 'invalid token' });
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(sha256(b.new_password || randHex(12)), user.id);
    // Session created THROUGH the reset flow — provenance recorded at creation.
    const sid = createSession(user, 'reset', false);
    res.setHeader('Set-Cookie', SID_COOKIE(sid));
    return res.json({ ok: true, username: user.username, auth_method: 'reset' });
  }
  // Portal-only account (chain B fallback hop): password update is delegated.
  return res.json({ ok: true, delegated: true, note: 'remote (portal) account — password updated at the portal' });
});

/* ------------------------------------------------------------------- JWT */

asApp.post('/jwt/issue', (req, res) => {
  const b = req.body || {};
  const user = usersApi.verify(b.username, b.password);
  if (!user) return res.status(401).json({ error: 'invalid username or password' });
  res.json({ token: issueToken(user), claims: { sub: user.uuid, role: user.role, tenant: user.tenant } });
});

asApp.get('/jwks.json', (req, res) => res.json(jwksJSON()));

asApp.get('/whoami', async (req, res) => {
  const m = /^Bearer\s+(.+)$/.exec(String(req.headers.authorization || ''));
  if (!m) return res.status(400).json({ error: 'bearer token required' });
  try {
    const v = await vulnerableVerify(m[1]);
    res.json({ verified: v.ok, via: v.via, claims: v.claims });
  } catch (e) {
    res.status(401).json({ verified: false, error: String(e.message || e) });
  }
});

/* ------------------------------------------------------- identity-gated flags */

asApp.get('/flag/auth', (req, res) => {
  const auth = getFullSession(req);
  if (!auth) return res.status(401).json({ ok: false, error: 'authentication required' });
  if (auth.user.username !== INNOCENT.username) {
    return res.status(403).json({ ok: false, error: 'identity gate: session user is not the target identity' });
  }
  if (auth.session.auth_method !== 'reset') {
    return res.status(403).json({ ok: false, error: 'provenance gate: session auth_method must be reset (not mere login)' });
  }
  flags.markMinted('AUTH');
  res.json({ ok: true, flag: flags.get('AUTH'), auth_method: 'reset' });
});

asApp.get('/flag/jwt', async (req, res) => {
  const m = /^Bearer\s+(.+)$/.exec(String(req.headers.authorization || ''));
  if (!m) return res.status(401).json({ ok: false, error: 'bearer token required' });
  let v;
  try {
    v = await vulnerableVerify(m[1]);
  } catch (e) {
    return res.status(401).json({ ok: false, error: `verification failed: ${String(e.message || e)}` });
  }
  const c = v.claims || {};
  if (c.sub !== INNOCENT.uuid || c.role !== 'admin') {
    return res.status(403).json({
      ok: false, verified: true, via: v.via,
      error: 'claim gate: requires the combo the real issuer never mints (sub == innocent uuid AND role == admin)',
    });
  }
  flags.markMinted('JWT');
  res.json({ ok: true, via: v.via, flag: flags.get('JWT') });
});

asApp.get('/flag/oauth', (req, res) => {
  const auth = getFullSession(req);
  if (!auth) return res.status(401).json({ ok: false, error: 'authentication required' });
  const row = db.prepare('SELECT id FROM linked_identities WHERE client_user_uuid = ? AND oauth_sub != ?')
    .get(INNOCENT.uuid, INNOCENT.uuid);
  if (!row) {
    return res.status(403).json({ ok: false, error: 'state gate: no foreign OAuth identity linked to the target account' });
  }
  flags.markMinted('OAUTH');
  res.json({ ok: true, flag: flags.get('OAUTH') });
});

/* ------------------------------------------------------- victim bot (solo) */

function botRequest(target, opts) {
  return new Promise((resolve, reject) => {
    const u = new URL(target);
    const req = http.request({
      host: u.hostname, port: u.port || 80, path: u.pathname + u.search,
      method: opts.method || 'GET', headers: opts.headers || {},
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => { if (chunks.length < 32) chunks.push(c); });
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        location: res.headers.location || null,
        setCookies: res.headers['set-cookie'] || [],
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

// *.aslv.lab URLs (any port) resolve to THIS app inside the container.
function labUrlToLoopback(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.hostname.endsWith('.aslv.lab')) {
      return { url: `http://127.0.0.1:${PORT}${u.pathname}${u.search}`, hostHeader: u.hostname };
    }
  } catch (_) { /* ignore */ }
  return { url: urlStr, hostHeader: null };
}

asApp.post('/victim', async (req, res) => {
  const b = req.body || {};
  if (!b.url && !b.mfa_pending) return res.status(400).json({ error: 'url required' });
  const innocent = usersApi.innocent();
  const jar = new Map();
  const out = { hops: [], finalUrl: null, status: null, excerpt: '', mfa_pending_sid: null };
  try {
    if (b.mfa_pending) {
      // Simulates an innocent device stuck at the MFA prompt whose pending
      // session identifier leaks (solo-play concession for the MFA flaw).
      out.mfa_pending_sid = createSession(innocent, 'password', true);
    }
    if (b.sso) {
      const r = await botRequest(`http://127.0.0.1:${PORT}/__sso`, { headers: { host: 'auth.aslv.lab' } });
      (r.setCookies || []).forEach((c) => { const m = /([^=]+)=([^;]*)/.exec(c); if (m) jar.set(m[1], m[2]); });
    }
    if (b.cookies) for (const [k, v] of Object.entries(b.cookies)) jar.set(k, v);
    if (!b.cookies && !b.sso && !b.mfa_pending) {
      jar.set('sid', createSession(innocent, 'password', false));
    }
    if (!b.url) return res.json(out);
    let current = String(b.url);
    for (let hop = 0; hop < 8; hop++) {
      const { url, hostHeader } = labUrlToLoopback(current);
      const headers = {};
      if (hostHeader) headers.host = hostHeader;
      if (jar.size) headers.cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
      if (b.origin) headers.origin = String(b.origin);
      if (b.referer) headers.referer = String(b.referer);
      if (b.body !== undefined && typeof b.body === 'object') headers['content-type'] = 'application/json';
      const r = await botRequest(url, {
        method: (hop === 0 && b.method) ? String(b.method).toUpperCase() : 'GET',
        headers,
        body: (hop === 0 && b.body !== undefined)
          ? (typeof b.body === 'object' ? JSON.stringify(b.body) : String(b.body)) : undefined,
      });
      (r.setCookies || []).forEach((c) => { const m = /([^=]+)=([^;]*)/.exec(c); if (m) jar.set(m[1], m[2]); });
      out.hops.push({ url: current, status: r.status, location: r.location });
      if (r.location && r.status >= 300 && r.status < 400) {
        let loc = r.location;
        if (loc.startsWith('/')) { const base = new URL(current); loc = `${base.origin}${loc}`; }
        out.finalUrl = loc; current = loc; continue;
      }
      out.status = r.status;
      out.finalUrl = current;
      out.excerpt = r.body.slice(0, 1200);
      break;
    }
    res.json(out);
  } catch (e) {
    res.status(502).json({ error: String(e), ...out });
  }
});

/* Innocent SSO: logs the innocent in at the AS AND at the client app (bot feeder). */
asApp.get('/__sso', (req, res) => {
  const innocent = usersApi.innocent();
  const sid = createSession(innocent, 'password', false);
  const csid = randHex(32);
  db.prepare('INSERT INTO client_sessions (csid, user_uuid, created_at) VALUES (?,?,?)').run(csid, innocent.uuid, nowIso());
  res.setHeader('Set-Cookie', [SID_COOKIE(sid), `csid=${csid}; Path=/; HttpOnly; SameSite=Lax`]);
  res.json({ ok: true, username: innocent.username, as: 'auth.aslv.lab', client: 'client.aslv.lab' });
});

/* -------------------------------------------------------------------- boot */

flags.bootstrap();
app.listen(PORT, () => {
  console.log(`[identity] aslv-identity listening on :${PORT} (vhosts: auth.aslv.lab default, client.aslv.lab)`);
  console.log(`[identity] mail transport: smtp=${SMTP_HOST || '-'} http=${MAIL_HTTP_URL || '-'} portal=${PORTAL_INTERNAL_URL || '-'}`);
});
