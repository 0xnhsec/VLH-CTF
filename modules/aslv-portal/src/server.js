'use strict';
/*
 * VLH-CTF — ASLV M2 portal (Express, deliberately minimal — NO CSRF
 * middleware, NO cors middleware: the bug surfaces are the point).
 *
 * One listener (:3000) dispatches by Host header, mirroring the
 * dsltv/base/runtime.js pattern:
 *
 *   victim.aslv.lab    login/account/api surface (the "browser app" origin)
 *   portal.aslv.lab / www.aslv.lab / aslv.lab / localhost / unknown
 *                      same account surface + portal home
 *   collector.aslv.lab verifier: /verify, /collect, /exfil, /victim,
 *                      /internal/activity, /ingest
 *   attacker.aslv.lab  exploit-page server (PUT/POST /pages/:name)
 *   mail.aslv.lab      mini mailbox (fallback when stub-mail-2 is not wired)
 *
 * Flags (event-verified, arch §7.0 M2):
 *   ASLV{CORS-...}  GET /api/secret reflects the request Origin in ACAO with
 *                   credentials — a cross-site read of the innocent session
 *                   exfiltrates her api_key to the collector, whose dual check
 *                   (attacker origin + secret match) mints the flag.
 *   ASLV{CSRF-...}  POST /account/recovery-email has no CSRF token and no
 *                   origin check — a cross-site POST with the innocent's
 *                   session changes her row; the verifier checks the innocent
 *                   row's state and mints the flag.
 */
const express = require('express');
const http = require('http');

const { initDb } = require('./db');
const { initFlags } = require('./flags');
const { makeActivity } = require('./activity');

/* ------------------------------------------------------------------- env */
const LISTEN_PORT = parseInt(process.env.LISTEN_PORT || '3000', 10);
const LAB_DOMAIN = process.env.LAB_DOMAIN || 'aslv.lab';
const DATA_DIR = process.env.DATA_DIR || '/data';
const REGISTRY_DIR = process.env.REGISTRY_DIR || '/registry';
const STANDALONE = process.env.STANDALONE === '1';
const PORTAL_PORT = process.env.PORTAL_PORT || (STANDALONE ? '18022' : '18024');
const ACTIVITY_SINK = process.env.ACTIVITY_SINK || '';

/* ------------------------------------------------------------- bootstrap */
const { db, SEED, sessionApi, usersApi, parseCookies } = initDb({ dataDir: DATA_DIR, labDomain: LAB_DOMAIN });
const flags = initFlags({ db, SEED, registryDir: REGISTRY_DIR, dataDir: DATA_DIR });
flags.bootUnminted(['CORS', 'CSRF']);

const nowIso = () => new Date().toISOString();
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

/* ----------------------------------------------------------- html layout */
const LAYOUT_CSS = `
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: ui-monospace, 'JetBrains Mono', Menlo, Consolas, monospace;
         background:#0a0f0a; color:#c7f0c7; margin:0; padding:0 0 4rem; }
  a { color:#4ade80; }
  .wrap { max-width: 880px; margin: 0 auto; padding: 1.25rem; }
  header { border-bottom:1px solid #1c3a1c; padding:.9rem 1.25rem; background:#0d140d;
           display:flex; gap:1rem; align-items:center; flex-wrap:wrap; }
  header .brand { color:#4ade80; font-weight:700; letter-spacing:.08em; }
  header nav a { margin-right:.9rem; text-decoration:none; color:#86efac; font-size:.85rem; }
  h1 { color:#4ade80; font-size:1.25rem; }
  .card { border:1px solid #1c3a1c; background:#0d140d; border-radius:6px; padding:1rem; margin:.75rem 0; }
  table { border-collapse:collapse; width:100%; font-size:.85rem; }
  th,td { border:1px solid #1c3a1c; padding:.4rem .55rem; text-align:left; vertical-align:top; }
  th { color:#4ade80; }
  input,textarea,button { font:inherit; background:#0f1a0f; color:#c7f0c7;
        border:1px solid #2a5a2a; border-radius:4px; padding:.45rem .6rem; }
  button { cursor:pointer; border-color:#4ade80; color:#4ade80; }
  .muted { color:#5c8a5c; font-size:.8rem; }
  code { background:#0f1a0f; padding:.1rem .3rem; border-radius:3px; }
`;

function render(title, bodyHtml, opts) {
  opts = opts || {};
  const p = `:${PORTAL_PORT}`;
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — ASLV M2 portal</title>
<style>${LAYOUT_CSS}</style>
</head><body>
<header>
  <span class="brand">ASLV M2 · portal</span>
  <nav>
    <a href="http://victim.${esc(LAB_DOMAIN)}${p}/">victim</a>
    <a href="http://attacker.${esc(LAB_DOMAIN)}${p}/">exploit server</a>
    <a href="http://collector.${esc(LAB_DOMAIN)}${p}/verify">verifier</a>
    <a href="http://mail.${esc(LAB_DOMAIN)}${p}/">mail</a>
  </nav>
  <span class="muted">${esc(opts.tagline || 'CORS + CSRF lab — VLH-CTF')}</span>
</header>
<main class="wrap">${bodyHtml}</main>
</body></html>`;
}

/* ------------------------------------------------------------- app setup */
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb', strict: false }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));
app.use(express.text({ limit: '256kb', type: ['text/plain', 'text/html'] }));
app.use((req, res, next) => { // raw body capture + cookie parse + session peek
  req.rawBody = '';
  const chunks = [];
  req.on('data', (c) => { if (chunks.length < 64) chunks.push(c); });
  req.on('end', () => { req.rawBody = Buffer.concat(chunks).toString('utf8'); });
  req.cookies = parseCookies(req.headers.cookie);
  req.auth = sessionApi.get(req);
  next();
});

const activity = makeActivity({ db, dataDir: DATA_DIR, sinkUrl: ACTIVITY_SINK, unit: 'm2' });
app.use(activity.middleware);

/* Activity feed on the main listener (all vhosts) — shared convention. */
app.get('/internal/activity', activity.handler);

/* ------------------------------------------------------- vhost dispatch */
const vhostOf = (req) => {
  const host = String(req.headers.host || '').split(':')[0].toLowerCase();
  if (host === `attacker.${LAB_DOMAIN}`) return 'attacker';
  if (host === `collector.${LAB_DOMAIN}`) return 'collector';
  if (host === `mail.${LAB_DOMAIN}`) return 'mail';
  if (host === `victim.${LAB_DOMAIN}`) return 'victim';
  return 'portal'; // portal.aslv.lab / www / apex / localhost / unknown
};

const portalRouter = express.Router();
const victimRouter = express.Router();
const attackerRouter = express.Router();
const collectorRouter = express.Router();
const mailRouter = express.Router();

app.use((req, res, next) => {
  switch (vhostOf(req)) {
    case 'attacker': attackerRouter(req, res, next); break;
    case 'collector': collectorRouter(req, res, next); break;
    case 'mail': mailRouter(req, res, next); break;
    case 'victim': victimRouter(req, res, next); break;
    default: portalRouter(req, res, next);
  }
});

/* ------------------------------------------- shared account surface ---- */
/* Mounted on BOTH the victim and portal vhosts: the same app, two origins.
 * Session cookie: sid, HttpOnly, SameSite=Lax. NO CSRF tokens anywhere. */

const accountRouter = express.Router();

const loginCookie = (res, user) => {
  const sid = sessionApi.create(user, 'password');
  res.setHeader('Set-Cookie', `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
  return sid;
};

const wantsJson = (req) =>
  (req.headers.accept || '').includes('application/json')
  || (req.headers['content-type'] || '').includes('application/json');

accountRouter.get('/healthz', (req, res) => res.json({ ok: true, module: 'aslv-portal' }));

accountRouter.get('/login', (req, res) => {
  res.type('html').send(render('Login', `
    <h1>Sign in</h1>
    <form method="post" action="/login">
      <p><input name="username" placeholder="username" required></p>
      <p><input type="password" name="password" placeholder="password" required></p>
      <button>sign in</button>
    </form>
    <p class="muted">testers: 0xnhsec / Noshiro (see player guide)</p>`));
});

accountRouter.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = usersApi.verify(username, password);
  if (!user) {
    if (wantsJson(req)) return res.status(401).json({ error: 'invalid credentials' });
    return res.status(401).type('html').send(render('Login', '<h1>Sign in</h1><p>Invalid credentials.</p><p><a href="/login">try again</a></p>'));
  }
  loginCookie(res, user);
  if (wantsJson(req)) return res.json({ ok: true, username: user.username });
  res.redirect('/me');
});

accountRouter.post('/logout', (req, res) => {
  sessionApi.destroy(req);
  res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0');
  if (wantsJson(req)) return res.json({ ok: true });
  res.redirect('/login');
});

accountRouter.get('/me', (req, res) => {
  if (!req.auth) return res.status(401).type('html').send(render('Account', '<p>Not logged in. <a href="/login">Log in</a></p>'));
  const u = req.auth.user;
  res.type('html').send(render('Account', `
    <h1>Account — ${esc(u.username)}</h1>
    <table>
      <tr><th>username</th><td>${esc(u.username)}</td></tr>
      <tr><th>role</th><td>${esc(u.role)}</td></tr>
      <tr><th>email</th><td>${esc(u.email || '')}</td></tr>
      <tr><th>recovery email</th><td>${esc(u.recovery_email || '')}</td></tr>
      <tr><th>api key</th><td><code>${esc(u.api_key || '')}</code></td></tr>
      <tr><th>auth method</th><td>${esc(req.auth.session.auth_method)}</td></tr>
    </table>
    <p class="muted">Your api key is the session-bound secret event verification matches against. <a href="/account">account settings</a> · <a href="/api/quotes">public API</a></p>`));
});

/* CSRF surface: state change with zero CSRF protection (deliberate, arch §7.0). */
accountRouter.get('/account', (req, res) => {
  if (!req.auth) return res.status(401).type('html').send(render('Account', '<p>Not logged in. <a href="/login">Log in</a></p>'));
  const u = req.auth.user;
  res.type('html').send(render('Account settings', `
    <h1>Recovery email</h1>
    <div class="card">
      <p>current recovery email: <code>${esc(u.recovery_email || '')}</code></p>
      <form method="post" action="/account/recovery-email">
        <p><input name="email" placeholder="new-recovery@example.net" required size="40"></p>
        <button>update recovery email</button>
      </form>
      <p class="muted">This form posts with the session cookie and nothing else — no token, no origin check. That is the M2 CSRF class.</p>
    </div>`));
});

accountRouter.post('/account/recovery-email', (req, res) => {
  if (!req.auth) return res.status(401).json({ error: 'authentication required' });
  const email = String((req.body && (req.body.email != null ? req.body.email : req.body)) || '');
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({ error: 'a valid email is required' });
  }
  db.prepare('UPDATE users SET recovery_email = ? WHERE id = ?').run(email, req.auth.user.id);
  if (wantsJson(req) || (req.headers['content-type'] || '').includes('application/json')) {
    return res.json({ ok: true, recovery_email: email });
  }
  res.type('html').send(render('Account settings', `<h1>Recovery email</h1><div class="card"><p>updated to <code>${esc(email)}</code></p><p><a href="/account">back</a></p></div>`));
});

/* CORS surface: reflected Origin + credentials on a credentialed endpoint. */
const reflectCors = (req, res, extra) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin); // deliberate reflection (M2 class)
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
    if (extra) {
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || 'content-type');
    }
  }
};

accountRouter.options('/api/secret', (req, res) => { reflectCors(req, res, true); res.status(204).end(); });
accountRouter.get('/api/secret', (req, res) => {
  reflectCors(req, res);
  if (!req.auth) return res.status(401).json({ error: 'authentication required' });
  const u = req.auth.user;
  res.json({ username: u.username, role: u.role, email: u.email, api_key: u.api_key });
});

/* Warm-up: public CORS-reflecting mini-API (standalone self-sufficiency). */
accountRouter.options('/api/quotes', (req, res) => { reflectCors(req, res, true); res.status(204).end(); });
accountRouter.get('/api/quotes', (req, res) => {
  reflectCors(req, res);
  res.json({
    quotes: [
      'Trust the edge, verify the origin.',
      'A cookie is not a capability.',
      'Same-site is a default, not a defense.',
      'Reflected is not allow-listed.',
    ],
  });
});

/* ------------------------------------------------------------ victim vhost */
victimRouter.get('/', (req, res) => {
  res.type('html').send(render('Login', `
    <h1>victim portal</h1>
    <div class="card">
      <form method="post" action="/login">
        <p><input name="username" placeholder="username" required></p>
        <p><input type="password" name="password" placeholder="password" required></p>
        <button>sign in</button>
      </form>
    </div>
    <p class="muted">This is the origin the innocent browser session lives on. Testers: 0xnhsec / Noshiro.</p>`));
});
victimRouter.use(accountRouter);

/* ------------------------------------------------------------ portal vhost */
portalRouter.get('/', (req, res) => {
  res.type('html').send(render('Portal', `
    <h1>aslv.lab portal</h1>
    <div class="card">
      <p>The organization portal. Sign in on the <a href="/login">login page</a>.</p>
      <p class="muted">Endpoints: /login, /me, /account, /account/recovery-email, /api/secret (session), /api/quotes (public).</p>
    </div>
    <div class="card">
      <p class="muted">Lab surfaces: reflected-origin CORS on /api/*, token-less state change on /account/recovery-email.
      Exploit pages: <code>attacker.${esc(LAB_DOMAIN)}</code>. Verifier: <code>collector.${esc(LAB_DOMAIN)}/verify</code>.</p>
    </div>`));
});
portalRouter.use(accountRouter);

/* --------------------------------------------------------- attacker vhost */
attackerRouter.use((req, res, next) => { // record every hit (Referer/origin capture)
  try {
    db.prepare('INSERT INTO attacker_hits (ts, host, url, referer, origin) VALUES (?,?,?,?,?)')
      .run(nowIso(), String(req.headers.host || ''), req.originalUrl,
        req.headers.referer || '', req.headers.origin || '');
  } catch (_) { /* best effort */ }
  next();
});

attackerRouter.get('/', (req, res) => {
  const pages = db.prepare('SELECT name, ts FROM attacker_pages ORDER BY name').all();
  res.type('html').send(render('Exploit server', `
    <h1>Exploit server</h1>
    <p class="muted">Store exploit pages, then serve them from <code>http://attacker.${esc(LAB_DOMAIN)}:${esc(PORTAL_PORT)}/pages/&lt;name&gt;</code>.</p>
    <form method="POST" action="/pages/exploit.html">
      <p><input name="name" value="exploit.html" size="24" required> <button>store page</button></p>
      <p><textarea name="body" rows="10" cols="90" placeholder="&lt;script&gt;fetch('http://victim.../api/secret', {credentials:'include'})...&lt;/script&gt;"></textarea></p>
    </form>
    <table><tr><th>page</th><th>stored at</th><th>url</th></tr>
    ${pages.map((p) => `<tr><td>${esc(p.name)}</td><td>${esc(p.ts)}</td><td><a href="/pages/${esc(p.name)}">/pages/${esc(p.name)}</a></td></tr>`).join('') || '<tr><td colspan="3" class="muted">no pages yet</td></tr>'}
    </table>`));
});

const storePage = (req, res) => {
  const name = String(req.params.name || '').replace(/[^a-zA-Z0-9._-]/g, '_');
  const body = (req.body && (req.body.body || req.body)) || req.rawBody || '';
  db.prepare('INSERT INTO attacker_pages (name, body, ts) VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET body=excluded.body, ts=excluded.ts')
    .run(name, typeof body === 'string' ? body : JSON.stringify(body), nowIso());
  res.json({ stored: true, url: `/pages/${name}` });
};
attackerRouter.put('/pages/:name', storePage);
attackerRouter.post('/pages/:name', storePage);
attackerRouter.get('/pages/:name', (req, res) => {
  const p = db.prepare('SELECT body FROM attacker_pages WHERE name = ?').get(String(req.params.name).replace(/[^a-zA-Z0-9._-]/g, '_'));
  if (!p) return res.status(404).send('no such page');
  res.type('html').send(p.body);
});
attackerRouter.get('/leaks', (req, res) => {
  const hits = db.prepare('SELECT * FROM attacker_hits ORDER BY id DESC LIMIT 100').all();
  res.type('html').send(render('Captured hits', `
    <h1>Attacker-captured hits</h1>
    <table><tr><th>time</th><th>host</th><th>url</th><th>referer</th><th>origin</th></tr>
    ${hits.map((h) => `<tr><td>${esc(h.ts)}</td><td>${esc(h.host)}</td><td>${esc(h.url)}</td><td>${esc(h.referer)}</td><td>${esc(h.origin)}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">no hits yet</td></tr>'}
    </table>`));
});

/* -------------------------------------------------------- collector vhost */
const recordExfil = (req, payload) => {
  db.prepare('INSERT INTO exfil_hits (ts, origin, referer, sec_fetch_site, payload, ip) VALUES (?,?,?,?,?,?)')
    .run(nowIso(), req.headers.origin || '', req.headers.referer || '', req.headers['sec-fetch-site'] || '',
      String(payload).slice(0, 4096), (req.socket && req.socket.remoteAddress) || '-');
};

collectorRouter.post('/collect', (req, res) => {
  const payload = (req.body && (req.body.payload != null ? req.body.payload : req.body)) || req.rawBody || '';
  recordExfil(req, typeof payload === 'string' ? payload : JSON.stringify(payload));
  res.json({ collected: true });
});
collectorRouter.post('/exfil', (req, res) => { // alias used by the qa solver
  const payload = (req.body && (req.body.payload != null ? req.body.payload : req.body)) || req.rawBody || '';
  recordExfil(req, typeof payload === 'string' ? payload : JSON.stringify(payload));
  res.json({ collected: true });
});

collectorRouter.get('/verify', (req, res) => {
  const want = String(req.query.category || '').toUpperCase();
  const results = {};
  for (const category of ['CORS', 'CSRF']) {
    const r = { category, verified: false, flag: null, reason: '' };
    const already = flags.minted(category);
    if (already) {
      r.verified = true;
      r.flag = already;
      r.reason = 'already minted';
    } else if (category === 'CORS') {
      const hit = db.prepare('SELECT * FROM exfil_hits ORDER BY id DESC LIMIT 1').get();
      if (!hit) {
        r.reason = 'no exfil hit received';
      } else {
        const innocent = usersApi.innocent();
        const crossSite = String(hit.origin).includes(`attacker.${LAB_DOMAIN}`)
          || String(hit.referer).includes(`attacker.${LAB_DOMAIN}`)
          || hit.sec_fetch_site === 'cross-site';
        const secretMatch = !!innocent && String(hit.payload).includes(innocent.api_key);
        if (crossSite && secretMatch) {
          r.verified = true;
          r.flag = flags.mint('CORS');
          r.reason = 'dual check passed: cross-site context + session-bound secret match';
        } else {
          r.reason = `dual check failed (cross-site=${crossSite}, secret-match=${secretMatch})`;
        }
      }
    } else { // CSRF — innocent-row state change (arch §7.0: checker inspects only the innocent row)
      const innocent = usersApi.innocent();
      if (innocent && innocent.recovery_email !== SEED.innocent.recovery_email) {
        r.verified = true;
        r.flag = flags.mint('CSRF');
        r.reason = 'innocent row state change observed';
      } else {
        r.reason = 'no innocent-row state change observed yet';
      }
    }
    results[category] = r;
  }
  const out = { verified: false, flag: null, reason: '', checked_at: nowIso(), module: 'aslv-portal' };
  if (want === 'CORS' || want === 'CSRF') {
    return res.json({ ...out, ...results[want] });
  }
  const first = results.CORS.verified ? results.CORS : results.CSRF;
  return res.json({ ...out, category: first.category, verified: first.verified, flag: first.flag, reason: first.reason, results });
});

collectorRouter.get('/', (req, res) => {
  res.type('html').send(render('Verifier', `
    <h1>Event verifier</h1>
    <div class="card"><p><a href="/verify">GET /verify</a> — dual check for CORS (exfil hit bound to the innocent secret) and CSRF (innocent row state change).</p></div>
    <p class="muted">POST /victim drives the innocent browser (url, origin, referer, method, body). POST /collect | /exfil record exfil hits. GET /internal/activity is the activity feed.</p>`));
});

collectorRouter.post('/ingest', activity.ingest);
collectorRouter.post('/internal/ingest', activity.ingest);

/* ------------------------------------------- victim bot (solo play) -----
 * Server-side victim-browser simulation, ported from dsltv/base/runtime.js:
 * logs in the innocent (fresh session by default), fetches the URL with her
 * cookie jar, follows redirects, and — when an attacker origin is supplied —
 * models the SOP-permitted cross-site read by piping the response body into
 * the exfil verifier with the cross-site context attached.
 */
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

function labUrlToLoopback(urlStr) {
  /* *.aslv.lab URLs resolve to the sidecar/gateway from the host; inside this
   * container we reach ourselves on LISTEN_PORT with the Host header set. */
  try {
    const u = new URL(urlStr);
    if (u.hostname.endsWith(`.${LAB_DOMAIN}`)) {
      const hostHeader = `${u.hostname}:${u.port || PORTAL_PORT}`;
      return { url: `http://127.0.0.1:${LISTEN_PORT}${u.pathname}${u.search}`, hostHeader };
    }
  } catch (_) { /* ignore */ }
  return { url: urlStr, hostHeader: null };
}

collectorRouter.post('/victim', async (req, res) => {
  const b = req.body || {};
  if (!b.url) return res.status(400).json({ error: 'url required' });
  const innocent = usersApi.innocent();
  const jar = new Map();
  const out = { hops: [], finalUrl: null, status: null, excerpt: '' };
  try {
    if (b.cookies) for (const [k, v] of Object.entries(b.cookies)) jar.set(k, v);
    if (!b.cookies) {
      const sid = sessionApi.create(innocent, 'password'); // fresh innocent session
      jar.set('sid', sid);
    }
    let current = b.url;
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
      out.status = r.status; out.finalUrl = current;
      out.excerpt = r.body.slice(0, 1200);
      if (b.origin) {
        db.prepare('INSERT INTO exfil_hits (ts, origin, referer, sec_fetch_site, payload, ip) VALUES (?,?,?,?,?,?)')
          .run(nowIso(), String(b.origin || ''), String(b.referer || ''), 'cross-site',
            r.body.slice(0, 4096), (req.socket && req.socket.remoteAddress) || '-');
      }
      break;
    }
    res.json(out);
  } catch (e) {
    res.status(502).json({ error: String(e), ...out });
  }
});

/* ------------------------------------------------------------- mail vhost */
/* Mini mailbox fallback (compose routes mail.aslv.lab to stub-mail-2; this
 * vhost keeps M2 self-sufficient when the stub is absent). */
mailRouter.post('/internal/mail', (req, res) => {
  const { to, subject, body } = req.body || {};
  if (!to || !subject) return res.status(400).json({ error: 'to, subject, body required' });
  const r = db.prepare('INSERT INTO mailbox (ts, to_addr, subject, body) VALUES (?,?,?,?)')
    .run(nowIso(), to, subject, body || '');
  res.json({ id: r.lastInsertRowid });
});
mailRouter.get('/', (req, res) => {
  const items = db.prepare('SELECT * FROM mailbox ORDER BY id DESC LIMIT 50').all();
  res.type('html').send(render('Mail', `
    <h1>Mailbox</h1>
    <table><tr><th>id</th><th>time</th><th>to</th><th>subject</th><th>view</th></tr>
    ${items.map((m) => `<tr><td>${m.id}</td><td>${esc(m.ts)}</td><td>${esc(m.to_addr)}</td><td>${esc(m.subject)}</td><td><a href="/mail/${m.id}">open</a></td></tr>`).join('') || '<tr><td colspan="5" class="muted">empty</td></tr>'}
    </table>`));
});
mailRouter.get('/mail/:id', (req, res) => {
  const m = db.prepare('SELECT * FROM mailbox WHERE id = ?').get(Number(req.params.id));
  if (!m) return res.status(404).json({ error: 'no such mail' });
  const links = String(m.body).match(/https?:\/\/[^\s"'<>)]+/g) || [];
  res.json({ id: m.id, ts: m.ts, to: m.to_addr, subject: m.subject, body: m.body, links });
});

/* ------------------------------------------------------------------ boot */
app.listen(LISTEN_PORT, () => {
  console.log(`[aslv-portal] listening on :${LISTEN_PORT} (vhosts: victim|portal|www|aslv|collector|attacker|mail .${LAB_DOMAIN})`);
  console.log(`[aslv-portal] standalone=${STANDALONE} portal_port=${PORTAL_PORT} activity_sink=${ACTIVITY_SINK || 'off'}`);
  console.log('[aslv-portal] event flags (CORS, CSRF) are unminted at boot — /verify mints them');
});
