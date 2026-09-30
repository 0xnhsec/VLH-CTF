'use strict';
/*
 * VLH-CTF — ASLV M5 aslv-identity: database, seed, boot keys, shared helpers.
 *
 * Binding: CONTRACT §3 (flags), §6 (module contract), arch §4 (user model),
 * §7.5 (identity-plane win-state separation). Session provenance auth_method
 * (password|reset|oauth_link|token) is recorded at session CREATION.
 */
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || '/data';
const REGISTRY_DIR = process.env.REGISTRY_DIR || '/registry';
const LAB_DOMAIN = process.env.LAB_DOMAIN || 'aslv.lab';

fs.mkdirSync(DATA_DIR, { recursive: true });
try { fs.mkdirSync(REGISTRY_DIR, { recursive: true }); } catch (_) { /* fallback below */ }

const registryFile = (() => {
  const p = path.join(REGISTRY_DIR, 'flags.ndjson');
  try { fs.appendFileSync(p, ''); return p; } catch (_) { return path.join(DATA_DIR, 'registry-fallback.ndjson'); }
})();
const registryAppend = (obj) => {
  try { fs.appendFileSync(registryFile, JSON.stringify(obj) + '\n'); } catch (_) { /* best effort */ }
};

/* ------------------------------------------------------------ helpers */
const randHex = (n) => crypto.randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
const randDigits = (n) => Array.from({ length: n }, () => crypto.randomInt(0, 10)).join('');
const nowIso = () => new Date().toISOString();
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const uuidv4 = () => crypto.randomUUID();
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const tenantFor = (username) => 't' + sha256('aslv-tenant:' + username).slice(0, 6);

const CSS = `
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: ui-monospace, 'JetBrains Mono', Menlo, Consolas, monospace;
         background:#0a0f0a; color:#c7f0c7; margin:0; padding:0 0 4rem; }
  a { color:#4ade80; }
  .wrap { max-width: 880px; margin: 0 auto; padding: 1.25rem; }
  header { border-bottom:1px solid #1c3a1c; padding:.9rem 1.25rem; background:#0d140d; }
  header .brand { color:#4ade80; font-weight:700; letter-spacing:.08em; }
  main.wrap h1 { color:#4ade80; font-size:1.25rem; }
  .card { border:1px solid #1c3a1c; background:#0d140d; border-radius:6px; padding:1rem; margin:.75rem 0; }
  table { border-collapse:collapse; width:100%; font-size:.85rem; }
  th,td { border:1px solid #1c3a1c; padding:.4rem .55rem; text-align:left; vertical-align:top; }
  th { color:#4ade80; }
  input,button { font:inherit; background:#0f1a0f; color:#c7f0c7;
        border:1px solid #2a5a2a; border-radius:4px; padding:.45rem .6rem; }
  button { cursor:pointer; border-color:#4ade80; color:#4ade80; }
  .muted { color:#5c8a5c; font-size:.8rem; }
  code { color:#facc15; }
  pre { background:#0f1a0f; border:1px solid #1c3a1c; padding:.75rem; overflow:auto; border-radius:6px; }
`;
function render(title, bodyHtml) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — ASLV identity</title><style>${CSS}</style></head><body>
<header><span class="brand">auth.aslv.lab</span> <span class="muted">ASLV organization identity plane (M5)</span></header>
<main class="wrap">${bodyHtml}</main>
</body></html>`;
}

/* ----------------------------------------------------------------- db */
const db = new Database(path.join(DATA_DIR, 'identity.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  uuid TEXT UNIQUE NOT NULL,
  email TEXT,
  recovery_email TEXT,
  role TEXT NOT NULL DEFAULT 'user',
  tenant TEXT,
  api_key TEXT,
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_secret TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  auth_method TEXT NOT NULL DEFAULT 'password',
  mfa_pending INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS client_sessions (
  csid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reset_tokens (
  token TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  user_id INTEGER,
  day TEXT NOT NULL,
  counter INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  redirect_uri TEXT,
  scope TEXT,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  scope TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
  kid TEXT PRIMARY KEY,
  kty TEXT NOT NULL,
  n TEXT NOT NULL,
  e TEXT NOT NULL,
  public_pem TEXT,
  private_pem TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS linked_identities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_user_uuid TEXT NOT NULL,
  oauth_sub TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  identifier TEXT NOT NULL,
  is_authenticated INTEGER NOT NULL,
  data TEXT NOT NULL,
  latency_ms REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS flags (
  category TEXT PRIMARY KEY,
  flag TEXT NOT NULL,
  state TEXT NOT NULL,
  minted_at TEXT
);
`);

/* ------------------------------------------------------------ boot keys */
const KID = 'key-' + randHex(4);
const bootKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = { ...bootKeys.publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' };
const privatePem = bootKeys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicPem = bootKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
db.prepare('DELETE FROM keys').run();
db.prepare('INSERT INTO keys (kid, kty, n, e, public_pem, private_pem, created_at) VALUES (?,?,?,?,?,?,?)')
  .run(KID, 'RSA', publicJwk.n, publicJwk.e, publicPem, privatePem, nowIso());

/* ---------------------------------------------------------------- seed */
const INNOCENT = {
  username: process.env.INNOCENT_USERNAME || ('usr_' + randHex(4)),
  password: process.env.INNOCENT_PASSWORD || randHex(16),
  api_key: process.env.INNOCENT_API_KEY || randHex(32),
  uuid: process.env.INNOCENT_UUID || uuidv4(),
};

const usersApi = {
  byUsername: (u) => db.prepare('SELECT * FROM users WHERE username = ?').get(String(u || '')),
  byUuid: (u) => db.prepare('SELECT * FROM users WHERE uuid = ?').get(String(u || '')),
  byId: (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id),
  innocent: () => usersApi.byUsername(INNOCENT.username),
  verify: (username, password) => {
    const u = usersApi.byUsername(username);
    return u && u.password === sha256(password) ? u : null;
  },
};

function insertUser({ username, password, role, email, recoveryEmail, apiKey, uuid, mfaEnabled, mfaSecret }) {
  return db.prepare(`INSERT INTO users (username, password, uuid, email, recovery_email, role, tenant, api_key, mfa_enabled, mfa_secret, created_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(username, sha256(password), uuid, email, recoveryEmail || null, role, tenantFor(username), apiKey,
      mfaEnabled ? 1 : 0, mfaSecret || null, nowIso());
}

function seedIfEmpty() {
  const count = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  if (count > 0) {
    // Org-wide seed override (full mode): keep the local innocent row in sync.
    const existing = usersApi.byUsername(INNOCENT.username) || usersApi.byUuid(INNOCENT.uuid);
    if (existing && existing.role === 'innocent') {
      db.prepare('UPDATE users SET username=?, password=?, api_key=?, uuid=? WHERE id=?')
        .run(INNOCENT.username, sha256(INNOCENT.password), INNOCENT.api_key, INNOCENT.uuid, existing.id);
    }
    return;
  }
  insertUser({ username: '0xnhsec', password: 'vlh-tester-01', role: 'tester', email: `0xnhsec@${LAB_DOMAIN}`, recoveryEmail: `0xnhsec+recovery@${LAB_DOMAIN}`, apiKey: randHex(32), uuid: uuidv4(), mfaEnabled: true, mfaSecret: randDigits(6) });
  insertUser({ username: 'Noshiro', password: 'vlh-tester-02', role: 'tester', email: `noshiro@${LAB_DOMAIN}`, recoveryEmail: `noshiro+recovery@${LAB_DOMAIN}`, apiKey: randHex(32), uuid: uuidv4(), mfaEnabled: true, mfaSecret: randDigits(6) });
  insertUser({ username: INNOCENT.username, password: INNOCENT.password, role: 'innocent', email: `${INNOCENT.username}@${LAB_DOMAIN}`, recoveryEmail: `${INNOCENT.username}+recovery@${LAB_DOMAIN}`, apiKey: INNOCENT.api_key, uuid: INNOCENT.uuid, mfaEnabled: true, mfaSecret: randDigits(6) });
  insertUser({ username: 'admin', password: randHex(16), role: 'admin', email: `admin@${LAB_DOMAIN}`, apiKey: randHex(32), uuid: uuidv4(), mfaEnabled: false, mfaSecret: null });
  // grading-only dump (container-internal, never player-accessible)
  try {
    fs.writeFileSync(path.join(DATA_DIR, 'seed.json'), JSON.stringify({
      generated_at: nowIso(),
      innocent: { username: INNOCENT.username, password: INNOCENT.password, api_key: INNOCENT.api_key, uuid: INNOCENT.uuid },
      admin: { username: 'admin' },
    }, null, 2));
  } catch (_) { /* best effort */ }
  console.log(`[identity] seeded users (innocent=${INNOCENT.username})`);
}
seedIfEmpty();

// Restart-with-volume safety: when the DB already holds an innocent account
// (seeded by a previous boot), the in-memory INNOCENT identity MUST be
// re-resolved from the DB — otherwise flag gates would compare against a
// stale random identity that exists nowhere.
(function resolveInnocent() {
  const row = db.prepare("SELECT username, uuid, api_key FROM users WHERE role = 'innocent' LIMIT 1").get();
  if (row) {
    INNOCENT.username = row.username;
    INNOCENT.uuid = row.uuid;
    INNOCENT.api_key = row.api_key;
  }
})();

module.exports = {
  db, registryAppend,
  DATA_DIR, LAB_DOMAIN,
  randHex, randDigits, nowIso, sha256, uuidv4, esc, render, tenantFor,
  usersApi, INNOCENT,
  keys: { kid: KID, publicJwk, privatePem, publicPem },
};
