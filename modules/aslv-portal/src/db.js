'use strict';
/*
 * VLH-CTF — ASLV M2 portal: database + seeding.
 * SQLite at /data/portal.db (named volume, standalone persistence per arch §6).
 * Seeding mirrors dsltv/base/runtime.js: testers (known), innocent usr_<hex>
 * (random password + 32-hex api_key — the event-verified secret), admin
 * (random password). Innocent/admin credentials never enter player-visible
 * responses; the plaintext dump below is grading-only inside the container.
 */
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const randHex = (n) => crypto.randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
const nowIso = () => new Date().toISOString();

function initDb({ dataDir, labDomain }) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new Database(path.join(dataDir, 'portal.db'));
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
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      auth_method TEXT NOT NULL DEFAULT 'password',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS flags (
      category TEXT PRIMARY KEY,
      flag TEXT,
      archetype TEXT NOT NULL,
      state TEXT NOT NULL,
      minted_at TEXT
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
    CREATE TABLE IF NOT EXISTS mailbox (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      to_addr TEXT NOT NULL,
      subject TEXT NOT NULL,
      body TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  `);

  /* ------------------------------------------------------------ seed */
  const SEED = (() => {
    const innocentName = 'usr_' + randHex(4);
    return {
      innocent: {
        username: innocentName,
        password: randHex(16),
        role: 'innocent',
        email: `${innocentName}@${labDomain}`,
        recovery_email: `${innocentName}+recovery@${labDomain}`,
        api_key: randHex(32),
      },
      admin: {
        username: 'admin',
        password: randHex(16),
        role: 'admin',
        email: `admin@${labDomain}`,
        api_key: randHex(32),
      },
      testers: [
        { username: '0xnhsec', password: 'vlh-tester-01', role: 'tester', email: `0xnhsec@${labDomain}`, api_key: randHex(32) },
        { username: 'Noshiro', password: 'vlh-tester-02', role: 'tester', email: `noshiro@${labDomain}`, api_key: randHex(32) },
      ],
    };
  })();

  if (!db.prepare('SELECT COUNT(*) c FROM users').get().c) {
    const ins = db.prepare(`INSERT INTO users (username, password, role, email, recovery_email, api_key, created_at)
                            VALUES (@username, @password, @role, @email, @recovery_email, @api_key, @created_at)`);
    const tx = db.transaction(() => {
      for (const u of [SEED.innocent, SEED.admin, ...SEED.testers]) {
        ins.run({ recovery_email: null, api_key: null, ...u, created_at: nowIso() });
      }
    });
    tx();
  }

  /* grading-only seed dump inside the container (never player-accessible) */
  try {
    fs.writeFileSync(path.join(dataDir, 'seed.json'), JSON.stringify({
      module: 'aslv-portal', generated_at: nowIso(),
      innocent: { username: SEED.innocent.username, password: SEED.innocent.password, api_key: SEED.innocent.api_key },
      admin: { username: 'admin', password: SEED.admin.password },
    }, null, 2));
  } catch (_) { /* best effort */ }

  /* ------------------------------------------------------- session api */
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
      const u = db.prepare('SELECT * FROM users WHERE id = ?').get(s.user_id);
      return u ? { user: u, session: s } : null;
    },
    destroy: (req) => {
      const sid = parseCookies(req.headers.cookie).sid;
      if (sid) db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
    },
  };

  const usersApi = {
    byUsername: (u) => db.prepare('SELECT * FROM users WHERE username = ?').get(u),
    byId: (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id),
    innocent: () => db.prepare("SELECT * FROM users WHERE role = 'innocent'").get(),
    verify: (username, password) => {
      const u = usersApi.byUsername(String(username || ''));
      return u && u.password === String(password || '') ? u : null;
    },
  };

  return { db, SEED, sessionApi, usersApi, parseCookies };
}

module.exports = { initDb };
