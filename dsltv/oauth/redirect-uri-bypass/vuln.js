'use strict';
/*
 * DSLTV oauth/redirect-uri-bypass — RedirectUriBypass (identity-gated, high).
 * "Socialite" — social SSO portal with an embedded mini Authorization Server.
 * Flaw: /oauth/authorize validates redirect_uri with substring matching
 * (includes) instead of exact comparison against the registered redirect.
 * Win: drive the innocent (victim bot, sso) through a crafted authorize URL
 * whose redirect_uri contains "victim.target.lab" but lands in attacker space
 * (catch-all *.target.lab) — the code for the INNOCENT identity is captured on
 * the attacker host (/leaks), exchanged for a token, and /flag releases the
 * flag only for a token whose sub == the innocent's social identity.
 */
module.exports = {
  meta: {
    category: 'OAUTH', subName: 'RedirectUriBypass', archetype: 'identity-gated', difficulty: 'high',
    description: 'Socialite SSO — flawed redirect_uri validation lets an attacker divert the innocent\'s authorization code to attacker space. Entry: http://victim.target.lab:8119/app',
    flags: [{ category: 'OAUTH', subName: 'RedirectUriBypass', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const db = ctx.db;
    const esc = ctx.esc;
    const render = ctx.render;
    const CLIENTS = {
      web: { name: 'Socialite Web', redirect: `http://victim.${ctx.labDomain}:8119/oauth/callback`, type: 'public' },
    };
    const REGISTERED = CLIENTS.web.redirect;

    db.exec(`
      CREATE TABLE IF NOT EXISTS social_accounts (sub TEXT PRIMARY KEY, email TEXT, name TEXT, password TEXT, created_at TEXT);
      CREATE TABLE IF NOT EXISTS as_sessions (asid TEXT PRIMARY KEY, sub TEXT, created_at TEXT);
      CREATE TABLE IF NOT EXISTS auth_codes (code TEXT PRIMARY KEY, sub TEXT, client_id TEXT, redirect_uri TEXT,
        scope TEXT, used INTEGER DEFAULT 0, expires_at TEXT, created_at TEXT);
      CREATE TABLE IF NOT EXISTS linked_identities (client_user_id INTEGER, social_sub TEXT, created_at TEXT, PRIMARY KEY (client_user_id, social_sub));
    `);

    const innocent = ctx.users.innocent();
    const INNOCENT_SUB = 'soc_' + ctx.randHex(8);
    db.prepare('INSERT INTO social_accounts (sub, email, name, password, created_at) VALUES (?,?,?,?,?)')
      .run(INNOCENT_SUB, innocent.email, innocent.username, ctx.randHex(16), ctx.nowIso());

    const SECRET = ctx.randHex(32);
    const signToken = (p) => ctx.jwt.sign(p, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
    const verifyToken = (t) => { try { return ctx.jwt.verify(t, SECRET); } catch (_) { return null; } };
    const cookies = (req) => {
      const out = {};
      String(req.headers.cookie || '').split(';').forEach((p) => {
        const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
      });
      return out;
    };
    const asSession = (req) => {
      const asid = cookies(req).as_sid;
      if (!asid) return null;
      return db.prepare('SELECT * FROM as_sessions WHERE asid = ?').get(asid) || null;
    };
    const socialBySub = (sub) => db.prepare('SELECT * FROM social_accounts WHERE sub = ?').get(sub) || null;
    const exchangeCode = (code) => {
      const row = db.prepare('SELECT * FROM auth_codes WHERE code = ?').get(String(code || ''));
      if (!row || row.used) return null;
      if (new Date(row.expires_at) < new Date()) return null;
      db.prepare('UPDATE auth_codes SET used = 1 WHERE code = ?').run(row.code);
      return { sub: row.sub, scope: row.scope, client_id: row.client_id };
    };

    /* ---------------- mini Authorization Server: "Socialite ID" ---------------- */
    ctx.app.get('/oauth/login', (req, res) => {
      res.type('html').send(render('Socialite ID — sign in', `
        <h1>Socialite ID (Authorization Server)</h1>
        <div class="card"><form method="POST" action="/oauth/login">
          <p><input name="email" placeholder="email" size="32" required>
             <input name="password" placeholder="password" type="password" size="24" required>
             <button>sign in</button></p>
        </form></div>
        <p class="muted">No social identity yet? <a href="/social">Register a social identity</a>.</p>`));
    });
    ctx.app.post('/oauth/login', (req, res) => {
      const { email, password } = req.body || {};
      const acct = db.prepare('SELECT * FROM social_accounts WHERE email = ?').get(String(email || ''));
      if (!acct || acct.password !== String(password || '')) {
        return res.status(401).type('html').send(render('Socialite ID', '<p>Invalid credentials. <a href="/oauth/login">try again</a></p>'));
      }
      const asid = ctx.randHex(32);
      db.prepare('INSERT INTO as_sessions (asid, sub, created_at) VALUES (?,?,?)').run(asid, acct.sub, ctx.nowIso());
      res.append('Set-Cookie', 'as_sid=' + asid + '; Path=/; HttpOnly; SameSite=Lax');
      res.redirect(302, '/oauth/panel');
    });
    ctx.app.get('/oauth/panel', (req, res) => {
      const s = asSession(req);
      if (!s) return res.redirect(302, '/oauth/login');
      const acct = socialBySub(s.sub);
      res.type('html').send(render('Socialite ID — panel', `
        <h1>AS session</h1>
        <table><tr><th>sub</th><td>${esc(acct.sub)}</td></tr><tr><th>email</th><td>${esc(acct.email)}</td></tr></table>
        <p class="muted">Registered client <code>web</code> → redirect_uri <code>${esc(REGISTERED)}</code></p>`));
    });
    ctx.app.get('/social', (req, res) => {
      res.type('html').send(render('Register social identity', `
        <h1>Register a social identity</h1>
        <div class="card"><form method="POST" action="/social/register">
          <p><input name="email" placeholder="email" size="32" required></p>
          <p><input name="name" placeholder="display name" size="32" required></p>
          <p><input name="password" placeholder="choose password" type="password" size="24" required></p>
          <p><button>create identity</button></p>
        </form></div>
        <p class="muted">Identities are created without email verification (demo AS).</p>`));
    });
    ctx.app.post('/social/register', (req, res) => {
      const { email, name, password } = req.body || {};
      if (!email || !name || !password) return res.status(400).type('html').send(render('Register', '<p>email, name, password required</p>'));
      const sub = 'soc_' + ctx.randHex(8);
      db.prepare('INSERT INTO social_accounts (sub, email, name, password, created_at) VALUES (?,?,?,?,?)')
        .run(sub, String(email), String(name), String(password), ctx.nowIso());
      const asid = ctx.randHex(32);
      db.prepare('INSERT INTO as_sessions (asid, sub, created_at) VALUES (?,?,?)').run(asid, sub, ctx.nowIso());
      res.append('Set-Cookie', 'as_sid=' + asid + '; Path=/; HttpOnly; SameSite=Lax');
      res.type('html').send(render('Identity created', `
        <h1>Social identity created</h1>
        <p>sub: <code>${esc(sub)}</code> — you are now signed in at the AS.</p>
        <p><a href="/app">back to the client app</a></p>`));
    });

    ctx.app.get('/oauth/authorize', (req, res) => {
      const q = req.query;
      const client = CLIENTS[String(q.client_id || '')];
      if (!client) return res.status(400).json({ error: 'unknown client_id' });
      const ru = String(q.redirect_uri || '');
      /* THE FLAW: substring check instead of exact match against client.redirect */
      if (!ru.includes('victim.target.lab')) return res.status(400).json({ error: 'invalid redirect_uri' });
      if (String(q.response_type || '') !== 'code') return res.status(400).json({ error: 'unsupported response_type' });
      const s = asSession(req);
      if (!s) return res.status(401).type('html').send(render('Socialite ID', '<p>AS login required. <a href="/oauth/login">sign in at the AS</a></p>'));
      const code = ctx.randHex(24);
      db.prepare('INSERT INTO auth_codes (code, sub, client_id, redirect_uri, scope, used, expires_at, created_at) VALUES (?,?,?,?,?,0,?,?)')
        .run(code, s.sub, String(q.client_id), ru, String(q.scope || 'read'),
          new Date(Date.now() + 10 * 60 * 1000).toISOString(), ctx.nowIso());
      const sep = ru.includes('?') ? '&' : '?';
      const loc = ru + sep + 'code=' + code + (q.state ? '&state=' + encodeURIComponent(String(q.state)) : '');
      res.redirect(302, loc);
    });

    ctx.app.post('/oauth/token', (req, res) => {
      const b = req.body || {};
      const grant = exchangeCode(b.code);
      if (!grant) return res.status(400).json({ error: 'invalid_grant' });
      const token = signToken({ sub: grant.sub, scope: grant.scope, cid: grant.client_id });
      res.json({ access_token: token, token_type: 'Bearer', expires_in: 3600, scope: grant.scope, sub: grant.sub });
    });

    ctx.app.get('/oauth/userinfo', (req, res) => {
      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
      const p = m && verifyToken(m[1]);
      if (!p) return res.status(401).json({ error: 'Bearer token required' });
      const acct = socialBySub(p.sub);
      res.json({ sub: p.sub, email: acct ? acct.email : null, name: acct ? acct.name : null, scope: p.scope });
    });

    /* ------------------------- client app: "Socialite" ------------------------- */
    ctx.app.get('/app', (req, res) => {
      const auth = ctx.session.get(req);
      const s = asSession(req);
      res.type('html').send(render('Socialite — client portal', `
        <h1>Socialite client portal</h1>
        ${auth ? `<p>Signed in as <b>${esc(auth.user.username)}</b> (client session, auth_method=${esc(auth.session.auth_method)}).</p>` : '<p>Not signed in. Use username/password login or SSO.</p>'}
        <div class="card">
          <form method="POST" action="/app/login"><p><input name="username" placeholder="username" size="16">
            <input name="password" type="password" placeholder="password" size="16">
            <button>password login</button></p></form>
          <p><a href="/login">Login with SSO (Socialite ID)</a></p>
        </div>
        <p class="muted">OAuth client <code>web</code> (public) · registered redirect_uri: <code>${esc(REGISTERED)}</code></p>
        ${s ? `<p class="muted">AS session active (sub ${esc(s.sub)}).</p>` : ''}`));
    });
    ctx.app.post('/app/login', (req, res) => {
      const u = ctx.users.verify(String((req.body || {}).username || ''), String((req.body || {}).password || ''));
      if (!u) return res.status(401).type('html').send(render('Socialite', '<p>Bad credentials.</p>'));
      ctx.login(res, u, { authMethod: 'password' });
      res.redirect(302, '/app');
    });
    ctx.app.get('/login', (req, res) => {
      const state = ctx.randHex(8);
      const url = `/oauth/authorize?client_id=web&redirect_uri=${encodeURIComponent(REGISTERED)}&response_type=code&scope=read&state=${state}`;
      res.redirect(302, url);
    });
    ctx.app.get('/oauth/callback', (req, res) => {
      const code = String((req.query || {}).code || '');
      const grant = exchangeCode(code);
      if (!grant) return res.status(400).type('html').send(render('Socialite', '<p>Invalid or used code.</p>'));
      const acct = socialBySub(grant.sub);
      const auth = ctx.session.get(req);
      let linked = false;
      if (auth) {
        db.prepare('INSERT OR IGNORE INTO linked_identities (client_user_id, social_sub, created_at) VALUES (?,?,?)')
          .run(auth.user.id, grant.sub, ctx.nowIso());
        linked = true;
      }
      res.type('html').send(render('SSO complete', `
        <h1>SSO sign-in complete</h1>
        <p>Signed in via Socialite ID as <b>${esc(acct ? acct.email : grant.sub)}</b> (sub <code>${esc(grant.sub)}</code>).</p>
        ${linked ? '<p>SSO identity linked to your client account.</p>' : '<p class="muted">No client session was active — identity not linked.</p>'}`));
    });

    /* -------- victim bootstrap: innocent AS session (bot sso:true) -------- */
    ctx.app.get('/__sso', (req, res) => {
      const asid = ctx.randHex(32);
      db.prepare('INSERT INTO as_sessions (asid, sub, created_at) VALUES (?,?,?)').run(asid, INNOCENT_SUB, ctx.nowIso());
      res.append('Set-Cookie', 'as_sid=' + asid + '; Path=/; HttpOnly; SameSite=Lax');
      res.redirect(302, '/app');
    });

    /* ------------------------------- flag gate ------------------------------- */
    ctx.app.get('/flag', (req, res) => {
      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
      const p = m && verifyToken(m[1]);
      if (!p) return res.status(401).json({ error: 'Bearer token required (exchange a code at /oauth/token)' });
      if (p.sub !== INNOCENT_SUB) {
        return res.status(403).json({ error: 'token identity is not the innocent user', your_sub: p.sub });
      }
      res.json({ flag: ctx.flags.held('OAUTH', 'RedirectUriBypass'), sub: p.sub });
    });
  },
};
