'use strict';
/*
 * DSLTV oauth/no-pkce — NoPkce (identity-gated, medium).
 * "FitSync" — fitness platform with a mobile app using a custom-scheme
 * redirect (fitsync://callback). The mobile client is a public client whose
 * policy REQUIRES PKCE.
 * Flaw: the AS never enforces PKCE — /oauth/authorize accepts requests
 * without a code_challenge, and /oauth/token exchanges codes without a
 * code_verifier.
 * Win: the "OS app-link dispatch log" (/intercepted) records every custom-
 * scheme callback (simulating a malicious app that registered the scheme):
 * drive the victim (bot, sso) through an authorize URL without a challenge,
 * read the intercepted myapp://callback?code=… link, exchange the code with
 * no verifier, present the token at /flag.
 */
module.exports = {
  meta: {
    category: 'OAUTH', subName: 'NoPkce', archetype: 'identity-gated', difficulty: 'medium',
    description: 'FitSync mobile app — PKCE never enforced: intercept the custom-scheme callback code and exchange it verifier-free. Entry: http://victim.target.lab:8119/app',
    flags: [{ category: 'OAUTH', subName: 'NoPkce', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const db = ctx.db;
    const esc = ctx.esc;
    const render = ctx.render;
    const APP_REDIRECT = 'fitsync://callback';
    const CLIENTS = { mobile: { name: 'FitSync Mobile', redirect: APP_REDIRECT, pkce: 'required' } };

    db.exec(`
      CREATE TABLE IF NOT EXISTS social_accounts (sub TEXT PRIMARY KEY, email TEXT, name TEXT, password TEXT, created_at TEXT);
      CREATE TABLE IF NOT EXISTS as_sessions (asid TEXT PRIMARY KEY, sub TEXT, created_at TEXT);
      CREATE TABLE IF NOT EXISTS auth_codes (code TEXT PRIMARY KEY, sub TEXT, client_id TEXT, redirect_uri TEXT,
        scope TEXT, code_challenge TEXT, used INTEGER DEFAULT 0, expires_at TEXT, created_at TEXT);
      CREATE TABLE IF NOT EXISTS intercepted_links (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, ts TEXT);
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
    const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    /* -------------------- mini Authorization Server: "FitID" -------------------- */
    ctx.app.get('/oauth/login', (req, res) => {
      res.type('html').send(render('FitID — sign in', `
        <h1>FitID (Authorization Server)</h1>
        <div class="card"><form method="POST" action="/oauth/login">
          <p><input name="email" placeholder="email" size="32" required>
             <input name="password" type="password" placeholder="password" size="24" required>
             <button>sign in</button></p></form></div>
        <p class="muted"><a href="/social">Register a social identity</a></p>`));
    });
    ctx.app.post('/oauth/login', (req, res) => {
      const acct = db.prepare('SELECT * FROM social_accounts WHERE email = ?').get(String((req.body || {}).email || ''));
      if (!acct || acct.password !== String((req.body || {}).password || '')) {
        return res.status(401).type('html').send(render('FitID', '<p>Invalid credentials.</p>'));
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
      res.type('html').send(render('FitID — panel', `
        <h1>AS session</h1><table>
        <tr><th>sub</th><td>${esc(acct.sub)}</td></tr><tr><th>email</th><td>${esc(acct.email)}</td></tr></table>
        <p class="muted">client <code>mobile</code> (public) · redirect <code>${esc(APP_REDIRECT)}</code> · PKCE policy: <b>required</b></p>`));
    });
    ctx.app.get('/social', (req, res) => {
      res.type('html').send(render('Register social identity', `
        <h1>Register a social identity</h1>
        <div class="card"><form method="POST" action="/social/register">
          <p><input name="email" placeholder="email" size="32" required></p>
          <p><input name="name" placeholder="display name" size="32" required></p>
          <p><input name="password" type="password" placeholder="choose password" size="24" required></p>
          <p><button>create identity</button></p></form></div>`));
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
      res.type('html').send(render('Identity created', `<p>sub: <code>${esc(sub)}</code> — signed in at the AS.</p>`));
    });
    ctx.app.get('/oauth/authorize', (req, res) => {
      const q = req.query;
      const client = CLIENTS[String(q.client_id || '')];
      if (!client) return res.status(400).json({ error: 'unknown client_id' });
      if (String(q.redirect_uri || '') !== client.redirect) return res.status(400).json({ error: 'invalid redirect_uri' });
      if (String(q.response_type || '') !== 'code') return res.status(400).json({ error: 'unsupported response_type' });
      const s = asSession(req);
      if (!s) return res.status(401).type('html').send(render('FitID', '<p>AS login required. <a href="/oauth/login">sign in</a></p>'));
      /* THE FLAW: PKCE is policy-required for this public client but the AS
       * accepts an authorize request WITHOUT any code_challenge. */
      const code = ctx.randHex(24);
      db.prepare('INSERT INTO auth_codes (code, sub, client_id, redirect_uri, scope, code_challenge, used, expires_at, created_at) VALUES (?,?,?,?,?,?,0,?,?)')
        .run(code, s.sub, String(q.client_id), client.redirect, String(q.scope || 'read'),
          q.code_challenge ? String(q.code_challenge) : null,
          new Date(Date.now() + 10 * 60 * 1000).toISOString(), ctx.nowIso());
      const loc = client.redirect + (client.redirect.includes('?') ? '&' : '?')
        + 'code=' + code + (q.state ? '&state=' + encodeURIComponent(String(q.state)) : '');
      /* custom-scheme dispatch log: the OS records every app link it hands out —
       * on a compromised device a malicious app registered the same scheme. */
      if (/^[a-z][a-z0-9+.-]*:/i.test(client.redirect) && !/^https?:/i.test(client.redirect)) {
        db.prepare('INSERT INTO intercepted_links (url, ts) VALUES (?,?)').run(loc, ctx.nowIso());
      }
      res.redirect(302, loc);
    });
    ctx.app.post('/oauth/token', (req, res) => {
      const b = req.body || {};
      const row = db.prepare('SELECT * FROM auth_codes WHERE code = ?').get(String(b.code || ''));
      if (!row || row.used) return res.status(400).json({ error: 'invalid_grant' });
      if (new Date(row.expires_at) < new Date()) return res.status(400).json({ error: 'invalid_grant' });
      if (row.code_challenge) {
        /* when a challenge WAS sent, verify S256 (correct behavior) */
        const expect = b64url(ctx.crypto.createHash('sha256').update(String(b.code_verifier || '')).digest());
        if (!b.code_verifier || expect !== row.code_challenge) return res.status(400).json({ error: 'invalid_grant: PKCE verification failed' });
      }
      /* THE FLAW (exchange side): no challenge stored → no verifier required. */
      db.prepare('UPDATE auth_codes SET used = 1 WHERE code = ?').run(row.code);
      res.json({ access_token: signToken({ sub: row.sub, scope: row.scope, cid: row.client_id }),
        token_type: 'Bearer', expires_in: 3600, scope: row.scope, sub: row.sub });
    });
    ctx.app.get('/oauth/userinfo', (req, res) => {
      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
      const p = m && verifyToken(m[1]);
      if (!p) return res.status(401).json({ error: 'Bearer token required' });
      const acct = socialBySub(p.sub);
      res.json({ sub: p.sub, email: acct ? acct.email : null, name: acct ? acct.name : null });
    });

    /* ------------------------- client app: "FitSync" ------------------------- */
    ctx.app.get('/app', (req, res) => {
      const count = db.prepare('SELECT COUNT(*) c FROM intercepted_links').get().c;
      res.type('html').send(render('FitSync', `
        <h1>FitSync</h1>
        <div class="card">
          <p>Mobile app sign-in uses the custom scheme <code>${esc(APP_REDIRECT)}</code>.</p>
          <p>Test device — <b>app-link dispatch log</b> (${count} entries): <a href="/intercepted">/intercepted</a></p>
        </div>
        <p class="muted">Authorize URL used by the app:
        <code>/oauth/authorize?client_id=mobile&redirect_uri=${encodeURIComponent(APP_REDIRECT)}&response_type=code&scope=read</code>
        (the real app also sends a PKCE code_challenge — anything that talks to the AS may forget it).</p>`));
    });
    ctx.app.get('/intercepted', (req, res) => {
      const rows = db.prepare('SELECT * FROM intercepted_links ORDER BY id DESC LIMIT 50').all();
      res.type('html').send(render('Intercepted app links', `
        <h1>App-link dispatch log (test device)</h1>
        <p class="muted">Custom-scheme URLs the OS would hand to whichever app registered the scheme.
        A malicious app on this device has registered <code>${esc(APP_REDIRECT)}</code> too — it receives every link below.</p>
        <table><tr><th>time</th><th>dispatched URL</th></tr>
        ${rows.map((r) => `<tr><td>${esc(r.ts)}</td><td><code>${esc(r.url)}</code></td></tr>`).join('') || '<tr><td colspan="2" class="muted">no links yet</td></tr>'}
        </table>`));
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
      if (!p) return res.status(401).json({ error: 'Bearer token required (exchange the intercepted code at /oauth/token — no verifier needed)' });
      if (p.sub !== INNOCENT_SUB) return res.status(403).json({ error: 'token identity is not the innocent user', your_sub: p.sub });
      res.json({ flag: ctx.flags.held('OAUTH', 'NoPkce'), sub: p.sub });
    });
  },
};
