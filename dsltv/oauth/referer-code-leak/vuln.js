'use strict';
/*
 * DSLTV oauth/referer-code-leak — RefererCodeLeak (identity-gated, medium).
 * "PixelFeed" — photo feed with social SSO ("FeedID").
 * Flaw: the /oauth/callback page loads a third-party analytics script while
 * the authorization code is still live in the URL, and sends no
 * Referrer-Policy — the victim's browser leaks the full callback URL
 * (including ?code=) to the attacker-hosted asset via the Referer header.
 * Win: walk the victim through /login (bot, sso), read the leaked code from
 * /leaks (asset hit with Referer), exchange it, and present the token at /flag.
 */
module.exports = {
  meta: {
    category: 'OAUTH', subName: 'RefererCodeLeak', archetype: 'identity-gated', difficulty: 'medium',
    description: 'PixelFeed — the SSO callback leaks the live authorization code to an attacker-hosted asset via Referer. Entry: http://victim.target.lab:8119/app',
    flags: [{ category: 'OAUTH', subName: 'RefererCodeLeak', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const db = ctx.db;
    const esc = ctx.esc;
    const render = ctx.render;
    const REGISTERED = `http://victim.${ctx.labDomain}:8119/oauth/callback`;
    const ANALYTICS = `http://attacker.${ctx.labDomain}:8119/analytics.js`;

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
      return { sub: row.sub, scope: row.scope };
    };

    /* -------------------- mini Authorization Server: "FeedID" -------------------- */
    ctx.app.get('/oauth/login', (req, res) => {
      res.type('html').send(render('FeedID — sign in', `
        <h1>FeedID (Authorization Server)</h1>
        <div class="card"><form method="POST" action="/oauth/login">
          <p><input name="email" placeholder="email" size="32" required>
             <input name="password" type="password" placeholder="password" size="24" required>
             <button>sign in</button></p></form></div>
        <p class="muted"><a href="/social">Register a social identity</a></p>`));
    });
    ctx.app.post('/oauth/login', (req, res) => {
      const acct = db.prepare('SELECT * FROM social_accounts WHERE email = ?').get(String((req.body || {}).email || ''));
      if (!acct || acct.password !== String((req.body || {}).password || '')) {
        return res.status(401).type('html').send(render('FeedID', '<p>Invalid credentials.</p>'));
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
      res.type('html').send(render('FeedID — panel', `
        <h1>AS session</h1><table>
        <tr><th>sub</th><td>${esc(acct.sub)}</td></tr><tr><th>email</th><td>${esc(acct.email)}</td></tr></table>`));
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
      if (String(q.client_id || '') !== 'web') return res.status(400).json({ error: 'unknown client_id' });
      if (String(q.redirect_uri || '') !== REGISTERED) return res.status(400).json({ error: 'invalid redirect_uri' });
      if (String(q.response_type || '') !== 'code') return res.status(400).json({ error: 'unsupported response_type' });
      const s = asSession(req);
      if (!s) return res.status(401).type('html').send(render('FeedID', '<p>AS login required. <a href="/oauth/login">sign in</a></p>'));
      const code = ctx.randHex(24);
      db.prepare('INSERT INTO auth_codes (code, sub, client_id, redirect_uri, scope, used, expires_at, created_at) VALUES (?,?,?,?,?,0,?,?)')
        .run(code, s.sub, 'web', REGISTERED, String(q.scope || 'read'),
          new Date(Date.now() + 10 * 60 * 1000).toISOString(), ctx.nowIso());
      res.redirect(302, REGISTERED + '?code=' + code + (q.state ? '&state=' + encodeURIComponent(String(q.state)) : ''));
    });
    ctx.app.post('/oauth/token', (req, res) => {
      const grant = exchangeCode((req.body || {}).code);
      if (!grant) return res.status(400).json({ error: 'invalid_grant' });
      res.json({ access_token: signToken({ sub: grant.sub, scope: grant.scope }), token_type: 'Bearer', expires_in: 3600, scope: grant.scope, sub: grant.sub });
    });
    ctx.app.get('/oauth/userinfo', (req, res) => {
      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
      const p = m && verifyToken(m[1]);
      if (!p) return res.status(401).json({ error: 'Bearer token required' });
      const acct = socialBySub(p.sub);
      res.json({ sub: p.sub, email: acct ? acct.email : null, name: acct ? acct.name : null });
    });

    /* ------------------------- client app: "PixelFeed" ------------------------- */
    ctx.app.get('/app', (req, res) => {
      const auth = ctx.session.get(req);
      res.type('html').send(render('PixelFeed', `
        <h1>PixelFeed</h1>
        ${auth ? `<p>Signed in as <b>${esc(auth.user.username)}</b> — your feed loads below.</p>
        <div class="card"><p class="muted">[photo grid placeholder]</p></div>` : `
        <div class="card"><p><a href="/login">Sign in with FeedID (SSO)</a></p></div>`}
        <p class="muted">SSO flow: /login → FeedID authorize → /oauth/callback (third-party analytics included).</p>`));
    });
    ctx.app.get('/login', (req, res) => {
      res.redirect(302, `/oauth/authorize?client_id=web&redirect_uri=${encodeURIComponent(REGISTERED)}&response_type=code&scope=read&state=${ctx.randHex(8)}`);
    });
    ctx.app.get('/oauth/callback', (req, res) => {
      /*
       * THE FLAW: the code stays live in the URL while this page loads an
       * attacker-hosted script, and no Referrer-Policy is sent — the browser's
       * default (no-referrer-when-downgrade) leaks the full URL incl. ?code=.
       */
      const code = String((req.query || {}).code || '');
      const state = String((req.query || {}).state || '');
      res.type('html').send(render('Finishing sign-in…', `
        <h1>Finishing sign-in…</h1>
        <p>Please wait, completing your FeedID sign-in.</p>
        <form method="POST" action="/callback/complete">
          <input type="hidden" name="code" value="${esc(code)}">
          <input type="hidden" name="state" value="${esc(state)}">
          <p><button>Complete sign-in</button></p>
        </form>
        <p class="muted">page analytics: <code>${esc(ANALYTICS)}</code></p>
        <script src="${esc(ANALYTICS)}"></script>`));
    });
    ctx.app.post('/callback/complete', (req, res) => {
      const grant = exchangeCode(String((req.body || {}).code || ''));
      if (!grant) return res.status(400).type('html').send(render('PixelFeed', '<p>Invalid or used code.</p>'));
      const acct = socialBySub(grant.sub);
      const auth = ctx.session.get(req);
      if (auth) {
        db.prepare('INSERT OR IGNORE INTO linked_identities (client_user_id, social_sub, created_at) VALUES (?,?,?)')
          .run(auth.user.id, grant.sub, ctx.nowIso());
      }
      res.type('html').send(render('Signed in', `
        <p>Signed in via FeedID as <b>${esc(acct ? acct.email : grant.sub)}</b>.</p>`));
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
      if (!p) return res.status(401).json({ error: 'Bearer token required (exchange the leaked code at /oauth/token)' });
      if (p.sub !== INNOCENT_SUB) return res.status(403).json({ error: 'token identity is not the innocent user', your_sub: p.sub });
      res.json({ flag: ctx.flags.held('OAUTH', 'RefererCodeLeak'), sub: p.sub });
    });
  },
};
