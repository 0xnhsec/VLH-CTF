'use strict';
/*
 * DSLTV oauth/implicit-grant-abuse — ImplicitGrantAbuse (identity-gated, high).
 * "QuickSign" — e-signature web app with a "mobile webview" sign-in.
 * Flaw: the AS still supports the implicit grant (response_type=token) for the
 * mobile client: the access token is returned in the URL fragment, where the
 * webview page's script (and anyone who can read the URL) can capture it.
 * Win: drive the victim (bot, sso) through /login?flow=token — the bot's hop
 * list exposes the final URL INCLUDING the #fragment with the innocent's
 * access token; present it at /flag.
 */
module.exports = {
  meta: {
    category: 'OAUTH', subName: 'ImplicitGrantAbuse', archetype: 'identity-gated', difficulty: 'high',
    description: 'QuickSign — implicit grant still enabled: the access token rides in the URL fragment of the mobile webview callback. Entry: http://victim.target.lab:8119/app',
    flags: [{ category: 'OAUTH', subName: 'ImplicitGrantAbuse', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const db = ctx.db;
    const esc = ctx.esc;
    const render = ctx.render;
    const CODE_REDIRECT = `http://victim.${ctx.labDomain}:8119/oauth/callback`;
    const IMPLICIT_REDIRECT = `http://victim.${ctx.labDomain}:8119/oauth/implicit/callback`;

    db.exec(`
      CREATE TABLE IF NOT EXISTS social_accounts (sub TEXT PRIMARY KEY, email TEXT, name TEXT, password TEXT, created_at TEXT);
      CREATE TABLE IF NOT EXISTS as_sessions (asid TEXT PRIMARY KEY, sub TEXT, created_at TEXT);
      CREATE TABLE IF NOT EXISTS auth_codes (code TEXT PRIMARY KEY, sub TEXT, client_id TEXT, redirect_uri TEXT,
        scope TEXT, used INTEGER DEFAULT 0, expires_at TEXT, created_at TEXT);
      CREATE TABLE IF NOT EXISTS tokens_issued (jti TEXT PRIMARY KEY, sub TEXT, scope TEXT, flow TEXT, created_at TEXT);
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
    const issueToken = (sub, scope, flow) => {
      const jti = ctx.randHex(12);
      db.prepare('INSERT INTO tokens_issued (jti, sub, scope, flow, created_at) VALUES (?,?,?,?,?)')
        .run(jti, sub, scope, flow, ctx.nowIso());
      return signToken({ sub, scope, jti });
    };

    /* -------------------- mini Authorization Server: "SignID" -------------------- */
    ctx.app.get('/oauth/login', (req, res) => {
      res.type('html').send(render('SignID — sign in', `
        <h1>SignID (Authorization Server)</h1>
        <div class="card"><form method="POST" action="/oauth/login">
          <p><input name="email" placeholder="email" size="32" required>
             <input name="password" type="password" placeholder="password" size="24" required>
             <button>sign in</button></p></form></div>
        <p class="muted"><a href="/social">Register a social identity</a></p>`));
    });
    ctx.app.post('/oauth/login', (req, res) => {
      const acct = db.prepare('SELECT * FROM social_accounts WHERE email = ?').get(String((req.body || {}).email || ''));
      if (!acct || acct.password !== String((req.body || {}).password || '')) {
        return res.status(401).type('html').send(render('SignID', '<p>Invalid credentials.</p>'));
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
      res.type('html').send(render('SignID — panel', `
        <h1>AS session</h1><table>
        <tr><th>sub</th><td>${esc(acct.sub)}</td></tr><tr><th>email</th><td>${esc(acct.email)}</td></tr></table>
        <p class="muted">grants: authorization_code (web) · implicit — legacy mobile webview (deprecated but still enabled)</p>`));
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
      const rt = String(q.response_type || 'code');
      const s = asSession(req);
      if (!s) return res.status(401).type('html').send(render('SignID', '<p>AS login required. <a href="/oauth/login">sign in</a></p>'));
      const scope = String(q.scope || 'read');
      if (rt === 'code') {
        if (String(q.redirect_uri || '') !== CODE_REDIRECT) return res.status(400).json({ error: 'invalid redirect_uri' });
        const code = ctx.randHex(24);
        db.prepare('INSERT INTO auth_codes (code, sub, client_id, redirect_uri, scope, used, expires_at, created_at) VALUES (?,?,?,?,?,0,?,?)')
          .run(code, s.sub, 'web', CODE_REDIRECT, scope,
            new Date(Date.now() + 10 * 60 * 1000).toISOString(), ctx.nowIso());
        return res.redirect(302, CODE_REDIRECT + '?code=' + code + (q.state ? '&state=' + encodeURIComponent(String(q.state)) : ''));
      }
      if (rt === 'token') {
        /* THE FLAW: implicit grant still enabled — token returned in the URL fragment */
        if (String(q.redirect_uri || '') !== IMPLICIT_REDIRECT) return res.status(400).json({ error: 'invalid redirect_uri' });
        const token = issueToken(s.sub, scope, 'implicit');
        const frag = '#access_token=' + encodeURIComponent(token)
          + '&token_type=Bearer&expires_in=3600&scope=' + encodeURIComponent(scope) + '&sub=' + encodeURIComponent(s.sub);
        return res.redirect(302, IMPLICIT_REDIRECT + frag);
      }
      return res.status(400).json({ error: 'unsupported response_type' });
    });
    ctx.app.post('/oauth/token', (req, res) => {
      const grant = exchangeCode((req.body || {}).code);
      if (!grant) return res.status(400).json({ error: 'invalid_grant' });
      res.json({ access_token: issueToken(grant.sub, grant.scope, 'code'), token_type: 'Bearer', expires_in: 3600, scope: grant.scope, sub: grant.sub });
    });
    ctx.app.get('/oauth/userinfo', (req, res) => {
      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
      const p = m && verifyToken(m[1]);
      if (!p) return res.status(401).json({ error: 'Bearer token required' });
      const acct = socialBySub(p.sub);
      res.json({ sub: p.sub, email: acct ? acct.email : null, name: acct ? acct.name : null });
    });

    /* ------------------------- client app: "QuickSign" ------------------------- */
    ctx.app.get('/app', (req, res) => {
      const auth = ctx.session.get(req);
      res.type('html').send(render('QuickSign', `
        <h1>QuickSign — e-signature</h1>
        ${auth ? '<p>You are signed in. Documents: <span class="muted">[list placeholder]</span></p>' : '<p>Not signed in.</p>'}
        <div class="card">
          <p><a href="/login">Sign in with SignID (web)</a></p>
          <p><a href="/login?flow=token">Sign in with SignID (mobile webview)</a> <span class="muted">— legacy flow</span></p>
        </div>`));
    });
    ctx.app.get('/login', (req, res) => {
      if (String(req.query.flow || '') === 'token') {
        return res.redirect(302, `/oauth/authorize?client_id=web&redirect_uri=${encodeURIComponent(IMPLICIT_REDIRECT)}&response_type=token&scope=read`);
      }
      res.redirect(302, `/oauth/authorize?client_id=web&redirect_uri=${encodeURIComponent(CODE_REDIRECT)}&response_type=code&scope=read&state=${ctx.randHex(8)}`);
    });
    ctx.app.get('/oauth/callback', (req, res) => {
      const grant = exchangeCode(String((req.query || {}).code || ''));
      if (!grant) return res.status(400).type('html').send(render('QuickSign', '<p>Invalid or used code.</p>'));
      const acct = socialBySub(grant.sub);
      res.type('html').send(render('Signed in', `<p>Signed in via SignID as <b>${esc(acct ? acct.email : grant.sub)}</b> (sub <code>${esc(grant.sub)}</code>).</p>`));
    });
    ctx.app.get('/oauth/implicit/callback', (req, res) => {
      /* "mobile webview simulation": the page's script reads location.hash and
       * displays the fragment — the token is fully exposed to page JS / URL observers. */
      res.type('html').send(render('QuickSign mobile webview', `
        <h1>QuickSign — mobile webview</h1>
        <div class="card"><p>Restoring session from webview URL…</p>
        <p>Fragment: <code id="frag">(enable JavaScript)</code></p></div>
        <script>
          var h = (location.hash || '').replace(/^#/, '');
          document.getElementById('frag').textContent = h;
          var p = new URLSearchParams(h);
          if (p.get('access_token')) {
            fetch('/app/webview-session', { method: 'POST', headers: { 'Authorization': 'Bearer ' + p.get('access_token') } });
          }
        </script>`));
    });
    ctx.app.post('/app/webview-session', (req, res) => {
      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
      const p = m && verifyToken(m[1]);
      if (!p) return res.status(401).json({ error: 'invalid token' });
      res.json({ ok: true, sub: p.sub, note: 'webview session restored' });
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
      if (!p) return res.status(401).json({ error: 'Bearer token required (capture the implicit-flow fragment)' });
      if (p.sub !== INNOCENT_SUB) return res.status(403).json({ error: 'token identity is not the innocent user', your_sub: p.sub });
      res.json({ flag: ctx.flags.held('OAUTH', 'ImplicitGrantAbuse'), sub: p.sub });
    });
  },
};
