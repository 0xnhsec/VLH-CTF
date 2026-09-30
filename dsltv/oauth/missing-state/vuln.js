'use strict';
/*
 * DSLTV oauth/missing-state — MissingState (identity-gated, high).
 * "CloudVault" — file-share portal with SSO account linking.
 * Flaw: the client /oauth/callback does NOT validate the `state` parameter
 * (login CSRF). The callback exchanges whatever code arrives and LINKS the
 * incoming social identity to the CURRENT client session's account.
 * Win: attacker obtains a code for their OWN social identity, then gets the
 * victim (bot, sso → innocent client session) to visit /oauth/callback?code=
 * <attacker code> → linked_identities gains row (innocent, attacker_sub).
 */
module.exports = {
  meta: {
    category: 'OAUTH', subName: 'MissingState', archetype: 'identity-gated', difficulty: 'high',
    description: 'CloudVault SSO linking — the callback ignores state (login CSRF), so the victim can be made to link the attacker\'s social identity. Entry: http://victim.target.lab:8119/app',
    flags: [{ category: 'OAUTH', subName: 'MissingState', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const db = ctx.db;
    const esc = ctx.esc;
    const render = ctx.render;
    const REGISTERED = `http://victim.${ctx.labDomain}:8119/oauth/callback`;

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
    const link = (clientUserId, sub) => db.prepare('INSERT OR IGNORE INTO linked_identities (client_user_id, social_sub, created_at) VALUES (?,?,?)')
      .run(clientUserId, sub, ctx.nowIso());

    /* ------------------- mini Authorization Server: "VaultID" ------------------- */
    ctx.app.get('/oauth/login', (req, res) => {
      res.type('html').send(render('VaultID — sign in', `
        <h1>VaultID (Authorization Server)</h1>
        <div class="card"><form method="POST" action="/oauth/login">
          <p><input name="email" placeholder="email" size="32" required>
             <input name="password" type="password" placeholder="password" size="24" required>
             <button>sign in</button></p>
        </form></div>
        <p class="muted"><a href="/social">Register a social identity</a></p>`));
    });
    ctx.app.post('/oauth/login', (req, res) => {
      const { email, password } = req.body || {};
      const acct = db.prepare('SELECT * FROM social_accounts WHERE email = ?').get(String(email || ''));
      if (!acct || acct.password !== String(password || '')) {
        return res.status(401).type('html').send(render('VaultID', '<p>Invalid credentials.</p>'));
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
      res.type('html').send(render('VaultID — panel', `
        <h1>AS session</h1><table>
        <tr><th>sub</th><td>${esc(acct.sub)}</td></tr><tr><th>email</th><td>${esc(acct.email)}</td></tr></table>
        <p class="muted">client <code>web</code> → redirect_uri <code>${esc(REGISTERED)}</code></p>`));
    });
    ctx.app.get('/social', (req, res) => {
      res.type('html').send(render('Register social identity', `
        <h1>Register a social identity</h1>
        <div class="card"><form method="POST" action="/social/register">
          <p><input name="email" placeholder="email" size="32" required></p>
          <p><input name="name" placeholder="display name" size="32" required></p>
          <p><input name="password" type="password" placeholder="choose password" size="24" required></p>
          <p><button>create identity</button></p>
        </form></div>`));
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
      const ru = String(q.redirect_uri || '');
      if (ru !== REGISTERED) return res.status(400).json({ error: 'invalid redirect_uri (exact match required)' });
      if (String(q.response_type || '') !== 'code') return res.status(400).json({ error: 'unsupported response_type' });
      const s = asSession(req);
      if (!s) return res.status(401).type('html').send(render('VaultID', '<p>AS login required. <a href="/oauth/login">sign in</a></p>'));
      const code = ctx.randHex(24);
      db.prepare('INSERT INTO auth_codes (code, sub, client_id, redirect_uri, scope, used, expires_at, created_at) VALUES (?,?,?,?,?,0,?,?)')
        .run(code, s.sub, 'web', ru, String(q.scope || 'read'),
          new Date(Date.now() + 10 * 60 * 1000).toISOString(), ctx.nowIso());
      const loc = ru + (ru.includes('?') ? '&' : '?') + 'code=' + code + (q.state ? '&state=' + encodeURIComponent(String(q.state)) : '');
      res.redirect(302, loc);
    });
    ctx.app.post('/oauth/token', (req, res) => {
      const b = req.body || {};
      const grant = exchangeCode(b.code);
      if (!grant) return res.status(400).json({ error: 'invalid_grant' });
      res.json({ access_token: signToken({ sub: grant.sub, scope: grant.scope, cid: grant.client_id }),
        token_type: 'Bearer', expires_in: 3600, scope: grant.scope, sub: grant.sub });
    });
    ctx.app.get('/oauth/userinfo', (req, res) => {
      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
      const p = m && verifyToken(m[1]);
      if (!p) return res.status(401).json({ error: 'Bearer token required' });
      const acct = socialBySub(p.sub);
      res.json({ sub: p.sub, email: acct ? acct.email : null, name: acct ? acct.name : null });
    });

    /* ------------------------- client app: "CloudVault" ------------------------- */
    ctx.app.get('/app', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(render('CloudVault', `
          <h1>CloudVault</h1>
          <div class="card"><form method="POST" action="/app/login">
            <p><input name="username" placeholder="username" size="16">
               <input name="password" type="password" placeholder="password" size="16">
               <button>sign in</button></p></form></div>
          <p class="muted">After signing in, use "Link SSO identity" to attach your VaultID social login.</p>`));
      }
      const links = db.prepare('SELECT * FROM linked_identities WHERE client_user_id = ?').all(auth.user.id);
      res.type('html').send(render('CloudVault — dashboard', `
        <h1>CloudVault dashboard</h1>
        <p>Signed in as <b>${esc(auth.user.username)}</b> (auth_method=${esc(auth.session.auth_method)}).</p>
        <div class="card"><p><a href="/login">Link SSO identity (VaultID)</a></p></div>
        <table><tr><th>linked social sub</th><th>since</th></tr>
        ${links.map((l) => `<tr><td>${esc(l.social_sub)}</td><td>${esc(l.created_at)}</td></tr>`).join('') || '<tr><td colspan="2" class="muted">none</td></tr>'}</table>`));
    });
    ctx.app.post('/app/login', (req, res) => {
      const u = ctx.users.verify(String((req.body || {}).username || ''), String((req.body || {}).password || ''));
      if (!u) return res.status(401).type('html').send(render('CloudVault', '<p>Bad credentials.</p>'));
      ctx.login(res, u, { authMethod: 'password' });
      res.redirect(302, '/app');
    });
    ctx.app.get('/login', (req, res) => {
      const state = ctx.randHex(8);
      res.append('Set-Cookie', 'st=' + state + '; Path=/; HttpOnly; SameSite=Lax');
      res.redirect(302, `/oauth/authorize?client_id=web&redirect_uri=${encodeURIComponent(REGISTERED)}&response_type=code&scope=read&state=${state}`);
    });
    ctx.app.get('/oauth/callback', (req, res) => {
      /* THE FLAW: `state` is never validated — any code delivered here is processed. */
      const code = String((req.query || {}).code || '');
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).type('html').send(render('CloudVault', '<p>Client session required before SSO linking.</p>'));
      const grant = exchangeCode(code);
      if (!grant) return res.status(400).type('html').send(render('CloudVault', '<p>Invalid or used code.</p>'));
      const acct = socialBySub(grant.sub);
      link(auth.user.id, grant.sub);
      res.type('html').send(render('SSO linked', `
        <h1>SSO identity linked</h1>
        <p>Linked <b>${esc(acct ? acct.email : grant.sub)}</b> (sub <code>${esc(grant.sub)}</code>) to account <b>${esc(auth.user.username)}</b>.</p>`));
    });

    /* ---- victim bootstrap: innocent client session + AS session + legit link ---- */
    ctx.app.get('/__sso', (req, res) => {
      const asid = ctx.randHex(32);
      db.prepare('INSERT INTO as_sessions (asid, sub, created_at) VALUES (?,?,?)').run(asid, INNOCENT_SUB, ctx.nowIso());
      db.prepare('INSERT OR IGNORE INTO linked_identities (client_user_id, social_sub, created_at) VALUES (?,?,?)')
        .run(innocent.id, INNOCENT_SUB, ctx.nowIso());
      ctx.login(res, innocent, { authMethod: 'oauth_link' });
      res.append('Set-Cookie', 'as_sid=' + asid + '; Path=/; HttpOnly; SameSite=Lax');
      res.redirect(302, '/app');
    });

    /* ------------------------------- flag gate ------------------------------- */
    ctx.app.get('/flag', (req, res) => {
      /* gate: the innocent account is linked to a social identity that is NOT its own */
      const row = db.prepare('SELECT social_sub FROM linked_identities WHERE client_user_id = ? AND social_sub != ?')
        .get(innocent.id, INNOCENT_SUB);
      if (!row) {
        return res.status(403).json({ error: 'no foreign social identity linked to the innocent account yet' });
      }
      res.json({ flag: ctx.flags.held('OAUTH', 'MissingState'), linked_sub: row.social_sub });
    });
  },
};
