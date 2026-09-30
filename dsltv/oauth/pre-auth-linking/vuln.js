'use strict';
/*
 * DSLTV oauth/pre-auth-linking — PreAuthLinking (identity-gated, high).
 * "TeamHub" — collaboration portal with username/password accounts, an open
 * team directory, and social SSO ("HubID").
 * Flaw: nothing verifies email ownership. Client registration MERGES new
 * credentials onto an existing account matched by email, and the SSO callback
 * links/logs in by EMAIL match against unverified social-identity emails.
 * Win: register a social identity carrying the innocent's email (leaked via
 * /api/profile/<innocent-username>), then SSO-login with it → the client links
 * the attacker's social sub to the innocent's account.
 */
module.exports = {
  meta: {
    category: 'OAUTH', subName: 'PreAuthLinking', archetype: 'identity-gated', difficulty: 'high',
    description: 'TeamHub — unverified email used as an identity key: pre-auth linking grafts the attacker\'s social identity onto the innocent account. Entry: http://victim.target.lab:8119/app',
    flags: [{ category: 'OAUTH', subName: 'PreAuthLinking', archetype: 'identity-gated' }],
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
      CREATE TABLE IF NOT EXISTS alt_creds (username TEXT PRIMARY KEY, user_id INTEGER, password TEXT, created_at TEXT);
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
    const link = (clientUserId, sub) => db.prepare('INSERT OR IGNORE INTO linked_identities (client_user_id, social_sub, created_at) VALUES (?,?,?)')
      .run(clientUserId, sub, ctx.nowIso());
    const loginAnywhere = (username, password) => {
      const u = ctx.users.verify(username, password);
      if (u) return u;
      const alt = db.prepare('SELECT * FROM alt_creds WHERE username = ?').get(String(username || ''));
      if (alt && alt.password === String(password || '')) return ctx.users.byId(alt.user_id) || null;
      return null;
    };

    /* -------------------- mini Authorization Server: "HubID" -------------------- */
    ctx.app.get('/oauth/login', (req, res) => {
      res.type('html').send(render('HubID — sign in', `
        <h1>HubID (Authorization Server)</h1>
        <div class="card"><form method="POST" action="/oauth/login">
          <p><input name="email" placeholder="email" size="32" required>
             <input name="password" type="password" placeholder="password" size="24" required>
             <button>sign in</button></p></form></div>
        <p class="muted"><a href="/social">Register a social identity</a></p>`));
    });
    ctx.app.post('/oauth/login', (req, res) => {
      const acct = db.prepare('SELECT * FROM social_accounts WHERE email = ?').get(String((req.body || {}).email || ''));
      if (!acct || acct.password !== String((req.body || {}).password || '')) {
        return res.status(401).type('html').send(render('HubID', '<p>Invalid credentials.</p>'));
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
      res.type('html').send(render('HubID — panel', `
        <h1>AS session</h1><table>
        <tr><th>sub</th><td>${esc(acct.sub)}</td></tr><tr><th>email</th><td>${esc(acct.email)}</td></tr></table>`));
    });
    ctx.app.get('/social', (req, res) => {
      res.type('html').send(render('Register social identity', `
        <h1>Register a social identity</h1>
        <div class="card"><form method="POST" action="/social/register">
          <p><input name="email" placeholder="email (any — not verified)" size="32" required></p>
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
      if (!s) return res.status(401).type('html').send(render('HubID', '<p>AS login required. <a href="/oauth/login">sign in</a></p>'));
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

    /* ------------------------- client app: "TeamHub" ------------------------- */
    ctx.app.get('/app', (req, res) => {
      const auth = ctx.session.get(req);
      res.type('html').send(render('TeamHub', `
        <h1>TeamHub</h1>
        ${auth ? `<p>Signed in as <b>${esc(auth.user.username)}</b> (auth_method=${esc(auth.session.auth_method)}).</p>` : '<p>Not signed in.</p>'}
        <div class="card">
          <form method="POST" action="/app/login"><p><input name="username" placeholder="username" size="16">
            <input name="password" type="password" placeholder="password" size="16"> <button>sign in</button></p></form>
          <p class="muted">or <a href="/login">Continue with HubID (social SSO)</a> · <a href="/app/register">Create account</a> · <a href="/team">Team directory</a></p>
        </div>`));
    });
    ctx.app.post('/app/login', (req, res) => {
      const u = loginAnywhere(String((req.body || {}).username || ''), String((req.body || {}).password || ''));
      if (!u) return res.status(401).type('html').send(render('TeamHub', '<p>Bad credentials.</p>'));
      ctx.login(res, u, { authMethod: 'password' });
      res.redirect(302, '/app');
    });
    ctx.app.get('/app/register', (req, res) => {
      res.type('html').send(render('Create account', `
        <h1>Create your TeamHub account</h1>
        <div class="card"><form method="POST" action="/app/register">
          <p><input name="username" placeholder="username" size="20" required></p>
          <p><input name="password" type="password" placeholder="password" size="20" required></p>
          <p><input name="email" placeholder="email" size="32" required></p>
          <p><button>create account</button></p></form></div>
        <p class="muted">Accounts are created instantly — email is used as the identity key (no verification).</p>`));
    });
    ctx.app.post('/app/register', (req, res) => {
      const { username, password, email } = req.body || {};
      if (!username || !password || !email) return res.status(400).type('html').send(render('Create account', '<p>username, password, email required</p>'));
      const existingEmail = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email));
      if (existingEmail) {
        /* THE FLAW (registration side): merge new credentials onto the account that owns this email */
        db.prepare('INSERT OR REPLACE INTO alt_creds (username, user_id, password, created_at) VALUES (?,?,?,?)')
          .run(String(username), existingEmail.id, String(password), ctx.nowIso());
        return res.type('html').send(render('Account merged', `
          <p>An account with this email already exists — for your convenience your new credentials have been
          <b>merged onto that account</b>. You can now sign in with <code>${esc(username)}</code>.</p>`));
      }
      db.prepare('INSERT INTO users (username, password, role, email, created_at) VALUES (?,?,?,?,?)')
        .run(String(username), String(password), 'user', String(email), ctx.nowIso());
      res.type('html').send(render('Account created', '<p>Account created — sign in at <a href="/app">/app</a>.</p>'));
    });
    ctx.app.get('/team', (req, res) => {
      const users = db.prepare('SELECT username FROM users ORDER BY id').all();
      res.type('html').send(render('Team directory', `
        <h1>Team directory</h1>
        <table><tr><th>member</th><th>profile</th></tr>
        ${users.map((u) => `<tr><td>${esc(u.username)}</td><td><a href="/api/profile/${esc(u.username)}">/api/profile/${esc(u.username)}</a></td></tr>`).join('')}
        </table>`));
    });
    ctx.app.get('/api/profile/:username', (req, res) => {
      const u = ctx.users.byUsername(String(req.params.username || ''));
      if (!u) return res.status(404).json({ error: 'no such member' });
      res.json({ username: u.username, email: u.email, title: u.role === 'admin' ? 'administrator' : 'member' });
    });
    ctx.app.get('/login', (req, res) => {
      res.redirect(302, `/oauth/authorize?client_id=web&redirect_uri=${encodeURIComponent(REGISTERED)}&response_type=code&scope=read&state=${ctx.randHex(8)}`);
    });
    ctx.app.get('/oauth/callback', (req, res) => {
      const grant = exchangeCode(String((req.query || {}).code || ''));
      if (!grant) return res.status(400).type('html').send(render('TeamHub', '<p>Invalid or used code.</p>'));
      const acct = socialBySub(grant.sub);
      if (!acct) return res.status(400).type('html').send(render('TeamHub', '<p>Unknown social identity.</p>'));
      /* THE FLAW (SSO side): account resolution by UNVERIFIED email match */
      const match = db.prepare('SELECT * FROM users WHERE email = ?').get(acct.email);
      if (!match) {
        return res.type('html').send(render('SSO sign-in', `
          <p>Signed in via HubID as <b>${esc(acct.email)}</b>, but no TeamHub account owns this email.</p>`));
      }
      link(match.id, grant.sub);
      ctx.login(res, match, { authMethod: 'oauth_link' });
      res.type('html').send(render('SSO sign-in', `
        <h1>SSO sign-in complete</h1>
        <p>Signed in via HubID as <b>${esc(acct.email)}</b> → TeamHub account <b>${esc(match.username)}</b>.</p>
        <p class="muted">Social sub ${esc(grant.sub)} linked to this account.</p>`));
    });

    /* -------- victim bootstrap: innocent client session (for exploring) -------- */
    ctx.app.get('/__sso', (req, res) => {
      ctx.login(res, innocent, { authMethod: 'oauth_link' });
      res.redirect(302, '/app');
    });

    /* ------------------------------- flag gate ------------------------------- */
    ctx.app.get('/flag', (req, res) => {
      const row = db.prepare('SELECT social_sub FROM linked_identities WHERE client_user_id = ? AND social_sub != ?')
        .get(innocent.id, INNOCENT_SUB);
      if (!row) return res.status(403).json({ error: 'no foreign social identity linked to the innocent account yet' });
      res.json({ flag: ctx.flags.held('OAUTH', 'PreAuthLinking'), linked_sub: row.social_sub });
    });
  },
};
