'use strict';
/*
 * DSLTV http/host-reset-poison — HostResetPoison (location-locked, high).
 * "NoteKeep" — notes portal with an email-based password reset.
 * Flaw: the app builds reset links from the *effective host*, trusting the
 * X-Forwarded-Host header it believes its edge proxy always sets ("we are
 * behind a proxy that rewrites Host"). A request carrying
 * X-Forwarded-Host: evil.target.lab poisons the mailed reset link so it points
 * into attacker space (catch-all *.target.lab), handing the reset token to the
 * attacker host. Solo play: the token is in the mailed link — reuse it at the
 * real /reset to take over the innocent account.
 * Gate: /flag requires a session that IS the innocent user AND was created by
 * the reset flow (auth_method=reset).
 */
module.exports = {
  meta: {
    category: 'HTTP', subName: 'HostResetPoison', archetype: 'location-locked', difficulty: 'high',
    description: 'NoteKeep — password-reset links are built from attacker-controllable X-Forwarded-Host. Entry: http://victim.target.lab:8119/home',
    flags: [{ category: 'HTTP', subName: 'HostResetPoison', archetype: 'location-locked' }],
  },
  async setup(ctx) {
    const db = ctx.db;
    const esc = ctx.esc;
    const render = ctx.render;
    const innocent = ctx.users.innocent();

    db.exec(`
      CREATE TABLE IF NOT EXISTS reset_tokens (token TEXT PRIMARY KEY, user_id INTEGER, used INTEGER DEFAULT 0,
        expires_at TEXT, created_at TEXT, link_host TEXT);
    `);

    /* "behind our edge proxy": the app prefers X-Forwarded-Host when present (THE FLAW) */
    const effectiveHost = (req) => {
      const xfh = req.headers['x-forwarded-host'];
      const raw = (Array.isArray(xfh) ? xfh[0] : xfh) || req.headers.host || `victim.${ctx.labDomain}:8119`;
      return String(raw);
    };

    ctx.app.get('/home', (req, res) => {
      const auth = ctx.session.get(req);
      res.type('html').send(render('NoteKeep', `
        <h1>NoteKeep — your notes, kept.</h1>
        ${auth ? `<p>Signed in as <b>${esc(auth.user.username)}</b> (auth_method=${esc(auth.session.auth_method)}).</p>
        <div class="card"><p class="muted">[your notes]</p></div>` : `
        <div class="card">
          <form method="POST" action="/login"><p><input name="username" placeholder="username" size="16">
            <input name="password" type="password" placeholder="password" size="16"> <button>sign in</button></p></form>
          <form method="POST" action="/forgot"><p><input name="username" placeholder="username" size="16">
            <button>send password reset mail</button></p></form>
        </div>`}
        <p class="muted">Public directory: <a href="/directory">/directory</a> · reset link host comes from the
        request's effective host (proxy headers honored).</p>`));
    });
    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(String((req.body || {}).username || ''), String((req.body || {}).password || ''));
      if (!u) return res.status(401).type('html').send(render('NoteKeep', '<p>Bad credentials.</p>'));
      ctx.login(res, u, { authMethod: 'password' });
      res.redirect(302, '/home');
    });
    ctx.app.get('/directory', (req, res) => {
      const users = db.prepare('SELECT username, email FROM users ORDER BY id').all();
      res.type('html').send(render('Directory', `
        <h1>NoteKeep directory</h1>
        <table><tr><th>username</th><th>email</th></tr>
        ${users.map((u) => `<tr><td>${esc(u.username)}</td><td>${esc(u.email || '')}</td></tr>`).join('')}</table>`));
    });

    ctx.app.post('/forgot', (req, res) => {
      const username = String((req.body || {}).username || '');
      const u = ctx.users.byUsername(username);
      const host = effectiveHost(req);
      if (u) {
        const token = ctx.randHex(24);
        db.prepare('INSERT INTO reset_tokens (token, user_id, used, expires_at, created_at, link_host) VALUES (?,?,0,?,?,?)')
          .run(token, u.id, new Date(Date.now() + 30 * 60 * 1000).toISOString(), ctx.nowIso(), host);
        const link = `http://${host}/reset?token=${token}`;
        ctx.mail.send({
          to: u.email,
          subject: 'NoteKeep password reset',
          body: `Hello ${u.username},\n\nReset your NoteKeep password within 30 minutes:\n\n${link}\n\nIf you did not request this, ignore this mail.`,
        });
      }
      res.type('html').send(render('Reset requested', `
        <p>If the account exists, a reset link has been mailed (see the <a href="http://mail.${esc(ctx.labDomain)}:8119/">mail UI</a>).</p>
        <p class="muted">Link base for this request: <code>http://${esc(host)}</code></p>`));
    });

    ctx.app.get('/reset', (req, res) => {
      const token = String((req.query || {}).token || '');
      if (!token) return res.status(400).type('html').send(render('Reset', '<p>missing token</p>'));
      res.type('html').send(render('Set a new password', `
        <form method="POST" action="/reset">
          <input type="hidden" name="token" value="${esc(token)}">
          <p><input name="new_password" type="password" placeholder="new password" size="24" required>
             <button>reset password</button></p>
        </form>`));
    });
    ctx.app.post('/reset', (req, res) => {
      const { token, new_password } = req.body || {};
      const row = db.prepare('SELECT * FROM reset_tokens WHERE token = ?').get(String(token || ''));
      if (!row || row.used || new Date(row.expires_at) < new Date()) {
        return res.status(400).type('html').send(render('Reset', '<p>Invalid, used or expired token.</p>'));
      }
      db.prepare('UPDATE reset_tokens SET used = 1 WHERE token = ?').run(row.token);
      const u = ctx.users.byId(row.user_id);
      if (!u) return res.status(400).type('html').send(render('Reset', '<p>Unknown account.</p>'));
      db.prepare('UPDATE users SET password = ? WHERE id = ?').run(String(new_password || ''), u.id);
      /* the reset flow signs the user straight in — the session's provenance records how it was created */
      ctx.login(res, u, { authMethod: 'reset' });
      res.type('html').send(render('Password reset', `
        <p>Password reset complete — you are signed in as <b>${esc(u.username)}</b>.</p>`));
    });

    /* ------------------------------- flag gate ------------------------------- */
    ctx.app.get('/flag', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'sign-in session required' });
      if (auth.user.username !== innocent.username) {
        return res.status(403).json({ error: 'session is not the innocent user', you: auth.user.username });
      }
      if (auth.session.auth_method !== 'reset') {
        return res.status(403).json({ error: 'session provenance must be auth_method=reset', auth_method: auth.session.auth_method });
      }
      res.json({ flag: ctx.flags.held('HTTP', 'HostResetPoison'), sub: auth.user.username, auth_method: auth.session.auth_method });
    });
  },
};
