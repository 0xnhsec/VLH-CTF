'use strict';
/*
 * DSLTV AUTH/ResetTokenPredictable — "Keyhole".
 * Bug: password-reset tokens are md5(username + ':' + SECRET_SUFFIX)[0:12]
 * with a STATIC suffix. The tester's own reset mail leaks the token format
 * (incl. the suffix), and /forgot reveals which usernames exist (folded user
 * enumeration prerequisite). Predict the innocent user's token, take over
 * the account via POST /reset — the flag needs a session with provenance
 * auth_method=reset FOR the innocent account.
 */
module.exports = {
  meta: {
    category: 'AUTH',
    subName: 'ResetTokenPredictable',
    archetype: 'identity-gated',
    difficulty: 'high',
    description: 'Keyhole recovery: reset tokens derive predictably from the username with a static suffix — predict one, take the account over.',
    flags: [{ category: 'AUTH', subName: 'ResetTokenPredictable', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session, db, crypto } = ctx;

    const SECRET_SUFFIX = 'vlh-lab'; // static (the flaw — leaked via mail note)
    const TOKEN_TTL_MS = 15 * 60 * 1000;

    db.exec(`CREATE TABLE IF NOT EXISTS reset_tokens (
      token TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL
    )`);

    const mkToken = (username) => crypto.createHash('md5')
      .update(`${username}:${SECRET_SUFFIX}`).digest('hex').slice(0, 12);

    const isJson = (req) => /json/i.test(String(req.headers['content-type'] || '')) || /json/i.test(String(req.headers.accept || ''));

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).json({ error: 'invalid credentials' });
      ctx.login(res, user);
      res.json({ ok: true, signed_in: user.username });
    });

    /* legit leak: account directory (usernames only) */
    app.get('/api/users', (req, res) => {
      res.json({ users: users.all().map((u) => ({ username: u.username, role: u.role })) });
    });

    /* THE BUG (part 1): predictable token + user enumeration in the response */
    app.post('/forgot', (req, res) => {
      const username = String((req.body || {}).username || '');
      const user = users.byUsername(username);
      if (!user) {
        return res.status(404).json({ error: 'no such user', username });
      }
      const token = mkToken(username);
      db.prepare('INSERT OR REPLACE INTO reset_tokens (token, username, expires_at, created_at) VALUES (?,?,?,?)')
        .run(token, username, Date.now() + TOKEN_TTL_MS, ctx.nowIso());
      /* tester mailboxes are local (mail.target.lab); customer mail routes
         externally — only staff/tester resets are visible in the lab mailbox. */
      if (user.role === 'tester') {
        ctx.mail.send({
          to: user.email,
          subject: 'Keyhole password reset',
          body: `Hello ${username},\n\nSomeone requested a password reset for your account.\n` +
            `Reset link: ${ctx.urls.victim}/reset?token=${token}\n\n` +
            `This link expires in 15 minutes.\n\n` +
            `(dev note — legacy token pipeline: token = md5(username + ':' + SECRET_SUFFIX)[0:12], ` +
            `SECRET_SUFFIX = '${SECRET_SUFFIX}' — rotation ticket #4021 open since 2023)`,
        });
      }
      return res.json({ status: 'ok', message: 'reset link generated and sent to the registered mailbox' });
    });

    /* THE BUG (part 2): the token is accepted without any account binding a
       real random secret would give — a predicted token is as good as a mailed one. */
    app.post('/reset', (req, res) => {
      const { token, new_password } = req.body || {};
      const row = db.prepare('SELECT * FROM reset_tokens WHERE token = ?').get(String(token || ''));
      if (!row) return res.status(400).json({ error: 'unknown or already-used token' });
      if (row.expires_at < Date.now()) return res.status(400).json({ error: 'token expired' });
      const user = users.byUsername(row.username);
      if (!user) return res.status(400).json({ error: 'account vanished' });
      db.prepare('DELETE FROM reset_tokens WHERE token = ?').run(row.token);
      db.prepare('UPDATE users SET password = ? WHERE id = ?').run(String(new_password || ''), user.id);
      /* session with reset provenance — the flag gate requires exactly this */
      ctx.login(res, user, { authMethod: 'reset' });
      return res.json({ ok: true, reset_for: user.username, auth_method: 'reset' });
    });

    /* identity gate: innocent account + reset provenance (arch §7.5) */
    app.get('/flag', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const innocent = users.innocent();
      if (auth.user.username === innocent.username && auth.session.auth_method === 'reset') {
        return res.json({ ok: true, flag: flags.held('AUTH', 'ResetTokenPredictable') });
      }
      return res.status(403).json({
        error: 'the flag needs a reset-provenance session for the innocent account',
        you: { sub: auth.user.username, auth_method: auth.session.auth_method },
      });
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      res.type('html').send(render('Keyhole — account recovery', `
        <h1>🔑 Keyhole</h1>
        <p class="muted">account recovery portal · ${auth ? `signed in as <b>${esc(auth.user.username)}</b> (<a href="/logout">sign out</a>)` : 'not signed in'}</p>
        <div class="card">
          <p>sign in:</p>
          <form method="POST" action="/login" onsubmit="return postAsJson(this,'/login')">
            <p><input name="username" placeholder="username" size="14"> <input name="password" type="password" placeholder="password" size="14"> <button>sign in</button></p>
          </form>
          <p class="muted">testers: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
        </div>
        <div class="card">
          <p>forgot password (<code>POST /forgot {username}</code>):</p>
          <form method="POST" action="/forgot" onsubmit="return postAsJson(this,'/forgot')">
            <p><input name="username" placeholder="username" size="14"> <button>request reset</button></p>
          </form>
        </div>
        <div class="card">
          <p>reset (<code>POST /reset {token, new_password}</code>):</p>
          <form method="POST" action="/reset" onsubmit="return postAsJson(this,'/reset')">
            <p><input name="token" placeholder="reset token" size="16"> <input name="new_password" placeholder="new password" size="14"> <button>reset</button></p>
          </form>
        </div>
        <p class="muted">directory: <a href="/api/users">/api/users</a> · flag: <code>GET /flag</code> · mail: <a href="${ctx.urls.mail}">mail.target.lab</a></p>
        <script>
          function postAsJson(form, path){const f=new FormData(form);const o={};f.forEach((v,k)=>o[k]=v);
            fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(o)})
              .then(r=>r.json()).then(j=>{out.textContent=JSON.stringify(j,null,2);}).catch(e=>{out.textContent=String(e);});
            return false;}
        </script>
        <pre id="out">—</pre>`));
    });

    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
