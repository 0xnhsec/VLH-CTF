'use strict';
/*
 * DSLTV AUTH/NoRateLimit — "Gatekeep".
 * Bug: POST /login has no rate limiting, no lockout, no delay scaling. A
 * legacy account `bknight` was migrated with a weak rockyou-style password.
 * Brute-force the login, then GET /flag (server-side check: the session must
 * belong to the bknight account).
 */
module.exports = {
  meta: {
    category: 'AUTH',
    subName: 'NoRateLimit',
    archetype: 'identity-gated',
    difficulty: 'low',
    description: 'Gatekeep portal: the login endpoint has no rate limit and a migrated account kept a weak rockyou-style password — brute-force it.',
    flags: [{ category: 'AUTH', subName: 'NoRateLimit', archetype: 'identity-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session, db } = ctx;

    /* seeded weak account (documented deviation: this one password is the
       challenge target — it is NOT printed anywhere in player scope). */
    if (!users.byUsername('bknight')) {
      db.prepare('INSERT INTO users (username, password, role, email, api_key, created_at) VALUES (?,?,?,?,?,?)')
        .run('bknight', 'dragon87', 'user', `bknight@${ctx.labDomain}`, ctx.randHex(32), ctx.nowIso());
    }

    const isJson = (req) => /json/i.test(String(req.headers['content-type'] || '')) || /json/i.test(String(req.headers.accept || ''));
    const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

    const loginPage = (msg) => render('Gatekeep — sign in', `
      <h1>🚪 Gatekeep</h1>
      <p class="muted">member portal — migrated from the old forum in 2019</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">member list: <a href="/api/users">/api/users</a> · note: some forum-era accounts kept weak passwords</p>`);

    /* THE BUG: unlimited attempts — no rate limit, no lockout, no captcha.
       The tiny artificial delay models password-hash latency, nothing more. */
    app.post('/login', async (req, res) => {
      const { username, password } = req.body || {};
      await sleep(50);
      const user = users.verify(username, password);
      if (!user) {
        if (isJson(req)) return res.status(401).json({ error: 'invalid credentials' });
        return res.status(401).type('html').send(loginPage('invalid credentials'));
      }
      ctx.login(res, user);
      if (isJson(req)) return res.json({ ok: true, signed_in: user.username });
      res.redirect('/');
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* legit leak: member directory (usernames only) */
    app.get('/api/users', (req, res) => {
      res.json({ users: users.all().map((u) => ({ username: u.username, role: u.role })) });
    });

    /* identity gate: server-side check that the session is the bknight account */
    app.get('/flag', (req, res) => {
      const auth = session.get(req);
      if (!auth) {
        if (isJson(req)) return res.status(401).json({ error: 'login required' });
        return res.status(401).type('html').send(loginPage('login required'));
      }
      if (auth.user.username !== 'bknight') {
        return res.status(403).json({ error: 'this flag is reserved for the bknight account (server-side check)' });
      }
      return res.json({ ok: true, account: 'bknight', flag: flags.held('AUTH', 'NoRateLimit') });
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const isKnight = auth.user.username === 'bknight';
      res.type('html').send(render('Gatekeep', `
        <h1>🚪 Gatekeep</h1>
        <p>welcome, <b>${esc(auth.user.username)}</b> · <a href="/logout">sign out</a></p>
        ${isKnight
          ? '<div class="card"><p>your member vault: <a href="/flag">/flag</a></p></div>'
          : '<div class="card"><p class="muted">member vault at <code>/flag</code> — reserved for the bknight account.</p></div>'}`));
    });

    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
