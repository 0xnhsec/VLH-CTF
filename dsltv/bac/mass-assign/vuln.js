'use strict';
/*
 * DSLTV BAC/MassAssign — "SignupDirect".
 * Bug: POST /register binds the whole request body onto the new user row,
 * including `role`. Register with role=admin, then open the (properly
 * role-checked) /admin/panel for the resource-resident flag.
 */
module.exports = {
  meta: {
    category: 'BAC',
    subName: 'MassAssign',
    archetype: 'resource-resident',
    difficulty: 'medium',
    description: 'SignupDirect registration: POST /register mass-binds body fields onto the user row — the role field is client-controlled.',
    flags: [{ category: 'BAC', subName: 'MassAssign', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session, db } = ctx;

    const isJson = (req) => /json/i.test(String(req.headers['content-type'] || '')) || /json/i.test(String(req.headers.accept || ''));

    const registerPage = (msg) => render('SignupDirect — register', `
      <h1>✦ SignupDirect</h1>
      <p class="muted">self-service onboarding — vault operations platform</p>
      <div class="card">
        <form method="POST" action="/register">
          <p><input name="username" placeholder="choose a username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="choose a password" required></p>
          <p><button>create account</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">roles are provisioned by the platform after onboarding.</p>
      </div>
      <div class="card">
        <p>already registered?</p>
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" size="14"> <input name="password" type="password" placeholder="password" size="14"> <button>sign in</button></p>
        </form>
        <p class="muted">demo accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>`);

    /* THE BUG: the whole body is bound onto the INSERT — `role` included. */
    app.post('/register', (req, res) => {
      const b = req.body || {};
      const username = String(b.username || '').trim().slice(0, 40);
      const password = String(b.password || '');
      if (!username || !password) {
        return res.status(400).type('html').send(registerPage('username and password are required'));
      }
      if (users.byUsername(username)) {
        return res.status(409).type('html').send(registerPage('username already taken'));
      }
      const role = String(b.role === undefined ? 'user' : b.role).slice(0, 32); // client-controlled
      const r = db.prepare(`INSERT INTO users (username, password, role, email, api_key, created_at)
                            VALUES (?,?,?,?,?,?)`)
        .run(username, password, role, `${username}@${ctx.labDomain}`, ctx.randHex(32), ctx.nowIso());
      const user = users.byId(r.lastInsertRowid);
      ctx.login(res, user);
      if (isJson(req)) return res.json({ ok: true, username: user.username, role: user.role });
      res.redirect('/');
    });

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(registerPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* properly role-checked gate — the tampered row must really say admin */
    app.get('/admin/panel', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).type('html').send(registerPage('login required'));
      const u = users.byId(auth.user.id);
      if (u.role !== 'admin') {
        return res.status(403).type('html').send(render('Vault Ops', `
          <h1>Vault Ops</h1><p class="flag">403 — vault operations require the admin role (you are ${esc(u.role)}).</p>
          <p><a href="/">back</a></p>`));
      }
      res.type('html').send(render('Vault Ops', `
        <h1>Vault Ops</h1>
        <div class="card"><table>
          <tr><th>safe</th><th>status</th></tr>
          <tr><td>S-01</td><td>sealed</td></tr>
          <tr><td>S-02</td><td>sealed</td></tr>
          <tr><td>S-03</td><td>open for audit</td></tr>
        </table></div>
        <div class="card"><p>audit key (admin only):<br><span class="flag">${esc(flags.held('BAC', 'MassAssign'))}</span></p></div>`));
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(registerPage());
      const u = users.byId(auth.user.id);
      res.type('html').send(render('SignupDirect', `
        <h1>✦ SignupDirect</h1>
        <p>welcome, <b>${esc(u.username)}</b> · role <code>${esc(u.role)}</code> · <a href="/logout">sign out</a></p>
        <p class="muted"><a href="/admin/panel">Vault Ops</a> (admin role required)</p>`));
    });

    /* base registers a fallback GET / before setup() runs and express dispatches
       in registration order — move this lab's themed landing to the front. */
    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
