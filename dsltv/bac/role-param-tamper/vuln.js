'use strict';
/*
 * DSLTV BAC/RoleParamTamper — "FleetOps".
 * Bug: POST /api/profile binds the request body straight onto the account row,
 * including the `role` field. The web UI no longer renders a role input, but
 * the API still accepts it — self-promote to admin, then open the (properly
 * role-checked) /admin/panel for the resource-resident flag.
 */
module.exports = {
  meta: {
    category: 'BAC',
    subName: 'RoleParamTamper',
    archetype: 'resource-resident',
    difficulty: 'medium',
    description: 'FleetOps settings: POST /api/profile still binds the client-supplied role field — tamper the parameter to self-promote.',
    flags: [{ category: 'BAC', subName: 'RoleParamTamper', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session, db } = ctx;

    const loginPage = (msg) => render('FleetOps — sign in', `
      <h1>🛞 FleetOps</h1>
      <p class="muted">delivery fleet management</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>`);

    const isJson = (req) => /json/i.test(String(req.headers['content-type'] || '')) || /json/i.test(String(req.headers.accept || ''));

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    app.get('/api/profile', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const u = users.byId(auth.user.id);
      res.json({ username: u.username, email: u.email, role: u.role });
    });

    /* THE BUG: the profile update binds every body field — `role` included. */
    app.post('/api/profile', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const b = req.body || {};
      const email = String(b.email || '').slice(0, 120) || null;
      const role = b.role === undefined ? undefined : String(b.role).slice(0, 32); // client-controlled
      if (role === undefined) {
        db.prepare('UPDATE users SET email = ? WHERE id = ?').run(email, auth.user.id);
      } else {
        db.prepare('UPDATE users SET email = ?, role = ? WHERE id = ?').run(email, role, auth.user.id);
      }
      const u = users.byId(auth.user.id);
      const out = { ok: true, username: u.username, email: u.email, role: u.role };
      if (isJson(req)) return res.json(out);
      res.type('html').send(render('Profile saved', `
        <h1>Profile saved</h1>
        <div class="card"><table>
          <tr><th>username</th><td>${esc(out.username)}</td></tr>
          <tr><th>email</th><td>${esc(out.email || '')}</td></tr>
          <tr><th>role</th><td>${esc(out.role)}</td></tr>
        </table></div>
        <p><a href="/">back</a></p>`));
    });

    /* properly role-checked gate — the tampered row must really say admin */
    app.get('/admin/panel', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).type('html').send(loginPage('login required'));
      const u = users.byId(auth.user.id); // re-read: server-side role check
      if (u.role !== 'admin') {
        return res.status(403).type('html').send(render('FleetOps', `
          <h1>Dispatcher console</h1><p class="flag">403 — dispatcher access requires the admin role (you are ${esc(u.role)}).</p>
          <p><a href="/">back</a></p>`));
      }
      res.type('html').send(render('Dispatcher console', `
        <h1>Dispatcher console</h1>
        <div class="card"><table>
          <tr><th>route</th><th>driver</th><th>status</th></tr>
          <tr><td>N-12 north loop</td><td>drv-07</td><td>on time</td></tr>
          <tr><td>harbor shuttle</td><td>drv-31</td><td>delayed 4m</td></tr>
        </table></div>
        <div class="card"><p>dispatch passphrase (admin only):<br><span class="flag">${esc(flags.held('BAC', 'RoleParamTamper'))}</span></p></div>`));
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const u = users.byId(auth.user.id);
      res.type('html').send(render('FleetOps', `
        <h1>🛞 FleetOps</h1>
        <p>signed in as <b>${esc(u.username)}</b> · role <code>${esc(u.role)}</code> · <a href="/logout">sign out</a></p>
        <div class="card">
          <p>settings (<code>POST /api/profile</code>):</p>
          <form method="POST" action="/api/profile">
            <p><input name="email" placeholder="email" size="28" value="${esc(u.email || '')}"></p>
            <p class="muted">role is assigned by staff — the role field was removed from this form in v2.1</p>
            <p><button>save profile</button></p>
          </form>
        </div>
        <p class="muted"><a href="/admin/panel">dispatcher console</a> (admin role required)</p>`));
    });

    /* base registers a fallback GET / before setup() runs and express dispatches
       in registration order — move this lab's themed landing to the front. */
    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
