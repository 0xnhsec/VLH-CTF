'use strict';
/*
 * DSLTV AUTH/DefaultCreds — "Factory Console" (warm-up lab).
 * Seed deviation (documented): this appliance was "restored to factory
 * defaults", so the admin account still has its out-of-the-box password
 * `admin`. Sign in with the default credentials and read the admin panel.
 */
module.exports = {
  meta: {
    category: 'AUTH',
    subName: 'DefaultCreds',
    archetype: 'resource-resident',
    difficulty: 'low',
    description: 'Factory Console: the appliance ships with default admin credentials that were never changed — sign in and read the panel.',
    flags: [{ category: 'AUTH', subName: 'DefaultCreds', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session, db } = ctx;

    /* documented seed deviation: admin keeps the factory default password */
    db.prepare("UPDATE users SET password = 'admin' WHERE username = 'admin'").run();

    const loginPage = (msg) => render('Factory Console — login', `
      <h1>🖨 Factory Console</h1>
      <p class="muted">appliance management · firmware 1.0.7 · <b>restored to factory defaults</b></p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">demo accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">consult the printed quick-start card for the initial administrator credentials.</p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* properly role-checked — the bug is the credentials, not the gate */
    app.get('/admin/panel', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).type('html').send(loginPage('login required'));
      const u = users.byId(auth.user.id);
      if (u.role !== 'admin') {
        return res.status(403).type('html').send(render('Factory Console', `
          <h1>403 — administrator only</h1><p class="flag">This console requires the admin role (you are ${esc(u.role)}).</p>
          <p><a href="/">back</a></p>`));
      }
      res.type('html').send(render('Factory Console — admin', `
        <h1>🖨 Factory Console</h1>
        <div class="card"><table>
          <tr><th>setting</th><th>value</th></tr>
          <tr><td>firmware</td><td>1.0.7</td></tr>
          <tr><td>factory defaults</td><td>RESTORED</td></tr>
          <tr><td>admin password changed</td><td>NO</td></tr>
        </table></div>
        <div class="card"><p>support key (admin only):<br><span class="flag">${esc(flags.held('AUTH', 'DefaultCreds'))}</span></p></div>`));
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      res.type('html').send(render('Factory Console', `
        <h1>🖨 Factory Console</h1>
        <p>signed in as <b>${esc(auth.user.username)}</b> · role <code>${esc(auth.user.role)}</code> · <a href="/logout">sign out</a></p>
        <p class="muted"><a href="/admin/panel">admin panel</a> (administrator only)</p>`));
    });

    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
