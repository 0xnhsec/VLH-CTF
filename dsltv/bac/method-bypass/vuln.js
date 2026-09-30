'use strict';
/*
 * DSLTV BAC/MethodBypass — "Aegis Gateway".
 * Bug: GET /admin/panel enforces the admin role, but a second handler for
 * POST /admin/panel (added "for the mobile app") was registered without the
 * check. Same resource, different method, missing guard.
 */
module.exports = {
  meta: {
    category: 'BAC',
    subName: 'MethodBypass',
    archetype: 'resource-resident',
    difficulty: 'medium',
    description: 'Aegis Gateway admin console: the POST /admin/panel handler (mobile-app compat) skips the role check the GET handler enforces.',
    flags: [{ category: 'BAC', subName: 'MethodBypass', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session } = ctx;

    const loginPage = (msg) => render('Aegis Gateway — sign in', `
      <h1>🛡 Aegis Gateway</h1>
      <p class="muted">perimeter access management</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">admin console: <a href="/admin/panel">/admin/panel</a></p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    const panel = (user) => render('Admin console', `
      <h1>Admin console</h1>
      <p class="muted">session: ${esc(user.username)} (${esc(user.role)})</p>
      <div class="card"><table>
        <tr><th>zone</th><th>policy</th></tr>
        <tr><td>north gate</td><td>badge + pin</td></tr>
        <tr><td>loading dock</td><td>badge</td></tr>
        <tr><td>vault corridor</td><td>badge + pin + escort</td></tr>
      </table></div>
      <div class="card"><p>master override phrase:<br><span class="flag">${esc(flags.held('BAC', 'MethodBypass'))}</span></p></div>`);

    /* properly checked — testers get 403 here. */
    app.get('/admin/panel', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).type('html').send(loginPage('login required'));
      const u = users.byId(auth.user.id);
      if (u.role !== 'admin') {
        return res.status(403).type('html').send(render('Denied', `
          <h1>403 — admin only</h1>
          <p class="flag">The admin console requires the admin role (you are ${esc(u.role)}).</p>
          <p class="muted">GET /admin/panel is protected. Nothing to see here.</p>
          <p><a href="/">back</a></p>`));
      }
      res.type('html').send(panel(u));
    });

    /* THE BUG: the "mobile-app fast path" re-registered the console without the
       role check — only login is verified. */
    app.post('/admin/panel', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).type('html').send(loginPage('login required'));
      const u = users.byId(auth.user.id);
      res.type('html').send(panel(u));
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      res.type('html').send(render('Aegis Gateway', `
        <h1>🛡 Aegis Gateway</h1>
        <p>signed in as <b>${esc(auth.user.username)}</b> · role <code>${esc(auth.user.role)}</code> · <a href="/logout">sign out</a></p>
        <div class="card">
          <p>endpoints:</p>
          <table>
            <tr><th>route</th><th>purpose</th></tr>
            <tr><td><a href="/admin/panel">GET /admin/panel</a></td><td>admin console (web)</td></tr>
            <tr><td><code>POST /admin/panel</code></td><td>admin console (mobile-app compat, added v3.4)</td></tr>
          </table>
        </div>`));
    });

    /* base registers a fallback GET / before setup() runs and express dispatches
       in registration order — move this lab's themed landing to the front. */
    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
