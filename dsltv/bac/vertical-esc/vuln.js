'use strict';
/*
 * DSLTV BAC/VerticalEsc — "Ctrl Center".
 * Bug: GET /admin/panel authenticates the caller (login required) but never
 * checks the account role. Any signed-in user — the seeded testers included —
 * can read the staff ops console, which carries the resource-resident flag.
 */
module.exports = {
  meta: {
    category: 'BAC',
    subName: 'VerticalEsc',
    archetype: 'resource-resident',
    difficulty: 'low',
    description: 'Ctrl Center ops console: /admin/panel requires a login but never checks the role — any authenticated account reaches the staff panel.',
    flags: [{ category: 'BAC', subName: 'VerticalEsc', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session } = ctx;

    const loginPage = (msg) => render('Ctrl Center — sign in', `
      <h1>⌁ Ctrl Center</h1>
      <p class="muted">infrastructure operations portal · node ctrl-01</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">operator accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">staff console: <a href="/admin/panel">/admin/panel</a></p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* THE BUG: authentication enforced, authorization (role check) missing. */
    app.get('/admin/panel', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).type('html').send(loginPage('login required for the ops console'));
      res.type('html').send(render('Ops console', `
        <h1>Ops console</h1>
        <p class="muted">signed in as ${esc(auth.user.username)} (${esc(auth.user.role)}) · cluster ctrl-01 · 412h uptime</p>
        <div class="card"><table>
          <tr><th>subsystem</th><th>state</th></tr>
          <tr><td>power grid</td><td>NOMINAL</td></tr>
          <tr><td>coolant loop B</td><td>NOMINAL</td></tr>
          <tr><td>door maglocks</td><td>ENGAGED</td></tr>
        </table></div>
        <div class="card"><p>staff bulletin (internal only):<br><span class="flag">${esc(flags.held('BAC', 'VerticalEsc'))}</span></p></div>`));
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      res.type('html').send(render('Ctrl Center', `
        <h1>⌁ Ctrl Center</h1>
        <p>signed in as <b>${esc(auth.user.username)}</b> · role <code>${esc(auth.user.role)}</code></p>
        <div class="card"><table>
          <tr><th>module</th><th>access</th></tr>
          <tr><td><a href="/me">account</a></td><td>self</td></tr>
          <tr><td><a href="/admin/panel">ops console</a></td><td>staff only</td></tr>
          <tr><td><a href="/logout">sign out</a></td><td>—</td></tr>
        </table></div>
        <p class="muted">session provenance <code>auth_method=${esc(auth.session.auth_method)}</code></p>`));
    });

    /* base registers a fallback GET / before setup() runs and express dispatches
       in registration order — move this lab's themed landing to the front. */
    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
