'use strict';
/*
 * DSLTV BAC/HorizontalEsc — "Ordery".
 * Bug: the order-list endpoint enforces ownership (you only see your own
 * orders), but the single-order endpoint GET /api/orders/:username/:id applies
 * the check on the wrong route and fetches ANY user's order. The innocent
 * user's order carries the resource-resident flag.
 */
module.exports = {
  meta: {
    category: 'BAC',
    subName: 'HorizontalEsc',
    archetype: 'resource-resident',
    difficulty: 'medium',
    description: 'Ordery order tracking: the ownership check lives on the list endpoint only — GET /api/orders/{user}/{id} returns any account\'s order.',
    flags: [{ category: 'BAC', subName: 'HorizontalEsc', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session, db } = ctx;

    db.exec(`CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      item TEXT NOT NULL,
      note TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`);
    const ins = db.prepare('INSERT INTO orders (username, item, note, created_at) VALUES (?,?,?,?)');
    const now = ctx.nowIso();
    const innocent = users.innocent();
    ins.run('0xnhsec', 'rubber duck (dev edition)', 'desk decoration', now);
    ins.run('Noshiro', 'mechanical keyboard', 'clicky switches, 65%', now);
    ins.run(innocent.username, 'flag box — exclusive batch', flags.held('BAC', 'HorizontalEsc'), now);
    ins.run('admin', 'rack screws M6', 'box of 100', now);

    const loginPage = (msg) => render('Ordery — sign in', `
      <h1>📦 Ordery</h1>
      <p class="muted">order tracking for everyone</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>track in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">account directory: <a href="/api/users">/api/users</a></p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* legit leak: account directory (usernames only, no secrets) */
    app.get('/api/users', (req, res) => {
      res.json({ users: users.all().map((u) => ({ username: u.username, role: u.role })) });
    });

    /* SAFE: the list endpoint checks ownership (you only see your own rows). */
    app.get('/api/orders', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const rows = db.prepare('SELECT id, username, item, note, created_at FROM orders WHERE username = ? ORDER BY id').all(auth.user.username);
      res.json({ orders: rows });
    });

    /* THE BUG: single-order fetch applies no ownership check — the :username
       path parameter is trusted directly (check was "already done" on the list
       route, so it was never repeated here — misplaced authorization). */
    app.get('/api/orders/:username/:id', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const row = db.prepare('SELECT id, username, item, note, created_at FROM orders WHERE username = ? AND id = ?')
        .get(String(req.params.username), Number(req.params.id));
      if (!row) return res.status(404).json({ error: 'no such order' });
      res.json({ order: row });
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const rows = db.prepare('SELECT id, item, note FROM orders WHERE username = ? ORDER BY id').all(auth.user.username);
      res.type('html').send(render('Ordery', `
        <h1>📦 Ordery</h1>
        <p>tracking as <b>${esc(auth.user.username)}</b> · <a href="/logout">sign out</a></p>
        <div class="card">
          <p>your orders (<code>GET /api/orders</code>):</p>
          <table><tr><th>id</th><th>item</th><th>note</th></tr>
          ${rows.map((r) => `<tr><td>${r.id}</td><td>${esc(r.item)}</td><td>${esc(r.note)}</td></tr>`).join('') || '<tr><td colspan="3" class="muted">no orders yet</td></tr>'}
          </table>
        </div>
        <div class="card">
          <p class="muted">single order lookup: <code>GET /api/orders/{username}/{orderId}</code></p>
          <form onsubmit="location.href='/api/orders/'+document.getElementById('ou').value+'/'+document.getElementById('oi').value;return false;">
            <p><input id="ou" placeholder="username" size="14"> <input id="oi" placeholder="order id" size="8" value="1"> <button>lookup</button></p>
          </form>
        </div>
        <p class="muted">ids are small integers — <a href="/api/users">/api/users</a> lists accounts</p>`));
    });

    /* base registers a fallback GET / before setup() runs and express dispatches
       in registration order — move this lab's themed landing to the front. */
    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
