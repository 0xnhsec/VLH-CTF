'use strict';
/*
 * DSLTV api/bopla — Bopla (resource-resident, medium).
 * "ShipFast Orders". GET /api/v1/orders returns the caller's own orders with
 * safe summary fields — object-level access control is correct. The flaw is
 * property-level (BOPLA): the endpoint honors a client-controllable
 * serialization switch — ?include=full, a projection meant for internal
 * support tooling — which adds the internal_audit_note property to every
 * order object. The tester's own seeded order carries the flag in its note.
 */
module.exports = {
  meta: {
    category: 'API', subName: 'Bopla', archetype: 'resource-resident', difficulty: 'medium',
    description: 'ShipFast Orders API — your order list is object-safe, but ?include=full swaps in the internal serialization and over-exposes the audit-note property. Entry: http://victim.target.lab:8119/',
    flags: [{ category: 'API', subName: 'Bopla', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, session, db } = ctx;

    /* seed-owned table: wipe + reseed each boot so the resident flag is fresh */
    db.exec(`CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      item TEXT NOT NULL,
      status TEXT NOT NULL,
      total_cents INTEGER NOT NULL,
      internal_audit_note TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`);
    const flag = ctx.flags.held('API', 'Bopla');
    const seedOrders = db.transaction(() => {
      db.prepare('DELETE FROM orders').run();
      const ins = db.prepare('INSERT INTO orders (user_id, item, status, total_cents, internal_audit_note, created_at) VALUES (?,?,?,?,?,?)');
      const now = ctx.nowIso();
      for (const t of users.all().filter((u) => u.role === 'tester')) {
        ins.run(t.id, 'ship: 100 mailing labels', 'shipped', 1899, 'lane: ground · cost center CC-114 · insurance: none', now);
        ins.run(t.id, 'ship: overnight red envelope (batch A7)', 'processing', 5499, flag, now);
      }
      /* users.innocent() is bound to THIS boot's random name; on a container
         restart the users table persists with the first boot's row — fall back
         to the persisted role:'innocent' account so reseeding stays restart-safe. */
      const innocent = users.innocent() || users.all().find((u) => u.role === 'innocent');
      ins.run(innocent.id, 'ship: premium crate (confidential recipient)', 'processing', 12400,
        'VIP: white-glove handling — internal only, never surface to the customer', now);
      const admin = users.admin();
      ins.run(admin.id, 'ship: pallet wrap rolls', 'shipped', 820, 'lane: freight · dock 3 · monthly restock', now);
    });
    seedOrders();

    const loginPage = (msg) => render('ShipFast — sign in', `
      <h1>ShipFast Orders</h1>
      <p class="muted">shipping dashboard · api v1</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">public directory: <a href="/api/v1/directory">/api/v1/directory</a></p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });
    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* legit leak: account directory (usernames only, no secrets) */
    app.get('/api/v1/directory', (req, res) => {
      res.json({ users: users.all().map((u) => ({ username: u.username, role: u.role })) });
    });

    /* Object-level access is SAFE: own orders only. */
    app.get('/api/v1/orders', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const rows = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id').all(auth.user.id);
      /* THE FLAW (BOPLA): client-controllable serialization — the "full"
         projection was built for internal support tooling, but any caller can
         select it and it serializes the internal audit-note property. */
      const full = String(req.query.include || '').toLowerCase() === 'full';
      res.json({
        orders: rows.map((r) => {
          const o = { id: r.id, item: r.item, status: r.status, total_cents: r.total_cents, created_at: r.created_at };
          if (full) o.internal_audit_note = r.internal_audit_note; /* over-exposed property */
          return o;
        }),
      });
    });

    /* dashboard: your orders in the safe projection + API docs */
    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const rows = db.prepare('SELECT id, item, status, total_cents FROM orders WHERE user_id = ? ORDER BY id').all(auth.user.id);
      res.type('html').send(render('ShipFast Orders', `
        <h1>ShipFast Orders</h1>
        <p class="muted">signed in as ${esc(auth.user.username)} · your shipments (summary view)</p>
        <div class="card">
          <table><tr><th>id</th><th>item</th><th>status</th><th>total</th></tr>
          ${rows.map((r) => `<tr><td>${r.id}</td><td>${esc(r.item)}</td><td>${esc(r.status)}</td><td>${(r.total_cents / 100).toFixed(2)}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">no orders yet</td></tr>'}
          </table>
        </div>
        <div class="card">
          <p><code>GET /api/v1/orders</code> <span class="muted">— summary projection (default)</span></p>
          <p><code>GET /api/v1/orders?include=full</code> <span class="muted">— extended projection for support tickets (adds internal tracking fields)</span></p>
          <p class="muted">directory: <a href="/api/v1/directory">/api/v1/directory</a></p>
        </div>
        <p class="muted"><a href="/me">account</a> · <a href="/logout">sign out</a></p>`));
    });

    /* base registers a fallback GET / before setup() runs and express dispatches
       in registration order — move this lab's themed landing to the front. */
    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
