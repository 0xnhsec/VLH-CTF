'use strict';
/*
 * DSLTV api/bola — Bola (resource-resident, low).
 * "ShipFast" orders API. GET /api/v1/orders/{id} performs authentication but
 * no object-level authorization (no ownership check) — any authenticated user
 * can read any order by sequential id. The innocent's order carries the flag
 * in its secret_note.
 */
module.exports = {
  meta: {
    category: 'API', subName: 'Bola', archetype: 'resource-resident', difficulty: 'low',
    description: 'ShipFast orders API — order objects have no ownership check on direct lookup. Entry: http://victim.target.lab:8119/console',
    flags: [{ category: 'API', subName: 'Bola', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const db = ctx.db;
    const esc = ctx.esc;
    const render = ctx.render;

    db.exec(`
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, item TEXT, status TEXT,
        secret_note TEXT, created_at TEXT);
    `);

    const testers = ctx.users.all().filter((u) => u.role === 'tester');
    const innocent = ctx.users.innocent();
    const admin = ctx.users.admin();
    const flag = ctx.flags.held('API', 'Bola');
    const ins = db.prepare('INSERT INTO orders (user_id, item, status, secret_note, created_at) VALUES (?,?,?,?,?)');
    if (!db.prepare('SELECT COUNT(*) c FROM orders').get().c) {
      ins.run(testers[0].id, 'ship: 100 mailing labels', 'shipped', 'customer note: reorder monthly', ctx.nowIso());
      ins.run(testers[1].id, 'ship: 40 padded envelopes', 'shipped', 'customer note: none', ctx.nowIso());
      ins.run(innocent.id, 'ship: premium crate (confidential recipient)', 'processing', flag, ctx.nowIso());
      ins.run(admin.id, 'ship: pallet wrap rolls', 'shipped', 'customer note: warehouse stock', ctx.nowIso());
      ins.run(innocent.id, 'ship: standard box', 'shipped', 'customer note: leave at door', ctx.nowIso());
    }

    const SECRET = ctx.randHex(32);
    const sign = (u) => ctx.jwt.sign({ uid: u.id, username: u.username }, SECRET, { expiresIn: '4h' });
    const authUser = (req) => {
      const m = /^Bearer (.+)$/.exec(String(req.headers.authorization || ''));
      if (!m) return null;
      try { const p = ctx.jwt.verify(m[1], SECRET); return ctx.users.byId(p.uid) || null; } catch (_) { return null; }
    };

    ctx.app.get('/console', (req, res) => {
      res.type('html').send(render('ShipFast API console', `
        <h1>ShipFast — orders API</h1>
        <div class="card">
          <p><code>POST /api/v1/auth/login</code> <span class="muted">{"username":"…","password":"…"}</span> → <code>{"token":"…"}</code></p>
          <p><code>GET /api/v1/orders</code> <span class="muted">— list your orders</span></p>
          <p><code>GET /api/v1/orders/{id}</code> <span class="muted">— order details (auth required)</span></p>
        </div>
        <p class="muted">Try it: curl -s -X POST -H 'Content-Type: application/json' \\
-d '{"username":"0xnhsec","password":"vlh-tester-01"}' http://victim.target.lab:8119/api/v1/auth/login</p>`));
    });

    ctx.app.post('/api/v1/auth/login', (req, res) => {
      const { username, password } = req.body || {};
      const u = ctx.users.verify(String(username || ''), String(password || ''));
      if (!u) return res.status(401).json({ error: 'invalid credentials' });
      res.json({ token: sign(u), username: u.username });
    });

    ctx.app.get('/api/v1/orders', (req, res) => {
      const u = authUser(req);
      if (!u) return res.status(401).json({ error: 'authentication required' });
      const rows = db.prepare('SELECT id, item, status, created_at FROM orders WHERE user_id = ? ORDER BY id').all(u.id);
      res.json({ orders: rows });
    });

    ctx.app.get('/api/v1/orders/:id', (req, res) => {
      const u = authUser(req);
      if (!u) return res.status(401).json({ error: 'authentication required' });
      const row = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(req.params.id));
      if (!row) return res.status(404).json({ error: 'no such order' });
      /* THE FLAW: no check that row.user_id === u.id */
      res.json({ id: row.id, item: row.item, status: row.status, secret_note: row.secret_note, created_at: row.created_at });
    });
  },
};
