'use strict';
/*
 * DSLTV api/sensitive-flow — SensitiveFlow (stage-gated, high).
 * "DropShop" store. Limited item flag-box: stock 1, 1 per customer. The
 * sensitive flow is: add to cart -> prove human (GET /api/v1/captcha returns
 * a token, POST /api/v1/checkout/verify-human records the stage) ->
 * POST /api/v1/checkout. THE FLOW BUG: the checkout endpoint never checks
 * that the verification stage was completed — a bot completes the whole
 * flow. The per-customer limit IS enforced (a second add for the same user
 * is blocked) — the win is skipping the verification stage, not the limit.
 * The order record (GET /api/v1/orders) carries the flag, and it only
 * exists once checkout has created it server-side (stage-gated).
 */
module.exports = {
  meta: {
    category: 'API', subName: 'SensitiveFlow', archetype: 'stage-gated', difficulty: 'high',
    description: 'DropShop checkout — the human-verification stage of the limited-item flow is never enforced on the final checkout call. Entry: http://victim.target.lab:8119/',
    flags: [{ category: 'API', subName: 'SensitiveFlow', archetype: 'stage-gated' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, session, db, state } = ctx;

    db.exec(`
      CREATE TABLE IF NOT EXISTS catalog (
        sku TEXT PRIMARY KEY, name TEXT NOT NULL, price_cents INTEGER NOT NULL,
        stock INTEGER NOT NULL, limit_per_user INTEGER NOT NULL, note TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS carts (
        user_id INTEGER NOT NULL, sku TEXT NOT NULL, added_at TEXT NOT NULL,
        PRIMARY KEY (user_id, sku)
      );
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        sku TEXT NOT NULL, item TEXT NOT NULL, secret_note TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS captchas (
        token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
      );
    `);
    /* seed-owned state: reset the whole flow each boot — stock, carts, orders,
       captchas, plus the per-user limit + verification markers in the kv store
       (the kv table persists on the volume, so purge the sflow:* keys). */
    const resetLab = db.transaction(() => {
      db.prepare('DELETE FROM carts').run();
      db.prepare('DELETE FROM orders').run();
      db.prepare('DELETE FROM captchas').run();
      db.prepare('DELETE FROM kv WHERE key LIKE ?').run('sflow:%');
      const upsert = db.prepare(`INSERT INTO catalog (sku, name, price_cents, stock, limit_per_user, note)
                                 VALUES (?,?,?,?,?,?)
                                 ON CONFLICT(sku) DO UPDATE SET stock=excluded.stock`);
      upsert.run('flag-box', 'Flag Box (limited release)', 4999, 1, 1, 'limited release — 1 per customer');
      upsert.run('mug', 'DropShop Mug', 1499, 42, 1, 'ceramic, 330ml');
      upsert.run('sticker-pack', 'Sticker Pack', 499, 100, 1, '12 die-cut stickers');
    });
    resetLab();

    const loginPage = (msg) => render('DropShop — sign in', `
      <h1>DropShop</h1>
      <p class="muted">limited drops · api v1</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">public catalog: <a href="/api/v1/catalog">/api/v1/catalog</a></p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });
    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* public catalog */
    app.get('/api/v1/catalog', (req, res) => {
      res.json({ items: db.prepare('SELECT sku, name, price_cents, stock, limit_per_user, note FROM catalog ORDER BY sku').all() });
    });

    /* cart add — stock + per-customer limit enforced (limit tracked in ctx.state) */
    app.post('/api/v1/cart/add', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const sku = String((req.body || {}).item || (req.body || {}).sku || '');
      const item = db.prepare('SELECT * FROM catalog WHERE sku = ?').get(sku);
      if (!item) return res.status(404).json({ error: 'no such item' });
      if (item.stock < 1) return res.status(409).json({ error: 'out of stock', sku });
      const limitKey = `sflow:limit:${auth.user.username}:${sku}`;
      const taken = Number(state.get(limitKey) || 0);
      if (taken >= item.limit_per_user) {
        return res.status(403).json({ error: `per-customer limit reached (${item.limit_per_user} per customer)`, sku });
      }
      const already = db.prepare('SELECT 1 AS x FROM carts WHERE user_id = ? AND sku = ?').get(auth.user.id, sku);
      if (already) return res.status(400).json({ error: 'item already in cart', sku });
      db.prepare('INSERT INTO carts (user_id, sku, added_at) VALUES (?,?,?)').run(auth.user.id, sku, ctx.nowIso());
      state.set(limitKey, taken + 1);
      res.json({ added: true, sku, stock_left: item.stock - 1, limit_per_user: item.limit_per_user });
    });

    /* captcha — the legit human-verification token source (always solvable) */
    app.get('/api/v1/captcha', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const token = ctx.randHex(16);
      db.prepare('INSERT INTO captchas (token, user_id, used, created_at) VALUES (?,?,0,?)')
        .run(token, auth.user.id, ctx.nowIso());
      res.json({ token, challenge: 'submit this token at POST /api/v1/checkout/verify-human to prove you are human' });
    });

    /* the verification stage — works when completed properly */
    app.post('/api/v1/checkout/verify-human', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const token = String((req.body || {}).captcha_token || '');
      const row = db.prepare('SELECT * FROM captchas WHERE token = ? AND user_id = ?').get(token, auth.user.id);
      if (!row || row.used) return res.status(400).json({ error: 'invalid captcha token' });
      db.prepare('UPDATE captchas SET used = 1 WHERE token = ?').run(token);
      state.set(`sflow:human:${auth.user.username}`, true);
      res.json({ verified: true, username: auth.user.username, note: 'human verification recorded — you may now check out' });
    });

    /* THE FLOW BUG (SensitiveFlow): the checkout endpoint accepts the order
       WITHOUT checking the human-verification stage. The missing gate would be:
         if (!state.get(`sflow:human:${auth.user.username}`))
           return res.status(403).json({ error: 'human verification required' });
       The per-customer limit is NOT the flaw — it is enforced upstream at add. */
    app.post('/api/v1/checkout', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const cart = db.prepare('SELECT * FROM carts WHERE user_id = ? ORDER BY sku').all(auth.user.id);
      if (!cart.length) return res.status(400).json({ error: 'cart is empty' });
      for (const c of cart) {
        const item = db.prepare('SELECT * FROM catalog WHERE sku = ?').get(c.sku);
        if (!item || item.stock < 1) return res.status(409).json({ error: `out of stock: ${c.sku}` });
      }
      const flag = ctx.flags.held('API', 'SensitiveFlow');
      const orderIds = [];
      const checkout = db.transaction(() => {
        for (const c of cart) {
          const item = db.prepare('SELECT * FROM catalog WHERE sku = ?').get(c.sku);
          db.prepare('UPDATE catalog SET stock = stock - 1 WHERE sku = ?').run(c.sku);
          /* stage-gated: the flag enters the world only NOW, inside the order
             record the flow creates */
          const note = c.sku === 'flag-box' ? flag : 'thanks for your order';
          const r = db.prepare('INSERT INTO orders (user_id, sku, item, secret_note, created_at) VALUES (?,?,?,?,?)')
            .run(auth.user.id, c.sku, item.name, note, ctx.nowIso());
          orderIds.push(r.lastInsertRowid);
        }
        db.prepare('DELETE FROM carts WHERE user_id = ?').run(auth.user.id);
      });
      checkout();
      res.json({
        checked_out: true,
        order_ids: orderIds,
        human_verified: Boolean(state.get(`sflow:human:${auth.user.username}`)),
      });
    });

    /* orders — the flag only appears here once checkout created it server-side */
    app.get('/api/v1/orders', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const rows = db.prepare('SELECT id, sku, item, secret_note, created_at FROM orders WHERE user_id = ? ORDER BY id').all(auth.user.id);
      res.json({ orders: rows });
    });

    /* store UI: catalog + cart + the flow + your orders */
    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const items = db.prepare('SELECT * FROM catalog ORDER BY sku').all();
      const cart = db.prepare('SELECT c.sku AS sku FROM carts c WHERE c.user_id = ? ORDER BY c.sku').all(auth.user.id);
      const orders = db.prepare('SELECT id, item, secret_note FROM orders WHERE user_id = ? ORDER BY id').all(auth.user.id);
      const human = Boolean(state.get(`sflow:human:${auth.user.username}`));
      res.type('html').send(render('DropShop', `
        <h1>DropShop</h1>
        <p class="muted">signed in as ${esc(auth.user.username)} · human verification: ${human ? 'completed' : 'not completed'}</p>
        <div class="card">
          <table><tr><th>sku</th><th>item</th><th>price</th><th>stock</th><th>limit</th><th></th></tr>
          ${items.map((i) => `<tr><td>${esc(i.sku)}</td><td>${esc(i.name)}</td><td>${(i.price_cents / 100).toFixed(2)}</td><td>${i.stock}</td><td>${i.limit_per_user}/customer</td>
            <td><form method="POST" action="/api/v1/cart/add"><input type="hidden" name="item" value="${esc(i.sku)}"><button>add to cart</button></form></td></tr>`).join('')}
          </table>
        </div>
        <div class="card">
          <p>cart: ${cart.map((c) => esc(c.sku)).join(', ') || '<span class="muted">empty</span>'}</p>
          <p class="muted">checkout flow: <code>POST /api/v1/cart/add {"item":"…"}</code> → <code>GET /api/v1/captcha</code> → <code>POST /api/v1/checkout/verify-human {"captcha_token":"…"}</code> → <code>POST /api/v1/checkout</code></p>
          <form method="POST" action="/api/v1/checkout"><p><button>check out</button></p></form>
        </div>
        <div class="card">
          <table><tr><th>order</th><th>item</th><th>secret note</th></tr>
          ${orders.map((o) => `<tr><td>${o.id}</td><td>${esc(o.item)}</td><td>${esc(o.secret_note)}</td></tr>`).join('') || '<tr><td colspan="3" class="muted">no orders yet</td></tr>'}
          </table>
          <p class="muted">orders API: <code>GET /api/v1/orders</code></p>
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
