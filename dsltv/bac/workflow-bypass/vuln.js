'use strict';
/*
 * DSLTV BAC/WorkflowBypass — "Shopflow".
 * Bug: ordering the limited "flag box" requires the checkout workflow state
 * 'address_verified' (which staff must grant — POST /verify-address only
 * submits for review). POST /checkout/confirm, a later "quick-buy" endpoint,
 * creates + confirms the order in one step and skips the state check.
 */
module.exports = {
  meta: {
    category: 'BAC',
    subName: 'WorkflowBypass',
    archetype: 'resource-resident',
    difficulty: 'high',
    description: 'Shopflow limited drop: POST /checkout enforces the address-verified workflow state; POST /checkout/confirm skips it and confirms the flag box order.',
    flags: [{ category: 'BAC', subName: 'WorkflowBypass', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session, db } = ctx;

    db.exec(`CREATE TABLE IF NOT EXISTS address_state (
      username TEXT PRIMARY KEY, address TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL
    )`);
    db.exec(`CREATE TABLE IF NOT EXISTS shop_orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, sku TEXT NOT NULL,
      status TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL
    )`);
    const innocent = users.innocent();
    db.prepare('INSERT OR IGNORE INTO address_state (username, address, status, updated_at) VALUES (?,?,?,?)')
      .run(innocent.username, '42 Orchard Lane', 'verified', ctx.nowIso()); // flavor: verified buyers exist

    const CATALOG = [
      { sku: 'sticker-pack', name: 'Sticker Pack', price: 300, limited: false },
      { sku: 'enamel-mug', name: 'Enamel Mug', price: 1200, limited: false },
      { sku: 'flag-box', name: 'FLAG BOX — limited drop (1 left)', price: 9999, limited: true },
    ];
    const catItem = (sku) => CATALOG.find((c) => c.sku === String(sku || ''));

    const isJson = (req) => /json/i.test(String(req.headers['content-type'] || '')) || /json/i.test(String(req.headers.accept || ''));
    const respond = (req, res, status, title, html, obj) => {
      if (isJson(req)) return res.status(status).json(obj);
      return res.status(status).type('html').send(render(title, `${html}<p><a href="/">back to shop</a></p>`));
    };

    const loginPage = (msg) => render('Shopflow — sign in', `
      <h1>🛒 Shopflow</h1>
      <p class="muted">verified-buyer drops since 2019</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* step 1 of the workflow — only SUBMITS for staff review (staff never comes) */
    app.post('/verify-address', (req, res) => {
      const auth = session.get(req);
      if (!auth) return respond(req, res, 401, 'Verify address', '<p class="flag">login required</p>', { error: 'login required' });
      const address = String((req.body || {}).address || '').slice(0, 200) || '(empty)';
      db.prepare(`INSERT INTO address_state (username, address, status, updated_at) VALUES (?,?,?,?)
                  ON CONFLICT(username) DO UPDATE SET address=excluded.address, status=excluded.status, updated_at=excluded.updated_at`)
        .run(auth.user.username, address, 'pending_review', ctx.nowIso());
      return respond(req, res, 200, 'Verify address', `
        <h1>Address submitted</h1>
        <div class="card"><p>Thanks — staff will review your address within <b>2 business days</b>.
        Verified buyers unlock the limited drop at <code>POST /checkout</code>.</p></div>`,
        { ok: true, status: 'pending_review', note: 'staff review takes 2 business days' });
    });

    /* the gated workflow endpoint — requires state 'address_verified' */
    app.post('/checkout', (req, res) => {
      const auth = session.get(req);
      if (!auth) return respond(req, res, 401, 'Checkout', '<p class="flag">login required</p>', { error: 'login required' });
      const item = catItem((req.body || {}).sku);
      if (!item) return respond(req, res, 400, 'Checkout', '<p class="flag">unknown sku</p>', { error: 'unknown sku' });
      const st = db.prepare('SELECT status FROM address_state WHERE username = ?').get(auth.user.username);
      if (!st || st.status !== 'verified') {
        return respond(req, res, 403, 'Checkout', `
          <h1>Checkout blocked</h1>
          <div class="card"><p class="flag">403 — address not verified.</p>
          <p>Submit your address at <code>POST /verify-address</code> and wait for staff review.</p></div>`,
          { error: 'address not verified — workflow state required: address_verified' });
      }
      const r = db.prepare('INSERT INTO shop_orders (username, sku, status, details, created_at) VALUES (?,?,?,?,?)')
        .run(auth.user.username, item.sku, 'confirmed', `order for ${item.name}`, ctx.nowIso());
      const order = { id: r.lastInsertRowid, sku: item.sku, status: 'confirmed' };
      return respond(req, res, 200, 'Checkout', `
        <h1>Order confirmed</h1><div class="card"><pre>${esc(JSON.stringify(order, null, 2))}</pre></div>`,
        { ok: true, order });
    });

    /* THE BUG: quick-buy endpoint (create + confirm) — skips the workflow
       state check entirely. */
    app.post('/checkout/confirm', (req, res) => {
      const auth = session.get(req);
      if (!auth) return respond(req, res, 401, 'Quick buy', '<p class="flag">login required</p>', { error: 'login required' });
      const item = catItem((req.body || {}).sku);
      if (!item) return respond(req, res, 400, 'Quick buy', '<p class="flag">unknown sku</p>', { error: 'unknown sku' });
      const details = item.limited
        ? `limited drop — exclusive contents: ${flags.held('BAC', 'WorkflowBypass')}`
        : `order for ${item.name}`;
      const r = db.prepare('INSERT INTO shop_orders (username, sku, status, details, created_at) VALUES (?,?,?,?,?)')
        .run(auth.user.username, item.sku, 'confirmed', details, ctx.nowIso());
      const order = { id: r.lastInsertRowid, sku: item.sku, status: 'confirmed', details };
      return respond(req, res, 200, 'Quick buy', `
        <h1>Order confirmed (quick buy)</h1>
        <div class="card"><pre>${esc(JSON.stringify(order, null, 2))}</pre></div>`,
        { ok: true, order });
    });

    app.get('/orders', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const rows = db.prepare('SELECT id, sku, status, details, created_at FROM shop_orders WHERE username = ? ORDER BY id DESC').all(auth.user.username);
      res.json({ orders: rows });
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const st = db.prepare('SELECT status FROM address_state WHERE username = ?').get(auth.user.username);
      res.type('html').send(render('Shopflow', `
        <h1>🛒 Shopflow</h1>
        <p>signed in as <b>${esc(auth.user.username)}</b> · address status: <code>${esc(st ? st.status : 'none')}</code> · <a href="/logout">sign out</a></p>
        <div class="card"><table>
          <tr><th>item</th><th>sku</th><th>price</th></tr>
          ${CATALOG.map((c) => `<tr><td>${esc(c.name)}</td><td><code>${esc(c.sku)}</code></td><td>${c.price}¢</td></tr>`).join('')}
        </table></div>
        <div class="card">
          <p>checkout (verified buyers only):</p>
          <form method="POST" action="/checkout">
            <p><input name="sku" placeholder="sku" size="14"> <button>checkout</button>
               <button formaction="/verify-address" name="address" value="1 Example St">submit address instead</button></p>
          </form>
          <form method="POST" action="/checkout/confirm">
            <p><input name="sku" placeholder="sku" size="14"> <button>quick buy (mobile app)</button></p>
          </form>
          <p class="muted">quick-buy was added for the mobile app in v4.0 — it skips the address queue "temporarily"</p>
        </div>
        <p class="muted">your orders: <a href="/orders">/orders</a></p>`));
    });

    /* base registers a fallback GET / before setup() runs and express dispatches
       in registration order — move this lab's themed landing to the front. */
    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
