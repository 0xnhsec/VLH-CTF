'use strict';
/*
 * DSLTV BAC/CrossTenant — "Tenantly".
 * Bug: GET /tenant/dashboard resolves the tenant from the client-supplied
 * X-Tenant-Id header and renders that tenant's board without any membership
 * check. The innocent user's private tenant board carries the flag.
 */
module.exports = {
  meta: {
    category: 'BAC',
    subName: 'CrossTenant',
    archetype: 'resource-resident',
    difficulty: 'high',
    description: 'Tenantly workspace boards: the dashboard trusts the X-Tenant-Id header — read any tenant\'s board without being a member.',
    flags: [{ category: 'BAC', subName: 'CrossTenant', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, flags, session, db } = ctx;

    db.exec(`CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL, board TEXT NOT NULL
    )`);
    db.exec(`CREATE TABLE IF NOT EXISTS tenant_members (
      tenant_id TEXT NOT NULL, username TEXT NOT NULL, PRIMARY KEY (tenant_id, username)
    )`);
    const innocent = users.innocent();
    const seedTenant = db.prepare('INSERT OR IGNORE INTO tenants (id, name, plan, board) VALUES (?,?,?,?)');
    seedTenant.run('tn-acme', 'Acme Co', 'trial', 'Q3 roadmap:\n- migrate billing\n- fix the coffee machine');
    seedTenant.run('tn-globex', 'Globex Industries', 'pro', 'Weekly sync notes:\n- reactor at 62%\n- marketing owns the mascot now');
    const innocentTenant = 'tn-' + ctx.randHex(4);
    seedTenant.run(innocentTenant, 'Quiet Cove Studio', 'pro',
      'private workspace — internal only:\n' + flags.held('BAC', 'CrossTenant'));
    const member = db.prepare('INSERT OR IGNORE INTO tenant_members (tenant_id, username) VALUES (?,?)');
    member.run('tn-acme', '0xnhsec'); member.run('tn-acme', 'Noshiro'); member.run('tn-acme', 'admin');
    member.run(innocentTenant, innocent.username);

    const loginPage = (msg) => render('Tenantly — sign in', `
      <h1>🏙 Tenantly</h1>
      <p class="muted">tenant workspaces, isolated by design (they said)</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">public tenant directory: <a href="/api/tenants">/api/tenants</a></p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });

    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* legit leak: public tenant directory (with member usernames) */
    app.get('/api/tenants', (req, res) => {
      const auth = session.get(req);
      const rows = db.prepare('SELECT id, name, plan FROM tenants ORDER BY id').all();
      const mine = auth
        ? db.prepare('SELECT tenant_id FROM tenant_members WHERE username = ?').all(auth.user.username).map((r) => r.tenant_id)
        : [];
      const owners = {};
      for (const m of db.prepare('SELECT tenant_id, username FROM tenant_members').all()) {
        owners[m.tenant_id] = owners[m.tenant_id] || [];
        owners[m.tenant_id].push(m.username);
      }
      res.json({
        tenants: rows.map((r) => ({ ...r, members: owners[r.id] || [], you_are_member: mine.includes(r.id) })),
      });
    });

    /* THE BUG: tenant resolution trusts the X-Tenant-Id header; membership is
       never validated (the "isolation" is only enforced by the client UI). */
    app.get('/tenant/dashboard', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).type('html').send(loginPage('login required'));
      const tid = String(req.headers['x-tenant-id'] || '');
      if (!tid) return res.status(400).type('html').send(render('Tenantly', `
        <h1>Tenant dashboard</h1><p class="flag">X-Tenant-Id header required.</p><p><a href="/">back</a></p>`));
      const tenant = db.prepare('SELECT * FROM tenants WHERE id = ?').get(tid);
      if (!tenant) return res.status(404).type('html').send(render('Tenantly', `
        <h1>Tenant dashboard</h1><p class="flag">Unknown tenant.</p><p><a href="/">back</a></p>`));
      const isMember = !!db.prepare('SELECT 1 FROM tenant_members WHERE tenant_id = ? AND username = ?').get(tid, auth.user.username);
      res.type('html').send(render(`Tenant: ${tenant.name}`, `
        <h1>🏙 ${esc(tenant.name)}</h1>
        <p class="muted">tenant <code>${esc(tenant.id)}</code> · plan ${esc(tenant.plan)} · ${isMember ? 'member view' : 'member view'}</p>
        <div class="card"><pre>${esc(tenant.board)}</pre></div>
        <p><a href="/">back</a></p>`));
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const rows = db.prepare(`SELECT t.id, t.name, t.plan FROM tenants t
        JOIN tenant_members m ON m.tenant_id = t.id WHERE m.username = ? ORDER BY t.id`).all(auth.user.username);
      res.type('html').send(render('Tenantly', `
        <h1>🏙 Tenantly</h1>
        <p>signed in as <b>${esc(auth.user.username)}</b> · <a href="/logout">sign out</a></p>
        <div class="card">
          <p>your workspaces:</p>
          <table><tr><th>tenant</th><th>plan</th><th>open</th></tr>
          ${rows.map((r) => `<tr><td>${esc(r.name)}</td><td>${esc(r.plan)}</td><td><a href="/tenant/dashboard" data-t="${esc(r.id)}">dashboard</a></td></tr>`).join('') || '<tr><td colspan="3" class="muted">none</td></tr>'}
          </table>
          <p class="muted">the dashboard app sends <code>X-Tenant-Id: &lt;tenant&gt;</code> with every request</p>
        </div>
        <p class="muted">all tenants (public directory): <a href="/api/tenants">/api/tenants</a></p>`));
    });

    /* base registers a fallback GET / before setup() runs and express dispatches
       in registration order — move this lab's themed landing to the front. */
    const stack = app.stack;
    const layer = stack[stack.length - 1];
    if (layer && layer.route && layer.route.path === '/') { stack.pop(); stack.unshift(layer); }
  },
};
