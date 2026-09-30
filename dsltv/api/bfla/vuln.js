'use strict';
/*
 * DSLTV api/bfla — Bfla (resource-resident, medium).
 * "PurgeHQ" edge-cache operations API. POST /api/v1/admin/purge-cache is an
 * operator-only maintenance function, but the route only checks that the
 * caller is AUTHENTICATED — the function-level authorization check (role)
 * is missing (the BFLA flaw). Any signed-in account can trigger the purge,
 * and the purge confirmation carries the flag.
 */
module.exports = {
  meta: {
    category: 'API', subName: 'Bfla', archetype: 'resource-resident', difficulty: 'medium',
    description: 'PurgeHQ infra API — the admin cache-purge function checks authentication but never the caller\'s role. Entry: http://victim.target.lab:8119/',
    flags: [{ category: 'API', subName: 'Bfla', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, session, db } = ctx;

    /* seed-owned table: wipe + reseed each boot so lab state never goes stale */
    db.exec(`CREATE TABLE IF NOT EXISTS edge_pops (
      code TEXT PRIMARY KEY, city TEXT NOT NULL, cache_mb INTEGER NOT NULL
    )`);
    const seedPops = db.transaction(() => {
      db.prepare('DELETE FROM edge_pops').run();
      const ins = db.prepare('INSERT INTO edge_pops (code, city, cache_mb) VALUES (?,?,?)');
      ins.run('hq-eu', 'Frankfurt', 8123);
      ins.run('hq-us', 'Ashburn', 14202);
      ins.run('hq-ap', 'Singapore', 5931);
      ins.run('hq-sa', 'Sao Paulo', 2201);
    });
    seedPops();

    const loginPage = (msg) => render('PurgeHQ — sign in', `
      <h1>PurgeHQ</h1>
      <p class="muted">edge cache operations · hq-api v1.4.2</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">operator accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">public status feed: <a href="/api/v1/status">/api/v1/status</a></p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });
    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* public: edge status feed */
    app.get('/api/v1/status', (req, res) => {
      const pops = db.prepare('SELECT code, city, cache_mb FROM edge_pops ORDER BY code').all();
      res.json({ service: 'purgehq', version: '1.4.2', status: 'operational', edge_pops: pops });
    });

    /* THE FLAW (BFLA): operator-only maintenance function enforces
       authentication but never the function-level authorization check —
       the role gate (u.role === 'admin') is simply missing. */
    app.post('/api/v1/admin/purge-cache', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const evicted = db.prepare('SELECT COALESCE(SUM(cache_mb), 0) AS t FROM edge_pops').get().t;
      db.prepare('UPDATE edge_pops SET cache_mb = 0').run();
      const regions = db.prepare('SELECT code FROM edge_pops ORDER BY code').all().map((r) => r.code);
      res.json({
        purged: true,
        evicted_mb: evicted,
        regions,
        executed_by: auth.user.username,
        role: auth.user.role,
        maintenance_note: ctx.flags.held('API', 'Bfla'),
      });
    });

    /* minimal console: status page + the purge button (intended for admins only) */
    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const pops = db.prepare('SELECT code, city, cache_mb FROM edge_pops ORDER BY code').all();
      res.type('html').send(render('PurgeHQ console', `
        <h1>PurgeHQ console</h1>
        <p class="muted">signed in as ${esc(auth.user.username)} (role ${esc(auth.user.role)}) · hq-api v1.4.2</p>
        <div class="card">
          <table><tr><th>edge PoP</th><th>city</th><th>cache</th></tr>
          ${pops.map((p) => `<tr><td>${esc(p.code)}</td><td>${esc(p.city)}</td><td>${p.cache_mb} MB</td></tr>`).join('')}
          </table>
          <p class="muted">public status feed: <a href="/api/v1/status">/api/v1/status</a></p>
        </div>
        <div class="card">
          <form method="POST" action="/api/v1/admin/purge-cache">
            <p><button>purge all edge caches</button></p>
          </form>
          <p class="muted">maintenance function — operators (role <code>admin</code>) only</p>
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
