'use strict';
/*
 * DSLTV api/mass-assign-esc — MassAssignEsc (stage-gated, high, 2 flags).
 * "Acctly" account settings. PATCH /api/v1/me copies client-supplied fields
 * onto the account record with NO allowlist — `role` is writable straight
 * from the request body (mass assignment). Stage 1: escalate your own
 * account; GET /api/v1/me then reflects role admin and releases flag1.
 * Stage 2: GET /api/v1/admin/panel re-verifies the role server-side (from
 * the DB row) and releases flag2. Stage 2 is impossible without stage 1:
 * the panel reads the persisted role, and role is only settable through
 * the flawed PATCH.
 */
module.exports = {
  meta: {
    category: 'API', subName: 'MassAssignEsc', archetype: 'stage-gated', difficulty: 'high',
    description: 'Acctly settings API — PATCH /api/v1/me mass-assigns the role field; the admin panel then trusts the escalated DB role. Entry: http://victim.target.lab:8119/',
    flags: [
      { category: 'API', subName: 'MassAssignEsc', archetype: 'stage-gated' },
      { category: 'API', subName: 'MassAssignAdmin', archetype: 'stage-gated' },
    ],
  },
  async setup(ctx) {
    const { app, render, esc, users, session, db } = ctx;

    db.exec(`CREATE TABLE IF NOT EXISTS acctly_profiles (
      user_id INTEGER PRIMARY KEY,
      display_name TEXT NOT NULL,
      company TEXT NOT NULL,
      plan TEXT NOT NULL
    )`);
    /* Stage-gating hygiene: the users table lives on a persistent volume, so
       reset the tester roles each boot — the escalation must be re-earned via
       the mass-assignment flaw every boot. (innocent/admin roles untouched.) */
    db.prepare("UPDATE users SET role = 'tester' WHERE username IN ('0xnhsec', 'Noshiro')").run();
    const seedProfiles = db.transaction(() => {
      db.prepare('DELETE FROM acctly_profiles').run();
      const ins = db.prepare('INSERT INTO acctly_profiles (user_id, display_name, company, plan) VALUES (?,?,?,?)');
      for (const u of users.all()) {
        const plan = u.role === 'admin' ? 'enterprise' : (u.role === 'innocent' ? 'personal' : 'starter');
        const company = u.role === 'admin' ? 'Acctly' : (u.role === 'innocent' ? 'personal' : u.username + ' Labs');
        ins.run(u.id, u.username, company, plan);
      }
    });
    seedProfiles();

    const loginPage = (msg) => render('Acctly — sign in', `
      <h1>Acctly</h1>
      <p class="muted">accounting settings · api v1</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">staff panel: <code>GET /api/v1/admin/panel</code> (role <code>admin</code> only)</p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });
    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* honest web-form path: allowlisted fields only (display name + company) */
    app.post('/settings', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.redirect('/');
      const { display_name, company } = req.body || {};
      db.prepare('UPDATE acctly_profiles SET display_name = ?, company = ? WHERE user_id = ?')
        .run(String(display_name || '').slice(0, 64), String(company || '').slice(0, 64), auth.user.id);
      res.redirect('/');
    });

    /* THE FLAW (mass assignment): PATCH /api/v1/me copies client fields onto
       the account record with no allowlist — `role` (and plan) are writable
       straight from the request body. */
    app.patch('/api/v1/me', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const b = req.body || {};
      const updated = [];
      if (typeof b.display_name === 'string') {
        db.prepare('UPDATE acctly_profiles SET display_name = ? WHERE user_id = ?').run(b.display_name.slice(0, 64), auth.user.id);
        updated.push('display_name');
      }
      if (typeof b.company === 'string') {
        db.prepare('UPDATE acctly_profiles SET company = ? WHERE user_id = ?').run(b.company.slice(0, 64), auth.user.id);
        updated.push('company');
      }
      if (typeof b.plan === 'string') {
        db.prepare('UPDATE acctly_profiles SET plan = ? WHERE user_id = ?').run(b.plan.slice(0, 32), auth.user.id);
        updated.push('plan');
      }
      if (b.role !== undefined) {
        db.prepare('UPDATE users SET role = ? WHERE id = ?').run(String(b.role).slice(0, 32), auth.user.id);
        updated.push('role');
      }
      res.json({ ok: true, updated });
    });

    /* stage 1 gate: the profile reflects the escalated role (server-side state
       in the DB — never a client claim), and releases flag1 only then. */
    app.get('/api/v1/me', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const p = db.prepare('SELECT * FROM acctly_profiles WHERE user_id = ?').get(auth.user.id);
      const out = {
        username: auth.user.username, role: auth.user.role,
        display_name: p.display_name, company: p.company, plan: p.plan,
      };
      if (auth.user.role === 'admin') out.enterprise_notice = ctx.flags.held('API', 'MassAssignEsc');
      res.json(out);
    });

    /* stage 2 gate: the role is re-verified server-side on every request
       (session.get re-reads the DB row) — flag2 only for persisted admins. */
    app.get('/api/v1/admin/panel', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      if (auth.user.role !== 'admin') {
        return res.status(403).json({ error: 'admin role required', your_role: auth.user.role });
      }
      res.json({
        panel: 'acctly/admin', operator: auth.user.username,
        seats: 12, mrr_usd: 48210,
        audit_key: ctx.flags.held('API', 'MassAssignAdmin'),
      });
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const p = db.prepare('SELECT * FROM acctly_profiles WHERE user_id = ?').get(auth.user.id);
      res.type('html').send(render('Acctly', `
        <h1>Acctly — account settings</h1>
        <p class="muted">signed in as ${esc(auth.user.username)} · role <code>${esc(auth.user.role)}</code> · plan ${esc(p.plan)}</p>
        <div class="card">
          <form method="POST" action="/settings">
            <p><input name="display_name" value="${esc(p.display_name)}" size="32" required></p>
            <p><input name="company" value="${esc(p.company)}" size="32" required></p>
            <p><button>save profile</button></p>
          </form>
          <p class="muted">the web form only edits display name + company</p>
        </div>
        <div class="card">
          <p><code>PATCH /api/v1/me</code> <span class="muted">— update your account (JSON body)</span></p>
          <p><code>GET /api/v1/me</code> <span class="muted">— your account</span></p>
          <p><code>GET /api/v1/admin/panel</code> <span class="muted">— staff panel (role <code>admin</code> only)</span></p>
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
