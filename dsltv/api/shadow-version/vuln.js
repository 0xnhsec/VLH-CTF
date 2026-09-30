'use strict';
/*
 * DSLTV api/shadow-version — ShadowVersion (resource-resident, medium).
 * "ProfileBook" social profiles. Current API v2 (GET /api/v2/users/{u}/profile)
 * returns clean profiles — the secret_answer field was removed from v2 output
 * entirely. But the FORGOTTEN v1 route is still mounted: GET /api/v1/users/{u}/profile?export=full
 * returns the legacy projection including security_question + secret_answer.
 * The innocent user's secret answer holds the flag (the old route's
 * over-exposure — the ShadowVersion flaw).
 */
module.exports = {
  meta: {
    category: 'API', subName: 'ShadowVersion', archetype: 'resource-resident', difficulty: 'medium',
    description: 'ProfileBook profiles — v2 is clean, but the deprecated v1 route is still mounted and keeps its over-exposing legacy export. Entry: http://victim.target.lab:8119/',
    flags: [{ category: 'API', subName: 'ShadowVersion', archetype: 'resource-resident' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, session, db } = ctx;

    /* seed-owned table: wipe + reseed each boot so the resident flag is fresh */
    db.exec(`CREATE TABLE IF NOT EXISTS profiles (
      username TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      bio TEXT NOT NULL,
      security_question TEXT NOT NULL,
      secret_answer TEXT NOT NULL,
      legacy_id INTEGER NOT NULL,
      joined_at TEXT NOT NULL
    )`);
    const flag = ctx.flags.held('API', 'ShadowVersion');
    const seedProfiles = db.transaction(() => {
      db.prepare('DELETE FROM profiles').run();
      const ins = db.prepare('INSERT INTO profiles (username, display_name, bio, security_question, secret_answer, legacy_id, joined_at) VALUES (?,?,?,?,?,?,?)');
      let legacy = 1000;
      const mk = (username, displayName, bio, q, a) => ins.run(username, displayName, bio, q, a, ++legacy, ctx.nowIso());
      for (const u of users.all()) {
        if (u.role === 'tester') mk(u.username, u.username + '-dev', 'shipping things and breaking builds', 'Name of your first pet?', 'Mochi');
      }
      /* users.innocent() is bound to THIS boot's random name; on a container
         restart the users table persists with the first boot's row — fall back
         to the persisted role:'innocent' account so reseeding stays restart-safe. */
      const innocent = users.innocent() || users.all().find((u) => u.role === 'innocent');
      mk(innocent.username, 'Quiet Owl', 'just here for the newsletter', 'What was your first carrier name?', flag);
      mk('admin', 'ProfileBook Staff', 'keeping the lights on', 'Name of your first school?', 'letmein');
    });
    seedProfiles();

    const loginPage = (msg) => render('ProfileBook — sign in', `
      <h1>ProfileBook</h1>
      <p class="muted">profiles for everyone · api v2</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">member directory (public): <a href="/api/v2/users">/api/v2/users</a> · <a href="/changelog">API changelog</a></p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });
    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* CURRENT API (v2) — directory is public, profiles require a login */
    app.get('/api/v2/users', (req, res) => {
      const roles = {};
      for (const u of users.all()) roles[u.username] = u.role;
      const rows = db.prepare('SELECT username, display_name FROM profiles ORDER BY username').all();
      res.json({ version: 2, users: rows.map((r) => ({ username: r.username, display_name: r.display_name, role: roles[r.username] || 'user' })) });
    });

    app.get('/api/v2/users/:username/profile', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const p = db.prepare('SELECT username, display_name, bio, joined_at FROM profiles WHERE username = ?')
        .get(String(req.params.username));
      if (!p) return res.status(404).json({ error: 'no such profile' });
      /* v2 projection: secret fields are gone from API output entirely */
      res.json({ version: 2, ...p });
    });

    /* FORGOTTEN v1 route — still mounted. THE FLAW (ShadowVersion): the
       deprecated version kept its legacy projection, including the exact
       fields v2 removed. Nothing links here anymore, but it still routes. */
    app.get('/api/v1/users/:username/profile', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const p = db.prepare('SELECT * FROM profiles WHERE username = ?').get(String(req.params.username));
      if (!p) return res.status(404).json({ error: 'no such profile' });
      const out = {
        version: 1, legacy_id: p.legacy_id, username: p.username,
        display_name: p.display_name, bio: p.bio, joined_at: p.joined_at,
      };
      if (String(req.query.export || '').toLowerCase() === 'full') {
        out.security_question = p.security_question;
        out.secret_answer = p.secret_answer; /* over-exposed legacy field */
      }
      res.json(out);
    });

    /* UI: clean profile page, rendered from the v2 projection only */
    app.get('/profile/:username', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const p = db.prepare('SELECT username, display_name, bio, joined_at FROM profiles WHERE username = ?')
        .get(String(req.params.username));
      if (!p) return res.status(404).type('html').send(render('ProfileBook', '<p class="muted">no such profile</p>'));
      res.type('html').send(render('Profile — ' + p.username, `
        <h1>${esc(p.display_name)}</h1>
        <p class="muted">@${esc(p.username)} · joined ${esc(String(p.joined_at).slice(0, 10))}</p>
        <div class="card"><p>${esc(p.bio)}</p></div>
        <p class="muted">served by API v2 — <code>GET /api/v2/users/${esc(p.username)}/profile</code></p>
        <p class="muted"><a href="/">back to directory</a></p>`));
    });

    /* API history: the deprecation notice is the discovery surface */
    app.get('/changelog', (req, res) => {
      res.type('html').send(render('ProfileBook API changelog', `
        <h1>API changelog</h1>
        <div class="card">
          <p><b>v2.0</b> (current) — profiles API rebuilt: directory at <code>/api/v2/users</code>,
          profiles at <code>/api/v2/users/{username}/profile</code>. Secret-answer fields were
          <b>removed from API output</b> entirely.</p>
          <p><b>v1.9</b> (legacy, deprecated 2024-06-30) — profile export with security questions:
          <code>/api/v1/users/{username}/profile?export=full</code>. Deprecated in favor of v2;
          still mounted while legacy partners migrate.</p>
          <p class="muted">Old v1 routes are no longer linked anywhere in the app UI.</p>
        </div>`));
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const rows = db.prepare('SELECT username, display_name FROM profiles ORDER BY username').all();
      res.type('html').send(render('ProfileBook', `
        <h1>ProfileBook</h1>
        <p class="muted">signed in as ${esc(auth.user.username)} · member directory</p>
        <div class="card">
          <table><tr><th>username</th><th>display name</th><th></th></tr>
          ${rows.map((p) => `<tr><td>${esc(p.username)}</td><td>${esc(p.display_name)}</td><td><a href="/profile/${esc(p.username)}">view</a></td></tr>`).join('')}
          </table>
        </div>
        <div class="card">
          <p><code>GET /api/v2/users</code> <span class="muted">— directory (public)</span></p>
          <p><code>GET /api/v2/users/{username}/profile</code> <span class="muted">— profile (auth required)</span></p>
          <p class="muted">API history: <a href="/changelog">/changelog</a></p>
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
