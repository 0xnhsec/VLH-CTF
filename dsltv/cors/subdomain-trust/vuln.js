'use strict';
/*
 * DSLTV CORS — SubdomainTrust · theme "Cloudshelf — file sync".
 * Flaw: Cloudshelf "trusts every *.target.lab service" (shared SSO story):
 * GET /api/secret reflects ANY origin whose hostname is target.lab or ends
 * with .target.lab into Access-Control-Allow-Origin with credentials.
 * The lab's wildcard attacker space means *.target.lab hosts you control
 * (e.g. http://evil.target.lab:8119) are served by your exploit server, so
 * the blanket subdomain trust hands the victim's data to the attacker.
 * Event-verified: /verify mints once the bot's cross-site fetch delivers
 * the innocent's api_key.
 */
module.exports = {
  meta: {
    category: 'CORS', subName: 'SubdomainTrust', archetype: 'event-verified', eventKind: 'cors', difficulty: 'medium',
    description: 'Cloudshelf trusts every *.target.lab origin with credentials — attacker-controlled subdomains get a credentialed cross-site read.',
    flags: [{ category: 'CORS', subName: 'SubdomainTrust', archetype: 'event-verified', eventKind: 'cors' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    ctx.db.exec(`CREATE TABLE IF NOT EXISTS cloudshelf_quota (user_id INTEGER PRIMARY KEY, files INTEGER NOT NULL, balance INTEGER NOT NULL)`);

    const seedQ = ctx.db.prepare('INSERT OR REPLACE INTO cloudshelf_quota (user_id, files, balance) VALUES (?,?,?)');
    for (const u of ctx.users.all()) seedQ.run(u.id, u.role === 'admin' ? 4096 : (u.role === 'innocent' ? 342 : 12), u.role === 'admin' ? 999999 : (u.role === 'innocent' ? 84213 : 500));

    /* "every *.target.lab service is ours, so every *.target.lab origin is trusted" */
    const trustedOrigin = (origin) => {
      try {
        const u = new URL(String(origin));
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
        return u.hostname === ctx.labDomain || u.hostname.endsWith('.' + ctx.labDomain); /* ← flaw: blanket subdomain trust */
      } catch (_) { return false; }
    };

    /* --- the vulnerable endpoint ------------------------------------------ */
    ctx.app.get('/api/secret', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const origin = req.headers.origin ? String(req.headers.origin) : '';
      if (origin && trustedOrigin(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
      const q = ctx.db.prepare('SELECT files, balance FROM cloudshelf_quota WHERE user_id = ?').get(auth.user.id);
      res.json({ username: auth.user.username, api_key: auth.user.api_key, balance: q ? q.balance : 0, files: q ? q.files : 0 });
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Cloudshelf', `
          <h1>Cloudshelf — your files, everywhere</h1>
          <div class="card">
            <p>Sync across the whole *.${esc(ctx.labDomain)} device fleet.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'file sync — Cloudshelf' }));
      }
      const q = ctx.db.prepare('SELECT files, balance FROM cloudshelf_quota WHERE user_id = ?').get(auth.user.id);
      res.type('html').send(ctx.render('Cloudshelf', `
        <h1>Cloudshelf — ${esc(auth.user.username)}</h1>
        <div class="card">
          <table>
            <tr><th>files synced</th><td>${q ? q.files : 0}</td></tr>
            <tr><th>storage credit</th><td>${q ? q.balance : 0} VLH</td></tr>
            <tr><th>sync api key</th><td><code>${esc(auth.user.api_key || '')}</code></td></tr>
          </table>
          <p class="muted">Account JSON at <code>GET /api/secret</code>. All <code>*.${esc(ctx.labDomain)}</code> services share our SSO, so every <code>*.${esc(ctx.labDomain)}</code> origin is trusted for credentialed API reads.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'file sync — Cloudshelf' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Cloudshelf', '<h1>Cloudshelf</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
