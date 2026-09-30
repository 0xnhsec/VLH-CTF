'use strict';
/*
 * DSLTV CORS — NullOrigin · theme "Keychest — digital key locker".
 * Flaw: GET /api/secret (auth required) allowlists the literal Origin "null"
 * (legacy support for the old sandboxed-iframe widget gallery) and answers
 * `Access-Control-Allow-Origin: null` + credentials. A page inside a sandboxed
 * iframe (<iframe sandbox="allow-scripts" src="...">) is served from the null
 * origin, so attacker-controlled sandboxed content can read the victim's data.
 * Event-verified: the base /verify mints the flag once the bot's cross-site
 * fetch (origin "null") delivers the innocent's api_key to the collector.
 */
module.exports = {
  meta: {
    category: 'CORS', subName: 'NullOrigin', archetype: 'event-verified', eventKind: 'cors', difficulty: 'medium',
    description: 'Keychest allowlists Origin: null (sandboxed iframes) with credentials — attacker content in a sandboxed iframe can read the victim\'s api_key.',
    flags: [{ category: 'CORS', subName: 'NullOrigin', archetype: 'event-verified', eventKind: 'cors' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    ctx.db.exec(`CREATE TABLE IF NOT EXISTS keychest_accounts (user_id INTEGER PRIMARY KEY, keys_stored INTEGER NOT NULL, balance INTEGER NOT NULL)`);

    const seedAcc = ctx.db.prepare('INSERT OR REPLACE INTO keychest_accounts (user_id, keys_stored, balance) VALUES (?,?,?)');
    for (const u of ctx.users.all()) seedAcc.run(u.id, u.role === 'admin' ? 4096 : (u.role === 'innocent' ? 128 : 7), u.role === 'admin' ? 999999 : (u.role === 'innocent' ? 84213 : 500));

    /* --- the vulnerable endpoint ------------------------------------------ */
    ctx.app.get('/api/secret', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const origin = req.headers.origin;
      if (origin === 'null') { /* ← flaw: null origin (sandboxed iframes) is allowlisted */
        res.setHeader('Access-Control-Allow-Origin', 'null');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
      const acc = ctx.db.prepare('SELECT keys_stored, balance FROM keychest_accounts WHERE user_id = ?').get(auth.user.id);
      res.json({ username: auth.user.username, api_key: auth.user.api_key, balance: acc ? acc.balance : 0, keys_stored: acc ? acc.keys_stored : 0 });
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Keychest', `
          <h1>Keychest — digital key locker</h1>
          <div class="card">
            <p>Keychest guards your API keys and your locker balance.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>unlock</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'key locker — Keychest' }));
      }
      const acc = ctx.db.prepare('SELECT keys_stored, balance FROM keychest_accounts WHERE user_id = ?').get(auth.user.id);
      res.type('html').send(ctx.render('Keychest', `
        <h1>Keychest — ${esc(auth.user.username)}</h1>
        <div class="card">
          <table>
            <tr><th>keys stored</th><td>${acc ? acc.keys_stored : 0}</td></tr>
            <tr><th>locker balance</th><td>${acc ? acc.balance : 0} VLH</td></tr>
            <tr><th>master api key</th><td><code>${esc(auth.user.api_key || '')}</code></td></tr>
          </table>
          <p class="muted">Locker data is exposed as JSON at <code>GET /api/secret</code>. Legacy note: the old widget-gallery embeds (sandboxed iframes, <code>Origin: null</code>) are still allowlisted for backwards compatibility.</p>
        </div>
        <form method="post" action="/logout"><button>lock</button></form>`, { tagline: 'key locker — Keychest' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Keychest', '<h1>Keychest</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
