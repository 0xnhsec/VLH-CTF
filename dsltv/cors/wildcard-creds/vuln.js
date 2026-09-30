'use strict';
/*
 * DSLTV CORS — WildcardCreds · theme "Stockleap — portfolio tracker". CUT CANDIDATE.
 * Flaw (educational): GET /api/secret answers every request with the illegal
 * combination `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials:
 * true`. Real browsers REFUSE credentialed responses with a wildcard ACAO, so in
 * a real browser this cannot be read with credentials — the combination is still
 * worth studying because it signals a broken CORS layer and because some
 * non-browser clients (and naive proxies) honour it. Documented cut-candidate
 * per architecture-decisions §7.3; the victim-bot model still lets the /verify
 * dual-check demonstrate the data flow end-to-end.
 */
module.exports = {
  meta: {
    category: 'CORS', subName: 'WildcardCreds', archetype: 'event-verified', eventKind: 'cors', difficulty: 'low',
    cutCandidate: true,
    description: 'CUT CANDIDATE — Stockleap sends ACAO:* with credentials (browser-illegal combo); educational only, real browsers reject it.',
    flags: [{ category: 'CORS', subName: 'WildcardCreds', archetype: 'event-verified', eventKind: 'cors' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    ctx.db.exec(`CREATE TABLE IF NOT EXISTS stockleap_portfolios (user_id INTEGER PRIMARY KEY, positions INTEGER NOT NULL, balance INTEGER NOT NULL)`);

    const seedP = ctx.db.prepare('INSERT OR REPLACE INTO stockleap_portfolios (user_id, positions, balance) VALUES (?,?,?)');
    for (const u of ctx.users.all()) seedP.run(u.id, u.role === 'admin' ? 42 : (u.role === 'innocent' ? 17 : 3), u.role === 'admin' ? 999999 : (u.role === 'innocent' ? 84213 : 500));

    /* --- the (browser-illegal) endpoint ------------------------------------ */
    ctx.app.get('/api/secret', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      res.setHeader('Access-Control-Allow-Origin', '*');          /* ← illegal combo: */
      res.setHeader('Access-Control-Allow-Credentials', 'true');  /*   * + credentials */
      const p = ctx.db.prepare('SELECT positions, balance FROM stockleap_portfolios WHERE user_id = ?').get(auth.user.id);
      res.json({ username: auth.user.username, api_key: auth.user.api_key, balance: p ? p.balance : 0, positions: p ? p.positions : 0 });
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Stockleap', `
          <h1>Stockleap — portfolio tracker</h1>
          <div class="card">
            <p>Track positions, watch your balance, keep your trading API key close.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'portfolio — Stockleap' }));
      }
      const p = ctx.db.prepare('SELECT positions, balance FROM stockleap_portfolios WHERE user_id = ?').get(auth.user.id);
      res.type('html').send(ctx.render('Stockleap', `
        <h1>Stockleap — ${esc(auth.user.username)}</h1>
        <div class="card">
          <table>
            <tr><th>open positions</th><td>${p ? p.positions : 0}</td></tr>
            <tr><th>portfolio value</th><td>${p ? p.balance : 0} VLH</td></tr>
            <tr><th>trading api key</th><td><code>${esc(auth.user.api_key || '')}</code></td></tr>
          </table>
          <p class="muted">Portfolio JSON at <code>GET /api/secret</code> — our API layer is configured "wide open" for partner dashboards.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'portfolio — Stockleap' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Stockleap', '<h1>Stockleap</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
