'use strict';
/*
 * DSLTV CORS — WeakOriginRegex · theme "Paynest — payments wallet".
 * Flaw: the CORS allowlist check on GET /api/secret uses an unanchored regex:
 *   /^https?:\/\/victim([a-z0-9.-]*)?\.target\.lab/
 * It was meant to allow only http://victim.target.lab (the app's own host) but
 * (a) never anchors the end (port/suffix ignored) and (b) lets any junk sit
 * between the leading "victim" label and ".target.lab". The lab's wildcard
 * attacker space serves pages at e.g. http://victim-evil.target.lab:8119 —
 * that origin matches the flawed regex and gets reflected into ACAO with
 * credentials. Event-verified: /verify mints once the bot's cross-site fetch
 * delivers the innocent's api_key.
 */
module.exports = {
  meta: {
    category: 'CORS', subName: 'WeakOriginRegex', archetype: 'event-verified', eventKind: 'cors', difficulty: 'medium',
    description: 'Paynest\'s origin allowlist regex is unanchored — attacker hosts like victim-evil.target.lab match and get a credentialed ACAO.',
    flags: [{ category: 'CORS', subName: 'WeakOriginRegex', archetype: 'event-verified', eventKind: 'cors' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    ctx.db.exec(`CREATE TABLE IF NOT EXISTS paynest_wallets (user_id INTEGER PRIMARY KEY, balance INTEGER NOT NULL)`);

    const seedW = ctx.db.prepare('INSERT OR REPLACE INTO paynest_wallets (user_id, balance) VALUES (?,?)');
    for (const u of ctx.users.all()) seedW.run(u.id, u.role === 'admin' ? 999999 : (u.role === 'innocent' ? 84213 : 500));

    /* the "carefully reviewed" allowlist (intended: only victim.target.lab) */
    const dotted = ctx.labDomain.replace(/\./g, '\\.');
    const allowRe = new RegExp('^https?://victim([a-z0-9.-]*)?\\.' + dotted); /* ← flaw: unanchored end + junk between labels */

    /* --- the vulnerable endpoint ------------------------------------------ */
    ctx.app.get('/api/secret', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const origin = req.headers.origin ? String(req.headers.origin) : '';
      if (origin && allowRe.test(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
      const w = ctx.db.prepare('SELECT balance FROM paynest_wallets WHERE user_id = ?').get(auth.user.id);
      res.json({ username: auth.user.username, api_key: auth.user.api_key, balance: w ? w.balance : 0 });
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Paynest', `
          <h1>Paynest — payments wallet</h1>
          <div class="card">
            <p>Move money, hold a balance, keep your API key safe.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'payments — Paynest' }));
      }
      const w = ctx.db.prepare('SELECT balance FROM paynest_wallets WHERE user_id = ?').get(auth.user.id);
      res.type('html').send(ctx.render('Paynest', `
        <h1>Paynest — ${esc(auth.user.username)}</h1>
        <div class="card">
          <table>
            <tr><th>wallet balance</th><td>${w ? w.balance : 0} VLH</td></tr>
            <tr><th>api key</th><td><code>${esc(auth.user.api_key || '')}</code></td></tr>
          </table>
          <p class="muted">Wallet JSON lives at <code>GET /api/secret</code>. CORS is restricted to our own Paynest dashboards (<code>victim.${esc(ctx.labDomain)}</code>) — origin checks are regex-based, see <code>SEC-102</code>.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'payments — Paynest' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Paynest', '<h1>Paynest</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
