'use strict';
/*
 * DSLTV CORS — MissingVary · theme "Quotabank — quotes bank". CUT CANDIDATE (heaviest CORS build).
 * Flaw: Quotabank's API gateway fronts GET /api/secret with an in-app response
 * cache whose key is the URL ONLY — no `Vary: Origin` and no cookie/session in
 * the key. The first response ever generated for a URL is cached in full
 * (body + ACAO header) and replayed verbatim to every later requester:
 *   - bot fetch #1 (innocent session + Origin: attacker) bakes the innocent's
 *     body together with `ACAO: <attacker origin>` into the cache;
 *   - any later fetch of the same URL (no session needed) is served from cache
 *     with the stored attacker ACAO and the victim's body — a persistent,
 *     session-free, cross-origin readable copy.
 * Real-world lesson: caches in front of credentialed, origin-varying responses
 * must key on (or `Vary:`) the Origin header and must never replay one
 * principal's body to another. POST /cache/purge lets ops (and players) reset
 * the experiment; the dashboard shows the cache monitor without bodies.
 */
module.exports = {
  meta: {
    category: 'CORS', subName: 'MissingVary', archetype: 'event-verified', eventKind: 'cors', difficulty: 'high',
    cutCandidate: true,
    description: 'CUT CANDIDATE — Quotabank caches /api/secret by URL only (no Vary: Origin, no cookie in the key): the victim\'s body is replayed with the attacker\'s stored ACAO.',
    flags: [{ category: 'CORS', subName: 'MissingVary', archetype: 'event-verified', eventKind: 'cors' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    ctx.db.exec(`CREATE TABLE IF NOT EXISTS quotabank_accounts (user_id INTEGER PRIMARY KEY, balance INTEGER NOT NULL)`);

    const seedA = ctx.db.prepare('INSERT OR REPLACE INTO quotabank_accounts (user_id, balance) VALUES (?,?)');
    for (const u of ctx.users.all()) seedA.run(u.id, u.role === 'admin' ? 999999 : (u.role === 'innocent' ? 84213 : 500));

    /* the flawed edge cache: key = URL only — no Origin, no cookie, no Vary */
    const edgeCache = new Map();

    const cacheRows = () => [...edgeCache.entries()].map(([url, c]) => ({
      url, filled_by: c.filled_by, acao: c.acao || '(none)', hits: c.hits,
    }));

    /* --- the vulnerable endpoint behind the flawed cache ------------------- */
    ctx.app.get('/api/secret', (req, res) => {
      const key = req.originalUrl.split('?')[0]; /* ← flaw: URL is the whole cache key */
      if (edgeCache.has(key)) {
        const c = edgeCache.get(key);
        c.hits += 1;
        if (c.acao) {
          res.setHeader('Access-Control-Allow-Origin', c.acao); /* stored ACAO replayed to everyone */
          res.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        res.setHeader('X-Cache', 'HIT from quotabank-edge');
        return res.status(200).type('json').send(c.body);
      }
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const origin = req.headers.origin ? String(req.headers.origin) : null;
      const body = JSON.stringify({ username: auth.user.username, api_key: auth.user.api_key, balance: (ctx.db.prepare('SELECT balance FROM quotabank_accounts WHERE user_id = ?').get(auth.user.id) || { balance: 0 }).balance });
      edgeCache.set(key, { body, acao: origin, hits: 0, filled_by: auth.user.username });
      if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin); /* fresh path reflects the requester's origin */
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
      res.setHeader('X-Cache', 'MISS from quotabank-edge');
      res.status(200).type('json').send(body);
    });

    ctx.app.post('/cache/purge', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      edgeCache.clear();
      res.redirect('/');
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Quotabank', `
          <h1>Quotabank — the quotes bank</h1>
          <div class="card">
            <p>Live quotes for account holders. Fast, because everything is served from the edge cache.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'quotes bank — Quotabank' }));
      }
      const bal = (ctx.db.prepare('SELECT balance FROM quotabank_accounts WHERE user_id = ?').get(auth.user.id) || { balance: 0 }).balance;
      res.type('html').send(ctx.render('Quotabank', `
        <h1>Quotabank — ${esc(auth.user.username)}</h1>
        <div class="card">
          <table>
            <tr><th>account balance</th><td>${bal} VLH</td></tr>
            <tr><th>api key</th><td><code>${esc(auth.user.api_key || '')}</code></td></tr>
          </table>
          <p class="muted">Quote/account JSON at <code>GET /api/secret</code> — served through the edge cache (URL-keyed, <code>Vary</code> not set — see the monitor below).</p>
        </div>
        <div class="card">
          <h2>edge cache monitor</h2>
          <table><tr><th>url</th><th>filled by</th><th>stored ACAO</th><th>hits</th></tr>
          ${cacheRows().map((r) => `<tr><td>${esc(r.url)}</td><td>${esc(r.filled_by)}</td><td>${esc(r.acao)}</td><td>${r.hits}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">cache cold</td></tr>'}
          </table>
          <form method="post" action="/cache/purge"><button>purge cache</button></form>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'quotes bank — Quotabank' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Quotabank', '<h1>Quotabank</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
