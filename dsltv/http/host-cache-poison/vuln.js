'use strict';
/*
 * DSLTV http/host-cache-poison — HostCachePoison (location-locked, critical).
 * CUT CANDIDATE (heaviest host-header build — kept per arch §7.3 list).
 * "FreshEdge CDN" marketing home with an in-app full-page cache.
 * Flaw: GET /home renders absolute links from the request's effective host
 * (X-Forwarded-Host trusted, "behind our proxy"), but the page cache is keyed
 * by PATH ONLY. One request with X-Forwarded-Host: evil.target.lab poisons the
 * cached /home for everyone: all absolute links now point into attacker space.
 * Gate: /flag returns the flag only after the poisoned /home was SERVED to the
 * innocent victim (server-side state set when the innocent's session fetches a
 * poisoned cached page) — proof the poisoned page reached the victim.
 */
module.exports = {
  meta: {
    category: 'HTTP', subName: 'HostCachePoison', archetype: 'location-locked', difficulty: 'critical',
    description: 'FreshEdge CDN — path-keyed page cache + host-derived absolute links: poison /home for every visitor (cut_candidate). Entry: http://victim.target.lab:8119/home',
    flags: [{ category: 'HTTP', subName: 'HostCachePoison', archetype: 'location-locked' }],
  },
  async setup(ctx) {
    const db = ctx.db;
    const esc = ctx.esc;
    const render = ctx.render;
    const innocent = ctx.users.innocent();
    const VICTIM_HOST = `victim.${ctx.labDomain}`;

    db.exec(`
      CREATE TABLE IF NOT EXISTS page_cache (path TEXT PRIMARY KEY, body TEXT, poisoned INTEGER DEFAULT 0, cached_at TEXT);
    `);

    const effectiveHost = (req) => {
      const xfh = req.headers['x-forwarded-host'];
      const raw = (Array.isArray(xfh) ? xfh[0] : xfh) || req.headers.host || `victim.${ctx.labDomain}:8119`;
      return String(raw);
    };
    const hostOnly = (h) => String(h).split(':')[0].toLowerCase();
    const stateKey = 'hostcache_victim_served_poisoned';

    const renderHome = (req) => {
      const base = 'http://' + effectiveHost(req);
      return render('FreshEdge CDN', `
        <h1>FreshEdge CDN — faster pages, happier users</h1>
        <div class="card">
          <p>Edge caching keeps this page snappy. This page was rendered for host
          <code>${esc(hostOnly(effectiveHost(req)))}</code>.</p>
          <p><a href="${esc(base)}/dashboard?next=home">Continue to your dashboard →</a></p>
          <p><a href="${esc(base)}/pricing">See pricing →</a></p>
          <form method="POST" action="${esc(base)}/subscribe"><input name="email" placeholder="email"> <button>Get updates</button></form>
        </div>
        <p class="muted">FreshEdge serves every page with absolute links so nothing breaks behind your proxy.</p>`);
    };

    ctx.app.get('/home', (req, res) => {
      const refresh = String(req.query.refresh || '') === '1';
      if (!refresh) {
        const hit = db.prepare('SELECT * FROM page_cache WHERE path = ?').get('/home');
        if (hit) {
          if (hit.poisoned) {
            const auth = ctx.session.get(req);
            if (auth && auth.user.username === innocent.username) {
              ctx.state.set(stateKey, { at: ctx.nowIso(), served_to: auth.user.username });
            }
          }
          res.setHeader('X-Cache', hit.poisoned ? 'HIT (poisoned)' : 'HIT');
          return res.type('html').send(hit.body);
        }
      }
      const body = renderHome(req);
      const poisoned = hostOnly(effectiveHost(req)) !== VICTIM_HOST;
      db.prepare('INSERT INTO page_cache (path, body, poisoned, cached_at) VALUES (?,?,?,?) '
        + 'ON CONFLICT(path) DO UPDATE SET body=excluded.body, poisoned=excluded.poisoned, cached_at=excluded.cached_at')
        .run('/home', body, poisoned ? 1 : 0, ctx.nowIso());
      res.setHeader('X-Cache', 'MISS');
      res.type('html').send(body);
    });

    ctx.app.get('/cache-state', (req, res) => {
      const hit = db.prepare('SELECT path, poisoned, cached_at FROM page_cache WHERE path = ?').get('/home');
      res.json({ cache: hit || null, victim_served_poisoned: ctx.state.get(stateKey) || null });
    });

    /* ------------------------------- flag gate ------------------------------- */
    ctx.app.get('/flag', (req, res) => {
      const proof = ctx.state.get(stateKey);
      if (!proof) {
        return res.status(403).json({ error: 'no proof yet that the poisoned page was served to the innocent victim' });
      }
      res.json({ flag: ctx.flags.held('HTTP', 'HostCachePoison'), served_at: proof.at, served_to: proof.served_to });
    });
  },
};
