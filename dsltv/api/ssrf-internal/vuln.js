'use strict';
const http = require('http');
const https = require('https');

/*
 * DSLTV api/ssrf-internal — SsrfInternal (location-locked, high).
 * "Avatario" profile avatars. POST /api/v1/profile/avatar {"url": ...} makes
 * the SERVER fetch any http/https URL the caller picks — there is no host
 * allowlist (the SSRF flaw) — and stores the response body as the "avatar
 * preview"; GET /api/v1/profile/avatar returns the stored preview. An
 * instance-metadata service listens on loopback INSIDE the container only
 * (127.0.0.1:8082) — no external routing reaches it (the edge sidecar only
 * forwards 8119 -> app:8080). Its /latest/meta-data/ document carries the
 * flag, so only the server-side fetch position (the SSRF) can read it.
 * Guard: file:// and every other scheme are rejected (http/https only).
 */
module.exports = {
  meta: {
    category: 'API', subName: 'SsrfInternal', archetype: 'location-locked', difficulty: 'high',
    description: 'Avatario avatar API — the server fetches any caller-supplied http/https URL with no allowlist; the loopback-only instance metadata holds the flag. Entry: http://victim.target.lab:8119/',
    flags: [{ category: 'API', subName: 'SsrfInternal', archetype: 'location-locked' }],
  },
  async setup(ctx) {
    const { app, render, esc, users, session, db } = ctx;

    db.exec(`CREATE TABLE IF NOT EXISTS avatars (
      user_id INTEGER PRIMARY KEY,
      url TEXT NOT NULL,
      status INTEGER,
      content_type TEXT,
      bytes INTEGER,
      body TEXT,
      fetched_at TEXT
    )`);
    db.prepare('DELETE FROM avatars').run(); /* fresh previews each boot */

    /* in-container-only metadata listener (the location-locked flag carrier).
       Binds 127.0.0.1:8082 — unreachable from outside this container. */
    const META_INSTANCE_ID = 'i-' + ctx.randHex(8);
    const metaServer = http.createServer((req, res) => {
      const path = String(req.url || '').split('?')[0].replace(/\/+$/, '') || '/';
      if (req.method === 'GET' && path === '/latest/meta-data') {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({
          service: 'avatario-instance-metadata',
          instance_id: META_INSTANCE_ID,
          region: 'lab-internal-1',
          local_ipv4: '127.0.0.1',
          instance_profile: 'avatario-avatar-worker',
          maintenance_token: ctx.flags.held('API', 'SsrfInternal'),
          note: 'loopback metadata for avatar fetch workers — not routed at the edge',
        }, null, 2));
      } else {
        res.statusCode = 404;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ error: 'not found' }));
      }
    });
    metaServer.on('error', (e) => console.error('[ssrf-internal] metadata listener error:', e.message));
    metaServer.listen(8082, '127.0.0.1', () => {
      console.log('[ssrf-internal] instance-metadata listening on 127.0.0.1:8082 (in-container only)');
    });

    /* THE FLAW (SSRF): server-side fetch of a caller-supplied URL with NO host
       allowlist. Guard: the scheme must be http/https (file:// etc. rejected),
       3s timeout, body capped at 64 KB. */
    const fetchUrl = (urlStr) => new Promise((resolve) => {
      let u;
      try { u = new URL(String(urlStr).slice(0, 2048)); } catch (_) { return resolve({ error: 'invalid url' }); }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return resolve({ error: `unsupported scheme "${u.protocol}" — only http/https URLs are fetched` });
      }
      const mod = u.protocol === 'https:' ? https : http;
      const opts = { method: 'GET', headers: {} };
      if (u.hostname.endsWith('.' + ctx.labDomain)) {
        /* *.target.lab hosts resolve to this container via the sidecar — rewrite
           to loopback, keeping the Host header so vhost routing still works. */
        opts.host = '127.0.0.1'; opts.port = ctx.listenPort;
        opts.path = u.pathname + u.search;
        opts.headers.host = `${u.hostname}:${u.port || 8119}`;
      } else {
        opts.host = u.hostname;
        opts.port = u.port || (u.protocol === 'https:' ? 443 : 80);
        opts.path = u.pathname + u.search;
      }
      const req = mod.request(opts, (res) => {
        const chunks = []; let n = 0;
        res.on('data', (c) => { n += c.length; if (n <= 65536) chunks.push(c); });
        res.on('end', () => resolve({
          status: res.statusCode,
          content_type: res.headers['content-type'] || '',
          bytes: n,
          body: Buffer.concat(chunks).toString('utf8'),
        }));
      });
      req.setTimeout(3000, () => req.destroy(new Error('fetch timeout after 3s')));
      req.on('error', (e) => resolve({ error: String((e && e.message) || e) }));
      req.end();
    });

    const loginPage = (msg) => render('Avatario — sign in', `
      <h1>Avatario</h1>
      <p class="muted">profile avatars · api v1</p>
      <div class="card">
        <form method="POST" action="/login">
          <p><input name="username" placeholder="username" autocomplete="off" required></p>
          <p><input name="password" type="password" placeholder="password" required></p>
          <p><button>sign in</button></p>
        </form>
        ${msg ? `<p class="muted">${esc(msg)}</p>` : ''}
        <p class="muted">accounts: 0xnhsec / vlh-tester-01 · Noshiro / vlh-tester-02</p>
      </div>
      <p class="muted">service status: <a href="/api/v1/status">/api/v1/status</a></p>`);

    app.post('/login', (req, res) => {
      const { username, password } = req.body || {};
      const user = users.verify(username, password);
      if (!user) return res.status(401).type('html').send(loginPage('invalid credentials'));
      ctx.login(res, user);
      res.redirect('/');
    });
    app.get('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });

    /* public status feed — the realistic leak: internal endpoints listed */
    app.get('/api/v1/status', (req, res) => {
      res.json({
        service: 'avatario', version: '2.1.0', status: 'operational', avatar_workers: 4,
        internal_endpoints: [
          { name: 'instance-metadata', url: 'http://127.0.0.1:8082/latest/meta-data/', scope: 'loopback only' },
        ],
        notes: 'avatar URLs are fetched server-side by our edge workers',
      });
    });

    /* the vulnerable fetch: any http/https URL, fetched by the server */
    app.post('/api/v1/profile/avatar', async (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const url = String((req.body || {}).url || '');
      const result = await fetchUrl(url);
      if (result.error) return res.status(400).json({ error: result.error });
      db.prepare(`INSERT INTO avatars (user_id, url, status, content_type, bytes, body, fetched_at)
                  VALUES (?,?,?,?,?,?,?)
                  ON CONFLICT(user_id) DO UPDATE SET url=excluded.url, status=excluded.status,
                    content_type=excluded.content_type, bytes=excluded.bytes, body=excluded.body,
                    fetched_at=excluded.fetched_at`)
        .run(auth.user.id, url, result.status, result.content_type, result.bytes, result.body, ctx.nowIso());
      res.json({
        stored: true, url, status: result.status,
        content_type: result.content_type, bytes: result.bytes,
        read_preview_at: 'GET /api/v1/profile/avatar',
      });
    });

    /* the stored preview — the flag is visible here after an SSRF fetch */
    app.get('/api/v1/profile/avatar', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.status(401).json({ error: 'authentication required' });
      const a = db.prepare('SELECT * FROM avatars WHERE user_id = ?').get(auth.user.id);
      if (!a) {
        return res.json({ avatar: null, hint: 'POST {"url":"https://…"} to /api/v1/profile/avatar — the server fetches it and stores a preview' });
      }
      res.json({
        avatar: { url: a.url, status: a.status, content_type: a.content_type, bytes: a.bytes, fetched_at: a.fetched_at },
        preview: a.body,
      });
    });

    app.get('/', (req, res) => {
      const auth = session.get(req);
      if (!auth) return res.type('html').send(loginPage());
      const a = db.prepare('SELECT * FROM avatars WHERE user_id = ?').get(auth.user.id);
      res.type('html').send(render('Avatario', `
        <h1>Avatario — profile avatar</h1>
        <p class="muted">signed in as ${esc(auth.user.username)} · avatar previews are fetched by our edge workers</p>
        <div class="card">
          <form method="POST" action="/api/v1/profile/avatar">
            <p><input name="url" placeholder="https://example.com/avatar.txt" size="48" required></p>
            <p><button>fetch + set avatar</button></p>
          </form>
          <p class="muted">http/https only · the server fetches the URL and stores a text preview</p>
        </div>
        ${a ? `<div class="card"><p class="muted">current avatar preview (${a.status} ${esc(a.content_type || '')}, ${a.bytes} bytes, from ${esc(a.url)}):</p><pre>${esc(a.body)}</pre></div>` : '<p class="muted">no avatar set yet</p>'}
        <div class="card">
          <p><code>POST /api/v1/profile/avatar</code> <span class="muted">— {"url": "…"} (or the form above)</span></p>
          <p><code>GET /api/v1/profile/avatar</code> <span class="muted">— stored preview (JSON)</span></p>
          <p><code>GET /api/v1/status</code> <span class="muted">— service status (public)</span></p>
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
