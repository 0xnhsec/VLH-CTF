'use strict';
/*
 * DSLTV CSRF — ContentTypeBypass · theme "Prefsio — preference center".
 * Flaw: POST /account/recovery-email treats its JSON-only content-type check
 * as CSRF protection: requests with `application/x-www-form-urlencoded` or
 * `multipart/form-data` are rejected (normal HTML forms blocked), but the
 * body is then JSON.parsed LENIENTLY for every other content type —
 * including `text/plain` and missing content types. The classic
 * `<form enctype="text/plain">` trick submits arbitrary JSON as a simple
 * request (no preflight, no CORS check), so the cross-site form sails
 * through the "protection". A real fix requires a CSRF token; content-type
 * alone is not one.
 * Event-verified (eventKind csrf): /verify mints once the innocent's
 * recovery_email row changes from its seed value.
 */
module.exports = {
  meta: {
    category: 'CSRF', subName: 'ContentTypeBypass', archetype: 'event-verified', eventKind: 'csrf', difficulty: 'medium',
    description: 'Prefsio\'s "JSON only" content-type check blocks normal forms but leniently parses text/plain bodies — the enctype=text/plain form bypasses it.',
    flags: [{ category: 'CSRF', subName: 'ContentTypeBypass', archetype: 'event-verified', eventKind: 'csrf' }],
  },
  async setup(ctx) {
    const esc = ctx.esc;
    const validEmail = (s) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

    /* Capture bodies that express's typed parsers leave on the stream (e.g. the
     * bot's raw string body with no content-type, or odd types). Form-encoded
     * and multipart bodies are left for the endpoint to reject. */
    ctx.app.use((req, res, next) => {
      if (req.method !== 'POST' && req.method !== 'PUT') return next();
      const ct = String(req.headers['content-type'] || '');
      if (/application\/x-www-form-urlencoded|multipart\/form-data/i.test(ct)) return next();
      if (req.body !== undefined && req.body !== null
          && (typeof req.body === 'string'
              || (typeof req.body === 'object' && !Array.isArray(req.body) && Object.keys(req.body).length > 0))) {
        return next(); /* already parsed by express.json / express.text */
      }
      const chunks = [];
      req.on('data', (c) => { if (chunks.length < 64) chunks.push(c); });
      req.on('end', () => { req.lenientBody = Buffer.concat(chunks).toString('utf8'); next(); });
      req.on('error', () => next());
    });

    /* --- the vulnerable state change --------------------------------------- */
    ctx.app.post('/account/recovery-email', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.status(401).json({ error: 'login required' });
      const ct = String(req.headers['content-type'] || '');
      /* the "CSRF protection": HTML form encodings are rejected... */
      if (/application\/x-www-form-urlencoded|multipart\/form-data/i.test(ct)) {
        return res.status(403).json({ error: 'form encodings are not accepted — this endpoint only takes JSON' });
      }
      /* ...but every other content type is JSON.parsed leniently ← the flaw */
      let data = null;
      const raw = (typeof req.body === 'string') ? req.body
        : (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) ? JSON.stringify(req.body)
          : (req.lenientBody || req.rawBody || '');
      try { data = JSON.parse(raw); } catch (_) { return res.status(400).json({ error: 'body must be valid JSON' }); }
      const email = data && typeof data === 'object' ? String(data.recovery_email || '') : '';
      if (!validEmail(email)) return res.status(400).json({ error: 'a valid recovery_email is required' });
      ctx.db.prepare('UPDATE users SET recovery_email = ? WHERE id = ?').run(email, auth.user.id);
      res.json({ ok: true, recovery_email: email });
    });

    /* --- themed UI --------------------------------------------------------- */
    ctx.app.get('/', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) {
        return res.type('html').send(ctx.render('Prefsio', `
          <h1>Prefsio — preference center</h1>
          <div class="card">
            <p>Tune your notifications and recovery settings.</p>
            <form method="post" action="/login">
              <p><input name="username" placeholder="username" autocomplete="off" required>
                 <input name="password" type="password" placeholder="password" required>
                 <button>sign in</button></p>
            </form>
            <p class="muted">Player accounts are documented in the player guide (0xnhsec / Noshiro).</p>
          </div>`, { tagline: 'preferences — Prefsio' }));
      }
      res.type('html').send(ctx.render('Prefsio', `
        <h1>Prefsio — ${esc(auth.user.username)}</h1>
        <div class="card">
          <p>Notification prefs: weekly digest (on), product news (off).</p>
          <p>Recovery email: <code>${esc(auth.user.recovery_email || '(not set)')}</code> — manage it in <a href="/account">account settings</a>.</p>
        </div>
        <form method="post" action="/logout"><button>sign out</button></form>`, { tagline: 'preferences — Prefsio' }));
    });

    ctx.app.get('/account', (req, res) => {
      const auth = ctx.session.get(req);
      if (!auth) return res.redirect('/');
      res.type('html').send(ctx.render('Account settings', `
        <h1>Account settings — ${esc(auth.user.username)}</h1>
        <div class="card">
          <h2>Recovery email</h2>
          <p>Current: <code>${esc(auth.user.recovery_email || '(not set)')}</code></p>
          <form id="prefs-form" onsubmit="return false">
            <p><input id="re" type="email" placeholder="new recovery email" required>
               <button id="save">save (JSON API)</button></p>
          </form>
          <pre>fetch('/account/recovery-email', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({recovery_email: value})
})</pre>
          <p class="muted">This endpoint is JSON-only — form encodings are rejected (SEC-77 "content-type CSRF protection").</p>
        </div>
        <script>
          document.getElementById('save').addEventListener('click', function () {
            var v = document.getElementById('re').value;
            fetch('/account/recovery-email', { method: 'POST', headers: {'Content-Type': 'application/json'}, credentials: 'same-origin', body: JSON.stringify({ recovery_email: v }) })
              .then(function (r) { return r.json(); })
              .then(function (j) { document.getElementById('prefs-status').textContent = JSON.stringify(j); });
          });
        </script>
        <p id="prefs-status" class="muted"></p>`, { tagline: 'preferences — Prefsio' }));
    });

    ctx.app.post('/login', (req, res) => {
      const u = ctx.users.verify(req.body && req.body.username, req.body && req.body.password);
      if (!u) return res.status(401).type('html').send(ctx.render('Prefsio', '<h1>Prefsio</h1><div class="card">Wrong credentials. <a href="/">back</a></div>'));
      ctx.login(res, u);
      res.redirect('/');
    });
    ctx.app.post('/logout', (req, res) => { ctx.logout(req, res); res.redirect('/'); });
  },
};
